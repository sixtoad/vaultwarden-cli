package dev.vaultwarden.companionslice

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

/**
 * The provider pinning rule of `PinnedTransport` (Trust.swift): the chain
 * must validate against the configured provider CA ALONE (no platform or
 * user trust store, no network fetch), for the endpoint host, and its leaf
 * DER must hash to the pinned SHA-256. Anything else fails the handshake.
 */
class PinnedTrustManager(ca: X509Certificate, private val leafSha256: String) : X509TrustManager {
    private val anchored: X509TrustManager

    init {
        require(Wire.validHex(leafSha256, 64))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("provider-ca", ca)
        }
        anchored = TrustManagerFactory.getInstance("PKIX").apply { init(store) }
            .trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (chain.isNullOrEmpty()) throw CertificateException("empty chain")
        anchored.checkServerTrusted(chain, authType)
        if (!pinMatches(chain[0].encoded, leafSha256)) throw CertificateException("pin mismatch")
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        throw CertificateException("client role unsupported")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    companion object {
        fun pinMatches(leafDer: ByteArray, pin: String): Boolean =
            Wire.validHex(pin, 64) && java.security.MessageDigest.isEqual(Wire.hex(Wire.sha256(leafDer)).toByteArray(), pin.toByteArray())

        fun certificate(der: ByteArray): X509Certificate =
            CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    }
}

/** Presents exactly one client identity (an AndroidKeyStore key and its chain). */
class FixedKeyManager(private val key: PrivateKey, private val chain: Array<X509Certificate>) : X509KeyManager {
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = ALIAS
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(ALIAS)
    override fun getCertificateChain(alias: String?) = if (alias == ALIAS) chain else null
    override fun getPrivateKey(alias: String?) = if (alias == ALIAS) key else null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = null
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = null

    private companion object { const val ALIAS = "client" }
}

class TransportException(val code: String) : Exception(code)

/** One POST of one body; no redirects, caches, cookies, retries or compression. */
class PinnedTransport(
    private val endpoint: URI,
    private val trust: PinnedTrustManager,
    private val identity: FixedKeyManager,
    private val hostnameVerifier: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier(),
) {
    fun send(body: ByteArray): ByteArray {
        if (body.size > ProviderRules.MAX_REQUEST) throw TransportException("oversized")
        val context = SSLContext.getInstance("TLS").apply { init(arrayOf(identity), arrayOf(trust), null) }
        val timeout = ProviderRules.timeoutSeconds(body) * 1000
        val connection = endpoint.toURL().openConnection() as HttpsURLConnection
        try {
            connection.sslSocketFactory = context.socketFactory
            connection.hostnameVerifier = hostnameVerifier
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = timeout
            connection.readTimeout = timeout
            connection.doOutput = true
            connection.requestMethod = "POST"
            connection.setFixedLengthStreamingMode(body.size)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("Connection", "close")
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            if (status !in ProviderRules.allowedStatus) throw TransportException("invalid_response")
            if (connection.contentLengthLong > ProviderRules.MAX_RESPONSE) throw TransportException("oversized")
            val stream = (if (status == HttpURLConnection.HTTP_OK) connection.inputStream else connection.errorStream)
                ?: throw TransportException("invalid_response")
            val bytes = stream.use { input ->
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (out.size() + read > ProviderRules.MAX_RESPONSE) throw TransportException("oversized")
                    out.write(buffer, 0, read)
                }
                out.toByteArray()
            }
            if (!ProviderRules.acceptsResponse(status, connection.contentType,
                    connection.getHeaderField("Content-Encoding"), bytes)) throw TransportException("invalid_response")
            return bytes
        } catch (error: TransportException) {
            throw error
        } catch (_: java.net.SocketTimeoutException) {
            throw TransportException("timeout")
        } catch (_: Exception) {
            // Never surface exception text: it may name hosts, paths or certificates.
            throw TransportException("transport")
        } finally {
            connection.disconnect()
        }
    }
}

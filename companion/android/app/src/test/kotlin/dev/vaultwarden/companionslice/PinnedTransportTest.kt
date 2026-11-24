package dev.vaultwarden.companionslice

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.InetAddress
import java.net.URI
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/**
 * The pinning rule over a real TLS handshake on loopback, with the
 * repository's synthetic identities (`tests/fixtures/provider-tls`: a server
 * leaf for 127.0.0.1 signed by its CA, and an unrelated self-signed
 * replacement; `tests/companion-tls`: the client identity and its CA).
 */
class PinnedTransportTest {
    private val ca = Fixtures.certificate("tests/fixtures/provider-tls/ca.pem")
    private val server = Fixtures.certificate("tests/fixtures/provider-tls/server.pem")
    private val replacement = Fixtures.certificate("tests/fixtures/provider-tls/replacement.pem")
    private val pin = Wire.hex(Wire.sha256(server.encoded))
    private val identity = FixedKeyManager(
        Fixtures.rsaKey("tests/companion-tls/client-key.pem"),
        arrayOf(Fixtures.certificate("tests/companion-tls/client.pem")),
    )
    private var socket: SSLServerSocket? = null
    private val requests = AtomicInteger()

    @After fun close() {
        socket?.close()
    }

    /** One-connection-at-a-time HTTPS server requiring the companion client certificate. */
    private fun serve(
        leaf: Pair<String, String> = "tests/fixtures/provider-tls/server.pem" to "tests/fixtures/provider-tls/server-key.pem",
        response: String,
    ): URI {
        val keys = KeyStore.getInstance("PKCS12").apply {
            load(null)
            setKeyEntry("server", Fixtures.rsaKey(leaf.second), STORE_PASSWORD, arrayOf(Fixtures.certificate(leaf.first)))
        }
        val clientCa = KeyStore.getInstance("PKCS12").apply {
            load(null)
            setCertificateEntry("ca", Fixtures.certificate("tests/companion-tls/ca.pem"))
        }
        val context = SSLContext.getInstance("TLS").apply {
            init(
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keys, STORE_PASSWORD) }.keyManagers,
                TrustManagerFactory.getInstance("PKIX").apply { init(clientCa) }.trustManagers,
                null,
            )
        }
        val listener = context.serverSocketFactory.createServerSocket(0, 4, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        listener.needClientAuth = true
        socket = listener
        thread(isDaemon = true) {
            while (!listener.isClosed) {
                try {
                    listener.accept().use { connection ->
                        val input = connection.getInputStream()
                        val head = StringBuilder()
                        while (!head.endsWith("\r\n\r\n")) {
                            val next = input.read()
                            if (next < 0) throw java.io.EOFException()
                            head.append(next.toChar())
                        }
                        val length = Regex("Content-Length: (\\d+)", RegexOption.IGNORE_CASE).find(head)!!.groupValues[1].toInt()
                        repeat(length) { input.read() }
                        requests.incrementAndGet()
                        connection.getOutputStream().apply { write(response.toByteArray()); flush() }
                    }
                } catch (_: Exception) {
                    // A refused handshake ends that connection only.
                }
            }
        }
        return URI("https://127.0.0.1:${listener.localPort}/v1/companion")
    }

    private fun http(status: String, body: String, type: String = "application/json") =
        "HTTP/1.1 $status\r\nContent-Type: $type\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"

    private fun transport(endpoint: URI, anchor: java.security.cert.X509Certificate = ca, leafPin: String = pin) =
        PinnedTransport(endpoint, PinnedTrustManager(anchor, leafPin), identity)

    private fun failure(block: () -> Unit): String = try {
        block()
        fail("expected a transport failure")
        ""
    } catch (error: TransportException) {
        error.code
    }

    @Test fun thePinnedProviderAnswers() {
        val endpoint = serve(response = http("200 OK", """{"version":1}"""))
        assertArrayEquals("""{"version":1}""".toByteArray(), transport(endpoint).send("""{"version":1,"command":"list"}""".toByteArray()))
        assertEquals(1, requests.get())
    }

    @Test fun aValidChainWithAnotherLeafIsRefused() {
        val endpoint = serve(response = http("200 OK", "{}"))
        assertEquals("transport", failure { transport(endpoint, leafPin = "00".repeat(32)).send("{}".toByteArray()) })
        assertEquals("no request reaches a server that failed the pin", 0, requests.get())
    }

    @Test fun thePinAloneIsNotEnough() {
        // The replacement's own pin, but it does not chain to the configured CA.
        val endpoint = serve(
            "tests/fixtures/provider-tls/replacement.pem" to "tests/fixtures/provider-tls/replacement-key.pem",
            http("200 OK", "{}"),
        )
        val replacementPin = Wire.hex(Wire.sha256(replacement.encoded))
        assertEquals("transport", failure { transport(endpoint, leafPin = replacementPin).send("{}".toByteArray()) })
        assertEquals(0, requests.get())
    }

    @Test fun onlyTheConfiguredAnchorIsTrusted() {
        // The CA-signed server, its correct pin, but another configured anchor:
        // nothing else (platform store, user CAs) can stand in for the CA.
        val endpoint = serve(response = http("200 OK", "{}"))
        assertEquals("transport", failure { transport(endpoint, anchor = replacement).send("{}".toByteArray()) })
        assertEquals(0, requests.get())
        assertTrue(PinnedTrustManager(ca, pin).acceptedIssuers.isEmpty())
    }

    @Test fun malformedOrRedirectedResponsesAreRefused() {
        for (response in listOf(
            http("500 Internal Server Error", "{}"),
            http("302 Found", "{}"),
            http("200 OK", """{"error":"stale"}"""),
            http("409 Conflict", """{"version":1,"error":"unavailable"}"""),
            http("200 OK", "{}", "text/plain"),
        )) {
            socket?.close()
            val endpoint = serve(response = response)
            assertEquals(response, "invalid_response", failure { transport(endpoint).send("{}".toByteArray()) })
        }
        socket?.close()
        val endpoint = serve(response = http("409 Conflict", """{"version":1,"error":"stale"}"""))
        assertArrayEquals("""{"version":1,"error":"stale"}""".toByteArray(), transport(endpoint).send("{}".toByteArray()))
    }

    @Test fun oversizedRequestsNeverLeave() {
        val endpoint = serve(response = http("200 OK", "{}"))
        assertEquals("oversized", failure { transport(endpoint).send(ByteArray(ProviderRules.MAX_REQUEST + 1)) })
        assertEquals(0, requests.get())
    }

    @Test fun pinComparison() {
        assertTrue(PinnedTrustManager.pinMatches(server.encoded, pin))
        assertFalse(PinnedTrustManager.pinMatches(server.encoded, pin.uppercase()))
        assertFalse(PinnedTrustManager.pinMatches(replacement.encoded, pin))
        try {
            PinnedTrustManager(ca, pin).checkServerTrusted(emptyArray(), "RSA")
            fail("an empty chain was trusted")
        } catch (_: java.security.cert.CertificateException) {
        }
    }

    private companion object {
        val STORE_PASSWORD = "synthetic".toCharArray()
    }
}

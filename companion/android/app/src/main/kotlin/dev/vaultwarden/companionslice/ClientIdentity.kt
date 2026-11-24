package dev.vaultwarden.companionslice

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * The client mTLS identity: imported once from a development PKCS#12 into
 * AndroidKeyStore, after which the private key is non-exportable and lives
 * in StrongBox or the TEE (a software-only import is deleted and refused).
 * The PKCS#12 bytes and passphrase are dropped right after the import; only
 * the alias is saved. A Keystore-generated key with a CSR is the enrollment
 * journey's job (#59), not this development path.
 */
object ClientIdentity {
    private const val PROVIDER = "AndroidKeyStore"
    const val ALIAS_PREFIX = "dev.vaultwarden.companion.client-identity."

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** Imports and returns (alias, client leaf SHA-256), or null. */
    fun import(pkcs12: ByteArray, passphrase: String): Pair<String, String>? {
        val password = passphrase.toCharArray()
        try {
            val source = KeyStore.getInstance("PKCS12").apply { load(pkcs12.inputStream(), password) }
            val entries = source.aliases().toList().filter { source.isKeyEntry(it) }
            if (entries.size != 1) return null
            val key = source.getKey(entries[0], password) as? PrivateKey ?: return null
            val chain = source.getCertificateChain(entries[0])?.map { it as X509Certificate }?.toTypedArray()
            if (chain.isNullOrEmpty()) return null
            val fingerprint = Wire.hex(Wire.sha256(chain[0].encoded))
            val alias = ALIAS_PREFIX + fingerprint
            val store = keyStore()
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            var imported = false
            for (strongBox in listOf(true, false)) {
                try {
                    store.setEntry(alias, KeyStore.PrivateKeyEntry(key, chain), protection(strongBox, rsa = key.algorithm == KeyProperties.KEY_ALGORITHM_RSA))
                    imported = true
                    break
                } catch (_: StrongBoxUnavailableException) {
                    continue
                } catch (_: java.security.KeyStoreException) {
                    // Some devices report a missing StrongBox import path this way.
                    if (!strongBox) return null
                }
            }
            if (!imported || !hardwareBacked(alias)) {
                runCatching { store.deleteEntry(alias) }
                return null
            }
            return alias to fingerprint
        } catch (_: Exception) {
            return null
        } finally {
            password.fill('\u0000')
        }
    }

    private fun protection(strongBox: Boolean, rsa: Boolean): KeyProtection =
        KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            // TLS client authentication signs with the stack's own digest choice.
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
            .apply {
                // Signature paddings are RSA-only; an EC key is imported without them.
                if (rsa) setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            }
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()

    private fun hardwareBacked(alias: String): Boolean {
        val key = keyStore().getKey(alias, null) as? PrivateKey ?: return false
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        return if (android.os.Build.VERSION.SDK_INT >= 31) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        } else {
            @Suppress("DEPRECATION") info.isInsideSecureHardware
        }
    }

    fun keyManager(alias: String): FixedKeyManager? = try {
        val entry = keyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        entry?.let { FixedKeyManager(it.privateKey, it.certificateChain.map { c -> c as X509Certificate }.toTypedArray()) }
    } catch (_: Exception) {
        null
    }

    fun fingerprint(alias: String): String? = try {
        (keyStore().getCertificate(alias) as? X509Certificate)?.let { Wire.hex(Wire.sha256(it.encoded)) }
    } catch (_: Exception) {
        null
    }
}

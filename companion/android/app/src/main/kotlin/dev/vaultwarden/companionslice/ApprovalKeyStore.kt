package dev.vaultwarden.companionslice

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The production approval key: a non-exportable AndroidKeyStore P-256 key in
 * StrongBox (else the TEE), one per [ApprovalBinding], usable only for one
 * signature per BIOMETRIC_STRONG authentication and invalidated by a new
 * biometric enrollment. Every method here runs off the main thread and never
 * prompts; the prompt is `ApprovalKeyChannel`'s, bound to the `Signature`
 * that [prepare] returns.
 */
object ApprovalKeyStore {
    private const val PROVIDER = "AndroidKeyStore"

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    sealed class Lookup {
        class Found(val key: PrivateKey, val publicKey: ByteArray) : Lookup()
        class Failure(val reply: KeyReply) : Lookup()
    }

    fun lookup(binding: ApprovalBinding): Lookup {
        try {
            val store = keyStore()
            if (!store.containsAlias(binding.alias)) return Lookup.Failure(KeyReply(KeyOutcome.absent))
            val entry = store.getEntry(binding.alias, null) as? KeyStore.PrivateKeyEntry
                ?: return Lookup.Failure(KeyReply(KeyOutcome.unsafe))
            val public = entry.certificate?.publicKey as? ECPublicKey
                ?: return Lookup.Failure(KeyReply(KeyOutcome.unsafe))
            val sec1 = SignatureEncoding.sec1(public) ?: return Lookup.Failure(KeyReply(KeyOutcome.unsafe))
            // Only a hardware, generated, per-use biometric key may sign.
            if (!KeyAttributePolicy.admits(facts(entry.privateKey))) return Lookup.Failure(KeyReply(KeyOutcome.unsafe))
            return Lookup.Found(entry.privateKey, sec1)
        } catch (_: Exception) {
            return Lookup.Failure(KeyReply(KeyOutcome.failed))
        }
    }

    fun facts(key: PrivateKey): KeyFacts {
        val info = KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
        val level = if (android.os.Build.VERSION.SDK_INT >= 31) {
            info.securityLevel
        } else {
            // API 30 has no security level; StrongBox is not distinguishable.
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeyProps.SECURITY_LEVEL_TRUSTED_ENVIRONMENT else KeyProps.SECURITY_LEVEL_SOFTWARE
        }
        return KeyFacts(
            securityLevel = level,
            origin = info.origin,
            purposes = info.purposes,
            keySize = info.keySize,
            userAuthenticationRequired = info.isUserAuthenticationRequired,
            authenticationEnforcedBySecureHardware = info.isUserAuthenticationRequirementEnforcedBySecureHardware,
            authenticationValiditySeconds = info.userAuthenticationValidityDurationSeconds,
            authenticators = info.userAuthenticationType,
            invalidatedByBiometricEnrollment = info.isInvalidatedByBiometricEnrollment,
            validWhileOnBody = info.isUserAuthenticationValidWhileOnBody,
        )
    }

    /** A Signature ready for one authenticated operation, or the reason there is none. */
    private fun initSign(key: PrivateKey): Pair<Signature?, KeyReply?> = try {
        Signature.getInstance("SHA256withECDSA").apply { initSign(key) } to null
    } catch (_: KeyPermanentlyInvalidatedException) {
        // A biometric was enrolled (or all removed) since the key was created.
        null to KeyReply(KeyOutcome.invalidated)
    } catch (_: Exception) {
        null to KeyReply(KeyOutcome.failed)
    }

    fun read(binding: ApprovalBinding): KeyReply = when (val found = lookup(binding)) {
        is Lookup.Failure -> found.reply
        is Lookup.Found -> initSign(found.key).second ?: KeyReply(KeyOutcome.present, found.publicKey)
    }

    /** Refuses when a key exists: replacing one is an explicit delete first. */
    fun create(binding: ApprovalBinding, biometricAvailable: Boolean): KeyReply {
        if (!biometricAvailable) return KeyReply(KeyOutcome.unavailable)
        return try {
            if (keyStore().containsAlias(binding.alias)) return KeyReply(KeyOutcome.refused)
            var generated = false
            for (spec in ApprovalKeySpec.preferred) {
                try {
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
                        initialize(parameters(binding.alias, spec))
                    }.generateKeyPair()
                    generated = true
                    break
                } catch (_: StrongBoxUnavailableException) {
                    continue
                }
            }
            if (!generated) return KeyReply(KeyOutcome.unavailable)
            when (val found = lookup(binding)) {
                is Lookup.Found -> KeyReply(KeyOutcome.created, found.publicKey)
                is Lookup.Failure -> {
                    // Never leave a key that does not meet the policy behind.
                    runCatching { keyStore().deleteEntry(binding.alias) }
                    KeyReply(if (found.reply.outcome == KeyOutcome.failed) KeyOutcome.failed else KeyOutcome.unsafe)
                }
            }
        } catch (_: Exception) {
            KeyReply(KeyOutcome.failed)
        }
    }

    fun delete(binding: ApprovalBinding): KeyReply = try {
        keyStore().deleteEntry(binding.alias)
        KeyReply(KeyOutcome.deleted)
    } catch (_: Exception) {
        KeyReply(KeyOutcome.failed)
    }

    fun parameters(alias: String, spec: ApprovalKeySpec): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, spec.purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec(spec.curve))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(spec.userAuthenticationRequired)
            .setUserAuthenticationParameters(spec.authenticationValiditySeconds, spec.authenticators)
            .setInvalidatedByBiometricEnrollment(spec.invalidatedByBiometricEnrollment)
            .setUnlockedDeviceRequired(spec.unlockedDeviceRequired)
            .setIsStrongBoxBacked(spec.strongBox)
            .build()

    class Prepared(val signature: Signature, val publicKey: ByteArray)

    /** Checks the key and the transcript, then initialises the Signature the prompt will authorise. */
    fun prepare(binding: ApprovalBinding, purpose: ApprovalPurpose, transcript: ByteArray): Pair<Prepared?, KeyReply?> {
        val found = when (val lookup = lookup(binding)) {
            is Lookup.Failure -> return null to lookup.reply
            is Lookup.Found -> lookup
        }
        if (!ApprovalTranscript.admits(transcript, purpose, binding, found.publicKey)) {
            return null to KeyReply(KeyOutcome.refused)
        }
        val (signature, failure) = initSign(found.key)
        return if (signature == null) null to failure else Prepared(signature, found.publicKey) to null
    }

    /**
     * The one operation the authentication admitted. [authorized] must be the
     * `Signature` BiometricPrompt returned in its `CryptoObject`.
     */
    fun complete(binding: ApprovalBinding, purpose: ApprovalPurpose, transcript: ByteArray,
                 prepared: Prepared, authorized: Signature): KeyReply {
        if (authorized !== prepared.signature) return KeyReply(KeyOutcome.refused)
        if (!ApprovalTranscript.admits(transcript, purpose, binding, prepared.publicKey)) return KeyReply(KeyOutcome.refused)
        return try {
            authorized.update(transcript)
            val der = authorized.sign()
            if (!SignatureEncoding.isStrictDer(der) || !verifies(prepared.publicKey, transcript, der)) {
                KeyReply(KeyOutcome.failed)
            } else {
                KeyReply(KeyOutcome.signed, prepared.publicKey, der)
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            KeyReply(KeyOutcome.invalidated)
        } catch (_: Exception) {
            KeyReply(KeyOutcome.failed)
        }
    }

    private fun verifies(publicKey: ByteArray, transcript: ByteArray, der: ByteArray): Boolean = try {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(Sec1.publicKey(publicKey))
            update(transcript)
            verify(der)
        }
    } catch (_: Exception) {
        false
    }
}

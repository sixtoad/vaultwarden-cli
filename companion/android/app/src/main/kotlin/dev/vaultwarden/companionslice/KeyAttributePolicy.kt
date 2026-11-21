package dev.vaultwarden.companionslice

/**
 * The approval key's required Keystore attributes, kept free of android.*
 * so JVM unit tests pin them. `ApprovalKeyStore` maps [ApprovalKeySpec] onto a
 * `KeyGenParameterSpec` and reads a generated key back into [KeyFacts]; a key
 * whose facts [KeyAttributePolicy.admits] refuses is reported `unsafe` and
 * never signs.
 *
 * Numeric values are `android.security.keystore.KeyProperties` constants
 * (pinned against the real ones by `KeyAttributePolicyAndroidTest`).
 */
object KeyProps {
    const val PURPOSE_SIGN = 4
    const val AUTH_DEVICE_CREDENTIAL = 1
    const val AUTH_BIOMETRIC_STRONG = 2
    const val SECURITY_LEVEL_SOFTWARE = 0
    const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
    const val SECURITY_LEVEL_STRONGBOX = 2
    const val ORIGIN_GENERATED = 1
}

/**
 * Generation request. Per-use authentication: validity 0 with BIOMETRIC_STRONG
 * only means the Keystore admits exactly one operation per authentication, and
 * only the `Signature` passed to BiometricPrompt as its `CryptoObject`.
 *
 * Device credential (PIN/pattern/password) is deliberately NOT an allowed
 * authenticator, matching the macOS key (no passcode fallback): it is not
 * invalidated by biometric enrollment and is easier to observe than a
 * biometric. The companion's explicit password approval is the fallback.
 */
data class ApprovalKeySpec(
    val curve: String = "secp256r1",
    val digest: String = "SHA-256",
    val purposes: Int = KeyProps.PURPOSE_SIGN,
    val userAuthenticationRequired: Boolean = true,
    val authenticationValiditySeconds: Int = 0,
    val authenticators: Int = KeyProps.AUTH_BIOMETRIC_STRONG,
    val invalidatedByBiometricEnrollment: Boolean = true,
    val unlockedDeviceRequired: Boolean = true,
    val strongBox: Boolean,
) {
    companion object {
        /** StrongBox first; TEE only when the device has no StrongBox. */
        val preferred = listOf(ApprovalKeySpec(strongBox = true), ApprovalKeySpec(strongBox = false))
    }
}

/** What `KeyInfo` reports for a stored key. */
data class KeyFacts(
    val securityLevel: Int,
    val origin: Int,
    val purposes: Int,
    val keySize: Int,
    val userAuthenticationRequired: Boolean,
    val authenticationEnforcedBySecureHardware: Boolean,
    val authenticationValiditySeconds: Int,
    val authenticators: Int,
    val invalidatedByBiometricEnrollment: Boolean,
    val validWhileOnBody: Boolean,
)

object KeyAttributePolicy {
    /** Only a hardware-backed, generated, per-use biometric P-256 signing key. */
    fun admits(facts: KeyFacts): Boolean =
        (facts.securityLevel == KeyProps.SECURITY_LEVEL_STRONGBOX ||
            facts.securityLevel == KeyProps.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) &&
            facts.origin == KeyProps.ORIGIN_GENERATED &&
            facts.purposes == KeyProps.PURPOSE_SIGN &&
            facts.keySize == 256 &&
            facts.userAuthenticationRequired &&
            facts.authenticationEnforcedBySecureHardware &&
            facts.authenticationValiditySeconds == 0 &&
            facts.authenticators == KeyProps.AUTH_BIOMETRIC_STRONG &&
            facts.invalidatedByBiometricEnrollment &&
            !facts.validWhileOnBody
}

/** Native outcomes; the names are the Dart `KeyOutcome` names. */
enum class KeyOutcome { present, absent, created, deleted, signed, invalidated, cancelled, unavailable, refused, failed, unsafe }

class KeyReply(val outcome: KeyOutcome, val publicKey: ByteArray = ByteArray(0), val signature: ByteArray = ByteArray(0)) {
    /** The closed reply schema `parseKeyReply` accepts: exactly these three entries. */
    fun encode(): Map<String, Any> = mapOf("outcome" to outcome.name, "publicKey" to publicKey, "signature" to signature)
}

/**
 * BiometricPrompt error codes (`androidx.biometric.BiometricPrompt.ERROR_*`,
 * pinned by `KeyAttributePolicyAndroidTest`). No error ever approves: the
 * reply carries no signature, and Dart never falls back to a password
 * submission on its own.
 */
object AuthErrors {
    const val ERROR_HW_UNAVAILABLE = 1
    const val ERROR_UNABLE_TO_PROCESS = 2
    const val ERROR_TIMEOUT = 3
    const val ERROR_NO_SPACE = 4
    const val ERROR_CANCELED = 5
    const val ERROR_LOCKOUT = 7
    const val ERROR_VENDOR = 8
    const val ERROR_LOCKOUT_PERMANENT = 9
    const val ERROR_USER_CANCELED = 10
    const val ERROR_NO_BIOMETRICS = 11
    const val ERROR_HW_NOT_PRESENT = 12
    const val ERROR_NEGATIVE_BUTTON = 13
    const val ERROR_NO_DEVICE_CREDENTIAL = 14
    const val ERROR_SECURITY_UPDATE_REQUIRED = 15

    fun classify(code: Int): KeyOutcome = when (code) {
        ERROR_CANCELED, ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON, ERROR_TIMEOUT -> KeyOutcome.cancelled
        ERROR_HW_UNAVAILABLE, ERROR_HW_NOT_PRESENT, ERROR_LOCKOUT, ERROR_LOCKOUT_PERMANENT,
        ERROR_NO_BIOMETRICS, ERROR_NO_DEVICE_CREDENTIAL, ERROR_SECURITY_UPDATE_REQUIRED -> KeyOutcome.unavailable
        else -> KeyOutcome.failed
    }
}

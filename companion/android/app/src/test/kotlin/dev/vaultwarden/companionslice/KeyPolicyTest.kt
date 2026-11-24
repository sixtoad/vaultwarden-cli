package dev.vaultwarden.companionslice

import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class KeyPolicyTest {
    private val good = KeyFacts(
        securityLevel = KeyProps.SECURITY_LEVEL_STRONGBOX,
        origin = KeyProps.ORIGIN_GENERATED,
        purposes = KeyProps.PURPOSE_SIGN,
        keySize = 256,
        userAuthenticationRequired = true,
        authenticationEnforcedBySecureHardware = true,
        authenticationValiditySeconds = 0,
        authenticators = KeyProps.AUTH_BIOMETRIC_STRONG,
        invalidatedByBiometricEnrollment = true,
        validWhileOnBody = false,
    )

    @Test fun constantsAreTheAndroidOnes() {
        // Compile-time constants: these compare the real SDK values on the JVM.
        assertEquals(KeyProperties.PURPOSE_SIGN, KeyProps.PURPOSE_SIGN)
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, KeyProps.AUTH_BIOMETRIC_STRONG)
        assertEquals(KeyProperties.AUTH_DEVICE_CREDENTIAL, KeyProps.AUTH_DEVICE_CREDENTIAL)
        assertEquals(KeyProperties.SECURITY_LEVEL_SOFTWARE, KeyProps.SECURITY_LEVEL_SOFTWARE)
        assertEquals(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProps.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
        assertEquals(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProps.SECURITY_LEVEL_STRONGBOX)
        assertEquals(KeyProperties.ORIGIN_GENERATED, KeyProps.ORIGIN_GENERATED)
        assertEquals(BiometricPrompt.ERROR_CANCELED, AuthErrors.ERROR_CANCELED)
        assertEquals(BiometricPrompt.ERROR_USER_CANCELED, AuthErrors.ERROR_USER_CANCELED)
        assertEquals(BiometricPrompt.ERROR_NEGATIVE_BUTTON, AuthErrors.ERROR_NEGATIVE_BUTTON)
        assertEquals(BiometricPrompt.ERROR_TIMEOUT, AuthErrors.ERROR_TIMEOUT)
        assertEquals(BiometricPrompt.ERROR_LOCKOUT, AuthErrors.ERROR_LOCKOUT)
        assertEquals(BiometricPrompt.ERROR_LOCKOUT_PERMANENT, AuthErrors.ERROR_LOCKOUT_PERMANENT)
        assertEquals(BiometricPrompt.ERROR_NO_BIOMETRICS, AuthErrors.ERROR_NO_BIOMETRICS)
        assertEquals(BiometricPrompt.ERROR_HW_NOT_PRESENT, AuthErrors.ERROR_HW_NOT_PRESENT)
        assertEquals(BiometricPrompt.ERROR_HW_UNAVAILABLE, AuthErrors.ERROR_HW_UNAVAILABLE)
        assertEquals(BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL, AuthErrors.ERROR_NO_DEVICE_CREDENTIAL)
        assertEquals(BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED, AuthErrors.ERROR_SECURITY_UPDATE_REQUIRED)
        assertEquals(BiometricPrompt.ERROR_VENDOR, AuthErrors.ERROR_VENDOR)
        assertEquals(BiometricPrompt.ERROR_UNABLE_TO_PROCESS, AuthErrors.ERROR_UNABLE_TO_PROCESS)
        assertEquals(BiometricPrompt.ERROR_NO_SPACE, AuthErrors.ERROR_NO_SPACE)
    }

    @Test fun theGenerationSpecIsPerUseStrongBiometricOnly() {
        val specs = ApprovalKeySpec.preferred
        assertEquals(listOf(true, false), specs.map { it.strongBox })
        for (spec in specs) {
            assertEquals("secp256r1", spec.curve)
            assertEquals(KeyProps.PURPOSE_SIGN, spec.purposes)
            assertTrue(spec.userAuthenticationRequired)
            assertEquals("one operation per authentication", 0, spec.authenticationValiditySeconds)
            assertEquals("no device-credential fallback", KeyProps.AUTH_BIOMETRIC_STRONG, spec.authenticators)
            assertTrue(spec.invalidatedByBiometricEnrollment)
            assertTrue(spec.unlockedDeviceRequired)
        }
    }

    @Test fun onlyAHardwarePerUseBiometricKeyIsAdmitted() {
        assertTrue(KeyAttributePolicy.admits(good))
        assertTrue(KeyAttributePolicy.admits(good.copy(securityLevel = KeyProps.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)))
        // API 30 may report -1 for the per-use key generated with validity 0
        // (to confirm on a real API 30 device); both are one operation per authentication.
        assertTrue(KeyAttributePolicy.admits(good.copy(authenticationValiditySeconds = -1)))
        val refused = listOf(
            good.copy(securityLevel = KeyProps.SECURITY_LEVEL_SOFTWARE),
            good.copy(securityLevel = -2), // unknown secure
            good.copy(origin = 2), // imported
            good.copy(purposes = KeyProps.PURPOSE_SIGN or 8),
            good.copy(keySize = 384),
            good.copy(userAuthenticationRequired = false),
            good.copy(authenticationEnforcedBySecureHardware = false),
            good.copy(authenticationValiditySeconds = 1),
            good.copy(authenticationValiditySeconds = 30),
            good.copy(authenticators = KeyProps.AUTH_BIOMETRIC_STRONG or KeyProps.AUTH_DEVICE_CREDENTIAL),
            good.copy(authenticators = KeyProps.AUTH_DEVICE_CREDENTIAL),
            good.copy(invalidatedByBiometricEnrollment = false),
            good.copy(validWhileOnBody = true),
        )
        refused.forEach { assertFalse(it.toString(), KeyAttributePolicy.admits(it)) }
    }

    @Test fun noPromptErrorApproves() {
        for (code in -1..20) {
            val outcome = AuthErrors.classify(code)
            assertTrue("$code -> $outcome", outcome in setOf(KeyOutcome.cancelled, KeyOutcome.unavailable, KeyOutcome.failed))
        }
        assertEquals(KeyOutcome.cancelled, AuthErrors.classify(AuthErrors.ERROR_USER_CANCELED))
        assertEquals(KeyOutcome.cancelled, AuthErrors.classify(AuthErrors.ERROR_NEGATIVE_BUTTON))
        assertEquals(KeyOutcome.unavailable, AuthErrors.classify(AuthErrors.ERROR_LOCKOUT))
        assertEquals(KeyOutcome.failed, AuthErrors.classify(AuthErrors.ERROR_VENDOR))
    }

    @Test fun repliesUseTheClosedSchema() {
        val encoded = KeyReply(KeyOutcome.cancelled).encode()
        assertEquals(setOf("outcome", "publicKey", "signature"), encoded.keys)
        assertEquals("cancelled", encoded["outcome"])
        assertArrayEquals(ByteArray(0), encoded["signature"] as ByteArray)
    }

    @Test fun sec1RoundTripsAGeneratedKey() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair().public as ECPublicKey
        val sec1 = SignatureEncoding.sec1(key)!!
        assertEquals(65, sec1.size)
        assertEquals(0x04.toByte(), sec1[0])
        assertEquals(key.w, Sec1.publicKey(sec1).w)
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }
            .generateKeyPair().public as ECPublicKey
        assertNull(SignatureEncoding.sec1(p384))
    }

    @Test fun derMustBeStrict() {
        val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        fun int(value: ByteArray) = byteArrayOf(0x02, value.size.toByte()) + value
        fun seq(vararg parts: ByteArray): ByteArray {
            val body = parts.fold(ByteArray(0)) { a, b -> a + b }
            return byteArrayOf(0x30, body.size.toByte()) + body
        }
        val one = byteArrayOf(1)
        assertTrue(SignatureEncoding.isStrictDer(seq(int(one), int(one))))
        assertTrue(SignatureEncoding.isStrictDer(seq(int(byteArrayOf(0, 0x80.toByte())), int(one))))
        val nMinusOne = n.subtract(BigInteger.ONE).toByteArray()
        assertTrue(SignatureEncoding.isStrictDer(seq(int(nMinusOne), int(nMinusOne))))
        val rejected = listOf(
            seq(int(byteArrayOf(0)), int(one)), // zero
            seq(int(byteArrayOf(0x80.toByte())), int(one)), // negative
            seq(int(byteArrayOf(0, 1)), int(one)), // not minimal
            seq(int(n.toByteArray()), int(one)), // r = n
            seq(int(one), int(one)) + byteArrayOf(0), // trailing
            seq(int(one)), // one integer
            byteArrayOf(0x31, 6) + int(one) + int(one), // not a sequence
            seq(int(one), int(one), int(one)), // three integers
        )
        rejected.forEachIndexed { index, bytes -> assertFalse("case $index", SignatureEncoding.isStrictDer(bytes)) }
        assertFalse(SignatureEncoding.isStrictDer(ByteArray(73)))
    }
}

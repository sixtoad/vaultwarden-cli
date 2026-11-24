package dev.vaultwarden.companionslice

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Signature

/** The v2 transcript rules against `tests/fixtures/approval-v2-golden.json`. */
class ApprovalTranscriptTest {
    private val approval = Fixtures.golden.getJSONObject("approval")
    private val enroll = Fixtures.golden.getJSONObject("enroll")
    private val publicKey = Fixtures.base64url(Fixtures.golden.getString("public_key"))
    private val binding = ApprovalBinding.of(approval.getString("provider_identity"), approval.getString("approval_client"))!!
    private val approvalTranscript = Fixtures.hex(approval.getString("transcript_hex"))
    private val enrollTranscript = Fixtures.hex(enroll.getString("transcript_hex"))

    private fun frame(fields: List<ByteArray>): ByteArray = fields.fold(ByteArray(0)) { out, field ->
        out + byteArrayOf((field.size ushr 24).toByte(), (field.size ushr 16).toByte(), (field.size ushr 8).toByte(), field.size.toByte()) + field
    }

    private fun replaced(transcript: ByteArray, index: Int, value: ByteArray): ByteArray =
        frame(ApprovalTranscript.fields(transcript)!!.toMutableList().also { it[index] = value })

    @Test fun goldenPublicKeyIdIsTheFixtureKeyId() {
        assertEquals(approval.getString("key_id"), Wire.hex(Wire.sha256(publicKey)))
        assertEquals(65, publicKey.size)
    }

    @Test fun goldenApprovalIsAdmittedAndItsSignatureVerifies() {
        assertTrue(ApprovalTranscript.admits(approvalTranscript, ApprovalPurpose.approve, binding, publicKey))
        val der = Fixtures.base64url(approval.getString("signature"))
        assertTrue(SignatureEncoding.isStrictDer(der))
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(Sec1.publicKey(publicKey))
            update(approvalTranscript)
        }
        assertTrue("the Keystore signs the transcript bytes, not a digest", verifier.verify(der))
    }

    @Test fun goldenEnrollmentIsAdmittedAndItsSignatureVerifies() {
        assertTrue(ApprovalTranscript.admits(enrollTranscript, ApprovalPurpose.enroll, binding, publicKey))
        val der = Fixtures.base64url(enroll.getString("signature"))
        assertTrue(SignatureEncoding.isStrictDer(der))
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(Sec1.publicKey(publicKey))
            update(enrollTranscript)
        }
        assertTrue(verifier.verify(der))
    }

    @Test fun purposesAreNotInterchangeable() {
        assertFalse(ApprovalTranscript.admits(approvalTranscript, ApprovalPurpose.enroll, binding, publicKey))
        assertFalse(ApprovalTranscript.admits(enrollTranscript, ApprovalPurpose.approve, binding, publicKey))
    }

    @Test fun anotherProviderClientOrKeyIsRefused() {
        val otherProvider = ApprovalBinding.of("00".repeat(32), approval.getString("approval_client"))!!
        val otherClient = ApprovalBinding.of(approval.getString("provider_identity"), "00".repeat(32))!!
        val otherKey = publicKey.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        for (purpose in ApprovalPurpose.entries) {
            val transcript = if (purpose == ApprovalPurpose.approve) approvalTranscript else enrollTranscript
            assertFalse(ApprovalTranscript.admits(transcript, purpose, otherProvider, publicKey))
            assertFalse(ApprovalTranscript.admits(transcript, purpose, otherClient, publicKey))
            assertFalse(ApprovalTranscript.admits(transcript, purpose, binding, otherKey))
        }
    }

    @Test fun everyApprovalFieldIsChecked() {
        // domain, action, provider, client, key id, request id (size), then fixed sizes.
        val wrong = listOf(
            0 to "dev.vaultwarden.companion.synthetic.v1".toByteArray(),
            1 to "deny".toByteArray(),
            2 to ByteArray(32),
            3 to ByteArray(32),
            4 to ByteArray(32),
            5 to ByteArray(42),
        ) + (6..13).map { it to ByteArray(31) }
        for ((index, value) in wrong) {
            assertFalse("field $index", ApprovalTranscript.admits(replaced(approvalTranscript, index, value),
                ApprovalPurpose.approve, binding, publicKey))
        }
    }

    @Test fun framingMustBeExact() {
        assertNull(ApprovalTranscript.fields(approvalTranscript + byteArrayOf(0)))
        assertNull(ApprovalTranscript.fields(approvalTranscript.copyOf(approvalTranscript.size - 1)))
        assertNull(ApprovalTranscript.fields(byteArrayOf(0, 0, 0, 9, 1)))
        assertNull(ApprovalTranscript.fields(frame(List(33) { ByteArray(0) })))
        val extra = frame(ApprovalTranscript.fields(approvalTranscript)!! + listOf(ByteArray(1)))
        assertNotNull(ApprovalTranscript.fields(extra))
        assertFalse(ApprovalTranscript.admits(extra, ApprovalPurpose.approve, binding, publicKey))
        assertFalse(ApprovalTranscript.admits(approvalTranscript + ByteArray(ApprovalTranscript.MAX_BYTES), ApprovalPurpose.approve, binding, publicKey))
    }

    @Test fun bindingsAreLowercaseHexAndTheAliasMatchesTheMacOSTag() {
        assertNull(ApprovalBinding.of("1F".repeat(32), "2e".repeat(32)))
        assertNull(ApprovalBinding.of("1f".repeat(31), "2e".repeat(32)))
        val expected = ApprovalBinding.ALIAS_PREFIX + Wire.hex(Wire.sha256(Fixtures.hex("1f".repeat(32)), Fixtures.hex("2e".repeat(32))))
        assertEquals(expected, binding.alias)
        assertArrayEquals(Fixtures.hex("1f".repeat(32)), binding.providerIdentity)
    }
}

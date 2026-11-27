package dev.vaultwarden.companionslice

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The native signer guard against the shared admission vectors
 * (`companion/fixtures/approval-v2-admission.json`, generated and checked by
 * the Rust reference `companion/rust/tests/admission_vectors.rs`). Signature
 * encoding and verification are Rust's (shared-approval-checks-spec S-3).
 */
class ApprovalTranscriptTest {
    private val approval = Fixtures.golden.getJSONObject("approval")
    private val publicKey = Fixtures.base64url(Fixtures.golden.getString("public_key"))
    private val binding = ApprovalBinding.of(approval.getString("provider_identity"), approval.getString("approval_client"))!!

    @Test fun goldenPublicKeyIdIsTheFixtureKeyId() {
        assertEquals(approval.getString("key_id"), Wire.hex(Wire.sha256(publicKey)))
        assertEquals(65, publicKey.size)
    }

    @Test fun everySharedAdmissionVectorGetsTheRustVerdict() {
        val cases = Fixtures.admission.getJSONArray("cases")
        assertTrue("the vectors are not empty", cases.length() > 40)
        var admitted = 0
        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val name = case.getString("name")
            val purpose = ApprovalPurpose.valueOf(case.getString("purpose"))
            val caseBinding = ApprovalBinding.of(case.getString("provider_identity"), case.getString("approval_client"))!!
            val key = Wire.lowerHex(case.getString("public_key_hex"))!!
            val transcript = Wire.lowerHex(case.getString("transcript_hex"))!!
            val expected = case.getBoolean("admitted")
            assertEquals(name, expected, ApprovalTranscript.admits(transcript, purpose, caseBinding, key))
            if (expected) admitted++
        }
        assertEquals("only the golden transcripts and their sized-field variants", 4, admitted)
    }

    @Test fun bindingsAreLowercaseHexAndTheAliasMatchesTheMacOSTag() {
        assertNull(ApprovalBinding.of("1F".repeat(32), "2e".repeat(32)))
        assertNull(ApprovalBinding.of("1f".repeat(31), "2e".repeat(32)))
        val expected = ApprovalBinding.ALIAS_PREFIX + Wire.hex(Wire.sha256(Fixtures.hex("1f".repeat(32)), Fixtures.hex("2e".repeat(32))))
        assertEquals(expected, ApprovalBinding.of("1f".repeat(32), "2e".repeat(32))!!.alias)
        assertArrayEquals(Wire.lowerHex(approval.getString("provider_identity")), binding.providerIdentity)
    }
}

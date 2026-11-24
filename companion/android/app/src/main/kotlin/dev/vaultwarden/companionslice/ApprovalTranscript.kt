package dev.vaultwarden.companionslice

import java.security.MessageDigest

/** Wire helpers shared with the Swift adapters (`Protocol.swift`). */
object Wire {
    fun validHex(value: String, count: Int): Boolean =
        value.length == count && value.all { it in '0'..'9' || it in 'a'..'f' }

    /** 43 base64url characters: a request or action id. */
    fun validRequestId(value: String): Boolean =
        value.length == 43 && value.all { it in '0'..'9' || it in 'A'..'Z' || it in 'a'..'z' || it == '-' || it == '_' }

    fun lowerHex(value: String): ByteArray? {
        if (value.length % 2 != 0 || !value.all { it in '0'..'9' || it in 'a'..'f' }) return null
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        parts.forEach { digest.update(it) }
        return digest.digest()
    }
}

enum class ApprovalPurpose { approve, enroll }

/**
 * One Keystore key per (provider identity, approval client): the SHA-256 pins
 * of the provider TLS leaf and of this device's client mTLS leaf. A provider
 * certificate rotation or a new client identity selects another key, which
 * must be enrolled again. Mirrors `ProductionBinding` in
 * `ProductionApprovalContract.swift`.
 */
class ApprovalBinding private constructor(val providerIdentity: ByteArray, val approvalClient: ByteArray) {
    /** AndroidKeyStore alias; disjoint from the client-identity alias prefix. */
    val alias: String
        get() = ALIAS_PREFIX + Wire.hex(Wire.sha256(providerIdentity, approvalClient))

    override fun equals(other: Any?): Boolean = other is ApprovalBinding &&
        providerIdentity.contentEquals(other.providerIdentity) && approvalClient.contentEquals(other.approvalClient)

    override fun hashCode(): Int = providerIdentity.contentHashCode() * 31 + approvalClient.contentHashCode()

    companion object {
        const val ALIAS_PREFIX = "dev.vaultwarden.companion.approval-v2.key."

        fun of(providerHex: String, clientHex: String): ApprovalBinding? {
            if (!Wire.validHex(providerHex, 64) || !Wire.validHex(clientHex, 64)) return null
            return ApprovalBinding(Wire.lowerHex(providerHex)!!, Wire.lowerHex(clientHex)!!)
        }
    }
}

/**
 * Production approval v2 transcripts (`docs/companion-protocol.md`,
 * `tests/fixtures/approval-v2-golden.json`). Rust builds every transcript and
 * the provider verifies every proof; this is the native second line of
 * defence, identical to `ProductionTranscript.admits` on macOS: the key signs
 * only a well-formed transcript bound to its own provider, client and key.
 */
object ApprovalTranscript {
    val approvalDomain = "dev.vaultwarden.provider.approval.v2".toByteArray(Charsets.US_ASCII)
    val enrollDomain = "dev.vaultwarden.provider.approval-enroll.v2".toByteArray(Charsets.US_ASCII)
    const val MAX_BYTES = 4096

    /** Splits 4-byte big-endian length framing; null on short or trailing bytes. */
    fun fields(data: ByteArray): List<ByteArray>? {
        val fields = mutableListOf<ByteArray>()
        var index = 0
        while (index < data.size) {
            if (data.size - index < 4) return null
            var length = 0L
            for (i in 0 until 4) length = (length shl 8) or (data[index + i].toLong() and 0xff)
            index += 4
            if (length > data.size - index) return null
            fields.add(data.copyOfRange(index, index + length.toInt()))
            index += length.toInt()
            if (fields.size > 32) return null
        }
        return fields
    }

    /** Whether the key bound to [binding], whose SEC1 point is [publicKey], may sign [transcript]. */
    fun admits(transcript: ByteArray, purpose: ApprovalPurpose, binding: ApprovalBinding, publicKey: ByteArray): Boolean {
        if (transcript.size > MAX_BYTES || publicKey.size != 65 || publicKey[0] != 0x04.toByte()) return false
        val f = fields(transcript) ?: return false
        return when (purpose) {
            ApprovalPurpose.approve -> {
                // record, policy, arguments, expiry, generation, ticket, deadline, review
                val sizes = intArrayOf(32, 32, 32, 8, 8, 32, 8, 32)
                f.size == 14 &&
                    f[0].contentEquals(approvalDomain) && f[1].contentEquals("approve".toByteArray()) &&
                    f[2].contentEquals(binding.providerIdentity) && f[3].contentEquals(binding.approvalClient) &&
                    f[4].contentEquals(Wire.sha256(publicKey)) && f[5].size == 43 &&
                    sizes.indices.all { f[6 + it].size == sizes[it] }
            }
            ApprovalPurpose.enroll -> f.size == 6 &&
                f[0].contentEquals(enrollDomain) &&
                f[1].contentEquals(binding.providerIdentity) && f[2].contentEquals(binding.approvalClient) &&
                f[3].contentEquals(publicKey) && f[4].size == 32 && f[5].size == 43
        }
    }
}

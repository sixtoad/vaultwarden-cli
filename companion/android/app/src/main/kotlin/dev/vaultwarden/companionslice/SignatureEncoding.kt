package dev.vaultwarden.companionslice

import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/**
 * The public key encoding the companion protocol fixes: a 65-byte
 * uncompressed SEC1 P-256 point. The signature (ASN.1 DER ECDSA P-256, as
 * AndroidKeyStore `SHA256withECDSA` returns it) is checked and verified once,
 * in Rust (shared-approval-checks-spec S-3), not here.
 */
object SignatureEncoding {
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val fieldPrime = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)

    /** 0x04 || X || Y for a P-256 key, or null for any other key. */
    fun sec1(key: ECPublicKey): ByteArray? {
        if (key.params.curve.field.fieldSize != 256 || key.params.order != order) return null
        val x = fixed(key.w.affineX) ?: return null
        val y = fixed(key.w.affineY) ?: return null
        return byteArrayOf(0x04) + x + y
    }

    private fun fixed(value: BigInteger): ByteArray? {
        if (value.signum() < 0 || value >= fieldPrime) return null
        val raw = value.toByteArray().let { if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it }
        if (raw.size > 32) return null
        return ByteArray(32 - raw.size) + raw
    }
}

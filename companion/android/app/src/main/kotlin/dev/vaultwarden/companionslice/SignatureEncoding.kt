package dev.vaultwarden.companionslice

import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/**
 * Encodings the companion protocol fixes: a 65-byte uncompressed SEC1 public
 * point and an ASN.1 DER ECDSA P-256 signature of at most 72 bytes.
 * AndroidKeyStore `SHA256withECDSA` already returns DER; this checks it is
 * strict DER before it leaves the native side, as `parseKeyReply` does in Dart.
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

    /** Strict DER `SEQUENCE { INTEGER r, INTEGER s }` with 1 <= r, s < n. */
    fun isStrictDer(signature: ByteArray): Boolean {
        if (signature.size < 8 || signature.size > 72) return false
        if (signature[0] != 0x30.toByte() || (signature[1].toInt() and 0xff) != signature.size - 2) return false
        var index = 2
        repeat(2) {
            if (index + 2 > signature.size || signature[index] != 0x02.toByte()) return false
            val length = signature[index + 1].toInt() and 0xff
            index += 2
            if (length < 1 || length > 33 || index + length > signature.size) return false
            val bytes = signature.copyOfRange(index, index + length)
            if ((bytes[0].toInt() and 0x80) != 0) return false // negative
            if (length > 1 && bytes[0] == 0.toByte() && (bytes[1].toInt() and 0x80) == 0) return false // not minimal
            val value = BigInteger(1, bytes)
            if (value.signum() == 0 || value >= order) return false
            index += length
        }
        return index == signature.size
    }
}

/** P-256 public keys from their 65-byte uncompressed SEC1 encoding. */
object Sec1 {
    private val params: java.security.spec.ECParameterSpec by lazy {
        java.security.AlgorithmParameters.getInstance("EC").run {
            init(java.security.spec.ECGenParameterSpec("secp256r1"))
            getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        }
    }

    fun publicKey(sec1: ByteArray): ECPublicKey {
        require(sec1.size == 65 && sec1[0] == 0x04.toByte())
        val point = java.security.spec.ECPoint(BigInteger(1, sec1.copyOfRange(1, 33)), BigInteger(1, sec1.copyOfRange(33, 65)))
        return java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.ECPublicKeySpec(point, params)) as ECPublicKey
    }
}

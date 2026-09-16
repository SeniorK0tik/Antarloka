package org.syncmob.mobile.security

import org.syncmob.mobile.crypto.Noise
import java.math.BigInteger

/**
 * Human-verifiable representations of keys.
 *
 * These must stay byte-for-byte identical to `desktop/src/security/fingerprint.rs`:
 * if the two sides derived the pairing code differently, users would be told to
 * compare codes that never match.
 */
object Fingerprints {
    private val DOMAIN_ID = "SyncMob/1 device-id".toByteArray(Charsets.US_ASCII)
    private val DOMAIN_FP = "SyncMob/1 fingerprint".toByteArray(Charsets.US_ASCII)
    private val DOMAIN_SAS = "SyncMob/1 sas".toByteArray(Charsets.US_ASCII)
    private val DOMAIN_SUBKEY = "SyncMob/1 subkey".toByteArray(Charsets.US_ASCII)

    /** Short stable handle. A hash of the key, never used for authentication. */
    fun deviceId(publicKey: ByteArray): String =
        hex(Noise.hash(DOMAIN_ID, publicKey).copyOfRange(0, 8))

    /** 128 bits as eight uppercase hex groups. */
    fun fingerprint(publicKey: ByteArray): String {
        val d = Noise.hash(DOMAIN_FP, publicKey)
        return (0 until 8).joinToString(" ") { i ->
            String.format("%02X%02X", d[i * 2], d[i * 2 + 1])
        }
    }

    /**
     * Eight decimal digits derived from the Noise handshake hash.
     *
     * The handshake hash commits to both static keys, both ephemeral keys and
     * the prologue, so two sessions (as a machine-in-the-middle must run)
     * produce different codes.
     */
    fun sasCode(handshakeHash: ByteArray): String {
        val d = Noise.hash(DOMAIN_SAS, handshakeHash)
        val v = BigInteger(1, d.copyOfRange(0, 8)).mod(BigInteger.valueOf(100_000_000L)).toLong()
        return String.format("%04d %04d", v / 10_000, v % 10_000)
    }

    /** Independent subkey derived from the identity private key. */
    fun deriveSubkey(privateKey: ByteArray, domain: String): ByteArray {
        val d = domain.toByteArray(Charsets.US_ASCII)
        val len = byteArrayOf(
            (d.size ushr 24).toByte(),
            (d.size ushr 16).toByte(),
            (d.size ushr 8).toByte(),
            d.size.toByte(),
        )
        return Noise.hash(DOMAIN_SUBKEY, len, d, privateKey)
    }

    fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x))
        return sb.toString()
    }

    fun unhex(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = s.substring(i * 2, i * 2 + 2).toIntOrNull(16)?.toByte() ?: return null
        }
        return out
    }
}

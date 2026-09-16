package org.syncmob.mobile

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.syncmob.mobile.crypto.Noise
import org.syncmob.mobile.security.Fingerprints

/**
 * Byte-for-byte agreement with the desktop module.
 *
 * Every constant below was produced by the Rust side and pinned here:
 *
 *     cd desktop && cargo test --test noise_reference --no-default-features \
 *         print_vectors -- --ignored --nocapture
 *
 * If a primitive ever drifts — a different BLAKE2s variant, a different HMAC
 * block size, an X25519 clamping difference — these tests fail here instead of
 * producing two devices that can never complete a handshake or that show users
 * pairing codes which never match.
 */
class CrossImplementationVectorsTest {

    private fun hex(b: ByteArray): String = Fingerprints.hex(b)

    private fun unhex(s: String): ByteArray = Fingerprints.unhex(s)!!

    @Test
    fun blake2s256_matches_the_published_vectors() {
        // The empty-input digest is also the value published with BLAKE2.
        assertEquals(
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            hex(Noise.hash(ByteArray(0))),
        )
        assertEquals(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            hex(Noise.hash("abc".toByteArray())),
        )
    }

    @Test
    fun protocol_name_hash_matches() {
        assertEquals(
            "1ceedd81c5f458b225923dc2507787bf156f9251fc17c45af63263a929fc1ed2",
            hex(Noise.hash(Noise.PROTOCOL_NAME.toByteArray(Charsets.US_ASCII))),
        )
    }

    @Test
    fun hmac_blake2s_matches() {
        assertEquals(
            "3d0cc9066036e0205928edfb169860d20dc0781d0a6d54ec42ade80579925e0b",
            hex(Noise.hmac(ByteArray(32) { 1 }, ByteArray(16) { 2 })),
        )
    }

    @Test
    fun noise_hkdf_matches() {
        val (o1, o2) = Noise.hkdf2(ByteArray(32) { 3 }, ByteArray(32) { 4 })
        assertEquals("a93d5be13b51cebd70afe0846bbef4585b1919a8fe10df0a34c35bf43974a63a", hex(o1))
        assertEquals("ceab18f92361dc2b68435147751d943530c85cc9f33f0003919bc07463e2c47e", hex(o2))
    }

    @Test
    fun x25519_matches() {
        val a = ByteArray(32) { 5 }
        val b = ByteArray(32) { 6 }
        assertEquals(
            "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d",
            hex(Noise.publicKeyOf(a)),
        )
        assertEquals(
            "f5b2d6e60f9477e310c2982daaa6c9136c108a1777c5947e448fa37d68174557",
            hex(Noise.publicKeyOf(b)),
        )
        val shared = "edfa360a9633ca9b6fe655be8849389323ae3a3444866567f463c8e2c80bbb5a"
        assertEquals(shared, hex(Noise.dh(a, Noise.publicKeyOf(b))))
        // Diffie-Hellman is symmetric; both ends must land on the same secret.
        assertEquals(shared, hex(Noise.dh(b, Noise.publicKeyOf(a))))
    }

    @Test
    fun device_id_and_fingerprint_match() {
        val pk = ByteArray(32) { 7 }
        assertEquals("caa7b2340f5e3283", Fingerprints.deviceId(pk))
        assertEquals("4BB0 BFBF 3E51 1937 3A86 682B A602 2DB9", Fingerprints.fingerprint(pk))
    }

    @Test
    fun pairing_code_matches() {
        // Both sides derive this from the Noise handshake hash; if the two
        // implementations disagreed, users would be asked to compare codes that
        // never match and pairing would be impossible.
        assertEquals("7395 0192", Fingerprints.sasCode(ByteArray(32) { 0x11 }))
    }

    @Test
    fun subkey_derivation_is_domain_separated() {
        val priv = ByteArray(32) { 9 }
        val a = Fingerprints.deriveSubkey(priv, "trust-store")
        val b = Fingerprints.deriveSubkey(priv, "other")
        assertEquals(32, a.size)
        assertArrayEquals(a, Fingerprints.deriveSubkey(priv, "trust-store"))
        org.junit.Assert.assertFalse(a.contentEquals(b))
        org.junit.Assert.assertFalse(a.contentEquals(Fingerprints.deriveSubkey(ByteArray(32) { 8 }, "trust-store")))
    }

    @Test
    fun hex_helpers_round_trip() {
        val b = ByteArray(32) { it.toByte() }
        assertArrayEquals(b, unhex(hex(b)))
        org.junit.Assert.assertNull(Fingerprints.unhex("nothex!!"))
        org.junit.Assert.assertNull(Fingerprints.unhex("abc"))
    }
}

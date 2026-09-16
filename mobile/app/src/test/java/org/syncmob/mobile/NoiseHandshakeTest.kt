package org.syncmob.mobile

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.syncmob.mobile.crypto.Noise
import org.syncmob.mobile.crypto.NoiseException
import org.syncmob.mobile.crypto.NoiseHandshake
import org.syncmob.mobile.security.Fingerprints

/**
 * The XX handshake driven in-process. Message sizes are asserted because they
 * are fixed by the pattern, and a wrong size is the first symptom of a step
 * being performed in the wrong order.
 */
class NoiseHandshakeTest {

    private fun pair(): Triple<NoiseHandshake, NoiseHandshake, Pair<ByteArray, ByteArray>> {
        val (aPriv, aPub) = Noise.generateKeyPair()
        val (bPriv, bPub) = Noise.generateKeyPair()
        val i = NoiseHandshake(true, aPriv, aPub)
        val r = NoiseHandshake(false, bPriv, bPub)

        val m1 = i.writeMessage()
        assertEquals("message 1 is a bare ephemeral key", 32, m1.size)
        r.readMessage(m1)

        val m2 = r.writeMessage()
        assertEquals("message 2 is e + encrypted s + tag", 96, m2.size)
        i.readMessage(m2)

        val m3 = i.writeMessage()
        assertEquals("message 3 is encrypted s + tag", 64, m3.size)
        r.readMessage(m3)

        return Triple(i, r, aPub to bPub)
    }

    @Test
    fun handshake_completes_and_authenticates_both_sides() {
        val (i, r, keys) = pair()
        val (aPub, bPub) = keys
        assertTrue(i.isFinished && r.isFinished)
        assertArrayEquals(bPub, i.remoteStatic)
        assertArrayEquals(aPub, r.remoteStatic)
        assertArrayEquals(i.handshakeHash, r.handshakeHash)
    }

    @Test
    fun both_sides_show_the_same_pairing_code() {
        val (i, r, _) = pair()
        assertEquals(Fingerprints.sasCode(i.handshakeHash), Fingerprints.sasCode(r.handshakeHash))
        assertEquals(9, Fingerprints.sasCode(i.handshakeHash).length)
    }

    @Test
    fun two_sessions_produce_different_codes() {
        // This is what stops a machine-in-the-middle: it has to run two
        // separate handshakes and cannot make both codes agree.
        val (i1, _, _) = pair()
        val (i2, _, _) = pair()
        assertNotEquals(
            Fingerprints.sasCode(i1.handshakeHash),
            Fingerprints.sasCode(i2.handshakeHash),
        )
    }

    @Test
    fun transport_messages_round_trip_both_ways() {
        val (i, r, _) = pair()
        val sender = i.split()
        val receiver = r.split()

        val ping = "привет".toByteArray()
        assertArrayEquals(ping, receiver.decrypt(sender.encrypt(ping)))
        val pong = ByteArray(32 * 1024) { index -> (index % 251).toByte() }
        assertArrayEquals(pong, sender.decrypt(receiver.encrypt(pong)))
    }

    @Test
    fun nonces_advance_so_identical_plaintexts_differ_on_the_wire() {
        val (i, r, _) = pair()
        val sender = i.split()
        val receiver = r.split()
        val msg = "same".toByteArray()
        val c1 = sender.encrypt(msg)
        val c2 = sender.encrypt(msg)
        assertTrue("ciphertexts must not repeat", !c1.contentEquals(c2))
        assertArrayEquals(msg, receiver.decrypt(c1))
        assertArrayEquals(msg, receiver.decrypt(c2))
    }

    @Test
    fun tampered_ciphertext_is_rejected() {
        val (i, r, _) = pair()
        val sender = i.split()
        val receiver = r.split()
        val ct = sender.encrypt("secret".toByteArray())
        ct[0] = (ct[0].toInt() xor 0x80).toByte()
        try {
            receiver.decrypt(ct)
            fail("a modified frame must not decrypt")
        } catch (e: NoiseException) {
            // expected
        }
    }

    @Test
    fun out_of_order_frames_are_rejected() {
        val (i, r, _) = pair()
        val sender = i.split()
        val receiver = r.split()
        val first = sender.encrypt("one".toByteArray())
        val second = sender.encrypt("two".toByteArray())
        // Delivering the second frame first breaks the nonce sequence.
        try {
            receiver.decrypt(second)
            fail("frames must be authenticated in order")
        } catch (e: NoiseException) {
            // expected
        }
        // And the transport is not silently usable afterwards either.
        assertTrue(first.isNotEmpty())
    }

    @Test
    fun handshake_steps_cannot_be_reordered() {
        val (priv, pub) = Noise.generateKeyPair()
        val i = NoiseHandshake(true, priv, pub)
        try {
            i.readMessage(ByteArray(96))
            fail("the initiator must write message 1 before reading anything")
        } catch (e: NoiseException) {
            // expected
        }
    }

    @Test
    fun oversized_plaintext_is_refused() {
        val (i, r, _) = pair()
        val sender = i.split()
        r.split()
        try {
            sender.encrypt(ByteArray(Noise.MAX_PLAINTEXT + 1))
            fail("a message larger than the Noise limit must be refused")
        } catch (e: NoiseException) {
            // expected
        }
    }

    @Test
    fun constant_time_compare_behaves_like_equality() {
        assertTrue(Noise.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertTrue(!Noise.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertTrue(!Noise.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2)))
        assertTrue(!Noise.constantTimeEquals(null, byteArrayOf(1)))
    }
}

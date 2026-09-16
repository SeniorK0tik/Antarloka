package org.syncmob.mobile

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.syncmob.mobile.proto.Beacon
import org.syncmob.mobile.proto.Message
import org.syncmob.mobile.proto.PairingUri
import org.syncmob.mobile.proto.Proto
import org.syncmob.mobile.proto.ProtocolException
import org.syncmob.mobile.proto.TransferId
import java.util.Base64

class ProtocolTest {

    @Test
    fun text_round_trips() {
        val id = TransferId.random()
        val encoded = Message.Text(id, 42L, "привет, мир").encode()
        val decoded = Message.decode(encoded)
        assertTrue(decoded is Message.Text)
        decoded as Message.Text
        assertEquals("привет, мир", decoded.text)
        assertEquals(42L, decoded.ts)
        assertEquals(id, decoded.id)
    }

    @Test
    fun file_chunk_round_trips_as_binary() {
        val id = TransferId.random()
        val data = ByteArray(Proto.CHUNK_SIZE) { (it % 251).toByte() }
        val encoded = Message.FileChunk(id, 4096L, data).encode()
        // One type byte + 16 id + 8 offset + payload, with no base64 inflation.
        assertEquals(1 + 16 + 8 + data.size, encoded.size)
        val decoded = Message.decode(encoded) as Message.FileChunk
        assertEquals(4096L, decoded.offset)
        assertEquals(id, decoded.id)
        assertArrayEquals(data, decoded.data)
    }

    @Test
    fun file_offer_round_trips() {
        val id = TransferId.random()
        val sha = "a".repeat(64)
        val decoded = Message.decode(
            Message.FileOffer(id, "отчёт.pdf", 1234L, sha, "application/pdf").encode(),
        ) as Message.FileOffer
        assertEquals("отчёт.pdf", decoded.name)
        assertEquals(1234L, decoded.size)
        assertEquals(sha, decoded.sha256)
    }

    @Test
    fun oversized_text_is_rejected() {
        val encoded = Message.Text(TransferId.random(), 0, "a".repeat(Proto.MAX_TEXT_CHARS + 1))
            .encode()
        try {
            Message.decode(encoded)
            fail("text longer than the limit must be refused")
        } catch (e: ProtocolException) {
            // expected
        }
    }

    @Test
    fun malformed_offers_are_rejected() {
        // Bad hash.
        try {
            Message.decode(Message.FileOffer(TransferId.random(), "a", 1, "zz").encode())
            fail("a non-hex digest must be refused")
        } catch (e: ProtocolException) {
        }
        // Size beyond the hard ceiling.
        try {
            Message.decode(
                Message.FileOffer(
                    TransferId.random(), "a", Proto.MAX_FILE_SIZE + 1, "a".repeat(64),
                ).encode(),
            )
            fail("an absurd size must be refused")
        } catch (e: ProtocolException) {
        }
    }

    @Test
    fun garbage_is_rejected_without_crashing() {
        for (bad in listOf(
            ByteArray(0),
            byteArrayOf(0xEE.toByte(), 1, 2, 3),
            byteArrayOf(Proto.TY_TEXT, '{'.code.toByte()),
            byteArrayOf(Proto.TY_FILE_CHUNK, 1, 2, 3),
        )) {
            try {
                Message.decode(bad)
                fail("malformed frame accepted: ${bad.toList()}")
            } catch (e: ProtocolException) {
                // expected
            }
        }
    }

    @Test
    fun unpaired_peers_may_only_send_handshake_level_messages() {
        assertFalse(Message.Text(TransferId.random(), 0, "x").allowedBeforePairing())
        assertFalse(Message.FileChunk(TransferId.random(), 0, ByteArray(1)).allowedBeforePairing())
        assertFalse(Message.FileOffer(TransferId.random(), "a", 1, "a".repeat(64)).allowedBeforePairing())
        assertTrue(Message.Ping.allowedBeforePairing())
        assertTrue(Message.PairAccept.allowedBeforePairing())
        assertTrue(Message.Hello("n", 1, "android").allowedBeforePairing())
    }

    @Test
    fun beacon_round_trips_and_rejects_junk() {
        val pk = ByteArray(32) { 9 }
        val raw = Beacon(pk, "Мой телефон", 45821, "android").encode()
        assertTrue(raw.size <= Proto.MAX_BEACON_BYTES)
        val parsed = Beacon.parse(raw, raw.size)!!
        assertArrayEquals(pk, parsed.publicKey)
        assertEquals(45821, parsed.port)

        assertNull(Beacon.parse("not json".toByteArray(), 8))
        assertNull(Beacon.parse(ByteArray(0), 0))
        assertNull(Beacon.parse(raw, Proto.MAX_BEACON_BYTES + 1))
        // Wrong key length must be refused, not truncated or padded.
        val shortKey = Beacon(ByteArray(16), "x", 1, "android").encode()
        assertNull(Beacon.parse(shortKey, shortKey.size))
    }

    @Test
    fun long_names_are_clamped() {
        val raw = Beacon(ByteArray(32), "n".repeat(300), 45821, "android").encode()
        val parsed = Beacon.parse(raw, raw.size)!!
        assertTrue(parsed.name.length <= 33)
    }

    @Test
    fun pairing_uri_is_parsed_strictly() {
        val pk = ByteArray(32) { 3 }
        val uri = "syncmob://pair?v=1&pk=" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(pk) +
            "&port=45821&host=192.168.1.7&name=%D0%9F%D0%9A"
        val target = PairingUri.parse(uri)!!
        assertArrayEquals(pk, target.publicKey)
        assertEquals(45821, target.port)
        assertEquals("192.168.1.7", target.host)
        assertEquals("ПК", target.name)

        assertNull(PairingUri.parse("https://evil.example/pair?pk=AAAA"))
        assertNull(PairingUri.parse("syncmob://pair?host=192.168.1.7"))
        // A truncated key must fail rather than be padded out.
        val short = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16))
        assertNull(PairingUri.parse("syncmob://pair?pk=$short&host=10.0.0.1"))
    }

    @Test
    fun transfer_ids_are_distinct_and_round_trip() {
        val a = TransferId.random()
        val b = TransferId.random()
        assertFalse(a == b)
        assertEquals(a, TransferId.parse(a.hex()))
        assertNull(TransferId.parse("abcd"))
        assertEquals(32, a.hex().length)
    }
}

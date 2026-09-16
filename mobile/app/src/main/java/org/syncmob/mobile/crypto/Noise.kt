package org.syncmob.mobile.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * Noise_XX_25519_ChaChaPoly_BLAKE2s.
 *
 * This is a line-by-line translation of the reference implementation in
 * `desktop/tests/noise_reference.rs`, which is tested against the `snow` crate
 * used by the desktop module in both the initiator and the responder role. Do
 * not "clean up" the ordering of operations here: the order of `mixHash`,
 * `mixKey` and `encryptAndHash` calls is the protocol.
 *
 * Bouncy Castle is used through the lightweight API only, so no JCA provider is
 * registered and nothing clashes with the platform's own copy.
 */
object Noise {
    const val PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
    val PROLOGUE: ByteArray = "SyncMob/1".toByteArray(Charsets.US_ASCII)

    const val HASH_LEN = 32
    const val KEY_LEN = 32
    const val TAG_LEN = 16
    /** Noise caps one transport message at 65535 bytes. */
    const val MAX_MESSAGE = 65535
    const val MAX_PLAINTEXT = MAX_MESSAGE - TAG_LEN

    private val rng = SecureRandom()

    // ---- primitives ----------------------------------------------------

    fun hash(vararg parts: ByteArray): ByteArray {
        val d = Blake2sDigest(256)
        for (p in parts) d.update(p, 0, p.size)
        val out = ByteArray(HASH_LEN)
        d.doFinal(out, 0)
        return out
    }

    /**
     * HMAC-BLAKE2s-256 (RFC 2104), written out rather than taken from a
     * library so that it provably matches the verified Rust reference.
     * BLAKE2s has a 64 byte block.
     */
    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val block = 64
        val k = ByteArray(block)
        if (key.size > block) {
            System.arraycopy(hash(key), 0, k, 0, HASH_LEN)
        } else {
            System.arraycopy(key, 0, k, 0, key.size)
        }
        val ipad = ByteArray(block) { (0x36 xor k[it].toInt()).toByte() }
        val opad = ByteArray(block) { (0x5c xor k[it].toInt()).toByte() }
        val inner = hash(ipad, data)
        return hash(opad, inner)
    }

    /** Noise's two-output HKDF. */
    fun hkdf2(ck: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val temp = hmac(ck, ikm)
        val o1 = hmac(temp, byteArrayOf(1))
        val o2 = hmac(temp, o1 + byteArrayOf(2))
        return o1 to o2
    }

    /**
     * X25519. Bouncy Castle rejects all-zero outputs (small subgroup points),
     * which is exactly the check the Noise specification requires.
     */
    fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(privateKey.size == KEY_LEN && publicKey.size == KEY_LEN) { "bad key length" }
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(privateKey, 0))
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(publicKey, 0), out, 0)
        return out
    }

    fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(rng))
        val kp = gen.generateKeyPair()
        val priv = (kp.private as X25519PrivateKeyParameters).encoded
        val pub = (kp.public as X25519PublicKeyParameters).encoded
        return priv to pub
    }

    fun publicKeyOf(privateKey: ByteArray): ByteArray =
        X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().encoded

    /** Comparison that does not leak where two keys differ. */
    fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean {
        if (a == null || b == null || a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}

class NoiseException(message: String) : Exception(message)

/**
 * One direction of a Noise cipher: a key plus a strictly increasing nonce.
 * Not thread safe by itself; [NoiseTransport] serialises access.
 */
class CipherState {
    private var k: ByteArray? = null
    private var n: Long = 0

    fun initializeKey(key: ByteArray?) {
        k = key
        n = 0
    }

    fun hasKey(): Boolean = k != null

    /** 96-bit nonce: 32 zero bits followed by the counter, little-endian. */
    private fun nonce(): ByteArray {
        val b = ByteArray(12)
        var v = n
        for (i in 0 until 8) {
            b[4 + i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
        return b
    }

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val key = k ?: return plaintext
        if (n == -1L) throw NoiseException("nonce exhausted, reconnect required")
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), 128, nonce(), ad))
        val out = ByteArray(c.getOutputSize(plaintext.size))
        var len = c.processBytes(plaintext, 0, plaintext.size, out, 0)
        len += c.doFinal(out, len)
        n++
        return if (len == out.size) out else out.copyOf(len)
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val key = k ?: return ciphertext
        if (n == -1L) throw NoiseException("nonce exhausted, reconnect required")
        val c = ChaCha20Poly1305()
        c.init(false, AEADParameters(KeyParameter(key), 128, nonce(), ad))
        val out = ByteArray(c.getOutputSize(ciphertext.size))
        val len = try {
            var l = c.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            l += c.doFinal(out, l)
            l
        } catch (e: Exception) {
            // A failed tag check is fatal: the session is torn down rather than
            // retried, so the nonce is deliberately not advanced.
            throw NoiseException("authentication failed")
        }
        n++
        return if (len == out.size) out else out.copyOf(len)
    }
}

/** Noise's SymmetricState: the running hash `h` and chaining key `ck`. */
class SymmetricState(protocolName: String) {
    var h: ByteArray
        private set
    private var ck: ByteArray
    private val cipher = CipherState()

    init {
        val name = protocolName.toByteArray(Charsets.US_ASCII)
        h = if (name.size <= Noise.HASH_LEN) {
            name.copyOf(Noise.HASH_LEN)
        } else {
            Noise.hash(name)
        }
        ck = h.copyOf()
        cipher.initializeKey(null)
    }

    fun mixHash(data: ByteArray) {
        h = Noise.hash(h, data)
    }

    fun mixKey(input: ByteArray) {
        val (newCk, tempK) = Noise.hkdf2(ck, input)
        ck = newCk
        cipher.initializeKey(tempK)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ct = cipher.encryptWithAd(h, plaintext)
        mixHash(ct)
        return ct
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val pt = cipher.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return pt
    }

    fun split(): Pair<CipherState, CipherState> {
        val (t1, t2) = Noise.hkdf2(ck, ByteArray(0))
        val c1 = CipherState().apply { initializeKey(t1) }
        val c2 = CipherState().apply { initializeKey(t2) }
        return c1 to c2
    }
}

/**
 * The XX handshake: `-> e`, `<- e, ee, s, es`, `-> s, se`.
 *
 * Both parties end up authenticated by their long term key and share a
 * [handshakeHash] that a machine-in-the-middle cannot reproduce on both sides.
 */
class NoiseHandshake(
    private val initiator: Boolean,
    private val staticPrivate: ByteArray,
    private val staticPublic: ByteArray,
) {
    private val sym = SymmetricState(Noise.PROTOCOL_NAME)
    private var ePrivate: ByteArray? = null
    private var ePublic: ByteArray? = null
    private var re: ByteArray? = null

    /** The peer's long term public key, known once message 2 (or 3) is read. */
    var remoteStatic: ByteArray? = null
        private set

    private var step = 0

    val handshakeHash: ByteArray get() = sym.h
    val isFinished: Boolean get() = step >= 3

    init {
        require(staticPrivate.size == 32 && staticPublic.size == 32) { "bad static key" }
        sym.mixHash(Noise.PROLOGUE)
    }

    private fun generateEphemeral() {
        val (priv, pub) = Noise.generateKeyPair()
        ePrivate = priv
        ePublic = pub
    }

    fun writeMessage(payload: ByteArray = ByteArray(0)): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        when {
            initiator && step == 0 -> {
                // -> e
                generateEphemeral()
                val e = ePublic!!
                sym.mixHash(e)
                out.write(e)
                out.write(sym.encryptAndHash(payload))
            }
            !initiator && step == 1 -> {
                // <- e, ee, s, es
                generateEphemeral()
                val e = ePublic!!
                sym.mixHash(e)
                out.write(e)
                sym.mixKey(Noise.dh(ePrivate!!, re!!))            // ee
                out.write(sym.encryptAndHash(staticPublic))        // s
                sym.mixKey(Noise.dh(staticPrivate, re!!))          // es (responder side)
                out.write(sym.encryptAndHash(payload))
            }
            initiator && step == 2 -> {
                // -> s, se
                out.write(sym.encryptAndHash(staticPublic))        // s
                sym.mixKey(Noise.dh(staticPrivate, re!!))          // se (initiator side)
                out.write(sym.encryptAndHash(payload))
            }
            else -> throw NoiseException("writeMessage out of order at step $step")
        }
        step++
        return out.toByteArray()
    }

    fun readMessage(message: ByteArray): ByteArray {
        val payload: ByteArray
        when {
            !initiator && step == 0 -> {
                // -> e
                if (message.size < 32) throw NoiseException("short handshake message 1")
                val peerE = message.copyOfRange(0, 32)
                sym.mixHash(peerE)
                re = peerE
                payload = sym.decryptAndHash(message.copyOfRange(32, message.size))
            }
            initiator && step == 1 -> {
                // <- e, ee, s, es
                if (message.size < 32 + 48) throw NoiseException("short handshake message 2")
                val peerE = message.copyOfRange(0, 32)
                sym.mixHash(peerE)
                re = peerE
                sym.mixKey(Noise.dh(ePrivate!!, peerE))            // ee
                val rs = sym.decryptAndHash(message.copyOfRange(32, 80))
                if (rs.size != 32) throw NoiseException("bad remote static key")
                remoteStatic = rs
                sym.mixKey(Noise.dh(ePrivate!!, rs))               // es (initiator side)
                payload = sym.decryptAndHash(message.copyOfRange(80, message.size))
            }
            !initiator && step == 2 -> {
                // -> s, se
                if (message.size < 48) throw NoiseException("short handshake message 3")
                val rs = sym.decryptAndHash(message.copyOfRange(0, 48))
                if (rs.size != 32) throw NoiseException("bad remote static key")
                remoteStatic = rs
                sym.mixKey(Noise.dh(ePrivate!!, rs))               // se (responder side)
                payload = sym.decryptAndHash(message.copyOfRange(48, message.size))
            }
            else -> throw NoiseException("readMessage out of order at step $step")
        }
        step++
        return payload
    }

    /** Derive the transport keys. Only valid once all three messages are done. */
    fun split(): NoiseTransport {
        if (!isFinished) throw NoiseException("handshake not finished")
        val (c1, c2) = sym.split()
        return if (initiator) NoiseTransport(c1, c2) else NoiseTransport(c2, c1)
    }
}

/** Post-handshake cipher pair. Safe to use from a reader and a writer thread. */
class NoiseTransport(private val sending: CipherState, private val receiving: CipherState) {
    private val sendLock = Any()
    private val recvLock = Any()

    fun encrypt(plaintext: ByteArray): ByteArray = synchronized(sendLock) {
        if (plaintext.size > Noise.MAX_PLAINTEXT) throw NoiseException("message too large")
        sending.encryptWithAd(ByteArray(0), plaintext)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray = synchronized(recvLock) {
        receiving.decryptWithAd(ByteArray(0), ciphertext)
    }
}

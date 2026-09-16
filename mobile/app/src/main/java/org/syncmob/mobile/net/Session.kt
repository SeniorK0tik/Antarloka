package org.syncmob.mobile.net

import org.syncmob.mobile.crypto.Identity
import org.syncmob.mobile.crypto.NoiseException
import org.syncmob.mobile.crypto.NoiseHandshake
import org.syncmob.mobile.crypto.NoiseTransport
import org.syncmob.mobile.proto.Message
import org.syncmob.mobile.proto.Proto
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * The Noise XX handshake and the framed encrypted channel on top of it.
 *
 * The handshake yields three things the layers above depend on: forward-secret
 * cipher states, the peer's long term public key ([SecureSession.remoteStatic])
 * that the trust store authorises or refuses, and the handshake hash that both
 * honest parties compute identically — the input to the pairing code.
 */
object Handshake {
    /** A stalled handshake is a held-open slot; keep the window short. */
    const val HANDSHAKE_TIMEOUT_MS = 10_000
    /** Three missed 30 s keepalives close the connection. */
    const val IO_TIMEOUT_MS = 100_000
    /** XX messages are at most 96 bytes; refuse more before allocating. */
    private const val MAX_HANDSHAKE_MSG = 1024

    fun initiator(socket: Socket, identity: Identity): SecureSession =
        run(socket, identity, isInitiator = true)

    fun responder(socket: Socket, identity: Identity): SecureSession =
        run(socket, identity, isInitiator = false)

    private fun run(socket: Socket, identity: Identity, isInitiator: Boolean): SecureSession {
        socket.soTimeout = HANDSHAKE_TIMEOUT_MS
        socket.tcpNoDelay = true
        val input = DataInputStream(socket.getInputStream().buffered())
        val output = DataOutputStream(socket.getOutputStream().buffered())

        val hs = NoiseHandshake(isInitiator, identity.privateKey, identity.publicKey)
        if (isInitiator) {
            writeFrame(output, hs.writeMessage())          // -> e
            hs.readMessage(readFrame(input, MAX_HANDSHAKE_MSG))  // <- e, ee, s, es
            writeFrame(output, hs.writeMessage())          // -> s, se
        } else {
            hs.readMessage(readFrame(input, MAX_HANDSHAKE_MSG))  // -> e
            writeFrame(output, hs.writeMessage())          // <- e, ee, s, es
            hs.readMessage(readFrame(input, MAX_HANDSHAKE_MSG))  // -> s, se
        }

        val remoteStatic = hs.remoteStatic
            ?: throw NoiseException("peer did not present a static key")
        val hash = hs.handshakeHash
        val transport = hs.split()

        socket.soTimeout = IO_TIMEOUT_MS
        return SecureSession(
            socket = socket,
            input = input,
            output = output,
            transport = transport,
            remoteStatic = remoteStatic,
            handshakeHash = hash,
            weDialed = isInitiator,
        )
    }

    fun writeFrame(output: DataOutputStream, data: ByteArray) {
        if (data.size > Proto.MAX_FRAME) throw IOException("frame too large")
        output.writeInt(data.size)
        output.write(data)
        output.flush()
    }

    fun readFrame(input: DataInputStream, max: Int = Proto.MAX_FRAME): ByteArray {
        val len = input.readInt()
        // Bound the allocation before reading: the length prefix is attacker
        // controlled.
        if (len <= 0 || len > max) throw IOException("bad frame length $len")
        val buf = ByteArray(len)
        input.readFully(buf)
        return buf
    }
}

/**
 * An authenticated, encrypted connection to one peer.
 *
 * [send] holds a single lock across encryption *and* the socket write, so
 * frames always reach the wire in the order their Noise nonces were assigned,
 * even when a file transfer and a chat message are sent from different threads.
 */
class SecureSession(
    private val socket: Socket,
    private val input: DataInputStream,
    private val output: DataOutputStream,
    private val transport: NoiseTransport,
    /** Authenticated by Noise, but not yet authorised — that is the trust store's job. */
    val remoteStatic: ByteArray,
    /** Binds this exact session; the pairing code is derived from it. */
    val handshakeHash: ByteArray,
    val weDialed: Boolean,
) {
    private val writeLock = Any()

    @Volatile
    var isClosed: Boolean = false
        private set

    val remoteAddress: InetSocketAddress
        get() = socket.remoteSocketAddress as? InetSocketAddress
            ?: InetSocketAddress(socket.inetAddress, socket.port)

    fun send(message: Message) {
        if (isClosed) throw IOException("session closed")
        val plaintext = message.encode()
        synchronized(writeLock) {
            Handshake.writeFrame(output, transport.encrypt(plaintext))
        }
    }

    /** Blocks until one message arrives. Called from a single reader thread. */
    fun receive(): Message {
        val frame = Handshake.readFrame(input)
        if (frame.size < 16) throw IOException("frame shorter than the AEAD tag")
        return Message.decode(transport.decrypt(frame))
    }

    fun close() {
        isClosed = true
        runCatching { socket.close() }
    }
}

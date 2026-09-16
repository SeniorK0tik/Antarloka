package org.syncmob.mobile.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.syncmob.mobile.crypto.Identity
import org.syncmob.mobile.crypto.Noise
import org.syncmob.mobile.net.Discovery
import org.syncmob.mobile.net.Handshake
import org.syncmob.mobile.net.SecureSession
import org.syncmob.mobile.proto.Message
import org.syncmob.mobile.proto.PairingUri
import org.syncmob.mobile.proto.Proto
import org.syncmob.mobile.proto.TransferId
import org.syncmob.mobile.security.Fingerprints
import org.syncmob.mobile.security.TrustStore
import org.syncmob.mobile.util.SafeFiles
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Orchestration: listener, dialer, pairing state machine and transfers.
 *
 * Authorisation rule, enforced in exactly one place ([onMessage]): a peer whose
 * static key is not in the trust store may send only the handful of messages
 * listed in [Message.allowedBeforePairing]. Text and files from an unpaired
 * peer are dropped and the connection closed. The desktop module enforces the
 * same rule independently on its end.
 */
class Engine(private val context: Context, val identity: Identity) {

    // ---- observable state ----------------------------------------------

    data class DeviceView(
        val deviceId: String,
        val name: String,
        val publicKey: ByteArray,
        val fingerprint: String,
        val online: Boolean,
        val connected: Boolean,
        val paired: Boolean,
        val blocked: Boolean,
        val autoAccept: Boolean,
        val address: String?,
    ) {
        override fun equals(other: Any?) = other is DeviceView && deviceId == other.deviceId &&
            name == other.name && online == other.online && connected == other.connected &&
            paired == other.paired && blocked == other.blocked && autoAccept == other.autoAccept

        override fun hashCode() = deviceId.hashCode()
    }

    data class ChatItem(val ts: Long, val mine: Boolean, val text: String, val system: Boolean)

    data class TransferView(
        val id: String,
        val peerId: String,
        val name: String,
        val size: Long,
        val done: Long,
        val incoming: Boolean,
        val finished: Boolean,
        val error: String?,
        val savedTo: String?,
    )

    data class PairPrompt(
        val deviceId: String,
        val name: String,
        val fingerprint: String,
        val sas: String,
        val address: String,
        val remoteInitiated: Boolean,
    )

    data class OfferPrompt(
        val transferId: String,
        val fromDeviceId: String,
        val fromName: String,
        val name: String,
        val size: Long,
    )

    data class LogLine(val ts: Long, val text: String, val level: Level) {
        enum class Level { INFO, GOOD, WARN, ERROR }
    }

    data class State(
        val myDeviceId: String = "",
        val myFingerprint: String = "",
        val hardwareBackedKey: Boolean = true,
        val port: Int = 0,
        val running: Boolean = false,
        val settings: Settings,
        val devices: List<DeviceView> = emptyList(),
        val chats: Map<String, List<ChatItem>> = emptyMap(),
        val transfers: List<TransferView> = emptyList(),
        val pairPrompt: PairPrompt? = null,
        val offerPrompt: OfferPrompt? = null,
        val log: List<LogLine> = emptyList(),
    )

    private val _state = MutableStateFlow(State(settings = Settings.load(context)))
    val state: StateFlow<State> = _state.asStateFlow()

    // ---- internals ------------------------------------------------------

    private class Conn(
        val session: SecureSession,
        val key: ByteArray,
        val fingerprint: String,
        val sas: String,
        @Volatile var name: String,
        @Volatile var authorised: Boolean,
        @Volatile var localOk: Boolean = false,
        @Volatile var remoteOk: Boolean = false,
        @Volatile var promptedAt: Long = 0,
    )

    private class PeerEntry(val peer: Discovery.DiscoveredPeer, @Volatile var lastSeen: Long)

    private val running = AtomicBoolean(false)
    private val conns = ConcurrentHashMap<String, Conn>()
    private val peers = ConcurrentHashMap<String, PeerEntry>()
    private val incoming = ConcurrentHashMap<String, IncomingTransfer>()
    private val outgoing = ConcurrentHashMap<String, OutgoingTransfer>()
    private val finished = ConcurrentHashMap<String, TransferView>()
    private val chats = ConcurrentHashMap<String, MutableList<ChatItem>>()
    private val handshakeGuard = ConnGuard()
    private val logLines = ArrayDeque<LogLine>()

    private var settings: Settings = Settings.load(context)
    private var trust: TrustStore = TrustStore.load(File(context.filesDir, "trust.json"), identity)
    private var server: ServerSocket? = null
    private var discovery: Discovery? = null
    private var boundPort: Int = 0

    @Volatile
    private var pairPrompt: PairPrompt? = null
    private val offerQueue = ArrayDeque<OfferPrompt>()

    // ---- lifecycle ------------------------------------------------------

    fun start() {
        if (!running.compareAndSet(false, true)) return
        startListener()
        startDiscovery()
        startHousekeeping()
        note("SyncMob запущен, порт $boundPort", LogLine.Level.GOOD)
        refresh()
    }

    fun stop() {
        running.set(false)
        discovery?.stop()
        discovery = null
        runCatching { server?.close() }
        server = null
        for (c in conns.values) c.session.close()
        conns.clear()
        for (t in incoming.values) t.abort()
        incoming.clear()
        refresh()
    }

    private fun startListener() {
        val s = try {
            ServerSocket(settings.tcpPort)
        } catch (e: Exception) {
            note("Порт ${settings.tcpPort} занят, выбираем свободный", LogLine.Level.WARN)
            ServerSocket(0)
        }
        server = s
        boundPort = s.localPort
        thread(name = "syncmob-listener", isDaemon = true) {
            while (running.get()) {
                val socket = try {
                    s.accept()
                } catch (e: Exception) {
                    if (running.get()) Log.d(TAG, "accept failed: ${e.message}")
                    break
                }
                if (!admit(socket)) {
                    runCatching { socket.close() }
                    continue
                }
                thread(name = "syncmob-conn", isDaemon = true) {
                    try {
                        val session = Handshake.responder(socket, identity)
                        runConnection(session, expectKey = null)
                    } catch (e: Exception) {
                        Log.d(TAG, "inbound handshake failed: ${e.message}")
                        runCatching { socket.close() }
                    }
                }
            }
        }
    }

    private fun startDiscovery() {
        val d = Discovery(context, identity.publicKey) { onBeacon(it) }
        d.announcedName = settings.deviceName
        d.announcedPort = boundPort
        d.announcing = settings.discoveryEnabled
        d.start()
        discovery = d
    }

    private fun startHousekeeping() {
        thread(name = "syncmob-housekeeping", isDaemon = true) {
            var lastPing = System.currentTimeMillis()
            while (running.get()) {
                Thread.sleep(2_000)
                expirePeers()
                expirePairings()
                val now = System.currentTimeMillis()
                if (now - lastPing >= KEEPALIVE_MS) {
                    lastPing = now
                    for (c in conns.values) runCatching { c.session.send(Message.Ping) }
                }
                refresh()
            }
        }
    }

    private fun admit(socket: Socket): Boolean {
        val addr = socket.inetAddress ?: return false
        if (!settings.acceptIncoming) return false
        if (settings.lanOnly && !SafeFiles.isLanAddress(addr)) {
            note("Отклонено подключение вне локальной сети: ${addr.hostAddress}", LogLine.Level.WARN)
            return false
        }
        if (conns.size >= MAX_CONNECTIONS) return false
        if (!handshakeGuard.allow(addr.hostAddress ?: return false)) {
            note("Слишком много попыток подключения с ${addr.hostAddress}", LogLine.Level.WARN)
            return false
        }
        return true
    }

    // ---- discovery ------------------------------------------------------

    private fun onBeacon(p: Discovery.DiscoveredPeer) {
        if (peers.size >= Discovery.MAX_PEERS && !peers.containsKey(p.deviceId)) return
        val isNew = peers.put(p.deviceId, PeerEntry(p, System.currentTimeMillis())) == null
        if (isNew) {
            note("Найдено устройство: ${p.name}", LogLine.Level.INFO)
        }
        refresh()
    }

    private fun expirePeers() {
        val now = System.currentTimeMillis()
        peers.entries.removeIf { now - it.value.lastSeen > Discovery.PEER_TTL_MS }
    }

    private fun expirePairings() {
        val now = System.currentTimeMillis()
        for (c in conns.values) {
            if (!c.authorised && c.promptedAt > 0 && now - c.promptedAt > PAIRING_TIMEOUT_MS) {
                note("Сопряжение отменено по тайм-ауту", LogLine.Level.WARN)
                c.session.close()
            }
        }
    }

    // ---- connection lifecycle ------------------------------------------

    fun connect(deviceId: String) {
        val entry = peers[deviceId]
        if (entry == null) {
            note("Устройство не найдено в сети", LogLine.Level.ERROR)
            refresh()
            return
        }
        dial(entry.peer.address, entry.peer.publicKey)
    }

    /**
     * Dial an explicit address. [expectKey], when present, must match the key
     * the peer proves in the handshake — this is what makes QR pairing immune
     * to a machine-in-the-middle.
     */
    fun dial(address: InetSocketAddress, expectKey: ByteArray?) {
        thread(name = "syncmob-dial", isDaemon = true) {
            try {
                val ip = address.address ?: InetAddress.getByName(address.hostString)
                if (settings.lanOnly && !SafeFiles.isLanAddress(ip)) {
                    note(
                        "Адрес ${ip.hostAddress} вне локальной сети — подключение запрещено настройками",
                        LogLine.Level.ERROR,
                    )
                    refresh()
                    return@thread
                }
                if (conns.size >= MAX_CONNECTIONS) {
                    note("Слишком много подключений", LogLine.Level.ERROR)
                    refresh()
                    return@thread
                }
                val socket = Socket()
                socket.connect(InetSocketAddress(ip, address.port), Handshake.HANDSHAKE_TIMEOUT_MS)
                val session = Handshake.initiator(socket, identity)
                runConnection(session, expectKey)
            } catch (e: Exception) {
                note("Не удалось подключиться: ${e.message}", LogLine.Level.ERROR)
                refresh()
            }
        }
    }

    fun dialPairingUri(uri: String) {
        val target = PairingUri.parse(uri)
        if (target == null) {
            note("Некорректная ссылка сопряжения", LogLine.Level.ERROR)
            refresh()
            return
        }
        dial(InetSocketAddress(target.host, target.port), target.publicKey)
    }

    private fun runConnection(session: SecureSession, expectKey: ByteArray?) {
        val key = session.remoteStatic
        val deviceId = Fingerprints.deviceId(key)

        // Out-of-band check: the key we were promised must be the key the peer
        // actually proved. A mismatch is an active attack, not a mistake.
        if (expectKey != null && !Noise.constantTimeEquals(expectKey, key)) {
            note(
                "ВНИМАНИЕ: устройство предъявило другой ключ, чем в QR-коде. Соединение разорвано.",
                LogLine.Level.ERROR,
            )
            session.close()
            refresh()
            return
        }

        val stored = trust.get(key)
        if (stored?.blocked == true) {
            session.close()
            return
        }
        val authorised = stored != null && !stored.blocked
        if (!authorised && !settings.allowNewPairings) {
            note("Запрос сопряжения отклонён: новые сопряжения запрещены", LogLine.Level.WARN)
            session.close()
            refresh()
            return
        }

        if (conns.containsKey(deviceId) || conns.size >= MAX_CONNECTIONS) {
            session.close()
            return
        }

        val conn = Conn(
            session = session,
            key = key,
            fingerprint = Fingerprints.fingerprint(key),
            sas = Fingerprints.sasCode(session.handshakeHash),
            name = stored?.name ?: "",
            authorised = authorised,
            promptedAt = if (authorised) 0 else System.currentTimeMillis(),
        )
        conns[deviceId] = conn

        runCatching {
            session.send(Message.Hello(settings.deviceName, Proto.VERSION, "android"))
        }

        if (authorised) {
            note("Защищённое соединение с ${displayName(deviceId)}", LogLine.Level.GOOD)
        } else {
            if (session.weDialed) {
                runCatching { session.send(Message.PairRequest(settings.deviceName, "android")) }
            }
            pairPrompt = PairPrompt(
                deviceId = deviceId,
                name = conn.name,
                fingerprint = conn.fingerprint,
                sas = conn.sas,
                address = session.remoteAddress.address?.hostAddress ?: "",
                remoteInitiated = !session.weDialed,
            )
        }
        refresh()

        var reason = "соединение закрыто"
        try {
            while (running.get() && !session.isClosed) {
                val msg = session.receive()
                val stop = onMessage(deviceId, conn, msg)
                if (stop != null) {
                    reason = stop
                    break
                }
            }
        } catch (e: Exception) {
            reason = e.message ?: e.javaClass.simpleName
        } finally {
            session.close()
            conns.remove(deviceId)
            failTransfersFor(deviceId, "соединение закрыто")
            if (pairPrompt?.deviceId == deviceId) pairPrompt = null
            note("Соединение с ${displayName(deviceId)} закрыто: $reason", LogLine.Level.INFO)
            refresh()
        }
    }

    /** Returns a reason string to terminate the connection, or null to continue. */
    private fun onMessage(deviceId: String, conn: Conn, msg: Message): String? {
        if (!conn.authorised && !msg.allowedBeforePairing()) {
            return "устройство прислало данные до сопряжения"
        }
        when (msg) {
            is Message.Ping -> runCatching { conn.session.send(Message.Pong) }
            is Message.Pong -> {}
            is Message.Hello -> {
                conn.name = Proto.clamp(msg.name, 64)
                if (conn.authorised) trust.touch(conn.key, conn.name)
                refresh()
            }
            is Message.PairRequest -> {
                conn.name = Proto.clamp(msg.name, 64)
                conn.promptedAt = System.currentTimeMillis()
                if (!conn.authorised) {
                    pairPrompt = PairPrompt(
                        deviceId = deviceId,
                        name = conn.name,
                        fingerprint = conn.fingerprint,
                        sas = conn.sas,
                        address = conn.session.remoteAddress.address?.hostAddress ?: "",
                        remoteInitiated = true,
                    )
                    refresh()
                }
            }
            is Message.PairAccept -> {
                conn.remoteOk = true
                tryFinalizePairing(deviceId, conn)
            }
            is Message.PairReject -> return "сопряжение отклонено: ${Proto.clamp(msg.reason, 80)}"
            is Message.Text -> {
                addChat(
                    deviceId,
                    ChatItem(msg.ts, false, Proto.clamp(msg.text, Proto.MAX_TEXT_CHARS), false),
                )
                runCatching { conn.session.send(Message.TextAck(msg.id)) }
                refresh()
            }
            is Message.TextAck -> {}
            is Message.FileOffer -> onOffer(deviceId, conn, msg)
            is Message.FileAccept ->
                outgoing[msg.id.hex()]?.answer(OutgoingTransfer.Answer.ACCEPT)
            is Message.FileReject -> {
                outgoing[msg.id.hex()]?.answer(OutgoingTransfer.Answer.REJECT)
            }
            is Message.FileCancel -> {
                outgoing[msg.id.hex()]?.answer(OutgoingTransfer.Answer.CANCEL)
                abortIncoming(msg.id, Proto.clamp(msg.reason, 120))
            }
            is Message.FileError -> {
                outgoing[msg.id.hex()]?.answer(OutgoingTransfer.Answer.CANCEL)
                abortIncoming(msg.id, Proto.clamp(msg.reason, 120))
            }
            is Message.FileChunk -> onChunk(deviceId, conn, msg)
            is Message.FileDone -> {
                val t = incoming[msg.id.hex()]
                if (t != null && !t.isComplete) {
                    abortIncoming(msg.id, "отправитель сообщил о завершении, но файл неполный")
                }
            }
        }
        return null
    }

    fun disconnect(deviceId: String) {
        conns[deviceId]?.session?.close()
    }

    // ---- pairing --------------------------------------------------------

    fun respondPairing(deviceId: String, accept: Boolean) {
        val conn = conns[deviceId]
        if (conn == null) {
            pairPrompt = null
            note("Соединение уже закрыто", LogLine.Level.WARN)
            refresh()
            return
        }
        if (!accept) {
            runCatching { conn.session.send(Message.PairReject("отклонено пользователем")) }
            conn.session.close()
            pairPrompt = null
            note("Сопряжение отклонено", LogLine.Level.WARN)
            refresh()
            return
        }
        conn.localOk = true
        runCatching { conn.session.send(Message.PairAccept) }
        tryFinalizePairing(deviceId, conn)
    }

    /** Pairing completes only when *both* users approved; one side is not enough. */
    private fun tryFinalizePairing(deviceId: String, conn: Conn) {
        if (conn.authorised || !conn.localOk || !conn.remoteOk) return
        try {
            trust.add(conn.key, conn.name)
        } catch (e: Exception) {
            note("Не удалось сохранить сопряжение: ${e.message}", LogLine.Level.ERROR)
            refresh()
            return
        }
        conn.authorised = true
        conn.promptedAt = 0
        if (pairPrompt?.deviceId == deviceId) pairPrompt = null
        note("Устройство ${displayName(deviceId)} сопряжено", LogLine.Level.GOOD)
        refresh()
    }

    fun forget(deviceId: String) {
        val key = keyFor(deviceId) ?: return
        trust.remove(key)
        disconnect(deviceId)
        note("Устройство удалено из доверенных", LogLine.Level.WARN)
        refresh()
    }

    fun setAutoAccept(deviceId: String, on: Boolean) {
        keyFor(deviceId)?.let { trust.setAutoAccept(it, on) }
        refresh()
    }

    fun setBlocked(deviceId: String, blocked: Boolean) {
        val key = keyFor(deviceId) ?: return
        trust.setBlocked(key, blocked)
        if (blocked) disconnect(deviceId)
        refresh()
    }

    // ---- text -----------------------------------------------------------

    fun sendText(deviceId: String, text: String) {
        val clean = Proto.clamp(text.trim(), Proto.MAX_TEXT_CHARS)
        if (clean.isEmpty()) return
        val conn = conns[deviceId]
        if (conn == null || !conn.authorised) {
            note("Устройство ещё не сопряжено или не на связи", LogLine.Level.ERROR)
            refresh()
            return
        }
        val ts = System.currentTimeMillis()
        try {
            conn.session.send(Message.Text(TransferId.random(), ts, clean))
            addChat(deviceId, ChatItem(ts, true, clean, false))
        } catch (e: Exception) {
            note("Не удалось отправить сообщение: ${e.message}", LogLine.Level.ERROR)
        }
        refresh()
    }

    // ---- files: sending -------------------------------------------------

    fun sendFile(deviceId: String, uri: Uri) {
        thread(name = "syncmob-send-file", isDaemon = true) { sendFileBlocking(deviceId, uri) }
    }

    private fun sendFileBlocking(deviceId: String, uri: Uri) {
        val displayName = queryDisplayName(uri)
        val id = TransferId.random()
        val staging = File(context.cacheDir, "outgoing").apply { mkdirs() }
        val staged = File(staging, "${id.hex()}.bin")

        try {
            // Copy first: a content URI may be a one-shot stream, and a file
            // that changes mid-send would fail the receiver's hash check.
            context.contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "не удалось открыть файл" }
                staged.outputStream().use { out -> input.copyTo(out, 256 * 1024) }
            }
            val (sha, size) = SafeFiles.sha256(staged.inputStream())

            val conn = conns[deviceId]
            if (conn == null || !conn.authorised) {
                throw IllegalStateException("устройство не на связи")
            }

            val out = OutgoingTransfer(id, deviceId, displayName, size)
            outgoing[id.hex()] = out
            refresh()

            conn.session.send(Message.FileOffer(id, displayName, size, sha))

            when (out.awaitAnswer(OFFER_TIMEOUT_MS)) {
                OutgoingTransfer.Answer.ACCEPT -> {}
                OutgoingTransfer.Answer.REJECT ->
                    throw IllegalStateException("получатель отказался принять файл")
                OutgoingTransfer.Answer.CANCEL -> throw IllegalStateException("передача отменена")
                null -> throw IllegalStateException("получатель не ответил")
            }

            staged.inputStream().buffered(256 * 1024).use { input ->
                val buf = ByteArray(Proto.CHUNK_SIZE)
                var offset = 0L
                var chunks = 0L
                while (true) {
                    if (out.cancelled || out.pollAnswer() == OutgoingTransfer.Answer.CANCEL) {
                        throw IllegalStateException("передача отменена")
                    }
                    val n = input.read(buf)
                    if (n <= 0) break
                    conn.session.send(Message.FileChunk(id, offset, buf.copyOf(n)))
                    offset += n
                    out.sent = offset
                    if (++chunks % 16 == 0L) refresh()
                }
                if (offset != size) throw IllegalStateException("файл изменился во время отправки")
            }
            conn.session.send(Message.FileDone(id, sha))
            finishOutgoing(id, deviceId, displayName, size, null, null)
        } catch (e: Exception) {
            finishOutgoing(id, deviceId, displayName, 0, e.message ?: "ошибка отправки", null)
        } finally {
            outgoing.remove(id.hex())
            staged.delete()
            refresh()
        }
    }

    private fun queryDisplayName(uri: Uri): String {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { c ->
                    if (c.moveToFirst()) {
                        val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (i >= 0) {
                            val n = c.getString(i)
                            if (!n.isNullOrBlank()) return SafeFiles.sanitizeFilename(n)
                        }
                    }
                }
        }
        return SafeFiles.sanitizeFilename(uri.lastPathSegment ?: "file")
    }

    private fun finishOutgoing(
        id: TransferId,
        peerId: String,
        name: String,
        size: Long,
        error: String?,
        savedTo: String?,
    ) {
        finished[id.hex()] = TransferView(
            id = id.hex(),
            peerId = peerId,
            name = name,
            size = size,
            done = size,
            incoming = false,
            finished = true,
            error = error,
            savedTo = savedTo,
        )
        val text = if (error != null) {
            "Файл «$name» не отправлен: $error"
        } else {
            "Файл «$name» отправлен"
        }
        addChat(peerId, ChatItem(System.currentTimeMillis(), true, text, true))
        note(text, if (error != null) LogLine.Level.ERROR else LogLine.Level.GOOD)
    }

    // ---- files: receiving -----------------------------------------------

    private fun onOffer(deviceId: String, conn: Conn, o: Message.FileOffer) {
        val limit = settings.maxFileSizeBytes
        if (limit > 0 && o.size > limit) {
            runCatching {
                conn.session.send(Message.FileReject(o.id, "файл слишком большой"))
            }
            note("Отклонён файл «${Proto.clamp(o.name, 60)}»: превышен лимит", LogLine.Level.WARN)
            refresh()
            return
        }
        if (incoming.size >= MAX_INCOMING_TRANSFERS || incoming.containsKey(o.id.hex())) {
            runCatching { conn.session.send(Message.FileReject(o.id, "слишком много передач")) }
            return
        }

        val t = IncomingTransfer(o.id, deviceId, conn.key, o.name, o.size, o.sha256)
        incoming[o.id.hex()] = t

        val autoAccept = trust.get(conn.key)?.autoAcceptFiles == true
        if (autoAccept) {
            respondOffer(o.id.hex(), true)
        } else {
            synchronized(offerQueue) {
                offerQueue.addLast(
                    OfferPrompt(o.id.hex(), deviceId, displayName(deviceId), t.name, o.size),
                )
            }
            refresh()
        }
    }

    fun respondOffer(transferIdHex: String, accept: Boolean) {
        synchronized(offerQueue) { offerQueue.removeIf { it.transferId == transferIdHex } }
        val t = incoming[transferIdHex]
        if (t == null) {
            refresh()
            return
        }
        val conn = conns[t.fromDeviceId]
        val id = t.id
        if (!accept) {
            abortIncoming(id, "отклонено пользователем")
            runCatching { conn?.session?.send(Message.FileReject(id, "отклонено получателем")) }
            refresh()
            return
        }
        try {
            t.accept(context)
            conn?.session?.send(Message.FileAccept(id))
        } catch (e: Exception) {
            abortIncoming(id, "не удалось создать файл: ${e.message}")
            runCatching { conn?.session?.send(Message.FileReject(id, "ошибка записи на диск")) }
        }
        refresh()
    }

    private fun onChunk(deviceId: String, conn: Conn, c: Message.FileChunk) {
        val t = incoming[c.id.hex()] ?: return
        // A transfer belongs to exactly one peer; another connection may not
        // write into it even if it learns the id.
        if (t.fromDeviceId != deviceId || !Noise.constantTimeEquals(t.fromKey, conn.key)) return

        try {
            t.writeChunk(c.offset, c.data)
        } catch (e: Exception) {
            val reason = e.message ?: "ошибка записи"
            runCatching { conn.session.send(Message.FileError(c.id, reason)) }
            abortIncoming(c.id, reason)
            refresh()
            return
        }

        if (t.isComplete) {
            incoming.remove(c.id.hex())
            try {
                val saved = t.finish(context)
                finished[c.id.hex()] = TransferView(
                    id = c.id.hex(),
                    peerId = deviceId,
                    name = saved.displayName,
                    size = t.size,
                    done = t.size,
                    incoming = true,
                    finished = true,
                    error = null,
                    savedTo = saved.location,
                )
                val text = "Файл «${saved.displayName}» сохранён в ${saved.location}"
                addChat(deviceId, ChatItem(System.currentTimeMillis(), false, text, true))
                note(text, LogLine.Level.GOOD)
            } catch (e: Exception) {
                val reason = e.message ?: "ошибка"
                runCatching { conn.session.send(Message.FileError(c.id, reason)) }
                finished[c.id.hex()] = TransferView(
                    c.id.hex(), deviceId, t.name, t.size, t.received, true, true, reason, null,
                )
                note("Файл «${t.name}» не принят: $reason", LogLine.Level.ERROR)
            }
            refresh()
        } else if (t.received % (Proto.CHUNK_SIZE.toLong() * 16) < Proto.CHUNK_SIZE) {
            refresh()
        }
    }

    private fun abortIncoming(id: TransferId, reason: String) {
        val t = incoming.remove(id.hex()) ?: return
        t.abort()
        finished[id.hex()] = TransferView(
            id.hex(), t.fromDeviceId, t.name, t.size, t.received, true, true, reason, null,
        )
        note("Приём файла «${t.name}» прерван: $reason", LogLine.Level.WARN)
        refresh()
    }

    fun cancelTransfer(transferIdHex: String) {
        outgoing[transferIdHex]?.let { o ->
            o.cancelled = true
            val conn = conns[o.toDeviceId]
            runCatching { conn?.session?.send(Message.FileCancel(o.id, "отменено отправителем")) }
            return
        }
        incoming[transferIdHex]?.let { t ->
            val conn = conns[t.fromDeviceId]
            runCatching { conn?.session?.send(Message.FileCancel(t.id, "отменено получателем")) }
            abortIncoming(t.id, "отменено")
        }
    }

    private fun failTransfersFor(deviceId: String, reason: String) {
        for (t in incoming.values.filter { it.fromDeviceId == deviceId }) {
            abortIncoming(t.id, reason)
        }
        for (o in outgoing.values.filter { it.toDeviceId == deviceId }) {
            o.cancelled = true
            o.answer(OutgoingTransfer.Answer.CANCEL)
        }
    }

    fun clearFinishedTransfers() {
        finished.clear()
        synchronized(logLines) { logLines.clear() }
        refresh()
    }

    // ---- settings -------------------------------------------------------

    fun updateSettings(newSettings: Settings) {
        val sanitised = newSettings.copy(
            deviceName = Proto.clamp(newSettings.deviceName.trim(), 32).ifEmpty { "Android" },
        )
        settings = sanitised
        Settings.save(context, sanitised)
        discovery?.let {
            it.announcedName = sanitised.deviceName
            it.announcing = sanitised.discoveryEnabled
        }
        note("Настройки сохранены", LogLine.Level.GOOD)
        refresh()
    }

    // ---- helpers --------------------------------------------------------

    private fun keyFor(deviceId: String): ByteArray? =
        conns[deviceId]?.key
            ?: peers[deviceId]?.peer?.publicKey
            ?: trust.byDeviceId(deviceId)?.keyBytes()

    private fun displayName(deviceId: String): String {
        conns[deviceId]?.name?.takeIf { it.isNotEmpty() }?.let { return it }
        peers[deviceId]?.peer?.name?.takeIf { it.isNotEmpty() }?.let { return it }
        trust.byDeviceId(deviceId)?.name?.takeIf { it.isNotEmpty() }?.let { return it }
        return deviceId
    }

    private fun addChat(deviceId: String, item: ChatItem) {
        val list = chats.getOrPut(deviceId) { mutableListOf() }
        synchronized(list) {
            list.add(item)
            while (list.size > 500) list.removeAt(0)
        }
    }

    private fun note(text: String, level: LogLine.Level) {
        synchronized(logLines) {
            logLines.addLast(LogLine(System.currentTimeMillis(), text, level))
            while (logLines.size > 200) logLines.removeFirst()
        }
        Log.i(TAG, text)
    }

    /** Recompute the immutable snapshot the UI renders. */
    private fun refresh() {
        val trusted = trust.list()
        val views = LinkedHashMap<String, DeviceView>()

        for (d in trusted) {
            val key = d.keyBytes() ?: continue
            val id = d.deviceId()
            views[id] = DeviceView(
                deviceId = id,
                name = d.name.ifEmpty { id },
                publicKey = key,
                fingerprint = d.fingerprint(),
                online = peers.containsKey(id),
                connected = conns[id]?.authorised == true,
                paired = true,
                blocked = d.blocked,
                autoAccept = d.autoAcceptFiles,
                address = peers[id]?.peer?.address?.address?.hostAddress,
            )
        }
        for ((id, entry) in peers) {
            if (views.containsKey(id)) continue
            views[id] = DeviceView(
                deviceId = id,
                name = entry.peer.name.ifEmpty { id },
                publicKey = entry.peer.publicKey,
                fingerprint = Fingerprints.fingerprint(entry.peer.publicKey),
                online = true,
                connected = conns.containsKey(id),
                paired = false,
                blocked = false,
                autoAccept = false,
                address = entry.peer.address.address?.hostAddress,
            )
        }

        val active = ArrayList<TransferView>()
        for (t in incoming.values) {
            active += TransferView(
                t.id.hex(), t.fromDeviceId, t.name, t.size, t.received, true, false, null, null,
            )
        }
        for (o in outgoing.values) {
            active += TransferView(
                o.id.hex(), o.toDeviceId, o.name, o.size, o.sent, false, false, null, null,
            )
        }
        active += finished.values.sortedByDescending { it.id }.take(10)

        _state.value = State(
            myDeviceId = identity.deviceId(),
            myFingerprint = identity.fingerprint(),
            hardwareBackedKey = identity.hardwareBacked,
            port = boundPort,
            running = running.get(),
            settings = settings,
            devices = views.values.sortedWith(
                compareByDescending<DeviceView> { it.paired }.thenBy { it.name.lowercase() },
            ),
            chats = chats.mapValues { synchronized(it.value) { it.value.toList() } },
            transfers = active,
            pairPrompt = pairPrompt,
            offerPrompt = synchronized(offerQueue) { offerQueue.firstOrNull() },
            log = synchronized(logLines) { logLines.toList() },
        )
    }

    /** Caps handshake attempts per source address. */
    private class ConnGuard {
        private val seen = ConcurrentHashMap<String, LongArray>()

        fun allow(host: String): Boolean {
            val now = System.currentTimeMillis()
            seen.entries.removeIf { now - it.value[0] > 60_000 }
            if (seen.size > 512) return false
            val e = seen.getOrPut(host) { longArrayOf(now, 0) }
            synchronized(e) {
                if (now - e[0] >= 60_000) {
                    e[0] = now
                    e[1] = 0
                }
                e[1]++
                return e[1] <= HANDSHAKES_PER_MINUTE
            }
        }
    }

    companion object {
        private const val TAG = "SyncMob/Engine"
        const val MAX_CONNECTIONS = 16
        const val MAX_INCOMING_TRANSFERS = 16
        const val PAIRING_TIMEOUT_MS = 180_000L
        const val OFFER_TIMEOUT_MS = 300_000L
        const val KEEPALIVE_MS = 30_000L
        private const val HANDSHAKES_PER_MINUTE = 10

    }
}

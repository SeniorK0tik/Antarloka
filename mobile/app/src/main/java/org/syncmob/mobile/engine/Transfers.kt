package org.syncmob.mobile.engine

import android.content.Context
import org.syncmob.mobile.proto.TransferId
import org.syncmob.mobile.util.Downloads
import org.syncmob.mobile.util.SafeFiles
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

class TransferException(message: String) : Exception(message)

/**
 * Receiving a file safely.
 *
 * Every byte here comes from the network, so: data lands in a quarantine file
 * inside the app's own cache (named by transfer id, never by anything the peer
 * chose), chunks must arrive strictly in order and may not push the total past
 * the advertised size, and the SHA-256 must match the offer before the file is
 * published to Downloads. A failure at any point removes the partial file.
 */
class IncomingTransfer(
    val id: TransferId,
    val fromDeviceId: String,
    /** The peer's static key, so a chunk from another connection is refused. */
    val fromKey: ByteArray,
    rawName: String,
    val size: Long,
    expectedSha: String,
) {
    /** Already sanitised; guaranteed free of path separators. */
    val name: String = SafeFiles.sanitizeFilename(rawName)
    private val expectedSha: String = expectedSha.lowercase()

    @Volatile
    var received: Long = 0
        private set

    @Volatile
    var accepted: Boolean = false
        private set

    val startedAt: Long = System.currentTimeMillis()

    private var partFile: File? = null
    private var out: BufferedOutputStream? = null
    private val digest = MessageDigest.getInstance("SHA-256")

    val isComplete: Boolean get() = received == size

    /** Open the quarantine file. Only after the user (or an explicit auto-accept rule) approved. */
    fun accept(context: Context) {
        val dir = File(context.cacheDir, "incoming").apply { mkdirs() }
        val f = File(dir, "${id.hex()}.part")
        partFile = f
        out = BufferedOutputStream(FileOutputStream(f), 256 * 1024)
        accepted = true
    }

    fun writeChunk(offset: Long, data: ByteArray) {
        if (!accepted) throw TransferException("передача не подтверждена")
        if (offset != received) {
            throw TransferException("нарушен порядок блоков (ожидался сдвиг $received, получен $offset)")
        }
        val end = received + data.size
        // Checked before writing, so a hostile peer cannot fill the disk past
        // what it declared.
        if (end < 0 || end > size) throw TransferException("прислано больше данных, чем заявлено")
        val stream = out ?: throw TransferException("передача не подтверждена")
        stream.write(data)
        digest.update(data)
        received = end
    }

    /** Verify the hash and publish the file. Removes the partial file on failure. */
    fun finish(context: Context): Downloads.Saved {
        try {
            out?.flush()
            out?.close()
            out = null
            if (received != size) {
                throw TransferException("файл неполный: $received из $size байт")
            }
            val actual = SafeFiles.hex(digest.digest())
            if (actual != expectedSha) {
                throw TransferException("хеш не совпадает с заявленным — файл отброшен")
            }
            val part = partFile ?: throw TransferException("нет временного файла")
            return Downloads.publish(context, part, name)
        } catch (e: Exception) {
            abort()
            throw e
        }
    }

    /** Drop a rejected or failed transfer, removing partial data. */
    fun abort() {
        runCatching { out?.close() }
        out = null
        runCatching { partFile?.delete() }
        partFile = null
    }
}

/** State of one file we are sending. */
class OutgoingTransfer(
    val id: TransferId,
    val toDeviceId: String,
    val name: String,
    val size: Long,
) {
    @Volatile
    var sent: Long = 0

    @Volatile
    var cancelled: Boolean = false

    /** Set by the reader thread when the peer answers the offer. */
    private val lock = Object()
    private var answer: Answer? = null

    enum class Answer { ACCEPT, REJECT, CANCEL }

    fun answer(a: Answer) = synchronized(lock) {
        answer = a
        lock.notifyAll()
    }

    /** Wait for the peer to accept, or return null on timeout. */
    fun awaitAnswer(timeoutMs: Long): Answer? = synchronized(lock) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (answer == null) {
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) return null
            lock.wait(left)
        }
        answer
    }

    fun pollAnswer(): Answer? = synchronized(lock) { answer }
}

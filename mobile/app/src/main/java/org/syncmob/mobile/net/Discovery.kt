package org.syncmob.mobile.net

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import org.syncmob.mobile.proto.Beacon
import org.syncmob.mobile.proto.Proto
import org.syncmob.mobile.security.Fingerprints
import org.syncmob.mobile.util.SafeFiles
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * LAN presence over UDP broadcast and multicast.
 *
 * Beacons are unauthenticated **by design**: they carry only public information
 * and are treated purely as a hint about where a device might be reachable.
 * Anyone can forge one, so a beacon never grants trust — it only populates the
 * "nearby" list, and every entry still has to survive the Noise handshake and
 * the trust store.
 */
class Discovery(
    private val context: Context,
    private val ownPublicKey: ByteArray,
    private val onPeer: (DiscoveredPeer) -> Unit,
) {
    data class DiscoveredPeer(
        val deviceId: String,
        val publicKey: ByteArray,
        val name: String,
        val platform: String,
        val address: InetSocketAddress,
    ) {
        override fun equals(other: Any?): Boolean =
            other is DiscoveredPeer && deviceId == other.deviceId

        override fun hashCode(): Int = deviceId.hashCode()
    }

    @Volatile
    var announcedName: String = "Android"

    @Volatile
    var announcedPort: Int = Proto.DEFAULT_TCP_PORT

    @Volatile
    var announcing: Boolean = true

    private val running = AtomicBoolean(false)
    private var socket: MulticastSocket? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private val rateLimiter = RateLimiter()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        try {
            acquireMulticastLock()
            val s = MulticastSocket(null).apply {
                reuseAddress = true
                bind(InetSocketAddress(Proto.DISCOVERY_PORT))
                soTimeout = 500
                broadcast = true
                timeToLive = 1
            }
            socket = s
            joinMulticast(s)
            thread(name = "syncmob-discovery-rx", isDaemon = true) { receiveLoop(s) }
            thread(name = "syncmob-discovery-tx", isDaemon = true) { announceLoop(s) }
        } catch (e: Exception) {
            Log.w(TAG, "discovery unavailable: ${e.message}")
            running.set(false)
            releaseMulticastLock()
        }
    }

    fun stop() {
        running.set(false)
        runCatching { socket?.close() }
        socket = null
        releaseMulticastLock()
    }

    private fun acquireMulticastLock() {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return
        multicastLock = wifi.createMulticastLock("syncmob").apply {
            setReferenceCounted(false)
            runCatching { acquire() }
        }
    }

    private fun releaseMulticastLock() {
        runCatching { multicastLock?.takeIf { it.isHeld }?.release() }
        multicastLock = null
    }

    private fun joinMulticast(s: MulticastSocket) {
        val group = InetSocketAddress(InetAddress.getByName(Proto.MULTICAST_GROUP), Proto.DISCOVERY_PORT)
        var joined = false
        for (nif in usableInterfaces()) {
            runCatching {
                s.joinGroup(group, nif)
                joined = true
            }
        }
        if (!joined) {
            runCatching { s.joinGroup(InetAddress.getByName(Proto.MULTICAST_GROUP)) }
        }
    }

    private fun receiveLoop(s: MulticastSocket) {
        val buf = ByteArray(Proto.MAX_BEACON_BYTES + 1)
        while (running.get()) {
            val packet = DatagramPacket(buf, buf.size)
            try {
                s.receive(packet)
            } catch (e: SocketTimeoutException) {
                continue
            } catch (e: Exception) {
                if (running.get()) Log.d(TAG, "receive error: ${e.message}")
                continue
            }
            val from = packet.address ?: continue
            if (packet.length > Proto.MAX_BEACON_BYTES) continue
            if (!SafeFiles.isLanAddress(from)) continue
            if (!rateLimiter.allow(from.hostAddress ?: continue)) continue

            val beacon = Beacon.parse(packet.data, packet.length) ?: continue
            // Ignore our own beacons echoing back off the network.
            if (beacon.publicKey.contentEquals(ownPublicKey)) continue

            onPeer(
                DiscoveredPeer(
                    deviceId = Fingerprints.deviceId(beacon.publicKey),
                    publicKey = beacon.publicKey,
                    name = beacon.name,
                    platform = beacon.platform,
                    // The address always comes from the UDP source, never from
                    // the payload: a beacon cannot point us at a third party.
                    address = InetSocketAddress(from, beacon.port),
                ),
            )
        }
    }

    private fun announceLoop(s: MulticastSocket) {
        val group = InetAddress.getByName(Proto.MULTICAST_GROUP)
        while (running.get()) {
            if (announcing) {
                val payload = Beacon(ownPublicKey, announcedName, announcedPort, "android").encode()
                if (payload.size <= Proto.MAX_BEACON_BYTES) {
                    val targets = mutableListOf<InetAddress>(group)
                    targets += broadcastAddresses()
                    for (t in targets) {
                        runCatching {
                            s.send(DatagramPacket(payload, payload.size, t, Proto.DISCOVERY_PORT))
                        }
                    }
                }
            }
            sleepInterruptible(ANNOUNCE_INTERVAL_MS)
        }
    }

    private fun sleepInterruptible(totalMs: Long) {
        var left = totalMs
        while (left > 0 && running.get()) {
            val step = minOf(200L, left)
            Thread.sleep(step)
            left -= step
        }
    }

    private fun usableInterfaces(): List<NetworkInterface> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && it.supportsMulticast() }
    }.getOrDefault(emptyList())

    /** Per-interface broadcast addresses, plus the global one. */
    private fun broadcastAddresses(): List<InetAddress> {
        val out = mutableListOf<InetAddress>()
        runCatching { out += InetAddress.getByName("255.255.255.255") }
        for (nif in usableInterfaces()) {
            for (ia in nif.interfaceAddresses) {
                val b = ia.broadcast ?: continue
                if (b is Inet4Address) out += b
            }
        }
        return out.distinct()
    }

    /** Caps how many beacons a single source can push into the peer list. */
    private class RateLimiter {
        private val seen = ConcurrentHashMap<String, LongArray>()

        fun allow(host: String): Boolean {
            val now = System.currentTimeMillis()
            if (seen.size > 1024) {
                seen.entries.removeIf { now - it.value[0] > 5_000 }
                if (seen.size > 1024) return false
            }
            val entry = seen.getOrPut(host) { longArrayOf(now, 0) }
            synchronized(entry) {
                if (now - entry[0] >= 1_000) {
                    entry[0] = now
                    entry[1] = 0
                }
                entry[1]++
                return entry[1] <= RATE_PER_SOURCE
            }
        }
    }

    companion object {
        private const val TAG = "SyncMob/Discovery"
        const val ANNOUNCE_INTERVAL_MS = 3_000L
        /** A peer leaves the list after this long without a beacon. */
        const val PEER_TTL_MS = 15_000L
        const val MAX_PEERS = 128
        private const val RATE_PER_SOURCE = 4
    }
}

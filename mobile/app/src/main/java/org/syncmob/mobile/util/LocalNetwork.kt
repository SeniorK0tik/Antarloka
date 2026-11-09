package org.syncmob.mobile.util

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.Network
import android.net.NetworkCapabilities
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Socket

/**
 * Talking to the local network while a VPN is up.
 *
 * A full-tunnel VPN on the phone captures every packet the app sends,
 * including ones meant for the PC on the same Wi-Fi, and those never arrive.
 * Android lets an app pin a socket to the underlying Wi-Fi network instead —
 * *if* the VPN allows bypassing. Many do; some (or "always-on, block
 * connections without VPN") do not, and then [bindSocket] throws and the
 * socket simply keeps using the VPN, exactly as before.
 *
 * Only traffic whose destination sits inside the Wi-Fi/Ethernet subnet is
 * pinned. Anything else keeps going through the VPN, so this never leaks
 * traffic the user meant to tunnel.
 */
object LocalNetwork {

    private fun cm(context: Context): ConnectivityManager? =
        context.getSystemService(ConnectivityManager::class.java)

    @Suppress("DEPRECATION") // allNetworks: the callback API is overkill for a periodic check.
    private fun networks(cm: ConnectivityManager): List<Pair<Network, NetworkCapabilities>> =
        cm.allNetworks.mapNotNull { n -> cm.getNetworkCapabilities(n)?.let { n to it } }

    fun isVpnActive(context: Context): Boolean = runCatching {
        val cm = cm(context) ?: return false
        networks(cm).any { (_, caps) -> caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }
    }.getOrDefault(false)

    /** The Wi-Fi or Ethernet network itself, not the VPN layered on top of it. */
    fun lanNetwork(context: Context): Network? = runCatching {
        val cm = cm(context) ?: return null
        networks(cm).firstOrNull { (_, caps) ->
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
        }?.first
    }.getOrNull()

    private fun lanLinkAddresses(context: Context, network: Network): List<LinkAddress> =
        runCatching { cm(context)?.getLinkProperties(network)?.linkAddresses.orEmpty() }
            .getOrDefault(emptyList())

    /** This phone's IPv4 addresses on Wi-Fi/Ethernet — what to type on the PC. */
    fun localAddresses(context: Context): List<String> {
        val n = lanNetwork(context) ?: return emptyList()
        return lanLinkAddresses(context, n)
            .map { it.address }
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
    }

    /**
     * The network to pin a socket to for reaching [dest], or null to leave the
     * socket alone: no VPN, no Wi-Fi, or [dest] is not on the Wi-Fi subnet.
     */
    fun networkFor(context: Context, dest: InetAddress): Network? {
        if (!isVpnActive(context)) return null
        val n = lanNetwork(context) ?: return null
        return if (lanLinkAddresses(context, n).any { inSubnet(dest, it) }) n else null
    }

    /** Returns true if the socket was pinned to the local network. */
    fun bind(context: Context, socket: Socket, dest: InetAddress): Boolean {
        val n = networkFor(context, dest) ?: return false
        return runCatching { n.bindSocket(socket) }.isSuccess
    }

    /** Pin a discovery socket; beacons only ever go to the local segment. */
    fun bind(network: Network, socket: DatagramSocket): Boolean =
        runCatching { network.bindSocket(socket) }.isSuccess

    private fun inSubnet(dest: InetAddress, link: LinkAddress): Boolean {
        val a = dest.address
        val b = link.address.address
        if (a.size != b.size) return false
        var bits = link.prefixLength
        // A /32 is a point-to-point address, not a segment with neighbours.
        if (bits <= 0 || bits >= a.size * 8) return false
        for (i in a.indices) {
            if (bits <= 0) break
            val mask = if (bits >= 8) 0xFF else (0xFF shl (8 - bits)) and 0xFF
            if ((a[i].toInt() and mask) != (b[i].toInt() and mask)) return false
            bits -= 8
        }
        return true
    }
}

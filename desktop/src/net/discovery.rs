//! LAN presence: UDP broadcast + multicast beacons.
//!
//! Beacons are **unauthenticated by design**. They carry only public
//! information (a public key, a display name, a port) and are treated purely as
//! a hint about where a device might be reachable. Anyone can forge one, so a
//! beacon never grants trust: it only populates the "nearby devices" list, and
//! every entry still has to survive the Noise handshake and the trust store.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use socket2::{Domain, Protocol, Socket, Type};

use crate::proto::{Beacon, BEACON_MAGIC, DISCOVERY_PORT, MAX_BEACON_BYTES, MULTICAST_GROUP};
use crate::security::{device_id, DeviceId};
use crate::util::{clamp_str, is_lan_addr};

/// How often we announce ourselves.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
/// A peer disappears from the list after this long without a beacon.
pub const PEER_TTL: Duration = Duration::from_secs(15);
/// Upper bound on the peer table, so a flood of forged beacons cannot exhaust
/// memory or make the UI unusable.
pub const MAX_PEERS: usize = 128;
/// Beacons accepted per source address per second.
const RATE_PER_SOURCE: u32 = 4;

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub device_id: DeviceId,
    /// Claimed X25519 static public key. Verified only by the handshake.
    pub public_key: Vec<u8>,
    /// Claimed display name. Untrusted; already clamped.
    pub name: String,
    pub platform: String,
    pub addr: SocketAddr,
}

/// What we announce. Behind a mutex so the UI can rename the device live.
#[derive(Debug, Clone)]
pub struct BeaconInfo {
    pub public_key: Vec<u8>,
    pub name: String,
    pub port: u16,
    pub platform: String,
    pub announce: bool,
}

pub struct Discovery {
    running: Arc<AtomicBool>,
    info: Arc<Mutex<BeaconInfo>>,
}

impl Discovery {
    /// Start the announce and listen loops. `on_peer` is called from the
    /// listener thread for every beacon that passes validation.
    pub fn start<F>(info: BeaconInfo, on_peer: F) -> std::io::Result<Self>
    where
        F: Fn(DiscoveredPeer) + Send + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let info = Arc::new(Mutex::new(info));

        let socket = bind_discovery_socket()?;
        join_multicast(&socket);
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;

        let send_sock = socket.try_clone()?;
        let own_pk = info.lock().expect("info").public_key.clone();

        // Listener.
        {
            let running = running.clone();
            std::thread::Builder::new()
                .name("syncmob-discovery-rx".into())
                .spawn(move || {
                    let mut limiter = RateLimiter::new();
                    let mut buf = [0u8; MAX_BEACON_BYTES + 1];
                    while running.load(Ordering::Relaxed) {
                        let (n, src) = match socket.recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(_) => continue, // timeout or transient error
                        };
                        if n > MAX_BEACON_BYTES || !limiter.allow(src.ip()) {
                            continue;
                        }
                        if let Some(peer) = validate_beacon(&buf[..n], src, &own_pk) {
                            on_peer(peer);
                        }
                    }
                })?;
        }

        // Announcer.
        {
            let running = running.clone();
            let info = info.clone();
            std::thread::Builder::new()
                .name("syncmob-discovery-tx".into())
                .spawn(move || {
                    while running.load(Ordering::Relaxed) {
                        let payload = {
                            let i = info.lock().expect("info");
                            if i.announce {
                                encode_beacon(&i)
                            } else {
                                None
                            }
                        };
                        if let Some(payload) = payload {
                            let targets = [
                                SocketAddr::from((Ipv4Addr::BROADCAST, DISCOVERY_PORT)),
                                SocketAddr::V4(SocketAddrV4::new(MULTICAST_GROUP, DISCOVERY_PORT)),
                            ];
                            for t in targets {
                                let _ = send_sock.send_to(&payload, t);
                            }
                            for bcast in interface_broadcasts() {
                                let _ = send_sock
                                    .send_to(&payload, SocketAddr::from((bcast, DISCOVERY_PORT)));
                            }
                        }
                        sleep_interruptible(&running, ANNOUNCE_INTERVAL);
                    }
                })?;
        }

        Ok(Self { running, info })
    }

    /// Change the announced name / port / platform at runtime.
    pub fn update(&self, f: impl FnOnce(&mut BeaconInfo)) {
        if let Ok(mut i) = self.info.lock() {
            f(&mut i);
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.stop();
    }
}

fn sleep_interruptible(running: &AtomicBool, total: Duration) {
    let step = Duration::from_millis(200);
    let mut left = total;
    while left > Duration::ZERO && running.load(Ordering::Relaxed) {
        let d = step.min(left);
        std::thread::sleep(d);
        left -= d;
    }
}

fn bind_discovery_socket() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // Several SyncMob instances (or other multicast users) may share the port.
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).into())?;
    Ok(socket.into())
}

fn join_multicast(socket: &UdpSocket) {
    // Join on every usable IPv4 interface; failures are non-fatal because
    // broadcast still works.
    let mut joined_any = false;
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let IpAddr::V4(v4) = iface.ip() {
                if socket.join_multicast_v4(&MULTICAST_GROUP, &v4).is_ok() {
                    joined_any = true;
                }
            }
        }
    }
    if !joined_any {
        let _ = socket.join_multicast_v4(&MULTICAST_GROUP, &Ipv4Addr::UNSPECIFIED);
    }
}

/// Per-interface broadcast addresses, so we also reach subnets where the
/// global 255.255.255.255 broadcast is filtered.
fn interface_broadcasts() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if let Some(b) = v4.broadcast {
                    out.push(b);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn encode_beacon(info: &BeaconInfo) -> Option<Vec<u8>> {
    let b = Beacon {
        m: BEACON_MAGIC.to_string(),
        v: 1,
        pk: B64.encode(&info.public_key),
        name: clamp_str(&info.name, 32),
        port: info.port,
        platform: info.platform.clone(),
    };
    let raw = serde_json::to_vec(&b).ok()?;
    (raw.len() <= MAX_BEACON_BYTES).then_some(raw)
}

/// Parse and sanity-check a beacon. Pure function, so every rejection rule is
/// directly testable.
pub fn validate_beacon(raw: &[u8], src: SocketAddr, own_pk: &[u8]) -> Option<DiscoveredPeer> {
    if raw.len() > MAX_BEACON_BYTES {
        return None;
    }
    // Only ever talk to the local network.
    if !is_lan_addr(src.ip()) {
        return None;
    }
    let b: Beacon = serde_json::from_slice(raw).ok()?;
    if b.m != BEACON_MAGIC || b.v != 1 || b.port == 0 {
        return None;
    }
    let pk = B64.decode(&b.pk).ok()?;
    if pk.len() != 32 {
        return None;
    }
    // Ignore our own beacons coming back from the network.
    if pk == own_pk {
        return None;
    }
    Some(DiscoveredPeer {
        device_id: device_id(&pk),
        public_key: pk,
        name: clamp_str(&b.name, 32),
        platform: clamp_str(&b.platform, 16),
        addr: SocketAddr::new(src.ip(), b.port),
    })
}

/// Simple per-source token bucket.
struct RateLimiter {
    seen: HashMap<IpAddr, (Instant, u32)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        // Keep the map from growing without bound under a spoofed-source flood.
        if self.seen.len() > 1024 {
            self.seen
                .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(5));
            if self.seen.len() > 1024 {
                return false;
            }
        }
        let e = self.seen.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(1) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= RATE_PER_SOURCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon_bytes(pk: &[u8], name: &str, port: u16) -> Vec<u8> {
        serde_json::to_vec(&Beacon {
            m: BEACON_MAGIC.into(),
            v: 1,
            pk: B64.encode(pk),
            name: name.into(),
            port,
            platform: "test".into(),
        })
        .unwrap()
    }

    fn lan_src() -> SocketAddr {
        "192.168.1.50:45820".parse().unwrap()
    }

    #[test]
    fn accepts_a_well_formed_beacon() {
        let raw = beacon_bytes(&[9u8; 32], "Phone", 45821);
        let p = validate_beacon(&raw, lan_src(), &[1u8; 32]).unwrap();
        assert_eq!(p.name, "Phone");
        assert_eq!(p.public_key, vec![9u8; 32]);
        assert_eq!(p.addr.port(), 45821);
        // The address always comes from the UDP source, never from the payload.
        assert_eq!(p.addr.ip(), lan_src().ip());
        assert_eq!(p.device_id, device_id(&[9u8; 32]));
    }

    #[test]
    fn rejects_non_lan_sources() {
        let raw = beacon_bytes(&[9u8; 32], "Phone", 45821);
        assert!(validate_beacon(&raw, "8.8.8.8:45820".parse().unwrap(), &[1u8; 32]).is_none());
    }

    #[test]
    fn rejects_own_beacon() {
        let raw = beacon_bytes(&[1u8; 32], "Me", 45821);
        assert!(validate_beacon(&raw, lan_src(), &[1u8; 32]).is_none());
    }

    #[test]
    fn rejects_malformed_payloads() {
        assert!(validate_beacon(b"not json", lan_src(), &[1u8; 32]).is_none());
        assert!(validate_beacon(&[], lan_src(), &[1u8; 32]).is_none());
        assert!(
            validate_beacon(&vec![b'{'; MAX_BEACON_BYTES + 1], lan_src(), &[1u8; 32]).is_none()
        );

        // Wrong magic / version / port / key length.
        let mut b: Beacon = serde_json::from_slice(&beacon_bytes(&[9u8; 32], "x", 1)).unwrap();
        b.m = "OTHER".into();
        assert!(validate_beacon(&serde_json::to_vec(&b).unwrap(), lan_src(), &[1u8; 32]).is_none());

        let raw = beacon_bytes(&[9u8; 32], "x", 0);
        assert!(validate_beacon(&raw, lan_src(), &[1u8; 32]).is_none());

        let raw = beacon_bytes(&[9u8; 16], "x", 45821);
        assert!(validate_beacon(&raw, lan_src(), &[1u8; 32]).is_none());
    }

    #[test]
    fn long_names_are_clamped() {
        let raw = beacon_bytes(&[9u8; 32], &"n".repeat(200), 45821);
        let p = validate_beacon(&raw, lan_src(), &[1u8; 32]).unwrap();
        assert!(p.name.chars().count() <= 33);
    }

    #[test]
    fn rate_limiter_caps_a_flood() {
        let mut l = RateLimiter::new();
        let ip: IpAddr = "192.168.1.9".parse().unwrap();
        let allowed = (0..50).filter(|_| l.allow(ip)).count();
        assert_eq!(allowed, RATE_PER_SOURCE as usize);
        // A different source is unaffected.
        assert!(l.allow("192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn our_own_beacon_encodes_within_the_limit() {
        let info = BeaconInfo {
            public_key: vec![7u8; 32],
            name: "x".repeat(64),
            port: 45821,
            platform: "windows".into(),
            announce: true,
        };
        let raw = encode_beacon(&info).unwrap();
        assert!(raw.len() <= MAX_BEACON_BYTES);
        let p = validate_beacon(&raw, lan_src(), &[0u8; 32]).unwrap();
        assert_eq!(p.public_key, vec![7u8; 32]);
    }
}

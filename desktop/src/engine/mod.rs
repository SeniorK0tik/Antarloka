//! Orchestration: listener, dialer, pairing state machine and transfers.
//!
//! The engine owns every long-lived thread and is the only place that mutates
//! the trust store. Front-ends drive it through plain methods and observe it
//! through an [`EngineEvent`] channel, so the GUI holds no networking state.
//!
//! Authorisation rule, enforced in exactly one place ([`Inner::on_message`]):
//! a peer whose static key is not in the trust store may send only the handful
//! of messages listed in [`Message::allowed_before_pairing`]. Text and files
//! from an unpaired peer are dropped and the connection closed.

pub mod transfer;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;

use crate::config::{Config, Paths};
use crate::net::discovery::{BeaconInfo, DiscoveredPeer, Discovery, MAX_PEERS, PEER_TTL};
use crate::net::session::{
    handshake_initiator, handshake_responder, ChannelSender, Handshaked, HANDSHAKE_TIMEOUT,
};
use crate::proto::{
    FileDone, FileOffer, Hello, IdReason, Message, PairRequest, TextMsg, TransferId, CHUNK_SIZE,
    DEFAULT_TCP_PORT,
};
use crate::security::fingerprint::keys_equal;
use crate::security::{device_id, fingerprint, sas_code, DeviceId, Identity, TrustStore};
use crate::util::{clamp_str, is_lan_addr};
use transfer::{hash_file, IncomingTransfer};

/// Simultaneous authenticated connections.
pub const MAX_CONNECTIONS: usize = 16;
/// Simultaneous incoming file transfers.
pub const MAX_INCOMING_TRANSFERS: usize = 16;
/// A pairing prompt that nobody answers is dropped after this long.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a sender waits for the receiver to accept an offer.
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(300);
/// Application level keepalive.
pub const KEEPALIVE: Duration = Duration::from_secs(30);
/// Handshake attempts allowed per source address per minute.
const HANDSHAKES_PER_MINUTE: u32 = 10;
/// Depth of the UI event queue; the engine never blocks on a slow UI.
const EVENT_QUEUE: usize = 4096;

pub const PLATFORM: &str = if cfg!(windows) { "windows" } else { "desktop" };

#[derive(Debug, Clone)]
pub enum EngineEvent {
    PeerDiscovered(PeerInfo),
    PeerLost(DeviceId),
    Connected(ConnInfo),
    Disconnected {
        device: DeviceId,
        reason: String,
    },
    /// A connection completed the handshake but the peer is not paired yet.
    /// The UI must show `sas` and `fingerprint` and ask the user.
    PairingRequired {
        device: DeviceId,
        name: String,
        fingerprint: String,
        sas: String,
        addr: SocketAddr,
        /// True when the peer asked us, false when we initiated.
        remote_initiated: bool,
    },
    PairingFinished {
        device: DeviceId,
        accepted: bool,
    },
    TextReceived {
        from: DeviceId,
        text: String,
        ts: u64,
    },
    TextSent {
        to: DeviceId,
        text: String,
        ts: u64,
    },
    OfferReceived {
        from: DeviceId,
        transfer: TransferId,
        name: String,
        size: u64,
    },
    TransferProgress {
        transfer: TransferId,
        done: u64,
        total: u64,
        incoming: bool,
    },
    TransferFinished {
        transfer: TransferId,
        incoming: bool,
        name: String,
        path: Option<PathBuf>,
        error: Option<String>,
    },
    TrustChanged,
    Notice(String),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub device: DeviceId,
    pub name: String,
    pub platform: String,
    pub addr: SocketAddr,
    pub public_key: Vec<u8>,
    pub paired: bool,
}

#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub id: TransferId,
    pub peer: DeviceId,
    pub name: String,
    pub size: u64,
    pub done: u64,
    pub incoming: bool,
}

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub device: DeviceId,
    pub name: String,
    pub addr: SocketAddr,
    pub fingerprint: String,
    pub sas: String,
    pub paired: bool,
}

enum OutSignal {
    Accept,
    Reject(String),
    Cancel,
}

struct Conn {
    sender: ChannelSender,
    key: Vec<u8>,
    name: String,
    addr: SocketAddr,
    fingerprint: String,
    sas: String,
    authorised: bool,
    local_ok: bool,
    remote_ok: bool,
    prompted_at: Option<Instant>,
}

struct Outgoing {
    to: DeviceId,
    name: String,
    size: u64,
    signal: Sender<OutSignal>,
    cancel: Arc<AtomicBool>,
}

struct PeerEntry {
    info: PeerInfo,
    last_seen: Instant,
}

struct ConnGuard {
    seen: HashMap<IpAddr, (Instant, u32)>,
}

impl ConnGuard {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.seen
            .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        if self.seen.len() > 512 {
            return false;
        }
        let e = self.seen.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= HANDSHAKES_PER_MINUTE
    }
}

struct Inner {
    identity: Identity,
    paths: Paths,
    config: Mutex<Config>,
    trust: Mutex<TrustStore>,
    conns: Mutex<HashMap<DeviceId, Conn>>,
    peers: Mutex<HashMap<DeviceId, PeerEntry>>,
    incoming: Mutex<HashMap<TransferId, IncomingTransfer>>,
    outgoing: Mutex<HashMap<TransferId, Outgoing>>,
    events: SyncSender<EngineEvent>,
    running: AtomicBool,
    guard: Mutex<ConnGuard>,
    bound_port: Mutex<u16>,
}

pub struct Engine {
    inner: Arc<Inner>,
    discovery: Mutex<Option<Discovery>>,
    pub events: Receiver<EngineEvent>,
}

impl Engine {
    /// Start the listener, discovery and housekeeping threads.
    pub fn start(
        identity: Identity,
        config: Config,
        paths: Paths,
        trust: TrustStore,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(EVENT_QUEUE);
        let inner = Arc::new(Inner {
            identity,
            paths,
            config: Mutex::new(config),
            trust: Mutex::new(trust),
            conns: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
            events: tx,
            running: AtomicBool::new(true),
            guard: Mutex::new(ConnGuard::new()),
            bound_port: Mutex::new(0),
        });

        let engine = Engine {
            inner: inner.clone(),
            discovery: Mutex::new(None),
            events: rx,
        };
        engine.spawn_listener()?;
        // Discovery is a convenience, not a requirement: if the UDP port is
        // unavailable the node still works for peers that know its address.
        if let Err(e) = engine.spawn_discovery() {
            inner.emit(EngineEvent::Notice(format!(
                "Обнаружение в сети недоступно ({e}); подключайтесь по адресу вручную"
            )));
        }
        engine.spawn_housekeeping()?;
        Ok(engine)
    }

    fn spawn_listener(&self) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        let (want_port, accept) = {
            let c = inner.config.lock().expect("config");
            (c.tcp_port, c.accept_incoming)
        };
        let listener = TcpListener::bind(SocketAddr::from((
            std::net::Ipv4Addr::UNSPECIFIED,
            want_port,
        )))
        .or_else(|_| {
            // Fall back to an ephemeral port rather than refusing to start.
            TcpListener::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
        })?;
        let port = listener.local_addr()?.port();
        *inner.bound_port.lock().expect("port") = port;
        if port != want_port {
            inner.emit(EngineEvent::Notice(format!(
                "Порт {want_port} занят, слушаем {port}"
            )));
        }
        if !accept {
            inner.emit(EngineEvent::Notice("Входящие подключения отключены".into()));
        }

        std::thread::Builder::new()
            .name("syncmob-listener".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if !inner.running.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let inner = inner.clone();
                    if !inner.admit(&stream) {
                        continue;
                    }
                    std::thread::Builder::new()
                        .name("syncmob-conn".into())
                        .spawn(move || match handshake_responder(stream, &inner.identity) {
                            Ok(hs) => inner.run_connection(hs, false, None),
                            Err(e) => log::debug!("inbound handshake failed: {e}"),
                        })
                        .ok();
                }
            })?;
        Ok(())
    }

    fn spawn_discovery(&self) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        let (name, announce) = {
            let c = inner.config.lock().expect("config");
            (c.device_name.clone(), c.discovery_enabled)
        };
        let port = *inner.bound_port.lock().expect("port");
        let info = BeaconInfo {
            public_key: inner.identity.public_key().to_vec(),
            name,
            port,
            platform: PLATFORM.into(),
            announce,
        };
        let cb_inner = inner.clone();
        let d = Discovery::start(info, move |p| cb_inner.on_beacon(p))?;
        *self.discovery.lock().expect("discovery") = Some(d);
        Ok(())
    }

    fn spawn_housekeeping(&self) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name("syncmob-housekeeping".into())
            .spawn(move || {
                let mut last_ping = Instant::now();
                while inner.running.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_secs(2));
                    inner.expire_peers();
                    inner.expire_pairings();
                    if last_ping.elapsed() >= KEEPALIVE {
                        last_ping = Instant::now();
                        inner.ping_all();
                    }
                }
            })?;
        Ok(())
    }

    // ---- queries -------------------------------------------------------

    pub fn device_id(&self) -> DeviceId {
        self.inner.identity.device_id()
    }
    pub fn fingerprint(&self) -> String {
        self.inner.identity.fingerprint()
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.identity.public_key().to_vec()
    }
    pub fn port(&self) -> u16 {
        *self.inner.bound_port.lock().expect("port")
    }
    pub fn config(&self) -> Config {
        self.inner.config.lock().expect("config").clone()
    }
    pub fn trusted(&self) -> Vec<crate::security::TrustedDevice> {
        self.inner.trust.lock().expect("trust").list()
    }
    pub fn peers(&self) -> Vec<PeerInfo> {
        let trust = self.inner.trust.lock().expect("trust");
        let mut v: Vec<PeerInfo> = self
            .inner
            .peers
            .lock()
            .expect("peers")
            .values()
            .map(|p| {
                let mut info = p.info.clone();
                info.paired = trust.is_authorised(&info.public_key);
                info
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
    /// File transfers currently in flight, for the UI's transfer list.
    pub fn active_transfers(&self) -> Vec<TransferInfo> {
        let mut out: Vec<TransferInfo> = self
            .inner
            .outgoing
            .lock()
            .expect("outgoing")
            .values()
            .map(|o| TransferInfo {
                id: TransferId::random(),
                peer: o.to,
                name: o.name.clone(),
                size: o.size,
                done: 0,
                incoming: false,
            })
            .collect();
        out.extend(
            self.inner
                .incoming
                .lock()
                .expect("incoming")
                .values()
                .map(|t| TransferInfo {
                    id: t.id,
                    peer: t.from,
                    name: t.name.clone(),
                    size: t.size,
                    done: t.received,
                    incoming: true,
                }),
        );
        out
    }

    pub fn connections(&self) -> Vec<ConnInfo> {
        self.inner
            .conns
            .lock()
            .expect("conns")
            .values()
            .map(|c| ConnInfo {
                device: device_id(&c.key),
                name: c.name.clone(),
                addr: c.addr,
                fingerprint: c.fingerprint.clone(),
                sas: c.sas.clone(),
                paired: c.authorised,
            })
            .collect()
    }

    /// The string encoded in the pairing QR code.
    ///
    /// It carries our public key out of band, so a device that scans it can
    /// detect a machine-in-the-middle without any code comparison.
    pub fn pairing_uri(&self) -> String {
        let pk = B64URL.encode(self.inner.identity.public_key());
        let cfg = self.config();
        let host = local_ipv4()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "0.0.0.0".into());
        format!(
            "syncmob://pair?v=1&pk={pk}&port={}&host={host}&name={}",
            self.port(),
            url_escape(&cfg.device_name)
        )
    }

    // ---- commands ------------------------------------------------------

    pub fn connect(&self, device: DeviceId) {
        let target = self
            .inner
            .peers
            .lock()
            .expect("peers")
            .get(&device)
            .map(|p| (p.info.addr, p.info.public_key.clone()));
        match target {
            Some((addr, key)) => self.dial(addr, Some(key)),
            None => self
                .inner
                .emit(EngineEvent::Error("Устройство не найдено в сети".into())),
        }
    }

    /// Dial an explicit address. `expect_key`, when present, must match the
    /// key the peer proves in the handshake — this is what makes QR pairing
    /// immune to a machine-in-the-middle.
    pub fn dial(&self, addr: SocketAddr, expect_key: Option<Vec<u8>>) {
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name("syncmob-dial".into())
            .spawn(move || {
                if inner.config.lock().expect("config").lan_only && !is_lan_addr(addr.ip()) {
                    inner.emit(EngineEvent::Error(format!(
                        "Адрес {addr} вне локальной сети (включите доступ вне LAN в настройках)"
                    )));
                    return;
                }
                if inner.conns.lock().expect("conns").len() >= MAX_CONNECTIONS {
                    inner.emit(EngineEvent::Error("Слишком много подключений".into()));
                    return;
                }
                match TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT) {
                    Ok(s) => match handshake_initiator(s, &inner.identity) {
                        Ok(hs) => inner.run_connection(hs, true, expect_key),
                        Err(e) => inner.emit(EngineEvent::Error(format!(
                            "Рукопожатие с {addr} не удалось: {e}"
                        ))),
                    },
                    Err(e) => inner.emit(EngineEvent::Error(format!(
                        "Не удалось подключиться к {addr}: {e}"
                    ))),
                }
            })
            .ok();
    }

    /// Parse and dial a `syncmob://pair?...` URI (typically from a QR code).
    pub fn dial_pairing_uri(&self, uri: &str) -> anyhow::Result<()> {
        let p = parse_pairing_uri(uri)?;
        self.dial(SocketAddr::new(p.host, p.port), Some(p.public_key));
        Ok(())
    }

    pub fn disconnect(&self, device: DeviceId) {
        if let Some(c) = self.inner.conns.lock().expect("conns").get(&device) {
            c.sender.close();
        }
    }

    pub fn send_text(&self, to: DeviceId, text: &str) {
        let text = clamp_str(text.trim(), crate::proto::MAX_TEXT_CHARS);
        if text.is_empty() {
            return;
        }
        let ts = crate::security::trust::now_ms();
        let msg = Message::Text(TextMsg {
            id: TransferId::random(),
            ts,
            text: text.clone(),
        });
        match self.inner.send_to(to, &msg) {
            Ok(()) => self.inner.emit(EngineEvent::TextSent { to, text, ts }),
            Err(e) => self.inner.emit(EngineEvent::Error(e)),
        }
    }

    pub fn send_file(&self, to: DeviceId, path: PathBuf) {
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name("syncmob-send-file".into())
            .spawn(move || inner.send_file_blocking(to, path))
            .ok();
    }

    /// Answer a [`EngineEvent::PairingRequired`] prompt.
    pub fn respond_pairing(&self, device: DeviceId, accept: bool) {
        self.inner.respond_pairing(device, accept);
    }

    /// Answer an [`EngineEvent::OfferReceived`] prompt.
    pub fn respond_offer(&self, transfer: TransferId, accept: bool) {
        self.inner.respond_offer(transfer, accept);
    }

    pub fn cancel_transfer(&self, transfer: TransferId) {
        self.inner.cancel_transfer(transfer);
    }

    pub fn forget(&self, device: DeviceId) {
        let key = self.inner.key_for(device);
        if let Some(key) = key {
            {
                let mut t = self.inner.trust.lock().expect("trust");
                t.remove(&key);
                let _ = t.save(&self.inner.paths.trust(), &self.inner.identity);
            }
            self.disconnect(device);
            self.inner.emit(EngineEvent::TrustChanged);
        }
    }

    pub fn set_auto_accept(&self, device: DeviceId, on: bool) {
        if let Some(key) = self.inner.key_for(device) {
            let mut t = self.inner.trust.lock().expect("trust");
            t.set_auto_accept(&key, on);
            let _ = t.save(&self.inner.paths.trust(), &self.inner.identity);
        }
        self.inner.emit(EngineEvent::TrustChanged);
    }

    pub fn set_blocked(&self, device: DeviceId, blocked: bool) {
        if let Some(key) = self.inner.key_for(device) {
            {
                let mut t = self.inner.trust.lock().expect("trust");
                t.set_blocked(&key, blocked);
                let _ = t.save(&self.inner.paths.trust(), &self.inner.identity);
            }
            if blocked {
                self.disconnect(device);
            }
        }
        self.inner.emit(EngineEvent::TrustChanged);
    }

    /// Apply changed settings. Port changes take effect on the next start.
    pub fn update_config(&self, new: Config) {
        {
            let mut c = self.inner.config.lock().expect("config");
            *c = new.clone();
            let _ = c.save(&self.inner.paths.config());
        }
        if let Some(d) = self.discovery.lock().expect("discovery").as_ref() {
            d.update(|i| {
                i.name = new.device_name.clone();
                i.announce = new.discovery_enabled;
            });
        }
    }

    pub fn shutdown(&self) {
        self.inner.running.store(false, Ordering::Relaxed);
        if let Some(d) = self.discovery.lock().expect("discovery").as_ref() {
            d.stop();
        }
        for c in self.inner.conns.lock().expect("conns").values() {
            c.sender.close();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Inner {
    fn emit(&self, e: EngineEvent) {
        // Never block the network threads on a stalled UI.
        let _ = self.events.try_send(e);
    }

    fn key_for(&self, device: DeviceId) -> Option<Vec<u8>> {
        if let Some(c) = self.conns.lock().expect("conns").get(&device) {
            return Some(c.key.clone());
        }
        if let Some(p) = self.peers.lock().expect("peers").get(&device) {
            return Some(p.info.public_key.clone());
        }
        self.trust
            .lock()
            .expect("trust")
            .by_device_id(device)
            .and_then(|d| d.key_bytes())
    }

    fn admit(&self, stream: &TcpStream) -> bool {
        let Ok(addr) = stream.peer_addr() else {
            return false;
        };
        let cfg = self.config.lock().expect("config");
        if !cfg.accept_incoming {
            return false;
        }
        if cfg.lan_only && !is_lan_addr(addr.ip()) {
            log::warn!("refused non-LAN connection from {addr}");
            return false;
        }
        drop(cfg);
        if self.conns.lock().expect("conns").len() >= MAX_CONNECTIONS {
            return false;
        }
        if !self.guard.lock().expect("guard").allow(addr.ip()) {
            log::warn!("handshake rate limit hit for {addr}");
            return false;
        }
        true
    }

    fn on_beacon(&self, p: DiscoveredPeer) {
        let paired = self
            .trust
            .lock()
            .expect("trust")
            .is_authorised(&p.public_key);
        let info = PeerInfo {
            device: p.device_id,
            name: p.name,
            platform: p.platform,
            addr: p.addr,
            public_key: p.public_key,
            paired,
        };
        let is_new = {
            let mut peers = self.peers.lock().expect("peers");
            if peers.len() >= MAX_PEERS && !peers.contains_key(&info.device) {
                return;
            }
            let new = !peers.contains_key(&info.device);
            peers.insert(
                info.device,
                PeerEntry {
                    info: info.clone(),
                    last_seen: Instant::now(),
                },
            );
            new
        };
        if is_new {
            self.emit(EngineEvent::PeerDiscovered(info));
        }
    }

    fn expire_peers(&self) {
        let mut gone = Vec::new();
        {
            let mut peers = self.peers.lock().expect("peers");
            peers.retain(|id, e| {
                let alive = e.last_seen.elapsed() < PEER_TTL;
                if !alive {
                    gone.push(*id);
                }
                alive
            });
        }
        for id in gone {
            self.emit(EngineEvent::PeerLost(id));
        }
    }

    fn expire_pairings(&self) {
        let mut close = Vec::new();
        {
            let conns = self.conns.lock().expect("conns");
            for (id, c) in conns.iter() {
                if !c.authorised {
                    if let Some(t) = c.prompted_at {
                        if t.elapsed() > PAIRING_TIMEOUT {
                            close.push((*id, c.sender.clone()));
                        }
                    }
                }
            }
        }
        for (id, s) in close {
            s.close();
            self.emit(EngineEvent::Notice(format!(
                "Сопряжение с {id} отменено по тайм-ауту"
            )));
        }
    }

    fn ping_all(&self) {
        let senders: Vec<ChannelSender> = self
            .conns
            .lock()
            .expect("conns")
            .values()
            .map(|c| c.sender.clone())
            .collect();
        for s in senders {
            let _ = s.send(&Message::Ping);
        }
    }

    fn send_to(&self, device: DeviceId, msg: &Message) -> Result<(), String> {
        let conns = self.conns.lock().expect("conns");
        let c = conns.get(&device).ok_or("Нет соединения с устройством")?;
        if !c.authorised {
            return Err("Устройство ещё не сопряжено".into());
        }
        let sender = c.sender.clone();
        drop(conns);
        sender
            .send(msg)
            .map_err(|e| format!("Ошибка отправки: {e}"))
    }

    // ---- connection lifecycle -----------------------------------------

    fn run_connection(
        self: &Arc<Self>,
        hs: Handshaked,
        we_dialed: bool,
        expect_key: Option<Vec<u8>>,
    ) {
        let key = hs.remote_static.clone();
        let device = device_id(&key);
        let addr = hs.peer_addr;

        // QR / out-of-band check: the key we were promised must be the key the
        // peer actually proved. A mismatch is an active attack, not a mistake.
        if let Some(expected) = expect_key {
            if !keys_equal(&expected, &key) {
                self.emit(EngineEvent::Error(format!(
                    "ВНИМАНИЕ: {addr} предъявил другой ключ, чем ожидалось. Соединение разорвано."
                )));
                return;
            }
        }

        let (authorised, blocked, stored_name) = {
            let t = self.trust.lock().expect("trust");
            match t.get(&key) {
                Some(d) => (!d.blocked, d.blocked, d.name.clone()),
                None => (false, false, String::new()),
            }
        };
        if blocked {
            log::warn!("refused connection from blocked device {device}");
            return;
        }
        if !authorised && !self.config.lock().expect("config").allow_new_pairings {
            self.emit(EngineEvent::Notice(format!(
                "Отклонён запрос сопряжения от {device}: новые сопряжения запрещены"
            )));
            return;
        }

        let sas = sas_code(&hs.handshake_hash);
        let fp = fingerprint(&key);
        let (mut reader, sender) = hs.channel.split();

        {
            let mut conns = self.conns.lock().expect("conns");
            if conns.contains_key(&device) {
                log::debug!("duplicate connection to {device}, dropping the new one");
                sender.close();
                return;
            }
            if conns.len() >= MAX_CONNECTIONS {
                sender.close();
                return;
            }
            conns.insert(
                device,
                Conn {
                    sender: sender.clone(),
                    key: key.clone(),
                    name: stored_name,
                    addr,
                    fingerprint: fp.clone(),
                    sas: sas.clone(),
                    authorised,
                    local_ok: false,
                    remote_ok: false,
                    prompted_at: (!authorised).then(Instant::now),
                },
            );
        }

        let cfg_name = self.config.lock().expect("config").device_name.clone();
        let _ = sender.send(&Message::Hello(Hello {
            name: cfg_name,
            version: 1,
            platform: PLATFORM.into(),
        }));

        if authorised {
            self.emit(EngineEvent::Connected(self.conn_info(device)));
        } else {
            if we_dialed {
                let name = self.config.lock().expect("config").device_name.clone();
                let _ = sender.send(&Message::PairRequest(PairRequest {
                    name,
                    platform: PLATFORM.into(),
                }));
            }
            self.emit(EngineEvent::PairingRequired {
                device,
                name: String::new(),
                fingerprint: fp,
                sas,
                addr,
                remote_initiated: !we_dialed,
            });
        }

        let reason = loop {
            match reader.recv() {
                Ok(msg) => {
                    if let Err(e) = self.on_message(device, &key, msg) {
                        break e;
                    }
                }
                Err(e) => break e.to_string(),
            }
        };

        sender.close();
        self.conns.lock().expect("conns").remove(&device);
        self.fail_transfers_for(device, "соединение закрыто");
        self.emit(EngineEvent::Disconnected { device, reason });
    }

    fn conn_info(&self, device: DeviceId) -> ConnInfo {
        let conns = self.conns.lock().expect("conns");
        match conns.get(&device) {
            Some(c) => ConnInfo {
                device,
                name: c.name.clone(),
                addr: c.addr,
                fingerprint: c.fingerprint.clone(),
                sas: c.sas.clone(),
                paired: c.authorised,
            },
            None => ConnInfo {
                device,
                name: String::new(),
                addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                fingerprint: String::new(),
                sas: String::new(),
                paired: false,
            },
        }
    }

    /// Single choke point for everything a peer can say. Returning `Err`
    /// terminates the connection.
    fn on_message(
        self: &Arc<Self>,
        device: DeviceId,
        key: &[u8],
        msg: Message,
    ) -> Result<(), String> {
        let authorised = self
            .conns
            .lock()
            .expect("conns")
            .get(&device)
            .map(|c| c.authorised)
            .unwrap_or(false);

        if !authorised && !msg.allowed_before_pairing() {
            return Err("устройство прислало данные до сопряжения".into());
        }

        match msg {
            Message::Ping => {
                let _ = self.send_raw(device, &Message::Pong);
            }
            Message::Pong => {}
            Message::Hello(h) => {
                let name = clamp_str(&h.name, 64);
                if let Some(c) = self.conns.lock().expect("conns").get_mut(&device) {
                    c.name = name.clone();
                }
                if authorised {
                    let mut t = self.trust.lock().expect("trust");
                    t.touch(key, &name);
                    let _ = t.save(&self.paths.trust(), &self.identity);
                }
                self.emit(EngineEvent::Connected(self.conn_info(device)));
            }
            Message::PairRequest(p) => {
                let name = clamp_str(&p.name, 64);
                let (fp, sas, addr) = {
                    let mut conns = self.conns.lock().expect("conns");
                    let c = conns.get_mut(&device).ok_or("нет соединения")?;
                    c.name = name.clone();
                    c.prompted_at = Some(Instant::now());
                    (c.fingerprint.clone(), c.sas.clone(), c.addr)
                };
                if !authorised {
                    self.emit(EngineEvent::PairingRequired {
                        device,
                        name,
                        fingerprint: fp,
                        sas,
                        addr,
                        remote_initiated: true,
                    });
                }
            }
            Message::PairAccept => {
                if let Some(c) = self.conns.lock().expect("conns").get_mut(&device) {
                    c.remote_ok = true;
                }
                self.try_finalize_pairing(device);
            }
            Message::PairReject { reason } => {
                self.emit(EngineEvent::PairingFinished {
                    device,
                    accepted: false,
                });
                return Err(format!("сопряжение отклонено: {}", clamp_str(&reason, 80)));
            }
            Message::Text(t) => {
                self.emit(EngineEvent::TextReceived {
                    from: device,
                    text: clamp_str(&t.text, crate::proto::MAX_TEXT_CHARS),
                    ts: t.ts,
                });
                let _ = self.send_raw(device, &Message::TextAck { id: t.id });
            }
            Message::TextAck { .. } => {}
            Message::FileOffer(o) => self.on_offer(device, key, o),
            Message::FileAccept { id } => self.signal_outgoing(id, OutSignal::Accept),
            Message::FileReject(r) => {
                self.signal_outgoing(r.id, OutSignal::Reject(clamp_str(&r.reason, 120)))
            }
            Message::FileCancel(r) => {
                self.signal_outgoing(r.id, OutSignal::Cancel);
                self.abort_incoming(r.id, &clamp_str(&r.reason, 120));
            }
            Message::FileError(r) => {
                self.signal_outgoing(r.id, OutSignal::Cancel);
                self.abort_incoming(r.id, &clamp_str(&r.reason, 120));
            }
            Message::FileChunk { id, offset, data } => {
                self.on_chunk(device, key, id, offset, &data)
            }
            Message::FileDone(FileDone { id, .. }) => {
                // Completion is decided by byte count and hash in `on_chunk`;
                // this only cleans up a transfer that never completed.
                let stale = self
                    .incoming
                    .lock()
                    .expect("incoming")
                    .get(&id)
                    .map(|t| !t.is_complete())
                    .unwrap_or(false);
                if stale {
                    self.abort_incoming(id, "отправитель сообщил о завершении, но файл неполный");
                }
            }
        }
        Ok(())
    }

    fn send_raw(&self, device: DeviceId, msg: &Message) -> Result<(), String> {
        let sender = self
            .conns
            .lock()
            .expect("conns")
            .get(&device)
            .map(|c| c.sender.clone())
            .ok_or("нет соединения")?;
        sender.send(msg).map_err(|e| e.to_string())
    }

    // ---- pairing -------------------------------------------------------

    fn respond_pairing(self: &Arc<Self>, device: DeviceId, accept: bool) {
        let sender = self
            .conns
            .lock()
            .expect("conns")
            .get(&device)
            .map(|c| c.sender.clone());
        let Some(sender) = sender else {
            self.emit(EngineEvent::Error("Соединение уже закрыто".into()));
            return;
        };
        if !accept {
            let _ = sender.send(&Message::PairReject {
                reason: "отклонено пользователем".into(),
            });
            sender.close();
            self.emit(EngineEvent::PairingFinished {
                device,
                accepted: false,
            });
            return;
        }
        if let Some(c) = self.conns.lock().expect("conns").get_mut(&device) {
            c.local_ok = true;
        }
        let _ = sender.send(&Message::PairAccept);
        self.try_finalize_pairing(device);
    }

    /// Pairing completes only when *both* users approved. One-sided approval
    /// never grants access.
    fn try_finalize_pairing(self: &Arc<Self>, device: DeviceId) {
        let (ready, key, name) = {
            let conns = self.conns.lock().expect("conns");
            match conns.get(&device) {
                Some(c) => (
                    c.local_ok && c.remote_ok && !c.authorised,
                    c.key.clone(),
                    c.name.clone(),
                ),
                None => (false, Vec::new(), String::new()),
            }
        };
        if !ready {
            return;
        }
        {
            let mut t = self.trust.lock().expect("trust");
            if let Err(e) = t.add(&key, &name) {
                self.emit(EngineEvent::Error(format!(
                    "Не удалось сохранить сопряжение: {e}"
                )));
                return;
            }
            if let Err(e) = t.save(&self.paths.trust(), &self.identity) {
                self.emit(EngineEvent::Error(format!(
                    "Не удалось записать список доверия: {e}"
                )));
            }
        }
        if let Some(c) = self.conns.lock().expect("conns").get_mut(&device) {
            c.authorised = true;
            c.prompted_at = None;
        }
        self.emit(EngineEvent::PairingFinished {
            device,
            accepted: true,
        });
        self.emit(EngineEvent::TrustChanged);
        self.emit(EngineEvent::Connected(self.conn_info(device)));
    }

    // ---- incoming files ------------------------------------------------

    fn on_offer(self: &Arc<Self>, device: DeviceId, key: &[u8], o: FileOffer) {
        let (limit, auto) = {
            let cfg = self.config.lock().expect("config");
            let auto = self
                .trust
                .lock()
                .expect("trust")
                .get(key)
                .map(|d| d.auto_accept_files)
                .unwrap_or(false);
            (cfg.max_file_size, auto)
        };
        if limit > 0 && o.size > limit {
            let _ = self.send_raw(
                device,
                &Message::FileReject(IdReason {
                    id: o.id,
                    reason: "файл слишком большой".into(),
                }),
            );
            self.emit(EngineEvent::Notice(format!(
                "Отклонён файл {} — превышен лимит размера",
                clamp_str(&o.name, 60)
            )));
            return;
        }

        let t = IncomingTransfer::new(o.id, device, key.to_vec(), &o.name, o.size, &o.sha256);
        let display_name = t.name.clone();
        {
            let mut inc = self.incoming.lock().expect("incoming");
            if inc.len() >= MAX_INCOMING_TRANSFERS || inc.contains_key(&o.id) {
                let _ = self.send_raw(
                    device,
                    &Message::FileReject(IdReason {
                        id: o.id,
                        reason: "слишком много передач".into(),
                    }),
                );
                return;
            }
            inc.insert(o.id, t);
        }

        if auto {
            self.respond_offer(o.id, true);
        } else {
            self.emit(EngineEvent::OfferReceived {
                from: device,
                transfer: o.id,
                name: display_name,
                size: o.size,
            });
        }
    }

    fn respond_offer(self: &Arc<Self>, id: TransferId, accept: bool) {
        let device = {
            let inc = self.incoming.lock().expect("incoming");
            match inc.get(&id) {
                Some(t) => t.from,
                None => return,
            }
        };
        if !accept {
            self.abort_incoming(id, "отклонено пользователем");
            let _ = self.send_raw(
                device,
                &Message::FileReject(IdReason {
                    id,
                    reason: "отклонено получателем".into(),
                }),
            );
            return;
        }
        let dir = self.paths.incoming();
        let ok = {
            let mut inc = self.incoming.lock().expect("incoming");
            match inc.get_mut(&id) {
                Some(t) => t.accept(&dir).is_ok(),
                None => false,
            }
        };
        if ok {
            let _ = self.send_raw(device, &Message::FileAccept { id });
        } else {
            self.abort_incoming(id, "не удалось создать файл");
            let _ = self.send_raw(
                device,
                &Message::FileReject(IdReason {
                    id,
                    reason: "ошибка записи на диск".into(),
                }),
            );
        }
    }

    fn on_chunk(
        self: &Arc<Self>,
        device: DeviceId,
        key: &[u8],
        id: TransferId,
        offset: u64,
        data: &[u8],
    ) {
        enum Outcome {
            Ignore,
            Progress(u64, u64),
            Complete,
            Fail(String),
        }
        let outcome = {
            let mut inc = self.incoming.lock().expect("incoming");
            match inc.get_mut(&id) {
                None => Outcome::Ignore,
                Some(t) => {
                    // A transfer belongs to exactly one peer; another
                    // connection may not write into it even if it learns the id.
                    if t.from != device || !keys_equal(&t.from_key, key) {
                        Outcome::Ignore
                    } else {
                        match t.write_chunk(offset, data) {
                            Ok(()) if t.is_complete() => Outcome::Complete,
                            Ok(()) => Outcome::Progress(t.received, t.size),
                            Err(e) => Outcome::Fail(e.to_string()),
                        }
                    }
                }
            }
        };
        match outcome {
            Outcome::Ignore => {}
            Outcome::Progress(done, total) => {
                // Throttle: one event per 64 chunks (~2 MiB).
                if done % (CHUNK_SIZE as u64 * 64) < CHUNK_SIZE as u64 {
                    self.emit(EngineEvent::TransferProgress {
                        transfer: id,
                        done,
                        total,
                        incoming: true,
                    });
                }
            }
            Outcome::Complete => {
                let t = self.incoming.lock().expect("incoming").remove(&id);
                if let Some(t) = t {
                    let name = t.name.clone();
                    let dir = self.config.lock().expect("config").download_dir.clone();
                    match t.finish(&dir) {
                        Ok(path) => {
                            self.emit(EngineEvent::TransferFinished {
                                transfer: id,
                                incoming: true,
                                name,
                                path: Some(path),
                                error: None,
                            });
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            let _ = self.send_raw(
                                device,
                                &Message::FileError(IdReason {
                                    id,
                                    reason: msg.clone(),
                                }),
                            );
                            self.emit(EngineEvent::TransferFinished {
                                transfer: id,
                                incoming: true,
                                name,
                                path: None,
                                error: Some(msg),
                            });
                        }
                    }
                }
            }
            Outcome::Fail(reason) => {
                let _ = self.send_raw(
                    device,
                    &Message::FileError(IdReason {
                        id,
                        reason: reason.clone(),
                    }),
                );
                self.abort_incoming(id, &reason);
            }
        }
    }

    fn abort_incoming(&self, id: TransferId, reason: &str) {
        let t = self.incoming.lock().expect("incoming").remove(&id);
        if let Some(t) = t {
            let name = t.name.clone();
            t.abort();
            self.emit(EngineEvent::TransferFinished {
                transfer: id,
                incoming: true,
                name,
                path: None,
                error: Some(reason.to_string()),
            });
        }
    }

    // ---- outgoing files ------------------------------------------------

    fn send_file_blocking(self: &Arc<Self>, to: DeviceId, path: PathBuf) {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into());

        let (sha, size) = match hash_file(&path) {
            Ok(v) => v,
            Err(e) => {
                self.emit(EngineEvent::Error(format!(
                    "Не удалось прочитать {name}: {e}"
                )));
                return;
            }
        };

        let id = TransferId::random();
        let (sig_tx, sig_rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        self.outgoing.lock().expect("outgoing").insert(
            id,
            Outgoing {
                to,
                name: name.clone(),
                size,
                signal: sig_tx,
                cancel: cancel.clone(),
            },
        );

        let offer = Message::FileOffer(FileOffer {
            id,
            name: name.clone(),
            size,
            sha256: sha,
            mime: String::new(),
        });
        if let Err(e) = self.send_to(to, &offer) {
            self.finish_outgoing(id, name, None, Some(e));
            return;
        }

        match sig_rx.recv_timeout(OFFER_TIMEOUT) {
            Ok(OutSignal::Accept) => {}
            Ok(OutSignal::Reject(r)) => {
                self.finish_outgoing(id, name, None, Some(format!("получатель отказался: {r}")));
                return;
            }
            Ok(OutSignal::Cancel) => {
                self.finish_outgoing(id, name, None, Some("отменено".into()));
                return;
            }
            Err(_) => {
                self.finish_outgoing(id, name, None, Some("получатель не ответил".into()));
                return;
            }
        }

        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                self.finish_outgoing(id, name, None, Some(e.to_string()));
                return;
            }
        };
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut offset = 0u64;
        let mut chunk_no = 0u64;

        loop {
            if cancel.load(Ordering::Relaxed) {
                self.finish_outgoing(id, name, None, Some("отменено".into()));
                return;
            }
            if let Ok(sig) = sig_rx.try_recv() {
                if matches!(sig, OutSignal::Cancel | OutSignal::Reject(_)) {
                    self.finish_outgoing(id, name, None, Some("прервано получателем".into()));
                    return;
                }
            }
            let n = match std::io::Read::read(&mut reader, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    let _ = self.send_to(
                        to,
                        &Message::FileError(IdReason {
                            id,
                            reason: e.to_string(),
                        }),
                    );
                    self.finish_outgoing(id, name, None, Some(e.to_string()));
                    return;
                }
            };
            let msg = Message::FileChunk {
                id,
                offset,
                data: buf[..n].to_vec(),
            };
            if let Err(e) = self.send_to(to, &msg) {
                self.finish_outgoing(id, name, None, Some(e));
                return;
            }
            offset += n as u64;
            chunk_no += 1;
            if chunk_no % 64 == 0 {
                self.emit(EngineEvent::TransferProgress {
                    transfer: id,
                    done: offset,
                    total: size,
                    incoming: false,
                });
            }
        }

        if offset != size {
            let _ = self.send_to(
                to,
                &Message::FileError(IdReason {
                    id,
                    reason: "файл изменился во время отправки".into(),
                }),
            );
            self.finish_outgoing(
                id,
                name,
                None,
                Some("файл изменился во время отправки".into()),
            );
            return;
        }

        let done = Message::FileDone(FileDone {
            id,
            sha256: String::new(),
        });
        let _ = self.send_to(to, &done);
        self.finish_outgoing(id, name, Some(path), None);
    }

    fn finish_outgoing(
        &self,
        id: TransferId,
        name: String,
        path: Option<PathBuf>,
        error: Option<String>,
    ) {
        self.outgoing.lock().expect("outgoing").remove(&id);
        self.emit(EngineEvent::TransferFinished {
            transfer: id,
            incoming: false,
            name,
            path,
            error,
        });
    }

    fn signal_outgoing(&self, id: TransferId, sig: OutSignal) {
        if let Some(o) = self.outgoing.lock().expect("outgoing").get(&id) {
            let _ = o.signal.send(sig);
        }
    }

    fn cancel_transfer(self: &Arc<Self>, id: TransferId) {
        let target = self
            .outgoing
            .lock()
            .expect("outgoing")
            .get(&id)
            .map(|o| (o.to, o.cancel.clone()));
        if let Some((to, cancel)) = target {
            cancel.store(true, Ordering::Relaxed);
            let _ = self.send_to(
                to,
                &Message::FileCancel(IdReason {
                    id,
                    reason: "отменено отправителем".into(),
                }),
            );
            return;
        }
        let device = self
            .incoming
            .lock()
            .expect("incoming")
            .get(&id)
            .map(|t| t.from);
        if let Some(device) = device {
            let _ = self.send_raw(
                device,
                &Message::FileCancel(IdReason {
                    id,
                    reason: "отменено получателем".into(),
                }),
            );
            self.abort_incoming(id, "отменено");
        }
    }

    fn fail_transfers_for(&self, device: DeviceId, reason: &str) {
        let ids: Vec<TransferId> = self
            .incoming
            .lock()
            .expect("incoming")
            .iter()
            .filter(|(_, t)| t.from == device)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.abort_incoming(id, reason);
        }
        let outs: Vec<Arc<AtomicBool>> = self
            .outgoing
            .lock()
            .expect("outgoing")
            .values()
            .filter(|o| o.to == device)
            .map(|o| o.cancel.clone())
            .collect();
        for c in outs {
            c.store(true, Ordering::Relaxed);
        }
    }
}

// ---- pairing URI --------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PairingTarget {
    pub public_key: Vec<u8>,
    pub host: IpAddr,
    pub port: u16,
    pub name: String,
}

/// Parse `syncmob://pair?v=1&pk=..&host=..&port=..&name=..`.
///
/// Strict on purpose: a malformed or truncated QR scan must not silently
/// degrade into "connect to whatever and trust it".
pub fn parse_pairing_uri(uri: &str) -> anyhow::Result<PairingTarget> {
    let rest = uri
        .strip_prefix("syncmob://pair?")
        .ok_or_else(|| anyhow::anyhow!("не похоже на ссылку сопряжения SyncMob"))?;
    let mut pk = None;
    let mut host = None;
    let mut port = None;
    let mut name = String::new();
    for kv in rest.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            "pk" => pk = B64URL.decode(v).ok(),
            "host" => host = v.parse::<IpAddr>().ok(),
            "port" => port = v.parse::<u16>().ok(),
            "name" => name = clamp_str(&url_unescape(v), 64),
            _ => {}
        }
    }
    let pk = pk.ok_or_else(|| anyhow::anyhow!("в ссылке нет корректного ключа"))?;
    if pk.len() != 32 {
        anyhow::bail!("некорректная длина ключа");
    }
    let host = host.ok_or_else(|| anyhow::anyhow!("в ссылке нет адреса"))?;
    let port = port.filter(|p| *p > 0).unwrap_or(DEFAULT_TCP_PORT);
    Ok(PairingTarget {
        public_key: pk,
        host,
        port,
        name,
    })
}

fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn url_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Best-effort local IPv4 for display and for the pairing QR code.
pub fn local_ipv4() -> Option<std::net::Ipv4Addr> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    ifaces
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) if is_lan_addr(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        })
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_uri_roundtrip() {
        let pk = vec![9u8; 32];
        let uri = format!(
            "syncmob://pair?v=1&pk={}&port=45821&host=192.168.1.7&name={}",
            B64URL.encode(&pk),
            url_escape("Мой ПК")
        );
        let t = parse_pairing_uri(&uri).unwrap();
        assert_eq!(t.public_key, pk);
        assert_eq!(t.port, 45821);
        assert_eq!(t.host.to_string(), "192.168.1.7");
        assert_eq!(t.name, "Мой ПК");
    }

    #[test]
    fn pairing_uri_rejects_garbage() {
        assert!(parse_pairing_uri("https://evil.example/pair?pk=AAAA").is_err());
        assert!(parse_pairing_uri("syncmob://pair?host=192.168.1.7").is_err());
        // Wrong key length must be refused, not truncated or padded.
        let short = B64URL.encode([1u8; 16]);
        assert!(parse_pairing_uri(&format!("syncmob://pair?pk={short}&host=10.0.0.1")).is_err());
    }

    #[test]
    fn url_escaping_roundtrips() {
        for s in ["Мой ПК", "a b&c=d", "plain", "100%"] {
            assert_eq!(url_unescape(&url_escape(s)), s);
        }
    }

    #[test]
    fn connection_guard_limits_bursts() {
        let mut g = ConnGuard::new();
        let ip: IpAddr = "192.168.0.2".parse().unwrap();
        let allowed = (0..100).filter(|_| g.allow(ip)).count();
        assert_eq!(allowed, HANDSHAKES_PER_MINUTE as usize);
    }
}

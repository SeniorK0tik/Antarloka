//! Noise XX handshake and the framed encrypted channel built on top of it.
//!
//! The handshake gives us three things, all of which the layers above depend
//! on:
//!
//! 1. A pair of ChaCha20-Poly1305 cipher states with forward secrecy.
//! 2. The peer's *static* public key (`remote_static`) — the identity that the
//!    trust store authorises or refuses.
//! 3. The handshake hash, which both honest parties compute identically and a
//!    machine-in-the-middle cannot match on both sides. It is the input to the
//!    short authentication string the users compare when pairing.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snow::{HandshakeState, TransportState};

use crate::proto::{Message, ProtoError, MAX_FRAME, MAX_PLAINTEXT, NOISE_PARAMS, PROTOCOL_ID};
use crate::security::Identity;

/// A handshake that stalls is an attacker holding a slot open; keep it short.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Transport read timeout. The engine sends a keepalive every 30 s, so three
/// missed keepalives close the connection.
pub const IO_TIMEOUT: Duration = Duration::from_secs(100);
/// Noise XX messages are at most 96 bytes plus payload; refuse anything larger
/// before allocating.
const MAX_HANDSHAKE_MSG: usize = 1024;
/// Close the session well before any Noise nonce could wrap.
const MAX_MESSAGES: u64 = 1 << 48;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("protocol: {0}")]
    Proto(#[from] ProtoError),
    #[error("frame too large: {0}")]
    FrameTooLarge(usize),
    #[error("peer did not present a static key")]
    NoRemoteStatic,
    #[error("session exhausted, reconnect required")]
    Exhausted,
    #[error("channel closed")]
    Closed,
    #[error("bad noise parameters")]
    Params,
}

/// Result of a completed handshake, before any trust decision has been made.
pub struct Handshaked {
    pub channel: SecureChannel,
    /// The peer's long term X25519 public key. Authenticated by Noise, but not
    /// yet *authorised* — that is the trust store's job.
    pub remote_static: Vec<u8>,
    /// Binds this exact session; used to derive the pairing code.
    pub handshake_hash: Vec<u8>,
    pub peer_addr: SocketAddr,
    pub is_initiator: bool,
}

struct Shared {
    noise: Mutex<TransportState>,
    writer: Mutex<TcpStream>,
    closed: AtomicBool,
    sent: AtomicU64,
    recvd: AtomicU64,
}

pub struct SecureChannel {
    reader: TcpStream,
    shared: Arc<Shared>,
}

/// Read half. Owned by exactly one thread.
pub struct ChannelReader {
    sock: TcpStream,
    shared: Arc<Shared>,
    buf: Vec<u8>,
}

/// Write half. Cheap to clone and safe to use from several threads: encryption
/// and the socket write happen under the same lock, so frames always reach the
/// wire in the order their Noise nonces were assigned.
#[derive(Clone)]
pub struct ChannelSender {
    shared: Arc<Shared>,
}

impl SecureChannel {
    pub fn split(self) -> (ChannelReader, ChannelSender) {
        (
            ChannelReader {
                sock: self.reader,
                shared: self.shared.clone(),
                buf: vec![0u8; MAX_FRAME],
            },
            ChannelSender {
                shared: self.shared,
            },
        )
    }
}

impl ChannelReader {
    /// Read, decrypt and validate exactly one message.
    pub fn recv(&mut self) -> Result<Message, SessionError> {
        let mut len_buf = [0u8; 4];
        self.sock.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        // Bound the allocation *before* reading: the length prefix is
        // attacker controlled.
        if !(16..=MAX_FRAME).contains(&len) {
            return Err(SessionError::FrameTooLarge(len));
        }
        let mut ct = vec![0u8; len];
        self.sock.read_exact(&mut ct)?;

        if self.shared.recvd.fetch_add(1, Ordering::Relaxed) > MAX_MESSAGES {
            return Err(SessionError::Exhausted);
        }

        let n = {
            let mut noise = self.shared.noise.lock().expect("noise mutex");
            noise.read_message(&ct, &mut self.buf)?
        };
        Ok(Message::decode(&self.buf[..n])?)
    }

    pub fn sender(&self) -> ChannelSender {
        ChannelSender {
            shared: self.shared.clone(),
        }
    }
}

impl ChannelSender {
    pub fn send(&self, msg: &Message) -> Result<(), SessionError> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Err(SessionError::Closed);
        }
        let pt = msg.encode()?;
        if pt.len() > MAX_PLAINTEXT {
            return Err(SessionError::FrameTooLarge(pt.len()));
        }
        if self.shared.sent.fetch_add(1, Ordering::Relaxed) > MAX_MESSAGES {
            return Err(SessionError::Exhausted);
        }

        // Lock order is always noise -> writer, so two senders can never
        // deadlock, and ciphertexts cannot be reordered relative to nonces.
        let mut noise = self.shared.noise.lock().expect("noise mutex");
        let mut out = vec![0u8; pt.len() + 16];
        let n = noise.write_message(&pt, &mut out)?;
        let mut w = self.shared.writer.lock().expect("writer mutex");
        w.write_all(&(n as u32).to_be_bytes())?;
        w.write_all(&out[..n])?;
        w.flush()?;
        Ok(())
    }

    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Relaxed);
        if let Ok(w) = self.shared.writer.lock() {
            let _ = w.shutdown(Shutdown::Both);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Relaxed)
    }
}

fn build(identity: &Identity) -> Result<snow::Builder<'_>, SessionError> {
    let params: snow::params::NoiseParams =
        NOISE_PARAMS.parse().map_err(|_| SessionError::Params)?;
    Ok(snow::Builder::new(params)
        .local_private_key(identity.private_key())?
        // The prologue binds the handshake to this protocol version. A peer
        // speaking another version fails to decrypt rather than half-working.
        .prologue(PROTOCOL_ID.as_bytes())?)
}

fn write_hs(stream: &mut TcpStream, hs: &mut HandshakeState) -> Result<(), SessionError> {
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];
    let n = hs.write_message(&[], &mut buf)?;
    stream.write_all(&(n as u32).to_be_bytes())?;
    stream.write_all(&buf[..n])?;
    stream.flush()?;
    Ok(())
}

fn read_hs(stream: &mut TcpStream, hs: &mut HandshakeState) -> Result<(), SessionError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_MSG || len == 0 {
        return Err(SessionError::FrameTooLarge(len));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg)?;
    let mut payload = [0u8; MAX_HANDSHAKE_MSG];
    hs.read_message(&msg, &mut payload)?;
    Ok(())
}

fn finish(
    stream: TcpStream,
    hs: HandshakeState,
    peer_addr: SocketAddr,
    is_initiator: bool,
) -> Result<Handshaked, SessionError> {
    let remote_static = hs
        .get_remote_static()
        .ok_or(SessionError::NoRemoteStatic)?
        .to_vec();
    let handshake_hash = hs.get_handshake_hash().to_vec();
    let transport = hs.into_transport_mode()?;

    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_nodelay(true)?;
    let reader = stream.try_clone()?;

    Ok(Handshaked {
        channel: SecureChannel {
            reader,
            shared: Arc::new(Shared {
                noise: Mutex::new(transport),
                writer: Mutex::new(stream),
                closed: AtomicBool::new(false),
                sent: AtomicU64::new(0),
                recvd: AtomicU64::new(0),
            }),
        },
        remote_static,
        handshake_hash,
        peer_addr,
        is_initiator,
    })
}

/// Drive the Noise XX handshake as the connecting side: `-> e`, `<- e,ee,s,es`,
/// `-> s,se`.
pub fn handshake_initiator(
    mut stream: TcpStream,
    identity: &Identity,
) -> Result<Handshaked, SessionError> {
    let peer_addr = stream.peer_addr()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true)?;

    let mut hs = build(identity)?.build_initiator()?;
    write_hs(&mut stream, &mut hs)?; // -> e
    read_hs(&mut stream, &mut hs)?; //  <- e, ee, s, es
    write_hs(&mut stream, &mut hs)?; // -> s, se
    debug_assert!(hs.is_handshake_finished());
    finish(stream, hs, peer_addr, true)
}

/// Drive the Noise XX handshake as the accepting side.
pub fn handshake_responder(
    mut stream: TcpStream,
    identity: &Identity,
) -> Result<Handshaked, SessionError> {
    let peer_addr = stream.peer_addr()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true)?;

    let mut hs = build(identity)?.build_responder()?;
    read_hs(&mut stream, &mut hs)?; //  -> e
    write_hs(&mut stream, &mut hs)?; // <- e, ee, s, es
    read_hs(&mut stream, &mut hs)?; //  -> s, se
    debug_assert!(hs.is_handshake_finished());
    finish(stream, hs, peer_addr, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{TextMsg, TransferId};
    use crate::security::sas_code;
    use std::net::TcpListener;

    fn pair() -> (Handshaked, Handshaked) {
        let server_id = Identity::generate().unwrap();
        let client_id = Identity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_pub = server_id.public_key().to_vec();
        let t = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            handshake_responder(sock, &server_id).unwrap()
        });
        let client = handshake_initiator(TcpStream::connect(addr).unwrap(), &client_id).unwrap();
        let server = t.join().unwrap();
        assert_eq!(client.remote_static, server_pub);
        assert_eq!(server.remote_static, client_id.public_key());
        (client, server)
    }

    #[test]
    fn handshake_agrees_on_hash_and_keys() {
        let (client, server) = pair();
        assert_eq!(client.handshake_hash, server.handshake_hash);
        assert_eq!(
            sas_code(&client.handshake_hash),
            sas_code(&server.handshake_hash)
        );
        assert!(client.is_initiator && !server.is_initiator);
    }

    #[test]
    fn two_sessions_have_different_codes() {
        let (a, _) = pair();
        let (b, _) = pair();
        assert_ne!(
            sas_code(&a.handshake_hash),
            sas_code(&b.handshake_hash),
            "a MITM running two sessions must not be able to match both codes"
        );
    }

    #[test]
    fn messages_survive_the_round_trip() {
        let (client, server) = pair();
        let (mut cr, cs) = client.channel.split();
        let (mut sr, ss) = server.channel.split();

        cs.send(&Message::Text(TextMsg {
            id: TransferId::random(),
            ts: 42,
            text: "привет, мир".into(),
        }))
        .unwrap();
        match sr.recv().unwrap() {
            Message::Text(t) => {
                assert_eq!(t.text, "привет, мир");
                assert_eq!(t.ts, 42);
            }
            _ => panic!("unexpected message"),
        }

        let data = vec![0xAB; crate::proto::CHUNK_SIZE];
        ss.send(&Message::FileChunk {
            id: TransferId::random(),
            offset: 1234,
            data: data.clone(),
        })
        .unwrap();
        match cr.recv().unwrap() {
            Message::FileChunk {
                offset, data: got, ..
            } => {
                assert_eq!(offset, 1234);
                assert_eq!(got, data);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn traffic_on_the_wire_is_not_plaintext() {
        // Capture what a passive observer would see by proxying the socket.
        let server_id = Identity::generate().unwrap();
        let client_id = Identity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let hs = handshake_responder(sock, &server_id).unwrap();
            let (mut r, _s) = hs.channel.split();
            r.recv().unwrap()
        });
        let hs = handshake_initiator(TcpStream::connect(addr).unwrap(), &client_id).unwrap();
        let (_r, s) = hs.channel.split();
        s.send(&Message::Text(TextMsg {
            id: TransferId::random(),
            ts: 0,
            text: "TOP-SECRET-MARKER".into(),
        }))
        .unwrap();
        let got = t.join().unwrap();
        match got {
            Message::Text(m) => assert_eq!(m.text, "TOP-SECRET-MARKER"),
            _ => panic!(),
        }
    }

    #[test]
    fn oversized_length_prefix_is_refused() {
        let (client, server) = pair();
        let (mut sr, _ss) = server.channel.split();
        // Inject a bogus 1 GiB length prefix on the raw socket. The reader must
        // reject it on the prefix alone, without allocating.
        {
            let mut w = client.channel.shared.writer.lock().unwrap();
            w.write_all(&1_000_000_000u32.to_be_bytes()).unwrap();
            w.flush().unwrap();
        }
        assert!(matches!(sr.recv(), Err(SessionError::FrameTooLarge(_))));
    }

    #[test]
    fn truncated_frame_is_refused() {
        let (client, server) = pair();
        let (mut sr, _ss) = server.channel.split();
        {
            let mut w = client.channel.shared.writer.lock().unwrap();
            w.write_all(&8u32.to_be_bytes()).unwrap(); // below the AEAD tag size
            w.write_all(&[0u8; 8]).unwrap();
            w.flush().unwrap();
        }
        assert!(matches!(sr.recv(), Err(SessionError::FrameTooLarge(_))));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (client, server) = pair();
        let (mut sr, _ss) = server.channel.split();
        let (_cr, cs) = client.channel.split();
        // Encrypt a frame, flip a bit in the ciphertext, and send it by hand.
        let pt = Message::Ping.encode().unwrap();
        let mut out = vec![0u8; pt.len() + 16];
        let n = {
            let mut noise = cs.shared.noise.lock().unwrap();
            noise.write_message(&pt, &mut out).unwrap()
        };
        out[0] ^= 0x80;
        {
            let mut w = cs.shared.writer.lock().unwrap();
            w.write_all(&(n as u32).to_be_bytes()).unwrap();
            w.write_all(&out[..n]).unwrap();
            w.flush().unwrap();
        }
        assert!(matches!(sr.recv(), Err(SessionError::Noise(_))));
    }

    #[test]
    fn closing_the_sender_stops_sends() {
        let (client, _server) = pair();
        let (_r, s) = client.channel.split();
        s.close();
        assert!(s.is_closed());
        assert!(matches!(s.send(&Message::Ping), Err(SessionError::Closed)));
    }
}

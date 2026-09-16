//! SyncMob wire protocol, version 1.
//!
//! This module is the single source of truth for what goes over the network and
//! is mirrored byte-for-byte by the Android module (`mobile/`). See
//! `../PROTOCOL.md` for the prose specification.
//!
//! Framing (inside the Noise transport):
//! ```text
//!   u32be  ciphertext_len   (<= 65535, Noise message limit)
//!   bytes  ciphertext       (ChaCha20-Poly1305, 16 byte tag included)
//! ```
//! Decrypted plaintext:
//! ```text
//!   u8     message type
//!   bytes  payload  (JSON for control messages, binary for FILE_CHUNK)
//! ```

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Human readable protocol identifier, also used as the Noise prologue so that
/// a handshake cannot be transplanted to another protocol version.
pub const PROTOCOL_ID: &str = "SyncMob/1";
/// Noise pattern: mutual authentication with identity hiding for the initiator
/// and forward secrecy for everything after the first message.
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub const DISCOVERY_PORT: u16 = 45820;
pub const DEFAULT_TCP_PORT: u16 = 45821;
pub const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 79, 20);

/// Noise caps a single transport message at 65535 bytes.
pub const MAX_FRAME: usize = 65535;
/// ...of which 16 bytes are the Poly1305 tag.
pub const MAX_PLAINTEXT: usize = MAX_FRAME - 16;
/// Payload bytes carried by one FILE_CHUNK.
pub const CHUNK_SIZE: usize = 32 * 1024;
/// Control messages are tiny; anything larger is malformed or hostile.
pub const MAX_CONTROL_JSON: usize = 16 * 1024;
/// Hard ceiling on an advertised file size (1 TiB), independent of user config.
pub const MAX_FILE_SIZE: u64 = 1 << 40;
/// Longest text message we accept.
pub const MAX_TEXT_CHARS: usize = 4096;
/// Longest device name we accept from the wire.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest (unsanitised) file name we accept from the wire.
pub const MAX_FILENAME_CHARS: usize = 255;

pub mod ty {
    pub const HELLO: u8 = 0x01;
    pub const PING: u8 = 0x02;
    pub const PONG: u8 = 0x03;

    pub const PAIR_REQUEST: u8 = 0x10;
    pub const PAIR_ACCEPT: u8 = 0x11;
    pub const PAIR_REJECT: u8 = 0x12;

    pub const TEXT: u8 = 0x20;
    pub const TEXT_ACK: u8 = 0x21;

    pub const FILE_OFFER: u8 = 0x30;
    pub const FILE_ACCEPT: u8 = 0x31;
    pub const FILE_REJECT: u8 = 0x32;
    pub const FILE_CHUNK: u8 = 0x33;
    pub const FILE_DONE: u8 = 0x34;
    pub const FILE_ERROR: u8 = 0x35;
    pub const FILE_CANCEL: u8 = 0x36;
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("empty frame")]
    Empty,
    #[error("unknown message type 0x{0:02x}")]
    UnknownType(u8),
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// 128-bit random transfer identifier, serialised as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransferId(pub [u8; 16]);

impl TransferId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::rng().fill_bytes(&mut b);
        Self(b)
    }
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}
impl fmt::Debug for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransferId({})", hex::encode(self.0))
    }
}

impl Serialize for TransferId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}
impl<'de> Deserialize<'de> for TransferId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let raw = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 16] = raw
            .try_into()
            .map_err(|_| serde::de::Error::custom("transfer id must be 16 bytes"))?;
        Ok(TransferId(arr))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Display name chosen by the remote user. Untrusted, clamp before use.
    pub name: String,
    /// Protocol version the peer speaks.
    pub version: u16,
    /// Informational only (`windows`, `android`, ...).
    #[serde(default)]
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub name: String,
    #[serde(default)]
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextMsg {
    pub id: TransferId,
    /// Sender clock, milliseconds since the Unix epoch. Display only — never
    /// used for ordering decisions that matter for security.
    pub ts: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    pub id: TransferId,
    pub name: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the complete file; verified on receipt.
    pub sha256: String,
    #[serde(default)]
    pub mime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdOnly {
    pub id: TransferId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdReason {
    pub id: TransferId,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDone {
    pub id: TransferId,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    Hello(Hello),
    Ping,
    Pong,
    PairRequest(PairRequest),
    PairAccept,
    PairReject {
        reason: String,
    },
    Text(TextMsg),
    TextAck {
        id: TransferId,
    },
    FileOffer(FileOffer),
    FileAccept {
        id: TransferId,
    },
    FileReject(IdReason),
    FileChunk {
        id: TransferId,
        offset: u64,
        data: Vec<u8>,
    },
    FileDone(FileDone),
    FileError(IdReason),
    FileCancel(IdReason),
}

impl Message {
    pub fn type_byte(&self) -> u8 {
        use Message::*;
        match self {
            Hello(_) => ty::HELLO,
            Ping => ty::PING,
            Pong => ty::PONG,
            PairRequest(_) => ty::PAIR_REQUEST,
            PairAccept => ty::PAIR_ACCEPT,
            PairReject { .. } => ty::PAIR_REJECT,
            Text(_) => ty::TEXT,
            TextAck { .. } => ty::TEXT_ACK,
            FileOffer(_) => ty::FILE_OFFER,
            FileAccept { .. } => ty::FILE_ACCEPT,
            FileReject(_) => ty::FILE_REJECT,
            FileChunk { .. } => ty::FILE_CHUNK,
            FileDone(_) => ty::FILE_DONE,
            FileError(_) => ty::FILE_ERROR,
            FileCancel(_) => ty::FILE_CANCEL,
        }
    }

    /// Messages a peer is allowed to send before it has been paired.
    ///
    /// Everything else is dropped and the connection closed, so an unpaired
    /// peer can never push a file or a message into the UI.
    pub fn allowed_before_pairing(&self) -> bool {
        matches!(
            self,
            Message::Hello(_)
                | Message::Ping
                | Message::Pong
                | Message::PairRequest(_)
                | Message::PairAccept
                | Message::PairReject { .. }
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut out = Vec::with_capacity(64);
        out.push(self.type_byte());
        match self {
            Message::Hello(h) => serde_json::to_writer(&mut out, h)?,
            Message::Ping | Message::Pong | Message::PairAccept => {}
            Message::PairRequest(p) => serde_json::to_writer(&mut out, p)?,
            Message::PairReject { reason } => {
                serde_json::to_writer(&mut out, &serde_json::json!({ "reason": reason }))?
            }
            Message::Text(t) => serde_json::to_writer(&mut out, t)?,
            Message::TextAck { id } => serde_json::to_writer(&mut out, &IdOnly { id: *id })?,
            Message::FileOffer(o) => serde_json::to_writer(&mut out, o)?,
            Message::FileAccept { id } => serde_json::to_writer(&mut out, &IdOnly { id: *id })?,
            Message::FileReject(r) | Message::FileError(r) | Message::FileCancel(r) => {
                serde_json::to_writer(&mut out, r)?
            }
            Message::FileDone(d) => serde_json::to_writer(&mut out, d)?,
            Message::FileChunk { id, offset, data } => {
                out.extend_from_slice(&id.0);
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        if out.len() > MAX_PLAINTEXT {
            return Err(ProtoError::TooLarge(out.len()));
        }
        Ok(out)
    }

    /// Parse and *validate* a decrypted frame.
    ///
    /// Every bound checked here is a bound an attacker would otherwise control:
    /// allocation sizes, string lengths, file sizes and hash formats.
    pub fn decode(buf: &[u8]) -> Result<Message, ProtoError> {
        let (&t, body) = buf.split_first().ok_or(ProtoError::Empty)?;

        // Binary message first: it is the only one allowed to be large.
        if t == ty::FILE_CHUNK {
            if body.len() < 24 {
                return Err(ProtoError::Malformed("file chunk header"));
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(&body[..16]);
            let mut off = [0u8; 8];
            off.copy_from_slice(&body[16..24]);
            let offset = u64::from_be_bytes(off);
            if offset > MAX_FILE_SIZE {
                return Err(ProtoError::Malformed("chunk offset"));
            }
            return Ok(Message::FileChunk {
                id: TransferId(id),
                offset,
                data: body[24..].to_vec(),
            });
        }

        if body.len() > MAX_CONTROL_JSON {
            return Err(ProtoError::TooLarge(body.len()));
        }

        let msg = match t {
            ty::HELLO => {
                let h: Hello = serde_json::from_slice(body)?;
                if h.name.chars().count() > MAX_NAME_CHARS {
                    return Err(ProtoError::Malformed("hello name"));
                }
                Message::Hello(h)
            }
            ty::PING => Message::Ping,
            ty::PONG => Message::Pong,
            ty::PAIR_REQUEST => {
                let p: PairRequest = serde_json::from_slice(body)?;
                if p.name.chars().count() > MAX_NAME_CHARS {
                    return Err(ProtoError::Malformed("pair name"));
                }
                Message::PairRequest(p)
            }
            ty::PAIR_ACCEPT => Message::PairAccept,
            ty::PAIR_REJECT => {
                #[derive(Deserialize)]
                struct R {
                    #[serde(default)]
                    reason: String,
                }
                let r: R = serde_json::from_slice(body)?;
                Message::PairReject { reason: r.reason }
            }
            ty::TEXT => {
                let t: TextMsg = serde_json::from_slice(body)?;
                if t.text.chars().count() > MAX_TEXT_CHARS {
                    return Err(ProtoError::Malformed("text length"));
                }
                Message::Text(t)
            }
            ty::TEXT_ACK => {
                let i: IdOnly = serde_json::from_slice(body)?;
                Message::TextAck { id: i.id }
            }
            ty::FILE_OFFER => {
                let o: FileOffer = serde_json::from_slice(body)?;
                if o.name.chars().count() > MAX_FILENAME_CHARS {
                    return Err(ProtoError::Malformed("file name length"));
                }
                if o.size > MAX_FILE_SIZE {
                    return Err(ProtoError::Malformed("file size"));
                }
                if o.sha256.len() != 64 || !o.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ProtoError::Malformed("sha256"));
                }
                Message::FileOffer(o)
            }
            ty::FILE_ACCEPT => {
                let i: IdOnly = serde_json::from_slice(body)?;
                Message::FileAccept { id: i.id }
            }
            ty::FILE_REJECT => Message::FileReject(serde_json::from_slice(body)?),
            ty::FILE_ERROR => Message::FileError(serde_json::from_slice(body)?),
            ty::FILE_CANCEL => Message::FileCancel(serde_json::from_slice(body)?),
            ty::FILE_DONE => {
                let d: FileDone = serde_json::from_slice(body)?;
                if d.sha256.len() != 64 || !d.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ProtoError::Malformed("sha256"));
                }
                Message::FileDone(d)
            }
            other => return Err(ProtoError::UnknownType(other)),
        };
        Ok(msg)
    }
}

/// UDP discovery beacon. Completely untrusted: it carries no authentication and
/// is only a hint about where a device *might* be reachable. All trust
/// decisions happen after the Noise handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon {
    /// Constant magic so we can reject foreign traffic cheaply.
    pub m: String,
    pub v: u16,
    /// Base64 (standard, padded) X25519 static public key.
    pub pk: String,
    pub name: String,
    pub port: u16,
    #[serde(default)]
    pub platform: String,
}

pub const BEACON_MAGIC: &str = "SYNCMOB";
/// Beacons are tiny; refuse to even parse anything bigger.
pub const MAX_BEACON_BYTES: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_text() {
        let m = Message::Text(TextMsg {
            id: TransferId::random(),
            ts: 1,
            text: "привет".into(),
        });
        let enc = m.encode().unwrap();
        match Message::decode(&enc).unwrap() {
            Message::Text(t) => assert_eq!(t.text, "привет"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn roundtrip_chunk() {
        let id = TransferId::random();
        let m = Message::FileChunk {
            id,
            offset: 4096,
            data: vec![7u8; 1000],
        };
        let enc = m.encode().unwrap();
        match Message::decode(&enc).unwrap() {
            Message::FileChunk {
                id: got,
                offset,
                data,
            } => {
                assert_eq!(got, id);
                assert_eq!(offset, 4096);
                assert_eq!(data.len(), 1000);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn rejects_oversize_text() {
        let m = Message::Text(TextMsg {
            id: TransferId::random(),
            ts: 0,
            text: "a".repeat(MAX_TEXT_CHARS + 1),
        });
        let enc = m.encode().unwrap();
        assert!(Message::decode(&enc).is_err());
    }

    #[test]
    fn rejects_bad_hash_and_size() {
        let bad = serde_json::json!({
            "id": "00000000000000000000000000000000",
            "name": "a.txt", "size": 1u64, "sha256": "zz"
        });
        let mut buf = vec![ty::FILE_OFFER];
        serde_json::to_writer(&mut buf, &bad).unwrap();
        assert!(Message::decode(&buf).is_err());

        let bad = serde_json::json!({
            "id": "00000000000000000000000000000000",
            "name": "a.txt", "size": MAX_FILE_SIZE + 1, "sha256": "0".repeat(64)
        });
        let mut buf = vec![ty::FILE_OFFER];
        serde_json::to_writer(&mut buf, &bad).unwrap();
        assert!(Message::decode(&buf).is_err());
    }

    #[test]
    fn unpaired_peers_cannot_send_data() {
        assert!(!Message::Text(TextMsg {
            id: TransferId::random(),
            ts: 0,
            text: "x".into()
        })
        .allowed_before_pairing());
        assert!(!Message::FileChunk {
            id: TransferId::random(),
            offset: 0,
            data: vec![]
        }
        .allowed_before_pairing());
        assert!(Message::Ping.allowed_before_pairing());
        assert!(Message::PairAccept.allowed_before_pairing());
    }

    #[test]
    fn unknown_type_is_rejected() {
        assert!(Message::decode(&[0xEE, 1, 2, 3]).is_err());
        assert!(Message::decode(&[]).is_err());
    }
}

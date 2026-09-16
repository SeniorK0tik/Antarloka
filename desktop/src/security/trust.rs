//! The list of devices this node has explicitly paired with.
//!
//! Membership in this store is the *only* thing that authorises a peer to send
//! text or files. The file is encrypted and authenticated with a subkey derived
//! from the identity private key, so an attacker who can write to the profile
//! directory cannot inject a trusted key without also owning the identity.

use std::collections::BTreeMap;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::fingerprint::{device_id, fingerprint, keys_equal, DeviceId};
use super::keystore::{write_private_file, Identity, KeystoreError};

const SUBKEY_DOMAIN: &[u8] = b"trust-store";
const AAD: &[u8] = b"SyncMob/1 trust-store";
const FORMAT_VERSION: u16 = 1;
/// Refuse to grow without bound; also caps the damage of a buggy UI loop.
pub const MAX_TRUSTED_DEVICES: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("trust store is corrupt or was tampered with")]
    Tampered,
    #[error("trust store is full ({MAX_TRUSTED_DEVICES} devices)")]
    Full,
    #[error("invalid public key")]
    BadKey,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// Base64 of the 32 byte X25519 static public key. This is the identity.
    pub public_key: String,
    /// Last known display name. Purely cosmetic and refreshed on every
    /// connection, so it must never influence an authorisation decision.
    pub name: String,
    pub added_at_ms: u64,
    pub last_seen_ms: u64,
    /// When true, files from this device are written without asking. Off by
    /// default; the UI warns when enabling it.
    #[serde(default)]
    pub auto_accept_files: bool,
    /// Keeps the key on record but refuses all connections from it.
    #[serde(default)]
    pub blocked: bool,
}

impl TrustedDevice {
    pub fn key_bytes(&self) -> Option<Vec<u8>> {
        let raw = B64.decode(&self.public_key).ok()?;
        (raw.len() == 32).then_some(raw)
    }
    pub fn device_id(&self) -> Option<DeviceId> {
        self.key_bytes().map(|k| device_id(&k))
    }
    pub fn fingerprint(&self) -> String {
        self.key_bytes()
            .map(|k| fingerprint(&k))
            .unwrap_or_default()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u16,
    nonce: String,
    ct: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Contents {
    devices: Vec<TrustedDevice>,
}

#[derive(Debug, Default)]
pub struct TrustStore {
    /// Keyed by base64 public key.
    devices: BTreeMap<String, TrustedDevice>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the store, or return an empty one if the file does not exist.
    ///
    /// A file that exists but fails authentication is an error, never an empty
    /// store: silently starting fresh would let an attacker clear the trust
    /// list by corrupting the file.
    pub fn load(path: &Path, identity: &Identity) -> Result<Self, TrustError> {
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(e.into()),
        };
        let env: Envelope = serde_json::from_slice(&raw).map_err(|_| TrustError::Tampered)?;
        if env.version != FORMAT_VERSION {
            return Err(TrustError::Tampered);
        }
        let nonce = B64.decode(&env.nonce).map_err(|_| TrustError::Tampered)?;
        let ct = B64.decode(&env.ct).map_err(|_| TrustError::Tampered)?;
        if nonce.len() != 24 {
            return Err(TrustError::Tampered);
        }
        let key = identity.derive_subkey(SUBKEY_DOMAIN);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(identity.public_key());
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| TrustError::Tampered)?;
        let contents: Contents = serde_json::from_slice(&pt).map_err(|_| TrustError::Tampered)?;

        let mut devices = BTreeMap::new();
        for d in contents.devices {
            // Drop anything that is not a well formed key rather than keeping a
            // half-valid entry around.
            if d.key_bytes().is_some() {
                devices.insert(d.public_key.clone(), d);
            }
        }
        Ok(Self { devices })
    }

    pub fn save(&self, path: &Path, identity: &Identity) -> Result<(), TrustError> {
        let contents = Contents {
            devices: self.devices.values().cloned().collect(),
        };
        let pt = serde_json::to_vec(&contents).map_err(|_| TrustError::Tampered)?;
        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let key = identity.derive_subkey(SUBKEY_DOMAIN);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(identity.public_key());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .map_err(|_| TrustError::Tampered)?;
        let env = Envelope {
            version: FORMAT_VERSION,
            nonce: B64.encode(nonce),
            ct: B64.encode(&ct),
        };
        let json = serde_json::to_vec_pretty(&env).map_err(|_| TrustError::Tampered)?;
        write_private_file(path, &json)?;
        Ok(())
    }

    /// Look up a device by raw public key.
    pub fn get(&self, public_key: &[u8]) -> Option<&TrustedDevice> {
        let d = self.devices.get(&B64.encode(public_key))?;
        // Belt and braces: verify the stored bytes really match, in constant
        // time, before this entry authorises anything.
        let stored = d.key_bytes()?;
        keys_equal(&stored, public_key).then_some(d)
    }

    /// True only for a device that was paired and is not blocked.
    pub fn is_authorised(&self, public_key: &[u8]) -> bool {
        self.get(public_key).map(|d| !d.blocked).unwrap_or(false)
    }

    pub fn by_device_id(&self, id: DeviceId) -> Option<&TrustedDevice> {
        self.devices.values().find(|d| d.device_id() == Some(id))
    }

    /// Record a new pairing, or refresh the name of an existing one.
    pub fn add(&mut self, public_key: &[u8], name: &str) -> Result<(), TrustError> {
        if public_key.len() != 32 {
            return Err(TrustError::BadKey);
        }
        let b64 = B64.encode(public_key);
        let now = now_ms();
        if let Some(existing) = self.devices.get_mut(&b64) {
            existing.name = crate::util::clamp_str(name, 64);
            existing.last_seen_ms = now;
            existing.blocked = false;
            return Ok(());
        }
        if self.devices.len() >= MAX_TRUSTED_DEVICES {
            return Err(TrustError::Full);
        }
        self.devices.insert(
            b64.clone(),
            TrustedDevice {
                public_key: b64,
                name: crate::util::clamp_str(name, 64),
                added_at_ms: now,
                last_seen_ms: now,
                auto_accept_files: false,
                blocked: false,
            },
        );
        Ok(())
    }

    pub fn remove(&mut self, public_key: &[u8]) -> bool {
        self.devices.remove(&B64.encode(public_key)).is_some()
    }

    pub fn set_auto_accept(&mut self, public_key: &[u8], on: bool) {
        if let Some(d) = self.devices.get_mut(&B64.encode(public_key)) {
            d.auto_accept_files = on;
        }
    }

    pub fn set_blocked(&mut self, public_key: &[u8], blocked: bool) {
        if let Some(d) = self.devices.get_mut(&B64.encode(public_key)) {
            d.blocked = blocked;
        }
    }

    pub fn touch(&mut self, public_key: &[u8], name: &str) {
        if let Some(d) = self.devices.get_mut(&B64.encode(public_key)) {
            d.last_seen_ms = now_ms();
            if !name.is_empty() {
                d.name = crate::util::clamp_str(name, 64);
            }
        }
    }

    pub fn list(&self) -> Vec<TrustedDevice> {
        self.devices.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpaired_key_is_not_authorised() {
        let store = TrustStore::new();
        assert!(!store.is_authorised(&[1u8; 32]));
    }

    #[test]
    fn add_get_remove() {
        let mut s = TrustStore::new();
        s.add(&[1u8; 32], "Phone").unwrap();
        assert!(s.is_authorised(&[1u8; 32]));
        assert!(!s.is_authorised(&[2u8; 32]));
        assert_eq!(s.get(&[1u8; 32]).unwrap().name, "Phone");
        assert!(s.remove(&[1u8; 32]));
        assert!(!s.is_authorised(&[1u8; 32]));
    }

    #[test]
    fn blocked_device_is_not_authorised() {
        let mut s = TrustStore::new();
        s.add(&[1u8; 32], "Phone").unwrap();
        s.set_blocked(&[1u8; 32], true);
        assert!(!s.is_authorised(&[1u8; 32]));
        assert!(s.get(&[1u8; 32]).is_some());
    }

    #[test]
    fn bad_key_length_rejected() {
        let mut s = TrustStore::new();
        assert!(s.add(&[1u8; 16], "x").is_err());
    }

    #[test]
    fn capacity_is_bounded() {
        let mut s = TrustStore::new();
        for i in 0..MAX_TRUSTED_DEVICES {
            let mut k = [0u8; 32];
            k[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            s.add(&k, "d").unwrap();
        }
        assert!(matches!(
            s.add(&[0xFFu8; 32], "overflow"),
            Err(TrustError::Full)
        ));
    }

    #[test]
    fn encrypted_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let id = Identity::generate().unwrap();

        let mut s = TrustStore::new();
        s.add(&[5u8; 32], "Pixel").unwrap();
        s.set_auto_accept(&[5u8; 32], true);
        s.save(&path, &id).unwrap();

        // Names are not readable on disk.
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("Pixel"));

        let loaded = TrustStore::load(&path, &id).unwrap();
        assert!(loaded.is_authorised(&[5u8; 32]));
        assert!(loaded.get(&[5u8; 32]).unwrap().auto_accept_files);
    }

    #[test]
    fn another_identity_cannot_read_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let id = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let mut s = TrustStore::new();
        s.add(&[5u8; 32], "Pixel").unwrap();
        s.save(&path, &id).unwrap();
        assert!(matches!(
            TrustStore::load(&path, &other),
            Err(TrustError::Tampered)
        ));
    }

    #[test]
    fn tampering_is_detected_not_silently_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let id = Identity::generate().unwrap();
        TrustStore::new().save(&path, &id).unwrap();

        let mut env: Envelope = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut ct = B64.decode(&env.ct).unwrap();
        ct[0] ^= 0x01;
        env.ct = B64.encode(&ct);
        std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();

        assert!(matches!(
            TrustStore::load(&path, &id),
            Err(TrustError::Tampered)
        ));
    }

    #[test]
    fn missing_file_is_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate().unwrap();
        let s = TrustStore::load(&dir.path().join("nope.json"), &id).unwrap();
        assert!(s.is_empty());
    }
}

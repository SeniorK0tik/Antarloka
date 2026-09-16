//! Human-verifiable representations of keys.
//!
//! Three distinct values, each with its own domain separation string so that
//! one can never be replayed as another:
//!
//! * [`device_id`] — a short stable handle used in the UI and in maps.
//! * [`fingerprint`] — the value a user compares to authenticate a *key*.
//! * [`sas_code`] — the value a user compares to authenticate a *session*.

use std::fmt;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

const DOMAIN_ID: &[u8] = b"SyncMob/1 device-id";
const DOMAIN_FP: &[u8] = b"SyncMob/1 fingerprint";
const DOMAIN_SAS: &[u8] = b"SyncMob/1 sas";

/// Short, stable identifier derived from the static public key.
///
/// It is a *hash*, not the key itself, and is never used for authentication —
/// only as a map key and a UI label.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId([u8; 8]);

impl DeviceId {
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
    pub fn parse(s: &str) -> Option<Self> {
        let raw = hex::decode(s).ok()?;
        let arr: [u8; 8] = raw.try_into().ok()?;
        Some(DeviceId(arr))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}
impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", hex::encode(self.0))
    }
}

/// Derive the short device identifier from an X25519 static public key.
pub fn device_id(public_key: &[u8]) -> DeviceId {
    let mut h = Blake2s256::new();
    h.update(DOMAIN_ID);
    h.update(public_key);
    let out = h.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&out[..8]);
    DeviceId(id)
}

/// Key fingerprint shown during pairing and in device details.
///
/// 128 bits rendered as eight uppercase hex groups, e.g.
/// `3F2A 91C0 4D18 BB27 0E55 A3F9 6C14 D082`.
pub fn fingerprint(public_key: &[u8]) -> String {
    let mut h = Blake2s256::new();
    h.update(DOMAIN_FP);
    h.update(public_key);
    let out = h.finalize();
    out[..16]
        .chunks(2)
        .map(|c| format!("{:02X}{:02X}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Short authentication string binding *this* session.
///
/// Computed from the Noise handshake hash, which commits to both static keys,
/// both ephemeral keys and the prologue. Two different sessions (as a
/// machine-in-the-middle must run) therefore produce different codes with
/// overwhelming probability, so comparing the code out of band detects the
/// attack. 8 decimal digits leave an online attacker a 1-in-10^8 chance per
/// pairing attempt, and pairing attempts are rate limited and user-visible.
pub fn sas_code(handshake_hash: &[u8]) -> String {
    let mut h = Blake2s256::new();
    h.update(DOMAIN_SAS);
    h.update(handshake_hash);
    let out = h.finalize();
    let mut n = [0u8; 8];
    n.copy_from_slice(&out[..8]);
    let v = u64::from_be_bytes(n) % 100_000_000;
    format!("{:04} {:04}", v / 10_000, v % 10_000)
}

/// Constant-time comparison of two public keys.
///
/// Key comparison happens on every connection; using `==` would leak the
/// position of the first differing byte through timing.
pub fn keys_equal(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_domain_separated() {
        let pk = [7u8; 32];
        assert_eq!(device_id(&pk), device_id(&pk));
        assert_eq!(fingerprint(&pk), fingerprint(&pk));
        // Same input, different domains => different outputs.
        assert_ne!(
            hex::encode(device_id(&pk).as_bytes()),
            fingerprint(&pk).replace(' ', "")
        );
        assert_ne!(fingerprint(&pk), sas_code(&pk));
    }

    #[test]
    fn different_keys_differ() {
        assert_ne!(device_id(&[1u8; 32]), device_id(&[2u8; 32]));
        assert_ne!(fingerprint(&[1u8; 32]), fingerprint(&[2u8; 32]));
        assert_ne!(sas_code(&[1u8; 32]), sas_code(&[2u8; 32]));
    }

    #[test]
    fn formats() {
        let fp = fingerprint(&[0u8; 32]);
        assert_eq!(fp.len(), 8 * 4 + 7);
        assert_eq!(fp.split(' ').count(), 8);
        let sas = sas_code(&[0u8; 32]);
        assert_eq!(sas.len(), 9);
        assert!(sas.chars().all(|c| c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn device_id_roundtrip() {
        let id = device_id(&[3u8; 32]);
        assert_eq!(DeviceId::parse(&id.to_string()), Some(id));
        assert_eq!(DeviceId::parse("nothex"), None);
        assert_eq!(DeviceId::parse("aabb"), None);
    }

    #[test]
    fn constant_time_compare() {
        assert!(keys_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!keys_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!keys_equal(&[1, 2, 3], &[1, 2]));
    }
}

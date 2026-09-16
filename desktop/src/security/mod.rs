//! Identity, at-rest protection and trust decisions.
//!
//! Threat model (see also `../SECURITY.md`):
//!
//! * **On-path attacker on the LAN.** Defeated by the Noise XX handshake:
//!   everything after the first message is encrypted and both sides are
//!   authenticated by their long term X25519 key. A machine-in-the-middle can
//!   complete two separate handshakes, so the *first* contact between two
//!   devices must be confirmed by a human comparing the short authentication
//!   string derived from the handshake hash (or by scanning a QR code that
//!   carries the expected public key out of band).
//! * **Malicious peer that already paired.** Constrained by: explicit approval
//!   per file (unless the user enabled auto-accept for that device), strict
//!   filename sanitising, size limits, SHA-256 verification and writes confined
//!   to the download directory.
//! * **Local attacker with read access to the profile directory.** Constrained
//!   by encrypting the private key with an Argon2id-derived key and
//!   authenticating the trust store with a key derived from the private key.
//! * **Not in scope:** an attacker with code execution as the user while the
//!   application is unlocked, or physical access to unlocked hardware.

pub mod fingerprint;
pub mod keystore;
pub mod trust;

pub use fingerprint::{device_id, fingerprint, sas_code, DeviceId};
pub use keystore::{Identity, KeystoreError, Protection};
pub use trust::{TrustStore, TrustedDevice};

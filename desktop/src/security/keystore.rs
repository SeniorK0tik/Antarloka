//! Long term identity and its protection at rest.
//!
//! The static X25519 private key is the root of all trust in SyncMob: whoever
//! holds it can impersonate this device to every already-paired peer. It is
//! therefore never written to disk in the clear unless the user explicitly
//! opts out, and it is wrapped with XChaCha20-Poly1305 under an Argon2id
//! derived key.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::fingerprint::{device_id, fingerprint, DeviceId};

/// Argon2id cost. ~64 MiB and three passes: comfortably above the point where
/// GPU cracking of a decent passphrase is cheap, still under a second on a
/// desktop CPU.
const ARGON_MEM_KIB: u32 = 64 * 1024;
const ARGON_TIME: u32 = 3;
const ARGON_LANES: u32 = 1;

const FORMAT_VERSION: u16 = 1;
const PROT_ARGON: &str = "argon2id-xchacha20poly1305";
const PROT_PLAIN: &str = "plaintext";

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("keystore file not found")]
    NotFound,
    #[error("this keystore is passphrase protected")]
    NeedPassphrase,
    #[error("this keystore is not passphrase protected")]
    UnexpectedPassphrase,
    #[error("wrong passphrase, or the keystore has been tampered with")]
    WrongPassphrase,
    #[error("keystore is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("unsupported keystore version {0}")]
    Version(u16),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto backend failure")]
    Crypto,
}

/// How the private key is protected on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Argon2id + XChaCha20-Poly1305 (recommended).
    Passphrase,
    /// Stored in the clear. Only ever chosen explicitly by the user.
    None,
}

/// What we can tell about an on-disk keystore without unlocking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreState {
    Missing,
    Encrypted,
    Plaintext,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    version: u16,
    protection: String,
    public: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    secret: String,
}

/// This device's long term identity.
pub struct Identity {
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    protection: Protection,
}

impl std::fmt::Debug for Identity {
    /// Never print key material, not even accidentally through `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("device_id", &self.device_id().to_string())
            .field("protection", &self.protection)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Identity {
    /// Generate a fresh X25519 static keypair using the OS CSPRNG.
    pub fn generate() -> Result<Self, KeystoreError> {
        let params: snow::params::NoiseParams = crate::proto::NOISE_PARAMS
            .parse()
            .map_err(|_| KeystoreError::Crypto)?;
        let kp = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|_| KeystoreError::Crypto)?;
        Ok(Self {
            secret: Zeroizing::new(kp.private),
            public: kp.public,
            protection: Protection::None,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Access to the private key, limited to what `snow` needs to build a
    /// handshake state.
    pub fn private_key(&self) -> &[u8] {
        &self.secret
    }

    pub fn protection(&self) -> Protection {
        self.protection
    }

    pub fn device_id(&self) -> DeviceId {
        device_id(&self.public)
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    /// Derive an independent subkey from the private key.
    ///
    /// Used to authenticate the trust store so that an attacker who can write
    /// to the profile directory cannot silently insert a trusted key without
    /// also holding the identity.
    pub fn derive_subkey(&self, domain: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut h = Blake2s256::new();
        h.update(b"SyncMob/1 subkey");
        h.update((domain.len() as u32).to_be_bytes());
        h.update(domain);
        h.update(&*self.secret);
        let out = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&out);
        Zeroizing::new(key)
    }

    /// Inspect a keystore file without unlocking it.
    pub fn state(path: &Path) -> KeystoreState {
        let Ok(raw) = fs::read(path) else {
            return KeystoreState::Missing;
        };
        match serde_json::from_slice::<StoredKey>(&raw) {
            Ok(s) if s.protection == PROT_ARGON => KeystoreState::Encrypted,
            Ok(_) => KeystoreState::Plaintext,
            Err(_) => KeystoreState::Missing,
        }
    }

    /// Load and, if necessary, decrypt the identity.
    pub fn load(path: &Path, passphrase: Option<&str>) -> Result<Self, KeystoreError> {
        let raw = match fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound)
            }
            Err(e) => return Err(e.into()),
        };
        let stored: StoredKey =
            serde_json::from_slice(&raw).map_err(|_| KeystoreError::Corrupt("json"))?;
        if stored.version != FORMAT_VERSION {
            return Err(KeystoreError::Version(stored.version));
        }
        let public = B64
            .decode(&stored.public)
            .map_err(|_| KeystoreError::Corrupt("public"))?;
        if public.len() != 32 {
            return Err(KeystoreError::Corrupt("public length"));
        }
        let secret_blob = B64
            .decode(&stored.secret)
            .map_err(|_| KeystoreError::Corrupt("secret"))?;

        let (secret, protection) = match stored.protection.as_str() {
            PROT_PLAIN => {
                if passphrase.is_some() {
                    return Err(KeystoreError::UnexpectedPassphrase);
                }
                (Zeroizing::new(secret_blob), Protection::None)
            }
            PROT_ARGON => {
                let Some(pass) = passphrase else {
                    return Err(KeystoreError::NeedPassphrase);
                };
                let salt = B64
                    .decode(
                        stored
                            .salt
                            .as_deref()
                            .ok_or(KeystoreError::Corrupt("salt"))?,
                    )
                    .map_err(|_| KeystoreError::Corrupt("salt"))?;
                let nonce = B64
                    .decode(
                        stored
                            .nonce
                            .as_deref()
                            .ok_or(KeystoreError::Corrupt("nonce"))?,
                    )
                    .map_err(|_| KeystoreError::Corrupt("nonce"))?;
                if salt.len() != 16 || nonce.len() != 24 {
                    return Err(KeystoreError::Corrupt("salt/nonce length"));
                }
                let key = derive_key(pass, &salt)?;
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
                // The public key is authenticated as associated data: swapping
                // in a different public key invalidates the tag.
                let pt = cipher
                    .decrypt(
                        XNonce::from_slice(&nonce),
                        Payload {
                            msg: &secret_blob,
                            aad: &public,
                        },
                    )
                    .map_err(|_| KeystoreError::WrongPassphrase)?;
                (Zeroizing::new(pt), Protection::Passphrase)
            }
            _ => return Err(KeystoreError::Corrupt("protection")),
        };

        if secret.len() != 32 {
            return Err(KeystoreError::Corrupt("secret length"));
        }
        Ok(Self {
            secret,
            public,
            protection,
        })
    }

    /// Write the identity atomically, encrypting it when a passphrase is given.
    pub fn save(&mut self, path: &Path, passphrase: Option<&str>) -> Result<(), KeystoreError> {
        let stored = match passphrase {
            Some(pass) if !pass.is_empty() => {
                let mut salt = [0u8; 16];
                let mut nonce = [0u8; 24];
                rand::rng().fill_bytes(&mut salt);
                rand::rng().fill_bytes(&mut nonce);
                let key = derive_key(pass, &salt)?;
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
                let ct = cipher
                    .encrypt(
                        XNonce::from_slice(&nonce),
                        Payload {
                            msg: &self.secret,
                            aad: &self.public,
                        },
                    )
                    .map_err(|_| KeystoreError::Crypto)?;
                self.protection = Protection::Passphrase;
                StoredKey {
                    version: FORMAT_VERSION,
                    protection: PROT_ARGON.into(),
                    public: B64.encode(&self.public),
                    salt: Some(B64.encode(salt)),
                    nonce: Some(B64.encode(nonce)),
                    secret: B64.encode(&ct),
                }
            }
            _ => {
                self.protection = Protection::None;
                StoredKey {
                    version: FORMAT_VERSION,
                    protection: PROT_PLAIN.into(),
                    public: B64.encode(&self.public),
                    salt: None,
                    nonce: None,
                    secret: B64.encode(&*self.secret),
                }
            }
        };
        let json = serde_json::to_vec_pretty(&stored).map_err(|_| KeystoreError::Crypto)?;
        write_private_file(path, &json)
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_TIME, ARGON_LANES, Some(32))
        .map_err(|_| KeystoreError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| KeystoreError::Crypto)?;
    Ok(key)
}

/// Write `data` to `path` atomically and with owner-only permissions.
///
/// The temporary file is created with the restrictive mode *before* any bytes
/// are written, so the secret is never briefly world readable.
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<(), KeystoreError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp: PathBuf = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("identity.json");
        (d, p)
    }

    #[test]
    fn generate_is_random() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_eq!(a.public_key().len(), 32);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn encrypted_roundtrip() {
        let (_d, p) = tmp();
        let mut id = Identity::generate().unwrap();
        let pk = id.public_key().to_vec();
        let sk = id.private_key().to_vec();
        id.save(&p, Some("correct horse battery staple")).unwrap();

        assert_eq!(Identity::state(&p), KeystoreState::Encrypted);
        // The private key must not appear in the file.
        let raw = fs::read(&p).unwrap();
        assert!(!raw.windows(32).any(|w| w == sk.as_slice()));

        let loaded = Identity::load(&p, Some("correct horse battery staple")).unwrap();
        assert_eq!(loaded.public_key(), &pk[..]);
        assert_eq!(loaded.private_key(), &sk[..]);
        assert_eq!(loaded.protection(), Protection::Passphrase);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let (_d, p) = tmp();
        let mut id = Identity::generate().unwrap();
        id.save(&p, Some("right")).unwrap();
        assert!(matches!(
            Identity::load(&p, Some("wrong")),
            Err(KeystoreError::WrongPassphrase)
        ));
        assert!(matches!(
            Identity::load(&p, None),
            Err(KeystoreError::NeedPassphrase)
        ));
    }

    #[test]
    fn tampering_with_public_key_is_detected() {
        let (_d, p) = tmp();
        let mut id = Identity::generate().unwrap();
        id.save(&p, Some("pass")).unwrap();
        let mut stored: StoredKey = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        stored.public = B64.encode([9u8; 32]);
        fs::write(&p, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(matches!(
            Identity::load(&p, Some("pass")),
            Err(KeystoreError::WrongPassphrase)
        ));
    }

    #[test]
    fn plaintext_roundtrip() {
        let (_d, p) = tmp();
        let mut id = Identity::generate().unwrap();
        let sk = id.private_key().to_vec();
        id.save(&p, None).unwrap();
        assert_eq!(Identity::state(&p), KeystoreState::Plaintext);
        let loaded = Identity::load(&p, None).unwrap();
        assert_eq!(loaded.private_key(), &sk[..]);
        assert_eq!(loaded.protection(), Protection::None);
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let id = Identity::generate().unwrap();
        let a = id.derive_subkey(b"trust");
        let b = id.derive_subkey(b"other");
        assert_ne!(*a, *b);
        assert_eq!(*a, *id.derive_subkey(b"trust"));
        assert_ne!(*a, *Identity::generate().unwrap().derive_subkey(b"trust"));
    }

    #[test]
    fn debug_never_leaks_secret() {
        let id = Identity::generate().unwrap();
        let s = format!("{id:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains(&hex::encode(id.private_key())));
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = tmp();
        Identity::generate().unwrap().save(&p, Some("x")).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keystore must not be readable by other users");
    }
}

//! Persistent, non-secret settings and the on-disk layout.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::proto::DEFAULT_TCP_PORT;

/// Everything the user can change that is not a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Name broadcast to the LAN. Visible to anyone on the network.
    pub device_name: String,
    pub tcp_port: u16,
    /// Announce our presence over UDP. Turning this off makes the device
    /// reachable only if the peer already knows its address.
    pub discovery_enabled: bool,
    /// Accept inbound connections at all.
    pub accept_incoming: bool,
    /// Where received files are written.
    pub download_dir: PathBuf,
    /// Refuse offers larger than this (bytes). 0 means "no extra limit".
    pub max_file_size: u64,
    /// Refuse connections from addresses outside RFC1918/link-local ranges.
    pub lan_only: bool,
    /// Allow pairing requests from unknown devices. When false, only already
    /// paired devices can connect at all.
    pub allow_new_pairings: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: default_device_name(),
            tcp_port: DEFAULT_TCP_PORT,
            discovery_enabled: true,
            accept_incoming: true,
            download_dir: default_download_dir(),
            max_file_size: 8 * 1024 * 1024 * 1024,
            lan_only: true,
            allow_new_pairings: true,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|r| serde_json::from_slice::<Config>(&r).ok())
            .map(|mut c| {
                c.device_name = crate::util::clamp_str(&c.device_name, 64);
                if c.device_name.trim().is_empty() {
                    c.device_name = default_device_name();
                }
                c
            })
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        std::fs::rename(tmp, path)
    }
}

/// Directory holding identity, trust store and settings.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn discover() -> Self {
        let root = directories::ProjectDirs::from("org", "SyncMob", "SyncMob")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".syncmob"));
        Self { root }
    }
    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.json")
    }
    pub fn trust(&self) -> PathBuf {
        self.root.join("trust.json")
    }
    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }
    /// Partially received files live here until they are verified.
    pub fn incoming(&self) -> PathBuf {
        self.root.join("incoming")
    }
}

fn default_device_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "SyncMob PC".to_string());
    crate::util::clamp_str(raw.trim(), 32)
}

fn default_download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|d| d.download_dir().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("SyncMob")
}

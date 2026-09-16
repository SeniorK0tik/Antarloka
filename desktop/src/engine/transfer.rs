//! Receiving a file safely.
//!
//! Every byte here comes from the network, so the rules are strict:
//!
//! * data is written to a quarantine file inside our own data directory, never
//!   straight into the user's Downloads folder;
//! * the file name is sanitised (see [`crate::util::sanitize_filename`]) and
//!   may not contain a path separator, so the final `join` cannot escape;
//! * chunks must arrive strictly in order and may not push the total past the
//!   advertised size;
//! * the SHA-256 must match what was offered, otherwise the file is deleted.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::proto::TransferId;
use crate::security::DeviceId;
use crate::util::{sanitize_filename, unique_path};

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("transfer was not accepted")]
    NotAccepted,
    #[error("chunk out of order (expected offset {expected}, got {got})")]
    BadOffset { expected: u64, got: u64 },
    #[error("peer sent more data than it offered")]
    TooLarge,
    #[error("incomplete: {received} of {size} bytes")]
    Incomplete { received: u64, size: u64 },
    #[error("content hash does not match the offer")]
    HashMismatch,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct IncomingTransfer {
    pub id: TransferId,
    pub from: DeviceId,
    /// The peer's static public key, so a chunk from another connection that
    /// guessed the id is still refused.
    pub from_key: Vec<u8>,
    /// Already sanitised; guaranteed free of path separators.
    pub name: String,
    pub size: u64,
    pub expected_sha: String,
    pub received: u64,
    pub accepted: bool,
    pub started: Instant,
    part_path: PathBuf,
    file: Option<BufWriter<File>>,
    hasher: Sha256,
}

impl IncomingTransfer {
    pub fn new(
        id: TransferId,
        from: DeviceId,
        from_key: Vec<u8>,
        raw_name: &str,
        size: u64,
        expected_sha: &str,
    ) -> Self {
        Self {
            id,
            from,
            from_key,
            name: sanitize_filename(raw_name),
            size,
            expected_sha: expected_sha.to_ascii_lowercase(),
            received: 0,
            accepted: false,
            started: Instant::now(),
            part_path: PathBuf::new(),
            file: None,
            hasher: Sha256::new(),
        }
    }

    /// Open the quarantine file. Called only after the user (or an explicit
    /// auto-accept rule) approved the transfer.
    pub fn accept(&mut self, incoming_dir: &Path) -> Result<(), TransferError> {
        std::fs::create_dir_all(incoming_dir)?;
        // Named by transfer id, not by the peer supplied name: nothing the peer
        // controls reaches the filesystem until the transfer is verified.
        self.part_path = incoming_dir.join(format!("{}.part", self.id));
        self.file = Some(BufWriter::with_capacity(
            256 * 1024,
            File::create(&self.part_path)?,
        ));
        self.accepted = true;
        Ok(())
    }

    pub fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<(), TransferError> {
        if !self.accepted {
            return Err(TransferError::NotAccepted);
        }
        if offset != self.received {
            return Err(TransferError::BadOffset {
                expected: self.received,
                got: offset,
            });
        }
        // Checked before writing so a hostile peer cannot fill the disk past
        // what it declared.
        let end = self
            .received
            .checked_add(data.len() as u64)
            .ok_or(TransferError::TooLarge)?;
        if end > self.size {
            return Err(TransferError::TooLarge);
        }
        let f = self.file.as_mut().ok_or(TransferError::NotAccepted)?;
        f.write_all(data)?;
        self.hasher.update(data);
        self.received = end;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.received == self.size
    }

    pub fn progress(&self) -> f32 {
        if self.size == 0 {
            1.0
        } else {
            self.received as f32 / self.size as f32
        }
    }

    /// Verify the hash and publish the file into `download_dir`.
    ///
    /// On any failure the quarantine file is removed, so a rejected transfer
    /// never leaves anything behind.
    pub fn finish(mut self, download_dir: &Path) -> Result<PathBuf, TransferError> {
        let result = self.finish_inner(download_dir);
        if result.is_err() {
            let _ = std::fs::remove_file(&self.part_path);
        }
        result
    }

    fn finish_inner(&mut self, download_dir: &Path) -> Result<PathBuf, TransferError> {
        if let Some(mut f) = self.file.take() {
            f.flush()?;
            f.get_ref().sync_all()?;
        }
        if self.received != self.size {
            return Err(TransferError::Incomplete {
                received: self.received,
                size: self.size,
            });
        }
        let actual = hex::encode(std::mem::take(&mut self.hasher).finalize());
        if actual != self.expected_sha {
            return Err(TransferError::HashMismatch);
        }

        std::fs::create_dir_all(download_dir)?;
        let dest = unique_path(download_dir, &self.name);
        // Defence in depth: after sanitising, the destination must still be a
        // direct child of the download directory.
        debug_assert_eq!(dest.parent(), Some(download_dir));
        if dest.parent() != Some(download_dir) {
            return Err(TransferError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination escaped the download directory",
            )));
        }

        match std::fs::rename(&self.part_path, &dest) {
            Ok(()) => Ok(dest),
            // Different volume: fall back to copy + delete.
            Err(_) => {
                std::fs::copy(&self.part_path, &dest)?;
                let _ = std::fs::remove_file(&self.part_path);
                Ok(dest)
            }
        }
    }

    /// Drop a transfer that was rejected or failed, removing partial data.
    pub fn abort(mut self) {
        self.file.take();
        if !self.part_path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.part_path);
        }
    }
}

/// Stream a file to get its size and SHA-256 without loading it into memory.
pub fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    fn setup(data: &[u8], name: &str) -> (tempfile::TempDir, IncomingTransfer) {
        let dir = tempfile::tempdir().unwrap();
        let t = IncomingTransfer::new(
            TransferId::random(),
            DeviceId::parse("0011223344556677").unwrap(),
            vec![1u8; 32],
            name,
            data.len() as u64,
            &sha_of(data),
        );
        (dir, t)
    }

    #[test]
    fn happy_path() {
        let data = b"hello syncmob".repeat(1000);
        let (dir, mut t) = setup(&data, "notes.txt");
        let inbox = dir.path().join("incoming");
        let downloads = dir.path().join("downloads");
        t.accept(&inbox).unwrap();
        for (i, c) in data.chunks(4096).enumerate() {
            t.write_chunk((i * 4096) as u64, c).unwrap();
        }
        assert!(t.is_complete());
        let path = t.finish(&downloads).unwrap();
        assert_eq!(path.file_name().unwrap(), "notes.txt");
        assert_eq!(std::fs::read(&path).unwrap(), data);
        // Quarantine directory is left clean.
        assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 0);
    }

    #[test]
    fn traversal_in_the_offered_name_is_neutralised() {
        let data = b"x";
        let (dir, mut t) = setup(data, "../../../../tmp/evil.sh");
        assert_eq!(t.name, "evil.sh");
        let downloads = dir.path().join("downloads");
        t.accept(&dir.path().join("incoming")).unwrap();
        t.write_chunk(0, data).unwrap();
        let path = t.finish(&downloads).unwrap();
        assert_eq!(path.parent().unwrap(), downloads);
    }

    #[test]
    fn chunks_must_be_in_order() {
        let data = b"abcdef";
        let (dir, mut t) = setup(data, "a.bin");
        t.accept(&dir.path().join("incoming")).unwrap();
        t.write_chunk(0, b"abc").unwrap();
        assert!(matches!(
            t.write_chunk(99, b"def"),
            Err(TransferError::BadOffset { .. })
        ));
    }

    #[test]
    fn cannot_exceed_the_offered_size() {
        let data = b"abc";
        let (dir, mut t) = setup(data, "a.bin");
        t.accept(&dir.path().join("incoming")).unwrap();
        assert!(matches!(
            t.write_chunk(0, b"abcdefghij"),
            Err(TransferError::TooLarge)
        ));
    }

    #[test]
    fn writing_before_acceptance_is_refused() {
        let (_dir, mut t) = setup(b"abc", "a.bin");
        assert!(matches!(
            t.write_chunk(0, b"abc"),
            Err(TransferError::NotAccepted)
        ));
    }

    #[test]
    fn hash_mismatch_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("incoming");
        let downloads = dir.path().join("downloads");
        let mut t = IncomingTransfer::new(
            TransferId::random(),
            DeviceId::parse("0011223344556677").unwrap(),
            vec![1u8; 32],
            "a.bin",
            3,
            &sha_of(b"GOOD"), // does not match what we will actually send
        );
        t.accept(&inbox).unwrap();
        t.write_chunk(0, b"BAD").unwrap();
        assert!(matches!(
            t.finish(&downloads),
            Err(TransferError::HashMismatch)
        ));
        assert!(!downloads.join("a.bin").exists());
        assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 0);
    }

    #[test]
    fn incomplete_transfer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"abcdef";
        let mut t = IncomingTransfer::new(
            TransferId::random(),
            DeviceId::parse("0011223344556677").unwrap(),
            vec![1u8; 32],
            "a.bin",
            data.len() as u64,
            &sha_of(data),
        );
        t.accept(&dir.path().join("incoming")).unwrap();
        t.write_chunk(0, b"abc").unwrap();
        assert!(matches!(
            t.finish(&dir.path().join("downloads")),
            Err(TransferError::Incomplete { .. })
        ));
    }

    #[test]
    fn existing_files_are_never_overwritten() {
        let data = b"new";
        let (dir, mut t) = setup(data, "a.txt");
        let downloads = dir.path().join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("a.txt"), b"original").unwrap();

        t.accept(&dir.path().join("incoming")).unwrap();
        t.write_chunk(0, data).unwrap();
        let path = t.finish(&downloads).unwrap();
        assert_eq!(path.file_name().unwrap(), "a (1).txt");
        assert_eq!(std::fs::read(downloads.join("a.txt")).unwrap(), b"original");
    }

    #[test]
    fn abort_removes_partial_data() {
        let (dir, mut t) = setup(b"abcdef", "a.bin");
        let inbox = dir.path().join("incoming");
        t.accept(&inbox).unwrap();
        t.write_chunk(0, b"abc").unwrap();
        t.abort();
        assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 0);
    }

    #[test]
    fn hash_file_matches() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.bin");
        let data = vec![3u8; 700_000];
        std::fs::write(&p, &data).unwrap();
        let (h, n) = hash_file(&p).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(h, sha_of(&data));
    }
}

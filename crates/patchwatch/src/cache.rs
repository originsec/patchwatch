use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Cache {
    base: PathBuf,
}

impl Cache {
    pub fn new(base: &Path) -> Self {
        Self {
            base: base.to_path_buf(),
        }
    }

    pub fn msu_dir(&self, kb_id: &str) -> PathBuf {
        self.base.join("cache/msu").join(kb_id)
    }
    pub fn csv_path(&self, kb_id: &str) -> PathBuf {
        self.base.join("cache/kb_csv").join(format!("{}.csv", kb_id))
    }
    /// Content-addressable binary cache: cache/binaries/<sha[:2]>/<sha>/<filename>
    pub fn binary_path(&self, sha256_hex: &str, filename: &str) -> PathBuf {
        self.base
            .join("cache/binaries")
            .join(&sha256_hex[..2])
            .join(sha256_hex)
            .join(filename)
    }

    pub fn ensure_dir(path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            Self::ensure_dir(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a/b/c.bin");
        Cache::write_atomic(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn binary_path_layout() {
        let cache = Cache::new(std::path::Path::new("/tmp/p"));
        let p = cache.binary_path("abcdef0123", "localspl.dll");
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(s.contains("cache/binaries/ab/abcdef0123/localspl.dll"));
    }
}

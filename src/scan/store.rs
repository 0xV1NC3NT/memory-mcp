//! Byte blobs for scan candidates: kept in memory up to a budget, spilled to a temporary
//! file beyond it. Each scan generation owns its spill file, deleted when dropped.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{MemError, Result};

pub struct Spill {
    path: PathBuf,
    writer: Mutex<File>,
    reader: File,
    written: AtomicU64,
}

impl Spill {
    fn create() -> Result<Self> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "memory-mcp-scan-{}-{}-{}.bin",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
        );
        let path = std::env::temp_dir().join(name);
        let writer = OpenOptions::new().create_new(true).write(true).read(true).open(&path)?;
        let reader = File::open(&path)?;
        Ok(Self { path, writer: Mutex::new(writer), reader, written: AtomicU64::new(0) })
    }

    fn append(&self, data: &[u8]) -> Result<u64> {
        let mut w = self.writer.lock().unwrap();
        let off = w.seek(SeekFrom::End(0))?;
        w.write_all(data)?;
        self.written.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(off)
    }

    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut done = 0;
        while done < len {
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_read(&self.reader, &mut buf[done..], off + done as u64)?;
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::read_at(&self.reader, &mut buf[done..], off + done as u64)?;
            if n == 0 {
                return Err(MemError::Os(format!("scan spill file {} is truncated", self.path.display())));
            }
            done += n;
        }
        Ok(buf)
    }
}

impl Drop for Spill {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub enum Blob {
    Mem(Vec<u8>),
    File { spill: Arc<Spill>, off: u64, len: usize },
}

impl Blob {
    pub fn get(&self) -> Result<std::borrow::Cow<'_, [u8]>> {
        match self {
            Blob::Mem(v) => Ok(std::borrow::Cow::Borrowed(v)),
            Blob::File { spill, off, len } => Ok(std::borrow::Cow::Owned(spill.read_at(*off, *len)?)),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Blob::Mem(v) => v.len(),
            Blob::File { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Allocates blobs for one scan generation within a memory budget.
pub struct Store {
    budget: u64,
    in_memory: AtomicU64,
    spill: Mutex<Option<Arc<Spill>>>,
}

impl Store {
    pub fn new(budget: u64) -> Self {
        Self { budget, in_memory: AtomicU64::new(0), spill: Mutex::new(None) }
    }

    pub fn put(&self, data: Vec<u8>) -> Result<Blob> {
        let len = data.len() as u64;
        let prev = self.in_memory.fetch_add(len, Ordering::Relaxed);
        if prev + len <= self.budget {
            return Ok(Blob::Mem(data));
        }
        self.in_memory.fetch_sub(len, Ordering::Relaxed);
        let spill = {
            let mut s = self.spill.lock().unwrap();
            if s.is_none() {
                *s = Some(Arc::new(Spill::create()?));
            }
            s.as_ref().unwrap().clone()
        };
        let off = spill.append(&data)?;
        Ok(Blob::File { spill, off, len: data.len() })
    }

    pub fn memory_bytes(&self) -> u64 {
        self.in_memory.load(Ordering::Relaxed)
    }

    pub fn disk_bytes(&self) -> u64 {
        self.spill.lock().unwrap().as_ref().map(|s| s.written.load(Ordering::Relaxed)).unwrap_or(0)
    }

    pub fn spill_path(&self) -> Option<PathBuf> {
        self.spill.lock().unwrap().as_ref().map(|s| s.path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spills_beyond_budget_and_cleans_up() {
        let store = Store::new(8);
        let a = store.put(vec![1; 8]).unwrap();
        let b = store.put(vec![2; 5]).unwrap();
        let c = store.put(vec![3; 3]).unwrap();
        assert!(matches!(a, Blob::Mem(_)));
        assert!(matches!(b, Blob::File { .. }));
        assert_eq!(b.get().unwrap().as_ref(), [2; 5]);
        assert_eq!(c.get().unwrap().as_ref(), [3; 3]);
        assert_eq!(store.memory_bytes(), 8);
        assert_eq!(store.disk_bytes(), 8);
        let path = store.spill_path().unwrap();
        assert!(path.exists());
        drop((a, b, c, store));
        assert!(!path.exists(), "spill file removed with its last blob");
    }
}

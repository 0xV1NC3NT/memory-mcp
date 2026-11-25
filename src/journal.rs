//! Journal of memory writes: kept in memory for undo and appended to a JSONL file for audit.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};

use crate::platform::ProtectionChange;
use crate::value::hex_bytes;

#[derive(Debug, Clone)]
pub struct WriteRecord {
    pub id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub process: String,
    pub address: u64,
    /// Address expression as given by the client.
    pub expression: String,
    /// Value type for `write_value`, None for raw `write_bytes`.
    pub value_type: Option<String>,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
    pub protection_changes: Vec<ProtectionChange>,
    pub undone: bool,
}

impl WriteRecord {
    pub fn to_json(&self, ptr_size: usize) -> Value {
        json!({
            "id": self.id,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process": self.process,
            "address": crate::format::addr(self.address, ptr_size),
            "expression": self.expression,
            "type": self.value_type,
            "size": self.new_bytes.len(),
            "old_bytes": hex_bytes(&self.old_bytes),
            "new_bytes": hex_bytes(&self.new_bytes),
            "protection_changes": self.protection_changes.iter().map(|c| json!({
                "base": crate::format::addr(c.base, ptr_size),
                "size": crate::format::size(c.size),
                "original": c.original,
            })).collect::<Vec<_>>(),
            "undone": self.undone,
        })
    }
}

/// Fields of a new record (id and timestamp are assigned by the journal).
pub struct NewWrite {
    pub pid: u32,
    pub process: String,
    pub address: u64,
    pub expression: String,
    pub value_type: Option<String>,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
    pub protection_changes: Vec<ProtectionChange>,
}

#[derive(Default)]
pub struct Journal {
    records: Vec<WriteRecord>,
    next_id: u64,
    file: Option<PathBuf>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Serialize)]
struct FileEvent<'a> {
    event: &'a str,
    #[serde(flatten)]
    record: Value,
}

impl Journal {
    pub fn new(file: Option<PathBuf>) -> Self {
        Self { records: Vec::new(), next_id: 1, file }
    }

    pub fn file(&self) -> Option<&PathBuf> {
        self.file.as_ref()
    }

    pub fn record(&mut self, w: NewWrite, ptr_size: usize) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let rec = WriteRecord {
            id,
            timestamp: now(),
            pid: w.pid,
            process: w.process,
            address: w.address,
            expression: w.expression,
            value_type: w.value_type,
            old_bytes: w.old_bytes,
            new_bytes: w.new_bytes,
            protection_changes: w.protection_changes,
            undone: false,
        };
        self.append("write", &rec, ptr_size);
        self.records.push(rec);
        id
    }

    pub fn get(&self, id: u64) -> Option<&WriteRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Latest write for `pid` that has not been undone.
    pub fn last_active(&self, pid: u32) -> Option<&WriteRecord> {
        self.records.iter().rev().find(|r| r.pid == pid && !r.undone)
    }

    pub fn mark_undone(&mut self, id: u64, ptr_size: usize) {
        if let Some(i) = self.records.iter().position(|r| r.id == id) {
            self.records[i].undone = true;
            let rec = self.records[i].clone();
            self.append("undo", &rec, ptr_size);
        }
    }

    pub fn records(&self) -> &[WriteRecord] {
        &self.records
    }

    fn append(&self, event: &str, rec: &WriteRecord, ptr_size: usize) {
        let Some(path) = &self.file else { return };
        let line = serde_json::to_string(&FileEvent { event, record: rec.to_json(ptr_size) }).unwrap_or_default();
        let res = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut f = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(f, "{line}")
        })();
        if let Err(e) = res {
            tracing::warn!("cannot append to write journal {}: {e}", path.display());
        }
    }
}

/// Default journal location: `%LOCALAPPDATA%\memory-mcp\writes.jsonl` (or `$XDG_STATE_HOME`/`~/.local/state`).
pub fn default_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_STATE_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")))?;
    Some(base.join("memory-mcp").join("writes.jsonl"))
}

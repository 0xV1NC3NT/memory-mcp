//! OS abstraction. Everything OS-specific lives below this module (plus executable-format
//! parsing behind `crate::binfmt`), so a Linux backend can be added without touching the rest
//! of the crate. A new backend implements:
//!
//! | Item                    | Windows (`windows.rs`)                       | Linux (to do: `linux.rs`)                          |
//! |-------------------------|----------------------------------------------|----------------------------------------------------|
//! | `list_processes`        | Toolhelp32 process snapshot                  | `/proc/<pid>/stat`, `/proc/<pid>/comm`             |
//! | `open_process`, `arch`  | `OpenProcess`, `IsWow64Process2`             | ELF class of `/proc/<pid>/exe`                     |
//! | `read`                  | `ReadProcessMemory`                          | `process_vm_readv` (fallback: `/proc/<pid>/mem`)   |
//! | `write`, `write_force`  | `WriteProcessMemory` + `VirtualProtectEx`    | `/proc/<pid>/mem` (ignores page protection; default `write_force` suffices) |
//! | `query`, `regions`      | `VirtualQueryEx`                             | parse `/proc/<pid>/maps` (rwxp, file path → kind)  |
//! | `modules`               | Toolhelp32 module snapshot                   | file-backed mappings with an ELF header, grouped by path |
//! | `is_alive`, `image_path`| `GetExitCodeProcess`, `QueryFullProcessImageNameW` | `/proc/<pid>` exists and not zombie, `readlink /proc/<pid>/exe` |
//! | `is_denied`             | system process names                         | pid ≤ 1 (and ptrace_scope / permissions surface as `AccessDenied`) |
//!
//! Plus `binfmt`: ELF `.dynsym` exports and section headers (now reported as unsupported).

use std::sync::Arc;

use serde::Serialize;

use crate::error::{MemError, Result};

#[cfg(windows)]
mod windows;

#[cfg(test)]
pub(crate) mod mock;

pub const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X64,
    Arm64,
    Unknown,
}

impl Arch {
    pub fn pointer_size(self) -> usize {
        match self {
            Arch::X86 => 4,
            _ => 8,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub threads: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u64,
    /// Architecture read from the module's PE header (None if unreadable).
    pub arch: Option<Arch>,
}

impl Module {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RegionState {
    Commit,
    Reserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RegionKind {
    Image,
    Mapped,
    Private,
    Unknown,
}

/// Platform-neutral page protection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protection {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub copy_on_write: bool,
    pub guard: bool,
    /// Raw OS value (PAGE_* on Windows).
    pub raw: u32,
}

impl Protection {
    /// Short form like `rwx`, `r-x`, `rw-`, with `c` for copy-on-write and `+g` for guard pages.
    pub fn short(&self) -> String {
        let mut s = String::with_capacity(5);
        s.push(if self.read { 'r' } else { '-' });
        s.push(if self.write { if self.copy_on_write { 'c' } else { 'w' } } else { '-' });
        s.push(if self.exec { 'x' } else { '-' });
        if self.guard {
            s.push_str("+g");
        }
        s
    }

    /// Whether every flag in `filter` (chars r/w/x) is present.
    pub fn matches(&self, filter: &str) -> bool {
        filter.chars().all(|c| match c.to_ascii_lowercase() {
            'r' => self.read,
            'w' => self.write,
            'x' => self.exec,
            _ => true,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub allocation_base: u64,
    pub state: RegionState,
    pub protect: Protection,
    pub kind: RegionKind,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.base + self.size
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
    pub fn readable(&self) -> bool {
        self.state == RegionState::Commit && self.protect.read && !self.protect.guard
    }
}

/// Protection that had to be lifted temporarily for a write.
#[derive(Debug, Clone, Serialize)]
pub struct ProtectionChange {
    pub base: u64,
    pub size: u64,
    /// Original protection (restored after the write), e.g. `r-x`.
    pub original: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WriteOutcome {
    pub protection_changes: Vec<ProtectionChange>,
}

/// Access to one opened process.
pub trait ProcessMemory: Send + Sync {
    fn pid(&self) -> u32;
    fn name(&self) -> &str;
    fn image_path(&self) -> Option<String>;
    fn arch(&self) -> Arch;
    fn is_alive(&self) -> bool;
    /// Whether the handle was opened with write access.
    fn can_write(&self) -> bool;

    /// All-or-nothing read of `buf.len()` bytes.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()>;
    /// All-or-nothing write.
    fn write(&self, addr: u64, data: &[u8]) -> Result<()>;

    /// Writes regardless of page protection: non-writable pages are made writable for the
    /// duration of the write and restored afterwards. Backends whose write path ignores
    /// protection (e.g. Linux /proc/pid/mem) can keep the default.
    fn write_force(&self, addr: u64, data: &[u8]) -> Result<WriteOutcome> {
        self.write(addr, data)?;
        Ok(WriteOutcome::default())
    }

    /// Region containing `addr` (None if the address is free / beyond the address space).
    fn query(&self, addr: u64) -> Option<Region>;
    /// All non-free regions in ascending order.
    fn regions(&self) -> Result<Vec<Region>>;
    fn modules(&self) -> Result<Vec<Module>>;

    fn pointer_size(&self) -> usize {
        self.arch().pointer_size()
    }

    /// Highest valid user-mode address for this process' bitness (inclusive).
    fn max_address(&self) -> u64 {
        if self.pointer_size() == 4 { 0xFFFF_FFFF } else { 0x7FFF_FFFF_FFFF }
    }

    /// Reads as much as possible; unreadable bytes are `None`.
    fn read_partial(&self, addr: u64, len: usize) -> Vec<Option<u8>> {
        let mut buf = vec![0u8; len];
        if self.read(addr, &mut buf).is_ok() {
            return buf.into_iter().map(Some).collect();
        }
        let mut out = Vec::with_capacity(len);
        let end = addr.saturating_add(len as u64);
        let mut cur = addr;
        while cur < end {
            let page_end = ((cur / PAGE_SIZE) + 1) * PAGE_SIZE;
            let chunk_end = page_end.min(end);
            let n = (chunk_end - cur) as usize;
            let mut chunk = vec![0u8; n];
            if self.read(cur, &mut chunk).is_ok() {
                out.extend(chunk.into_iter().map(Some));
            } else {
                out.extend(std::iter::repeat_n(None, n));
            }
            cur = chunk_end;
        }
        out
    }

    /// Human-readable reason why `addr` cannot be read.
    fn explain_unreadable(&self, addr: u64) -> String {
        if addr > self.max_address() {
            return format!(
                "address is outside the {}-bit user address space",
                self.pointer_size() * 8
            );
        }
        match self.query(addr) {
            None => "address is not mapped".into(),
            Some(r) if r.state == RegionState::Reserve => "memory is reserved but not committed".into(),
            Some(r) if r.protect.guard => "guard page".into(),
            Some(r) if !r.protect.read => format!("page is not readable (protection {})", r.protect.short()),
            Some(_) => "read failed (range may cross into an unreadable page)".into(),
        }
    }

    fn read_u64_ptr(&self, addr: u64) -> Result<u64> {
        if self.pointer_size() == 4 {
            let mut b = [0u8; 4];
            self.read(addr, &mut b)?;
            Ok(u32::from_le_bytes(b) as u64)
        } else {
            let mut b = [0u8; 8];
            self.read(addr, &mut b)?;
            Ok(u64::from_le_bytes(b))
        }
    }
}

pub type Process = Arc<dyn ProcessMemory>;

pub fn list_processes() -> Result<Vec<ProcessEntry>> {
    #[cfg(windows)]
    {
        windows::list_processes()
    }
    #[cfg(not(windows))]
    {
        Err(MemError::Unsupported("process enumeration"))
    }
}

pub fn open_process(pid: u32) -> Result<Process> {
    let _ = pid;
    #[cfg(windows)]
    {
        Ok(Arc::new(windows::WinProcess::open(pid)?))
    }
    #[cfg(not(windows))]
    {
        Err(MemError::Unsupported("opening processes"))
    }
}

/// Processes the server refuses to attach to (critical system processes of the host OS).
pub fn is_denied(pid: u32, name: &str) -> bool {
    #[cfg(windows)]
    {
        windows::is_denied(pid, name)
    }
    #[cfg(not(windows))]
    {
        // Linux: the idle task and init.
        let _ = name;
        pid <= 1
    }
}


#[allow(dead_code)]
fn _assert_object_safe(_: &dyn ProcessMemory) {}

impl From<std::io::Error> for MemError {
    fn from(e: std::io::Error) -> Self {
        MemError::Os(e.to_string())
    }
}

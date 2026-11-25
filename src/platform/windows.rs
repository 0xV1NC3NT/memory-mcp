//! Windows backend: ReadProcessMemory / WriteProcessMemory / VirtualQueryEx / Toolhelp32.

use std::ffi::c_void;
use std::mem::size_of;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, ERROR_INVALID_PARAMETER, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtectEx, VirtualQueryEx,
};
use windows::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, IsWow64Process2, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use super::{
    Arch, Module, ProcessEntry, ProcessMemory, Protection, ProtectionChange, Region, RegionKind,
    RegionState, WriteOutcome,
};
use crate::error::{MemError, Result};

const STILL_ACTIVE: u32 = 259;

/// NUL-terminated UTF-16 buffer from WinAPI structures → String.
fn from_wide(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}


/// Critical Windows processes we refuse to attach to (lower-case).
const DENYLIST: &[&str] = &[
    "system",
    "secure system",
    "registry",
    "memory compression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
];

pub fn is_denied(pid: u32, name: &str) -> bool {
    pid == 0 || pid == 4 || DENYLIST.contains(&name.to_ascii_lowercase().as_str())
}

/// Owned process / snapshot handle.
struct OwnedHandle(HANDLE);

// SAFETY: a process handle is a kernel object reference usable from any thread.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn os_err(e: &windows::core::Error) -> String {
    format!("{} (0x{:08X})", e.message().trim(), e.code().0 as u32)
}

pub fn list_processes() -> Result<Vec<ProcessEntry>> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| MemError::Os(os_err(&e)))?;
    let snap = OwnedHandle(snap);
    let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    let mut out = Vec::new();
    let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) }.is_ok();
    while ok {
        out.push(ProcessEntry {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            name: from_wide(&entry.szExeFile),
            threads: entry.cntThreads,
        });
        ok = unsafe { Process32NextW(snap.0, &mut entry) }.is_ok();
    }
    Ok(out)
}

fn machine_to_arch(m: IMAGE_FILE_MACHINE) -> Arch {
    match m {
        IMAGE_FILE_MACHINE_I386 => Arch::X86,
        IMAGE_FILE_MACHINE_AMD64 => Arch::X64,
        IMAGE_FILE_MACHINE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    }
}

pub struct WinProcess {
    handle: OwnedHandle,
    pid: u32,
    name: String,
    arch: Arch,
    can_write: bool,
}

impl WinProcess {
    pub fn open(pid: u32) -> Result<Self> {
        let name = list_processes()?
            .into_iter()
            .find(|p| p.pid == pid)
            .map(|p| p.name)
            .ok_or_else(|| MemError::ProcessNotFound(format!("pid {pid}")))?;
        if super::is_denied(pid, &name) {
            return Err(MemError::DeniedProcess(name));
        }

        let read_rights: PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let full_rights = read_rights | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

        let (handle, can_write) = match unsafe { OpenProcess(full_rights, false, pid) } {
            Ok(h) => (h, true),
            Err(_) => match unsafe { OpenProcess(read_rights, false, pid) } {
                Ok(h) => (h, false),
                Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
                    return Err(MemError::AccessDenied {
                        pid,
                        hint: "the process is protected or runs elevated; run the MCP server as administrator".into(),
                    });
                }
                Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => {
                    return Err(MemError::ProcessNotFound(format!("pid {pid}")));
                }
                Err(e) => return Err(MemError::Os(os_err(&e))),
            },
        };
        let handle = OwnedHandle(handle);

        let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        unsafe { IsWow64Process2(handle.0, &mut process_machine, Some(&mut native_machine)) }
            .map_err(|e| MemError::Os(os_err(&e)))?;
        // process_machine is UNKNOWN when the process is not running under WOW64.
        let arch = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
            machine_to_arch(native_machine)
        } else {
            machine_to_arch(process_machine)
        };

        Ok(Self { handle, pid, name, arch, can_write })
    }

    fn h(&self) -> HANDLE {
        self.handle.0
    }

    fn check_range(&self, addr: u64, len: usize) -> std::result::Result<(), String> {
        let end = addr.checked_add(len as u64).ok_or("address range overflows")?;
        if len > 0 && end - 1 > self.max_address() {
            return Err(format!(
                "address is outside the {}-bit user address space",
                self.pointer_size() * 8
            ));
        }
        Ok(())
    }

    fn pe_arch(&self, base: u64) -> Option<Arch> {
        let mut lfanew = [0u8; 4];
        self.read(base + 0x3C, &mut lfanew).ok()?;
        let lfanew = u32::from_le_bytes(lfanew) as u64;
        let mut hdr = [0u8; 6];
        self.read(base + lfanew, &mut hdr).ok()?;
        if &hdr[..4] != b"PE\0\0" {
            return None;
        }
        let machine = u16::from_le_bytes([hdr[4], hdr[5]]);
        Some(machine_to_arch(IMAGE_FILE_MACHINE(machine)))
    }
}

fn decode_protect(raw: u32) -> Protection {
    let base = raw & 0xFF;
    let (read, write, exec, cow) = match base {
        0x02 => (true, false, false, false), // READONLY
        0x04 => (true, true, false, false),  // READWRITE
        0x08 => (true, true, false, true),   // WRITECOPY
        0x10 => (false, false, true, false), // EXECUTE
        0x20 => (true, false, true, false),  // EXECUTE_READ
        0x40 => (true, true, true, false),   // EXECUTE_READWRITE
        0x80 => (true, true, true, true),    // EXECUTE_WRITECOPY
        _ => (false, false, false, false),   // NOACCESS / 0
    };
    Protection { read, write, exec, copy_on_write: cow, guard: raw & 0x100 != 0, raw }
}

fn mbi_to_region(mbi: &MEMORY_BASIC_INFORMATION) -> Option<Region> {
    if mbi.State == MEM_FREE {
        return None;
    }
    let state = if mbi.State == MEM_COMMIT { RegionState::Commit } else { RegionState::Reserve };
    let kind = match mbi.Type {
        t if t == MEM_IMAGE => RegionKind::Image,
        t if t == MEM_MAPPED => RegionKind::Mapped,
        t if t == MEM_PRIVATE => RegionKind::Private,
        _ => RegionKind::Unknown,
    };
    Some(Region {
        base: mbi.BaseAddress as u64,
        size: mbi.RegionSize as u64,
        allocation_base: mbi.AllocationBase as u64,
        state,
        protect: decode_protect(mbi.Protect.0),
        kind,
    })
}

impl ProcessMemory for WinProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn image_path(&self) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(self.h(), PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
        }
        .ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn arch(&self) -> Arch {
        self.arch
    }

    fn is_alive(&self) -> bool {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(self.h(), &mut code) }.is_ok() && code == STILL_ACTIVE
    }

    fn can_write(&self) -> bool {
        self.can_write
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if let Err(reason) = self.check_range(addr, buf.len()) {
            return Err(MemError::Read { addr, size: buf.len(), reason });
        }
        let mut n = 0usize;
        let r = unsafe {
            ReadProcessMemory(
                self.h(),
                addr as usize as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                Some(&mut n),
            )
        };
        match r {
            Ok(()) if n == buf.len() => Ok(()),
            _ => Err(MemError::Read { addr, size: buf.len(), reason: self.explain_unreadable(addr) }),
        }
    }

    fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.can_write {
            return Err(MemError::Write {
                addr,
                size: data.len(),
                reason: "process was opened without write access (run the server as administrator)".into(),
            });
        }
        if let Err(reason) = self.check_range(addr, data.len()) {
            return Err(MemError::Write { addr, size: data.len(), reason });
        }
        let mut n = 0usize;
        let r = unsafe {
            WriteProcessMemory(
                self.h(),
                addr as usize as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut n),
            )
        };
        match r {
            Ok(()) if n == data.len() => Ok(()),
            Ok(()) => Err(MemError::Write { addr, size: data.len(), reason: format!("only {n} bytes written") }),
            Err(e) => Err(MemError::Write { addr, size: data.len(), reason: os_err(&e) }),
        }
    }

    fn write_force(&self, addr: u64, data: &[u8]) -> Result<WriteOutcome> {
        let size = data.len();
        if size == 0 {
            return Ok(WriteOutcome::default());
        }
        if !self.can_write {
            return self.write(addr, data).map(|_| WriteOutcome::default());
        }
        if let Err(reason) = self.check_range(addr, size) {
            return Err(MemError::Write { addr, size, reason });
        }
        let end = addr + size as u64;

        // Collect the regions covering the range and validate them up front.
        let mut segments: Vec<(u64, u64, Protection)> = Vec::new();
        let mut cur = addr;
        while cur < end {
            let r = self.query(cur).ok_or_else(|| MemError::Write { addr, size, reason: format!("{cur:#x} is not mapped") })?;
            if r.state != RegionState::Commit {
                return Err(MemError::Write { addr, size, reason: format!("{cur:#x} is reserved but not committed") });
            }
            if r.protect.guard {
                return Err(MemError::Write { addr, size, reason: format!("{cur:#x} is a guard page") });
            }
            let seg_end = r.end().min(end);
            segments.push((cur, seg_end - cur, r.protect));
            cur = seg_end;
        }

        // Lift protection where needed. Copy-on-write pages are writable through WriteProcessMemory.
        let mut changed: Vec<(u64, u64, Protection, PAGE_PROTECTION_FLAGS)> = Vec::new();
        let mut result: Result<()> = Ok(());
        for &(base, len, prot) in &segments {
            if prot.write {
                continue;
            }
            let new = if prot.exec { PAGE_EXECUTE_READWRITE } else { PAGE_READWRITE };
            let mut old = PAGE_PROTECTION_FLAGS(0);
            match unsafe { VirtualProtectEx(self.h(), base as usize as *const c_void, len as usize, new, &mut old) } {
                Ok(()) => changed.push((base, len, prot, old)),
                Err(e) => {
                    result = Err(MemError::Write {
                        addr,
                        size,
                        reason: format!("cannot make {base:#x} ({}) writable: {}", prot.short(), os_err(&e)),
                    });
                    break;
                }
            }
        }
        if result.is_ok() {
            result = self.write(addr, data);
        }
        // Always restore the original protection, even if the write failed.
        let mut restore_err = None;
        for &(base, len, _, old) in changed.iter().rev() {
            let mut tmp = PAGE_PROTECTION_FLAGS(0);
            if let Err(e) = unsafe { VirtualProtectEx(self.h(), base as usize as *const c_void, len as usize, old, &mut tmp) } {
                restore_err = Some(format!("failed to restore protection at {base:#x}: {}", os_err(&e)));
            }
        }
        result?;
        if segments.iter().any(|s| s.2.exec) {
            unsafe {
                let _ = FlushInstructionCache(self.h(), Some(addr as usize as *const c_void), size);
            }
        }
        if let Some(reason) = restore_err {
            return Err(MemError::Write { addr, size, reason: format!("data was written but {reason}") });
        }
        Ok(WriteOutcome {
            protection_changes: changed
                .into_iter()
                .map(|(base, size, prot, _)| ProtectionChange { base, size, original: prot.short() })
                .collect(),
        })
    }

    fn query(&self, addr: u64) -> Option<Region> {
        if addr > self.max_address() {
            return None;
        }
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let n = unsafe {
            VirtualQueryEx(
                self.h(),
                Some(addr as usize as *const c_void),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 { None } else { mbi_to_region(&mbi) }
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let mut out = Vec::new();
        let mut addr: u64 = 0;
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let n = unsafe {
                VirtualQueryEx(
                    self.h(),
                    Some(addr as usize as *const c_void),
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                break;
            }
            let base = mbi.BaseAddress as u64;
            let size = mbi.RegionSize as u64;
            if let Some(r) = mbi_to_region(&mbi) {
                out.push(r);
            }
            match base.checked_add(size) {
                Some(next) if next > addr && next <= self.max_address() + 1 => addr = next,
                _ => break,
            }
        }
        if out.is_empty() && !self.is_alive() {
            return Err(MemError::ProcessExited(self.pid));
        }
        Ok(out)
    }

    fn modules(&self) -> Result<Vec<Module>> {
        // Toolhelp may fail with ERROR_BAD_LENGTH while the loader is busy; retry a few times.
        let mut last_err = None;
        for _ in 0..5 {
            match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) } {
                Ok(snap) => {
                    let snap = OwnedHandle(snap);
                    let mut e = MODULEENTRY32W { dwSize: size_of::<MODULEENTRY32W>() as u32, ..Default::default() };
                    let mut out = Vec::new();
                    let mut ok = unsafe { Module32FirstW(snap.0, &mut e) }.is_ok();
                    while ok {
                        let base = e.modBaseAddr as u64;
                        out.push(Module {
                            name: from_wide(&e.szModule),
                            path: from_wide(&e.szExePath),
                            base,
                            size: e.modBaseSize as u64,
                            arch: self.pe_arch(base),
                        });
                        ok = unsafe { Module32NextW(snap.0, &mut e) }.is_ok();
                    }
                    // For WOW64 targets Toolhelp reports the main image twice and also lists the
                    // 64-bit WOW64 layer above 4 GiB, which 32-bit pointers can never reach.
                    let max = self.max_address();
                    out.retain(|m| m.base <= max);
                    out.sort_by_key(|m| m.base);
                    out.dedup_by_key(|m| m.base);
                    return Ok(out);
                }
                Err(e) if e.code() == ERROR_BAD_LENGTH.to_hresult() => {
                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => {
                    if !self.is_alive() {
                        return Err(MemError::ProcessExited(self.pid));
                    }
                    return Err(MemError::Os(os_err(&e)));
                }
            }
        }
        Err(MemError::Os(last_err.map(|e| os_err(&e)).unwrap_or_default()))
    }
}

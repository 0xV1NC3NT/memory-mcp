//! Which memory a scan covers: a module, one of its PE sections, an address range, the whole
//! process — always intersected with readable committed regions and an optional protection filter.

use crate::address::lookup_module;
use crate::error::{MemError, Result};
use crate::format;
use crate::binfmt;
use crate::platform::ProcessMemory;

#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub module: Option<String>,
    /// PE section name such as `.text` or `.rdata` (requires `module`).
    pub section: Option<String>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    /// Required protection flags (r/w/x), e.g. `x` for code only.
    pub protection: Option<String>,
    /// Skip memory-mapped files/sections (MEM_MAPPED), like Cheat Engine's default.
    pub skip_mapped: bool,
}

/// Returns merged `[start, end)` ranges to scan and a human-readable description.
pub fn resolve_ranges(p: &dyn ProcessMemory, scope: &Scope) -> Result<(Vec<(u64, u64)>, String)> {
    let ps = p.pointer_size();
    let (mut lo, mut hi, mut desc) = (0u64, p.max_address() + 1, String::from("whole process"));
    if let Some(name) = scope.module.as_deref().filter(|m| !m.is_empty()) {
        let modules = p.modules()?;
        let m = lookup_module(&modules, name)?
            .ok_or_else(|| MemError::InvalidArg(format!("module '{name}' is not loaded")))?
            .clone();
        lo = m.base;
        hi = m.base + m.size;
        desc = m.name.clone();
        if let Some(sec) = scope.section.as_deref().filter(|s| !s.is_empty()) {
            let secs = binfmt::sections(p, &m)?;
            let s = secs.iter().find(|s| s.name.eq_ignore_ascii_case(sec)).ok_or_else(|| {
                MemError::InvalidArg(format!(
                    "section '{sec}' not found in {} (available: {})",
                    m.name,
                    secs.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
                ))
            })?;
            lo = m.base + s.rva as u64;
            hi = lo + s.virtual_size as u64;
            desc = format!("{} {}", m.name, s.name);
        }
    } else if scope.section.as_deref().is_some_and(|s| !s.is_empty()) {
        return Err(MemError::InvalidArg("`section` requires `module`".into()));
    }
    if let Some(s) = scope.start {
        lo = lo.max(s);
    }
    if let Some(e) = scope.end {
        hi = hi.min(e);
    }
    if scope.start.is_some() || scope.end.is_some() {
        desc = format!("{desc} ∩ [{}, {})", format::addr(lo, ps), format::addr(hi, ps));
    }
    if lo >= hi {
        return Err(MemError::InvalidArg(format!("empty scan range ({desc})")));
    }
    let filter = scope.protection.as_deref().unwrap_or("");
    if !filter.is_empty() {
        desc = format!("{desc}, protection {filter}");
    }
    if scope.skip_mapped {
        desc = format!("{desc}, no mapped files");
    }

    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for r in p.regions()? {
        if r.end() <= lo || r.base >= hi || !r.readable() || !r.protect.matches(filter) {
            continue;
        }
        if scope.skip_mapped && r.kind == crate::platform::RegionKind::Mapped {
            continue;
        }
        let (s, e) = (r.base.max(lo), r.end().min(hi));
        match ranges.last_mut() {
            Some(last) if last.1 == s => last.1 = e,
            _ => ranges.push((s, e)),
        }
    }
    Ok((ranges, desc))
}

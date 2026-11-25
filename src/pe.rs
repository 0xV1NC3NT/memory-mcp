//! Minimal PE parsing performed directly on a module image mapped in the target process
//! (works for both PE32 and PE32+).

use crate::error::{MemError, Result};
use crate::platform::{Module, ProcessMemory};

const MAX_FORWARD_DEPTH: usize = 8;
const MAX_EXPORT_DIR: u32 = 16 * 1024 * 1024;

fn read_u16(p: &dyn ProcessMemory, a: u64) -> Result<u16> {
    let mut b = [0u8; 2];
    p.read(a, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(p: &dyn ProcessMemory, a: u64) -> Result<u32> {
    let mut b = [0u8; 4];
    p.read(a, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

#[derive(Debug, Clone, Copy)]
pub struct DataDir {
    pub rva: u32,
    pub size: u32,
}

/// Locates data directory `index` (0 = exports) of the image at `base`.
pub fn data_directory(p: &dyn ProcessMemory, base: u64, index: u32) -> Result<DataDir> {
    if read_u16(p, base)? != 0x5A4D {
        return Err(MemError::Os(format!("no MZ header at {base:#x}")));
    }
    let nt = base + read_u32(p, base + 0x3C)? as u64;
    if read_u32(p, nt)? != 0x0000_4550 {
        return Err(MemError::Os(format!("no PE signature at {nt:#x}")));
    }
    let opt = nt + 24;
    let (dirs, count_off) = match read_u16(p, opt)? {
        0x10B => (opt + 96, 92),  // PE32
        0x20B => (opt + 112, 108), // PE32+
        m => return Err(MemError::Os(format!("unknown optional header magic {m:#x}"))),
    };
    let count = read_u32(p, opt + count_off)?;
    if index >= count {
        return Ok(DataDir { rva: 0, size: 0 });
    }
    let d = dirs + index as u64 * 8;
    Ok(DataDir { rva: read_u32(p, d)?, size: read_u32(p, d + 4)? })
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

/// Section headers of the image at `base`.
pub fn sections(p: &dyn ProcessMemory, base: u64) -> Result<Vec<Section>> {
    if read_u16(p, base)? != 0x5A4D {
        return Err(MemError::Os(format!("no MZ header at {base:#x}")));
    }
    let nt = base + read_u32(p, base + 0x3C)? as u64;
    if read_u32(p, nt)? != 0x0000_4550 {
        return Err(MemError::Os(format!("no PE signature at {nt:#x}")));
    }
    let count = read_u16(p, nt + 6)? as u64;
    let opt_size = read_u16(p, nt + 20)? as u64;
    let first = nt + 24 + opt_size;
    let mut raw = vec![0u8; (count * 40) as usize];
    p.read(first, &mut raw)?;
    Ok(raw
        .as_chunks::<40>()
        .0
        .iter()
        .map(|h| Section {
            name: String::from_utf8_lossy(&h[..8]).trim_end_matches('\0').to_string(),
            virtual_size: le_u32(h, 8),
            rva: le_u32(h, 12),
            characteristics: le_u32(h, 36),
        })
        .collect())
}

/// x64 exception-directory entry (RVAs relative to the image base).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Entries of the exception directory (`.pdata`), sorted by `begin`. Empty if there is none.
pub fn runtime_functions(p: &dyn ProcessMemory, base: u64) -> Result<Vec<RuntimeFunction>> {
    const MAX_ENTRIES: u32 = 4 << 20;
    let dir = data_directory(p, base, 3)?;
    if dir.rva == 0 || dir.size < 12 {
        return Ok(Vec::new());
    }
    let n = (dir.size / 12).min(MAX_ENTRIES) as usize;
    let raw: Vec<u8> = p.read_partial(base + dir.rva as u64, n * 12).into_iter().map(|b| b.unwrap_or(0)).collect();
    let mut out: Vec<RuntimeFunction> = raw
        .as_chunks::<12>()
        .0
        .iter()
        .map(|c| RuntimeFunction { begin: le_u32(c, 0), end: le_u32(c, 4), unwind: le_u32(c, 8) })
        .filter(|f| f.begin != 0 && f.end > f.begin)
        .collect();
    out.sort_by_key(|f| f.begin);
    Ok(out)
}

/// The parent entry of a chained unwind record (function fragment), if any.
pub fn chained_parent(p: &dyn ProcessMemory, base: u64, f: &RuntimeFunction) -> Option<RuntimeFunction> {
    let mut hdr = [0u8; 4];
    p.read(base + f.unwind as u64, &mut hdr).ok()?;
    if (hdr[0] >> 3) & UNW_FLAG_CHAININFO == 0 {
        return None;
    }
    let codes = hdr[2] as u64;
    let at = base + f.unwind as u64 + 4 + ((codes + 1) & !1) * 2;
    let mut rf = [0u8; 12];
    p.read(at, &mut rf).ok()?;
    let parent = RuntimeFunction { begin: le_u32(&rf, 0), end: le_u32(&rf, 4), unwind: le_u32(&rf, 8) };
    (parent.begin != 0 && parent.end > parent.begin).then_some(parent)
}

/// All named exports of a module that point into code/data (forwarders skipped), sorted by address.
pub fn exports(p: &dyn ProcessMemory, m: &Module) -> Result<Vec<(u64, String)>> {
    const MAX_ENTRIES: u32 = 1 << 20;
    let base = m.base;
    let dir = data_directory(p, base, 0)?;
    if dir.rva == 0 || dir.size < 40 || dir.size > MAX_EXPORT_DIR {
        return Ok(Vec::new());
    }
    let blob: Vec<u8> =
        p.read_partial(base + dir.rva as u64, dir.size as usize).into_iter().map(|b| b.unwrap_or(0)).collect();
    let in_dir = |rva: u32| rva >= dir.rva && rva < dir.rva + dir.size;
    let n_funcs = le_u32(&blob, 20).min(MAX_ENTRIES) as usize;
    let n_names = le_u32(&blob, 24).min(MAX_ENTRIES) as usize;
    let (a_funcs, a_names, a_ords) = (le_u32(&blob, 28), le_u32(&blob, 32), le_u32(&blob, 36));
    let read_vec = |rva: u32, len: usize| -> Vec<u8> {
        p.read_partial(base + rva as u64, len).into_iter().map(|b| b.unwrap_or(0)).collect()
    };
    let funcs = read_vec(a_funcs, n_funcs * 4);
    let names = read_vec(a_names, n_names * 4);
    let ords = read_vec(a_ords, n_names * 2);
    let cstr = |rva: u32| -> String {
        let bytes: Vec<u8> = if in_dir(rva) {
            blob[(rva - dir.rva) as usize..].iter().copied().take_while(|&b| b != 0).take(512).collect()
        } else {
            p.read_partial(base + rva as u64, 256).into_iter().map_while(|b| b.filter(|&b| b != 0)).collect()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let mut out = Vec::with_capacity(n_names);
    for i in 0..n_names {
        let idx = u16::from_le_bytes([ords[i * 2], ords[i * 2 + 1]]) as usize;
        if idx >= n_funcs {
            continue;
        }
        let rva = le_u32(&funcs, idx * 4);
        if rva == 0 || in_dir(rva) {
            continue;
        }
        let name = cstr(le_u32(&names, i * 4));
        if !name.is_empty() {
            out.push((base + rva as u64, name));
        }
    }
    out.sort();
    Ok(out)
}

/// Result of resolving an export, including any forwarder hops taken.
#[derive(Debug, Clone)]
pub struct ExportHit {
    pub address: u64,
    pub module: String,
    /// Forwarder strings followed, e.g. `["NTDLL.RtlAllocateHeap"]`.
    pub forwards: Vec<String>,
}

fn find_module<'m>(modules: &'m [Module], name: &str) -> Option<&'m Module> {
    let lower = name.to_ascii_lowercase();
    modules.iter().find(|m| {
        let mn = m.name.to_ascii_lowercase();
        mn == lower || mn.strip_suffix(".dll") == Some(lower.as_str())
    })
}

/// Resolves `symbol` (`Name` or `#ordinal`) exported by `module`, following forwarders.
pub fn resolve_export(p: &dyn ProcessMemory, modules: &[Module], module: &Module, symbol: &str) -> Result<ExportHit> {
    let mut hit = ExportHit { address: 0, module: module.name.clone(), forwards: Vec::new() };
    let mut cur = module.clone();
    let mut sym = symbol.to_string();
    for _ in 0..=MAX_FORWARD_DEPTH {
        match export_rva(p, &cur, &sym)? {
            Target::Address(a) => {
                hit.address = a;
                hit.module = cur.name.clone();
                return Ok(hit);
            }
            Target::Forward(fwd) => {
                hit.forwards.push(fwd.clone());
                let (dll, name) = fwd
                    .rsplit_once('.')
                    .ok_or_else(|| MemError::Os(format!("malformed forwarder '{fwd}'")))?;
                cur = find_module(modules, dll)
                    .ok_or_else(|| {
                        MemError::InvalidArg(format!(
                            "{}!{symbol} is forwarded to '{fwd}', but module '{dll}' is not loaded{}",
                            module.name,
                            if dll.to_ascii_lowercase().starts_with("api-ms-") || dll.to_ascii_lowercase().starts_with("ext-ms-") {
                                " (API-set forwarders are not resolved; use the implementing DLL, e.g. kernelbase.dll)"
                            } else {
                                ""
                            }
                        ))
                    })?
                    .clone();
                sym = name.to_string();
            }
        }
    }
    Err(MemError::Os(format!("forwarder chain for {}!{symbol} is too long", module.name)))
}

enum Target {
    Address(u64),
    Forward(String),
}

fn export_rva(p: &dyn ProcessMemory, m: &Module, symbol: &str) -> Result<Target> {
    let base = m.base;
    let dir = data_directory(p, base, 0)?;
    if dir.rva == 0 || dir.size < 40 {
        return Err(MemError::InvalidArg(format!("module {} has no export table", m.name)));
    }
    if dir.size > MAX_EXPORT_DIR {
        return Err(MemError::Os(format!("export directory of {} is implausibly large", m.name)));
    }
    // The export directory range normally contains the name strings, so read it in one go.
    let blob = p
        .read_partial(base + dir.rva as u64, dir.size as usize)
        .into_iter()
        .map(|b| b.unwrap_or(0))
        .collect::<Vec<u8>>();
    let in_dir = |rva: u32| rva >= dir.rva && rva < dir.rva + dir.size;
    let cstr = |rva: u32| -> String {
        let bytes: Vec<u8> = if in_dir(rva) {
            blob[(rva - dir.rva) as usize..].iter().copied().take_while(|&b| b != 0).collect()
        } else {
            p.read_partial(base + rva as u64, 512).into_iter().map_while(|b| b.filter(|&b| b != 0)).collect()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    };

    let ord_base = le_u32(&blob, 16);
    let n_funcs = le_u32(&blob, 20);
    let n_names = le_u32(&blob, 24);
    let a_funcs = le_u32(&blob, 28);
    let a_names = le_u32(&blob, 32);
    let a_ords = le_u32(&blob, 36);

    let index = if let Some(ord) = symbol.strip_prefix('#') {
        let ord: u32 = ord
            .parse()
            .map_err(|_| MemError::InvalidArg(format!("bad ordinal '{symbol}' (use decimal, e.g. #12)")))?;
        ord.checked_sub(ord_base)
            .filter(|i| *i < n_funcs)
            .ok_or_else(|| MemError::InvalidArg(format!("ordinal {ord} not exported by {}", m.name)))?
    } else {
        let n = n_names as usize;
        let mut names = vec![0u8; n * 4];
        p.read(base + a_names as u64, &mut names)?;
        let mut ords = vec![0u8; n * 2];
        p.read(base + a_ords as u64, &mut ords)?;
        let name_at = |i: usize| cstr(le_u32(&names, i * 4));
        let ord_at = |i: usize| u16::from_le_bytes([ords[i * 2], ords[i * 2 + 1]]) as u32;
        // Names are sorted (case-sensitive), so try binary search first.
        let mut lo = 0usize;
        let mut hi = n;
        let mut found = None;
        while lo < hi {
            let mid = (lo + hi) / 2;
            match name_at(mid).as_str().cmp(symbol) {
                std::cmp::Ordering::Equal => {
                    found = Some(mid);
                    break;
                }
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        // Fall back to a case-insensitive scan (convenient for hand-typed names).
        let found = found.or_else(|| (0..n).find(|&i| name_at(i).eq_ignore_ascii_case(symbol)));
        let i = found.ok_or_else(|| MemError::InvalidArg(format!("export '{symbol}' not found in {}", m.name)))?;
        let idx = ord_at(i);
        if idx >= n_funcs {
            return Err(MemError::Os(format!("corrupt export table in {}", m.name)));
        }
        idx
    };

    let rva = read_u32(p, base + a_funcs as u64 + index as u64 * 4)?;
    if rva == 0 {
        return Err(MemError::InvalidArg(format!("export '{symbol}' in {} has no address", m.name)));
    }
    if in_dir(rva) {
        Ok(Target::Forward(cstr(rva)))
    } else {
        Ok(Target::Address(base + rva as u64))
    }
}

#[cfg(test)]
pub(crate) mod testpe {
    //! Builds a tiny fake PE image with an export table for unit tests.

    /// Exports: `Alpha` (ord 1, rva 0x1000), `Beta` (ord 2, forwarded to `<fwd>`), `Gamma` (ord 3, rva 0x2000).
    pub fn image(pe32_plus: bool, fwd: &str) -> Vec<u8> {
        let mut img = vec![0u8; 0x3000];
        let w16 = |img: &mut Vec<u8>, o: usize, v: u16| img[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let w32 = |img: &mut Vec<u8>, o: usize, v: u32| img[o..o + 4].copy_from_slice(&v.to_le_bytes());
        w16(&mut img, 0, 0x5A4D);
        w32(&mut img, 0x3C, 0x80);
        w32(&mut img, 0x80, 0x4550);
        let opt = 0x80 + 24;
        let (dirs, count) = if pe32_plus { (opt + 112, opt + 108) } else { (opt + 96, opt + 92) };
        w16(&mut img, opt, if pe32_plus { 0x20B } else { 0x10B });
        w32(&mut img, count, 16);
        let exp = 0x400u32;
        w32(&mut img, dirs, exp);
        w32(&mut img, dirs + 4, 0x200);
        let e = exp as usize;
        w32(&mut img, e + 16, 1); // ordinal base
        w32(&mut img, e + 20, 3); // functions
        w32(&mut img, e + 24, 3); // names
        w32(&mut img, e + 28, exp + 0x40);
        w32(&mut img, e + 32, exp + 0x50);
        w32(&mut img, e + 36, exp + 0x60);
        // functions
        w32(&mut img, e + 0x40, 0x1000);
        w32(&mut img, e + 0x44, exp + 0x100); // forwarder string inside the export dir
        w32(&mut img, e + 0x48, 0x2000);
        // sorted names → ordinal index
        let names = [("Alpha", 0u16, 0x80u32), ("Beta", 1, 0x88), ("Gamma", 2, 0x90)];
        for (i, (name, idx, off)) in names.iter().enumerate() {
            w32(&mut img, e + 0x50 + i * 4, exp + off);
            w16(&mut img, e + 0x60 + i * 2, *idx);
            let o = e + *off as usize;
            img[o..o + name.len()].copy_from_slice(name.as_bytes());
        }
        let f = e + 0x100;
        img[f..f + fwd.len()].copy_from_slice(fwd.as_bytes());
        img
    }
}

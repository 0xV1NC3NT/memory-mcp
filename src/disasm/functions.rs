//! Function boundaries.
//!
//! * x64 PE: the exception directory (`.pdata`) gives exact ranges; chained unwind entries are
//!   fragments (e.g. cold code) of a root function.
//! * Everywhere else, and for x64 leaf functions (they have no `.pdata` entry): the start is the
//!   nearest known start (call target, export, `.pdata` root) or the nearest 16-byte-aligned
//!   address after `int3` padding — whichever is closer and decodes exactly up to the address;
//!   the end comes from a recursive traversal of the control flow, bounded by the next known start.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use rayon::prelude::*;
use serde::Serialize;

use super::{Line, LineKind, branch_target, static_memory_address};
use crate::binfmt;
use crate::error::{MemError, Result};
use crate::platform::{Module, ProcessMemory};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SWEEP_CHUNK: u64 = 1 << 20;
const MAX_FUNCTION: u64 = 1 << 20;
const MAX_INSTRUCTIONS: usize = 100_000;
const PADDING_WINDOW: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartKind {
    Pdata,
    CallTarget,
    Export,
}

#[derive(Debug, Clone, Copy)]
pub struct PdataEntry {
    pub begin: u64,
    pub end: u64,
    /// Begin of the root function (== begin unless this is a chained fragment).
    pub root: u64,
}

/// Per-module code facts, built once and cached.
pub struct ModuleCode {
    pub module: Module,
    pub exec_ranges: Vec<(u64, u64)>,
    pub pdata: Vec<PdataEntry>,
    /// Known function starts (sorted) with the strongest evidence for each.
    pub starts: Vec<(u64, StartKind)>,
    pub call_targets: usize,
    /// Cross-reference index, built on first use.
    pub xrefs: std::sync::OnceLock<Arc<super::xrefs::XrefIndex>>,
}

impl ModuleCode {
    pub fn pdata_at(&self, a: u64) -> Option<&PdataEntry> {
        let i = self.pdata.partition_point(|e| e.begin <= a);
        let e = self.pdata.get(i.checked_sub(1)?)?;
        (a < e.end).then_some(e)
    }

    pub fn exec_range(&self, a: u64) -> Option<(u64, u64)> {
        self.exec_ranges.iter().copied().find(|&(s, e)| a >= s && a < e)
    }

    pub fn start_at_or_before(&self, a: u64) -> Option<(u64, StartKind)> {
        let i = self.starts.partition_point(|(s, _)| *s <= a);
        self.starts.get(i.checked_sub(1)?).copied()
    }

    pub fn start_after(&self, a: u64) -> Option<u64> {
        let i = self.starts.partition_point(|(s, _)| *s <= a);
        self.starts.get(i).map(|(s, _)| *s)
    }

    /// The cross-reference index of this module (built on first call).
    pub fn xref_index(&self, p: &dyn ProcessMemory, modules: &[Module]) -> Arc<super::xrefs::XrefIndex> {
        self.xrefs.get_or_init(|| Arc::new(super::xrefs::build(p, self, modules))).clone()
    }

    pub fn is_start(&self, a: u64) -> bool {
        self.starts.binary_search_by_key(&a, |(s, _)| *s).is_ok()
    }
}

fn decode_one(bitness: u32, bytes: &[u8], ip: u64) -> Option<Instruction> {
    let i = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE).decode();
    (!i.is_invalid()).then_some(i)
}

/// Builds the code facts of `module`.
pub fn build_module_code(p: &dyn ProcessMemory, module: &Module) -> Result<ModuleCode> {
    let bitness = (p.pointer_size() * 8) as u32;
    let exec_ranges: Vec<(u64, u64)> = match binfmt::sections(p, module) {
        Ok(secs) => secs
            .iter()
            .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && s.virtual_size > 0)
            .map(|s| (module.base + s.rva as u64, module.base + s.rva as u64 + s.virtual_size as u64))
            .collect(),
        Err(e) => return Err(MemError::InvalidArg(format!("cannot read sections of {}: {e}", module.name))),
    };

    // .pdata with chain roots
    let raw = binfmt::runtime_functions(p, module).unwrap_or_default();
    let pdata: Vec<PdataEntry> = raw
        .iter()
        .map(|f| {
            let mut root = *f;
            for _ in 0..32 {
                match binfmt::chained_parent(p, module, &root) {
                    Some(parent) => root = parent,
                    None => break,
                }
            }
            PdataEntry { begin: module.base + f.begin as u64, end: module.base + f.end as u64, root: module.base + root.begin as u64 }
        })
        .collect();

    // direct call targets from a linear sweep of the executable sections
    let in_exec = |a: u64| exec_ranges.iter().any(|&(s, e)| a >= s && a < e);
    let mut chunks = Vec::new();
    for &(s, e) in &exec_ranges {
        let mut c = s;
        while c < e {
            let ce = (c + SWEEP_CHUNK).min(e);
            chunks.push((c, ce, (ce + 16).min(e)));
            c = ce;
        }
    }
    let mut targets: Vec<u64> = chunks
        .par_iter()
        .flat_map_iter(|&(c, ce, read_end)| {
            let data: Vec<u8> =
                p.read_partial(c, (read_end - c) as usize).into_iter().map(|b| b.unwrap_or(0xCC)).collect();
            let mut dec = Decoder::with_ip(bitness, &data, c, DecoderOptions::NONE);
            let mut out = Vec::new();
            let mut i = Instruction::default();
            while dec.can_decode() {
                dec.decode_out(&mut i);
                if i.ip() >= ce {
                    break;
                }
                if i.flow_control() == FlowControl::Call
                    && let Some(t) = branch_target(&i)
                {
                    out.push(t);
                }
            }
            out
        })
        .filter(|&t| in_exec(t))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    // Plausibility: real function starts are aligned or follow padding / a return.
    let targets: Vec<u64> = targets
        .into_iter()
        .filter(|&t| {
            if t.is_multiple_of(16) {
                return true;
            }
            let mut b = [0u8; 1];
            p.read(t - 1, &mut b).is_ok() && matches!(b[0], 0xCC | 0x90 | 0xC3)
        })
        .collect();

    let exports = binfmt::exports(p, module).unwrap_or_default();
    let mut starts: BTreeMap<u64, StartKind> = BTreeMap::new();
    for &t in &targets {
        starts.insert(t, StartKind::CallTarget);
    }
    for (a, _) in exports.iter().filter(|(a, _)| in_exec(*a)) {
        starts.insert(*a, StartKind::Export);
    }
    for e in pdata.iter().filter(|e| e.begin == e.root) {
        starts.insert(e.begin, StartKind::Pdata);
    }
    Ok(ModuleCode {
        module: module.clone(),
        exec_ranges,
        pdata,
        starts: starts.into_iter().collect(),
        call_targets: targets.len(),
        xrefs: std::sync::OnceLock::new(),
    })
}

/// Cache of [`ModuleCode`] keyed by (pid, module base, module size).
#[derive(Default)]
pub struct CodeCache {
    map: Mutex<HashMap<(u32, u64, u64), Arc<ModuleCode>>>,
}

impl CodeCache {
    pub fn get(&self, p: &dyn ProcessMemory, module: &Module) -> Result<Arc<ModuleCode>> {
        let key = (p.pid(), module.base, module.size);
        if let Some(mc) = self.map.lock().unwrap().get(&key) {
            return Ok(mc.clone());
        }
        let mc = Arc::new(build_module_code(p, module)?);
        let mut map = self.map.lock().unwrap();
        map.retain(|k, _| k.0 == p.pid());
        map.insert(key, mc.clone());
        Ok(mc)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Pdata,
    PdataChained,
    CallTarget,
    Export,
    Padding,
    SectionStart,
}

pub struct Function {
    pub start: u64,
    pub end: u64,
    pub source: Source,
    /// Code ranges belonging to the function (several for chained `.pdata` fragments).
    pub fragments: Vec<(u64, u64)>,
    /// Decoded instructions in address order.
    pub lines: Vec<Line>,
    pub blocks: usize,
    pub truncated: bool,
    /// Whether `addr` (the address the lookup started from) lies on a decoded instruction.
    pub contains_query: bool,
}

/// Linear decode of `[from, to)`.
fn decode_range(p: &dyn ProcessMemory, from: u64, to: u64) -> Vec<Line> {
    let bitness = (p.pointer_size() * 8) as u32;
    let data: Vec<Option<u8>> = p.read_partial(from, (to - from) as usize + 15);
    let readable = data.iter().take_while(|b| b.is_some()).count();
    let bytes: Vec<u8> = data[..readable].iter().map(|b| b.unwrap()).collect();
    let mut out = Vec::new();
    let mut off = 0usize;
    while (from + off as u64) < to && off < readable {
        let ip = from + off as u64;
        match decode_one(bitness, &bytes[off..], ip) {
            Some(i) => {
                out.push(Line { address: ip, bytes: bytes[off..off + i.len()].to_vec(), kind: LineKind::Code, instr: Some(i) });
                off += i.len();
            }
            None => {
                out.push(Line { address: ip, bytes: vec![bytes[off]], kind: LineKind::Invalid, instr: None });
                off += 1;
            }
        }
    }
    out
}

/// Whether linear decoding from `from` reaches an instruction that covers `to`.
fn decodes_over(bitness: u32, window: &[u8], window_base: u64, from: u64, to: u64) -> bool {
    if from > to || from < window_base {
        return false;
    }
    let mut off = (from - window_base) as usize;
    let target = (to - window_base) as usize;
    while off <= target && off < window.len() {
        match decode_one(bitness, &window[off..], window_base + off as u64) {
            Some(i) if off + i.len() > target => return true,
            Some(i) => off += i.len(),
            None => return false,
        }
    }
    false
}

/// Recursive traversal of the control flow from `start`, staying inside `[start, limit)` and
/// not entering other known function starts.
fn traverse(p: &dyn ProcessMemory, start: u64, limit: u64, is_other_start: &dyn Fn(u64) -> bool) -> (Vec<Line>, usize, bool) {
    let bitness = (p.pointer_size() * 8) as u32;
    let data: Vec<Option<u8>> = p.read_partial(start, (limit - start) as usize + 15);
    let readable = data.iter().take_while(|b| b.is_some()).count();
    let bytes: Vec<u8> = data[..readable].iter().map(|b| b.unwrap()).collect();
    let in_range = |a: u64| a >= start && a < limit && ((a - start) as usize) < readable;
    let mut insns: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut blocks: BTreeSet<u64> = BTreeSet::new();
    let mut work = vec![start];
    let mut truncated = false;
    while let Some(b) = work.pop() {
        if !blocks.insert(b) {
            continue;
        }
        let mut ip = b;
        loop {
            if !in_range(ip) || insns.contains_key(&ip) {
                break;
            }
            let off = (ip - start) as usize;
            let Some(i) = decode_one(bitness, &bytes[off..], ip) else { break };
            insns.insert(ip, i);
            if insns.len() >= MAX_INSTRUCTIONS {
                truncated = true;
                break;
            }
            let next = ip + i.len() as u64;
            match i.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => {
                    if let Some(t) = branch_target(&i).filter(|&t| in_range(t) && !is_other_start(t)) {
                        work.push(t);
                    }
                    ip = next;
                }
                FlowControl::UnconditionalBranch => {
                    // Jumps to another known function are tail calls.
                    if let Some(t) = branch_target(&i).filter(|&t| in_range(t) && !is_other_start(t)) {
                        work.push(t);
                    }
                    break;
                }
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Interrupt | FlowControl::Exception => break,
                FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => ip = next,
            }
        }
        if truncated {
            break;
        }
    }
    let lines = insns
        .into_iter()
        .map(|(ip, i)| {
            let off = (ip - start) as usize;
            Line { address: ip, bytes: bytes[off..off + i.len()].to_vec(), kind: LineKind::Code, instr: Some(i) }
        })
        .collect();
    (lines, blocks.len(), truncated)
}

/// Finds the function containing `addr`. `code` is the module's code facts (None for code outside modules).
pub fn find(p: &dyn ProcessMemory, code: Option<&ModuleCode>, addr: u64) -> Result<Function> {
    let bitness = (p.pointer_size() * 8) as u32;
    let contains = |lines: &[Line]| lines.iter().any(|l| addr >= l.address && addr < l.address + l.bytes.len() as u64);

    // 1. exact boundaries from .pdata
    if let Some(mc) = code
        && let Some(e) = mc.pdata_at(addr)
    {
        let root = e.root;
        let mut fragments: Vec<(u64, u64)> = mc.pdata.iter().filter(|x| x.root == root).map(|x| (x.begin, x.end)).collect();
        fragments.sort_unstable();
        let lines: Vec<Line> = fragments.iter().flat_map(|&(b, e)| decode_range(p, b, e)).collect();
        let source = if fragments.len() > 1 || e.begin != root { Source::PdataChained } else { Source::Pdata };
        let end = fragments.iter().find(|f| f.0 == root).map(|f| f.1).unwrap_or(e.end);
        let blocks = 1 + lines.iter().filter_map(|l| l.instr.as_ref()).filter(|i| i.flow_control() == FlowControl::ConditionalBranch).count();
        let contains_query = contains(&lines);
        return Ok(Function { start: root, end, source, fragments, lines, blocks, truncated: false, contains_query });
    }

    // 2. heuristics
    let (lo, hi) = code
        .and_then(|mc| mc.exec_range(addr))
        .unwrap_or((addr.saturating_sub(PADDING_WINDOW), addr.saturating_add(MAX_FUNCTION)));
    let win_lo = addr.saturating_sub(PADDING_WINDOW).max(lo);
    let window: Vec<u8> =
        p.read_partial(win_lo, (addr - win_lo) as usize + 16).into_iter().map(|b| b.unwrap_or(0)).collect();

    // nearest known start whose code can reach `addr` (a .pdata function only if `addr` is inside it)
    let known = code.and_then(|mc| {
        let i = mc.starts.partition_point(|(s, _)| *s <= addr);
        mc.starts[..i]
            .iter()
            .rev()
            .take(64)
            .copied()
            .take_while(|&(s, _)| s >= win_lo)
            .find(|&(s, k)| {
                if k == StartKind::Pdata && mc.pdata_at(addr).is_none() {
                    return false;
                }
                decodes_over(bitness, &window, win_lo, s, addr)
            })
    });

    // nearest aligned address after int3 padding (not itself int3) whose code reaches `addr`
    let mut padding = None;
    let mut cand = addr - addr % 16;
    while cand > win_lo {
        let at = (cand - win_lo) as usize;
        if window[at - 1] == 0xCC && window[at] != 0xCC && decodes_over(bitness, &window, win_lo, cand, addr) {
            padding = Some(cand);
            break;
        }
        cand -= 16;
    }
    let mut padding_source = Source::Padding;
    // The first function of a code section has no padding before it.
    if padding.is_none()
        && code.is_some_and(|mc| mc.exec_range(addr).is_some())
        && win_lo == lo
        && window.first().is_some_and(|&b| b != 0xCC)
        && decodes_over(bitness, &window, win_lo, lo, addr)
    {
        padding = Some(lo);
        padding_source = Source::SectionStart;
    }

    let (start, source) = match (known, padding) {
        (Some((s, k)), Some(pad)) if s >= pad => (s, kind_source(k)),
        (_, Some(pad)) => (pad, padding_source),
        (Some((s, k)), None) => (s, kind_source(k)),
        (None, None) => {
            return Err(MemError::InvalidArg(format!(
                "cannot determine the start of the function containing {addr:#x} (no .pdata entry, known start or padding before it)"
            )));
        }
    };
    let next_start = code.and_then(|mc| mc.start_after(start)).unwrap_or(u64::MAX);
    let limit = hi.min(next_start).min(start + MAX_FUNCTION).max(addr + 1);
    let is_other = |t: u64| t != start && code.is_some_and(|mc| mc.is_start(t));
    let (lines, blocks, truncated) = traverse(p, start, limit, &is_other);
    if lines.is_empty() {
        return Err(MemError::Read { addr: start, size: 1, reason: p.explain_unreadable(start) });
    }
    let end = lines.iter().map(|l| l.address + l.bytes.len() as u64).max().unwrap();
    let contains_query = contains(&lines);
    Ok(Function { start, end, source, fragments: vec![(start, end)], lines, blocks, truncated, contains_query })
}

fn kind_source(k: StartKind) -> Source {
    match k {
        StartKind::Pdata => Source::Pdata,
        StartKind::CallTarget => Source::CallTarget,
        StartKind::Export => Source::Export,
    }
}

/// (call site, target) of direct calls.
pub type DirectCalls = Vec<(u64, u64)>;
/// (call site, memory slot when statically known) of indirect calls.
pub type IndirectCalls = Vec<(u64, Option<u64>)>;

/// Direct call targets and indirect call sites of a function.
pub fn calls(f: &Function) -> (DirectCalls, IndirectCalls) {
    let mut direct = Vec::new();
    let mut indirect = Vec::new();
    for l in &f.lines {
        let Some(i) = &l.instr else { continue };
        match i.flow_control() {
            FlowControl::Call => direct.extend(branch_target(i).map(|t| (l.address, t))),
            FlowControl::IndirectCall => indirect.push((l.address, static_memory_address(i))),
            _ => {}
        }
    }
    (direct, indirect)
}

/// Local labels (`loc_<module offset>`) for branch targets inside the function.
pub fn local_labels(f: &Function, module: Option<&Module>) -> HashMap<u64, String> {
    let inside = |a: u64| f.fragments.iter().any(|&(s, e)| a >= s && a < e) && a != f.start;
    let mut out = HashMap::new();
    for l in &f.lines {
        let Some(i) = &l.instr else { continue };
        if matches!(i.flow_control(), FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch)
            && let Some(t) = branch_target(i).filter(|&t| inside(t))
        {
            let name = match module {
                Some(m) => format!("loc_{:X}", t - m.base),
                None => format!("loc_{t:X}"),
            };
            out.insert(t, name);
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    pub const BASE: u64 = 0x1_4000_0000;

    fn w32(img: &mut [u8], o: usize, v: u32) {
        img[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// x64 PE: .text at 0x1000 (int3-filled), .pdata, unwind info.
    ///   f1 0x1000..0x1010 (pdata) calls f2
    ///   f2 0x1040..0x1046 leaf (no pdata, call target)
    ///   f3 0x1080..0x1089 (pdata) + cold fragment 0x1800..0x1803 (chained pdata)
    ///   f4 0x10C0..       leaf, not called (padding heuristic)
    pub fn image_x64() -> Vec<u8> {
        let mut img = vec![0u8; 0x3000];
        img[..2].copy_from_slice(b"MZ");
        w32(&mut img, 0x3C, 0x80);
        w32(&mut img, 0x80, 0x4550);
        img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        img[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = 0x80 + 24;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        w32(&mut img, opt + 108, 16); // NumberOfRvaAndSizes
        let dirs = opt + 112;
        w32(&mut img, dirs + 3 * 8, 0x2100); // exception directory
        w32(&mut img, dirs + 3 * 8 + 4, 36);
        let sec = opt + 240;
        img[sec..sec + 5].copy_from_slice(b".text");
        w32(&mut img, sec + 8, 0x1000); // VirtualSize
        w32(&mut img, sec + 12, 0x1000); // VirtualAddress
        w32(&mut img, sec + 36, 0x6000_0020); // code | execute | read
        img[0x1000..0x2000].fill(0xCC);
        let code: &[(usize, &[u8])] = &[
            (0x1000, &[0x53, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x36, 0, 0, 0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]),
            (0x1040, &[0xB8, 1, 0, 0, 0, 0xC3]),
            (0x1080, &[0x85, 0xC9, 0x0F, 0x84, 0x78, 0x07, 0, 0, 0xC3]),
            // f4: test ecx,ecx ; jz +1 ; inc eax ; ret
            (0x10C0, &[0x85, 0xC9, 0x74, 0x02, 0xFF, 0xC0, 0xC3]),
            (0x1800, &[0x31, 0xC0, 0xC3]),
        ];
        for (o, b) in code {
            img[*o..*o + b.len()].copy_from_slice(b);
        }
        img[0x2000..0x2004].copy_from_slice(&[0x01, 5, 0, 0]); // unwind A
        img[0x2010..0x2014].copy_from_slice(&[0x01, 0, 0, 0]); // unwind B
        img[0x2020..0x2024].copy_from_slice(&[0x01 | (0x4 << 3), 0, 0, 0]); // unwind C (chained)
        for (o, v) in [(0x2024, 0x1080u32), (0x2028, 0x1089), (0x202C, 0x2010)] {
            w32(&mut img, o, v);
        }
        for (i, (b, e, u)) in [(0x1000u32, 0x1010u32, 0x2000u32), (0x1080, 0x1089, 0x2010), (0x1800, 0x1803, 0x2020)].iter().enumerate() {
            let o = 0x2100 + i * 12;
            w32(&mut img, o, *b);
            w32(&mut img, o + 4, *e);
            w32(&mut img, o + 8, *u);
        }
        img
    }

    pub fn mock_x64() -> (MockProcess, Module) {
        let mut m = MockProcess::new(Arch::X64);
        m.add_module("game.exe", BASE, image_x64());
        let module = m.modules().unwrap()[0].clone();
        (m, module)
    }

    #[test]
    fn module_code_facts() {
        let (m, module) = mock_x64();
        let mc = build_module_code(&m, &module).unwrap();
        assert_eq!(mc.exec_ranges, [(BASE + 0x1000, BASE + 0x2000)]);
        assert_eq!(mc.pdata.len(), 3);
        assert_eq!(mc.pdata[2].root, BASE + 0x1080, "chained fragment points to its root");
        let starts: Vec<(u64, StartKind)> = mc.starts.clone();
        assert_eq!(
            starts,
            [(BASE + 0x1000, StartKind::Pdata), (BASE + 0x1040, StartKind::CallTarget), (BASE + 0x1080, StartKind::Pdata)]
        );
    }

    #[test]
    fn finds_functions_by_every_method() {
        let (m, module) = mock_x64();
        let mc = build_module_code(&m, &module).unwrap();
        let f = find(&m, Some(&mc), BASE + 0x100A).unwrap();
        assert_eq!((f.start, f.end, f.source), (BASE + 0x1000, BASE + 0x1010, Source::Pdata));
        assert!(f.contains_query);
        assert_eq!(calls(&f).0, [(BASE + 0x1005, BASE + 0x1040)]);

        let f = find(&m, Some(&mc), BASE + 0x1045).unwrap();
        assert_eq!((f.start, f.end, f.source), (BASE + 0x1040, BASE + 0x1046, Source::CallTarget));

        let f = find(&m, Some(&mc), BASE + 0x1801).unwrap();
        assert_eq!((f.start, f.source), (BASE + 0x1080, Source::PdataChained));
        assert_eq!(f.fragments, [(BASE + 0x1080, BASE + 0x1089), (BASE + 0x1800, BASE + 0x1803)]);
        let labels = local_labels(&f, Some(&module));
        assert_eq!(labels.get(&(BASE + 0x1800)).map(String::as_str), Some("loc_1800"));

        let f = find(&m, Some(&mc), BASE + 0x10C6).unwrap();
        assert_eq!((f.start, f.end, f.source), (BASE + 0x10C0, BASE + 0x10C7, Source::Padding));
        assert_eq!(f.blocks, 2, "jz splits the function into blocks");

        // the address must lie on an instruction boundary reachable from a start
        let e = find(&m, Some(&mc), BASE + 0x1F00);
        assert!(e.is_err() || !e.unwrap().contains_query);
    }

    #[test]
    fn x86_without_pdata() {
        let mut m = MockProcess::new(Arch::X86);
        let mut img = vec![0u8; 0x2000];
        img[..2].copy_from_slice(b"MZ");
        w32(&mut img, 0x3C, 0x80);
        w32(&mut img, 0x80, 0x4550);
        img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        img[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
        let opt = 0x80 + 24;
        img[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        w32(&mut img, opt + 92, 16);
        let sec = opt + 224;
        img[sec..sec + 5].copy_from_slice(b".text");
        w32(&mut img, sec + 8, 0x1000);
        w32(&mut img, sec + 12, 0x1000);
        w32(&mut img, sec + 36, 0x6000_0020);
        img[0x1000..0x2000].fill(0xCC);
        // f1: push ebp; mov ebp,esp; call f2; pop ebp; ret   f2 @0x1010: mov eax,1; ret
        img[0x1000..0x100A].copy_from_slice(&[0x55, 0x8B, 0xEC, 0xE8, 0x08, 0, 0, 0, 0x5D, 0xC3]);
        img[0x1010..0x1016].copy_from_slice(&[0xB8, 1, 0, 0, 0, 0xC3]);
        m.add_module("game.exe", 0x40_0000, img);
        let module = m.modules().unwrap()[0].clone();
        let mc = build_module_code(&m, &module).unwrap();
        assert!(mc.pdata.is_empty());
        // an address in the middle of an instruction is fine
        let f = find(&m, Some(&mc), 0x40_1011).unwrap();
        assert_eq!((f.start, f.end, f.source), (0x40_1010, 0x40_1016, Source::CallTarget));
        assert!(f.contains_query);
        let f = find(&m, Some(&mc), 0x40_1008).unwrap();
        assert_eq!((f.start, f.end, f.source), (0x40_1000, 0x40_100A, Source::SectionStart));
    }
}

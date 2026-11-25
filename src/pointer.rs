//! Pointer scan: find chains `[[module+base]+o1]+o2 … = target` that survive restarts.
//!
//! 1. Index: every aligned pointer-sized value in image/writable memory that points into a
//!    readable region, as (value, address) pairs sorted by value.
//! 2. Reverse BFS from the target: at each level find pointers whose value lies in
//!    `[node - max_offset, node]`, closest first; addresses inside a module image are static
//!    bases (results), the others become the next frontier (ordered by total offset). An address
//!    appears at most once per level; each static base is reported once per depth.
//! 3. Rescan re-evaluates the module-relative chains in the current process.

use std::collections::HashSet;

use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use crate::address::{self, Offset};
use crate::error::{MemError, Result};
use crate::format;
use crate::platform::{Module, ProcessMemory, Region, RegionKind, RegionState};

const CHUNK: u64 = 1 << 20;
pub const MAX_INDEX: usize = 64 << 20;
pub const MAX_DEPTH: usize = 7;

#[derive(Debug, Clone, Copy)]
pub struct PtrScanOptions {
    pub max_depth: usize,
    pub max_offset: u64,
    pub max_results: usize,
    pub max_nodes: usize,
    pub include_mapped: bool,
    /// Pointer alignment in memory (default: pointer size).
    pub align: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Chain {
    pub module: String,
    pub base_offset: u64,
    pub offsets: Vec<u64>,
}

impl Chain {
    /// Base expression with a quoted module name (unambiguous vs. hex).
    pub fn base_expr(&self) -> String {
        format!("\"{}\"+0x{:X}", self.module, self.base_offset)
    }

    /// Nested form, e.g. `[["game.exe"+0x10]+0x18]+0x4`.
    pub fn expression(&self) -> String {
        let mut e = self.base_expr();
        for o in &self.offsets {
            e = format!("[{e}]+0x{o:X}");
        }
        e
    }

    pub fn offsets_as_args(&self) -> Vec<Offset> {
        self.offsets.iter().map(|o| Offset::Expr(format!("0x{o:X}"))).collect()
    }

    pub fn resolve(&self, p: &dyn ProcessMemory) -> Result<u64> {
        address::resolve(p, &self.base_expr(), &self.offsets_as_args()).map(|r| r.address)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "base": format!("{}+0x{:X}", self.module, self.base_offset),
            "offsets": self.offsets.iter().map(|o| format!("0x{o:X}")).collect::<Vec<_>>(),
            "depth": self.offsets.len(),
            "expression": self.expression(),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PtrScanStats {
    pub regions_indexed: usize,
    pub bytes_indexed: u64,
    pub pointers: usize,
    pub nodes_visited: usize,
    pub levels: usize,
    pub truncated: bool,
    pub truncated_reason: Option<String>,
    pub index_ms: u64,
    pub search_ms: u64,
}

fn readable_bytes(p: &dyn ProcessMemory, start: u64, end: u64) -> Vec<(u64, Vec<u8>)> {
    let len = (end - start) as usize;
    let mut buf = vec![0u8; len];
    if p.read(start, &mut buf).is_ok() {
        return vec![(start, buf)];
    }
    let partial = p.read_partial(start, len);
    let mut out = Vec::new();
    let mut i = 0;
    while i < len {
        if partial[i].is_none() {
            i += 1;
            continue;
        }
        let s = i;
        while i < len && partial[i].is_some() {
            i += 1;
        }
        out.push((start + s as u64, partial[s..i].iter().map(|b| b.unwrap()).collect()));
    }
    out
}

/// Sorted, merged ranges of readable committed memory (valid pointer targets).
fn valid_ranges(regions: &[Region]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for r in regions.iter().filter(|r| r.readable()) {
        match out.last_mut() {
            Some(last) if last.1 == r.base => last.1 = r.end(),
            _ => out.push((r.base, r.end())),
        }
    }
    out
}

#[inline]
fn in_ranges(ranges: &[(u64, u64)], v: u64) -> bool {
    let i = ranges.partition_point(|r| r.1 <= v);
    i < ranges.len() && ranges[i].0 <= v
}

/// (value, address) pairs sorted by value.
pub fn build_index(p: &dyn ProcessMemory, opts: &PtrScanOptions, stats: &mut PtrScanStats) -> Result<Vec<(u64, u64)>> {
    let regions = p.regions()?;
    let valid = valid_ranges(&regions);
    let src: Vec<&Region> = regions
        .iter()
        .filter(|r| r.state == RegionState::Commit && r.readable())
        .filter(|r| r.kind == RegionKind::Image || r.protect.write)
        .filter(|r| opts.include_mapped || r.kind != RegionKind::Mapped)
        .collect();
    stats.regions_indexed = src.len();
    stats.bytes_indexed = src.iter().map(|r| r.size).sum();
    let mut chunks = Vec::new();
    for r in &src {
        let mut c = r.base;
        while c < r.end() {
            let e = (c + CHUNK).min(r.end());
            chunks.push((c, e));
            c = e;
        }
    }
    let ps = p.pointer_size();
    let align = opts.align.max(1);
    let parts: Vec<Vec<(u64, u64)>> = chunks
        .par_iter()
        .map(|&(s, e)| {
            let mut out = Vec::new();
            for (base, data) in readable_bytes(p, s, e) {
                let first = base.div_ceil(align) * align;
                let mut a = first;
                while a + ps as u64 <= base + data.len() as u64 {
                    let i = (a - base) as usize;
                    let v = if ps == 4 {
                        u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as u64
                    } else {
                        u64::from_le_bytes(data[i..i + 8].try_into().unwrap())
                    };
                    if v >= 0x10000 && in_ranges(&valid, v) {
                        out.push((v, a));
                    }
                    a += align;
                }
            }
            out
        })
        .collect();
    let total: usize = parts.iter().map(Vec::len).sum();
    if total > MAX_INDEX {
        return Err(MemError::InvalidArg(format!(
            "{total} candidate pointers exceed the index limit ({MAX_INDEX}); narrow the scan (e.g. exclude mapped memory)"
        )));
    }
    let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(total);
    for part in parts {
        pairs.extend(part);
    }
    pairs.par_sort_unstable();
    stats.pointers = pairs.len();
    Ok(pairs)
}

struct Node {
    addr: u64,
    parent: u32,
    /// parent.addr - [addr]
    offset: u64,
    /// Sum of offsets from the target to this node.
    cost: u64,
}

/// Static base modules: `None` = any module.
pub fn search(
    index: &[(u64, u64)],
    modules: &[Module],
    allowed: Option<&[String]>,
    target: u64,
    opts: &PtrScanOptions,
    stats: &mut PtrScanStats,
) -> Vec<Chain> {
    let static_of = |a: u64| -> Option<&Module> {
        let m = modules.iter().find(|m| m.contains(a))?;
        match allowed {
            Some(list) if !list.iter().any(|n| n.eq_ignore_ascii_case(&m.name)) => None,
            _ => Some(m),
        }
    };
    let mut nodes = vec![Node { addr: target, parent: u32::MAX, offset: 0, cost: 0 }];
    let mut frontier: Vec<u32> = vec![0];
    let mut results: Vec<u32> = Vec::new();
    // One chain per (static base, depth): found first through the path with the smallest offsets.
    let mut static_seen: HashSet<(u64, usize)> = HashSet::new();
    'levels: for depth in 1..=opts.max_depth {
        stats.levels = depth;
        // An address may appear once per level, so a short path through it cannot hide a
        // longer structural path that reaches it at a deeper level.
        let mut seen: HashSet<u64> = HashSet::new();
        let mut next = Vec::new();
        for &ni in &frontier {
            let t = nodes[ni as usize].addr;
            let cost = nodes[ni as usize].cost;
            let lo = t.saturating_sub(opts.max_offset);
            let start = index.partition_point(|&(v, _)| v < lo);
            let end = index.partition_point(|&(v, _)| v <= t);
            // Closest values (smallest offsets) first.
            for &(v, a) in index[start..end].iter().rev() {
                if a == target {
                    continue;
                }
                let is_static = static_of(a).is_some();
                if is_static {
                    if !static_seen.insert((a, depth)) {
                        continue;
                    }
                } else if !seen.insert(a) {
                    continue;
                }
                nodes.push(Node { addr: a, parent: ni, offset: t - v, cost: cost + (t - v) });
                let idx = (nodes.len() - 1) as u32;
                if is_static {
                    results.push(idx);
                    if results.len() >= opts.max_results {
                        stats.truncated = true;
                        stats.truncated_reason = Some(format!("max_results ({}) reached", opts.max_results));
                        break 'levels;
                    }
                } else {
                    next.push(idx);
                }
                if nodes.len() >= opts.max_nodes {
                    stats.truncated = true;
                    stats.truncated_reason = Some(format!("max_nodes ({}) reached at depth {depth}", opts.max_nodes));
                    break 'levels;
                }
            }
        }
        if next.is_empty() {
            break;
        }
        next.sort_by_key(|&i| nodes[i as usize].cost);
        frontier = next;
    }
    stats.nodes_visited = nodes.len();
    let mut chains: Vec<Chain> = results
        .into_iter()
        .map(|ri| {
            let base = nodes[ri as usize].addr;
            let m = static_of(base).expect("static");
            let mut offsets = Vec::new();
            let mut c = ri;
            while c != 0 {
                offsets.push(nodes[c as usize].offset);
                c = nodes[c as usize].parent;
            }
            Chain { module: m.name.clone(), base_offset: base - m.base, offsets }
        })
        .collect();
    chains.sort_by(|a, b| {
        a.offsets
            .len()
            .cmp(&b.offsets.len())
            .then(a.offsets.iter().sum::<u64>().cmp(&b.offsets.iter().sum::<u64>()))
            .then(a.module.cmp(&b.module))
            .then(a.base_offset.cmp(&b.base_offset))
    });
    chains
}

/// Keeps the chains that currently resolve to `target`.
pub fn rescan(p: &dyn ProcessMemory, chains: &[Chain], target: u64) -> Vec<Chain> {
    chains.par_iter().filter(|c| c.resolve(p).is_ok_and(|a| a == target)).cloned().collect()
}

pub fn describe_target(p: &dyn ProcessMemory, modules: &[Module], target: u64) -> Value {
    json!({
        "address": format::addr(target, p.pointer_size()),
        "symbol": address::symbolize(modules, target),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    const GAME: u64 = 0x40_0000;
    const HEAP: u64 = 0x100_0000;

    fn opts() -> PtrScanOptions {
        PtrScanOptions { max_depth: 4, max_offset: 0x100, max_results: 100, max_nodes: 100_000, include_mapped: false, align: 8 }
    }

    /// game.exe+0x10 → A (HEAP); [A+0x18] → B (HEAP+0x200); B+0x30 → C (HEAP+0x900); target = C+0x8.
    /// Plus a decoy heap pointer to A (not static) and a far static pointer (offset 0x808 > max_offset).
    fn mock(arch: Arch) -> (MockProcess, u64) {
        let mut m = MockProcess::new(arch);
        m.add_module("game.exe", GAME, vec![0u8; 0x1000]);
        m.map(HEAP, vec![0u8; 0x1000]);
        let (a, b, c) = (HEAP, HEAP + 0x200, HEAP + 0x900);
        m.put_ptr(GAME + 0x10, a);
        m.put_ptr(a + 0x18, b);
        m.put_ptr(b + 0x30, c);
        m.put_ptr(HEAP + 0x800, a); // decoy (heap → A)
        m.put_ptr(GAME + 0x20, c + 0x8 - 0x808); // far pointer into the heap
        (m, c + 0x8)
    }

    #[test]
    fn finds_shortest_static_chain() {
        for arch in [Arch::X86, Arch::X64] {
            let (m, target) = mock(arch);
            let mut o = opts();
            o.align = arch.pointer_size() as u64;
            let mut st = PtrScanStats::default();
            let idx = build_index(&m, &o, &mut st).unwrap();
            assert!(st.pointers >= 5, "{st:?}");
            let mods = m.modules().unwrap();
            let chains = search(&idx, &mods, None, target, &o, &mut st);
            let want = Chain { module: "game.exe".into(), base_offset: 0x10, offsets: vec![0x18, 0x30, 0x8] };
            assert_eq!(chains, std::slice::from_ref(&want), "{chains:?}");
            assert_eq!(want.resolve(&m).unwrap(), target);
            assert_eq!(want.expression(), "[[[\"game.exe\"+0x10]+0x18]+0x30]+0x8");

            // depth limit
            o.max_depth = 2;
            assert!(search(&idx, &mods, None, target, &o, &mut st).is_empty());
            // module filter
            o.max_depth = 4;
            assert!(search(&idx, &mods, Some(&["other.dll".into()]), target, &o, &mut st).is_empty());
            // larger max_offset also finds the direct far pointer
            o.max_offset = 0x1000;
            let chains = search(&idx, &mods, None, target, &o, &mut st);
            assert_eq!(chains[0], Chain { module: "game.exe".into(), base_offset: 0x20, offsets: vec![0x808] });
        }
    }

    #[test]
    fn short_unstable_path_does_not_hide_static_base() {
        // game.exe+0x10 → A; A+0x18 → B; B+0x30 → C (target). A lies just below B+0x30, so
        // [game.exe+0x10]+0x248 = B+0x30 is also a (depth-2) path through the same static base.
        let mut m = MockProcess::new(Arch::X64);
        m.add_module("game.exe", GAME, vec![0u8; 0x1000]);
        m.map(HEAP, vec![0u8; 0x1000]);
        let (a, b, c) = (HEAP + 0x100, HEAP + 0x200, HEAP + 0x900);
        m.put_ptr(GAME + 0x10, a);
        m.put_ptr(a + 0x18, b);
        m.put_ptr(b + 0x30, c);
        let mut o = opts();
        o.max_offset = 0x1000;
        let mut st = PtrScanStats::default();
        let idx = build_index(&m, &o, &mut st).unwrap();
        let chains = search(&idx, &m.modules().unwrap(), None, c, &o, &mut st);
        let short = Chain { module: "game.exe".into(), base_offset: 0x10, offsets: vec![0x130, 0x0] };
        let long = Chain { module: "game.exe".into(), base_offset: 0x10, offsets: vec![0x18, 0x30, 0x0] };
        assert!(chains.contains(&short) && chains.contains(&long), "{chains:?}");
    }

    #[test]
    fn rescan_filters_chains() {
        let (m, target) = mock(Arch::X64);
        let good = Chain { module: "game.exe".into(), base_offset: 0x10, offsets: vec![0x18, 0x30, 0x8] };
        let bad = Chain { module: "game.exe".into(), base_offset: 0x10, offsets: vec![0x18, 0x38, 0x8] };
        assert_eq!(rescan(&m, &[good.clone(), bad.clone()], target), std::slice::from_ref(&good));
        // the object moves: B now points to a different C
        m.put_ptr(HEAP + 0x200 + 0x30, HEAP + 0x600);
        assert!(rescan(&m, std::slice::from_ref(&good), target).is_empty());
        assert_eq!(rescan(&m, std::slice::from_ref(&good), HEAP + 0x608), [good]);
    }

    #[test]
    fn limits_truncate() {
        let (m, target) = mock(Arch::X64);
        let mut o = opts();
        let mut st = PtrScanStats::default();
        let idx = build_index(&m, &o, &mut st).unwrap();
        o.max_nodes = 2;
        search(&idx, &m.modules().unwrap(), None, target, &o, &mut st);
        assert!(st.truncated && st.truncated_reason.as_deref().unwrap().contains("max_nodes"));
    }
}

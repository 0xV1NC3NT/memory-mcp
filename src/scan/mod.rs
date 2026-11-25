//! Value scanning sessions (first scan → next scan → …), Cheat Engine style.
//!
//! A generation is a list of 1 MiB chunks. A chunk is a raw snapshot (after an "unknown initial
//! value" scan), a snapshot with a bitmap of surviving positions (dense results), or a list of
//! hits: u32 offsets from the chunk base followed by the values seen in the last scan — whichever
//! is smaller. Blobs live in memory up to a budget, then in a temp file.

pub mod cond;
mod store;

use rayon::prelude::*;

pub use cond::{Cond, FloatMode, Num, ScanType, test};
pub use store::{Blob, Store};

use crate::error::{MemError, Result};
use crate::platform::ProcessMemory;

const CHUNK: u64 = 1 << 20;
/// Below this many hits a chunk is re-read value by value instead of as a whole.
const INDIVIDUAL_READS: usize = 64;

pub enum ChunkData {
    /// `data_len` bytes; every aligned position is a candidate.
    Snapshot(Blob),
    /// Bitmap (one bit per aligned position) followed by `data_len` bytes.
    Masked(Blob),
    /// `count` u32 offsets followed by `count` values.
    Hits(Blob),
}

pub struct Chunk {
    pub base: u64,
    /// Candidate positions are `< base + span`.
    pub span: u64,
    pub count: u64,
    /// Bytes of memory held by Snapshot / Masked chunks (0 for Hits).
    pub data_len: u64,
    pub data: ChunkData,
}

fn bitmap_len(npos: u64) -> usize {
    npos.div_ceil(8) as usize
}

#[inline]
fn bit(bits: &[u8], k: usize) -> bool {
    bits[k / 8] & (1 << (k % 8)) != 0
}

pub struct Generation {
    pub chunks: Vec<Chunk>,
    pub total: u64,
    pub store: Store,
}

impl Generation {
    pub fn memory_bytes(&self) -> u64 {
        self.store.memory_bytes()
    }
    pub fn disk_bytes(&self) -> u64 {
        self.store.disk_bytes()
    }
}

/// Parameters shared by all scans of a session.
#[derive(Debug, Clone, Copy)]
pub struct ScanSpec {
    pub ty: ScanType,
    pub align: u64,
    pub float_mode: FloatMode,
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

/// Number of aligned positions p with base <= p < base+span and p+size <= base+data_len.
fn positions(base: u64, span: u64, data_len: u64, spec: &ScanSpec) -> impl Iterator<Item = u64> {
    let size = spec.ty.size as u64;
    let end = (base + span).min((base + data_len).saturating_sub(size - 1));
    let first = align_up(base, spec.align);
    (first..end.max(first)).step_by(spec.align as usize)
}

fn count_positions(base: u64, span: u64, data_len: u64, spec: &ScanSpec) -> u64 {
    let size = spec.ty.size as u64;
    let end = (base + span).min((base + data_len).saturating_sub(size - 1));
    let first = align_up(base, spec.align);
    if end <= first { 0 } else { (end - first).div_ceil(spec.align) }
}

/// Readable pieces of `[start, read_end)`: (base, bytes). Fully readable ranges come back whole.
fn readable_segments(p: &dyn ProcessMemory, start: u64, read_end: u64) -> Vec<(u64, Vec<u8>)> {
    let len = (read_end - start) as usize;
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

fn pack_hits(offsets: &[u32], values: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(offsets.len() * 4 + values.len());
    for o in offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(values);
    out
}

fn unpack_hits(blob: &[u8], count: usize) -> (Vec<u32>, &[u8]) {
    let offs = blob[..count * 4].as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
    (offs, &blob[count * 4..])
}

/// First scan over `ranges` (ascending, non-overlapping). Returns the generation and bytes scanned.
pub fn first_scan(p: &dyn ProcessMemory, spec: &ScanSpec, cond: &Cond, ranges: &[(u64, u64)], budget: u64) -> Result<(Generation, u64)> {
    let size = spec.ty.size as u64;
    let mut pieces = Vec::new();
    for &(s, e) in ranges {
        let mut c = s;
        while c < e {
            let ce = (c + CHUNK).min(e);
            pieces.push((c, ce, (ce + size - 1).min(e)));
            c = ce;
        }
    }
    let scanned: u64 = ranges.iter().map(|(s, e)| e - s).sum();
    let store = Store::new(budget);
    // Exact integer (or exact-bits float) values can be found with memmem.
    let needle: Option<Vec<u8>> = match cond {
        Cond::Exact(t) if !spec.ty.is_float() || spec.float_mode == FloatMode::Exact => Some(spec.ty.encode(t.n)),
        _ => None,
    };
    let chunks: Vec<Vec<Chunk>> = pieces
        .par_iter()
        .map(|&(c, ce, read_end)| -> Result<Vec<Chunk>> {
            let mut out = Vec::new();
            for (seg_base, data) in readable_segments(p, c, read_end) {
                let span = ce.min(seg_base + data.len() as u64).saturating_sub(seg_base);
                if span == 0 {
                    continue;
                }
                if *cond == Cond::Unknown {
                    let count = count_positions(seg_base, span, data.len() as u64, spec);
                    if count > 0 {
                        let data_len = data.len() as u64;
                        out.push(Chunk { base: seg_base, span, count, data_len, data: ChunkData::Snapshot(store.put(data)?) });
                    }
                    continue;
                }
                let mut offs: Vec<u32> = Vec::new();
                let mut vals: Vec<u8> = Vec::new();
                let pos_end = seg_base + span;
                match &needle {
                    Some(n) => {
                        // Overlapping search: find_iter would skip aligned hits after an unaligned one.
                        let finder = memchr::memmem::Finder::new(n);
                        let mut from = 0usize;
                        while let Some(rel) = finder.find(&data[from..]) {
                            let i = from + rel;
                            let a = seg_base + i as u64;
                            if a >= pos_end {
                                break;
                            }
                            if a.is_multiple_of(spec.align) {
                                offs.push(i as u32);
                                vals.extend_from_slice(n);
                            }
                            from = i + 1;
                        }
                    }
                    None => {
                        for a in positions(seg_base, span, data.len() as u64, spec) {
                            let i = (a - seg_base) as usize;
                            let b = &data[i..i + spec.ty.size];
                            if test(cond, spec.ty.decode(b), None, spec.float_mode) {
                                offs.push(i as u32);
                                vals.extend_from_slice(b);
                            }
                        }
                    }
                }
                if !offs.is_empty() {
                    let count = offs.len() as u64;
                    out.push(Chunk {
                        base: seg_base,
                        span,
                        count,
                        data_len: 0,
                        data: ChunkData::Hits(store.put(pack_hits(&offs, &vals))?),
                    });
                }
            }
            Ok(out)
        })
        .collect::<Result<_>>()?;
    let chunks: Vec<Chunk> = chunks.into_iter().flatten().collect();
    let total = chunks.iter().map(|c| c.count).sum();
    Ok((Generation { chunks, total, store }, scanned))
}

/// Filters the previous generation with `cond`, re-reading current values.
pub fn next_scan(p: &dyn ProcessMemory, spec: &ScanSpec, cond: &Cond, prev: &Generation, budget: u64) -> Result<Generation> {
    let size = spec.ty.size;
    let store = Store::new(budget);
    let chunks: Vec<Option<Chunk>> = prev
        .chunks
        .par_iter()
        .map(|chunk| -> Result<Option<Chunk>> {
            let mut offs: Vec<u32> = Vec::new();
            let mut vals: Vec<u8> = Vec::new();
            let mut check = |off: u32, old: &[u8], cur: &[u8]| -> bool {
                let prev_v = spec.ty.decode(old);
                let hit = test(cond, spec.ty.decode(cur), Some(prev_v), spec.float_mode);
                if hit {
                    offs.push(off);
                    vals.extend_from_slice(cur);
                }
                hit
            };
            // For snapshot-like chunks the whole current data is kept to allow a Masked result.
            let mut dense: Option<(u64, Vec<u8>, Vec<u8>)> = None; // (npos, new bitmap, current data)
            match &chunk.data {
                ChunkData::Snapshot(blob) | ChunkData::Masked(blob) => {
                    let raw = blob.get()?;
                    let npos = count_positions(chunk.base, chunk.span, chunk.data_len, spec);
                    let (bits, old): (Option<&[u8]>, &[u8]) = match &chunk.data {
                        ChunkData::Masked(_) => {
                            let (b, d) = raw.split_at(bitmap_len(npos));
                            (Some(b), d)
                        }
                        _ => (None, &raw[..]),
                    };
                    let segs = readable_segments(p, chunk.base, chunk.base + chunk.data_len);
                    let full = matches!(segs.as_slice(), [(b, d)] if *b == chunk.base && d.len() as u64 == chunk.data_len);
                    let mut new_bits = vec![0u8; bitmap_len(npos)];
                    for (k, a) in positions(chunk.base, chunk.span, chunk.data_len, spec).enumerate() {
                        if bits.is_some_and(|b| !bit(b, k)) {
                            continue;
                        }
                        let o = (a - chunk.base) as usize;
                        let (b, d) = if full {
                            (&segs[0].0, &segs[0].1)
                        } else {
                            match segs.iter().find(|(b, d)| a >= *b && a + size as u64 <= b + d.len() as u64) {
                                Some((b, d)) => (b, d),
                                None => continue,
                            }
                        };
                        let i = (a - b) as usize;
                        if check(o as u32, &old[o..o + size], &d[i..i + size]) {
                            new_bits[k / 8] |= 1 << (k % 8);
                        }
                    }
                    if full {
                        let (_, d) = segs.into_iter().next().unwrap();
                        dense = Some((npos, new_bits, d));
                    }
                }
                ChunkData::Hits(blob) => {
                    let raw = blob.get()?;
                    let (hit_offs, old_vals) = unpack_hits(&raw, chunk.count as usize);
                    if hit_offs.len() <= INDIVIDUAL_READS {
                        let mut cur = vec![0u8; size];
                        for (k, &o) in hit_offs.iter().enumerate() {
                            if p.read(chunk.base + o as u64, &mut cur).is_ok() {
                                check(o, &old_vals[k * size..(k + 1) * size], &cur);
                            }
                        }
                    } else {
                        let last = *hit_offs.last().unwrap() as u64 + size as u64;
                        let segs = readable_segments(p, chunk.base, chunk.base + last);
                        for (k, &o) in hit_offs.iter().enumerate() {
                            let a = chunk.base + o as u64;
                            let seg = segs.iter().find(|(b, d)| a >= *b && a + size as u64 <= b + d.len() as u64);
                            if let Some((b, d)) = seg {
                                let i = (a - b) as usize;
                                check(o, &old_vals[k * size..(k + 1) * size], &d[i..i + size]);
                            }
                        }
                    }
                }
            }
            if offs.is_empty() {
                return Ok(None);
            }
            let count = offs.len() as u64;
            // Keep whichever representation is smaller.
            if let Some((npos, bits, data)) = dense {
                let masked_size = bitmap_len(npos) + data.len();
                if count as usize * (4 + size) > masked_size {
                    let data_len = data.len() as u64;
                    let mut blob = bits;
                    blob.extend_from_slice(&data);
                    return Ok(Some(Chunk { base: chunk.base, span: chunk.span, count, data_len, data: ChunkData::Masked(store.put(blob)?) }));
                }
            }
            Ok(Some(Chunk {
                base: chunk.base,
                span: chunk.span,
                count,
                data_len: 0,
                data: ChunkData::Hits(store.put(pack_hits(&offs, &vals))?),
            }))
        })
        .collect::<Result<_>>()?;
    let chunks: Vec<Chunk> = chunks.into_iter().flatten().collect();
    let total = chunks.iter().map(|c| c.count).sum();
    Ok(Generation { chunks, total, store })
}

/// Candidates `[offset, offset+limit)` in address order: (address, value from the last scan).
pub fn page(gen_: &Generation, spec: &ScanSpec, offset: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
    let size = spec.ty.size;
    let mut out = Vec::new();
    let mut skip = offset;
    for chunk in &gen_.chunks {
        if out.len() >= limit {
            break;
        }
        if skip >= chunk.count {
            skip -= chunk.count;
            continue;
        }
        match &chunk.data {
            ChunkData::Snapshot(blob) | ChunkData::Masked(blob) => {
                let raw = blob.get()?;
                let npos = count_positions(chunk.base, chunk.span, chunk.data_len, spec);
                let (bits, data): (Option<&[u8]>, &[u8]) = match &chunk.data {
                    ChunkData::Masked(_) => {
                        let (b, d) = raw.split_at(bitmap_len(npos));
                        (Some(b), d)
                    }
                    _ => (None, &raw[..]),
                };
                let candidates = positions(chunk.base, chunk.span, chunk.data_len, spec)
                    .enumerate()
                    .filter(|(k, _)| bits.is_none_or(|b| bit(b, *k)))
                    .skip(skip as usize);
                for (_, a) in candidates {
                    if out.len() >= limit {
                        break;
                    }
                    let i = (a - chunk.base) as usize;
                    out.push((a, data[i..i + size].to_vec()));
                }
            }
            ChunkData::Hits(blob) => {
                let raw = blob.get()?;
                let (offs, vals) = unpack_hits(&raw, chunk.count as usize);
                for k in (skip as usize)..offs.len() {
                    if out.len() >= limit {
                        break;
                    }
                    out.push((chunk.base + offs[k] as u64, vals[k * size..(k + 1) * size].to_vec()));
                }
            }
        }
        skip = 0;
    }
    Ok(out)
}

/// Guards against scanning a different process than the session was created for.
pub fn check_pid(session_pid: u32, current: u32, id: u64) -> Result<()> {
    if session_pid != current {
        return Err(MemError::InvalidArg(format!(
            "scan #{id} belongs to pid {session_pid}, but pid {current} is attached; start a new scan"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;
    use serde_json::json;

    fn spec(t: &str, align: u64) -> ScanSpec {
        ScanSpec { ty: ScanType::parse(t, 8).unwrap(), align, float_mode: FloatMode::Rounded }
    }

    fn cond(name: &str, v: Option<serde_json::Value>, t: &str, first: bool) -> Cond {
        Cond::parse(name, v.as_ref(), None, ScanType::parse(t, 8).unwrap(), first).unwrap()
    }

    fn addrs(g: &Generation, s: &ScanSpec) -> Vec<u64> {
        page(g, s, 0, usize::MAX).unwrap().into_iter().map(|(a, _)| a).collect()
    }

    /// 3 MiB of zeros with i32 markers at chosen places (one straddles a chunk boundary unaligned).
    fn mock() -> MockProcess {
        let mut m = MockProcess::new(Arch::X64);
        let mut mem = vec![0u8; 3 << 20];
        for (o, v) in [(0x100usize, 77i32), (0x10_0000 - 2, 77), (0x20_0008, 77), (0x2F_FFFC, 5)] {
            mem[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        m.map(0x1000_0000, mem);
        m
    }

    const R: (u64, u64) = (0x1000_0000, 0x1000_0000 + (3 << 20));

    #[test]
    fn exact_first_scan_respects_alignment_and_chunk_boundaries() {
        let m = mock();
        for budget in [u64::MAX, 0] {
            let s1 = spec("i32", 1);
            let (g, scanned) = first_scan(&m, &s1, &cond("exact", Some(json!(77)), "i32", true), &[R], budget).unwrap();
            assert_eq!(scanned, 3 << 20);
            assert_eq!(addrs(&g, &s1), [0x1000_0100, 0x1000_0000 + 0x10_0000 - 2, 0x1020_0008]);
            assert_eq!(g.disk_bytes() > 0, budget == 0);
            let s4 = spec("i32", 4);
            let (g, _) = first_scan(&m, &s4, &cond("exact", Some(json!(77)), "i32", true), &[R], budget).unwrap();
            assert_eq!(addrs(&g, &s4), [0x1000_0100, 0x1020_0008]);
        }
    }

    #[test]
    fn unknown_then_changed_and_relative_filters() {
        let m = mock();
        for budget in [u64::MAX, 0] {
            let s = spec("i32", 4);
            let (g0, _) = first_scan(&m, &s, &Cond::Unknown, &[R], budget).unwrap();
            assert_eq!(g0.total, (3 << 20) / 4);
            m.write(0x1000_0100, &80i32.to_le_bytes()).unwrap();
            m.write(0x1020_0008, &70i32.to_le_bytes()).unwrap();
            let g1 = next_scan(&m, &s, &cond("changed", None, "i32", false), &g0, budget).unwrap();
            assert_eq!(addrs(&g1, &s), [0x1000_0100, 0x1020_0008]);
            // relative conditions compare with the previous scan (80 → 83), not the first one
            m.write(0x1000_0100, &83i32.to_le_bytes()).unwrap();
            let g2 = next_scan(&m, &s, &cond("increased_by", Some(json!(3)), "i32", false), &g1, budget).unwrap();
            assert_eq!(addrs(&g2, &s), [0x1000_0100]);
            let g2b = next_scan(&m, &s, &cond("unchanged", None, "i32", false), &g1, budget).unwrap();
            assert_eq!(addrs(&g2b, &s), [0x1020_0008]);
            let page_ = page(&g1, &s, 1, 10).unwrap();
            assert_eq!(page_, [(0x1020_0008, 70i32.to_le_bytes().to_vec())]);
            // restore for the next budget iteration
            m.write(0x1000_0100, &77i32.to_le_bytes()).unwrap();
            m.write(0x1020_0008, &77i32.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn many_hits_use_bulk_reads_and_paging() {
        let m = mock();
        let s = spec("i32", 4);
        let (g, _) = first_scan(&m, &s, &cond("exact", Some(json!(0)), "i32", true), &[R], u64::MAX).unwrap();
        let zeros = g.total;
        assert!(zeros > 700_000);
        let g2 = next_scan(&m, &s, &cond("unchanged", None, "i32", false), &g, u64::MAX).unwrap();
        assert_eq!(g2.total, zeros);
        // dense results after an unknown scan are kept as bitmap + snapshot, not as an offset list
        let (u, _) = first_scan(&m, &s, &Cond::Unknown, &[R], u64::MAX).unwrap();
        let u2 = next_scan(&m, &s, &cond("unchanged", None, "i32", false), &u, u64::MAX).unwrap();
        assert!(u2.chunks.iter().all(|c| matches!(c.data, ChunkData::Masked(_))));
        assert!(u2.memory_bytes() < (3 << 20) * 11 / 10, "bitmap overhead is ~3%: {}", u2.memory_bytes());
        let u3 = next_scan(&m, &s, &cond("exact", Some(json!(77)), "i32", false), &u2, u64::MAX).unwrap();
        assert_eq!(addrs(&u3, &s), [0x1000_0100, 0x1020_0008]);
        assert!(u3.chunks.iter().all(|c| matches!(c.data, ChunkData::Hits(_))), "sparse results become hit lists");
        let uz = next_scan(&m, &s, &cond("exact", Some(json!(0)), "i32", false), &u, u64::MAX).unwrap();
        assert!(matches!(uz.chunks[0].data, ChunkData::Masked(_)));
        assert_eq!(uz.total, zeros);
        let p = page(&uz, &s, 0x40, 2).unwrap();
        assert_eq!(p[0].0, 0x1000_0104, "paging skips the cleared bit of the marker at +0x100");
        let p = page(&g2, &s, zeros - 2, 10).unwrap();
        assert_eq!(p.len(), 2);
        let g3 = next_scan(&m, &s, &cond("bigger", Some(json!(0)), "i32", false), &g2, u64::MAX).unwrap();
        assert_eq!(g3.total, 0);
    }

    #[test]
    fn unreadable_gaps_are_skipped() {
        let mut m = MockProcess::new(Arch::X86);
        m.map(0x1000, 5i32.to_le_bytes().to_vec());
        m.map(0x3000, [0u8, 0, 0, 0, 5, 0, 0, 0].to_vec());
        let s = spec("i32", 4);
        let (g, _) = first_scan(&m, &s, &cond("exact", Some(json!(5)), "i32", true), &[(0x1000, 0x3008)], u64::MAX).unwrap();
        assert_eq!(addrs(&g, &s), [0x1000, 0x3004]);
        let (g, _) = first_scan(&m, &s, &Cond::Unknown, &[(0x1000, 0x3008)], u64::MAX).unwrap();
        assert_eq!(g.total, 3);
    }
}

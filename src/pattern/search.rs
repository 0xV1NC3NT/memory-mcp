//! Parallel pattern search over process memory.

use rayon::prelude::*;

use super::Pattern;
use crate::platform::ProcessMemory;

const CHUNK: u64 = 1 << 20;

#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Match addresses in ascending order (at most `limit`).
    pub matches: Vec<u64>,
    /// More matches exist than `limit`.
    pub truncated: bool,
    pub bytes_scanned: u64,
}

/// Searches `data` (starting at `base`) and records match starts below `report_end`.
fn find_in(data: &[u8], base: u64, report_end: u64, pat: &Pattern, align: u64, cap: usize, out: &mut Vec<u64>) {
    let n = pat.len();
    if data.len() < n {
        return;
    }
    let last_start = data.len() - n;
    let mut check = |i: usize| -> bool {
        let a = base + i as u64;
        if a >= report_end {
            return false;
        }
        if (align <= 1 || a.is_multiple_of(align)) && pat.matches(&data[i..i + n]) {
            out.push(a);
            if out.len() >= cap {
                return false;
            }
        }
        true
    };
    match pat.anchor() {
        Some(k) => {
            for i in memchr::memchr_iter(pat.bytes[k], &data[k..=last_start + k]) {
                if !check(i) {
                    break;
                }
            }
        }
        None => {
            for i in 0..=last_start {
                if !check(i) {
                    break;
                }
            }
        }
    }
}

/// Scans `ranges` (non-overlapping, ascending) for `pat`. Results are deterministic:
/// the first `limit` matches by address.
pub fn scan(p: &dyn ProcessMemory, pat: &Pattern, ranges: &[(u64, u64)], alignment: u64, limit: usize) -> ScanResult {
    let overlap = pat.len() as u64 - 1;
    let mut chunks = Vec::new();
    for &(s, e) in ranges {
        let mut c = s;
        while c < e {
            let ce = (c + CHUNK).min(e);
            chunks.push((c, ce, (ce + overlap).min(e)));
            c = ce;
        }
    }
    let bytes_scanned = ranges.iter().map(|(s, e)| e - s).sum();
    let cap = limit.saturating_add(1);
    let per_chunk: Vec<Vec<u64>> = chunks
        .par_iter()
        .map(|&(start, report_end, read_end)| {
            let len = (read_end - start) as usize;
            let mut out = Vec::new();
            let mut buf = vec![0u8; len];
            if p.read(start, &mut buf).is_ok() {
                find_in(&buf, start, report_end, pat, alignment, cap, &mut out);
                return out;
            }
            // Some pages became unreadable: search each readable run separately.
            let partial = p.read_partial(start, len);
            let mut i = 0;
            while i < len && out.len() < cap {
                if partial[i].is_none() {
                    i += 1;
                    continue;
                }
                let run_start = i;
                while i < len && partial[i].is_some() {
                    i += 1;
                }
                let run: Vec<u8> = partial[run_start..i].iter().map(|b| b.unwrap()).collect();
                find_in(&run, start + run_start as u64, report_end, pat, alignment, cap - out.len(), &mut out);
            }
            out
        })
        .collect();
    let mut matches: Vec<u64> = per_chunk.into_iter().flatten().collect();
    let truncated = matches.len() > limit;
    matches.truncate(limit);
    ScanResult { matches, truncated, bytes_scanned }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    #[test]
    fn finds_across_chunk_boundaries_with_alignment_and_limit() {
        let mut m = MockProcess::new(Arch::X64);
        let size = (CHUNK * 2 + 0x100) as usize;
        let mut mem = vec![0u8; size];
        let pat = Pattern::parse("DE AD ?? EF", None).unwrap();
        // one match straddling the first chunk boundary, one aligned, one at the very end
        let spots = [CHUNK as usize - 2, 0x1000, size - 4];
        for &s in &spots {
            mem[s..s + 4].copy_from_slice(&[0xDE, 0xAD, 0x55, 0xEF]);
        }
        m.map(0x10_0000, mem);
        let ranges = [(0x10_0000u64, 0x10_0000 + size as u64)];
        let r = scan(&m, &pat, &ranges, 1, 100);
        let mut want: Vec<u64> = spots.iter().map(|&s| 0x10_0000 + s as u64).collect();
        want.sort();
        assert_eq!(r.matches, want);
        assert!(!r.truncated);
        assert_eq!(r.bytes_scanned, size as u64);

        let r = scan(&m, &pat, &ranges, 0x1000, 100);
        assert_eq!(r.matches, [0x10_1000]);

        let r = scan(&m, &pat, &ranges, 1, 2);
        assert_eq!(r.matches, want[..2]);
        assert!(r.truncated);
    }

    #[test]
    fn wildcard_only_anchor_and_partial_reads() {
        let mut m = MockProcess::new(Arch::X86);
        m.map(0x1000, vec![0x00, 0x4C, 0x8B, 0xA5, 0x00]);
        m.map(0x2000, vec![0x41, 0x8B, 0x15]);
        let pat = Pattern::parse("4? 8B ?5", None).unwrap();
        let r = scan(&m, &pat, &[(0x1000, 0x1005), (0x2000, 0x2003)], 1, 10);
        assert_eq!(r.matches, [0x1001, 0x2000]);
        // a range including unmapped bytes falls back to readable runs
        let r = scan(&m, &pat, &[(0x1000, 0x2003)], 1, 10);
        assert_eq!(r.matches, [0x1001, 0x2000]);
    }
}

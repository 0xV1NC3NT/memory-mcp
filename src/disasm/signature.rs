//! Signature (AOB pattern) generation for code that survives rebuilds and ASLR: bytes that encode
//! addresses (RIP-relative / absolute displacements, relative branch targets, address-like
//! immediates) are wildcarded; the pattern grows instruction by instruction until it is unique.

use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, Instruction, OpKind, Register};

use crate::error::{MemError, Result};
use crate::pattern::{self, Pattern};
use crate::platform::ProcessMemory;

#[derive(Debug, Clone, Copy)]
pub struct SigOptions {
    pub min_len: usize,
    pub max_len: usize,
    /// Also wildcard displacements of `[reg+disp]` (struct offsets). Default false.
    pub wildcard_offsets: bool,
    /// Wildcard every immediate, not only address-like ones. Default false.
    pub wildcard_immediates: bool,
    /// How many instructions before the target may be tried as the signature start.
    pub max_back: usize,
}

impl Default for SigOptions {
    fn default() -> Self {
        Self { min_len: 8, max_len: 64, wildcard_offsets: false, wildcard_immediates: false, max_back: 8 }
    }
}

/// How the data referenced by an instruction can be computed from its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRef {
    /// `rip(insn, disp_offset, insn_len)`
    Rip { disp_offset: u32, insn_len: u32 },
    /// `abs32(insn, disp_offset)`
    Abs32 { disp_offset: u32 },
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub pattern: Pattern,
    /// Address where the pattern matches.
    pub start: u64,
    /// Decoded instructions covered by the pattern.
    pub instructions: Vec<Instruction>,
}

fn decode_at(bitness: u32, bytes: &[u8], ip: u64) -> Option<(Instruction, ConstantOffsets)> {
    let mut dec = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let i = dec.decode();
    if i.is_invalid() {
        return None;
    }
    let co = dec.get_constant_offsets(&i);
    Some((i, co))
}

fn in_images(images: &[(u64, u64)], v: u64) -> bool {
    let k = images.partition_point(|r| r.0 <= v);
    k > 0 && v < images[k - 1].1
}

/// Instruction bytes and nibble masks (0xFF keep, 0x00 wildcard).
pub fn mask_instruction(i: &Instruction, co: &ConstantOffsets, bytes: &[u8], images: &[(u64, u64)], opts: &SigOptions) -> (Vec<u8>, Vec<u8>) {
    let mut mask = vec![0xFFu8; bytes.len()];
    let mut wild = |off: usize, size: usize| {
        for m in mask.iter_mut().skip(off).take(size) {
            *m = 0;
        }
    };
    if co.has_displacement() {
        let absolute = i.is_ip_rel_memory_operand()
            || (i.memory_base() == Register::None && i.memory_index() == Register::None)
            || (co.displacement_size() >= 4 && in_images(images, i.memory_displacement64()));
        if absolute || opts.wildcard_offsets {
            wild(co.displacement_offset(), co.displacement_size());
        }
    }
    let is_branch = (0..i.op_count()).any(|n| {
        matches!(i.op_kind(n), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 | OpKind::FarBranch16 | OpKind::FarBranch32)
    });
    if co.has_immediate() {
        let looks_like_address = (0..i.op_count()).any(|n| {
            matches!(i.op_kind(n), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64)
                && in_images(images, i.immediate(n))
        });
        if is_branch || looks_like_address || opts.wildcard_immediates {
            wild(co.immediate_offset(), co.immediate_size());
        }
    }
    if co.has_immediate2() && opts.wildcard_immediates {
        wild(co.immediate_offset2(), co.immediate_size2());
    }
    let masked = bytes.iter().zip(&mask).map(|(b, m)| b & m).collect();
    (masked, mask)
}

/// Data reference of an instruction with a statically known memory operand.
pub fn data_ref(i: &Instruction, co: &ConstantOffsets) -> Option<DataRef> {
    if !co.has_displacement() || co.displacement_size() != 4 {
        return None;
    }
    if i.is_ip_rel_memory_operand() {
        return Some(DataRef::Rip { disp_offset: co.displacement_offset() as u32, insn_len: i.len() as u32 });
    }
    if i.memory_base() == Register::None && i.memory_index() == Register::None {
        return Some(DataRef::Abs32 { disp_offset: co.displacement_offset() as u32 });
    }
    None
}

/// Decodes the instruction at `ip` with its constant offsets.
pub fn instruction_at(p: &dyn ProcessMemory, ip: u64) -> Result<(Instruction, ConstantOffsets)> {
    let bitness = (p.pointer_size() * 8) as u32;
    let bytes: Vec<u8> = p.read_partial(ip, 15).into_iter().map_while(|b| b).collect();
    decode_at(bitness, &bytes, ip).ok_or_else(|| MemError::InvalidArg(format!("no valid instruction at {ip:#x}")))
}

/// Grows a pattern from `start` until it covers the instruction at `target` and matches exactly
/// once in `ranges` (at `start`).
fn grow(p: &dyn ProcessMemory, start: u64, target: u64, ranges: &[(u64, u64)], images: &[(u64, u64)], opts: &SigOptions) -> Option<Signature> {
    let bitness = (p.pointer_size() * 8) as u32;
    let window: Vec<u8> = p.read_partial(start, opts.max_len + 15).into_iter().map_while(|b| b).collect();
    let mut bytes = Vec::new();
    let mut masks = Vec::new();
    let mut insns = Vec::new();
    let mut off = 0usize;
    while bytes.len() < opts.max_len && off < window.len() {
        let (i, co) = decode_at(bitness, &window[off..], start + off as u64)?;
        let (b, m) = mask_instruction(&i, &co, &window[off..off + i.len()], images, opts);
        bytes.extend(b);
        masks.extend(m);
        insns.push(i);
        off += i.len();
        if bytes.len() < opts.min_len || start + (off as u64) <= target {
            continue;
        }
        // trailing wildcards add nothing
        let keep = masks.iter().rposition(|&m| m != 0).map(|k| k + 1).unwrap_or(0);
        if keep == 0 {
            continue;
        }
        let pat = Pattern { bytes: bytes[..keep].to_vec(), masks: masks[..keep].to_vec() };
        let r = pattern::scan(p, &pat, ranges, 1, 2);
        if r.matches == [start] {
            return Some(Signature { pattern: pat, start, instructions: insns });
        }
        if r.matches.is_empty() {
            // the start itself must match; unreadable code or a changed page
            return None;
        }
    }
    None
}

/// Generates the shortest unique signature that covers `target`, starting at the target itself or,
/// failing that, at one of the `earlier` instruction starts (nearest first).
pub fn generate(
    p: &dyn ProcessMemory,
    target: u64,
    earlier: &[u64],
    ranges: &[(u64, u64)],
    images: &[(u64, u64)],
    opts: &SigOptions,
) -> Result<Signature> {
    if let Some(s) = grow(p, target, target, ranges, images, opts) {
        return Ok(s);
    }
    let mut best: Option<Signature> = None;
    for &s in earlier.iter().filter(|&&s| s < target).rev().take(opts.max_back) {
        if let Some(sig) = grow(p, s, target, ranges, images, opts)
            && best.as_ref().is_none_or(|b| sig.pattern.len() < b.pattern.len())
        {
            best = Some(sig);
        }
    }
    best.ok_or_else(|| {
        MemError::InvalidArg(format!(
            "no unique signature of at most {} bytes covers {target:#x}; raise max_len or enable wildcard options less aggressively",
            opts.max_len
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    const BASE: u64 = 0x1_4000_0000;

    fn opts() -> SigOptions {
        SigOptions { min_len: 4, ..Default::default() }
    }

    /// Two copies of the same function body; the second differs after the first 2 instructions.
    fn mock() -> MockProcess {
        let mut m = MockProcess::new(Arch::X64);
        let mut img = vec![0xCCu8; 0x2000];
        img[..2].copy_from_slice(b"MZ");
        // A @0x100: mov eax,[rip+X]; dec eax; mov [rip+X],eax; ret          (X = 0x1800)
        // B @0x200: mov eax,[rip+Y]; dec eax; add eax, 5; ret               (Y = 0x1900)
        let enc = |at: u32, op: &[u8], len: u32, target: u32| {
            let mut v = op.to_vec();
            v.extend(((target as i64 - (at + len) as i64) as i32).to_le_bytes());
            v
        };
        let mut a = enc(0x100, &[0x8B, 0x05], 6, 0x1800);
        a.extend([0xFF, 0xC8]);
        a.extend(enc(0x108, &[0x89, 0x05], 6, 0x1800));
        a.push(0xC3);
        let mut b = enc(0x200, &[0x8B, 0x05], 6, 0x1900);
        b.extend([0xFF, 0xC8, 0x83, 0xC0, 0x05, 0xC3]);
        img[0x100..0x100 + a.len()].copy_from_slice(&a);
        img[0x200..0x200 + b.len()].copy_from_slice(&b);
        m.add_module("game.exe", BASE, img);
        m
    }

    #[test]
    fn masks_addresses_but_keeps_opcodes_and_small_offsets() {
        let m = mock();
        let images = [(BASE, BASE + 0x2000)];
        let (i, co) = instruction_at(&m, BASE + 0x100).unwrap();
        let (b, mask) = mask_instruction(&i, &co, &[0x8B, 0x05, 0xFA, 0x16, 0, 0], &images, &opts());
        assert_eq!(mask, [0xFF, 0xFF, 0, 0, 0, 0]);
        assert_eq!(b[..2], [0x8B, 0x05]);
        assert_eq!(data_ref(&i, &co), Some(DataRef::Rip { disp_offset: 2, insn_len: 6 }));
        // mov eax, [rcx+0x10]: struct offset kept unless wildcard_offsets
        let code = [0x8B, 0x41, 0x10];
        // constant offsets come from the decoder that decoded the instruction
        let mut dec = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);
        let i = dec.decode();
        let co = dec.get_constant_offsets(&i);
        assert_eq!(mask_instruction(&i, &co, &code, &images, &opts()).1, [0xFF, 0xFF, 0xFF]);
        let all = SigOptions { wildcard_offsets: true, ..opts() };
        assert_eq!(mask_instruction(&i, &co, &code, &images, &all).1, [0xFF, 0xFF, 0x00]);
        assert_eq!(data_ref(&i, &co), None);
    }

    #[test]
    fn grows_until_unique_and_falls_back_to_earlier_starts() {
        let m = mock();
        let images = [(BASE, BASE + 0x2000)];
        let ranges = [(BASE, BASE + 0x2000)];
        // At A, "8B 05 ?? ?? ?? ?? FF C8" also matches B → must include A's third instruction.
        let s = generate(&m, BASE + 0x100, &[], &ranges, &images, &opts()).unwrap();
        assert_eq!(s.start, BASE + 0x100);
        assert_eq!(s.pattern.display(), "8B 05 ?? ?? ?? ?? FF C8 89 05");
        assert_eq!(s.instructions.len(), 3);
        // A's ret alone is never unique → start earlier
        let s = generate(&m, BASE + 0x10E, &[BASE + 0x100, BASE + 0x106, BASE + 0x108], &ranges, &images, &opts()).unwrap();
        assert!(s.start < BASE + 0x10E, "{s:?}");
        assert!(s.instructions.iter().any(|i| i.ip() == BASE + 0x10E), "the decoded run includes the target");
        assert_eq!(s.pattern.display(), "89 05 ?? ?? ?? ?? C3", "nearest unique start, extended through the target");
        let tight = SigOptions { max_len: 3, max_back: 0, ..opts() };
        assert!(generate(&m, BASE + 0x10E, &[], &ranges, &images, &tight).is_err());
    }
}

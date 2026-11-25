//! Cross-references: which instructions of a module call, jump to, read, write or take the
//! address of a given address. Built lazily per module by a linear sweep of its code sections
//! that re-synchronizes at known function starts (so data inside `.text` cannot desync it).

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, OpAccess, OpKind};
use rayon::prelude::*;
use serde::Serialize;

use super::functions::ModuleCode;
use super::{branch_target, static_memory_address};
use crate::platform::{Module, ProcessMemory};

const CHUNK: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    Call,
    Jump,
    Read,
    Write,
    ReadWrite,
    /// The address is taken (`lea`, an immediate operand) without accessing memory.
    Address,
}

impl XrefKind {
    /// Whether this kind passes a user filter (`read` includes read_write, etc.).
    pub fn matches(self, filter: &str) -> bool {
        match filter {
            "" | "any" => true,
            "call" => self == XrefKind::Call,
            "jump" => self == XrefKind::Jump,
            "read" => matches!(self, XrefKind::Read | XrefKind::ReadWrite),
            "write" => matches!(self, XrefKind::Write | XrefKind::ReadWrite),
            "access" => matches!(self, XrefKind::Read | XrefKind::Write | XrefKind::ReadWrite),
            "address" => self == XrefKind::Address,
            "code" => matches!(self, XrefKind::Call | XrefKind::Jump),
            _ => false,
        }
    }
}

pub const KIND_FILTERS: &str = "any, call, jump, code (call+jump), read, write, access (read+write), address";

/// One reference, compact: target address, source offset from the module base, kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Xref {
    pub to: u64,
    pub from_off: u32,
    pub kind: XrefKind,
}

pub struct XrefIndex {
    pub base: u64,
    pub refs: Vec<Xref>,
    pub instructions: u64,
}

impl XrefIndex {
    /// References whose target lies in `[lo, hi)`.
    pub fn query(&self, lo: u64, hi: u64) -> &[Xref] {
        let a = self.refs.partition_point(|x| x.to < lo);
        let b = self.refs.partition_point(|x| x.to < hi);
        &self.refs[a..b]
    }
}

fn access_kind(a: OpAccess) -> Option<XrefKind> {
    match a {
        OpAccess::Read | OpAccess::CondRead => Some(XrefKind::Read),
        OpAccess::Write | OpAccess::CondWrite => Some(XrefKind::Write),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some(XrefKind::ReadWrite),
        OpAccess::NoMemAccess => Some(XrefKind::Address),
        OpAccess::None => None,
    }
}

/// References made by one instruction: (target, kind).
pub fn instruction_refs(i: &Instruction, info: &mut InstructionInfoFactory, images: &[(u64, u64)]) -> Vec<(u64, XrefKind)> {
    let mut out = Vec::new();
    match i.flow_control() {
        FlowControl::Call => out.extend(branch_target(i).map(|t| (t, XrefKind::Call))),
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            out.extend(branch_target(i).map(|t| (t, XrefKind::Jump)))
        }
        _ => {}
    }
    if let Some(m) = static_memory_address(i) {
        let ii = info.info(i);
        let access = (0..i.op_count()).find(|&n| i.op_kind(n) == OpKind::Memory).map(|n| ii.op_access(n));
        if let Some(k) = access.and_then(access_kind) {
            out.push((m, k));
        }
    }
    let in_image = |v: u64| {
        let k = images.partition_point(|r| r.0 <= v);
        k > 0 && v < images[k - 1].1
    };
    for n in 0..i.op_count() {
        if matches!(i.op_kind(n), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64) {
            let v = i.immediate(n);
            if v >= 0x10000 && in_image(v) {
                out.push((v, XrefKind::Address));
            }
        }
    }
    out
}

/// Builds the index for `code`'s module. `modules` (all loaded modules) decide which immediates
/// look like addresses.
pub fn build(p: &dyn ProcessMemory, code: &ModuleCode, modules: &[Module]) -> XrefIndex {
    let bitness = (p.pointer_size() * 8) as u32;
    let base = code.module.base;
    let mut images: Vec<(u64, u64)> = modules.iter().map(|m| (m.base, m.base + m.size)).collect();
    images.sort_unstable();
    let starts: Vec<u64> = code.starts.iter().map(|s| s.0).chain(code.pdata.iter().map(|e| e.begin)).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let mut chunks = Vec::new();
    for &(s, e) in &code.exec_ranges {
        let mut c = s;
        while c < e {
            let ce = (c + CHUNK).min(e);
            chunks.push((c, ce, (ce + 16).min(e)));
            c = ce;
        }
    }
    let parts: Vec<(Vec<Xref>, u64)> = chunks
        .par_iter()
        .map(|&(c, ce, read_end)| {
            let data: Vec<u8> = p.read_partial(c, (read_end - c) as usize).into_iter().map(|b| b.unwrap_or(0xCC)).collect();
            let mut info = InstructionInfoFactory::new();
            let mut out = Vec::new();
            let mut count = 0u64;
            // start at the first known function start in this chunk (if any)
            let mut si = starts.partition_point(|&s| s < c);
            let mut ip = match starts.get(si) {
                Some(&s) if s < ce => s,
                _ => c,
            };
            let mut dec = Decoder::with_ip(bitness, &data, c, DecoderOptions::NONE);
            let mut i = Instruction::default();
            while ip < ce {
                let off = (ip - c) as usize;
                if dec.set_position(off).is_err() {
                    break;
                }
                dec.set_ip(ip);
                dec.decode_out(&mut i);
                if i.is_invalid() {
                    ip += 1;
                    continue;
                }
                let next = ip + i.len() as u64;
                while si < starts.len() && starts[si] <= ip {
                    si += 1;
                }
                // An instruction running over a known function start is a desync: restart there.
                if let Some(&s) = starts.get(si)
                    && s < next
                {
                    ip = s;
                    continue;
                }
                count += 1;
                for (to, kind) in instruction_refs(&i, &mut info, &images) {
                    out.push(Xref { to, from_off: (ip - base) as u32, kind });
                }
                ip = next;
            }
            (out, count)
        })
        .collect();
    let instructions = parts.iter().map(|p| p.1).sum();
    let mut refs: Vec<Xref> = parts.into_iter().flat_map(|p| p.0).collect();
    refs.par_sort_unstable();
    refs.dedup();
    XrefIndex { base, refs, instructions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::functions::build_module_code;
    use crate::disasm::functions::tests::{BASE, mock_x64};

    #[test]
    fn index_of_mock_module() {
        let (m, module) = mock_x64();
        let code = build_module_code(&m, &module).unwrap();
        let idx = build(&m, &code, std::slice::from_ref(&module));
        // f1 calls f2; f3 jumps to its cold fragment; f4 jumps inside itself
        let to_f2 = idx.query(BASE + 0x1040, BASE + 0x1041);
        assert_eq!(to_f2.len(), 1);
        assert_eq!((to_f2[0].from_off, to_f2[0].kind), (0x1005, XrefKind::Call));
        let to_cold = idx.query(BASE + 0x1800, BASE + 0x1801);
        assert_eq!((to_cold[0].from_off, to_cold[0].kind), (0x1082, XrefKind::Jump));
        assert!(idx.instructions >= 15);
    }

    #[test]
    fn classifies_memory_access_and_resyncs() {
        use crate::platform::Arch;
        use crate::platform::mock::MockProcess;
        let mut m = MockProcess::new(Arch::X64);
        let mut img = crate::disasm::functions::tests::image_x64();
        // replace f4 (0x10C0) with: mov eax,[rip+X] ; mov [rip+X],eax ; add [rip+X],eax ; lea rcx,[rip+X] ; ret
        // X = 0x2800 (data); each instruction is 6 or 7 bytes
        let code: Vec<u8> = {
            let mut v = Vec::new();
            let mut at = 0x10C0u32;
            for (op, len) in [(&[0x8B, 0x05][..], 6u32), (&[0x89, 0x05][..], 6), (&[0x01, 0x05][..], 6), (&[0x48, 0x8D, 0x0D][..], 7)] {
                let disp = 0x2800i64 - (at + len) as i64;
                v.extend_from_slice(op);
                v.extend_from_slice(&(disp as i32).to_le_bytes());
                at += len;
            }
            v.push(0xC3);
            v
        };
        img[0x10C0..0x10C0 + code.len()].copy_from_slice(&code);
        // garbage bytes right before f3 (0x1080) that would swallow its first instruction:
        // 0x107E: 48 B8 = mov rax, imm64 (10 bytes) running over 0x1080
        img[0x107E] = 0x48;
        img[0x107F] = 0xB8;
        m.add_module("game.exe", BASE, img);
        let module = m.modules().unwrap()[0].clone();
        let mc = build_module_code(&m, &module).unwrap();
        let idx = build(&m, &mc, std::slice::from_ref(&module));
        let kinds: Vec<XrefKind> = idx.query(BASE + 0x2800, BASE + 0x2801).iter().map(|x| x.kind).collect();
        assert_eq!(kinds.len(), 4);
        for k in [XrefKind::Read, XrefKind::Write, XrefKind::ReadWrite, XrefKind::Address] {
            assert!(kinds.contains(&k), "{k:?} in {kinds:?}");
        }
        // f3's jz to the cold fragment is still decoded despite the garbage before it
        assert_eq!(idx.query(BASE + 0x1800, BASE + 0x1801).len(), 1);
        assert!(XrefKind::ReadWrite.matches("write") && XrefKind::ReadWrite.matches("read"));
        assert!(!XrefKind::Address.matches("access"));
    }
}

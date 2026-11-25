//! Disassembly of process memory with iced-x86.

pub mod functions;
pub mod signature;
pub mod symbols;
pub mod xrefs;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, GasFormatter, Instruction, IntelFormatter, MasmFormatter,
    NasmFormatter, OpKind, Register,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{MemError, Result};
use crate::format;
use crate::platform::ProcessMemory;
use symbols::{Resolver, SymbolTable};

pub const MAX_INSN_LEN: usize = 15;
pub const MAX_COUNT: usize = 2000;
pub const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    Intel,
    Masm,
    Nasm,
    Gas,
}

impl Syntax {
    pub fn parse(s: Option<&str>) -> Result<Self> {
        match s.map(str::to_ascii_lowercase).as_deref() {
            None | Some("") | Some("intel") => Ok(Syntax::Intel),
            Some("masm") => Ok(Syntax::Masm),
            Some("nasm") => Ok(Syntax::Nasm),
            Some("gas") | Some("att") | Some("at&t") => Ok(Syntax::Gas),
            Some(o) => Err(MemError::InvalidArg(format!("unknown syntax '{o}' (intel|masm|nasm|att)"))),
        }
    }
}

/// Creates a formatter with consistent options and the given symbol table.
pub fn formatter(syntax: Syntax, table: SymbolTable, labels: Arc<HashMap<u64, String>>) -> Box<dyn Formatter> {
    let resolver: Option<Box<dyn iced_x86::SymbolResolver>> = Some(Box::new(Resolver { table, labels }));
    let mut f: Box<dyn Formatter> = match syntax {
        Syntax::Intel => Box::new(IntelFormatter::with_options(resolver, None)),
        Syntax::Masm => Box::new(MasmFormatter::with_options(resolver, None)),
        Syntax::Nasm => Box::new(NasmFormatter::with_options(resolver, None)),
        Syntax::Gas => Box::new(GasFormatter::with_options(resolver, None)),
    };
    let o = f.options_mut();
    o.set_space_after_operand_separator(true);
    // Show the absolute (symbolized) target of RIP-relative operands, not `rip+disp`.
    o.set_rip_relative_addresses(false);
    o.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    o.set_uppercase_hex(true);
    o.set_branch_leading_zeros(false);
    if syntax != Syntax::Masm {
        o.set_hex_prefix("0x");
        o.set_hex_suffix("");
    }
    f
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Code,
    /// Bytes that do not decode to a valid instruction (shown as `db`).
    Invalid,
    /// Memory that could not be read; the listing stops here.
    Unreadable,
}

#[derive(Debug, Clone)]
pub struct Line {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub kind: LineKind,
    pub instr: Option<Instruction>,
}

#[derive(Debug, Clone, Copy)]
pub struct DecodeOptions {
    pub count: usize,
    pub max_bytes: usize,
    pub until_ret: bool,
}

/// Decodes from `start`: at most `count` lines within `max_bytes`; stops at unreadable memory
/// and (optionally) after the first `ret`.
pub fn decode(p: &dyn ProcessMemory, start: u64, opts: &DecodeOptions) -> Vec<Line> {
    let bitness = (p.pointer_size() * 8) as u32;
    let want = opts.max_bytes.min(MAX_BYTES) + MAX_INSN_LEN;
    let raw = p.read_partial(start, want);
    let readable = raw.iter().take_while(|b| b.is_some()).count();
    let bytes: Vec<u8> = raw[..readable].iter().map(|b| b.unwrap()).collect();
    let mut lines = Vec::new();
    let mut off = 0usize;
    while lines.len() < opts.count && off < opts.max_bytes.min(MAX_BYTES) {
        let ip = start + off as u64;
        if off >= readable {
            lines.push(Line { address: ip, bytes: Vec::new(), kind: LineKind::Unreadable, instr: None });
            break;
        }
        let mut dec = Decoder::with_ip(bitness, &bytes[off..], ip, DecoderOptions::NONE);
        let instr = dec.decode();
        if instr.is_invalid() {
            // An instruction cut short by unreadable memory is not "invalid".
            if readable - off < MAX_INSN_LEN && readable < raw.len() {
                lines.push(Line { address: ip, bytes: Vec::new(), kind: LineKind::Unreadable, instr: None });
                break;
            }
            lines.push(Line { address: ip, bytes: vec![bytes[off]], kind: LineKind::Invalid, instr: None });
            off += 1;
            continue;
        }
        let len = instr.len();
        let is_ret = instr.flow_control() == FlowControl::Return;
        lines.push(Line { address: ip, bytes: bytes[off..off + len].to_vec(), kind: LineKind::Code, instr: Some(instr) });
        off += len;
        if opts.until_ret && is_ret {
            break;
        }
    }
    lines
}

pub fn flow_name(f: FlowControl) -> &'static str {
    match f {
        FlowControl::Next => "next",
        FlowControl::UnconditionalBranch => "jump",
        FlowControl::IndirectBranch => "indirect_jump",
        FlowControl::ConditionalBranch => "conditional_jump",
        FlowControl::Return => "ret",
        FlowControl::Call => "call",
        FlowControl::IndirectCall => "indirect_call",
        FlowControl::Interrupt => "interrupt",
        FlowControl::XbeginXabortXend => "transaction",
        FlowControl::Exception => "exception",
    }
}

/// Direct branch/call target.
pub fn branch_target(i: &Instruction) -> Option<u64> {
    match i.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call
        | FlowControl::XbeginXabortXend => (0..i.op_count())
            .any(|n| matches!(i.op_kind(n), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64))
            .then(|| i.near_branch_target()),
        _ => None,
    }
}

/// Absolute address of the memory operand when it is known statically (RIP-relative or
/// absolute displacement without base/index registers).
pub fn static_memory_address(i: &Instruction) -> Option<u64> {
    if !(0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory) {
        return None;
    }
    if i.is_ip_rel_memory_operand() {
        return Some(i.ip_rel_memory_address());
    }
    if i.memory_base() == Register::None && i.memory_index() == Register::None && i.memory_displacement64() != 0 {
        return Some(i.memory_displacement64());
    }
    None
}

/// Addresses whose symbols a listing may need (line addresses, targets, memory operands and,
/// for indirect calls/jumps, the pointers stored there).
pub fn referenced_addresses(p: &dyn ProcessMemory, lines: &[Line]) -> Vec<u64> {
    let mut out = Vec::new();
    for l in lines {
        out.push(l.address);
        let Some(i) = &l.instr else { continue };
        out.extend(branch_target(i));
        if let Some(m) = static_memory_address(i) {
            out.push(m);
            if matches!(i.flow_control(), FlowControl::IndirectCall | FlowControl::IndirectBranch)
                && let Ok(ptr) = p.read_u64_ptr(m)
            {
                out.push(ptr);
            }
        }
        for n in 0..i.op_count() {
            if matches!(i.op_kind(n), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64) {
                out.push(i.immediate(n));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub address: String,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rendered {
    pub address: String,
    pub symbol: Option<String>,
    /// Set when the line starts at an exported symbol (e.g. `kernel32.dll!Sleep`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub bytes: String,
    pub text: String,
    pub flow: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Target>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Target>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Formats decoded lines; `labels` are local labels (e.g. `loc_1234`) used for branch targets and
/// shown as label lines.
pub fn render(
    p: &dyn ProcessMemory,
    lines: &[Line],
    table: &SymbolTable,
    syntax: Syntax,
    labels: &HashMap<u64, String>,
) -> Vec<Rendered> {
    let ps = p.pointer_size();
    let mut fmt = formatter(syntax, table.clone(), Arc::new(labels.clone()));
    let target = |a: u64| Target { address: format::addr(a, ps), symbol: table.name(a) };
    lines
        .iter()
        .map(|l| {
            let base = Rendered {
                address: format::addr(l.address, ps),
                symbol: table.name(l.address),
                label: labels.get(&l.address).cloned().or_else(|| table.export_at(l.address)),
                bytes: crate::value::hex_bytes(&l.bytes),
                text: String::new(),
                flow: "next",
                target: None,
                memory: None,
                comment: None,
            };
            match (&l.kind, &l.instr) {
                (LineKind::Code, Some(i)) => {
                    let mut text = String::new();
                    fmt.format(i, &mut text);
                    let mem = static_memory_address(i);
                    let mut comment = None;
                    if let Some(m) = mem
                        && matches!(i.flow_control(), FlowControl::IndirectCall | FlowControl::IndirectBranch)
                        && let Ok(ptr) = p.read_u64_ptr(m)
                    {
                        comment = Some(format!("-> {}", table.name(ptr).unwrap_or_else(|| format::addr(ptr, ps))));
                    }
                    Rendered {
                        text,
                        flow: flow_name(i.flow_control()),
                        target: branch_target(i).map(target),
                        memory: mem.map(target),
                        comment,
                        ..base
                    }
                }
                (LineKind::Invalid, _) => Rendered {
                    text: format!("db 0x{:02X}", l.bytes[0]),
                    flow: "invalid",
                    comment: Some("invalid instruction".into()),
                    ..base
                },
                _ => Rendered { text: "??".into(), flow: "unreadable", comment: Some(p.explain_unreadable(l.address)), ..base },
            }
        })
        .collect()
}

/// Compact one-line-per-instruction listing.
pub fn listing(rendered: &[Rendered], show_bytes: bool) -> Vec<String> {
    let bytes_width = if show_bytes { rendered.iter().map(|r| r.bytes.len()).max().unwrap_or(0).min(44) } else { 0 };
    let mut out = Vec::with_capacity(rendered.len());
    for r in rendered {
        if let Some(l) = &r.label {
            out.push(format!("{l}:"));
        }
        let loc = r.symbol.clone().unwrap_or_else(|| r.address.clone());
        let mut line = if show_bytes {
            format!("{loc}  {:<bytes_width$}  {}", r.bytes, r.text)
        } else {
            format!("{loc}  {}", r.text)
        };
        if let Some(c) = &r.comment {
            line.push_str("  ; ");
            line.push_str(c);
        }
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;
    use symbols::SymbolCache;

    const GAME: u64 = 0x1_4000_0000;
    const CODE: u64 = GAME + 0x1000;

    /// game.exe image at GAME (code at +0x1000, data at +0x2000) and other.dll with exports.
    fn mock_x64() -> MockProcess {
        let mut m = MockProcess::new(Arch::X64);
        let mut img = vec![0u8; 0x3000];
        img[..2].copy_from_slice(b"MZ");
        // mov rax, qword ptr [rip+0xFF9] (→ GAME+0x2000)
        let mut code = vec![0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00];
        // call qword ptr [rip+0xFFB] (→ GAME+0x2008, IAT slot) — at CODE+7, len 6, next = CODE+0xD
        code.extend([0xFF, 0x15, 0xFB, 0x0F, 0x00, 0x00]);
        // call rel32 → CODE+0x100   (at CODE+0xD, len 5, next CODE+0x12; disp = 0xEE)
        code.extend([0xE8, 0xEE, 0x00, 0x00, 0x00]);
        // je short +2 ; nop ; nop ; ret ; (invalid) 0x06 in x64 ; int3
        code.extend([0x74, 0x02, 0x90, 0x90, 0xC3, 0x06, 0xCC]);
        img[0x1000..0x1000 + code.len()].copy_from_slice(&code);
        m.add_module("game.exe", GAME, img);
        let dll = 0x1_8000_0000u64;
        m.add_module("other.dll", dll, testpe::image(true, "X.Y"));
        m.put_ptr(GAME + 0x2008, dll + 0x1000); // IAT → other.dll!Alpha
        m
    }

    fn opts(count: usize) -> DecodeOptions {
        DecodeOptions { count, max_bytes: 4096, until_ret: false }
    }

    #[test]
    fn decodes_annotates_and_stops() {
        let m = mock_x64();
        let lines = decode(&m, CODE, &DecodeOptions { until_ret: true, ..opts(100) });
        assert_eq!(lines.len(), 7, "stops after ret");
        let mut cache = SymbolCache::default();
        let table = cache.table_for(&m, &referenced_addresses(&m, &lines));
        let r = render(&m, &lines, &table, Syntax::Intel, &HashMap::new());
        assert_eq!(r[0].text, "mov rax, qword ptr [game.exe+0x2000]");
        assert_eq!(r[0].memory.as_ref().unwrap().symbol.as_deref(), Some("game.exe+0x2000"));
        assert_eq!(r[0].symbol.as_deref(), Some("game.exe+0x1000"));
        assert_eq!(r[1].flow, "indirect_call");
        assert_eq!(r[1].comment.as_deref(), Some("-> other.dll!Alpha"));
        assert_eq!(r[2].text, "call game.exe+0x1100");
        assert_eq!(r[2].target.as_ref().unwrap().address, "0x0000000140001100");
        assert_eq!(r[3].flow, "conditional_jump");
        assert_eq!(r[6].flow, "ret");
        let lst = listing(&r, true);
        assert!(lst[0].starts_with("game.exe+0x1000  48 8B 05 F9 0F 00 00"), "{lst:?}");
        assert!(lst[1].ends_with("; -> other.dll!Alpha"), "{lst:?}");
    }

    #[test]
    fn invalid_and_unreadable() {
        let m = mock_x64();
        // from the invalid byte: db 0x06, int3, then zeros (add [rax], al)...
        let lines = decode(&m, CODE + 0x17, &opts(3));
        assert_eq!(lines[0].kind, LineKind::Invalid);
        assert_eq!(lines[1].instr.unwrap().flow_control(), FlowControl::Interrupt);
        // near the end of the image the listing stops at unmapped memory
        let lines = decode(&m, GAME + 0x2FFE, &opts(10));
        assert_eq!(lines.last().unwrap().kind, LineKind::Unreadable);
        let table = SymbolCache::default().table_for(&m, &[]);
        let r = render(&m, &lines, &table, Syntax::Intel, &HashMap::new());
        assert_eq!(r.last().unwrap().flow, "unreadable");
    }

    #[test]
    fn exports_label_lines_and_syntaxes() {
        let m = mock_x64();
        let lines = decode(&m, CODE, &opts(1));
        let table = SymbolCache::default().table_for(&m, &referenced_addresses(&m, &lines));
        let text = |s| render(&m, &lines, &table, s, &HashMap::new())[0].text.clone();
        assert_eq!(text(Syntax::Intel), "mov rax, qword ptr [game.exe+0x2000]");
        // symbol text comes from our resolver, so it is the same in every syntax
        assert_eq!(text(Syntax::Masm), "mov rax, qword ptr [game.exe+0x2000]");
        assert_eq!(text(Syntax::Nasm), "mov rax, qword [rel game.exe+0x2000]");
        assert_eq!(text(Syntax::Gas), "mov game.exe+0x2000, %rax");
        // a line at an export gets a label
        let dll = 0x1_8000_1000u64;
        let lines = decode(&m, dll, &opts(1));
        let table = SymbolCache::default().table_for(&m, &referenced_addresses(&m, &lines));
        let r = render(&m, &lines, &table, Syntax::Intel, &HashMap::new());
        assert_eq!(r[0].label.as_deref(), Some("other.dll!Alpha"));
        assert_eq!(listing(&r, false)[0], "other.dll!Alpha:");
    }

    #[test]
    fn x86_absolute_memory() {
        let mut m = MockProcess::new(Arch::X86);
        let mut img = vec![0u8; 0x2000];
        img[..2].copy_from_slice(b"MZ");
        // mov eax, dword ptr [0x401800] ; push 0x401800 ; ret
        img[0x1000..0x100B].copy_from_slice(&[0xA1, 0x00, 0x18, 0x40, 0x00, 0x68, 0x00, 0x18, 0x40, 0x00, 0xC3]);
        m.add_module("game.exe", 0x40_0000, img);
        let lines = decode(&m, 0x40_1000, &DecodeOptions { until_ret: true, ..opts(10) });
        let table = SymbolCache::default().table_for(&m, &referenced_addresses(&m, &lines));
        let r = render(&m, &lines, &table, Syntax::Intel, &HashMap::new());
        assert_eq!(r[0].text, "mov eax, dword ptr [game.exe+0x1800]");
        assert_eq!(r[0].memory.as_ref().unwrap().address, "0x00401800");
        assert_eq!(r[1].text, "push game.exe+0x1800");
        assert_eq!(Syntax::parse(Some("AT&T")).unwrap(), Syntax::Gas);
        assert!(Syntax::parse(Some("arm")).is_err());
    }
}

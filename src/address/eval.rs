//! Evaluation of parsed address expressions against a live process, with a step trace.

use serde::{Deserialize, Serialize};

use super::parser::{Arg, Expr, parse};
use crate::pattern::{Pattern, Scope, resolve_ranges, scan};
use super::parse_number;
use crate::error::{MemError, Result};
use crate::format;
use crate::binfmt;
use crate::platform::{Module, ProcessMemory};

/// Pointer-chain offset: a JSON number (decimal, may be negative) or an expression string
/// (bare numbers in strings are hex, e.g. "18" == 0x18, "-0x8").
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Offset {
    Num(i64),
    Expr(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    pub op: String,
    pub value: String,
}

pub struct Evaluator<'a> {
    p: &'a dyn ProcessMemory,
    modules: Option<Vec<Module>>,
    pub trace: Vec<TraceStep>,
    derefs: usize,
    input: String,
}

/// Finds a module by exact (case-insensitive) name, or by name without extension if unique.
pub fn lookup_module<'m>(modules: &'m [Module], name: &str) -> Result<Option<&'m Module>> {
    if let Some(m) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(name)) {
        return Ok(Some(m));
    }
    if name.contains('.') {
        return Ok(None);
    }
    let stem = |n: &str| n.rsplit_once('.').map(|(s, _)| s.to_ascii_lowercase()).unwrap_or_else(|| n.to_ascii_lowercase());
    let want = name.to_ascii_lowercase();
    let hits: Vec<&Module> = modules.iter().filter(|m| stem(&m.name) == want).collect();
    match hits.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        many => Err(MemError::InvalidArg(format!(
            "'{name}' matches several modules ({}); use the full name",
            many.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// `module+0xOFFSET` for addresses inside a module.
pub fn symbolize(modules: &[Module], addr: u64) -> Option<String> {
    modules.iter().find(|m| m.contains(addr)).map(|m| format!("{}+0x{:X}", m.name, addr - m.base))
}

impl<'a> Evaluator<'a> {
    pub fn new(p: &'a dyn ProcessMemory) -> Self {
        Self { p, modules: None, trace: Vec::new(), derefs: 0, input: String::new() }
    }

    pub fn modules(&mut self) -> Result<&[Module]> {
        if self.modules.is_none() {
            self.modules = Some(self.p.modules()?);
        }
        Ok(self.modules.as_deref().unwrap())
    }

    fn fmt(&self, a: u64) -> String {
        format::addr(a, self.p.pointer_size())
    }

    fn bad(&self, reason: impl Into<String>) -> MemError {
        MemError::BadAddress { input: self.input.clone(), reason: reason.into() }
    }

    fn push(&mut self, op: impl Into<String>, v: u64) {
        let value = self.fmt(v);
        self.trace.push(TraceStep { op: op.into(), value });
    }

    fn trace_text(&self) -> String {
        if self.trace.is_empty() {
            return "(empty)".into();
        }
        self.trace.iter().map(|s| format!("{} = {}", s.op, s.value)).collect::<Vec<_>>().join("; ")
    }

    pub fn eval_str(&mut self, input: &str) -> Result<u64> {
        let prev = std::mem::replace(&mut self.input, input.to_string());
        let r = parse(input).and_then(|e| self.eval(&e));
        self.input = prev;
        r
    }

    /// Reads a pointer at `addr`, recording the step.
    pub fn deref(&mut self, addr: u64) -> Result<u64> {
        self.derefs += 1;
        let step = self.derefs;
        match self.p.read_u64_ptr(addr) {
            Ok(v) => {
                self.push(format!("[{}] (deref #{step})", self.fmt(addr)), v);
                Ok(v)
            }
            Err(_) => {
                let mut reason = self.p.explain_unreadable(addr);
                if addr < 0x10000 {
                    reason.push_str("; the previous pointer is probably NULL");
                }
                Err(MemError::PointerChain { step, addr, reason, trace: self.trace_text() })
            }
        }
    }

    pub fn eval(&mut self, e: &Expr) -> Result<u64> {
        match e {
            Expr::Word(w) => self.word(w),
            Expr::Module(name) => {
                let m = lookup_module(self.modules()?, name)?.cloned().ok_or_else(|| self.bad(format!("module '{name}' is not loaded")))?;
                self.push(format!("module {}", m.name), m.base);
                Ok(m.base)
            }
            Expr::Export { module, symbol } => {
                let m = lookup_module(self.modules()?, module)?
                    .cloned()
                    .ok_or_else(|| self.bad(format!("module '{module}' is not loaded")))?;
                let modules = self.modules()?.to_vec();
                let hit = binfmt::resolve_export(self.p, &modules, &m, symbol)?;
                let mut op = format!("export {}!{symbol}", m.name);
                if !hit.forwards.is_empty() {
                    op.push_str(&format!(" (forwarded: {} → {})", hit.forwards.join(" → "), hit.module));
                }
                self.push(op, hit.address);
                Ok(hit.address)
            }
            Expr::Deref(inner) => {
                let a = self.eval(inner)?;
                self.deref(a)
            }
            Expr::Neg(inner) => Ok(self.eval(inner)?.wrapping_neg()),
            Expr::Add(a, b) => Ok(self.eval(a)?.wrapping_add(self.eval(b)?)),
            Expr::Sub(a, b) => Ok(self.eval(a)?.wrapping_sub(self.eval(b)?)),
            Expr::Mul(a, b) => Ok(self.eval(a)?.wrapping_mul(self.eval(b)?)),
            Expr::Call { name, args } => match name.as_str() {
                "sig" => self.call_sig(args),
                "rip" => self.call_rip(args),
                "abs32" => self.call_abs32(args),
                _ => Err(self.bad(format!("unknown function '{name}()'; available: sig, rip, abs32"))),
            },
        }
    }

    fn arg_num(&mut self, a: Option<&Arg>, func: &str, what: &str) -> Result<u64> {
        match a {
            Some(Arg::Expr(e)) => self.eval(e),
            Some(Arg::Str(s)) => self.eval_str(s),
            None => Err(self.bad(format!("{func}() is missing its {what} argument"))),
        }
    }

    /// `sig("pattern" [, "mask"] [, module] [, ".section"])` → address of the unique match.
    fn call_sig(&mut self, args: &[Arg]) -> Result<u64> {
        let Some(Arg::Str(pat_src)) = args.first() else {
            return Err(self.bad("sig() needs a quoted pattern as its first argument, e.g. sig(\"48 8B 05 ?? ?? ?? ??\", game.exe)"));
        };
        let probe = Pattern::parse(pat_src, None)?;
        let mut mask: Option<String> = None;
        let mut scope = Scope::default();
        for a in &args[1..] {
            let s = match a {
                Arg::Str(s) => s.clone(),
                Arg::Expr(Expr::Word(w)) => w.clone(),
                Arg::Expr(Expr::Module(m)) => m.clone(),
                _ => return Err(self.bad("sig() arguments after the pattern must be a mask, a module name or a .section")),
            };
            if mask.is_none() && scope.module.is_none() && probe.is_mask_for(&s) {
                mask = Some(s);
            } else if s.starts_with('.') && scope.section.is_none() {
                scope.section = Some(s);
            } else if scope.module.is_none() {
                scope.module = Some(s);
            } else {
                return Err(self.bad(format!("unexpected sig() argument '{s}'")));
            }
        }
        let pat = Pattern::parse(pat_src, mask.as_deref())?;
        let (ranges, desc) = resolve_ranges(self.p, &scope)?;
        let r = scan(self.p, &pat, &ranges, 1, 8);
        match r.matches.as_slice() {
            [] => Err(self.bad(format!("signature {} not found in {desc}", pat.display()))),
            [one] => {
                self.push(format!("sig({}) in {desc}", pat.display()), *one);
                Ok(*one)
            }
            many => {
                let shown: Vec<String> = many.iter().take(4).map(|a| self.fmt(*a)).collect();
                Err(self.bad(format!(
                    "signature {} is not unique in {desc}: {}{} matches ({}{}); lengthen the pattern or narrow the scope (module/.section)",
                    pat.display(),
                    many.len(),
                    if r.truncated { "+" } else { "" },
                    shown.join(", "),
                    if many.len() > 4 { ", …" } else { "" }
                )))
            }
        }
    }

    /// `rip(addr [, disp_offset = 3] [, insn_len = 7])` → addr + insn_len + i32 at (addr + disp_offset).
    /// Also resolves relative call/jmp targets (`rip(addr, 1, 5)` for E8/E9), on x86 as well.
    fn call_rip(&mut self, args: &[Arg]) -> Result<u64> {
        let a = self.arg_num(args.first(), "rip", "address")?;
        let off = if args.len() > 1 { self.arg_num(args.get(1), "rip", "displacement offset")? } else { 3 };
        let len = if args.len() > 2 { self.arg_num(args.get(2), "rip", "instruction length")? } else { 7 };
        let at = a.wrapping_add(off);
        let mut b = [0u8; 4];
        self.p.read(at, &mut b).map_err(|_| {
            self.bad(format!("rip(): cannot read the 32-bit displacement at {} ({})", self.fmt(at), self.p.explain_unreadable(at)))
        })?;
        let disp = i32::from_le_bytes(b);
        let mut target = a.wrapping_add(len).wrapping_add(disp as i64 as u64);
        if self.p.pointer_size() == 4 {
            target &= 0xFFFF_FFFF;
        }
        self.push(format!("rip({}, {off:#x}, {len:#x}) disp {disp:+#x}", self.fmt(a)), target);
        Ok(target)
    }

    /// `abs32(addr [, offset = 0])` → u32 absolute address stored at addr + offset (x86 code).
    fn call_abs32(&mut self, args: &[Arg]) -> Result<u64> {
        let a = self.arg_num(args.first(), "abs32", "address")?;
        let off = if args.len() > 1 { self.arg_num(args.get(1), "abs32", "offset")? } else { 0 };
        let at = a.wrapping_add(off);
        let mut b = [0u8; 4];
        self.p.read(at, &mut b).map_err(|_| {
            self.bad(format!("abs32(): cannot read 4 bytes at {} ({})", self.fmt(at), self.p.explain_unreadable(at)))
        })?;
        let v = u32::from_le_bytes(b) as u64;
        self.push(format!("abs32({}, {off:#x})", self.fmt(a)), v);
        Ok(v)
    }

    fn word(&mut self, w: &str) -> Result<u64> {
        // Explicit numeric forms are never module names.
        let lw = w.to_ascii_lowercase();
        if lw.starts_with("0x") || lw.starts_with('#') {
            return parse_number(w).map_err(|_| self.bad(format!("invalid number '{w}'")));
        }
        // Modules take precedence over bare hex (`dead.dll` vs `dead`), like Cheat Engine.
        if let Some(m) = lookup_module(self.modules()?, w)?.cloned() {
            self.push(format!("module {}", m.name), m.base);
            return Ok(m.base);
        }
        parse_number(w).map_err(|_| self.bad(format!("'{w}' is neither a loaded module nor a number")))
    }

    /// Cheat Engine pointer semantics: for each offset, `addr = [addr] + offset`.
    pub fn chain(&mut self, base: u64, offsets: &[Offset]) -> Result<u64> {
        let mut addr = base;
        for off in offsets {
            let ptr = self.deref(addr)?;
            let delta = match off {
                Offset::Num(n) => *n as u64,
                Offset::Expr(s) => self.eval_str(s)?,
            };
            addr = ptr.wrapping_add(delta);
        }
        Ok(addr)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolved {
    pub address: u64,
    pub trace: Vec<TraceStep>,
}

/// Evaluates `input` and then applies the pointer-chain `offsets`.
pub fn resolve(p: &dyn ProcessMemory, input: &str, offsets: &[Offset]) -> Result<Resolved> {
    let mut ev = Evaluator::new(p);
    ev.input = input.to_string();
    let base = ev.eval_str(input)?;
    let address = ev.chain(base, offsets)?;
    if address > p.max_address() {
        return Err(MemError::BadAddress {
            input: input.into(),
            reason: format!(
                "result {address:#x} is outside the {}-bit address space (trace: {})",
                p.pointer_size() * 8,
                ev.trace_text()
            ),
        });
    }
    Ok(Resolved { address, trace: ev.trace })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    const GAME: u64 = 0x40_0000;
    const HEAP: u64 = 0x100_0000;

    /// game.exe with a pointer at +0x10 → HEAP; HEAP+0x18 → HEAP+0x100.
    fn mock(arch: Arch) -> MockProcess {
        let mut m = MockProcess::new(arch);
        m.add_module("game.exe", GAME, vec![0u8; 0x1000]);
        m.add_module("other.dll", 0x50_0000, testpe::image(arch == Arch::X64, "game2.Alpha"));
        m.add_module("game2.dll", 0x60_0000, testpe::image(arch == Arch::X64, "OTHER.#3"));
        m.add_module("dead.dll", 0x70_0000, vec![0u8; 0x100]);
        m.map(HEAP, vec![0u8; 0x1000]);
        m.put_ptr(GAME + 0x10, HEAP);
        m.put_ptr(HEAP + 0x18, HEAP + 0x100);
        m
    }

    fn r(p: &MockProcess, s: &str) -> u64 {
        resolve(p, s, &[]).unwrap_or_else(|e| panic!("{s}: {e}")).address
    }

    #[test]
    fn numbers_modules_arith() {
        for arch in [Arch::X86, Arch::X64] {
            let p = mock(arch);
            assert_eq!(r(&p, "0x1234"), 0x1234);
            assert_eq!(r(&p, "1234h"), 0x1234);
            assert_eq!(r(&p, "#100"), 100);
            assert_eq!(r(&p, "game.exe"), GAME);
            assert_eq!(r(&p, "GAME.EXE+10"), GAME + 0x10);
            assert_eq!(r(&p, "\"game.exe\"+0x10"), GAME + 0x10);
            assert_eq!(r(&p, "game+0x10"), GAME + 0x10);
            assert_eq!(r(&p, "game.exe+0x100-0x10*2"), GAME + 0xE0);
            assert_eq!(r(&p, "game.exe+(0x10-8)*2"), GAME + 0x10);
            assert_eq!(r(&p, "game.exe+-8+8"), GAME);
            // module beats bare hex
            assert_eq!(r(&p, "dead"), 0x70_0000);
            assert_eq!(r(&p, "0xdead"), 0xdead);
            assert_eq!(r(&p, "beef"), 0xbeef);
        }
    }

    #[test]
    fn deref_and_chains() {
        for arch in [Arch::X86, Arch::X64] {
            let p = mock(arch);
            assert_eq!(r(&p, "[game.exe+0x10]"), HEAP);
            assert_eq!(r(&p, "[[game.exe+0x10]+0x18]+0x4"), HEAP + 0x104);
            let res = resolve(&p, "game.exe+0x10", &[Offset::Num(0x18), Offset::Expr("4".into())]).unwrap();
            assert_eq!(res.address, HEAP + 0x104);
            assert_eq!(res.trace.len(), 3, "{:?}", res.trace);
            assert!(res.trace[1].op.contains("deref #1"));
            let res = resolve(&p, "game.exe+0x10", &[Offset::Num(0x20), Offset::Num(8), Offset::Num(0)]).unwrap_err();
            // [HEAP+0x20] = 0 → step 3 reads [0 + 8]
            match res {
                MemError::PointerChain { step, addr, reason, .. } => {
                    assert_eq!(step, 3);
                    assert_eq!(addr, 8);
                    assert!(reason.contains("NULL"), "{reason}");
                }
                e => panic!("{e}"),
            }
            let res = resolve(&p, "game.exe+0x10", &[Offset::Num(0x18), Offset::Num(-0x100)]).unwrap();
            assert_eq!(res.address, HEAP);
        }
    }

    #[test]
    fn exports_and_forwarders() {
        for arch in [Arch::X86, Arch::X64] {
            let p = mock(arch);
            assert_eq!(r(&p, "other.dll!Alpha"), 0x50_1000);
            assert_eq!(r(&p, "other.dll!gamma"), 0x50_2000, "case-insensitive fallback");
            assert_eq!(r(&p, "other.dll!#3"), 0x50_2000);
            assert_eq!(r(&p, "other!Alpha+0x10"), 0x50_1010);
            // other!Beta → game2.Alpha
            let res = resolve(&p, "other.dll!Beta", &[]).unwrap();
            assert_eq!(res.address, 0x60_1000);
            assert!(res.trace[0].op.contains("forwarded"), "{:?}", res.trace);
            // game2!Beta → OTHER.#3
            assert_eq!(r(&p, "game2.dll!Beta"), 0x50_2000);
            let e = resolve(&p, "other.dll!Nope", &[]).unwrap_err().to_string();
            assert!(e.contains("not found"), "{e}");
            let e = resolve(&p, "game.exe!Alpha", &[]).unwrap_err().to_string();
            assert!(e.contains("no recognizable executable header"), "{e}");
        }
    }

    #[test]
    fn errors() {
        let p = mock(Arch::X86);
        let e = resolve(&p, "nosuch.dll+1", &[]).unwrap_err().to_string();
        assert!(e.contains("neither a loaded module"), "{e}");
        let e = resolve(&p, "\"nosuch.dll\"", &[]).unwrap_err().to_string();
        assert!(e.contains("not loaded"), "{e}");
        let e = resolve(&p, "0x100000000", &[]).unwrap_err().to_string();
        assert!(e.contains("32-bit"), "{e}");
        let e = resolve(&p, "sig(\"48 8B\", game.exe)", &[]).unwrap_err().to_string();
        assert!(e.contains("not found in game.exe"), "{e}");
        let e = resolve(&p, "sig(game.exe)", &[]).unwrap_err().to_string();
        assert!(e.contains("quoted pattern"), "{e}");
        let e = resolve(&p, "nope(1)", &[]).unwrap_err().to_string();
        assert!(e.contains("unknown function"), "{e}");
        let e = resolve(&p, "[0x10]", &[]).unwrap_err().to_string();
        assert!(e.contains("dereference #1"), "{e}");
    }

    #[test]
    fn sig_rip_abs32() {
        for arch in [Arch::X86, Arch::X64] {
            let p = mock(arch);
            // game.exe+0x100: CA FE | 48 8B 05 <disp32> → GAME+0x800
            let disp = (0x800i64 - (0x102 + 7)) as i32;
            let mut code = vec![0xCA, 0xFE, 0x48, 0x8B, 0x05];
            code.extend(disp.to_le_bytes());
            p.write(GAME + 0x100, &code).unwrap();
            // game.exe+0x200: 5A 5A A1 <abs32 HEAP>
            let mut abs = vec![0x5A, 0x5A, 0xA1];
            abs.extend((HEAP as u32).to_le_bytes());
            p.write(GAME + 0x200, &abs).unwrap();

            assert_eq!(r(&p, "sig(\"CA FE 48 8B 05\", game.exe)"), GAME + 0x100);
            assert_eq!(r(&p, "sig(\"\\xCA\\xFE\\x00\\x8B\", \"xx?x\", game.exe)"), GAME + 0x100);
            assert_eq!(r(&p, "rip(sig(\"CA FE 48 8B 05\", game.exe)+2, 3, 7)"), GAME + 0x800);
            assert_eq!(r(&p, "rip(sig(\"CA FE 48 8B 05\", game.exe)+2)"), GAME + 0x800, "defaults 3, 7");
            assert_eq!(r(&p, "abs32(sig(\"5A 5A A1\", game.exe), 3)"), HEAP);
            assert_eq!(r(&p, "[[abs32(sig(\"5A 5A A1\", game.exe), 3)+0x18]]"), 0, "chains compose");
            let res = resolve(&p, "rip(sig(\"CA FE 48 8B 05\", game.exe)+2)", &[]).unwrap();
            assert!(res.trace[0].op.starts_with("sig(CA FE 48 8B 05) in game.exe"), "{:?}", res.trace);
            assert!(res.trace[1].op.contains("disp +0x6f7"), "{:?}", res.trace);
            // two matches → not unique
            p.write(GAME + 0x300, &[0xCA, 0xFE, 0x48, 0x8B, 0x05]).unwrap();
            let e = resolve(&p, "sig(\"CA FE 48 8B 05\", game.exe)", &[]).unwrap_err().to_string();
            assert!(e.contains("not unique") && e.contains("2 matches"), "{e}");
        }
    }

    #[test]
    fn symbolize_addr() {
        let p = mock(Arch::X64);
        let mods = p.modules().unwrap();
        assert_eq!(symbolize(&mods, GAME + 0x10).as_deref(), Some("game.exe+0x10"));
        assert_eq!(symbolize(&mods, HEAP), None);
    }
}

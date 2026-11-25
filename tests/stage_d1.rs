//! D1 integration tests: disassembly of live x64 and x86 code.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{AttachParams, DisassembleParams};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn params(addr: &str) -> DisassembleParams {
    DisassembleParams {
        address: addr.into(),
        offsets: None,
        count: None,
        size: None,
        until_ret: None,
        syntax: None,
        show_bytes: None,
        details: Some(true),
    }
}

fn dis(s: &MemoryServer, p: DisassembleParams) -> Value {
    let a = p.address.clone();
    s.do_disassemble(p).unwrap_or_else(|e| panic!("disassemble {a}: {e}"))
}

fn details(v: &Value) -> &Vec<Value> {
    v["details"].as_array().unwrap()
}

/// Function entry, following an incremental-linking `jmp` thunk if there is one.
fn entry(s: &MemoryServer, addr: u64) -> String {
    let v = dis(s, DisassembleParams { count: Some(1), ..params(&format!("0x{addr:X}")) });
    let first = &details(&v)[0];
    if first["flow"] == "jump" {
        first["target"]["address"].as_str().unwrap().to_string()
    } else {
        format!("0x{addr:X}")
    }
}

fn suite(triple: &str, print: bool) {
    let tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let x86 = tb.bits() == 32;

    // tick(): reads and writes HEALTH through a static memory operand (rip-relative / absolute)
    let tick = entry(&s, tb.addr("fn_tick"));
    let v = dis(&s, DisassembleParams { until_ret: Some(true), count: Some(64), ..params(&tick) });
    if print {
        println!("{triple} tick:\n  {}", v["listing"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n  "));
    }
    assert_eq!(v["stopped_by"], json!("ret"), "{v}");
    let d = details(&v);
    assert_eq!(d.last().unwrap()["flow"], json!("ret"));
    let health_refs: Vec<&Value> = d.iter().filter(|i| i["memory"]["address"].as_str().is_some_and(|a| hex(&json!(a)) == tb.addr("health"))).collect();
    assert!(!health_refs.is_empty(), "tick references HEALTH: {v}");
    let sym = health_refs[0]["memory"]["symbol"].as_str().unwrap();
    assert!(sym.starts_with("testbed.exe+0x"), "{sym}");
    assert!(health_refs.iter().any(|i| i["text"].as_str().unwrap().contains(sym)), "symbol shown in the instruction text");
    assert!(v["symbol"].as_str().unwrap().starts_with("testbed.exe+0x"));

    // take_damage(): stores the new health through a pointer register
    let td = entry(&s, tb.addr("fn_take_damage"));
    let v = dis(&s, DisassembleParams { until_ret: Some(true), count: Some(64), ..params(&td) });
    if print {
        println!("{triple} take_damage:\n  {}", v["listing"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n  "));
    }
    assert!(
        details(&v).iter().any(|i| i["text"].as_str().unwrap().starts_with("mov dword ptr [")),
        "a 32-bit store into the player: {v}"
    );

    // export labels and import-table comments: kernel32!Sleep forwards to KERNELBASE
    let v = dis(&s, DisassembleParams { count: Some(4), ..params("kernel32.dll!Sleep") });
    if print {
        println!("{triple} kernel32!Sleep:\n  {}", v["listing"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n  "));
    }
    let listing = v["listing"].as_array().unwrap();
    assert!(listing[0].as_str().unwrap().eq_ignore_ascii_case("kernel32.dll!Sleep:"), "{listing:?}");
    let mentions_kernelbase = details(&v).iter().any(|i| {
        let c = i["comment"].as_str().unwrap_or("").to_ascii_lowercase();
        let t = i["target"]["symbol"].as_str().unwrap_or("").to_ascii_lowercase();
        c.contains("kernelbase") || t.contains("kernelbase")
    });
    assert!(mentions_kernelbase, "Sleep reaches KERNELBASE: {v}");

    // syntaxes, bounds and continuation
    let att = dis(&s, DisassembleParams { syntax: Some("att".into()), until_ret: Some(true), count: Some(64), ..params(&tick) });
    assert!(details(&att).iter().any(|i| i["text"].as_str().unwrap().contains('%')), "AT&T registers");
    let three = dis(&s, DisassembleParams { count: Some(3), ..params(&tick) });
    assert_eq!(three["instructions"], json!(3));
    assert_eq!(three["stopped_by"], json!("count"));
    let cont = dis(&s, DisassembleParams { count: Some(1), ..params(three["next"].as_str().unwrap()) });
    let full = dis(&s, DisassembleParams { count: Some(4), ..params(&tick) });
    assert_eq!(details(&cont)[0]["text"], details(&full)[3]["text"], "`next` continues the listing");
    let sized = dis(&s, DisassembleParams { size: Some(4), count: Some(100), ..params(&tick) });
    assert!(sized["bytes"].as_u64().unwrap() <= 4 + 15);
    let plain = s.do_disassemble(DisassembleParams { show_bytes: Some(false), details: None, count: Some(2), ..params(&tick) }).unwrap();
    assert!(plain.get("details").is_none());
    let first_bytes = details(&full)[0]["bytes"].as_str().unwrap();
    assert!(!plain["listing"][0].as_str().unwrap().contains(first_bytes), "show_bytes=false hides bytes");
    assert!(full["listing"][0].as_str().unwrap().contains(first_bytes));
    // x86 code uses absolute addresses for statics, x64 RIP-relative ones; both are symbolized
    let tick_text = details(&full)[0]["text"].as_str().unwrap();
    assert!(tick_text.contains("testbed.exe+0x"), "{tick_text} (x86: {x86})");

    // errors
    let e = s.do_disassemble(params("0x0")).unwrap_err();
    assert!(matches!(e, MemError::Read { .. }) && e.to_string().contains("not mapped"), "{e}");
    let e = s.do_disassemble(DisassembleParams { syntax: Some("arm".into()), ..params(&tick) }).unwrap_err();
    assert!(e.to_string().contains("unknown syntax"), "{e}");
    tb.quit();
}

#[test]
fn x64_disassembly() {
    suite(X64, false);
}

#[test]
fn x86_disassembly() {
    suite(X86, false);
}

/// Prints listings: `cargo test --test stage_d1 -- --ignored --nocapture`
#[test]
#[ignore]
fn print_listings() {
    suite(X64, true);
    suite(X86, true);
}

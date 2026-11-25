//! D2 integration tests: function boundaries, function listings and module function lists (x64 and x86).
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{AttachParams, DisassembleFunctionParams, FunctionParams, ListFunctionsParams};
use memory_mcp::MemoryServer;
use serde_json::{Value, json};

fn info(s: &MemoryServer, addr: u64) -> Value {
    s.do_function_info(FunctionParams { address: format!("0x{addr:X}"), offsets: None })
        .unwrap_or_else(|e| panic!("function_info 0x{addr:X}: {e}"))
}

fn list(s: &MemoryServer, module: &str, filter: Option<&str>, limit: usize) -> Value {
    s.do_list_functions(ListFunctionsParams { module: module.into(), filter: filter.map(Into::into), offset: None, limit: Some(limit) })
        .unwrap()
}

fn listing(s: &MemoryServer, addr: u64) -> Value {
    s.do_disassemble_function(DisassembleFunctionParams {
        address: format!("0x{addr:X}"),
        offsets: None,
        syntax: None,
        show_bytes: Some(false),
        details: None,
    })
    .unwrap()
}

fn suite(triple: &str, print: bool) {
    let tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let x64 = tb.bits() == 64;

    // leaf functions of the testbed: found from their call sites (no .pdata on x64 either)
    for (name, field) in [("tick", "fn_tick"), ("take_damage", "fn_take_damage"), ("heal", "fn_heal")] {
        let start = tb.addr(field);
        let v = info(&s, start + 2);
        if print {
            println!("{triple} {name}: {v}");
        }
        assert_eq!(hex(&v["start"]), start, "{name}: {v}");
        assert!(["call_target", "pdata"].contains(&v["source"].as_str().unwrap()), "{name}: {v}");
        let size = v["size"].as_u64().unwrap();
        assert!((4..64).contains(&size), "{name}: small leaf function, got {size}");
        assert_eq!(v["calls"], json!([]), "{name} is a leaf");
        let l = listing(&s, start);
        let lines = l["listing"].as_array().unwrap();
        assert!(lines.last().unwrap().as_str().unwrap().ends_with("ret"), "{l}");
        assert_eq!(hex(&l["end"]), start + size);
    }

    // module function list
    let v = list(&s, "testbed.exe", None, 1000);
    assert!(v["functions_total"].as_u64().unwrap() > 20, "{}", v["functions_total"]);
    let tick = format!("0x{:0w$X}", tb.addr("fn_tick"), w = if x64 { 16 } else { 8 });
    assert!(v["items"].as_array().unwrap().iter().any(|i| i["address"] == json!(tick)), "tick is listed");
    assert_eq!(v["from_pdata"].as_u64().unwrap() > 0, x64, "x64 has .pdata, x86 does not");

    let k = list(&s, "kernel32.dll", Some("!Sleep"), 50);
    assert!(k["items"].as_array().unwrap().iter().any(|i| i["symbol"].as_str().unwrap().eq_ignore_ascii_case("KERNEL32.DLL!Sleep")), "{k}");

    // a real non-leaf function: exact .pdata boundaries on x64
    if x64 {
        let all = list(&s, "kernel32.dll", None, 1000);
        let f = all["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["source"] == "pdata" && i["size"].as_u64().is_some_and(|n| (64..4096).contains(&n)))
            .expect("a pdata function in kernel32");
        let start = hex(&f["address"]);
        let size = f["size"].as_u64().unwrap();
        let v = info(&s, start + size / 2);
        if print {
            println!("{triple} kernel32 pdata function: {v}");
        }
        assert_eq!(hex(&v["start"]), start);
        assert!(v["source"] == "pdata" || v["source"] == "pdata_chained", "{v}");
        if v["source"] == "pdata" {
            assert_eq!(v["size"].as_u64().unwrap(), size);
        }
        let l = listing(&s, start);
        assert!(l["instructions"].as_u64().unwrap() > 5);
    }

    // not code
    let e = s.do_function_info(FunctionParams { address: tb.addr_str("player"), offsets: None }).unwrap_err().to_string();
    assert!(e.contains("cannot determine") || e.contains("not inside"), "{e}");
    tb.quit();
}

#[test]
fn x64_functions() {
    suite(X64, false);
}

#[test]
fn x86_functions() {
    suite(X86, false);
}

/// `cargo test --test stage_d2 -- --ignored --nocapture`
#[test]
#[ignore]
fn print_functions() {
    suite(X64, true);
    suite(X86, true);
}

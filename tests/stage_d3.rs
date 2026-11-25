//! D3 integration tests: cross-references in live x64 and x86 code.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{AttachParams, FindXrefsParams, FunctionParams};
use memory_mcp::MemoryServer;
use serde_json::{Value, json};

fn params(target: &str) -> FindXrefsParams {
    FindXrefsParams {
        target: target.into(),
        offsets: None,
        size: None,
        kind: None,
        modules: None,
        via_pointers: None,
        offset: None,
        limit: Some(1000),
        syntax: None,
    }
}

fn xrefs(s: &MemoryServer, p: FindXrefsParams) -> Value {
    let t = p.target.clone();
    s.do_find_xrefs(p).unwrap_or_else(|e| panic!("find_xrefs {t}: {e}"))
}

fn items(v: &Value) -> &Vec<Value> {
    v["items"].as_array().unwrap()
}

fn suite(triple: &str, print: bool) {
    let tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();

    // HEALTH: tick reads and writes it; main reads (get) and writes (set) it
    let v = xrefs(&s, FindXrefsParams { size: Some(4), ..params(&tb.addr_str("health")) });
    if print {
        println!("{triple} xrefs to HEALTH: counts {} searched {}", v["counts"], v["searched"]);
        for i in items(&v) {
            println!("  {} {:<10} in {:<22} {}", i["symbol"].as_str().unwrap(), i["kind"].as_str().unwrap(), i["function"].as_str().unwrap_or("?"), i["text"].as_str().unwrap());
        }
    }
    let tick = tb.addr("fn_tick");
    let tick_size = s.do_function_info(FunctionParams { address: format!("0x{tick:X}"), offsets: None }).unwrap()["size"].as_u64().unwrap();
    let in_tick = |i: &&Value| (tick..tick + tick_size).contains(&hex(&i["from"]));
    let tick_refs: Vec<&Value> = items(&v).iter().filter(in_tick).collect();
    assert!(tick_refs.iter().any(|i| i["kind"] == "read"), "tick reads HEALTH: {v}");
    assert!(tick_refs.iter().any(|i| i["kind"] == "write"), "tick writes HEALTH: {v}");
    assert!(tick_refs.iter().all(|i| i["function"].as_str().unwrap().starts_with("testbed.exe+")));
    assert!(items(&v).iter().any(|i| !in_tick(&i)), "main also touches HEALTH");
    // references outside tick are not attributed to the small game functions placed before main
    for f in ["fn_take_damage", "fn_heal", "fn_tick"] {
        let fname = s.do_function_info(FunctionParams { address: tb.addr_str(f), offsets: None }).unwrap()["symbol"].clone();
        let wrongly = items(&v).iter().filter(|i| !in_tick(i) && i["function"] == fname).count();
        assert_eq!(wrongly, 0, "{f} ({fname}) does not contain main's references: {v}");
    }
    assert!(items(&v).iter().all(|i| i["text"].as_str().unwrap().contains("testbed.exe+0x")));

    // kind filters
    let w = xrefs(&s, FindXrefsParams { size: Some(4), kind: Some("write".into()), ..params(&tb.addr_str("health")) });
    assert!(items(&w).iter().all(|i| i["kind"] == "write" || i["kind"] == "read_write"), "{w}");
    assert!(w["total"].as_u64().unwrap() < v["total"].as_u64().unwrap());

    // calls to the game functions come from main's command loop
    for f in ["fn_tick", "fn_take_damage", "fn_heal"] {
        let c = xrefs(&s, FindXrefsParams { kind: Some("call".into()), ..params(&tb.addr_str(f)) });
        assert!(c["total"].as_u64().unwrap() >= 1, "{f}: {c}");
        assert!(items(&c).iter().all(|i| i["text"].as_str().unwrap().starts_with("call ")), "{c}");
    }

    // an import: kernel32!GetStdHandle is called through the import table of testbed.exe
    let g = xrefs(&s, FindXrefsParams { modules: Some(vec!["testbed.exe".into()]), ..params("kernel32.dll!GetStdHandle") });
    if print {
        println!("{triple} xrefs to GetStdHandle: {}", serde_json::to_string_pretty(&g["items"]).unwrap());
    }
    assert!(items(&g).iter().any(|i| i["kind"] == "call" && i["via"].as_str().is_some()), "call through the IAT: {g}");
    let no_ptr = xrefs(&s, FindXrefsParams { modules: Some(vec!["testbed.exe".into()]), via_pointers: Some(false), ..params("kernel32.dll!GetStdHandle") });
    assert_eq!(no_ptr["total"], json!(0), "without pointer slots there is no direct reference");

    // errors
    let e = s.do_find_xrefs(FindXrefsParams { kind: Some("teleport".into()), ..params(&tb.addr_str("health")) }).unwrap_err();
    assert!(e.to_string().contains("unknown kind"), "{e}");
    let e = s.do_find_xrefs(FindXrefsParams { modules: Some(vec!["nosuch.dll".into()]), ..params(&tb.addr_str("health")) }).unwrap_err();
    assert!(e.to_string().contains("not loaded"), "{e}");
    tb.quit();
}

#[test]
fn x64_xrefs() {
    suite(X64, false);
}

#[test]
fn x86_xrefs() {
    suite(X86, false);
}

/// `cargo test --test stage_d3 -- --ignored --nocapture`
#[test]
#[ignore]
fn print_xrefs() {
    suite(X64, true);
    suite(X86, true);
}

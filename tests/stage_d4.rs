//! D4 integration tests: signature generation that survives a restart (ASLR), x64 and x86.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{AttachParams, MakeSignatureParams, ReadValueParams, ResolveAddressParams};
use memory_mcp::MemoryServer;
use serde_json::{Value, json};

fn params(addr: &str) -> MakeSignatureParams {
    MakeSignatureParams {
        address: addr.into(),
        offsets: None,
        module: None,
        min_len: None,
        max_len: None,
        wildcard_offsets: None,
        wildcard_immediates: None,
        max_back: None,
    }
}

fn sign(s: &MemoryServer, p: MakeSignatureParams) -> Value {
    let a = p.address.clone();
    s.do_make_signature(p).unwrap_or_else(|e| panic!("make_signature {a}: {e}"))
}

fn resolve(s: &MemoryServer, e: &str) -> u64 {
    hex(&s.do_resolve_address(ResolveAddressParams { address: e.into(), offsets: None }).unwrap_or_else(|err| panic!("{e}: {err}"))["address"])
}

fn read_i32(s: &MemoryServer, e: &str) -> Value {
    s.do_read_value(ReadValueParams { address: e.into(), offsets: None, value_type: "i32".into(), count: None, length: None, big_endian: None })
        .unwrap()["value"]
        .clone()
}

fn suite(triple: &str, print: bool) {
    let tb1 = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb1.pid()), name: None }).unwrap();

    // code: tick, with the data it references
    let tick = sign(&s, params(&tb1.addr_str("fn_tick")));
    if print {
        println!("{triple} tick: {}", serde_json::to_string_pretty(&tick).unwrap());
    }
    assert_eq!(tick["kind"], json!("code"));
    assert!(tick["pattern"].as_str().unwrap().contains("??"), "the address of HEALTH is wildcarded: {tick}");
    assert_eq!(resolve(&s, tick["expression"].as_str().unwrap()), tb1.addr("fn_tick"));
    let tick_data = tick["data"]["expression"].as_str().expect("tick reads HEALTH").to_string();
    assert_eq!(resolve(&s, &tick_data), tb1.addr("health"));
    let mask = tick["code_style"]["mask"].as_str().unwrap();
    assert_eq!(mask.len(), tick["length"].as_u64().unwrap() as usize);

    // data: HEALTH itself (a referencing instruction is signed)
    let health = sign(&s, params(&tb1.addr_str("health")));
    if print {
        println!("{triple} HEALTH: {}", serde_json::to_string_pretty(&health).unwrap());
    }
    assert_eq!(health["kind"], json!("data"));
    let health_expr = health["expression"].as_str().unwrap().to_string();
    assert!(health_expr.starts_with(if tb1.bits() == 64 { "rip(sig(" } else { "abs32(sig(" }), "{health_expr}");
    assert_eq!(read_i32(&s, &health_expr), json!(100));

    // tiny functions: the pattern runs past the function or starts earlier, but stays unique
    let td = sign(&s, params(&tb1.addr_str("fn_take_damage")));
    assert_eq!(resolve(&s, td["expression"].as_str().unwrap()), tb1.addr("fn_take_damage"));
    let td_wild = sign(&s, MakeSignatureParams { wildcard_offsets: Some(true), ..params(&tb1.addr_str("fn_take_damage")) });
    assert_eq!(resolve(&s, td_wild["expression"].as_str().unwrap()), tb1.addr("fn_take_damage"));

    // a mid-function address (second instruction of tick)
    let second = hex(&tick["covered"].as_array().unwrap()[1].as_str().unwrap().split_whitespace().next().map(|sym| {
        json!(format!("0x{:X}", resolve(&s, sym)))
    }).unwrap());
    let mid = sign(&s, params(&format!("0x{second:X}")));
    assert_eq!(resolve(&s, mid["expression"].as_str().unwrap()), second);

    // errors
    let e = s.do_make_signature(params(&tb1.addr_str("player"))).unwrap_err().to_string();
    assert!(e.contains("inside a module"), "{e}");
    let e = s.do_make_signature(params(&format!("0x{:X}", tb1.addr("signature") + 3))).unwrap_err().to_string();
    assert!(e.contains("references it"), "{e}");

    // restart: ASLR moves everything, the expressions still find the same places
    let exprs = (tick["expression"].as_str().unwrap().to_string(), tick_data, health_expr, td["expression"].as_str().unwrap().to_string());
    tb1.quit();
    let mut tb2 = Testbed::spawn(triple);
    s.do_attach(AttachParams { pid: Some(tb2.pid()), name: None }).unwrap();
    assert_eq!(resolve(&s, &exprs.0), tb2.addr("fn_tick"));
    assert_eq!(resolve(&s, &exprs.1), tb2.addr("health"));
    assert_eq!(resolve(&s, &exprs.3), tb2.addr("fn_take_damage"));
    tb2.cmd("set health 321");
    assert_eq!(read_i32(&s, &exprs.2), json!(321));
}

#[test]
fn x64_signatures() {
    suite(X64, false);
}

#[test]
fn x86_signatures() {
    suite(X86, false);
}

/// `cargo test --test stage_d4 -- --ignored --nocapture`
#[test]
#[ignore]
fn print_signatures() {
    suite(X64, true);
    suite(X86, true);
}

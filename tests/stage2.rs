//! Stage 2 integration tests: address expressions, pointer chains and exports on x64 and x86 targets.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::address::Offset;
use memory_mcp::server::{AttachParams, ReadValueParams, ResolveAddressParams};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn read_i32(s: &MemoryServer, addr: &str, offsets: Option<Vec<Offset>>) -> Value {
    s.do_read_value(ReadValueParams {
        address: addr.into(),
        offsets,
        value_type: "i32".into(),
        count: None,
        length: None,
        big_endian: None,
    })
    .unwrap_or_else(|e| panic!("{addr}: {e}"))["value"]
        .clone()
}

fn resolve(s: &MemoryServer, addr: &str, offsets: Option<Vec<Offset>>) -> Result<Value, MemError> {
    s.do_resolve_address(ResolveAddressParams { address: addr.into(), offsets })
}

fn suite(triple: &str) {
    let tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();

    // module base and module-relative offsets
    let base = hex(&resolve(&s, "testbed.exe", None).unwrap()["address"]);
    let health_rel = tb.addr("health") - base;
    let root_rel = tb.addr("world_root") - base;

    assert_eq!(read_i32(&s, &format!("testbed.exe+0x{health_rel:X}"), None), json!(100));
    assert_eq!(read_i32(&s, &format!("TESTBED+{health_rel:X}"), None), json!(100));
    assert_eq!(read_i32(&s, &format!("\"testbed.exe\" + #{health_rel}"), None), json!(100));
    assert_eq!(read_i32(&s, &format!("testbed.exe+0x{:X}-0x10*2", health_rel + 0x20), None), json!(100));

    let r = resolve(&s, &format!("testbed.exe+0x{health_rel:X}"), None).unwrap();
    assert_eq!(r["symbol"], json!(format!("testbed.exe+0x{health_rel:X}")));
    assert_eq!(r["region"]["protect"], json!("rw-"));

    // pointer chain as an expression: [[root]+0x18]+4 == player.armor
    let expr = format!("[[testbed.exe+0x{root_rel:X}]+0x18]+4");
    assert_eq!(read_i32(&s, &expr, None), json!(75));
    let r = resolve(&s, &expr, None).unwrap();
    assert_eq!(hex(&r["address"]), tb.addr("player_armor"));
    assert_eq!(r["symbol"], Value::Null, "heap address has no module");
    let trace = r["trace"].as_array().unwrap();
    assert_eq!(trace.len(), 3, "{trace:?}");
    assert_eq!(hex(&trace[1]["value"]), tb.addr("world"));
    assert_eq!(hex(&trace[2]["value"]), tb.addr("player"));

    // the same chain as an offsets list (numbers are decimal, strings are hex)
    let offs = vec![Offset::Num(0x18), Offset::Expr("4".into())];
    assert_eq!(read_i32(&s, &format!("testbed.exe+0x{root_rel:X}"), Some(offs)), json!(75));
    let offs = vec![Offset::Expr("18".into()), Offset::Num(0)];
    assert_eq!(read_i32(&s, &format!("testbed.exe+0x{root_rel:X}"), Some(offs)), json!(250));

    // broken chain
    let e = resolve(&s, "[[0x10]+8]", None).unwrap_err();
    assert!(matches!(e, MemError::PointerChain { step: 1, .. }), "{e}");
    let e = resolve(&s, &format!("testbed.exe+0x{root_rel:X}"), Some(vec![Offset::Num(0x18), Offset::Num(0x1000000), Offset::Num(0)]))
        .unwrap_err();
    assert!(matches!(e, MemError::PointerChain { step: 3, .. }), "{e}");

    // exports
    let k32 = resolve(&s, "kernel32.dll!GetProcAddress", None).unwrap();
    assert!(k32["symbol"].as_str().unwrap().to_ascii_lowercase().starts_with("kernel32.dll+"), "{k32}");
    assert!(k32["region"]["protect"].as_str().unwrap().contains('x'), "export points to code: {k32}");
    let same = resolve(&s, "kernel32!getprocaddress", None).unwrap();
    assert_eq!(same["address"], k32["address"]);

    // forwarder: kernel32!HeapAlloc → NTDLL.RtlAllocateHeap
    let fwd = resolve(&s, "kernel32.dll!HeapAlloc", None).unwrap();
    let direct = resolve(&s, "ntdll.dll!RtlAllocateHeap", None).unwrap();
    assert_eq!(fwd["address"], direct["address"]);
    assert!(fwd["trace"][0]["op"].as_str().unwrap().contains("forwarded"), "{fwd}");

    let e = resolve(&s, "kernel32.dll!NoSuchExport", None).unwrap_err().to_string();
    assert!(e.contains("not found"), "{e}");
    let e = resolve(&s, "nosuch.dll+10", None).unwrap_err().to_string();
    assert!(e.contains("neither a loaded module"), "{e}");
}

#[test]
fn x64_expressions() {
    suite(X64);
}

#[test]
fn x86_expressions() {
    suite(X86);
}

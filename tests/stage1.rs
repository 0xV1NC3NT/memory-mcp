//! Stage 1 integration tests: attach, process info, modules, regions, reads — on x64 and x86 targets.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{
    AttachParams, ListModulesParams, ListProcessesParams, ListRegionsParams, ReadBytesParams, ReadValueParams,
};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn read(s: &MemoryServer, addr: &str, ty: &str, count: Option<usize>, length: Option<usize>) -> Value {
    s.do_read_value(ReadValueParams {
        address: addr.into(),
        value_type: ty.into(),
        count,
        length,
        big_endian: None, offsets: None,
    })
    .unwrap_or_else(|e| panic!("read {ty} at {addr}: {e}"))
}

fn attached(tb: &Testbed) -> MemoryServer {
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    s
}

fn suite(triple: &str, bits: u64) {
    let mut tb = Testbed::spawn(triple);
    assert_eq!(tb.bits(), bits);
    let s = MemoryServer::new();

    // attach + process_info
    let a = s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let info = &a["attached"];
    assert_eq!(info["bits"], json!(bits));
    assert_eq!(info["arch"], json!(if bits == 32 { "x86" } else { "x64" }));
    assert_eq!(info["can_write"], json!(true));
    let main = &info["main_module"];
    assert_eq!(main["name"].as_str().unwrap().to_ascii_lowercase(), "testbed.exe");
    let base = hex(&main["base"]);
    let size = u64::from_str_radix(main["size"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let health = tb.addr("health");
    assert!(health >= base && health < base + size, "static lies inside main module");
    // Address formatting width follows bitness.
    assert_eq!(main["base"].as_str().unwrap().len(), 2 + (bits as usize / 4));

    // list_modules
    let mods = s.do_list_modules(ListModulesParams { filter: Some("testbed".into()), offset: None, limit: None }).unwrap();
    assert_eq!(mods["total"], json!(1));
    assert_eq!(mods["items"][0]["arch"], json!(if bits == 32 { "x86" } else { "x64" }));
    let k32 = s.do_list_modules(ListModulesParams { filter: Some("kernel32".into()), offset: None, limit: None }).unwrap();
    assert!(k32["total"].as_u64().unwrap() >= 1, "kernel32 listed");

    // list_regions: the .data static lies in an rw region of testbed.exe
    let regs = s
        .do_list_regions(ListRegionsParams {
            protection: Some("rw".into()),
            kind: Some("image".into()),
            module: Some("testbed.exe".into()),
            include_reserved: None,
            offset: None,
            limit: Some(1000),
        })
        .unwrap();
    let found = regs["items"].as_array().unwrap().iter().any(|r| hex(&r["base"]) <= health && health < hex(&r["end"]));
    assert!(found, "rw image region containing health: {regs}");

    // read_value: scalars
    assert_eq!(read(&s, &tb.addr_str("health"), "i32", None, None)["value"], json!(100));
    assert_eq!(read(&s, &tb.addr_str("gold"), "u64", None, None)["value"], json!(123_456_789_012u64));
    assert_eq!(read(&s, &tb.addr_str("speed"), "float", None, None)["value"], json!(1.5));
    let pi = read(&s, &tb.addr_str("precision"), "double", None, None)["value"].as_f64().unwrap();
    assert!((pi - std::f64::consts::PI).abs() < 1e-6);

    // value changes in the target are observed
    assert_eq!(tb.cmd("set health 42"), "ok");
    assert_eq!(read(&s, &tb.addr_str("health"), "int", None, None)["value"], json!(42));

    // strings and bytes
    assert_eq!(read(&s, &tb.addr_str("name"), "utf8", None, Some(16))["value"], json!("TestbedPlayer"));
    assert_eq!(read(&s, &tb.addr_str("wname"), "wstring", None, Some(8))["value"], json!("Testbed"));
    assert_eq!(read(&s, &tb.addr_str("signature"), "bytes", None, Some(6))["value"], json!("4D 45 4D 4D 43 50"));

    // pointers: root → world → player (pointer size follows bitness)
    let world = read(&s, &tb.addr_str("world_root"), "ptr", None, None);
    assert_eq!(hex(&world["value"]), tb.addr("world"));
    assert_eq!(world["bytes"].as_str().unwrap().split(' ').count(), bits as usize / 8);
    let player = read(&s, &format!("0x{:X}", tb.addr("world") + 0x18), "ptr", None, None);
    assert_eq!(hex(&player["value"]), tb.addr("player"));

    // arrays
    let arr = read(&s, &tb.addr_str("player_health"), "i32", Some(2), None);
    assert_eq!(arr["values"][0]["value"], json!(250));
    assert_eq!(arr["values"][1]["value"], json!(75));
    assert_eq!(hex(&arr["values"][1]["address"]), tb.addr("player_armor"));

    // read_bytes
    let rb = s.do_read_bytes(ReadBytesParams { address: tb.addr_str("signature"), size: 16, offsets: None }).unwrap();
    assert!(rb["hex"].as_str().unwrap().starts_with("4D 45 4D 4D 43 50 DE AD BE EF 13 37"));
    assert_eq!(rb["unreadable_bytes"], json!(0));

    // errors: unmapped address
    let e = s
        .do_read_value(ReadValueParams { address: "0x0".into(), value_type: "i32".into(), count: None, length: None, big_endian: None, offsets: None })
        .unwrap_err();
    assert!(matches!(e, MemError::Read { .. }), "{e}");
    assert!(e.to_string().contains("not mapped"), "{e}");

    // partial read across the end of a readable region followed by an unreadable one
    let p = s.process().unwrap();
    let regions = p.regions().unwrap();
    let edge = regions
        .iter()
        .filter(|r| r.readable())
        .find(|r| p.query(r.end()).is_none_or(|n| !n.readable()))
        .expect("a readable region followed by an unreadable one");
    let rb = s.do_read_bytes(ReadBytesParams { address: format!("0x{:X}", edge.end() - 8), size: 16, offsets: None }).unwrap();
    assert_eq!(rb["unreadable_bytes"], json!(8));
    assert!(rb["hex"].as_str().unwrap().ends_with("?? ?? ?? ?? ?? ?? ?? ??"));

    if bits == 32 {
        let e = s
            .do_read_value(ReadValueParams {
                address: "0x100000000".into(),
                value_type: "i32".into(),
                count: None,
                length: None,
                big_endian: None, offsets: None,
            })
            .unwrap_err();
        assert!(e.to_string().contains("32-bit"), "{e}");
    }

    // process exit is detected
    tb.quit();
    let e = s.do_process_info().unwrap_err();
    assert!(matches!(e, MemError::ProcessExited(_)), "{e}");
}

#[test]
fn x64_target() {
    suite(X64, 64);
}

#[test]
fn x86_wow64_target() {
    suite(X86, 32);
}

#[test]
fn attach_by_name_and_ambiguity() {
    let a = Testbed::spawn(X64);
    let b = Testbed::spawn(X86);
    let s = MemoryServer::new();
    let e = s.do_attach(AttachParams { pid: None, name: Some("testbed".into()) }).unwrap_err();
    match e {
        MemError::Ambiguous { pids, .. } => {
            assert!(pids.contains(&a.pid()) && pids.contains(&b.pid()));
        }
        other => panic!("expected ambiguity, got {other}"),
    }
    let list = s.do_list_processes(ListProcessesParams { filter: Some(a.pid().to_string()), offset: None, limit: None }).unwrap();
    assert_eq!(list["items"][0]["pid"], json!(a.pid()));
}

#[test]
fn denied_and_missing_processes() {
    let s = MemoryServer::new();
    let e = s.do_attach(AttachParams { pid: None, name: Some("lsass.exe".into()) }).unwrap_err();
    assert!(matches!(e, MemError::DeniedProcess(_)), "{e}");
    let e = s.do_attach(AttachParams { pid: Some(4), name: None }).unwrap_err();
    assert!(matches!(e, MemError::DeniedProcess(_)), "{e}");
    let e = s.do_attach(AttachParams { pid: None, name: Some("no-such-process-xyz.exe".into()) }).unwrap_err();
    assert!(matches!(e, MemError::ProcessNotFound(_)), "{e}");
    let e = s.do_process_info().unwrap_err();
    assert!(matches!(e, MemError::NotAttached), "{e}");
}

#[test]
fn detach() {
    let tb = Testbed::spawn(X64);
    let s = attached(&tb);
    assert_eq!(s.do_detach().unwrap()["detached"], json!(tb.pid()));
    assert!(matches!(s.do_process_info().unwrap_err(), MemError::NotAttached));
}

//! Stage 3 integration tests: writes, page protection handling, journal and undo (x64 and x86).
#![cfg(windows)]

mod common;

use std::path::PathBuf;

use common::{Testbed, X64, X86, hex};
use memory_mcp::address::Offset;
use memory_mcp::server::{
    AttachParams, ListWritesParams, ReadBytesParams, ReadValueParams, ResolveAddressParams, UndoWriteParams,
    WriteBytesParams, WriteValueParams,
};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn temp_journal(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("memory-mcp-test-{}-{tag}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn write(s: &MemoryServer, addr: &str, offsets: Option<Vec<Offset>>, ty: &str, value: Value) -> Result<Value, MemError> {
    s.do_write_value(WriteValueParams {
        address: addr.into(),
        offsets,
        value_type: ty.into(),
        value,
        big_endian: None,
        null_terminate: None,
    })
}

fn read(s: &MemoryServer, addr: &str, ty: &str, length: Option<usize>) -> Value {
    s.do_read_value(ReadValueParams {
        address: addr.into(),
        offsets: None,
        value_type: ty.into(),
        count: None,
        length,
        big_endian: None,
    })
    .unwrap()["value"]
        .clone()
}

fn undo(s: &MemoryServer, id: Option<u64>, force: bool) -> Result<Value, MemError> {
    s.do_undo_write(UndoWriteParams { id, force: Some(force) })
}

fn protect_of(s: &MemoryServer, addr: &str) -> String {
    s.do_resolve_address(ResolveAddressParams { address: addr.into(), offsets: None }).unwrap()["region"]["protect"]
        .as_str()
        .unwrap()
        .to_string()
}

fn suite(triple: &str) {
    let mut tb = Testbed::spawn(triple);
    let journal = temp_journal(triple);
    let s = MemoryServer::with_journal(Some(journal.clone()));
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let health = tb.addr_str("health");

    // typed writes, observed by the target itself
    let w = write(&s, &health, None, "i32", json!(999)).unwrap();
    assert_eq!(w["old_value"], json!(100));
    assert_eq!(w["new_value"], json!(999));
    assert_eq!(w["verified"], json!(true));
    assert_eq!(w["protection_changes"], json!([]));
    let health_write = w["write_id"].as_u64().unwrap();
    assert_eq!(tb.cmd("get health"), "999");

    write(&s, &tb.addr_str("speed"), None, "float", json!("3.75")).unwrap();
    assert_eq!(tb.cmd("get speed"), "3.75");
    write(&s, &tb.addr_str("precision"), None, "double", json!(2.5)).unwrap();
    assert_eq!(tb.cmd("get precision"), "2.5");
    write(&s, &tb.addr_str("gold"), None, "u64", json!("0xFFFFFFFF")).unwrap();
    assert_eq!(tb.cmd("get gold"), "4294967295");
    // signed value into unsigned type, array write
    write(&s, &tb.addr_str("player_health"), None, "i32", json!([-1, 11])).unwrap();
    assert_eq!(tb.cmd("get player_health"), "-1");
    assert_eq!(tb.cmd("get player_armor"), "11");

    // write through a pointer chain: [[root]+0x18]+0 = player.health
    let base = hex(&s.do_resolve_address(ResolveAddressParams { address: "testbed.exe".into(), offsets: None }).unwrap()["address"]);
    let root = format!("testbed.exe+0x{:X}", tb.addr("world_root") - base);
    write(&s, &root, Some(vec![Offset::Num(0x18), Offset::Num(0)]), "i32", json!(1)).unwrap();
    assert_eq!(tb.cmd("get player_health"), "1");

    // pointer value given as an address expression (pointer width follows bitness)
    let health_expr = format!("testbed.exe+0x{:X}", tb.addr("health") - base);
    let w = write(&s, &root, None, "ptr", json!(health_expr)).unwrap();
    assert_eq!(hex(&w["new_value"]), tb.addr("health"));
    assert_eq!(w["size"], json!(if tb.bits() == 32 { 4 } else { 8 }));
    assert_eq!(read(&s, &format!("[{root}]"), "i32", None), json!(999));
    undo(&s, None, false).unwrap(); // restores the world pointer
    assert_eq!(hex(&read(&s, &root, "ptr", None)), tb.addr("world"));

    // range / argument errors
    let e = write(&s, &health, None, "u8", json!(300)).unwrap_err().to_string();
    assert!(e.contains("does not fit"), "{e}");
    let e = write(&s, "0x0", None, "i32", json!(1)).unwrap_err().to_string();
    assert!(e.contains("unreadable") && e.contains("nothing was written"), "{e}");

    // read-only data (.rdata): protection lifted temporarily and restored
    let wname = tb.addr_str("wname");
    assert_eq!(protect_of(&s, &wname), "r--");
    let w = write(&s, &wname, None, "wstring", json!("Hack")).unwrap();
    assert_eq!(w["protection_changes"][0]["original"], json!("r--"), "{w}");
    assert_eq!(read(&s, &wname, "wstring", Some(8)), json!("Hack"));
    assert_eq!(protect_of(&s, &wname), "r--", "protection restored");

    let sig = tb.addr_str("signature");
    let w = s.do_write_bytes(WriteBytesParams { address: sig.clone(), offsets: None, bytes: "\\xAA\\xBB".into() }).unwrap();
    assert_eq!(w["old_bytes"], json!("4D 45"));
    let sig_write = w["write_id"].as_u64().unwrap();
    let rb = s.do_read_bytes(ReadBytesParams { address: sig.clone(), offsets: None, size: 4 }).unwrap();
    assert_eq!(rb["hex"], json!("AA BB 4D 4D"));
    undo(&s, Some(sig_write), false).unwrap();
    let rb = s.do_read_bytes(ReadBytesParams { address: sig.clone(), offsets: None, size: 4 }).unwrap();
    assert_eq!(rb["hex"], json!("4D 45 4D 4D"));
    assert_eq!(protect_of(&s, &sig), "r--");

    // executable code: rewrite the first byte of an export with itself
    let code = "kernel32.dll!GetProcAddress";
    let first = s.do_read_bytes(ReadBytesParams { address: code.into(), offsets: None, size: 1 }).unwrap()["hex"]
        .as_str()
        .unwrap()
        .to_string();
    let w = s.do_write_bytes(WriteBytesParams { address: code.into(), offsets: None, bytes: first }).unwrap();
    assert_eq!(w["verified"], json!(true));
    assert!(w["protection_changes"][0]["original"].as_str().unwrap().ends_with('x'), "{w}");
    assert!(protect_of(&s, code).ends_with('x'));

    // undo by id, double undo
    let u = undo(&s, Some(health_write), false).unwrap();
    assert_eq!(u["restored_bytes"], json!(value_hex_i32(100)));
    assert_eq!(tb.cmd("get health"), "100");
    let e = undo(&s, Some(health_write), false).unwrap_err().to_string();
    assert!(e.contains("already undone"), "{e}");

    // conflict detection: the target changes the value after our write
    let id = write(&s, &health, None, "i32", json!(5)).unwrap()["write_id"].as_u64().unwrap();
    assert_eq!(tb.cmd("set health 7"), "ok");
    let e = undo(&s, Some(id), false).unwrap_err().to_string();
    assert!(e.contains("changed since"), "{e}");
    let u = undo(&s, Some(id), true).unwrap();
    assert_eq!(u["forced"], json!(true));
    assert_eq!(tb.cmd("get health"), "100");

    // journal
    let list = s.do_list_writes(ListWritesParams { all_processes: None, include_undone: None, offset: None, limit: Some(1000) }).unwrap();
    let total = list["total"].as_u64().unwrap();
    assert_eq!(list["items"][0]["id"], json!(id), "newest first");
    let active = s
        .do_list_writes(ListWritesParams { all_processes: None, include_undone: Some(false), offset: None, limit: Some(1000) })
        .unwrap();
    assert_eq!(active["total"].as_u64().unwrap(), total - 4, "4 writes were undone");
    assert_eq!(list["journal_file"], json!(journal.display().to_string()));
    let lines: Vec<Value> = std::fs::read_to_string(&journal)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.iter().filter(|l| l["event"] == "write").count() as u64, total);
    assert_eq!(lines.iter().filter(|l| l["event"] == "undo").count(), 4);

    tb.quit();
    let _ = std::fs::remove_file(&journal);
}

fn value_hex_i32(v: i32) -> String {
    v.to_le_bytes().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

#[test]
fn x64_writes() {
    suite(X64);
}

#[test]
fn x86_writes() {
    suite(X86);
}

#[test]
fn undo_is_bound_to_the_process() {
    let a = Testbed::spawn(X64);
    let b = Testbed::spawn(X64);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(a.pid()), name: None }).unwrap();
    let id = write(&s, &a.addr_str("health"), None, "i32", json!(1)).unwrap()["write_id"].as_u64().unwrap();
    s.do_attach(AttachParams { pid: Some(b.pid()), name: None }).unwrap();
    let e = undo(&s, Some(id), false).unwrap_err().to_string();
    assert!(e.contains(&format!("pid {}", a.pid())), "{e}");
    let e = undo(&s, None, false).unwrap_err().to_string();
    assert!(e.contains("no active writes"), "{e}");
    let all = s.do_list_writes(ListWritesParams { all_processes: Some(true), include_undone: None, offset: None, limit: None }).unwrap();
    assert_eq!(all["total"], json!(1));
    let mine = s.do_list_writes(ListWritesParams { all_processes: None, include_undone: None, offset: None, limit: None }).unwrap();
    assert_eq!(mine["total"], json!(0));
}

//! Stage 8 integration tests: pointer scan and rescan across a process restart (x64 and x86).
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::address::Offset;
use memory_mcp::server::{
    AttachParams, PointerCloseParams, PointerRescanParams, PointerResultsParams, PointerScanParams, ReadValueParams,
    ResolveAddressParams,
};
use memory_mcp::structs::FieldOffset;
use memory_mcp::MemoryServer;
use serde_json::{Value, json};

fn scan_params(target: &str, depth: usize) -> PointerScanParams {
    PointerScanParams {
        target: target.into(),
        offsets: None,
        max_depth: Some(depth),
        max_offset: None,
        modules: None,
        max_results: None,
        max_nodes: None,
        include_mapped: None,
        alignment: None,
    }
}

fn root_rel(s: &MemoryServer, tb: &Testbed) -> u64 {
    let base = hex(&s.do_resolve_address(ResolveAddressParams { address: "testbed.exe".into(), offsets: None }).unwrap()["address"]);
    tb.addr("world_root") - base
}

fn all_chains(s: &MemoryServer, id: u64) -> Vec<Value> {
    s.do_pointer_results(PointerResultsParams { ptr_scan_id: id, offset: None, limit: Some(1000), verify: Some(true) }).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone()
}

fn has_chain(chains: &[Value], base: &str, offsets: &[&str]) -> bool {
    chains.iter().any(|c| {
        c["base"].as_str().unwrap().eq_ignore_ascii_case(base)
            && c["offsets"].as_array().unwrap().iter().map(|o| o.as_str().unwrap()).collect::<Vec<_>>() == offsets
    })
}

fn suite(triple: &str) {
    let tb1 = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb1.pid()), name: None }).unwrap();
    let rel = root_rel(&s, &tb1);
    let base = format!("testbed.exe+0x{rel:X}");

    // player.health: [[root]+0x18]+0x0
    let v = s.do_pointer_scan(scan_params(&tb1.addr_str("player_health"), 3)).unwrap();
    let id = v["ptr_scan_id"].as_u64().unwrap();
    assert!(v["stats"]["pointers"].as_u64().unwrap() > 0, "{v}");
    assert!(v["total"].as_u64().unwrap() >= 1, "{v}");
    let chains = all_chains(&s, id);
    assert!(has_chain(&chains, &base, &["0x18", "0x0"]), "{chains:#?}");
    assert!(chains.iter().all(|c| c["valid"] == json!(true)), "every chain resolves to the target now");
    // the chain is usable as address + offsets
    let c = chains.iter().find(|c| has_chain(std::slice::from_ref(c), &base, &["0x18", "0x0"])).unwrap();
    let read = |addr: &str, offs: Option<Vec<Offset>>| {
        s.do_read_value(ReadValueParams { address: addr.into(), offsets: offs, value_type: "i32".into(), count: None, length: None, big_endian: None })
            .unwrap()["value"]
            .clone()
    };
    assert_eq!(read(c["expression"].as_str().unwrap(), None), json!(250));
    let offs: Vec<Offset> = c["offsets"].as_array().unwrap().iter().map(|o| Offset::Expr(o.as_str().unwrap().into())).collect();
    assert_eq!(read(&base, Some(offs)), json!(250));

    // depth 3 chain through the linked list: [[[root]+0x18]+0x30]+0x0 == sidekick.health
    let v = s.do_pointer_scan(scan_params(&tb1.addr_str("sidekick"), 3)).unwrap();
    let side = v["ptr_scan_id"].as_u64().unwrap();
    assert!(has_chain(&all_chains(&s, side), &base, &["0x18", "0x30", "0x0"]));
    // ...not reachable with depth 2 or with max_offset below 0x18
    let v = s.do_pointer_scan(scan_params(&tb1.addr_str("sidekick"), 2)).unwrap();
    assert!(!has_chain(&all_chains(&s, v["ptr_scan_id"].as_u64().unwrap()), &base, &["0x18", "0x30", "0x0"]));
    let mut small = scan_params(&tb1.addr_str("player_health"), 3);
    small.max_offset = Some(FieldOffset::Str("0x10".into()));
    let v = s.do_pointer_scan(small).unwrap();
    assert!(!has_chain(&all_chains(&s, v["ptr_scan_id"].as_u64().unwrap()), &base, &["0x18", "0x0"]));
    let mut only_k32 = scan_params(&tb1.addr_str("player_health"), 3);
    only_k32.modules = Some(vec!["kernel32".into()]);
    let v = s.do_pointer_scan(only_k32).unwrap();
    assert!(!has_chain(&all_chains(&s, v["ptr_scan_id"].as_u64().unwrap()), &base, &["0x18", "0x0"]));
    let mut bad = scan_params(&tb1.addr_str("player_health"), 3);
    bad.modules = Some(vec!["nosuch.dll".into()]);
    assert!(s.do_pointer_scan(bad).unwrap_err().to_string().contains("not loaded"));

    // rescan in the same process keeps everything
    let r = s.do_pointer_rescan(PointerRescanParams { ptr_scan_id: id, target: None, offsets: None }).unwrap();
    assert_eq!(r["removed"], json!(0), "{r}");

    // restart: heap addresses change, the module-relative chain survives
    tb1.quit();
    let tb2 = Testbed::spawn(triple);
    s.do_attach(AttachParams { pid: Some(tb2.pid()), name: None }).unwrap();
    let e = s.do_pointer_rescan(PointerRescanParams { ptr_scan_id: id, target: None, offsets: None }).unwrap_err();
    assert!(e.to_string().contains("pass the new `target`"), "{e}");
    let r = s
        .do_pointer_rescan(PointerRescanParams { ptr_scan_id: id, target: Some(tb2.addr_str("player_health")), offsets: None })
        .unwrap();
    let after = all_chains(&s, id);
    assert!(has_chain(&after, &base, &["0x18", "0x0"]), "{r}");
    assert!(after.iter().all(|c| c["valid"] == json!(true)), "only working chains remain");
    assert_eq!(r["after"].as_u64().unwrap() as usize, after.len());
    assert_eq!(r["history"].as_array().unwrap().len(), 3, "scan, same-process rescan, rescan after restart");
    let list = s.do_pointer_list().unwrap();
    assert!(list["pointer_scans"].as_array().unwrap().iter().any(|x| x["ptr_scan_id"] == json!(id) && x["pid"] == json!(tb2.pid())));

    s.do_pointer_close(PointerCloseParams { ptr_scan_id: id }).unwrap();
    assert!(s.do_pointer_results(PointerResultsParams { ptr_scan_id: id, offset: None, limit: None, verify: None }).is_err());
}

/// Statistics on a real target: `cargo test --release --test stage8 -- --ignored --nocapture`
#[test]
#[ignore]
fn report_pointer_scan() {
    for triple in [X64, X86] {
        let tb1 = Testbed::spawn(triple);
        let s = MemoryServer::new();
        s.do_attach(AttachParams { pid: Some(tb1.pid()), name: None }).unwrap();
        for depth in [3, 5] {
            let v = s.do_pointer_scan(scan_params(&tb1.addr_str("sidekick"), depth)).unwrap();
            println!(
                "{triple} depth {depth}: {} pointers indexed in {} ms, {} nodes, {} chains in {} ms, truncated: {}",
                v["stats"]["pointers"], v["stats"]["index_ms"], v["stats"]["nodes_visited"], v["total"], v["stats"]["search_ms"], v["stats"]["truncated"]
            );
        }
        let id = s.do_pointer_scan(scan_params(&tb1.addr_str("sidekick"), 4)).unwrap()["ptr_scan_id"].as_u64().unwrap();
        tb1.quit();
        let tb2 = Testbed::spawn(triple);
        s.do_attach(AttachParams { pid: Some(tb2.pid()), name: None }).unwrap();
        let r = s.do_pointer_rescan(PointerRescanParams { ptr_scan_id: id, target: Some(tb2.addr_str("sidekick")), offsets: None }).unwrap();
        println!("{triple} rescan after restart: {} → {} chains; first: {}", r["before"], r["after"], r["preview"][0]["expression"]);
    }
}

#[test]
fn x64_pointer_scan() {
    suite(X64);
}

#[test]
fn x86_pointer_scan() {
    suite(X86);
}

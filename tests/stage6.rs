//! Stage 6 integration tests: Cheat Engine style value scans (first/next scan) on x64 and x86 targets.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{AttachParams, ScanCloseParams, ScanNextParams, ScanResultsParams, ScanStartParams};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn start(ty: &str, cond: Option<&str>, value: Option<Value>) -> ScanStartParams {
    ScanStartParams {
        value_type: ty.into(),
        condition: cond.map(Into::into),
        value,
        value2: None,
        module: None,
        section: None,
        start: None,
        end: None,
        protection: None,
        include_mapped: None,
        alignment: None,
        float_mode: None,
        tolerance: None,
        max_memory_mb: None,
    }
}

fn next(s: &MemoryServer, id: u64, cond: &str, value: Option<Value>) -> Value {
    s.do_scan_next(ScanNextParams { scan_id: id, condition: cond.into(), value, value2: None })
        .unwrap_or_else(|e| panic!("scan_next {cond}: {e}"))
}

/// All candidate addresses of a scan.
fn all(s: &MemoryServer, id: u64) -> Vec<u64> {
    let r = s.do_scan_results(ScanResultsParams { scan_id: id, offset: None, limit: Some(1000) }).unwrap();
    r["items"].as_array().unwrap().iter().map(|i| hex(&i["address"])).collect()
}

fn id(v: &Value) -> u64 {
    v["scan_id"].as_u64().unwrap()
}

fn suite(triple: &str) {
    let mut tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let health = tb.addr("health");

    // classic loop: exact → change → exact → increased → unchanged → decreased_by
    let v = s.do_scan_start(start("i32", None, Some(json!(100)))).unwrap();
    assert_eq!(v["condition"], json!("exact 100"));
    assert!(v["scope"].as_str().unwrap().contains("protection w"), "{v}");
    let scan = id(&v);
    assert!(all(&s, scan).contains(&health) || v["total"].as_u64().unwrap() > 1000);
    tb.cmd("set health 101");
    let v = next(&s, scan, "exact", Some(json!(101)));
    assert!(all(&s, scan).contains(&health), "{v}");
    tb.cmd("set health 150");
    next(&s, scan, "increased", None);
    next(&s, scan, "unchanged", None);
    tb.cmd("set health 140");
    let v = next(&s, scan, "decreased_by", Some(json!(10)));
    assert_eq!(all(&s, scan), [health], "{v}");
    assert!(v["previous_total"].as_u64().unwrap() >= 1);
    assert_eq!(v["preview"][0]["value"], json!(140));
    assert!(v["preview"][0]["symbol"].as_str().unwrap().starts_with("testbed.exe+"));
    let r = s.do_scan_results(ScanResultsParams { scan_id: scan, offset: None, limit: None }).unwrap();
    assert_eq!(r["items"][0]["previous"], json!(140));
    tb.cmd("set health 1");
    let r = s.do_scan_results(ScanResultsParams { scan_id: scan, offset: None, limit: None }).unwrap();
    assert_eq!(r["items"][0]["value"], json!(1), "results show the live value");
    let list = s.do_scan_list().unwrap();
    assert_eq!(list["scans"][0]["history"].as_array().unwrap().len(), 5);

    // unknown initial value in a module's .data, forced to spill to disk
    let mut p = start("i32", Some("unknown"), None);
    p.module = Some("testbed.exe".into());
    p.section = Some(".data".into());
    p.max_memory_mb = Some(0);
    let v = s.do_scan_start(p).unwrap();
    let unknown = id(&v);
    assert!(v["storage"]["disk_bytes"].as_u64().unwrap() > 0, "{v}");
    assert!(v["total"].as_u64().unwrap() > 4);
    tb.cmd("set health 77");
    let v = next(&s, unknown, "changed", None);
    assert!(all(&s, unknown).contains(&health), "{v}");
    next(&s, unknown, "unchanged", None);
    tb.cmd("set health 80");
    next(&s, unknown, "increased_by", Some(json!(3)));
    assert_eq!(all(&s, unknown), [health]);

    // floats: rounded to the typed decimals, then range
    let v = s.do_scan_start(start("float", None, Some(json!("1.5")))).unwrap();
    let fscan = id(&v);
    tb.cmd("set speed 1.55");
    next(&s, fscan, "exact", Some(json!("1.55")));
    assert!(all(&s, fscan).contains(&tb.addr("speed")));
    let v = s
        .do_scan_next(ScanNextParams { scan_id: fscan, condition: "range".into(), value: Some(json!(1.54)), value2: Some(json!(1.56)) })
        .unwrap();
    assert!(all(&s, fscan).contains(&tb.addr("speed")), "{v}");
    // exact mode compares the f32 bit pattern; the fast (memmem) path and the slow path agree
    let mut exact_mode = start("f32", None, Some(json!("1.55")));
    exact_mode.float_mode = Some("exact".into());
    exact_mode.module = Some("testbed.exe".into());
    let v = s.do_scan_start(exact_mode).unwrap();
    assert_eq!(all(&s, id(&v)), [tb.addr("speed")]);
    let v = s.do_scan_start(ScanStartParams { float_mode: Some("exact".into()), module: Some("testbed.exe".into()), ..start("f32", Some("range"), Some(json!("1.55"))) }).unwrap_err();
    assert!(v.to_string().contains("value2"), "{v}");
    tb.cmd("set speed 1.5501");
    let v = next(&s, fscan, "exact", Some(json!("1.55")));
    assert!(all(&s, fscan).contains(&tb.addr("speed")), "rounded mode tolerates 1.5501: {v}");

    // 64-bit range scan on heap+data, unaligned search finds the same value
    let mut p = start("u64", Some("range"), Some(json!("123456789000")));
    p.value2 = Some(json!(123456789100u64));
    let v = s.do_scan_start(p).unwrap();
    assert!(all(&s, id(&v)).contains(&tb.addr("gold")), "{v}");

    // the player's heap value via bigger/smaller + changed
    let v = s.do_scan_start(start("i32", Some("bigger"), Some(json!(249)))).unwrap();
    let heap = id(&v);
    tb.cmd("set player_health 260");
    next(&s, heap, "changed", None);
    next(&s, heap, "smaller", Some(json!(261)));
    assert!(all(&s, heap).contains(&tb.addr("player_health")));

    // errors
    let e = s.do_scan_start(start("utf8", None, Some(json!("x")))).unwrap_err().to_string();
    assert!(e.contains("numeric types only"), "{e}");
    let e = s.do_scan_start(start("i32", Some("changed"), None)).unwrap_err().to_string();
    assert!(e.contains("scan_next"), "{e}");
    let e = s.do_scan_start(start("i32", None, None)).unwrap_err().to_string();
    assert!(e.contains("pass `value`"), "{e}");
    let e = s.do_scan_next(ScanNextParams { scan_id: scan, condition: "unknown".into(), value: None, value2: None }).unwrap_err();
    assert!(e.to_string().contains("first scan"), "{e}");

    // close frees the session
    s.do_scan_close(ScanCloseParams { scan_id: unknown }).unwrap();
    let e = s.do_scan_results(ScanResultsParams { scan_id: unknown, offset: None, limit: None }).unwrap_err();
    assert!(e.to_string().contains("no scan with id"), "{e}");
    tb.quit();
}

#[test]
fn x64_value_scans() {
    suite(X64);
}

#[test]
fn x86_value_scans() {
    suite(X86);
}

#[test]
fn scans_are_bound_to_their_process() {
    let a = Testbed::spawn(X64);
    let b = Testbed::spawn(X86);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(a.pid()), name: None }).unwrap();
    let mut p = start("i32", None, Some(json!(100)));
    p.module = Some("testbed.exe".into());
    let scan = id(&s.do_scan_start(p).unwrap());
    s.do_attach(AttachParams { pid: Some(b.pid()), name: None }).unwrap();
    let e = s.do_scan_next(ScanNextParams { scan_id: scan, condition: "unchanged".into(), value: None, value2: None }).unwrap_err();
    assert!(matches!(e, MemError::InvalidArg(_)) && e.to_string().contains(&format!("pid {}", a.pid())), "{e}");
}

/// `cargo test --release --test stage6 -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_unknown_scan_1gib() {
    let mut tb = Testbed::spawn(X64);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let buf = u64::from_str_radix(tb.cmd("alloc 1024").trim_start_matches("0x"), 16).unwrap();
    let range = |mut p: ScanStartParams| {
        p.start = Some(format!("0x{buf:X}"));
        p.end = Some(format!("0x{:X}", buf + (1024 << 20)));
        p
    };
    for (name, p) in [
        ("exact i32", range(start("i32", None, Some(json!(12345))))),
        ("range f32", {
            let mut p = range(start("f32", Some("range"), Some(json!(0.5))));
            p.value2 = Some(json!(1.5));
            p
        }),
        ("unknown i32", range(start("i32", Some("unknown"), None))),
        ("unknown RAM", ScanStartParams { max_memory_mb: Some(4096), ..range(start("i32", Some("unknown"), None)) }),
    ] {
        let v = s.do_scan_start(p).unwrap();
        println!(
            "{name:12} first: {:>9} candidates in {:>5} ms (mem {} MiB, disk {} MiB)",
            v["total"],
            v["elapsed_ms"],
            v["storage"]["memory_bytes"].as_u64().unwrap() >> 20,
            v["storage"]["disk_bytes"].as_u64().unwrap() >> 20
        );
        let n = next(&s, id(&v), "unchanged", None);
        println!("{name:12} next:  {:>9} candidates in {:>5} ms", n["total"], n["elapsed_ms"]);
        s.do_scan_close(ScanCloseParams { scan_id: id(&v) }).unwrap();
    }
}

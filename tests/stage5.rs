//! Stage 5 integration tests: AOB scanning, signature notations, scopes, sig()/rip()/abs32(), aob_resolve.
#![cfg(windows)]

mod common;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{AobResolveParams, AobScanParams, AttachParams, ReadValueParams, WriteValueParams};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn scan_params(pattern: &str) -> AobScanParams {
    AobScanParams {
        pattern: pattern.into(),
        mask: None,
        module: Some("testbed.exe".into()),
        section: None,
        start: None,
        end: None,
        protection: None,
        alignment: None,
        limit: None,
    }
}

fn resolve_params(pattern: &str) -> AobResolveParams {
    AobResolveParams {
        pattern: pattern.into(),
        mask: None,
        module: Some("testbed.exe".into()),
        section: None,
        protection: None,
        index: None,
        offset: None,
        mode: None,
        disp_offset: None,
        insn_len: None,
    }
}

fn scan(s: &MemoryServer, prm: AobScanParams) -> Value {
    let pat = prm.pattern.clone();
    s.do_aob_scan(prm).unwrap_or_else(|e| panic!("{pat}: {e}"))
}

fn addrs(v: &Value) -> Vec<u64> {
    v["matches"].as_array().unwrap().iter().map(|m| hex(&m["address"])).collect()
}

fn read_i32(s: &MemoryServer, addr: &str) -> Value {
    s.do_read_value(ReadValueParams {
        address: addr.into(),
        offsets: None,
        value_type: "i32".into(),
        count: None,
        length: None,
        big_endian: None,
    })
    .unwrap_or_else(|e| panic!("{addr}: {e}"))["value"]
        .clone()
}

fn suite(triple: &str) {
    let mut tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let sig = tb.addr("signature");
    let health = tb.addr("health");
    let x86 = tb.bits() == 32;

    // every notation finds the same unique match
    let v = scan(&s, scan_params("4D 45 4D 4D 43 50 DE AD ?? EF"));
    assert_eq!(addrs(&v), [sig], "{v}");
    assert!(v["matches"][0]["symbol"].as_str().unwrap().starts_with("testbed.exe+"));
    assert_eq!(v["matches"][0]["bytes"], json!("4D 45 4D 4D 43 50 DE AD BE EF"));
    assert_eq!(v["pattern"], json!("4D 45 4D 4D 43 50 DE AD ?? EF"));
    for p in ["4D454D4D4350DEAD??EF", "4D 45 * 4D 43 50 DE AD BE EF", "4? 45 4D 4D 4? 50 DE AD", "str:\"MEMMCP\"", "0x4D, 0x45, 0x4D, 0x4D, 0x43, 0x50"] {
        assert_eq!(addrs(&scan(&s, scan_params(p))), [sig], "{p}");
    }
    let mut code_style = scan_params("\\x4D\\x45\\x00\\x4D\\x43\\x50\\xDE");
    code_style.mask = Some("xx?xxxx".into());
    assert_eq!(addrs(&scan(&s, code_style)), [sig]);
    assert_eq!(addrs(&scan(&s, scan_params("wstr:\"Testbed\""))), [tb.addr("wname")]);

    // scopes
    let in_section = |sec: &str| {
        let mut p = scan_params("str:MEMMCP");
        p.section = Some(sec.into());
        s.do_aob_scan(p)
    };
    assert_eq!(addrs(&in_section(".rdata").unwrap()), [sig]);
    assert_eq!(in_section(".text").unwrap()["count"], json!(0));
    let e = in_section(".nope").unwrap_err().to_string();
    assert!(e.contains("available:") && e.contains(".text"), "{e}");
    let mut code_only = scan_params("str:MEMMCP");
    code_only.protection = Some("x".into());
    assert_eq!(scan(&s, code_only)["count"], json!(0));
    let mut after = scan_params("str:MEMMCP");
    after.start = Some(format!("0x{:X}", sig + 1));
    assert_eq!(scan(&s, after)["count"], json!(0));
    let mut whole = scan_params("str:MEMMCP");
    whole.module = None;
    assert!(addrs(&scan(&s, whole)).contains(&sig));
    let mut many = scan_params("00 00 00 00");
    many.limit = Some(3);
    let v = scan(&s, many);
    assert_eq!(v["count"], json!(3));
    assert_eq!(v["truncated"], json!(true));
    let mut bad = scan_params("str:MEMMCP");
    bad.module = None;
    bad.section = Some(".text".into());
    assert!(s.do_aob_scan(bad).unwrap_err().to_string().contains("requires `module`"));
    let mut missing = scan_params("str:MEMMCP");
    missing.module = Some("nosuch.dll".into());
    assert!(s.do_aob_scan(missing).unwrap_err().to_string().contains("not loaded"));

    // aob_resolve: rip-relative operand → HEALTH, with an equivalent expression
    let mut r = resolve_params("CA FE BA BE 51 6E 48 8B 05");
    r.offset = Some(6);
    r.mode = Some("rip".into());
    let v = s.do_aob_resolve(r).unwrap();
    assert_eq!(hex(&v["address"]), health, "{v}");
    assert_eq!(hex(&v["match"]), tb.addr("patch"));
    let expr = v["expression"].as_str().unwrap().to_string();
    assert_eq!(expr, "rip(sig(\"CA FE BA BE 51 6E 48 8B 05\", \"testbed.exe\")+0x6, 0x3, 0x7)");
    assert_eq!(read_i32(&s, &expr), json!(100));
    assert_eq!(v["trace"].as_array().unwrap().len(), 3);

    // abs32 operand (meaningful on x86; on x64 it is the truncated address)
    let mut r = resolve_params("CA FE BA BE 51 6E");
    r.offset = Some(0xD);
    r.mode = Some("abs32".into());
    r.disp_offset = Some(1);
    let v = s.do_aob_resolve(r).unwrap();
    assert_eq!(hex(&v["address"]), health & 0xFFFF_FFFF);
    if x86 {
        assert_eq!(read_i32(&s, v["expression"].as_str().unwrap()), json!(100));
    }

    // ptr mode reads a pointer-sized value at the match
    let mut r = resolve_params("str:MEMMCP");
    r.mode = Some("ptr".into());
    let v = s.do_aob_resolve(r).unwrap();
    let expect = if x86 { 0x4D4D_454D } else { 0xADDE_5043_4D4D_454D };
    assert_eq!(hex(&v["address"]), expect);

    // uniqueness and index
    let e = s.do_aob_resolve(resolve_params("00 00 00 00")).unwrap_err().to_string();
    assert!(e.contains("pass `index`"), "{e}");
    let mut idx = resolve_params("00 00 00 00");
    idx.index = Some(2);
    let v = s.do_aob_resolve(idx).unwrap();
    assert_eq!(v["expression"], Value::Null, "no expression for indexed matches");
    let e = s.do_aob_resolve(resolve_params("DE AD C0 DE 12 34 56 78 9A")).unwrap_err().to_string();
    assert!(e.contains("not found in testbed.exe"), "{e}");

    // functions straight in expressions (reads and writes)
    assert_eq!(read_i32(&s, "rip(sig(\"CA FE BA BE 51 6E\", testbed.exe)+6)"), json!(100));
    assert_eq!(read_i32(&s, "rip(sig(\"\\xCA\\xFE\\x00\\xBE\", \"xx?x\", \"testbed.exe\", \".data\")+6, 3, 7)"), json!(100));
    if x86 {
        assert_eq!(read_i32(&s, "abs32(sig(\"CA FE BA BE 51 6E\", testbed.exe)+0xD, 1)"), json!(100));
    }
    s.do_write_value(WriteValueParams {
        address: "rip(sig(\"CA FE BA BE 51 6E\", testbed.exe)+6)".into(),
        offsets: None,
        value_type: "i32".into(),
        value: json!(555),
        big_endian: None,
        null_terminate: None,
    })
    .unwrap();
    assert_eq!(tb.cmd("get health"), "555");
    let e = s
        .do_read_value(ReadValueParams {
            address: "sig(\"00 00 00 00\", testbed.exe)".into(),
            offsets: None,
            value_type: "i32".into(),
            count: None,
            length: None,
            big_endian: None,
        })
        .unwrap_err();
    assert!(matches!(e, MemError::BadAddress { .. }) && e.to_string().contains("not unique"), "{e}");
}

#[test]
fn x64_signatures() {
    suite(X64);
}

#[test]
fn x86_signatures() {
    suite(X86);
}

/// Throughput check over ~1 GiB of private memory: `cargo test --release --test stage5 -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_scan_1gib() {
    let mut tb = Testbed::spawn(X64);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let buf = tb.cmd("alloc 1024");
    let base = u64::from_str_radix(buf.trim_start_matches("0x"), 16).unwrap();
    for (name, pattern) in [("rare anchor", "4D 45 4D 4D 43 50 DE AD BE EF 13 37"), ("wildcards", "48 8B ?? ?? ?? ?? 89 ?? 24")] {
        let mut p = scan_params(pattern);
        p.module = None;
        p.start = Some(format!("0x{base:X}"));
        p.end = Some(format!("0x{:X}", base + (1024 << 20)));
        let v = s.do_aob_scan(p).unwrap();
        let mb = v["bytes_scanned"].as_u64().unwrap() as f64 / (1u64 << 20) as f64;
        let ms = v["elapsed_ms"].as_u64().unwrap().max(1) as f64;
        println!("{name:12} {mb:7.0} MiB in {ms:6.0} ms = {:7.0} MiB/s, {} matches", mb / ms * 1000.0, v["count"]);
    }
    let mut whole = scan_params("4D 45 4D 4D 43 50 DE AD BE EF 13 37");
    whole.module = None;
    let v = s.do_aob_scan(whole).unwrap();
    println!(
        "whole process: {:.0} MiB in {} ms, {} matches",
        v["bytes_scanned"].as_u64().unwrap() as f64 / (1u64 << 20) as f64,
        v["elapsed_ms"],
        v["count"]
    );
}

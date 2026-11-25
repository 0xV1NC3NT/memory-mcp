//! Stage 7 integration tests: freezing and watching values in a live process (x64 and x86).
#![cfg(windows)]

mod common;

use std::time::{Duration, Instant};

use common::{Testbed, X64, X86, hex};
use memory_mcp::address::Offset;
use memory_mcp::server::{
    AttachParams, FreezeParams, ResolveAddressParams, UnfreezeParams, UnwatchParams, WatchParams, WatchReadParams,
};
use memory_mcp::MemoryServer;
use serde_json::{Value, json};

fn freeze(addr: &str, ty: &str, value: Option<Value>) -> FreezeParams {
    FreezeParams {
        address: addr.into(),
        offsets: None,
        value_type: ty.into(),
        value,
        length: None,
        mode: None,
        interval_ms: Some(5),
        re_resolve: None,
    }
}

fn watch(addr: &str, ty: &str) -> WatchParams {
    WatchParams {
        address: addr.into(),
        offsets: None,
        value_type: ty.into(),
        length: None,
        interval_ms: Some(5),
        max_events: None,
        re_resolve: None,
    }
}

/// Polls `f` until it returns true (5 s timeout).
fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn suite(triple: &str) {
    let mut tb = Testbed::spawn(triple);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let health = tb.addr_str("health");

    // freeze at a new value: the target cannot change it
    let f = s.do_freeze(freeze(&health, "i32", Some(json!(1234)))).unwrap();
    let fid = f["freeze_id"].as_u64().unwrap();
    assert_eq!(f["original"], json!(100));
    assert!(f["symbol"].as_str().unwrap().starts_with("testbed.exe+"));
    eventually("frozen value", || tb.cmd("get health") == "1234");
    tb.cmd("set health 5");
    eventually("restore after change", || tb.cmd("get health") == "1234");
    let list = s.do_list_freezes().unwrap();
    assert!(list["freezes"][0]["writes"].as_u64().unwrap() >= 2, "{list}");
    assert_eq!(list["freezes"][0]["running"], json!(true));
    // unfreeze with restore puts the original value back; afterwards the target is free again
    let u = s.do_unfreeze(UnfreezeParams { freeze_id: Some(fid), all: None, restore: Some(true) }).unwrap();
    assert_eq!(u["stopped"][0]["running"], json!(false));
    assert_eq!(tb.cmd("get health"), "100");
    tb.cmd("set health 6");
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(tb.cmd("get health"), "6");

    // freeze the current value through a pointer chain (re-resolved every tick)
    let base = hex(&s.do_resolve_address(ResolveAddressParams { address: "testbed.exe".into(), offsets: None }).unwrap()["address"]);
    let root = format!("testbed.exe+0x{:X}", tb.addr("world_root") - base);
    let mut p = freeze(&root, "i32", None);
    p.offsets = Some(vec![Offset::Num(0x18), Offset::Num(4)]);
    let f = s.do_freeze(p).unwrap();
    assert_eq!(f["re_resolve"], json!(true));
    assert_eq!(f["value"], json!(75));
    assert_eq!(hex(&f["address"]), tb.addr("player_armor"));
    tb.cmd("set player_armor 1");
    eventually("armor restored", || tb.cmd("get player_armor") == "75");

    // no_decrease: increases are allowed, drops are undone
    let mut p = freeze(&tb.addr_str("player_health"), "i32", Some(json!(300)));
    p.mode = Some("no_decrease".into());
    s.do_freeze(p).unwrap();
    eventually("raised to 300", || tb.cmd("get player_health") == "300");
    tb.cmd("set player_health 400");
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(tb.cmd("get player_health"), "400");
    tb.cmd("set player_health 10");
    eventually("drop undone", || tb.cmd("get player_health") == "300");

    // freezing a float and a string
    s.do_freeze(freeze(&tb.addr_str("speed"), "float", Some(json!(9.5)))).unwrap();
    eventually("speed", || tb.cmd("get speed") == "9.5");
    s.do_unfreeze(UnfreezeParams { freeze_id: None, all: Some(true), restore: Some(false) }).unwrap();
    assert_eq!(s.do_list_freezes().unwrap()["freezes"], json!([]));

    // watch: every change is recorded in order; since= returns only new ones
    let w = s.do_watch(watch(&health, "i32")).unwrap();
    let wid = w["watch_id"].as_u64().unwrap();
    assert_eq!(w["initial"], json!(6));
    for v in [7, 8, 9] {
        tb.cmd(&format!("set health {v}"));
        eventually("watch saw change", || {
            s.do_watch_read(WatchReadParams { watch_id: wid, since: None, limit: None }).unwrap()["current"] == json!(v)
        });
    }
    let r = s.do_watch_read(WatchReadParams { watch_id: wid, since: None, limit: None }).unwrap();
    let vals: Vec<i64> = r["changes"].as_array().unwrap().iter().map(|c| c["value"].as_i64().unwrap()).collect();
    assert_eq!(vals, [6, 7, 8, 9]);
    let seqs: Vec<u64> = r["changes"].as_array().unwrap().iter().map(|c| c["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, [0, 1, 2, 3]);
    let t: Vec<u64> = r["changes"].as_array().unwrap().iter().map(|c| c["t_ms"].as_u64().unwrap()).collect();
    assert!(t.windows(2).all(|w| w[0] <= w[1]), "timestamps are monotonic");
    let next = r["next_since"].as_u64().unwrap();
    tb.cmd("set health 10");
    eventually("new change", || {
        s.do_watch_read(WatchReadParams { watch_id: wid, since: Some(next), limit: None }).unwrap()["returned"] == json!(1)
    });

    // ring buffer limit
    let mut p = watch(&tb.addr_str("gold"), "u64");
    p.max_events = Some(2);
    let g = s.do_watch(p).unwrap()["watch_id"].as_u64().unwrap();
    for v in 1..=4 {
        tb.cmd(&format!("set gold {v}"));
        eventually("gold change", || {
            s.do_watch_read(WatchReadParams { watch_id: g, since: None, limit: None }).unwrap()["current"] == json!(v)
        });
    }
    let r = s.do_watch_read(WatchReadParams { watch_id: g, since: None, limit: None }).unwrap();
    assert_eq!(r["returned"], json!(2));
    assert_eq!(r["dropped"], json!(3));
    s.do_unwatch(UnwatchParams { watch_id: Some(g), all: None }).unwrap();

    // validation
    assert!(s.do_watch(watch("0x10", "i32")).unwrap_err().to_string().contains("not mapped"));
    let mut bad = freeze(&health, "i32", Some(json!(1)));
    bad.interval_ms = Some(1);
    assert!(s.do_freeze(bad).unwrap_err().to_string().contains("interval_ms"));
    let mut bad = freeze(&tb.addr_str("name"), "utf8", Some(json!("x")));
    bad.mode = Some("no_decrease".into());
    assert!(s.do_freeze(bad).unwrap_err().to_string().contains("numeric"));

    // a freeze and a watch stop by themselves when the process exits
    s.do_freeze(freeze(&health, "i32", Some(json!(1)))).unwrap();
    tb.quit();
    eventually("background stopped on exit", || {
        let f = s.do_list_freezes().unwrap();
        let w = s.do_list_watches().unwrap();
        f["freezes"].as_array().unwrap().iter().all(|x| x["running"] == json!(false))
            && w["watches"].as_array().unwrap().iter().all(|x| x["running"] == json!(false))
    });
    let w = s.do_list_watches().unwrap();
    assert_eq!(w["watches"][0]["stop_reason"], json!("process exited"));
}

#[test]
fn x64_freeze_and_watch() {
    suite(X64);
}

#[test]
fn x86_freeze_and_watch() {
    suite(X86);
}

#[test]
fn detach_and_attach_stop_background_work() {
    let mut a = Testbed::spawn(X64);
    let b = Testbed::spawn(X64);
    let s = MemoryServer::new();
    s.do_attach(AttachParams { pid: Some(a.pid()), name: None }).unwrap();
    s.do_freeze(freeze(&a.addr_str("health"), "i32", Some(json!(42)))).unwrap();
    s.do_watch(watch(&a.addr_str("gold"), "u64")).unwrap();
    let r = s.do_attach(AttachParams { pid: Some(b.pid()), name: None }).unwrap();
    assert_eq!(r["stopped_background"], json!({"freezes": 1, "watches": 1}));
    a.cmd("set health 7");
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(a.cmd("get health"), "7", "freeze no longer active");
    s.do_watch(watch(&b.addr_str("gold"), "u64")).unwrap();
    let d = s.do_detach().unwrap();
    assert_eq!(d["stopped_background"]["watches"], json!(1));
    assert_eq!(s.do_list_watches().unwrap()["watches"], json!([]));
}

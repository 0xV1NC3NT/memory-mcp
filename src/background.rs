//! Background workers: freezing values and watching values for changes.
//! Each worker is a thread with an interruptible sleep; it stops when asked or when the
//! target process exits.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::address::{self, Offset};
use crate::error::{MemError, Result};
use crate::format;
use crate::platform::Process;
use crate::scan::ScanType;
use crate::value::{self, ValueType};

pub const MIN_INTERVAL_MS: u64 = 5;
pub const MAX_INTERVAL_MS: u64 = 60_000;
pub const MAX_EVENTS: usize = 100_000;

/// Interruptible sleep + stop flag.
#[derive(Default)]
pub struct Stopper {
    stopped: Mutex<bool>,
    cv: Condvar,
}

impl Stopper {
    pub fn stop(&self) {
        *self.stopped.lock().unwrap() = true;
        self.cv.notify_all();
    }

    /// Sleeps for `d`; returns true if stopped meanwhile.
    pub fn sleep(&self, d: Duration) -> bool {
        let guard = self.stopped.lock().unwrap();
        let (guard, _) = self.cv.wait_timeout_while(guard, d, |s| !*s).unwrap();
        *guard
    }

    pub fn is_stopped(&self) -> bool {
        *self.stopped.lock().unwrap()
    }
}

/// Where a worker reads/writes: a fixed address, or an expression re-resolved every tick
/// (for pointer chains whose objects may move).
#[derive(Debug, Clone)]
pub struct Target {
    pub expression: String,
    pub offsets: Vec<Offset>,
    pub re_resolve: bool,
    pub address: u64,
}

impl Target {
    fn current(&self, p: &Process) -> Result<u64> {
        if self.re_resolve { address::resolve(p.as_ref(), &self.expression, &self.offsets).map(|r| r.address) } else { Ok(self.address) }
    }
}

pub fn check_interval(ms: u64) -> Result<Duration> {
    if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&ms) {
        return Err(MemError::InvalidArg(format!("interval_ms must be {MIN_INTERVAL_MS}..={MAX_INTERVAL_MS}")));
    }
    Ok(Duration::from_millis(ms))
}

fn stop_reason_json(running: bool, reason: &Option<String>) -> Value {
    json!({ "running": running, "stop_reason": reason })
}

// ---------------------------------------------------------------- freeze

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeMode {
    /// Restore whenever the value differs.
    Exact,
    /// Allow increases, restore when it drops below the frozen value (numeric types).
    NoDecrease,
    /// Allow decreases, restore when it rises above the frozen value (numeric types).
    NoIncrease,
}

impl FreezeMode {
    pub fn parse(s: Option<&str>, numeric: bool) -> Result<Self> {
        let m = match s.map(|s| s.trim().to_ascii_lowercase().replace('-', "_")).as_deref() {
            None | Some("") | Some("exact") => FreezeMode::Exact,
            Some("no_decrease") | Some("allow_increase") => FreezeMode::NoDecrease,
            Some("no_increase") | Some("allow_decrease") => FreezeMode::NoIncrease,
            Some(other) => return Err(MemError::InvalidArg(format!("unknown freeze mode '{other}' (exact|no_decrease|no_increase)"))),
        };
        if m != FreezeMode::Exact && !numeric {
            return Err(MemError::InvalidArg("no_decrease / no_increase need a numeric type".into()));
        }
        Ok(m)
    }

    pub fn name(self) -> &'static str {
        match self {
            FreezeMode::Exact => "exact",
            FreezeMode::NoDecrease => "no_decrease",
            FreezeMode::NoIncrease => "no_increase",
        }
    }
}

#[derive(Debug, Default)]
pub struct FreezeStats {
    pub ticks: u64,
    pub writes: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    pub last_address: u64,
    pub running: bool,
    pub stop_reason: Option<String>,
}

pub struct Freeze {
    pub id: u64,
    pub pid: u32,
    pub target: Target,
    pub ty: ValueType,
    pub bytes: Vec<u8>,
    /// Bytes at the address when the freeze was created (for `restore`).
    pub original: Vec<u8>,
    pub mode: FreezeMode,
    pub interval: Duration,
    pub stats: Arc<Mutex<FreezeStats>>,
    stopper: Arc<Stopper>,
    handle: Option<JoinHandle<()>>,
    process: Process,
}

fn numeric_cmp(st: Option<ScanType>, a: &[u8], b: &[u8]) -> Option<std::cmp::Ordering> {
    let st = st?;
    match (st.decode(a), st.decode(b)) {
        (crate::scan::Num::I(x), crate::scan::Num::I(y)) => Some(x.cmp(&y)),
        (crate::scan::Num::F(x), crate::scan::Num::F(y)) => x.partial_cmp(&y),
        _ => None,
    }
}

impl Freeze {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        id: u64,
        p: Process,
        target: Target,
        ty: ValueType,
        bytes: Vec<u8>,
        original: Vec<u8>,
        mode: FreezeMode,
        interval: Duration,
    ) -> Freeze {
        let stats = Arc::new(Mutex::new(FreezeStats { running: true, last_address: target.address, ..Default::default() }));
        let stopper = Arc::new(Stopper::default());
        let scan_ty = match ty {
            ValueType::Scalar(_) => ScanType::parse(ty.name().as_str(), p.pointer_size()).ok(),
            _ => None,
        };
        let handle = {
            let (p, target, bytes, stats, stopper) = (p.clone(), target.clone(), bytes.clone(), stats.clone(), stopper.clone());
            std::thread::Builder::new()
                .name(format!("freeze-{id}"))
                .spawn(move || {
                    let mut cur = vec![0u8; bytes.len()];
                    loop {
                        if !p.is_alive() {
                            let mut s = stats.lock().unwrap();
                            s.running = false;
                            s.stop_reason = Some("process exited".into());
                            return;
                        }
                        let tick: Result<bool> = (|| {
                            let addr = target.current(&p)?;
                            stats.lock().unwrap().last_address = addr;
                            p.read(addr, &mut cur)?;
                            let restore = match mode {
                                FreezeMode::Exact => cur != bytes,
                                FreezeMode::NoDecrease => numeric_cmp(scan_ty, &cur, &bytes) == Some(std::cmp::Ordering::Less),
                                FreezeMode::NoIncrease => numeric_cmp(scan_ty, &cur, &bytes) == Some(std::cmp::Ordering::Greater),
                            };
                            if restore && p.write(addr, &bytes).is_err() {
                                p.write_force(addr, &bytes)?;
                            }
                            Ok(restore)
                        })();
                        {
                            let mut s = stats.lock().unwrap();
                            s.ticks += 1;
                            match tick {
                                Ok(true) => s.writes += 1,
                                Ok(false) => {}
                                Err(e) => {
                                    s.errors += 1;
                                    s.last_error = Some(e.to_string());
                                }
                            }
                        }
                        if stopper.sleep(interval) {
                            let mut s = stats.lock().unwrap();
                            s.running = false;
                            s.stop_reason.get_or_insert_with(|| "stopped".into());
                            return;
                        }
                    }
                })
                .expect("spawn freeze thread")
        };
        Freeze { id, pid: p.pid(), target, ty, bytes, original, mode, interval, stats, stopper, handle: Some(handle), process: p }
    }

    /// Stops the thread and waits for it; optionally writes back the original bytes.
    pub fn stop(mut self, restore: bool, reason: &str) -> Value {
        self.stats.lock().unwrap().stop_reason.get_or_insert_with(|| reason.to_string());
        self.stopper.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let mut restored = Value::Null;
        if restore {
            let addr = self.stats.lock().unwrap().last_address;
            restored = match self.process.write_force(addr, &self.original) {
                Ok(_) => json!(value::hex_bytes(&self.original)),
                Err(e) => json!(format!("restore failed: {e}")),
            };
        }
        let mut v = self.to_json();
        v["restored"] = restored;
        v
    }

    pub fn to_json(&self) -> Value {
        let ps = self.process.pointer_size();
        let s = self.stats.lock().unwrap();
        let mut v = json!({
            "freeze_id": self.id,
            "pid": self.pid,
            "expression": self.target.expression,
            "re_resolve": self.target.re_resolve,
            "address": format::addr(s.last_address, ps),
            "type": self.ty.name(),
            "value": value::decode(self.ty, &self.bytes, ps, false)["value"],
            "original": value::decode(self.ty, &self.original, ps, false)["value"],
            "mode": self.mode.name(),
            "interval_ms": self.interval.as_millis() as u64,
            "ticks": s.ticks,
            "writes": s.writes,
            "errors": s.errors,
            "last_error": s.last_error,
        });
        if let (Value::Object(o), Value::Object(r)) = (&mut v, stop_reason_json(s.running, &s.stop_reason)) {
            o.extend(r);
        }
        v
    }
}

// ---------------------------------------------------------------- watch

#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub seq: u64,
    pub t_ms: u64,
    pub address: u64,
    pub raw: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct WatchState {
    pub events: VecDeque<WatchEvent>,
    pub next_seq: u64,
    pub dropped: u64,
    pub reads: u64,
    pub errors: u64,
    pub running: bool,
    pub stop_reason: Option<String>,
}

pub struct Watch {
    pub id: u64,
    pub pid: u32,
    pub target: Target,
    pub ty: ValueType,
    pub interval: Duration,
    pub max_events: usize,
    pub state: Arc<Mutex<WatchState>>,
    stopper: Arc<Stopper>,
    handle: Option<JoinHandle<()>>,
    process: Process,
}

impl Watch {
    /// `initial` (read by the caller at `target.address`) becomes event #0 synchronously, so the
    /// starting value is never lost to a race with the first sample.
    pub fn start(id: u64, p: Process, target: Target, ty: ValueType, interval: Duration, max_events: usize, initial: Vec<u8>) -> Watch {
        let started = Instant::now();
        let mut first = WatchState { running: true, next_seq: 1, ..Default::default() };
        first.events.push_back(WatchEvent { seq: 0, t_ms: 0, address: target.address, raw: Some(initial.clone()), error: None });
        let state = Arc::new(Mutex::new(first));
        let stopper = Arc::new(Stopper::default());
        let len = ty.size(p.pointer_size());
        let handle = {
            let (p, target, state, stopper) = (p.clone(), target.clone(), state.clone(), stopper.clone());
            std::thread::Builder::new()
                .name(format!("watch-{id}"))
                .spawn(move || {
                    // Last observation: Ok(bytes) or Err(message); events are recorded on change.
                    let mut last: Option<std::result::Result<Vec<u8>, String>> = Some(Ok(initial));
                    let mut last_addr = target.address;
                    if stopper.sleep(interval) {
                        let mut s = state.lock().unwrap();
                        s.running = false;
                        s.stop_reason.get_or_insert_with(|| "stopped".into());
                        return;
                    }
                    loop {
                        if !p.is_alive() {
                            let mut s = state.lock().unwrap();
                            s.running = false;
                            s.stop_reason = Some("process exited".into());
                            return;
                        }
                        let obs: std::result::Result<(u64, Vec<u8>), String> = (|| {
                            let addr = target.current(&p).map_err(|e| e.to_string())?;
                            let mut buf = vec![0u8; len];
                            p.read(addr, &mut buf).map_err(|e| e.to_string())?;
                            Ok((addr, buf))
                        })();
                        let (addr, now) = match obs {
                            Ok((a, b)) => (a, Ok(b)),
                            Err(e) => (last_addr, Err(e)),
                        };
                        {
                            let mut s = state.lock().unwrap();
                            s.reads += 1;
                            if now.is_err() {
                                s.errors += 1;
                            }
                            if last.as_ref() != Some(&now) || addr != last_addr {
                                let seq = s.next_seq;
                                s.next_seq += 1;
                                let (raw, error) = match &now {
                                    Ok(b) => (Some(b.clone()), None),
                                    Err(e) => (None, Some(e.clone())),
                                };
                                s.events.push_back(WatchEvent { seq, t_ms: started.elapsed().as_millis() as u64, address: addr, raw, error });
                                while s.events.len() > max_events {
                                    s.events.pop_front();
                                    s.dropped += 1;
                                }
                            }
                        }
                        last = Some(now);
                        last_addr = addr;
                        if stopper.sleep(interval) {
                            let mut s = state.lock().unwrap();
                            s.running = false;
                            s.stop_reason.get_or_insert_with(|| "stopped".into());
                            return;
                        }
                    }
                })
                .expect("spawn watch thread")
        };
        Watch { id, pid: p.pid(), target, ty, interval, max_events, state, stopper, handle: Some(handle), process: p }
    }

    pub fn stop(mut self, reason: &str) -> Value {
        self.state.lock().unwrap().stop_reason.get_or_insert_with(|| reason.to_string());
        self.stopper.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.summary()
    }

    fn event_json(&self, e: &WatchEvent) -> Value {
        let ps = self.process.pointer_size();
        let mut v = json!({ "seq": e.seq, "t_ms": e.t_ms, "address": format::addr(e.address, ps) });
        match (&e.raw, &e.error) {
            (Some(raw), _) => {
                let d = value::decode(self.ty, raw, ps, false);
                v["value"] = d["value"].clone();
                if let Some(h) = d.get("hex") {
                    v["hex"] = h.clone();
                }
            }
            (None, err) => {
                v["value"] = Value::Null;
                v["error"] = json!(err);
            }
        }
        v
    }

    pub fn summary(&self) -> Value {
        let ps = self.process.pointer_size();
        let s = self.state.lock().unwrap();
        let current = s.events.back().map(|e| self.event_json(e)["value"].clone());
        let mut v = json!({
            "watch_id": self.id,
            "pid": self.pid,
            "expression": self.target.expression,
            "re_resolve": self.target.re_resolve,
            "address": format::addr(s.events.back().map(|e| e.address).unwrap_or(self.target.address), ps),
            "type": self.ty.name(),
            "interval_ms": self.interval.as_millis() as u64,
            "max_events": self.max_events,
            "events": s.next_seq,
            "dropped": s.dropped,
            "reads": s.reads,
            "errors": s.errors,
            "current": current,
        });
        if let (Value::Object(o), Value::Object(r)) = (&mut v, stop_reason_json(s.running, &s.stop_reason)) {
            o.extend(r);
        }
        v
    }

    /// Events with `seq >= since`, oldest first, at most `limit`.
    pub fn read(&self, since: u64, limit: usize) -> Value {
        let events: Vec<Value> = {
            let s = self.state.lock().unwrap();
            s.events.iter().filter(|e| e.seq >= since).take(limit).cloned().collect::<Vec<_>>()
        }
        .iter()
        .map(|e| self.event_json(e))
        .collect();
        let next = events.last().and_then(|e| e["seq"].as_u64()).map(|s| s + 1).unwrap_or(since);
        let mut v = self.summary();
        v["returned"] = json!(events.len());
        v["next_since"] = json!(next);
        v["changes"] = json!(events);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;
    use crate::value::Scalar;

    fn mock() -> Process {
        let mut m = MockProcess::new(Arch::X64);
        m.map(0x1000, 100i32.to_le_bytes().to_vec());
        Arc::new(m)
    }

    fn fixed(addr: u64) -> Target {
        Target { expression: format!("0x{addr:X}"), offsets: vec![], re_resolve: false, address: addr }
    }

    fn wait_until(mut f: impl FnMut() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(5), "timeout");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn get(p: &Process) -> i32 {
        let mut b = [0u8; 4];
        p.read(0x1000, &mut b).unwrap();
        i32::from_le_bytes(b)
    }

    #[test]
    fn stopper_wakes_immediately() {
        let s = Arc::new(Stopper::default());
        let s2 = s.clone();
        let t = Instant::now();
        let h = std::thread::spawn(move || s2.sleep(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(20));
        s.stop();
        assert!(h.join().unwrap());
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(s.is_stopped());
    }

    #[test]
    fn freeze_modes() {
        let p = mock();
        let i32t = ValueType::Scalar(Scalar::I32);
        let f = Freeze::start(1, p.clone(), fixed(0x1000), i32t, 500i32.to_le_bytes().to_vec(), 100i32.to_le_bytes().to_vec(), FreezeMode::Exact, Duration::from_millis(5));
        wait_until(|| get(&p) == 500);
        p.write(0x1000, &7i32.to_le_bytes()).unwrap();
        wait_until(|| get(&p) == 500);
        let v = f.stop(true, "test");
        assert!(v["writes"].as_u64().unwrap() >= 2);
        assert_eq!(v["running"], json!(false));
        assert_eq!(get(&p), 100, "restored original");

        let f = Freeze::start(2, p.clone(), fixed(0x1000), i32t, 300i32.to_le_bytes().to_vec(), vec![0; 4], FreezeMode::NoDecrease, Duration::from_millis(5));
        wait_until(|| get(&p) == 300);
        p.write(0x1000, &400i32.to_le_bytes()).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(get(&p), 400, "increase allowed");
        p.write(0x1000, &10i32.to_le_bytes()).unwrap();
        wait_until(|| get(&p) == 300);
        f.stop(false, "test");
        assert!(FreezeMode::parse(Some("no_decrease"), false).is_err());
    }

    #[test]
    fn watch_records_changes_and_drops_old_events() {
        let p = mock();
        let w = Watch::start(1, p.clone(), fixed(0x1000), ValueType::Scalar(Scalar::I32), Duration::from_millis(2), 3, 100i32.to_le_bytes().to_vec());
        assert_eq!(w.state.lock().unwrap().next_seq, 1, "initial value recorded synchronously");
        for v in [1, 2, 3, 4] {
            p.write(0x1000, &(v as i32).to_le_bytes()).unwrap();
            let want = v + 1;
            wait_until(|| w.state.lock().unwrap().next_seq == want);
        }
        let r = w.read(0, 100);
        let vals: Vec<i64> = r["changes"].as_array().unwrap().iter().map(|e| e["value"].as_i64().unwrap()).collect();
        assert_eq!(vals, [2, 3, 4], "only the newest max_events are kept");
        assert_eq!(r["dropped"], json!(2));
        assert_eq!(r["current"], json!(4));
        let r2 = w.read(r["next_since"].as_u64().unwrap(), 100);
        assert_eq!(r2["returned"], json!(0));
        let s = w.stop("test");
        assert_eq!(s["running"], json!(false));
    }

    #[test]
    fn interval_bounds() {
        assert!(check_interval(1).is_err());
        assert!(check_interval(100).is_ok());
        assert!(check_interval(MAX_INTERVAL_MS + 1).is_err());
    }
}

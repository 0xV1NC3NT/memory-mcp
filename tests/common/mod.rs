#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

pub const X64: &str = "x86_64-pc-windows-msvc";
pub const X86: &str = "i686-pc-windows-msvc";

/// Builds the testbed for `triple` once per test binary and returns the exe path.
pub fn testbed_exe(triple: &str) -> PathBuf {
    static BUILT: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    let map = BUILT.get_or_init(Default::default);
    let mut map = map.lock().unwrap();
    if let Some(p) = map.get(triple) {
        return p.clone();
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "testbed", "--target", triple])
        .current_dir(&root)
        .status()
        .expect("run cargo");
    assert!(status.success(), "failed to build testbed for {triple} (is the rustup target installed?)");
    let exe = root.join("target").join(triple).join("debug").join("testbed.exe");
    assert!(exe.exists(), "{exe:?} missing");
    map.insert(triple.into(), exe.clone());
    exe
}

pub struct Testbed {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pub info: Value,
}

impl Testbed {
    pub fn spawn(triple: &str) -> Self {
        let mut child = Command::new(testbed_exe(triple))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn testbed");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let info: Value = serde_json::from_str(&line).expect("testbed json");
        Self { child, stdin, stdout, info }
    }

    pub fn pid(&self) -> u32 {
        self.info["pid"].as_u64().unwrap() as u32
    }

    pub fn bits(&self) -> u64 {
        self.info["bits"].as_u64().unwrap()
    }

    pub fn addr(&self, field: &str) -> u64 {
        let s = self.info[field].as_str().unwrap_or_else(|| panic!("no field {field}"));
        u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
    }

    pub fn addr_str(&self, field: &str) -> String {
        format!("0x{:X}", self.addr(field))
    }

    pub fn cmd(&mut self, c: &str) -> String {
        writeln!(self.stdin, "{c}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        line.trim().to_string()
    }

    /// Asks the testbed to exit and waits for it.
    pub fn quit(mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

impl Drop for Testbed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Parses a `0x…` hex string from a JSON value.
pub fn hex(v: &Value) -> u64 {
    let s = v.as_str().unwrap_or_else(|| panic!("expected hex string, got {v}"));
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

//! End-to-end: talk JSON-RPC to the real server binary over stdio.
#![cfg(windows)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use common::{Testbed, X86};
use serde_json::{Value, json};

struct Client {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Client {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_memory-mcp"))
            .args(["--no-journal", "--no-structs-file"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self { child, stdin, stdout, next_id: 1 }
    }

    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).unwrap() > 0, "server closed stdout");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    fn call(&mut self, tool: &str, args: Value) -> (bool, Value) {
        let r = self.request("tools/call", json!({"name": tool, "arguments": args}));
        let result = &r["result"];
        assert!(result.is_object(), "no result: {r}");
        let is_error = result["isError"].as_bool().unwrap_or(false);
        let text = result["content"][0]["text"].as_str().unwrap().to_string();
        let parsed = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (is_error, parsed)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Collects paths of schema positions that hold a bare `true`/`false` instead of an object.
fn find_boolean_subschemas(schema: &Value, path: String, out: &mut Vec<String>) {
    const SCHEMA_MAPS: [&str; 3] = ["properties", "$defs", "definitions"];
    const SCHEMA_KEYS: [&str; 6] = ["items", "additionalProperties", "not", "if", "then", "else"];
    const SCHEMA_LISTS: [&str; 4] = ["anyOf", "oneOf", "allOf", "prefixItems"];
    let Value::Object(map) = schema else { return };
    for (k, v) in map {
        let p = format!("{path}/{k}");
        if SCHEMA_MAPS.contains(&k.as_str()) {
            for (name, sub) in v.as_object().into_iter().flatten() {
                if sub.is_boolean() {
                    out.push(format!("{p}/{name}"));
                }
                find_boolean_subschemas(sub, format!("{p}/{name}"), out);
            }
        } else if SCHEMA_KEYS.contains(&k.as_str()) {
            if v.is_boolean() {
                out.push(p.clone());
            }
            find_boolean_subschemas(v, p, out);
        } else if SCHEMA_LISTS.contains(&k.as_str()) {
            for (i, sub) in v.as_array().into_iter().flatten().enumerate() {
                if sub.is_boolean() {
                    out.push(format!("{p}/{i}"));
                }
                find_boolean_subschemas(sub, format!("{p}/{i}"), out);
            }
        }
    }
}

#[test]
fn stdio_roundtrip() {
    let tb = Testbed::spawn(X86);
    let mut c = Client::start();

    let init = c.request(
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], json!("memory-mcp"), "{init}");
    c.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    let tools = c.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    for t in ["list_processes", "attach", "detach", "process_info", "list_modules", "list_regions", "resolve_address", "read_value", "read_bytes", "write_value", "write_bytes", "undo_write", "list_writes", "define_struct", "list_structs", "delete_struct", "read_struct", "write_struct", "aob_scan", "aob_resolve", "scan_start", "scan_next", "scan_results", "scan_close", "scan_list", "freeze_value", "unfreeze", "list_freezes", "watch_value", "watch_read", "unwatch", "list_watches", "pointer_scan", "pointer_scan_results", "pointer_rescan", "pointer_scan_close", "pointer_scan_list", "disassemble", "function_info", "disassemble_function", "list_functions", "find_xrefs", "make_signature"] {
        assert!(names.contains(&t), "missing tool {t}: {names:?}");
    }
    // Some clients (opencode) reject boolean JSON subschemas such as `"value": true`.
    for t in tools["result"]["tools"].as_array().unwrap() {
        let mut bad = Vec::new();
        find_boolean_subschemas(&t["inputSchema"], t["name"].as_str().unwrap().to_string(), &mut bad);
        assert!(bad.is_empty(), "boolean subschemas: {bad:?}");
    }

    let (err, v) = c.call("attach", json!({"pid": tb.pid()}));
    assert!(!err, "{v}");
    assert_eq!(v["attached"]["bits"], json!(32));

    let (err, v) = c.call("read_value", json!({"address": tb.addr_str("health"), "type": "i32"}));
    assert!(!err, "{v}");
    assert_eq!(v["value"], json!(100));

    // pointer chain through the MCP surface: [[root]+0x18] == player.health
    let (err, v) = c.call("resolve_address", json!({"address": "testbed.exe"}));
    assert!(!err, "{v}");
    let base = common::hex(&v["address"]);
    let root = format!("testbed.exe+0x{:X}", tb.addr("world_root") - base);
    let (err, v) = c.call("read_value", json!({"address": root, "offsets": [24, "0"], "type": "i32"}));
    assert!(!err, "{v}");
    assert_eq!(v["value"], json!(250));

    // write + undo through MCP
    let (err, v) = c.call("write_value", json!({"address": tb.addr_str("health"), "type": "i32", "value": "-0x10"}));
    assert!(!err, "{v}");
    assert_eq!(v["new_value"], json!(-16));
    let (err, v) = c.call("list_writes", json!({}));
    assert!(!err, "{v}");
    assert_eq!(v["total"], json!(1));
    assert_eq!(v["journal_file"], Value::Null);
    let (err, v) = c.call("undo_write", json!({}));
    assert!(!err, "{v}");
    let (_, v) = c.call("read_value", json!({"address": tb.addr_str("health"), "type": "i32"}));
    assert_eq!(v["value"], json!(100));

    let (err, v) = c.call("read_value", json!({"address": "0x0", "type": "i32"}));
    assert!(err);
    assert!(v.as_str().unwrap().contains("not mapped"), "{v}");

    let (err, v) = c.call("read_value", json!({"address": "0x10", "type": "nope"}));
    assert!(err);
    assert!(v.as_str().unwrap().contains("unknown type"), "{v}");
}

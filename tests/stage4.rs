//! Stage 4 integration tests: struct templates, layout per bitness, read_struct, write_struct, persistence.
#![cfg(windows)]

mod common;

use std::path::PathBuf;

use common::{Testbed, X64, X86, hex};
use memory_mcp::server::{
    AttachParams, DefineStructParams, DeleteStructParams, ListStructsParams, ReadStructParams, ServerOptions,
    UndoWriteParams, WriteStructParams,
};
use memory_mcp::structs::{FieldDef, FieldOffset};
use memory_mcp::{MemError, MemoryServer};
use serde_json::{Value, json};

fn f(name: &str, ty: &str) -> FieldDef {
    FieldDef { name: name.into(), ty: ty.into(), offset: None, length: None, count: None, comment: None }
}

fn define(s: &MemoryServer, name: &str, fields: Vec<FieldDef>) -> Value {
    s.do_define_struct(DefineStructParams { name: name.into(), fields, packed: None, size: None, description: None })
        .unwrap_or_else(|e| panic!("define {name}: {e}"))
}

fn define_all(s: &MemoryServer) -> Value {
    define(s, "Vec3", vec![f("x", "f32"), f("y", "f32"), f("z", "f32")]);
    let player = define(
        s,
        "Player",
        vec![
            f("health", "i32"),
            f("armor", "i32"),
            f("speed", "float"),
            FieldDef { length: Some(16), ..f("name", "utf8") },
            f("pos", "Vec3"),
            FieldDef { count: Some(4), ..f("items", "u16") },
            f("next", "*Player"),
        ],
    );
    define(s, "World", vec![FieldDef { count: Some(3), ..f("pad", "u64") }, f("player", "*Player")]);
    player
}

fn read_struct(s: &MemoryServer, addr: &str, name: Option<&str>, fields: Option<Vec<FieldDef>>, count: Option<usize>, depth: Option<usize>) -> Result<Value, MemError> {
    s.do_read_struct(ReadStructParams {
        address: addr.into(),
        offsets: None,
        r#struct: name.map(Into::into),
        fields,
        packed: None,
        count,
        depth,
    })
}

fn write_struct(s: &MemoryServer, addr: &str, values: Value) -> Result<Value, MemError> {
    s.do_write_struct(WriteStructParams {
        address: addr.into(),
        offsets: None,
        r#struct: Some("Player".into()),
        fields: None,
        packed: None,
        values,
    })
}

/// Field value by name from a read_struct result.
fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["fields"].as_array().unwrap().iter().find(|x| x["name"] == name).unwrap_or_else(|| panic!("no field {name} in {v}"))
}

fn temp_structs(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("memory-mcp-structs-{}-{tag}.json", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn suite(triple: &str) {
    let mut tb = Testbed::spawn(triple);
    let file = temp_structs(triple);
    let s = MemoryServer::with_options(ServerOptions { journal: None, structs: Some(file.clone()) });
    s.do_attach(AttachParams { pid: Some(tb.pid()), name: None }).unwrap();
    let x86 = tb.bits() == 32;

    // layout matches the compiler's repr(C) layout for this bitness
    let player = define_all(&s);
    assert_eq!(player["size_x64"], json!("0x38"));
    assert_eq!(player["size_x86"], json!("0x34"));
    let offs: Vec<&str> = player["layout"]["fields"].as_array().unwrap().iter().map(|x| x["offset"].as_str().unwrap()).collect();
    assert_eq!(offs, ["0x0", "0x4", "0x8", "0xC", "0x1C", "0x28", "0x30"]);
    assert_eq!(player["layout"]["pointer_size"], json!(if x86 { 4 } else { 8 }));

    // read World → Player → Sidekick through pointer fields
    let world = read_struct(&s, &tb.addr_str("world"), Some("World"), None, None, Some(2)).unwrap();
    assert_eq!(field(&world, "pad")["value"], json!([0x1111, 0x2222, 0x3333]));
    assert_eq!(hex(&field(&world, "player")["value"]), tb.addr("player"));
    let hero = &field(&world, "player")["target"];
    assert_eq!(field(hero, "health")["value"], json!(250));
    assert_eq!(field(hero, "name")["value"], json!("Hero"));
    assert_eq!(field(hero, "speed")["value"], json!(2.25));
    assert_eq!(field(&field(hero, "pos")["value"], "z")["value"], json!(3.0));
    assert_eq!(field(hero, "items")["value"], json!([10, 20, 30, 40]));
    assert_eq!(hex(&field(hero, "items")["address"]), tb.addr("player_items"));
    let side = &field(hero, "next")["target"];
    assert_eq!(hex(&field(hero, "next")["value"]), tb.addr("sidekick"));
    assert_eq!(field(side, "health")["value"], json!(60));
    assert_eq!(field(side, "name")["value"], json!("Sidekick"));
    assert_eq!(field(side, "next")["target"], Value::Null, "null pointer has no target");

    // depth limit
    let w0 = read_struct(&s, &tb.addr_str("world"), Some("world"), None, None, Some(0)).unwrap();
    assert_eq!(field(&w0, "player")["target"], json!("not followed (depth limit)"));

    // inline fields with explicit offsets, and arrays of structs
    let inline = vec![f("hp", "i32"), FieldDef { offset: Some(FieldOffset::Str("30".into())), ..f("next", "ptr") }];
    let v = read_struct(&s, &tb.addr_str("player"), None, Some(inline), None, None).unwrap();
    assert_eq!(field(&v, "hp")["value"], json!(250));
    assert_eq!(hex(&field(&v, "next")["value"]), tb.addr("sidekick"));
    let v = read_struct(&s, &tb.addr_str("player_items"), None, Some(vec![f("v", "u16")]), Some(4), None).unwrap();
    let vals: Vec<&Value> = v["elements"].as_array().unwrap().iter().map(|e| &field(e, "v")["value"]).collect();
    assert_eq!(vals, [&json!(10), &json!(20), &json!(30), &json!(40)]);

    // write fields by path; the target sees the new values
    let w = write_struct(&s, &tb.addr_str("player"), json!({"health": 300, "pos.x": 9.5, "items[2]": 77, "name": "Neo"})).unwrap();
    assert_eq!(w["writes"].as_array().unwrap().len(), 4);
    assert_eq!(tb.cmd("get player_health"), "300");
    assert_eq!(tb.cmd("get pos_x"), "9.5");
    assert_eq!(tb.cmd("get item2"), "77");
    assert_eq!(tb.cmd("get player_name"), "Neo");
    // each field is its own journaled write
    s.do_undo_write(UndoWriteParams { id: None, force: None }).unwrap();
    assert_eq!(tb.cmd("get player_name"), "Hero");

    // pointer field accepts an address expression; write through a template at a chained address
    let w = write_struct(&s, &format!("[{}]", tb.addr_str("player_next")), json!({"health": 61})).unwrap();
    assert_eq!(w["writes"][0]["old_value"], json!(60));
    assert_eq!(tb.cmd("get sidekick_health"), "61");

    // validation happens before any write
    let e = write_struct(&s, &tb.addr_str("player"), json!({"health": 1, "nope": 2})).unwrap_err().to_string();
    assert!(e.contains("no field 'nope'"), "{e}");
    let e = write_struct(&s, &tb.addr_str("player"), json!({"health": 1, "name": "ThisNameIsWayTooLong"})).unwrap_err().to_string();
    assert!(e.contains("do not fit"), "{e}");
    let e = write_struct(&s, &tb.addr_str("player"), json!({"next.health": 1})).unwrap_err().to_string();
    assert!(e.contains("pointer"), "{e}");
    let e = write_struct(&s, &tb.addr_str("player"), json!({"items": [1, 2, 3, 4, 5]})).unwrap_err().to_string();
    assert!(e.contains("do not fit"), "{e}");
    assert_eq!(tb.cmd("get player_health"), "300", "nothing was written");

    // unreadable struct
    let e = read_struct(&s, "0x0", Some("Player"), None, None, None).unwrap_err().to_string();
    assert!(e.contains("not mapped"), "{e}");

    // persistence: a new server loads the templates
    let s2 = MemoryServer::with_options(ServerOptions { journal: None, structs: Some(file.clone()) });
    let list = s2.do_list_structs(ListStructsParams { name: None, offset: None, limit: None }).unwrap();
    assert_eq!(list["total"], json!(3));
    let one = s2.do_list_structs(ListStructsParams { name: Some("player".into()), offset: None, limit: None }).unwrap();
    assert_eq!(one["definition"]["fields"].as_array().unwrap().len(), 7);
    let e = s2.do_delete_struct(DeleteStructParams { name: "Vec3".into() }).unwrap_err().to_string();
    assert!(e.contains("used by: Player"), "{e}");
    s2.do_delete_struct(DeleteStructParams { name: "World".into() }).unwrap();
    let s3 = MemoryServer::with_options(ServerOptions { journal: None, structs: Some(file.clone()) });
    assert_eq!(s3.do_list_structs(ListStructsParams { name: None, offset: None, limit: None }).unwrap()["total"], json!(2));

    tb.quit();
    let _ = std::fs::remove_file(&file);
}

#[test]
fn x64_structs() {
    suite(X64);
}

#[test]
fn x86_structs() {
    suite(X86);
}

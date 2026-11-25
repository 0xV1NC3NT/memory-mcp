//! Structure templates: definitions, C-like layout, decoding from memory and persistence.
//!
//! Field types: any value type (`i32`, `f32`, `ptr`, `utf8`, `bytes` ...), the name of another
//! struct (embedded by value), or `*Name` / `ptr:Name` (pointer to a struct, followed on read).
//! Offsets are optional: missing offsets are laid out sequentially with natural alignment
//! (as a C compiler would), unless the struct is `packed`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::address::parse_number;
use crate::error::{MemError, Result};
use crate::format;
use crate::platform::ProcessMemory;
use crate::value::{self, Scalar, ValueType};

pub const MAX_STRUCT_SIZE: u64 = 64 * 1024;
pub const MAX_FIELDS: usize = 512;
pub const MAX_COUNT: usize = 4096;
pub const MAX_DEPTH: usize = 8;

/// Field offset: JSON number (decimal) or string (hex by default: "0x18", "18", "#24").
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(untagged)]
pub enum FieldOffset {
    Num(u64),
    Str(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FieldDef {
    /// Field name (unique within the struct).
    pub name: String,
    /// Value type (i8..u64, f32, f64, bool, ptr, bytes, utf8, utf16), another struct name
    /// (embedded by value), or `*Name` / `ptr:Name` for a pointer to a struct.
    #[serde(rename = "type")]
    pub ty: String,
    /// Offset from the struct start. Omit to place the field after the previous one with natural alignment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<FieldOffset>,
    /// For bytes (required) / utf8 (bytes) / utf16 (chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    /// Array length (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    /// Free-form note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
    /// No alignment padding between auto-placed fields. Default false.
    #[serde(default)]
    pub packed: bool,
    /// Explicit total size (must cover all fields). Default: computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    Value(ValueType),
    Struct(String),
    PtrTo(String),
}

#[derive(Debug, Clone)]
pub struct FieldLayout {
    pub name: String,
    pub type_name: String,
    pub offset: u64,
    pub kind: FieldKind,
    pub elem_size: u64,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct Layout {
    pub name: String,
    pub size: u64,
    pub align: u64,
    pub fields: Vec<FieldLayout>,
}

impl Layout {
    pub fn to_json(&self, ptr_size: usize) -> Value {
        json!({
            "name": self.name,
            "size": format::size(self.size),
            "size_dec": self.size,
            "align": self.align,
            "pointer_size": ptr_size,
            "fields": self.fields.iter().map(|f| json!({
                "name": f.name,
                "type": f.type_name,
                "offset": format::size(f.offset),
                "size": format::size(f.elem_size * f.count as u64),
                "count": f.count,
            })).collect::<Vec<_>>(),
        })
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 { v } else { v.div_ceil(a) * a }
}

/// Registry of named struct templates, optionally persisted to a JSON file.
#[derive(Default)]
pub struct Registry {
    defs: BTreeMap<String, StructDef>,
    file: Option<PathBuf>,
}

fn key(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

impl Registry {
    /// Loads definitions from `file` if it exists. A corrupt file is reported, not overwritten silently.
    pub fn load(file: Option<PathBuf>) -> (Self, Option<String>) {
        let mut reg = Registry { defs: BTreeMap::new(), file };
        let mut warning = None;
        if let Some(path) = &reg.file
            && path.exists()
        {
            match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|s| {
                serde_json::from_str::<Vec<StructDef>>(&s).map_err(|e| e.to_string())
            }) {
                Ok(defs) => {
                    for d in defs {
                        reg.defs.insert(key(&d.name), d);
                    }
                }
                Err(e) => {
                    warning = Some(format!("cannot load struct templates from {}: {e}", path.display()));
                    // Keep the broken file untouched: disable persistence for this session.
                    reg.file = None;
                }
            }
        }
        (reg, warning)
    }

    pub fn file(&self) -> Option<&PathBuf> {
        self.file.as_ref()
    }

    pub fn get(&self, name: &str) -> Option<&StructDef> {
        self.defs.get(&key(name))
    }

    pub fn all(&self) -> impl Iterator<Item = &StructDef> {
        self.defs.values()
    }

    /// Validates (layout must succeed for both pointer sizes) and stores the definition.
    /// Returns true if an existing definition was replaced.
    pub fn define(&mut self, def: StructDef) -> Result<bool> {
        validate_name(&def.name)?;
        let k = key(&def.name);
        let prev = self.defs.insert(k.clone(), def.clone());
        let check = layout_of(self, &def, 4).and_then(|_| layout_of(self, &def, 8));
        if let Err(e) = check {
            match prev {
                Some(p) => self.defs.insert(k, p),
                None => self.defs.remove(&k),
            };
            return Err(e);
        }
        // Structs embedding this one must still be valid (e.g. no size overflow / cycles).
        let dependents: Vec<StructDef> = self.defs.values().filter(|d| key(&d.name) != k).cloned().collect();
        for d in &dependents {
            if let Err(e) = layout_of(self, d, 8) {
                match prev {
                    Some(p) => self.defs.insert(k, p),
                    None => self.defs.remove(&k),
                };
                return Err(MemError::InvalidArg(format!("redefining '{}' breaks '{}': {e}", def.name, d.name)));
            }
        }
        self.save()?;
        Ok(prev.is_some())
    }

    pub fn delete(&mut self, name: &str) -> Result<StructDef> {
        let k = key(name);
        let users: Vec<String> = self
            .defs
            .values()
            .filter(|d| key(&d.name) != k)
            .filter(|d| d.fields.iter().any(|f| struct_ref(&f.ty).is_some_and(|r| key(r) == k)))
            .map(|d| d.name.clone())
            .collect();
        if !users.is_empty() {
            return Err(MemError::InvalidArg(format!("struct '{name}' is used by: {}", users.join(", "))));
        }
        let def = self.defs.remove(&k).ok_or_else(|| MemError::InvalidArg(format!("no struct named '{name}'")))?;
        self.save()?;
        Ok(def)
    }

    fn save(&self) -> Result<()> {
        let Some(path) = &self.file else { return Ok(()) };
        let defs: Vec<&StructDef> = self.defs.values().collect();
        let text = serde_json::to_string_pretty(&defs).map_err(|e| MemError::Os(e.to_string()))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.chars().next().unwrap().is_ascii_digit();
    if !ok {
        return Err(MemError::InvalidArg(format!(
            "invalid struct name '{name}' (letters, digits, underscore; must not start with a digit)"
        )));
    }
    if ValueType::parse(name, Some(1)).is_ok() {
        return Err(MemError::InvalidArg(format!("'{name}' is a built-in type name")));
    }
    Ok(())
}

/// Struct name referenced by a field type (`Name`, `*Name`, `ptr:Name`), if it is not a built-in type.
fn struct_ref(ty: &str) -> Option<&str> {
    let t = ty.trim();
    if let Some(n) = t.strip_prefix('*').or_else(|| t.strip_prefix("ptr:")) {
        return Some(n.trim());
    }
    if ValueType::parse(t, Some(1)).is_ok() { None } else { Some(t) }
}

fn parse_offset(o: &FieldOffset) -> Result<u64> {
    match o {
        FieldOffset::Num(n) => Ok(*n),
        FieldOffset::Str(s) => parse_number(s),
    }
}

/// Computes the layout of `def` for a target with `ptr_size`-byte pointers.
pub fn layout_of(reg: &Registry, def: &StructDef, ptr_size: usize) -> Result<Layout> {
    let mut stack = Vec::new();
    layout_inner(reg, def, ptr_size, &mut stack)
}

pub fn layout_named(reg: &Registry, name: &str, ptr_size: usize) -> Result<Layout> {
    let def = reg.get(name).ok_or_else(|| MemError::InvalidArg(format!("no struct named '{name}'")))?;
    layout_of(reg, def, ptr_size)
}

fn layout_inner(reg: &Registry, def: &StructDef, ptr_size: usize, stack: &mut Vec<String>) -> Result<Layout> {
    let k = key(&def.name);
    if stack.contains(&k) {
        stack.push(k);
        return Err(MemError::InvalidArg(format!(
            "struct embeds itself by value ({}); use a pointer field (*{}) instead",
            stack.join(" → "),
            def.name
        )));
    }
    if def.fields.is_empty() {
        return Err(MemError::InvalidArg(format!("struct '{}' has no fields", def.name)));
    }
    if def.fields.len() > MAX_FIELDS {
        return Err(MemError::InvalidArg(format!("struct '{}' has more than {MAX_FIELDS} fields", def.name)));
    }
    stack.push(k);
    let err = |msg: String| MemError::InvalidArg(format!("struct '{}': {msg}", def.name));

    let mut fields: Vec<FieldLayout> = Vec::with_capacity(def.fields.len());
    let mut cursor = 0u64;
    let mut max_end = 0u64;
    let mut struct_align = 1u64;
    for f in &def.fields {
        if f.name.is_empty() || f.name.contains(['.', '[', ']']) {
            return Err(err(format!("invalid field name '{}'", f.name)));
        }
        if fields.iter().any(|x| x.name.eq_ignore_ascii_case(&f.name)) {
            return Err(err(format!("duplicate field '{}'", f.name)));
        }
        let count = f.count.unwrap_or(1);
        if count == 0 || count > MAX_COUNT {
            return Err(err(format!("field '{}': count must be 1..={MAX_COUNT}", f.name)));
        }
        let t = f.ty.trim();
        let (kind, elem_size, align, type_name) = if let Some(target) = t.strip_prefix('*').or_else(|| t.strip_prefix("ptr:")) {
            let target = target.trim();
            let resolved = reg.get(target).ok_or_else(|| err(format!("field '{}': unknown struct '{target}'", f.name)))?;
            (FieldKind::PtrTo(resolved.name.clone()), ptr_size as u64, ptr_size as u64, format!("*{}", resolved.name))
        } else {
            match ValueType::parse(t, f.length) {
                Ok(vt) => {
                    let size = vt.size(ptr_size) as u64;
                    let align = match vt {
                        ValueType::Scalar(s) => s.size(ptr_size) as u64,
                        ValueType::Utf16(_) => 2,
                        _ => 1,
                    };
                    (FieldKind::Value(vt), size, align, vt.name())
                }
                Err(type_err) => match reg.get(t) {
                    Some(sub) => {
                        let sub_layout = layout_inner(reg, sub, ptr_size, stack)?;
                        (FieldKind::Struct(sub.name.clone()), sub_layout.size, sub_layout.align, sub.name.clone())
                    }
                    None => return Err(err(format!("field '{}': {type_err}; no struct named '{t}' either", f.name))),
                },
            }
        };
        let align = if def.packed { 1 } else { align };
        struct_align = struct_align.max(align);
        let offset = match &f.offset {
            Some(o) => parse_offset(o).map_err(|e| err(format!("field '{}': {e}", f.name)))?,
            None => align_up(cursor, align),
        };
        let end = offset + elem_size * count as u64;
        if end > MAX_STRUCT_SIZE {
            return Err(err(format!("field '{}' ends at {end:#x}, beyond the {MAX_STRUCT_SIZE:#x} limit", f.name)));
        }
        cursor = end;
        max_end = max_end.max(end);
        fields.push(FieldLayout { name: f.name.clone(), type_name, offset, kind, elem_size, count });
    }
    let size = match def.size {
        Some(s) if s < max_end => return Err(err(format!("explicit size {s:#x} is smaller than the fields' extent {max_end:#x}"))),
        Some(s) if s > MAX_STRUCT_SIZE => return Err(err(format!("size {s:#x} exceeds {MAX_STRUCT_SIZE:#x}"))),
        Some(s) => s,
        None => align_up(max_end, struct_align),
    };
    stack.pop();
    Ok(Layout { name: def.name.clone(), size, align: struct_align, fields })
}

/// Finds the field at a dotted path (`pos.x`, `items[2]`, `inner.arr[1].y`) and returns
/// its absolute offset, value type and the number of bytes that may be written there
/// (rest of the array from the index on). Pointer fields can be written as `ptr` values.
pub fn field_at_path(reg: &Registry, layout: &Layout, path: &str, ptr_size: usize) -> Result<(u64, ValueType, u64)> {
    let mut cur = layout.clone();
    let mut base = 0u64;
    let segments: Vec<&str> = path.split('.').collect();
    for (i, seg) in segments.iter().enumerate() {
        let (name, index) = match seg.split_once('[') {
            Some((n, rest)) => {
                let idx = rest
                    .strip_suffix(']')
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .ok_or_else(|| MemError::InvalidArg(format!("bad index in '{seg}'")))?;
                (n, Some(idx))
            }
            None => (*seg, None),
        };
        let f = cur
            .fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| MemError::InvalidArg(format!("struct '{}' has no field '{name}'", cur.name)))?
            .clone();
        let idx = index.unwrap_or(0);
        if idx >= f.count {
            return Err(MemError::InvalidArg(format!("index {idx} out of range for '{}' (count {})", f.name, f.count)));
        }
        if index.is_none() && f.count > 1 && i + 1 == segments.len() && !matches!(f.kind, FieldKind::Value(_)) {
            return Err(MemError::InvalidArg(format!("'{}' is an array; use {}[i]", f.name, f.name)));
        }
        base += f.offset + f.elem_size * idx as u64;
        let last = i + 1 == segments.len();
        match (&f.kind, last) {
            (FieldKind::Value(vt), true) => {
                // Without an index, a whole array of scalars may be written.
                return Ok((base, *vt, f.elem_size * (f.count - idx) as u64));
            }
            (FieldKind::PtrTo(_), true) => {
                return Ok((base, ValueType::Scalar(Scalar::Ptr), f.elem_size * (f.count - idx) as u64));
            }
            (FieldKind::Struct(n), false) => cur = layout_named(reg, n, ptr_size)?,
            (FieldKind::Struct(_), true) => {
                return Err(MemError::InvalidArg(format!("'{path}' is a struct; write its fields (e.g. {path}.x)")));
            }
            (FieldKind::PtrTo(n), false) => {
                return Err(MemError::InvalidArg(format!(
                    "'{}' is a pointer to {n}; read_struct/write_struct cannot cross pointers in a path — use the pointer value as the address",
                    f.name
                )));
            }
            (FieldKind::Value(_), false) => {
                return Err(MemError::InvalidArg(format!("'{}' is not a struct", f.name)));
            }
        }
    }
    unreachable!("path has at least one segment")
}

/// Decodes a struct from memory. Unreadable fields get an `error` instead of a value;
/// pointer-to-struct fields are followed up to `depth` levels.
pub fn read(reg: &Registry, p: &dyn ProcessMemory, layout: &Layout, addr: u64, depth: usize) -> Value {
    let bytes = p.read_partial(addr, layout.size as usize);
    decode(reg, p, layout, addr, &bytes, depth)
}

fn decode(reg: &Registry, p: &dyn ProcessMemory, layout: &Layout, addr: u64, bytes: &[Option<u8>], depth: usize) -> Value {
    let ps = p.pointer_size();
    let fields: Vec<Value> = layout
        .fields
        .iter()
        .map(|f| {
            let faddr = addr + f.offset;
            let mut out = json!({
                "name": f.name,
                "type": f.type_name,
                "offset": format::size(f.offset),
                "address": format::addr(faddr, ps),
            });
            let mut values = Vec::with_capacity(f.count);
            let mut targets = Vec::new();
            let mut error = None;
            for i in 0..f.count {
                let start = (f.offset + f.elem_size * i as u64) as usize;
                let end = start + f.elem_size as usize;
                let slice = &bytes[start..end];
                let elem_addr = addr + start as u64;
                if slice.iter().any(|b| b.is_none()) && !matches!(f.kind, FieldKind::Struct(_)) {
                    error = Some(format!("unreadable: {}", p.explain_unreadable(elem_addr + slice.iter().position(|b| b.is_none()).unwrap() as u64)));
                    values.push(Value::Null);
                    continue;
                }
                match &f.kind {
                    FieldKind::Value(vt) => {
                        let raw: Vec<u8> = slice.iter().map(|b| b.unwrap()).collect();
                        values.push(value::decode(*vt, &raw, ps, false)["value"].clone());
                    }
                    FieldKind::Struct(name) => match layout_named(reg, name, ps) {
                        Ok(sub) => values.push(decode(reg, p, &sub, elem_addr, slice, depth)),
                        Err(e) => values.push(json!({ "error": e.to_string() })),
                    },
                    FieldKind::PtrTo(name) => {
                        let raw: Vec<u8> = slice.iter().map(|b| b.unwrap()).collect();
                        let ptr = if ps == 4 {
                            u32::from_le_bytes(raw[..4].try_into().unwrap()) as u64
                        } else {
                            u64::from_le_bytes(raw[..8].try_into().unwrap())
                        };
                        values.push(json!(format::addr(ptr, ps)));
                        let target = if ptr == 0 {
                            Value::Null
                        } else if depth == 0 {
                            json!("not followed (depth limit)")
                        } else {
                            match layout_named(reg, name, ps) {
                                Ok(sub) => read(reg, p, &sub, ptr, depth - 1),
                                Err(e) => json!({ "error": e.to_string() }),
                            }
                        };
                        targets.push(target);
                    }
                }
            }
            let single = f.count == 1;
            out["value"] = if single { values.into_iter().next().unwrap() } else { Value::Array(values) };
            if !targets.is_empty() {
                out["target"] = if single { targets.into_iter().next().unwrap() } else { Value::Array(targets) };
            }
            if let Some(e) = error {
                out["error"] = json!(e);
            }
            out
        })
        .collect();
    json!({
        "struct": layout.name,
        "address": format::addr(addr, ps),
        "size": format::size(layout.size),
        "fields": fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;
    use crate::platform::mock::MockProcess;

    fn f(name: &str, ty: &str) -> FieldDef {
        FieldDef { name: name.into(), ty: ty.into(), offset: None, length: None, count: None, comment: None }
    }

    fn def(name: &str, fields: Vec<FieldDef>) -> StructDef {
        StructDef { name: name.into(), fields, packed: false, size: None, description: None }
    }

    fn reg() -> Registry {
        let mut r = Registry::default();
        r.define(def("Vec3", vec![f("x", "f32"), f("y", "f32"), f("z", "f32")])).unwrap();
        r.define(def(
            "Node",
            vec![
                f("flag", "u8"),
                f("value", "i64"),
                f("pos", "Vec3"),
                FieldDef { count: Some(3), ..f("ids", "u16") },
                f("next", "*Node"),
            ],
        ))
        .unwrap();
        r
    }

    #[test]
    fn natural_alignment_depends_on_pointer_size() {
        let r = reg();
        let l = layout_named(&r, "node", 8).unwrap();
        let offs: Vec<u64> = l.fields.iter().map(|f| f.offset).collect();
        // flag@0, value@8, pos@0x10 (12 bytes), ids@0x1C (6 bytes), next@0x28
        assert_eq!(offs, [0, 8, 0x10, 0x1C, 0x28]);
        assert_eq!(l.size, 0x30);
        let l = layout_named(&r, "Node", 4).unwrap();
        assert_eq!(l.fields[4].offset, 0x24);
        assert_eq!(l.size, 0x28, "aligned to i64");
    }

    #[test]
    fn packed_explicit_offsets_and_size() {
        let mut r = reg();
        let mut d = def("P", vec![f("a", "u8"), f("b", "u32"), FieldDef { offset: Some(FieldOffset::Str("10".into())), ..f("c", "u16") }]);
        d.packed = true;
        r.define(d).unwrap();
        let l = layout_named(&r, "P", 8).unwrap();
        assert_eq!(l.fields.iter().map(|f| f.offset).collect::<Vec<_>>(), [0, 1, 0x10]);
        assert_eq!(l.size, 0x12);
        let mut d = def("S", vec![f("a", "u32")]);
        d.size = Some(2);
        assert!(r.define(d).unwrap_err().to_string().contains("smaller"));
    }

    #[test]
    fn validation() {
        let mut r = reg();
        let e = r.define(def("Loop", vec![f("me", "Loop")])).unwrap_err().to_string();
        assert!(e.contains("embeds itself"), "{e}");
        assert!(r.get("Loop").is_none(), "failed define is rolled back");
        assert!(r.define(def("int", vec![f("a", "u8")])).is_err());
        assert!(r.define(def("X", vec![f("a", "u8"), f("A", "u8")])).unwrap_err().to_string().contains("duplicate"));
        assert!(r.define(def("X", vec![f("a", "Nope")])).unwrap_err().to_string().contains("no struct named"));
        assert!(r.define(def("X", vec![f("a", "*Nope")])).unwrap_err().to_string().contains("unknown struct"));
        let e = r.delete("Vec3").unwrap_err().to_string();
        assert!(e.contains("used by: Node"), "{e}");
        // redefining Vec3 to embed Node would create a cycle Node → Vec3 → Node
        let e = r.define(def("Vec3", vec![f("n", "Node")])).unwrap_err().to_string();
        assert!(e.contains("embeds itself") || e.contains("breaks"), "{e}");
        assert_eq!(r.get("vec3").unwrap().fields.len(), 3, "old definition kept");
    }

    #[test]
    fn paths() {
        let r = reg();
        let l = layout_named(&r, "Node", 8).unwrap();
        assert_eq!(field_at_path(&r, &l, "pos.y", 8).unwrap(), (0x14, ValueType::Scalar(Scalar::F32), 4));
        assert_eq!(field_at_path(&r, &l, "ids[2]", 8).unwrap(), (0x20, ValueType::Scalar(Scalar::U16), 2));
        assert_eq!(field_at_path(&r, &l, "ids", 8).unwrap(), (0x1C, ValueType::Scalar(Scalar::U16), 6));
        assert_eq!(field_at_path(&r, &l, "next", 8).unwrap(), (0x28, ValueType::Scalar(Scalar::Ptr), 8));
        assert!(field_at_path(&r, &l, "ids[3]", 8).is_err());
        assert!(field_at_path(&r, &l, "pos", 8).is_err());
        assert!(field_at_path(&r, &l, "next.flag", 8).unwrap_err().to_string().contains("pointer"));
        assert!(field_at_path(&r, &l, "nope", 8).is_err());
    }

    #[test]
    fn read_with_pointers_and_partial() {
        let r = reg();
        let mut m = MockProcess::new(Arch::X64);
        let mut a = vec![0u8; 0x30];
        a[0] = 1;
        a[8..16].copy_from_slice(&(-7i64).to_le_bytes());
        a[0x10..0x14].copy_from_slice(&1.5f32.to_le_bytes());
        a[0x1C..0x1E].copy_from_slice(&5u16.to_le_bytes());
        a[0x28..0x30].copy_from_slice(&0x2000u64.to_le_bytes());
        m.map(0x1000, a);
        // second node: only the first 0x10 bytes are mapped
        let mut b = vec![0u8; 0x10];
        b[8..16].copy_from_slice(&42i64.to_le_bytes());
        m.map(0x2000, b);

        let l = layout_named(&r, "Node", 8).unwrap();
        let v = read(&r, &m, &l, 0x1000, 1);
        let fields = v["fields"].as_array().unwrap();
        assert_eq!(fields[0]["value"], json!(1));
        assert_eq!(fields[1]["value"], json!(-7));
        assert_eq!(fields[2]["value"]["fields"][0]["value"], json!(1.5));
        assert_eq!(fields[3]["value"], json!([5, 0, 0]));
        assert_eq!(fields[4]["value"], json!("0x0000000000002000"));
        let target = &fields[4]["target"];
        assert_eq!(target["fields"][1]["value"], json!(42));
        assert!(target["fields"][2]["value"]["fields"][0]["error"].is_string(), "{target}");
        assert!(target["fields"][4]["error"].as_str().unwrap().contains("unreadable"));

        let v = read(&r, &m, &l, 0x1000, 0);
        assert_eq!(v["fields"][4]["target"], json!("not followed (depth limit)"));
    }

    #[test]
    fn persistence_roundtrip() {
        let path = std::env::temp_dir().join(format!("memory-mcp-structs-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let (mut r, w) = Registry::load(Some(path.clone()));
            assert!(w.is_none());
            r.define(def("Vec3", vec![f("x", "f32"), f("y", "f32"), f("z", "f32")])).unwrap();
        }
        let (r, w) = Registry::load(Some(path.clone()));
        assert!(w.is_none());
        assert_eq!(r.get("VEC3").unwrap().fields.len(), 3);
        std::fs::write(&path, "{broken").unwrap();
        let (r, w) = Registry::load(Some(path.clone()));
        assert!(w.unwrap().contains("cannot load"));
        assert!(r.file().is_none(), "broken file is not overwritten");
        let _ = std::fs::remove_file(&path);
    }
}

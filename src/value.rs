//! Value types and decoding. Encoding (for writes) is added in the write stage.

use serde_json::{Value, json};

use crate::error::{MemError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scalar {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Bool,
    /// Pointer-sized unsigned integer (4 or 8 bytes depending on the target).
    Ptr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Scalar(Scalar),
    Bytes(usize),
    Utf8(usize),
    Utf16(usize),
}

pub const DEFAULT_STRING_LEN: usize = 256;
pub const MAX_STRING_LEN: usize = 64 * 1024;

pub const TYPE_HELP: &str = "i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 bool ptr bytes utf8 utf16 \
(aliases: byte, short, int, long, float, double, pointer, string, wstring)";

impl ValueType {
    /// Parses a type name. `length` applies to bytes/strings (bytes; for utf16 — characters).
    pub fn parse(name: &str, length: Option<usize>) -> Result<Self> {
        let n = name.trim().to_ascii_lowercase();
        let scalar = |s| Ok(ValueType::Scalar(s));
        match n.as_str() {
            "i8" | "int8" | "sbyte" => scalar(Scalar::I8),
            "u8" | "uint8" | "byte" => scalar(Scalar::U8),
            "i16" | "int16" | "short" => scalar(Scalar::I16),
            "u16" | "uint16" | "ushort" | "word" => scalar(Scalar::U16),
            "i32" | "int32" | "int" => scalar(Scalar::I32),
            "u32" | "uint32" | "uint" | "dword" => scalar(Scalar::U32),
            "i64" | "int64" | "long" => scalar(Scalar::I64),
            "u64" | "uint64" | "ulong" | "qword" => scalar(Scalar::U64),
            "f32" | "float" => scalar(Scalar::F32),
            "f64" | "double" => scalar(Scalar::F64),
            "bool" | "boolean" => scalar(Scalar::Bool),
            "ptr" | "pointer" | "usize" => scalar(Scalar::Ptr),
            "bytes" | "aob" => {
                let len = length.ok_or_else(|| MemError::InvalidArg("type 'bytes' requires `length`".into()))?;
                Self::check_len(len)?;
                Ok(ValueType::Bytes(len))
            }
            "utf8" | "string" | "str" | "ascii" => {
                let len = length.unwrap_or(DEFAULT_STRING_LEN);
                Self::check_len(len)?;
                Ok(ValueType::Utf8(len))
            }
            "utf16" | "wstring" | "wstr" | "unicode" => {
                let len = length.unwrap_or(DEFAULT_STRING_LEN);
                Self::check_len(len * 2)?;
                Ok(ValueType::Utf16(len))
            }
            _ => Err(MemError::InvalidArg(format!("unknown type '{name}'; supported: {TYPE_HELP}"))),
        }
    }

    fn check_len(len: usize) -> Result<()> {
        if len == 0 || len > MAX_STRING_LEN {
            return Err(MemError::InvalidArg(format!("length must be 1..={MAX_STRING_LEN}")));
        }
        Ok(())
    }

    /// Size in bytes of one element.
    pub fn size(&self, ptr_size: usize) -> usize {
        match self {
            ValueType::Scalar(s) => s.size(ptr_size),
            ValueType::Bytes(n) | ValueType::Utf8(n) => *n,
            ValueType::Utf16(n) => n * 2,
        }
    }

    pub fn name(&self) -> String {
        match self {
            ValueType::Scalar(s) => s.name().into(),
            ValueType::Bytes(n) => format!("bytes[{n}]"),
            ValueType::Utf8(n) => format!("utf8[{n}]"),
            ValueType::Utf16(n) => format!("utf16[{n}]"),
        }
    }
}

impl Scalar {
    pub fn size(self, ptr_size: usize) -> usize {
        match self {
            Scalar::I8 | Scalar::U8 | Scalar::Bool => 1,
            Scalar::I16 | Scalar::U16 => 2,
            Scalar::I32 | Scalar::U32 | Scalar::F32 => 4,
            Scalar::I64 | Scalar::U64 | Scalar::F64 => 8,
            Scalar::Ptr => ptr_size,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Scalar::I8 => "i8",
            Scalar::U8 => "u8",
            Scalar::I16 => "i16",
            Scalar::U16 => "u16",
            Scalar::I32 => "i32",
            Scalar::U32 => "u32",
            Scalar::I64 => "i64",
            Scalar::U64 => "u64",
            Scalar::F32 => "f32",
            Scalar::F64 => "f64",
            Scalar::Bool => "bool",
            Scalar::Ptr => "ptr",
        }
    }
}

fn arr<const N: usize>(b: &[u8], big_endian: bool) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[..N]);
    if big_endian {
        a.reverse();
    }
    a
}

fn float_json(v: f64) -> Value {
    if v.is_finite() { json!(v) } else { json!(v.to_string()) }
}

pub fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{x:02X}"));
    }
    s
}

/// Decodes one element. Returns `{"value": .., "hex": ..}` (hex = integer value or raw bytes).
pub fn decode(ty: ValueType, b: &[u8], ptr_size: usize, big_endian: bool) -> Value {
    match ty {
        ValueType::Scalar(s) => {
            let raw = hex_bytes(&b[..s.size(ptr_size)]);
            let (value, hex) = match s {
                Scalar::I8 => {
                    let v = b[0] as i8;
                    (json!(v), format!("0x{:02X}", v as u8))
                }
                Scalar::U8 => (json!(b[0]), format!("0x{:02X}", b[0])),
                Scalar::Bool => (json!(b[0] != 0), format!("0x{:02X}", b[0])),
                Scalar::I16 => {
                    let v = i16::from_le_bytes(arr(b, big_endian));
                    (json!(v), format!("0x{:04X}", v as u16))
                }
                Scalar::U16 => {
                    let v = u16::from_le_bytes(arr(b, big_endian));
                    (json!(v), format!("0x{v:04X}"))
                }
                Scalar::I32 => {
                    let v = i32::from_le_bytes(arr(b, big_endian));
                    (json!(v), format!("0x{:08X}", v as u32))
                }
                Scalar::U32 => {
                    let v = u32::from_le_bytes(arr(b, big_endian));
                    (json!(v), format!("0x{v:08X}"))
                }
                Scalar::I64 => {
                    let v = i64::from_le_bytes(arr(b, big_endian));
                    (json!(v), format!("0x{:016X}", v as u64))
                }
                Scalar::U64 => {
                    let v = u64::from_le_bytes(arr(b, big_endian));
                    (json!(v), format!("0x{v:016X}"))
                }
                Scalar::F32 => {
                    let v = f32::from_le_bytes(arr(b, big_endian));
                    (float_json(v as f64), format!("0x{:08X}", v.to_bits()))
                }
                Scalar::F64 => {
                    let v = f64::from_le_bytes(arr(b, big_endian));
                    (float_json(v), format!("0x{:016X}", v.to_bits()))
                }
                Scalar::Ptr => {
                    let v = if ptr_size == 4 {
                        u32::from_le_bytes(arr(b, big_endian)) as u64
                    } else {
                        u64::from_le_bytes(arr(b, big_endian))
                    };
                    let s = crate::format::addr(v, ptr_size);
                    (json!(s.clone()), s)
                }
            };
            json!({ "value": value, "hex": hex, "bytes": raw })
        }
        ValueType::Bytes(_) => json!({ "value": hex_bytes(b) }),
        ValueType::Utf8(_) => {
            let end = b.iter().position(|&c| c == 0);
            let text = String::from_utf8_lossy(&b[..end.unwrap_or(b.len())]).into_owned();
            json!({ "value": text, "terminated": end.is_some() })
        }
        ValueType::Utf16(_) => {
            let units: Vec<u16> = b
                .as_chunks::<2>().0.iter()
                .map(|c| if big_endian { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) })
                .collect();
            let end = units.iter().position(|&c| c == 0);
            let text = String::from_utf16_lossy(&units[..end.unwrap_or(units.len())]);
            json!({ "value": text, "terminated": end.is_some() })
        }
    }
}

pub const MAX_WRITE_ELEMENTS: usize = 4096;

/// Parses hex bytes in any common notation: `DE AD BE EF`, `DEADBEEF`, `\xDE\xAD`, `0xDE, 0xAD`, `DE-AD`.
pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let cleaned = input.replace("0x", "").replace("0X", "").replace("\\x", "").replace("\\X", "");
    let digits: String = cleaned.chars().filter(|c| !c.is_whitespace() && *c != ',' && *c != '-').collect();
    if digits.is_empty() {
        return Err(MemError::InvalidArg("no bytes given".into()));
    }
    if let Some(c) = digits.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(MemError::InvalidArg(format!("invalid hex character '{c}' in bytes")));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(MemError::InvalidArg("odd number of hex digits in bytes".into()));
    }
    Ok((0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap()).collect())
}

fn parse_int(v: &Value) -> Result<i128> {
    let bad = || MemError::InvalidArg(format!("expected an integer, got {v}"));
    match v {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i as i128)
            } else if let Some(u) = n.as_u64() {
                Ok(u as i128)
            } else {
                Err(bad())
            }
        }
        Value::Bool(b) => Ok(*b as i128),
        Value::String(s) => {
            let t: String = s.trim().chars().filter(|c| *c != '_').collect();
            let (neg, body) = match t.strip_prefix('-') {
                Some(r) => (true, r),
                None => (false, t.strip_prefix('+').unwrap_or(&t)),
            };
            let mag = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
                i128::from_str_radix(h, 16)
            } else {
                body.strip_prefix('#').unwrap_or(body).parse::<i128>()
            }
            .map_err(|_| bad())?;
            Ok(if neg { -mag } else { mag })
        }
        _ => Err(bad()),
    }
}

fn parse_float(v: &Value) -> Result<f64> {
    match v {
        Value::Number(n) => n.as_f64().ok_or_else(|| MemError::InvalidArg(format!("bad number {v}"))),
        Value::String(s) => s.trim().parse::<f64>().map_err(|_| MemError::InvalidArg(format!("expected a float, got {v}"))),
        _ => Err(MemError::InvalidArg(format!("expected a float, got {v}"))),
    }
}

fn int_bytes(x: i128, size: usize, big_endian: bool, ty: &str) -> Result<Vec<u8>> {
    let bits = size as u32 * 8;
    let min = -(1i128 << (bits - 1));
    let max = (1i128 << bits) - 1;
    if x < min || x > max {
        return Err(MemError::InvalidArg(format!("{x} does not fit in {ty} (allowed {min}..={max})")));
    }
    let mut b = (x as u128).to_le_bytes()[..size].to_vec();
    if big_endian {
        b.reverse();
    }
    Ok(b)
}

fn maybe_reverse(b: &[u8], big_endian: bool) -> Vec<u8> {
    if big_endian { b.iter().rev().copied().collect() } else { b.to_vec() }
}

/// Encodes a JSON value for writing. Integers accept numbers or strings (`"-5"`, `"0xFF"`);
/// a JSON array writes consecutive elements. Signed and unsigned ranges are both accepted
/// (e.g. -1 for u32 → FF FF FF FF).
pub fn encode(ty: ValueType, v: &Value, ptr_size: usize, big_endian: bool, null_terminate: bool) -> Result<Vec<u8>> {
    if let (ValueType::Scalar(_), Value::Array(items)) = (ty, v) {
        if items.is_empty() || items.len() > MAX_WRITE_ELEMENTS {
            return Err(MemError::InvalidArg(format!("array must have 1..={MAX_WRITE_ELEMENTS} elements")));
        }
        let mut out = Vec::new();
        for item in items {
            out.extend(encode(ty, item, ptr_size, big_endian, null_terminate)?);
        }
        return Ok(out);
    }
    match ty {
        ValueType::Scalar(s) => match s {
            Scalar::F32 => {
                let f = parse_float(v)?;
                if f.is_finite() && f.abs() > f32::MAX as f64 {
                    return Err(MemError::InvalidArg(format!("{f} does not fit in f32")));
                }
                Ok(maybe_reverse(&(f as f32).to_le_bytes(), big_endian))
            }
            Scalar::F64 => Ok(maybe_reverse(&parse_float(v)?.to_le_bytes(), big_endian)),
            Scalar::Bool => {
                let b = match v {
                    Value::Bool(b) => *b,
                    Value::String(t) if t.eq_ignore_ascii_case("true") => true,
                    Value::String(t) if t.eq_ignore_ascii_case("false") => false,
                    other => match parse_int(other)? {
                        0 => false,
                        1 => true,
                        x => return Err(MemError::InvalidArg(format!("bool must be true/false/0/1, got {x}"))),
                    },
                };
                Ok(vec![b as u8])
            }
            _ => int_bytes(parse_int(v)?, s.size(ptr_size), big_endian, s.name()),
        },
        ValueType::Bytes(_) => match v {
            Value::String(t) => parse_hex_bytes(t),
            Value::Array(items) => {
                items.iter().map(|i| parse_int(i).and_then(|x| int_bytes(x, 1, false, "u8")).map(|b| b[0])).collect()
            }
            _ => Err(MemError::InvalidArg("bytes value must be a hex string like \"DE AD BE EF\"".into())),
        },
        ValueType::Utf8(_) => {
            let t = v.as_str().ok_or_else(|| MemError::InvalidArg("string value expected".into()))?;
            let mut b = t.as_bytes().to_vec();
            if null_terminate {
                b.push(0);
            }
            Ok(b)
        }
        ValueType::Utf16(_) => {
            let t = v.as_str().ok_or_else(|| MemError::InvalidArg("string value expected".into()))?;
            let mut units: Vec<u16> = t.encode_utf16().collect();
            if null_terminate {
                units.push(0);
            }
            Ok(units.iter().flat_map(|u| if big_endian { u.to_be_bytes() } else { u.to_le_bytes() }).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aliases() {
        assert_eq!(ValueType::parse("int", None).unwrap(), ValueType::Scalar(Scalar::I32));
        assert_eq!(ValueType::parse("Float", None).unwrap(), ValueType::Scalar(Scalar::F32));
        assert_eq!(ValueType::parse("wstring", Some(8)).unwrap(), ValueType::Utf16(8));
        assert!(ValueType::parse("bytes", None).is_err());
        assert!(ValueType::parse("quux", None).is_err());
    }

    #[test]
    fn decode_scalars() {
        let v = decode(ValueType::Scalar(Scalar::I32), &(-5i32).to_le_bytes(), 8, false);
        assert_eq!(v["value"], json!(-5));
        assert_eq!(v["hex"], json!("0xFFFFFFFB"));
        let v = decode(ValueType::Scalar(Scalar::F32), &1.5f32.to_le_bytes(), 8, false);
        assert_eq!(v["value"], json!(1.5));
        let v = decode(ValueType::Scalar(Scalar::U16), &[0x12, 0x34], 8, true);
        assert_eq!(v["value"], json!(0x1234));
        let v = decode(ValueType::Scalar(Scalar::Ptr), &0x1000u32.to_le_bytes(), 4, false);
        assert_eq!(v["value"], json!("0x00001000"));
    }

    #[test]
    fn encode_values() {
        let i = |t: &str| ValueType::parse(t, Some(1)).unwrap();
        let e = |t: &str, v: Value| encode(i(t), &v, 8, false, true);
        assert_eq!(e("i32", json!(-5)).unwrap(), (-5i32).to_le_bytes());
        assert_eq!(e("u32", json!(-1)).unwrap(), [0xFF; 4]);
        assert_eq!(encode(i("u16"), &json!("0x1234"), 8, true, true).unwrap(), [0x12, 0x34]);
        assert_eq!(e("i8", json!("-0x80")).unwrap(), [0x80]);
        assert!(e("u8", json!(256)).is_err());
        assert!(e("i8", json!(-129)).is_err());
        assert!(e("i32", json!(1.5)).is_err());
        assert_eq!(e("u64", json!(u64::MAX)).unwrap(), [0xFF; 8]);
        assert_eq!(e("f32", json!(1.5)).unwrap(), 1.5f32.to_le_bytes());
        assert_eq!(e("double", json!("2.5")).unwrap(), 2.5f64.to_le_bytes());
        assert!(e("f32", json!(1e300)).is_err());
        assert_eq!(e("bool", json!(true)).unwrap(), [1]);
        assert_eq!(encode(i("ptr"), &json!("0x1000"), 4, false, true).unwrap(), [0, 0x10, 0, 0]);
        assert_eq!(e("i16", json!([1, 2])).unwrap(), [1, 0, 2, 0]);
        assert_eq!(e("utf8", json!("hi")).unwrap(), b"hi\0");
        assert_eq!(encode(i("utf8"), &json!("hi"), 8, false, false).unwrap(), b"hi");
        assert_eq!(e("utf16", json!("A")).unwrap(), [0x41, 0, 0, 0]);
        assert_eq!(e("bytes", json!("de ad")).unwrap(), [0xDE, 0xAD]);
    }

    #[test]
    fn hex_bytes_formats() {
        for s in ["DE AD BE EF", "deadbeef", "\\xDE\\xAD\\xBE\\xEF", "0xDE, 0xAD, 0xBE, 0xEF", "DE-AD-BE-EF"] {
            assert_eq!(parse_hex_bytes(s).unwrap(), [0xDE, 0xAD, 0xBE, 0xEF], "{s}");
        }
        assert!(parse_hex_bytes("ABC").is_err());
        assert!(parse_hex_bytes("GG").is_err());
        assert!(parse_hex_bytes("").is_err());
    }

    #[test]
    fn decode_strings() {
        let v = decode(ValueType::Utf8(8), b"abc\0zzzz", 8, false);
        assert_eq!(v["value"], json!("abc"));
        let w: Vec<u8> = "hi\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let v = decode(ValueType::Utf16(3), &w, 8, false);
        assert_eq!(v["value"], json!("hi"));
    }
}

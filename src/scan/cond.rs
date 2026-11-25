//! Scan value types, conditions and comparison (with float tolerance modes).

use serde_json::Value;

use crate::error::{MemError, Result};
use crate::value::{Scalar, ValueType};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Num {
    I(i128),
    F(f64),
}

impl Num {
    pub fn to_json(self) -> Value {
        match self {
            Num::I(i) => i64::try_from(i)
                .map(Value::from)
                .or_else(|_| u64::try_from(i).map(Value::from))
                .unwrap_or_else(|_| Value::from(i.to_string())),
            Num::F(f) if f.is_finite() => Value::from(f),
            Num::F(f) => Value::from(f.to_string()),
        }
    }
}

/// A scalar type usable in value scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanType {
    pub scalar: Scalar,
    pub size: usize,
}

impl ScanType {
    pub fn parse(name: &str, ptr_size: usize) -> Result<Self> {
        match ValueType::parse(name, Some(1))? {
            ValueType::Scalar(s) => Ok(Self { scalar: s, size: s.size(ptr_size) }),
            other => Err(MemError::InvalidArg(format!(
                "value scans support numeric types only (got {}); use aob_scan for bytes and strings",
                other.name()
            ))),
        }
    }

    pub fn is_float(self) -> bool {
        matches!(self.scalar, Scalar::F32 | Scalar::F64)
    }

    pub fn name(self) -> &'static str {
        self.scalar.name()
    }

    /// Default alignment ("fast scan"): natural alignment, at most 4 so that 8-byte values
    /// in 32-bit packing are not missed.
    pub fn default_alignment(self) -> u64 {
        (self.size as u64).min(4)
    }

    #[inline]
    pub fn decode(self, b: &[u8]) -> Num {
        match self.scalar {
            Scalar::I8 => Num::I(b[0] as i8 as i128),
            Scalar::U8 | Scalar::Bool => Num::I(b[0] as i128),
            Scalar::I16 => Num::I(i16::from_le_bytes([b[0], b[1]]) as i128),
            Scalar::U16 => Num::I(u16::from_le_bytes([b[0], b[1]]) as i128),
            Scalar::I32 => Num::I(i32::from_le_bytes(b[..4].try_into().unwrap()) as i128),
            Scalar::U32 => Num::I(u32::from_le_bytes(b[..4].try_into().unwrap()) as i128),
            Scalar::I64 => Num::I(i64::from_le_bytes(b[..8].try_into().unwrap()) as i128),
            Scalar::U64 => Num::I(u64::from_le_bytes(b[..8].try_into().unwrap()) as i128),
            Scalar::F32 => Num::F(f32::from_le_bytes(b[..4].try_into().unwrap()) as f64),
            Scalar::F64 => Num::F(f64::from_le_bytes(b[..8].try_into().unwrap())),
            Scalar::Ptr => {
                if self.size == 4 {
                    Num::I(u32::from_le_bytes(b[..4].try_into().unwrap()) as i128)
                } else {
                    Num::I(u64::from_le_bytes(b[..8].try_into().unwrap()) as i128)
                }
            }
        }
    }

    fn int_range(self) -> (i128, i128) {
        let bits = self.size as u32 * 8;
        match self.scalar {
            Scalar::I8 | Scalar::I16 | Scalar::I32 | Scalar::I64 => (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1),
            _ => (0, (1i128 << bits) - 1),
        }
    }

    /// Little-endian bytes of an exact value (for the memmem fast path).
    pub fn encode(self, n: Num) -> Vec<u8> {
        match (self.scalar, n) {
            (Scalar::F32, Num::F(f)) => (f as f32).to_le_bytes().to_vec(),
            (Scalar::F64, Num::F(f)) => f.to_le_bytes().to_vec(),
            (_, Num::I(i)) => (i as u128).to_le_bytes()[..self.size].to_vec(),
            (_, Num::F(f)) => (f as i128 as u128).to_le_bytes()[..self.size].to_vec(),
        }
    }

    /// Parses a user value for this type. Returns the number and, for floats, the number
    /// of decimals the user typed (used by the rounded/truncated modes).
    pub fn parse_value(self, v: &Value, delta: bool) -> Result<(Num, usize)> {
        let text = match v {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.trim().to_string(),
            Value::Bool(b) => (*b as u8).to_string(),
            other => return Err(MemError::InvalidArg(format!("expected a number, got {other}"))),
        };
        if self.is_float() {
            let f: f64 = text.parse().map_err(|_| MemError::InvalidArg(format!("expected a float, got '{text}'")))?;
            let decimals = text
                .split_once('.')
                .map(|(_, d)| d.chars().take_while(|c| c.is_ascii_digit()).count())
                .unwrap_or(0);
            return Ok((Num::F(f), decimals));
        }
        let t: String = text.chars().filter(|c| *c != '_').collect();
        let (neg, body) = match t.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, t.as_str()),
        };
        let mag = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            i128::from_str_radix(h, 16)
        } else {
            body.parse::<i128>()
        }
        .map_err(|_| MemError::InvalidArg(format!("expected an integer, got '{text}'")))?;
        let i = if neg { -mag } else { mag };
        let bits = self.size as u32 * 8;
        let (lo, hi) = self.int_range();
        // Accept both signed and unsigned spellings (e.g. -1 for u32, 0xFF for i8); deltas just need to fit.
        let (min, max) = (-(1i128 << (bits - 1)), (1i128 << bits) - 1);
        let ok = if delta { i.abs() <= max } else { i >= min && i <= max };
        if !ok {
            return Err(MemError::InvalidArg(format!("{i} does not fit in {}", self.name())));
        }
        let normalized = if delta {
            i
        } else if i > hi {
            i - (1i128 << bits) // unsigned spelling of a signed type
        } else if i < lo {
            i + (1i128 << bits) // negative spelling of an unsigned type
        } else {
            i
        };
        Ok((Num::I(normalized), 0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloatMode {
    /// Equal after rounding both to the user's number of decimals (Cheat Engine default).
    Rounded,
    Truncated,
    Exact,
    /// |a - b| <= tolerance.
    Tolerance(f64),
}

impl FloatMode {
    pub fn parse(mode: Option<&str>, tolerance: Option<f64>) -> Result<Self> {
        if let Some(t) = tolerance {
            if !(t >= 0.0 && t.is_finite()) {
                return Err(MemError::InvalidArg("tolerance must be a finite number >= 0".into()));
            }
            return Ok(FloatMode::Tolerance(t));
        }
        match mode.map(str::to_ascii_lowercase).as_deref() {
            None | Some("") | Some("rounded") => Ok(FloatMode::Rounded),
            Some("truncated") => Ok(FloatMode::Truncated),
            Some("exact") => Ok(FloatMode::Exact),
            Some(m) => Err(MemError::InvalidArg(format!("unknown float_mode '{m}' (rounded|truncated|exact)"))),
        }
    }

    pub fn name(self) -> String {
        match self {
            FloatMode::Rounded => "rounded".into(),
            FloatMode::Truncated => "truncated".into(),
            FloatMode::Exact => "exact".into(),
            FloatMode::Tolerance(t) => format!("tolerance {t}"),
        }
    }
}

/// A value with the precision information needed for float comparison.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Target {
    pub n: Num,
    pub decimals: usize,
    /// The scanned type is f32: `exact` compares with the nearest f32, not the typed decimal.
    pub single: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cond {
    Exact(Target),
    Not(Target),
    Range(Target, Target),
    Bigger(Target),
    Smaller(Target),
    Unknown,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy(Target),
    DecreasedBy(Target),
}

pub const FIRST_CONDITIONS: &str = "exact, not, range, bigger, smaller, unknown";
pub const NEXT_CONDITIONS: &str =
    "exact, not, range, bigger, smaller, changed, unchanged, increased, decreased, increased_by, decreased_by";

impl Cond {
    pub fn parse(name: &str, value: Option<&Value>, value2: Option<&Value>, ty: ScanType, first: bool) -> Result<Cond> {
        let n = name.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        let need = |v: Option<&Value>, what: &str, delta: bool| -> Result<Target> {
            let v = v.ok_or_else(|| MemError::InvalidArg(format!("condition '{n}' needs `{what}`")))?;
            let (n, decimals) = ty.parse_value(v, delta)?;
            Ok(Target { n, decimals, single: ty.scalar == Scalar::F32 && !delta })
        };
        let c = match n.as_str() {
            "exact" | "equal" | "eq" | "=" => Cond::Exact(need(value, "value", false)?),
            "not" | "not_equal" | "ne" | "!=" => Cond::Not(need(value, "value", false)?),
            "range" | "between" => {
                let a = need(value, "value", false)?;
                let b = need(value2, "value2", false)?;
                Cond::Range(a, b)
            }
            "bigger" | "greater" | "gt" | ">" => Cond::Bigger(need(value, "value", false)?),
            "smaller" | "less" | "lt" | "<" => Cond::Smaller(need(value, "value", false)?),
            "unknown" => Cond::Unknown,
            "changed" => Cond::Changed,
            "unchanged" => Cond::Unchanged,
            "increased" => Cond::Increased,
            "decreased" => Cond::Decreased,
            "increased_by" => Cond::IncreasedBy(need(value, "value", true)?),
            "decreased_by" => Cond::DecreasedBy(need(value, "value", true)?),
            _ => {
                return Err(MemError::InvalidArg(format!(
                    "unknown condition '{name}'; first scan: {FIRST_CONDITIONS}; next scan: {NEXT_CONDITIONS}"
                )));
            }
        };
        let relative = c.needs_previous();
        if first && relative {
            return Err(MemError::InvalidArg(format!(
                "'{n}' compares with a previous scan; use it in scan_next (first scan: {FIRST_CONDITIONS})"
            )));
        }
        if !first && c == Cond::Unknown {
            return Err(MemError::InvalidArg("'unknown' is only valid for the first scan; use changed/unchanged/... next".into()));
        }
        Ok(c)
    }

    pub fn needs_previous(&self) -> bool {
        matches!(
            self,
            Cond::Changed | Cond::Unchanged | Cond::Increased | Cond::Decreased | Cond::IncreasedBy(_) | Cond::DecreasedBy(_)
        )
    }

    pub fn describe(&self) -> String {
        let v = |t: &Target| match t.n {
            Num::I(i) => i.to_string(),
            Num::F(f) => f.to_string(),
        };
        match self {
            Cond::Exact(t) => format!("exact {}", v(t)),
            Cond::Not(t) => format!("not {}", v(t)),
            Cond::Range(a, b) => format!("range {}..={}", v(a), v(b)),
            Cond::Bigger(t) => format!("bigger than {}", v(t)),
            Cond::Smaller(t) => format!("smaller than {}", v(t)),
            Cond::Unknown => "unknown initial value".into(),
            Cond::Changed => "changed".into(),
            Cond::Unchanged => "unchanged".into(),
            Cond::Increased => "increased".into(),
            Cond::Decreased => "decreased".into(),
            Cond::IncreasedBy(t) => format!("increased by {}", v(t)),
            Cond::DecreasedBy(t) => format!("decreased by {}", v(t)),
        }
    }
}

fn as_f64(n: Num) -> f64 {
    match n {
        Num::I(i) => i as f64,
        Num::F(f) => f,
    }
}

fn float_eq(x: f64, t: &Target, mode: FloatMode) -> bool {
    let v = as_f64(t.n);
    match mode {
        FloatMode::Exact if t.single => x == v as f32 as f64,
        FloatMode::Exact => x == v,
        FloatMode::Tolerance(e) => (x - v).abs() <= e,
        FloatMode::Rounded | FloatMode::Truncated => {
            if !x.is_finite() {
                return x == v;
            }
            let scale = 10f64.powi(t.decimals.min(15) as i32);
            if mode == FloatMode::Rounded {
                (x * scale).round() == (v * scale).round()
            } else {
                (x * scale).trunc() == (v * scale).trunc()
            }
        }
    }
}

fn cmp(cur: Num, t: &Target) -> std::cmp::Ordering {
    match (cur, t.n) {
        (Num::I(a), Num::I(b)) => a.cmp(&b),
        (a, b) => as_f64(a).partial_cmp(&as_f64(b)).unwrap_or(std::cmp::Ordering::Less),
    }
}

fn eq(cur: Num, t: &Target, mode: FloatMode) -> bool {
    match (cur, t.n) {
        (Num::I(a), Num::I(b)) => a == b,
        (a, _) => float_eq(as_f64(a), t, mode),
    }
}

fn diff(cur: Num, prev: Num) -> Num {
    match (cur, prev) {
        (Num::I(a), Num::I(b)) => Num::I(a - b),
        (a, b) => Num::F(as_f64(a) - as_f64(b)),
    }
}

/// Whether `cur` (and `prev` for relative conditions) satisfies `c`.
#[inline]
pub fn test(c: &Cond, cur: Num, prev: Option<Num>, mode: FloatMode) -> bool {
    use std::cmp::Ordering::*;
    if let Num::F(f) = cur
        && f.is_nan()
    {
        return matches!(c, Cond::Unknown | Cond::Changed | Cond::Not(_));
    }
    match c {
        Cond::Unknown => true,
        Cond::Exact(t) => eq(cur, t, mode),
        Cond::Not(t) => !eq(cur, t, mode),
        Cond::Range(a, b) => cmp(cur, a) != Less && cmp(cur, b) != Greater,
        Cond::Bigger(t) => cmp(cur, t) == Greater,
        Cond::Smaller(t) => cmp(cur, t) == Less,
        _ => {
            let Some(prev) = prev else { return false };
            match c {
                Cond::Changed => cur != prev,
                Cond::Unchanged => cur == prev,
                Cond::Increased => cmp(cur, &Target { n: prev, decimals: 0, single: false }) == Greater,
                Cond::Decreased => cmp(cur, &Target { n: prev, decimals: 0, single: false }) == Less,
                Cond::IncreasedBy(t) => eq(diff(cur, prev), t, mode),
                Cond::DecreasedBy(t) => eq(diff(prev, cur), t, mode),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ty(n: &str) -> ScanType {
        ScanType::parse(n, 8).unwrap()
    }

    fn c(name: &str, v: Option<Value>, t: &str, first: bool) -> Cond {
        Cond::parse(name, v.as_ref(), None, ty(t), first).unwrap()
    }

    #[test]
    fn parse_values() {
        assert_eq!(ty("u32").parse_value(&json!(-1), false).unwrap().0, Num::I(0xFFFF_FFFF));
        assert_eq!(ty("i8").parse_value(&json!("0xFF"), false).unwrap().0, Num::I(-1));
        assert_eq!(ty("i32").parse_value(&json!("-0x10"), false).unwrap().0, Num::I(-16));
        assert!(ty("u8").parse_value(&json!(300), false).is_err());
        assert_eq!(ty("f32").parse_value(&json!("1.25"), false).unwrap(), (Num::F(1.25), 2));
        assert_eq!(ty("f64").parse_value(&json!(3), false).unwrap(), (Num::F(3.0), 0));
        assert!(ScanType::parse("utf8", 8).is_err());
    }

    #[test]
    fn integer_conditions() {
        let m = FloatMode::Rounded;
        assert!(test(&c("exact", Some(json!(5)), "i32", true), Num::I(5), None, m));
        assert!(!test(&c("exact", Some(json!(5)), "i32", true), Num::I(6), None, m));
        let r = Cond::parse("range", Some(&json!(1)), Some(&json!(3)), ty("i32"), true).unwrap();
        assert!(test(&r, Num::I(3), None, m) && !test(&r, Num::I(4), None, m));
        assert!(test(&c("increased_by", Some(json!(10)), "i32", false), Num::I(60), Some(Num::I(50)), m));
        assert!(test(&c("decreased_by", Some(json!(10)), "u32", false), Num::I(40), Some(Num::I(50)), m));
        assert!(test(&c("increased", None, "i32", false), Num::I(2), Some(Num::I(1)), m));
        assert!(test(&c("unchanged", None, "i32", false), Num::I(2), Some(Num::I(2)), m));
        assert!(test(&c("not", Some(json!(1)), "i32", true), Num::I(2), None, m));
    }

    #[test]
    fn float_modes() {
        let ex = c("exact", Some(json!("1.55")), "f32", true);
        let x = 1.55f32 as f64; // 1.5499999523...
        assert!(test(&ex, Num::F(x), None, FloatMode::Rounded));
        assert!(test(&ex, Num::F(1.554), None, FloatMode::Rounded));
        assert!(!test(&ex, Num::F(1.556), None, FloatMode::Rounded));
        assert!(test(&ex, Num::F(1.559), None, FloatMode::Truncated));
        assert!(!test(&ex, Num::F(x), None, FloatMode::Truncated), "1.5499 truncates to 1.54");
        assert!(test(&ex, Num::F(x), None, FloatMode::Exact), "exact = the same f32");
        assert!(!test(&ex, Num::F(1.55f64), None, FloatMode::Exact));
        assert!(test(&ex, Num::F(1.6), None, FloatMode::Tolerance(0.1)));
        assert!(!test(&ex, Num::F(f64::NAN), None, FloatMode::Rounded));
        let by = c("increased_by", Some(json!(0.5)), "f32", false);
        assert!(test(&by, Num::F(2.0), Some(Num::F(1.5)), FloatMode::Rounded));
    }

    #[test]
    fn condition_validation() {
        assert!(Cond::parse("changed", None, None, ty("i32"), true).unwrap_err().to_string().contains("scan_next"));
        assert!(Cond::parse("unknown", None, None, ty("i32"), false).is_err());
        assert!(Cond::parse("exact", None, None, ty("i32"), true).unwrap_err().to_string().contains("needs `value`"));
        assert!(Cond::parse("range", Some(&json!(1)), None, ty("i32"), true).unwrap_err().to_string().contains("value2"));
        assert!(Cond::parse("weird", None, None, ty("i32"), true).is_err());
    }
}

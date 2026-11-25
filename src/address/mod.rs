//! Address expressions.
//!
//! | Form                | Example                                  |
//! |---------------------|------------------------------------------|
//! | hex                 | `0x7FF6A1B2C3D0`, `7FF6A1B2C3D0h`, `1A2B`  |
//! | decimal             | `#6699`                                  |
//! | module (+offset)    | `game.exe+0x1A2B`, `"my mod.dll"+10`, `game+10` |
//! | export / ordinal    | `kernel32.dll!CreateFileW`, `k32.dll!#12` |
//! | dereference         | `[[game.exe+0x10]+0x20]+0x30`            |
//! | arithmetic          | `game.exe+0x100*4-8`, parentheses        |
//! | pointer chain list  | base + `offsets: [0x20, "-8", 48]`        |
//!
//! Bare words are numbers in hex unless a loaded module has that name.

mod eval;
mod lexer;
mod parser;

pub use eval::{Evaluator, Offset, Resolved, TraceStep, lookup_module, resolve, symbolize};
pub use parser::{Arg, Expr, parse};

use crate::error::{MemError, Result};

/// Parses `0x1A2B`, `1A2Bh`, `#6699` (decimal) or bare hex `1A2B`. Underscores and the
/// WinDbg backtick separator (`00007ff6`a1b2c3d0`) are ignored.
pub fn parse_number(input: &str) -> Result<u64> {
    let bad = |reason: &str| MemError::BadAddress { input: input.to_string(), reason: reason.into() };
    let s: String = input.trim().chars().filter(|c| *c != '_' && *c != '`').collect();
    if s.is_empty() {
        return Err(bad("empty"));
    }
    let (digits, radix) = if let Some(d) = s.strip_prefix('#') {
        (d, 10)
    } else if let Some(d) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (d, 16)
    } else if let Some(d) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        (d, 16)
    } else {
        (s.as_str(), 16)
    };
    if digits.is_empty() {
        return Err(bad("no digits"));
    }
    u64::from_str_radix(digits, radix).map_err(|e| bad(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(parse_number("0x1A2B").unwrap(), 0x1A2B);
        assert_eq!(parse_number("1A2Bh").unwrap(), 0x1A2B);
        assert_eq!(parse_number("1a2b").unwrap(), 0x1A2B);
        assert_eq!(parse_number("#100").unwrap(), 100);
        assert_eq!(parse_number("00007ff6`a1b2c3d0").unwrap(), 0x7ff6a1b2c3d0);
        assert!(parse_number("0x").is_err());
        assert!(parse_number("zz").is_err());
    }
}

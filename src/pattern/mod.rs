//! Byte signatures (AOB patterns) in every common notation, normalized to bytes + nibble masks.
//!
//! | Notation          | Example                                      |
//! |-------------------|----------------------------------------------|
//! | IDA               | `48 8B ?? ?? 05`, `48 8B ? ? 05`             |
//! | Cheat Engine      | `48 8B * * 05`                               |
//! | nibble wildcards  | `4? 8B ?5`                                   |
//! | code + mask       | `\x48\x8B\x00\x00\x05` with mask `xx??x`     |
//! | raw hex           | `488B????05`                                 |
//! | strings           | `str:"Health"` (UTF-8), `wstr:"Health"` (UTF-16LE) |

mod scope;
mod search;

pub use scope::{Scope, resolve_ranges};
pub use search::{ScanResult, scan};

use crate::error::{MemError, Result};

pub const MAX_PATTERN_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub bytes: Vec<u8>,
    /// Per byte: 0xFF exact, 0xF0 high nibble only, 0x0F low nibble only, 0x00 wildcard.
    pub masks: Vec<u8>,
}

fn bad(input: &str, reason: impl Into<String>) -> MemError {
    MemError::InvalidArg(format!("invalid pattern '{input}': {}", reason.into()))
}

fn nibble(c: char) -> Option<Option<u8>> {
    match c {
        '?' | '*' => Some(None),
        _ => c.to_digit(16).map(|d| Some(d as u8)),
    }
}

/// Parses one byte token of 1–2 chars: `48`, `??`, `?`, `*`, `4?`, `?5`.
fn parse_token(input: &str, tok: &str) -> Result<(u8, u8)> {
    let chars: Vec<char> = tok.chars().collect();
    match chars.as_slice() {
        ['?'] | ['*'] => Ok((0, 0)),
        [h, l] => {
            let h = nibble(*h).ok_or_else(|| bad(input, format!("bad byte '{tok}'")))?;
            let l = nibble(*l).ok_or_else(|| bad(input, format!("bad byte '{tok}'")))?;
            let byte = (h.unwrap_or(0) << 4) | l.unwrap_or(0);
            let mask = if h.is_some() { 0xF0 } else { 0 } | if l.is_some() { 0x0F } else { 0 };
            Ok((byte, mask))
        }
        _ => Err(bad(input, format!("bad byte '{tok}'"))),
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    for q in ['"', '\''] {
        if let Some(inner) = s.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner;
        }
    }
    s
}

impl Pattern {
    /// Parses `input`; `mask` (`x` = exact, `?` = wildcard, one char per byte) optionally
    /// overrides the wildcards — required semantics for the `\x..` code style.
    pub fn parse(input: &str, mask: Option<&str>) -> Result<Pattern> {
        let s = input.trim();
        let (bytes, mut masks): (Vec<u8>, Vec<u8>) = if let Some(rest) = s.strip_prefix("wstr:") {
            let b: Vec<u8> = unquote(rest).encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let m = vec![0xFF; b.len()];
            (b, m)
        } else if let Some(rest) = s.strip_prefix("str:") {
            let b = unquote(rest).as_bytes().to_vec();
            let m = vec![0xFF; b.len()];
            (b, m)
        } else if s.contains("\\x") || s.contains("\\X") {
            let mut b = Vec::new();
            let mut rest = s;
            while !rest.is_empty() {
                let r = rest
                    .strip_prefix("\\x")
                    .or_else(|| rest.strip_prefix("\\X"))
                    .ok_or_else(|| bad(input, "expected \\xHH sequences"))?;
                let hh = r.get(..2).ok_or_else(|| bad(input, "truncated \\x escape"))?;
                b.push(u8::from_str_radix(hh, 16).map_err(|_| bad(input, format!("bad escape \\x{hh}")))?);
                rest = r[2..].trim_start();
            }
            let m = vec![0xFF; b.len()];
            (b, m)
        } else {
            let mut b = Vec::new();
            let mut m = Vec::new();
            for raw in s.split(|c: char| c.is_whitespace() || c == ',') {
                let tok = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
                if tok.is_empty() {
                    continue;
                }
                if tok.chars().count() <= 2 {
                    let (byte, mask) = parse_token(input, tok)?;
                    b.push(byte);
                    m.push(mask);
                } else if tok.len() % 2 == 0 && tok.is_ascii() {
                    for i in (0..tok.len()).step_by(2) {
                        let (byte, mask) = parse_token(input, &tok[i..i + 2])?;
                        b.push(byte);
                        m.push(mask);
                    }
                } else {
                    return Err(bad(input, format!("token '{tok}' has an odd number of hex digits")));
                }
            }
            (b, m)
        };
        if let Some(mask) = mask.map(str::trim).filter(|m| !m.is_empty()) {
            if mask.chars().count() != bytes.len() {
                return Err(bad(input, format!("mask has {} chars but the pattern has {} bytes", mask.chars().count(), bytes.len())));
            }
            for (i, c) in mask.chars().enumerate() {
                match c {
                    'x' | 'X' => {}
                    '?' | '.' | '*' => masks[i] = 0,
                    other => return Err(bad(input, format!("mask char '{other}' (use x or ?)"))),
                }
            }
        }
        if bytes.is_empty() {
            return Err(bad(input, "empty pattern"));
        }
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(bad(input, format!("longer than {MAX_PATTERN_LEN} bytes")));
        }
        if masks.iter().all(|&m| m == 0) {
            return Err(bad(input, "pattern consists only of wildcards"));
        }
        let bytes = bytes.iter().zip(&masks).map(|(b, m)| b & m).collect();
        Ok(Pattern { bytes, masks })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline]
    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() >= self.len() && self.bytes.iter().zip(&self.masks).zip(data).all(|((b, m), d)| d & m == *b)
    }

    /// Normalized IDA-style text, e.g. `48 8B ?? 4? ?5`.
    pub fn display(&self) -> String {
        self.bytes
            .iter()
            .zip(&self.masks)
            .map(|(b, m)| match m {
                0xFF => format!("{b:02X}"),
                0xF0 => format!("{:X}?", b >> 4),
                0x0F => format!("?{:X}", b & 0x0F),
                _ => "??".into(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Index of the most selective exact byte, used as the memchr anchor.
    pub fn anchor(&self) -> Option<usize> {
        fn score(b: u8) -> u8 {
            match b {
                0x00 => 0,
                0xFF => 1,
                0xCC => 2,
                0x90 => 3,
                0x48 | 0x8B | 0x89 | 0x0F | 0x01 | 0x24 | 0xE8 | 0x4C | 0x83 | 0xC3 => 5,
                _ => 10,
            }
        }
        (0..self.len()).filter(|&i| self.masks[i] == 0xFF).max_by_key(|&i| (score(self.bytes[i]), std::cmp::Reverse(i)))
    }

    /// Whether `s` looks like a code-style mask for this pattern (only x/? and the right length).
    pub fn is_mask_for(&self, s: &str) -> bool {
        s.chars().count() == self.len() && s.chars().all(|c| matches!(c, 'x' | 'X' | '?' | '.'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pattern {
        Pattern::parse(s, None).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn notations_are_equivalent() {
        let ida = p("48 8B ?? ?? 05");
        assert_eq!(ida.bytes, [0x48, 0x8B, 0, 0, 0x05]);
        assert_eq!(ida.masks, [0xFF, 0xFF, 0, 0, 0xFF]);
        assert_eq!(p("48 8B ? ? 05"), ida);
        assert_eq!(p("48 8B * * 05"), ida);
        assert_eq!(p("488B????05"), ida);
        assert_eq!(p("0x48, 0x8B, ??, ??, 0x05"), ida);
        assert_eq!(Pattern::parse("\\x48\\x8B\\x00\\x00\\x05", Some("xx??x")).unwrap(), ida);
        assert_eq!(Pattern::parse("48 8B 00 00 05", Some("xx??x")).unwrap(), ida);
        assert_eq!(ida.display(), "48 8B ?? ?? 05");
    }

    #[test]
    fn nibbles_and_strings() {
        let n = p("4? 8B ?5");
        assert_eq!(n.masks, [0xF0, 0xFF, 0x0F]);
        assert!(n.matches(&[0x4C, 0x8B, 0xA5]));
        assert!(!n.matches(&[0x5C, 0x8B, 0xA5]));
        assert_eq!(n.display(), "4? 8B ?5");
        assert_eq!(p("str:\"Hi\"").bytes, b"Hi");
        assert_eq!(p("str:Hi").bytes, b"Hi");
        assert_eq!(p("wstr:'Hi'").bytes, [b'H', 0, b'i', 0]);
    }

    #[test]
    fn anchor_prefers_rare_bytes() {
        assert_eq!(p("00 48 ?? 7A 00").anchor(), Some(3));
        assert_eq!(p("?? 00 FF").anchor(), Some(2));
        assert_eq!(p("4? ?? ?5").anchor(), None);
    }

    #[test]
    fn errors() {
        for (s, m, frag) in [
            ("", None, "empty"),
            ("?? ??", None, "only of wildcards"),
            ("48 8G", None, "bad byte"),
            ("488", None, "odd number"),
            ("\\x48\\x8", None, "truncated"),
            ("48 8B", Some("x"), "mask has 1 chars"),
            ("48 8B", Some("xz"), "mask char"),
        ] {
            let e = Pattern::parse(s, m).unwrap_err().to_string();
            assert!(e.contains(frag), "{s}: {e}");
        }
    }
}

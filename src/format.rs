//! Output formatting helpers shared by tools.

use serde::Serialize;
use serde_json::{Value, json};

pub fn addr(a: u64, ptr_size: usize) -> String {
    if ptr_size == 4 { format!("0x{a:08X}") } else { format!("0x{a:016X}") }
}

pub fn size(s: u64) -> String {
    format!("0x{s:X}")
}

pub const DEFAULT_PAGE: usize = 100;
pub const MAX_PAGE: usize = 1000;

/// Wraps a slice of items into a paginated JSON response.
pub fn page<T: Serialize>(items: &[T], offset: Option<usize>, limit: Option<usize>) -> Value {
    let total = items.len();
    let offset = offset.unwrap_or(0).min(total);
    let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let end = (offset + limit).min(total);
    json!({
        "total": total,
        "offset": offset,
        "returned": end - offset,
        "has_more": end < total,
        "items": &items[offset..end],
    })
}

/// Classic hexdump: `ADDRESS  XX XX .. |ascii|`; unreadable bytes shown as `??`.
pub fn hexdump(base: u64, bytes: &[Option<u8>], ptr_size: usize) -> Vec<String> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let mut hex = String::with_capacity(48);
            let mut ascii = String::with_capacity(16);
            for (j, b) in chunk.iter().enumerate() {
                if j == 8 {
                    hex.push(' ');
                }
                match b {
                    Some(b) => {
                        hex.push_str(&format!("{b:02X} "));
                        ascii.push(if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' });
                    }
                    None => {
                        hex.push_str("?? ");
                        ascii.push('?');
                    }
                }
            }
            format!("{}  {:<49} |{}|", addr(base + (i * 16) as u64, ptr_size), hex, ascii)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging() {
        let v: Vec<u32> = (0..250).collect();
        let p = page(&v, Some(200), Some(100));
        assert_eq!(p["returned"], 50);
        assert_eq!(p["has_more"], false);
        let p = page(&v, None, None);
        assert_eq!(p["returned"], 100);
        assert_eq!(p["has_more"], true);
    }

    #[test]
    fn dump() {
        let bytes: Vec<Option<u8>> = b"Hello".iter().copied().map(Some).chain([None]).collect();
        let lines = hexdump(0x1000, &bytes, 4);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("0x00001000  48 65 6C 6C 6F ?? "));
        assert!(lines[0].ends_with("|Hello?|"));
    }
}

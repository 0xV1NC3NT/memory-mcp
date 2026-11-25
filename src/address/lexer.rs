//! Tokenizer for address expressions.

use crate::error::{MemError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// Number, module name or symbol — classified later (needs the module list).
    Word(String),
    /// Quoted string: module name with spaces, or a string argument of a function.
    Str(String),
    Plus,
    Minus,
    Star,
    LBrack,
    RBrack,
    LParen,
    RParen,
    Bang,
    Comma,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub pos: usize,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '@' | '?' | '`' | '#' | '~')
}

pub fn tokenize(input: &str) -> Result<Vec<Token>> {
    let bad = |pos: usize, reason: String| MemError::BadAddress { input: input.to_string(), reason: format!("{reason} at position {pos}") };
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let (pos, c) = chars[i];
        let simple = match c {
            '+' => Some(Tok::Plus),
            '-' => Some(Tok::Minus),
            '*' => Some(Tok::Star),
            '[' => Some(Tok::LBrack),
            ']' => Some(Tok::RBrack),
            '(' => Some(Tok::LParen),
            ')' => Some(Tok::RParen),
            '!' => Some(Tok::Bang),
            ',' => Some(Tok::Comma),
            _ => None,
        };
        if let Some(tok) = simple {
            out.push(Token { tok, pos });
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            let mut s = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err(bad(pos, "unterminated string".into())),
                    Some(&(_, '\\')) if chars.get(i + 1).is_some_and(|&(_, n)| n == quote || n == '\\') => {
                        s.push(chars[i + 1].1);
                        i += 2;
                    }
                    Some(&(_, ch)) if ch == quote => {
                        i += 1;
                        break;
                    }
                    Some(&(_, ch)) => {
                        s.push(ch);
                        i += 1;
                    }
                }
            }
            out.push(Token { tok: Tok::Str(s), pos });
            continue;
        }
        if is_word_char(c) {
            let start = i;
            while i < chars.len() && is_word_char(chars[i].1) {
                i += 1;
            }
            let word: String = chars[start..i].iter().map(|&(_, c)| c).collect();
            out.push(Token { tok: Tok::Word(word), pos });
            continue;
        }
        return Err(bad(pos, format!("unexpected character '{c}'")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        tokenize(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn basic() {
        use Tok::*;
        assert_eq!(
            toks("[[game.exe+0x10]+20h] - 8"),
            vec![
                LBrack, LBrack, Word("game.exe".into()), Plus, Word("0x10".into()), RBrack, Plus,
                Word("20h".into()), RBrack, Minus, Word("8".into())
            ]
        );
        assert_eq!(toks(r#""my mod.dll"+1"#), vec![Str("my mod.dll".into()), Plus, Word("1".into())]);
        assert_eq!(toks("k32.dll!#12"), vec![Word("k32.dll".into()), Bang, Word("#12".into())]);
        assert_eq!(toks(r#"sig("48 ?? \"x", m)"#)[2], Str("48 ?? \"x".into()));
    }

    #[test]
    fn errors() {
        assert!(tokenize("\"open").is_err());
        assert!(tokenize("a % b").is_err());
    }
}

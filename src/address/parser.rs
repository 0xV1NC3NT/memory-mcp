//! Recursive-descent parser for address expressions.
//!
//! ```text
//! expr    := term (('+' | '-') term)*
//! term    := unary ('*' unary)*
//! unary   := '-' unary | primary
//! primary := '[' expr ']' | '(' expr ')'
//!          | WORD '(' args? ')'                       function call: sig/rip/abs32
//!          | (WORD | STR) ('!' (WORD | STR))?         number / module / module!export
//! args    := arg (',' arg)*        arg := STR | expr
//! ```

use super::lexer::{Tok, Token, tokenize};
use crate::error::{MemError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Unquoted word: hex/dec number or module name (resolved at evaluation time).
    Word(String),
    /// Quoted module name.
    Module(String),
    /// `module!symbol` or `module!#ordinal`.
    Export { module: String, symbol: String },
    Deref(Box<Expr>),
    Neg(Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Call { name: String, args: Vec<Arg> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Str(String),
    Expr(Expr),
}

struct Parser<'a> {
    input: &'a str,
    toks: Vec<Token>,
    i: usize,
}

pub fn parse(input: &str) -> Result<Expr> {
    let toks = tokenize(input)?;
    if toks.is_empty() {
        return Err(MemError::BadAddress { input: input.into(), reason: "empty expression".into() });
    }
    let mut p = Parser { input, toks, i: 0 };
    let e = p.expr()?;
    if let Some(t) = p.toks.get(p.i) {
        return Err(p.err_at(t.pos, &format!("unexpected {}", describe(&t.tok))));
    }
    Ok(e)
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Word(w) => format!("'{w}'"),
        Tok::Str(s) => format!("\"{s}\""),
        Tok::Plus => "'+'".into(),
        Tok::Minus => "'-'".into(),
        Tok::Star => "'*'".into(),
        Tok::LBrack => "'['".into(),
        Tok::RBrack => "']'".into(),
        Tok::LParen => "'('".into(),
        Tok::RParen => "')'".into(),
        Tok::Bang => "'!'".into(),
        Tok::Comma => "','".into(),
    }
}

impl Parser<'_> {
    fn err_at(&self, pos: usize, msg: &str) -> MemError {
        MemError::BadAddress { input: self.input.into(), reason: format!("{msg} at position {pos}") }
    }

    fn err_end(&self, msg: &str) -> MemError {
        MemError::BadAddress { input: self.input.into(), reason: format!("{msg} at end of input") }
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.tok)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.toks.get(self.i).cloned();
        self.i += 1;
        t
    }

    fn expect(&mut self, want: Tok) -> Result<()> {
        match self.next() {
            Some(t) if t.tok == want => Ok(()),
            Some(t) => Err(self.err_at(t.pos, &format!("expected {}, found {}", describe(&want), describe(&t.tok)))),
            None => Err(self.err_end(&format!("expected {}", describe(&want)))),
        }
    }

    fn expr(&mut self) -> Result<Expr> {
        let mut lhs = self.term()?;
        loop {
            match self.peek() {
                Some(Tok::Plus) => {
                    self.i += 1;
                    lhs = Expr::Add(Box::new(lhs), Box::new(self.term()?));
                }
                Some(Tok::Minus) => {
                    self.i += 1;
                    lhs = Expr::Sub(Box::new(lhs), Box::new(self.term()?));
                }
                _ => return Ok(lhs),
            }
        }
    }

    fn term(&mut self) -> Result<Expr> {
        let mut lhs = self.unary()?;
        while self.peek() == Some(&Tok::Star) {
            self.i += 1;
            lhs = Expr::Mul(Box::new(lhs), Box::new(self.unary()?));
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr> {
        if self.peek() == Some(&Tok::Minus) {
            self.i += 1;
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr> {
        let Some(t) = self.next() else {
            return Err(self.err_end("expected a value"));
        };
        match t.tok {
            Tok::LBrack => {
                let e = self.expr()?;
                self.expect(Tok::RBrack)?;
                Ok(Expr::Deref(Box::new(e)))
            }
            Tok::LParen => {
                let e = self.expr()?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Tok::Word(w) if self.peek() == Some(&Tok::LParen) => {
                self.i += 1;
                let mut args = Vec::new();
                if self.peek() != Some(&Tok::RParen) {
                    loop {
                        args.push(self.arg()?);
                        if self.peek() == Some(&Tok::Comma) {
                            self.i += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.expect(Tok::RParen)?;
                Ok(Expr::Call { name: w.to_ascii_lowercase(), args })
            }
            Tok::Word(w) => self.maybe_export(w, false),
            Tok::Str(s) => self.maybe_export(s, true),
            other => Err(self.err_at(t.pos, &format!("unexpected {}", describe(&other)))),
        }
    }

    fn maybe_export(&mut self, module: String, quoted: bool) -> Result<Expr> {
        if self.peek() != Some(&Tok::Bang) {
            return Ok(if quoted { Expr::Module(module) } else { Expr::Word(module) });
        }
        self.i += 1;
        match self.next() {
            Some(Token { tok: Tok::Word(symbol) | Tok::Str(symbol), .. }) => Ok(Expr::Export { module, symbol }),
            Some(t) => Err(self.err_at(t.pos, &format!("expected export name after '!', found {}", describe(&t.tok)))),
            None => Err(self.err_end("expected export name after '!'")),
        }
    }

    fn arg(&mut self) -> Result<Arg> {
        if let Some(Tok::Str(s)) = self.peek().cloned()
            && matches!(self.toks.get(self.i + 1).map(|t| &t.tok), Some(Tok::Comma) | Some(Tok::RParen))
        {
            self.i += 1;
            return Ok(Arg::Str(s));
        }
        Ok(Arg::Expr(self.expr()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Box<Expr> {
        Box::new(Expr::Word(s.into()))
    }

    #[test]
    fn precedence_and_deref() {
        assert_eq!(
            parse("[[game.exe+10]+0x20]+30h").unwrap(),
            Expr::Add(
                Box::new(Expr::Deref(Box::new(Expr::Add(
                    Box::new(Expr::Deref(Box::new(Expr::Add(w("game.exe"), w("10"))))),
                    w("0x20")
                )))),
                w("30h")
            )
        );
        assert_eq!(parse("a+b*2").unwrap(), Expr::Add(w("a"), Box::new(Expr::Mul(w("b"), w("2")))));
        assert_eq!(parse("-8").unwrap(), Expr::Neg(w("8")));
        assert_eq!(parse("1-2-3").unwrap(), Expr::Sub(Box::new(Expr::Sub(w("1"), w("2"))), w("3")));
    }

    #[test]
    fn modules_exports_calls() {
        assert_eq!(parse("\"my mod.dll\"").unwrap(), Expr::Module("my mod.dll".into()));
        assert_eq!(
            parse("kernel32.dll!CreateFileW").unwrap(),
            Expr::Export { module: "kernel32.dll".into(), symbol: "CreateFileW".into() }
        );
        assert_eq!(parse("k.dll!#3").unwrap(), Expr::Export { module: "k.dll".into(), symbol: "#3".into() });
        assert_eq!(
            parse("rip(sig(\"48 8B 05 ?? ?? ?? ??\", game.exe), 3, 7)").unwrap(),
            Expr::Call {
                name: "rip".into(),
                args: vec![
                    Arg::Expr(Expr::Call {
                        name: "sig".into(),
                        args: vec![Arg::Str("48 8B 05 ?? ?? ?? ??".into()), Arg::Expr(Expr::Word("game.exe".into()))]
                    }),
                    Arg::Expr(Expr::Word("3".into())),
                    Arg::Expr(Expr::Word("7".into())),
                ]
            }
        );
    }

    #[test]
    fn errors_are_positioned() {
        for (src, frag) in [
            ("[a+1", "expected ']'"),
            ("a+", "expected a value"),
            ("a b", "unexpected 'b' at position 2"),
            ("mod!", "expected export name"),
            ("]", "unexpected ']' at position 0"),
            ("", "empty"),
        ] {
            let e = parse(src).unwrap_err().to_string();
            assert!(e.contains(frag), "{src}: {e}");
        }
    }
}

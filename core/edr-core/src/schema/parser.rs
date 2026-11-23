//! Lexer and recursive-descent parser for schema source.

use super::CompileError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Num(u64),
    Var(String),
    Pos,
    End,
    Size,
    Bin(BinOp, Box<Expr>, Box<Expr>),
    LogAnd(Box<Expr>, Box<Expr>),
    LogOr(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Func(String, Vec<Expr>),
}

/// Statements with their source line.
pub type Block = Vec<(usize, Stmt)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Expect(Vec<u8>, String),
    Field(String, u8, Option<Endian>),
    Let(String, Expr),
    Require(Expr, String),
    Fail(String),
    Skip(Expr),
    Seek(Expr),
    While(Expr, Block),
    If(Expr, Block, Block),
    Break,
    Region(Expr, Block),
    At(Expr, Block),
    Call(String),
    Once(Expr, String),
    SetEndian(Endian),
}

#[derive(Debug, Clone)]
pub struct Def {
    pub name: String,
    pub line: usize,
    pub body: Block,
}

#[derive(Debug, Clone)]
pub struct SchemaAst {
    pub name: String,
    pub detect: Vec<(u64, Vec<u8>)>,
    pub endian: Endian,
    /// `main` is always first.
    pub defs: Vec<Def>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Num(u64),
    Str(String),
    Hex(Vec<u8>),
    Sym(&'static str),
    Newline,
    Eof,
}

const SYMS: &[&str] = &[
    "||", "&&", "==", "!=", "<=", ">=", "<<", ">>", "{", "}", "(", ")", ",", ";", "=", "<", ">", "+", "-", "*", "/",
    "%", "&", "|", "^", "!",
];

pub const MAX_SOURCE_LEN: usize = 256 * 1024;
const MAX_NESTING: usize = 64;

fn err<T>(line: usize, msg: impl Into<String>) -> Result<T, CompileError> {
    Err(CompileError { line, msg: msg.into() })
}

fn lex(src: &str) -> Result<Vec<(usize, Tok)>, CompileError> {
    if src.len() > MAX_SOURCE_LEN {
        return err(0, "schema source too large");
    }
    let b = src.as_bytes();
    let mut i = 0;
    let mut line = 1;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => {
                out.push((line, Tok::Newline));
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                let (s, n) = lex_str(b, i, line)?;
                out.push((line, Tok::Str(s)));
                i = n;
            }
            b'0'..=b'9' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let t: String = src[start..i].chars().filter(|&c| c != '_').collect();
                let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u64::from_str_radix(h, 16)
                } else {
                    t.parse::<u64>()
                };
                match v {
                    Ok(v) => out.push((line, Tok::Num(v))),
                    Err(_) => return err(line, format!("bad number {t}")),
                }
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let id = &src[start..i];
                if i < b.len() && b[i] == b'"' && (id == "hex" || id == "fourcc") {
                    let (s, n) = lex_str(b, i, line)?;
                    i = n;
                    if id == "hex" {
                        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
                        match hex::decode(&clean) {
                            Ok(v) if !v.is_empty() => out.push((line, Tok::Hex(v))),
                            _ => return err(line, "bad hex literal"),
                        }
                    } else {
                        let sb = s.as_bytes();
                        if sb.len() != 4 {
                            return err(line, "fourcc literal must be 4 bytes");
                        }
                        out.push((line, Tok::Num(u32::from_be_bytes([sb[0], sb[1], sb[2], sb[3]]) as u64)));
                    }
                } else {
                    out.push((line, Tok::Ident(id.to_string())));
                }
            }
            _ => {
                let rest = &src[i..];
                match SYMS.iter().find(|s| rest.starts_with(**s)) {
                    Some(s) => {
                        out.push((line, Tok::Sym(s)));
                        i += s.len();
                    }
                    None => return err(line, format!("unexpected character {:?}", c as char)),
                }
            }
        }
    }
    out.push((line, Tok::Eof));
    Ok(out)
}

fn lex_str(b: &[u8], start: usize, line: usize) -> Result<(String, usize), CompileError> {
    let mut i = start + 1;
    while i < b.len() && b[i] != b'"' {
        if b[i] == b'\n' || b[i] == b'\\' {
            return err(line, "strings cannot contain newlines or escapes");
        }
        i += 1;
    }
    if i >= b.len() {
        return err(line, "unterminated string");
    }
    let s = std::str::from_utf8(&b[start + 1..i]).map_err(|_| CompileError { line, msg: "invalid utf-8".into() })?;
    Ok((s.to_string(), i + 1))
}

struct P {
    toks: Vec<(usize, Tok)>,
    i: usize,
    depth: usize,
}

const KEYWORDS: &[&str] = &[
    "schema", "detect", "endian", "def", "main", "expect", "field", "let", "require", "fail", "skip", "seek", "while",
    "if", "else", "break", "region", "at", "call", "once", "pos", "end", "size",
];

impl P {
    fn peek(&self) -> &Tok {
        &self.toks[self.i].1
    }
    fn line(&self) -> usize {
        self.toks[self.i].0
    }
    fn next(&mut self) -> Tok {
        let t = self.toks[self.i].1.clone();
        if self.i + 1 < self.toks.len() {
            self.i += 1;
        }
        t
    }
    fn skip_nl(&mut self) {
        while matches!(self.peek(), Tok::Newline | Tok::Sym(";")) {
            self.next();
        }
    }
    fn sym(&mut self, s: &str) -> Result<(), CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Sym(x) if x == s => Ok(()),
            t => err(l, format!("expected `{s}`, found {t:?}")),
        }
    }
    fn is_sym(&self, s: &str) -> bool {
        matches!(self.peek(), Tok::Sym(x) if *x == s)
    }
    fn is_kw(&self, k: &str) -> bool {
        matches!(self.peek(), Tok::Ident(x) if x == k)
    }
    fn kw(&mut self, k: &str) -> Result<(), CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Ident(x) if x == k => Ok(()),
            t => err(l, format!("expected `{k}`, found {t:?}")),
        }
    }
    fn ident(&mut self) -> Result<String, CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Ident(x) if !KEYWORDS.contains(&x.as_str()) => Ok(x),
            t => err(l, format!("expected identifier, found {t:?}")),
        }
    }
    fn string(&mut self) -> Result<String, CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Str(s) => Ok(s),
            t => err(l, format!("expected string, found {t:?}")),
        }
    }
    fn end_stmt(&mut self) -> Result<(), CompileError> {
        match self.peek() {
            Tok::Newline | Tok::Sym(";") => {
                self.next();
                Ok(())
            }
            Tok::Sym("}") | Tok::Eof => Ok(()),
            t => err(self.line(), format!("expected end of statement, found {t:?}")),
        }
    }

    fn block(&mut self) -> Result<Block, CompileError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return err(self.line(), "nesting too deep");
        }
        self.sym("{")?;
        let mut out = Vec::new();
        loop {
            self.skip_nl();
            if self.is_sym("}") {
                self.next();
                break;
            }
            if matches!(self.peek(), Tok::Eof) {
                return err(self.line(), "unterminated block");
            }
            let l = self.line();
            let s = self.stmt()?;
            out.push((l, s));
            self.end_stmt()?;
        }
        self.depth -= 1;
        Ok(out)
    }

    fn endian(&mut self) -> Result<Endian, CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Ident(x) if x == "little" => Ok(Endian::Little),
            Tok::Ident(x) if x == "big" => Ok(Endian::Big),
            t => err(l, format!("expected little or big, found {t:?}")),
        }
    }

    fn stmt(&mut self) -> Result<Stmt, CompileError> {
        let l = self.line();
        let Tok::Ident(kw) = self.next() else {
            return err(l, "expected statement");
        };
        Ok(match kw.as_str() {
            "expect" => {
                let bytes = match self.next() {
                    Tok::Hex(v) => v,
                    t => return err(l, format!("expect needs hex\"..\", found {t:?}")),
                };
                Stmt::Expect(bytes, self.string()?)
            }
            "field" => {
                let name = self.ident()?;
                let ty = self.ident_any()?;
                let (w, e) = parse_int_type(&ty).ok_or(CompileError { line: l, msg: format!("unknown type {ty}") })?;
                Stmt::Field(name, w, e)
            }
            "let" => {
                let name = self.ident()?;
                self.sym("=")?;
                Stmt::Let(name, self.expr()?)
            }
            "require" => {
                let e = self.expr()?;
                Stmt::Require(e, self.string()?)
            }
            "fail" => Stmt::Fail(self.string()?),
            "skip" => Stmt::Skip(self.expr()?),
            "seek" => Stmt::Seek(self.expr()?),
            "while" => {
                let c = self.expr()?;
                Stmt::While(c, self.block()?)
            }
            "if" => self.if_rest()?,
            "break" => Stmt::Break,
            "region" => {
                let e = self.expr()?;
                Stmt::Region(e, self.block()?)
            }
            "at" => {
                let e = self.expr()?;
                Stmt::At(e, self.block()?)
            }
            "call" => Stmt::Call(self.ident()?),
            "once" => {
                let e = self.expr()?;
                Stmt::Once(e, self.string()?)
            }
            "endian" => Stmt::SetEndian(self.endian()?),
            other => return err(l, format!("unknown statement `{other}`")),
        })
    }

    fn ident_any(&mut self) -> Result<String, CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Ident(x) => Ok(x),
            t => err(l, format!("expected identifier, found {t:?}")),
        }
    }

    fn if_rest(&mut self) -> Result<Stmt, CompileError> {
        let c = self.expr()?;
        let then = self.block()?;
        let mut els = Vec::new();
        if self.is_kw("else") {
            self.next();
            if self.is_kw("if") {
                let l = self.line();
                self.next();
                els.push((l, self.if_rest()?));
            } else {
                els = self.block()?;
            }
        }
        Ok(Stmt::If(c, then, els))
    }

    fn expr(&mut self) -> Result<Expr, CompileError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return err(self.line(), "expression too deep");
        }
        let r = self.binary(0);
        self.depth -= 1;
        r
    }

    fn binary(&mut self, min_prec: u8) -> Result<Expr, CompileError> {
        let mut lhs = self.unary()?;
        loop {
            let Tok::Sym(s) = self.peek().clone() else { break };
            let Some(prec) = prec(s) else { break };
            if prec < min_prec {
                break;
            }
            self.next();
            let rhs = self.binary(prec + 1)?;
            lhs = match s {
                "&&" => Expr::LogAnd(Box::new(lhs), Box::new(rhs)),
                "||" => Expr::LogOr(Box::new(lhs), Box::new(rhs)),
                _ => Expr::Bin(binop(s), Box::new(lhs), Box::new(rhs)),
            };
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr, CompileError> {
        if self.is_sym("!") {
            self.next();
            self.depth += 1;
            if self.depth > MAX_NESTING {
                return err(self.line(), "expression too deep");
            }
            let e = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(e)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, CompileError> {
        let l = self.line();
        match self.next() {
            Tok::Num(n) => Ok(Expr::Num(n)),
            Tok::Sym("(") => {
                let e = self.expr()?;
                self.sym(")")?;
                Ok(e)
            }
            Tok::Ident(x) => match x.as_str() {
                "pos" => Ok(Expr::Pos),
                "end" => Ok(Expr::End),
                "size" => Ok(Expr::Size),
                _ if self.is_sym("(") => {
                    self.next();
                    let mut args = Vec::new();
                    if !self.is_sym(")") {
                        loop {
                            args.push(self.expr()?);
                            if self.is_sym(",") {
                                self.next();
                            } else {
                                break;
                            }
                        }
                    }
                    self.sym(")")?;
                    Ok(Expr::Func(x, args))
                }
                _ if KEYWORDS.contains(&x.as_str()) => err(l, format!("keyword `{x}` in expression")),
                _ => Ok(Expr::Var(x)),
            },
            t => err(l, format!("unexpected {t:?} in expression")),
        }
    }
}

fn prec(s: &str) -> Option<u8> {
    Some(match s {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | "<=" | ">" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    })
}

fn binop(s: &str) -> BinOp {
    match s {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "%" => BinOp::Mod,
        "&" => BinOp::And,
        "|" => BinOp::Or,
        "^" => BinOp::Xor,
        "<<" => BinOp::Shl,
        ">>" => BinOp::Shr,
        "==" => BinOp::Eq,
        "!=" => BinOp::Ne,
        "<" => BinOp::Lt,
        "<=" => BinOp::Le,
        ">" => BinOp::Gt,
        _ => BinOp::Ge,
    }
}

pub fn parse_int_type(t: &str) -> Option<(u8, Option<Endian>)> {
    let (base, e) = if let Some(b) = t.strip_suffix("le") {
        (b, Some(Endian::Little))
    } else if let Some(b) = t.strip_suffix("be") {
        (b, Some(Endian::Big))
    } else {
        (t, None)
    };
    let w = match base {
        "u8" => 1,
        "u16" => 2,
        "u32" => 4,
        "u64" => 8,
        _ => return None,
    };
    Some((w, e))
}

pub fn parse(src: &str) -> Result<SchemaAst, CompileError> {
    let mut p = P { toks: lex(src)?, i: 0, depth: 0 };
    p.skip_nl();
    p.kw("schema")?;
    let name = p.ident()?;
    if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') || name.len() > 32 {
        return err(p.line(), "schema name must be lowercase [a-z0-9_]{1,32}");
    }
    p.end_stmt()?;
    let mut detect = Vec::new();
    let mut endian = Endian::Big;
    let mut defs: Vec<Def> = Vec::new();
    let mut main: Option<Def> = None;
    loop {
        p.skip_nl();
        let l = p.line();
        match p.next() {
            Tok::Eof => break,
            Tok::Ident(k) if k == "detect" => {
                p.kw("at")?;
                let off = match p.next() {
                    Tok::Num(n) => n,
                    t => return err(l, format!("detect offset must be a number, found {t:?}")),
                };
                let bytes = match p.next() {
                    Tok::Hex(v) => v,
                    t => return err(l, format!("detect needs hex\"..\", found {t:?}")),
                };
                detect.push((off, bytes));
            }
            Tok::Ident(k) if k == "endian" => endian = p.endian()?,
            Tok::Ident(k) if k == "def" => {
                let n = p.ident()?;
                if defs.iter().any(|d| d.name == n) {
                    return err(l, format!("duplicate def {n}"));
                }
                defs.push(Def { name: n, line: l, body: p.block()? });
            }
            Tok::Ident(k) if k == "main" => {
                if main.is_some() {
                    return err(l, "duplicate main");
                }
                main = Some(Def { name: "main".into(), line: l, body: p.block()? });
            }
            t => return err(l, format!("unexpected top-level {t:?}")),
        }
        p.end_stmt()?;
    }
    let Some(main) = main else { return err(0, "missing main block") };
    if detect.is_empty() {
        return err(0, "at least one detect line is required");
    }
    defs.insert(0, main);
    Ok(SchemaAst { name, detect, endian, defs })
}

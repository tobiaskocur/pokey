//! AST -> IR code generation.

use std::collections::{BTreeSet, HashMap};

use super::ir::{Func, Op, Program, IR_VERSION, MAX_LOCALS};
use super::parser::{Block, Endian, Expr, SchemaAst, Stmt};
use super::CompileError;

#[derive(Clone, Copy)]
enum Frame {
    Region,
    At,
}

struct Loop {
    frame_depth: usize,
    breaks: Vec<usize>,
}

struct Gen<'a> {
    code: Vec<Op>,
    consts: Vec<Vec<u8>>,
    messages: Vec<String>,
    func_ids: &'a HashMap<String, u16>,
    locals: HashMap<String, u16>,
    frames: Vec<Frame>,
    loops: Vec<Loop>,
}

fn err<T>(line: usize, msg: impl Into<String>) -> Result<T, CompileError> {
    Err(CompileError { line, msg: msg.into() })
}

fn collect_assigned(b: &Block, out: &mut BTreeSet<String>) {
    for (_, s) in b {
        match s {
            Stmt::Field(n, _, _) | Stmt::Let(n, _) => {
                out.insert(n.clone());
            }
            Stmt::While(_, b) | Stmt::Region(_, b) | Stmt::At(_, b) => collect_assigned(b, out),
            Stmt::If(_, t, e) => {
                collect_assigned(t, out);
                collect_assigned(e, out);
            }
            _ => {}
        }
    }
}

impl Gen<'_> {
    fn emit(&mut self, op: Op) -> usize {
        self.code.push(op);
        self.code.len() - 1
    }

    fn patch(&mut self, at: usize, target: usize) {
        match &mut self.code[at] {
            Op::Jmp(t) | Op::Jz(t) => *t = target as u32,
            _ => unreachable!("patching a non-jump"),
        }
    }

    fn msg(&mut self, line: usize, m: &str) -> Result<u32, CompileError> {
        if m.len() > 200 {
            return err(line, "message too long");
        }
        let full = format!("{m} (line {line})");
        if let Some(i) = self.messages.iter().position(|x| *x == full) {
            return Ok(i as u32);
        }
        self.messages.push(full);
        Ok((self.messages.len() - 1) as u32)
    }

    fn local(&self, line: usize, n: &str) -> Result<u16, CompileError> {
        self.locals.get(n).copied().ok_or(CompileError { line, msg: format!("unknown variable {n}") })
    }

    fn expr(&mut self, line: usize, e: &Expr) -> Result<(), CompileError> {
        match e {
            Expr::Num(n) => {
                self.emit(Op::Push(*n));
            }
            Expr::Var(v) => {
                let i = self.local(line, v)?;
                self.emit(Op::Load(i));
            }
            Expr::Pos => {
                self.emit(Op::Pos);
            }
            Expr::End => {
                self.emit(Op::End);
            }
            Expr::Size => {
                self.emit(Op::Size);
            }
            Expr::Bin(op, a, b) => {
                self.expr(line, a)?;
                self.expr(line, b)?;
                self.emit(Op::Bin(*op));
            }
            Expr::Not(a) => {
                self.expr(line, a)?;
                self.emit(Op::Not);
            }
            Expr::LogAnd(a, b) | Expr::LogOr(a, b) => {
                let is_and = matches!(e, Expr::LogAnd(..));
                // and: a==0 -> 0; else b!=0.  or: a!=0 -> 1; else b!=0.
                self.expr(line, a)?;
                if !is_and {
                    self.emit(Op::Not);
                }
                let j_short = self.emit(Op::Jz(0));
                self.expr(line, b)?;
                self.emit(Op::Not);
                self.emit(Op::Not);
                let j_end = self.emit(Op::Jmp(0));
                let short = self.emit(Op::Push(if is_and { 0 } else { 1 }));
                self.patch(j_short, short);
                let end = self.code.len();
                self.patch(j_end, end);
            }
            Expr::Func(name, args) => {
                let (arity, op) = match name.as_str() {
                    "u8" => (1, Op::Peek { width: 1 }),
                    "u16" => (1, Op::Peek { width: 2 }),
                    "u32" => (1, Op::Peek { width: 4 }),
                    "u64" => (1, Op::Peek { width: 8 }),
                    "crc32" => (2, Op::Crc32),
                    "min" => (2, Op::Min),
                    "max" => (2, Op::Max),
                    _ => return err(line, format!("unknown function {name}")),
                };
                if args.len() != arity {
                    return err(line, format!("{name} takes {arity} argument(s)"));
                }
                for a in args {
                    self.expr(line, a)?;
                }
                self.emit(op);
            }
        }
        Ok(())
    }

    fn block(&mut self, b: &Block) -> Result<(), CompileError> {
        for (line, s) in b {
            self.stmt(*line, s)?;
        }
        Ok(())
    }

    fn stmt(&mut self, line: usize, s: &Stmt) -> Result<(), CompileError> {
        match s {
            Stmt::Expect(bytes, m) => {
                if bytes.len() > 4096 {
                    return err(line, "expect literal too long");
                }
                self.consts.push(bytes.clone());
                let konst = (self.consts.len() - 1) as u32;
                let msg = self.msg(line, m)?;
                self.emit(Op::Expect { konst, msg });
            }
            Stmt::Field(n, w, e) => {
                let endian = e.map(|e| e == Endian::Little);
                self.emit(Op::Read { width: *w, endian });
                let i = self.local(line, n)?;
                self.emit(Op::Store(i));
            }
            Stmt::Let(n, e) => {
                self.expr(line, e)?;
                let i = self.local(line, n)?;
                self.emit(Op::Store(i));
            }
            Stmt::Require(e, m) => {
                self.expr(line, e)?;
                let msg = self.msg(line, m)?;
                self.emit(Op::Require { msg });
            }
            Stmt::Fail(m) => {
                self.emit(Op::Push(0));
                let msg = self.msg(line, m)?;
                self.emit(Op::Require { msg });
            }
            Stmt::Skip(e) => {
                self.expr(line, e)?;
                self.emit(Op::Skip);
            }
            Stmt::Seek(e) => {
                self.expr(line, e)?;
                self.emit(Op::Seek);
            }
            Stmt::Once(e, m) => {
                self.expr(line, e)?;
                let msg = self.msg(line, m)?;
                self.emit(Op::Once { msg });
            }
            Stmt::SetEndian(e) => {
                self.emit(Op::SetEndian(*e == Endian::Little));
            }
            Stmt::Call(n) => {
                let Some(&id) = self.func_ids.get(n) else {
                    return err(line, format!("unknown def {n}"));
                };
                self.emit(Op::Call(id));
            }
            Stmt::While(c, body) => {
                let top = self.code.len();
                self.expr(line, c)?;
                let j_end = self.emit(Op::Jz(0));
                self.loops.push(Loop { frame_depth: self.frames.len(), breaks: Vec::new() });
                self.block(body)?;
                self.emit(Op::Jmp(top as u32));
                let l = self.loops.pop().unwrap_or(Loop { frame_depth: 0, breaks: Vec::new() });
                let end = self.code.len();
                self.patch(j_end, end);
                for b in l.breaks {
                    self.patch(b, end);
                }
            }
            Stmt::Break => {
                let Some(l) = self.loops.last() else {
                    return err(line, "break outside loop");
                };
                let depth = l.frame_depth;
                let exits: Vec<Frame> = self.frames[depth..].iter().rev().copied().collect();
                for f in exits {
                    self.emit(match f {
                        Frame::Region => Op::RegionExit,
                        Frame::At => Op::AtExit,
                    });
                }
                let j = self.emit(Op::Jmp(0));
                if let Some(l) = self.loops.last_mut() {
                    l.breaks.push(j);
                }
            }
            Stmt::If(c, then, els) => {
                self.expr(line, c)?;
                let j_else = self.emit(Op::Jz(0));
                self.block(then)?;
                if els.is_empty() {
                    let end = self.code.len();
                    self.patch(j_else, end);
                } else {
                    let j_end = self.emit(Op::Jmp(0));
                    let else_start = self.code.len();
                    self.patch(j_else, else_start);
                    self.block(els)?;
                    let end = self.code.len();
                    self.patch(j_end, end);
                }
            }
            Stmt::Region(e, body) | Stmt::At(e, body) => {
                let is_region = matches!(s, Stmt::Region(..));
                self.expr(line, e)?;
                self.emit(if is_region { Op::RegionEnter } else { Op::AtEnter });
                self.frames.push(if is_region { Frame::Region } else { Frame::At });
                self.block(body)?;
                self.frames.pop();
                self.emit(if is_region { Op::RegionExit } else { Op::AtExit });
            }
        }
        Ok(())
    }
}

pub fn generate(ast: &SchemaAst) -> Result<Program, CompileError> {
    let func_ids: HashMap<String, u16> =
        ast.defs.iter().enumerate().map(|(i, d)| (d.name.clone(), i as u16)).collect();
    let mut g = Gen {
        code: Vec::new(),
        consts: Vec::new(),
        messages: Vec::new(),
        func_ids: &func_ids,
        locals: HashMap::new(),
        frames: Vec::new(),
        loops: Vec::new(),
    };
    let mut funcs = Vec::new();
    for d in &ast.defs {
        let mut names = BTreeSet::new();
        collect_assigned(&d.body, &mut names);
        if names.len() > MAX_LOCALS as usize {
            return err(d.line, format!("too many locals in {}", d.name));
        }
        g.locals = names.into_iter().enumerate().map(|(i, n)| (n, i as u16)).collect();
        funcs.push(Func { entry: g.code.len() as u32, nlocals: g.locals.len() as u16 });
        g.block(&d.body)?;
        g.emit(Op::Ret);
    }
    Ok(Program {
        version: IR_VERSION,
        name: ast.name.clone(),
        detect: ast.detect.clone(),
        little_endian: ast.endian == Endian::Little,
        consts: g.consts,
        messages: g.messages,
        funcs,
        code: g.code,
    })
}

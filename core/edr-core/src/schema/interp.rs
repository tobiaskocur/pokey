//! Fuel-limited interpreter for schema IR.
//!
//! Invariants: `base <= pos <= end <= data.len()` at all times; every read is
//! checked against `end` (region) or `data.len()` (peek/crc) with checked
//! arithmetic; every op costs fuel and byte-proportional ops cost extra, so a
//! run either finishes or returns `FuelExhausted`. No input can panic it.

use std::collections::HashSet;

use super::ir::{BinOp, Op, Program};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub fuel: u64,
    pub max_call_depth: usize,
    pub max_frames: usize,
    pub max_stack: usize,
    pub max_once: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel: 10_000_000,
            max_call_depth: 32,
            max_frames: 64,
            max_stack: 256,
            max_once: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    #[error("schema violation at offset {offset}: {msg}")]
    Violation { msg: String, offset: u64 },
    #[error("read outside bounds at offset {offset} (+{len})")]
    OutOfBounds { offset: u64, len: u64 },
    #[error("arithmetic overflow or division by zero near offset {offset}")]
    Arithmetic { offset: u64 },
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("invalid program: {0}")]
    InvalidProgram(&'static str),
}

impl ExecError {
    /// Whether this error says something about the file (as opposed to the
    /// scan running out of resources or a broken program).
    pub fn is_file_defect(&self) -> bool {
        matches!(
            self,
            ExecError::Violation { .. }
                | ExecError::OutOfBounds { .. }
                | ExecError::Arithmetic { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecStats {
    pub fuel_used: u64,
}

#[derive(Clone, Copy)]
enum Frame {
    Region { saved_base: u64, saved_end: u64 },
    At { saved_pos: u64 },
}

struct CallFrame {
    ret_pc: usize,
    locals_base: usize,
    frames_len: usize,
}

struct Vm<'a> {
    p: &'a Program,
    data: &'a [u8],
    lim: Limits,
    fuel: u64,
    pos: u64,
    base: u64,
    end: u64,
    little: bool,
    stack: Vec<u64>,
    locals: Vec<u64>,
    locals_base: usize,
    calls: Vec<CallFrame>,
    frames: Vec<Frame>,
    once: HashSet<u64>,
}

type R<T> = Result<T, ExecError>;

impl Vm<'_> {
    fn pop(&mut self) -> R<u64> {
        self.stack
            .pop()
            .ok_or(ExecError::InvalidProgram("stack underflow"))
    }

    fn push(&mut self, v: u64) -> R<()> {
        if self.stack.len() >= self.lim.max_stack {
            return Err(ExecError::InvalidProgram("stack overflow"));
        }
        self.stack.push(v);
        Ok(())
    }

    fn charge(&mut self, n: u64) -> R<()> {
        self.fuel = self.fuel.checked_sub(n).ok_or(ExecError::FuelExhausted)?;
        Ok(())
    }

    fn arith(&self) -> ExecError {
        ExecError::Arithmetic { offset: self.pos }
    }

    /// Absolute range `[off, off+len)` that must lie within `[lo, hi]`.
    fn range(off: u64, len: u64, lo: u64, hi: u64) -> R<(usize, usize)> {
        let e = off
            .checked_add(len)
            .ok_or(ExecError::OutOfBounds { offset: off, len })?;
        if off < lo || e > hi {
            return Err(ExecError::OutOfBounds { offset: off, len });
        }
        Ok((off as usize, e as usize))
    }

    fn int(&self, b: &[u8], little: bool) -> u64 {
        let mut v = 0u64;
        if little {
            for &x in b.iter().rev() {
                v = (v << 8) | x as u64;
            }
        } else {
            for &x in b {
                v = (v << 8) | x as u64;
            }
        }
        v
    }

    fn violation(&self, msg: u32) -> ExecError {
        let msg = self
            .p
            .messages
            .get(msg as usize)
            .cloned()
            .unwrap_or_default();
        ExecError::Violation {
            msg,
            offset: self.pos,
        }
    }

    fn local_index(&self, i: u16) -> R<usize> {
        let idx = self.locals_base + i as usize;
        if idx >= self.locals.len() {
            return Err(ExecError::InvalidProgram("local out of range"));
        }
        Ok(idx)
    }

    fn enter(&mut self, func: u16, ret_pc: usize) -> R<usize> {
        if self.calls.len() >= self.lim.max_call_depth {
            return Err(ExecError::LimitExceeded("call depth"));
        }
        let f = *self
            .p
            .funcs
            .get(func as usize)
            .ok_or(ExecError::InvalidProgram("bad function"))?;
        self.calls.push(CallFrame {
            ret_pc,
            locals_base: self.locals_base,
            frames_len: self.frames.len(),
        });
        self.locals_base = self.locals.len();
        self.locals
            .resize(self.locals.len() + f.nlocals as usize, 0);
        Ok(f.entry as usize)
    }

    fn exec(&mut self) -> R<()> {
        let mut pc = self.enter(0, usize::MAX)?;
        loop {
            self.charge(1)?;
            let op = *self
                .p
                .code
                .get(pc)
                .ok_or(ExecError::InvalidProgram("pc out of range"))?;
            pc += 1;
            match op {
                Op::Push(v) => self.push(v)?,
                Op::Load(i) => {
                    let v = self.locals[self.local_index(i)?];
                    self.push(v)?;
                }
                Op::Store(i) => {
                    let v = self.pop()?;
                    let idx = self.local_index(i)?;
                    self.locals[idx] = v;
                }
                Op::Pos => self.push(self.pos)?,
                Op::End => self.push(self.end)?,
                Op::Size => self.push(self.data.len() as u64)?,
                Op::Not => {
                    let v = self.pop()?;
                    self.push((v == 0) as u64)?;
                }
                Op::Bin(b) => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    let v = match b {
                        BinOp::Add => l.checked_add(r).ok_or_else(|| self.arith())?,
                        BinOp::Sub => l.checked_sub(r).ok_or_else(|| self.arith())?,
                        BinOp::Mul => l.checked_mul(r).ok_or_else(|| self.arith())?,
                        BinOp::Div => l.checked_div(r).ok_or_else(|| self.arith())?,
                        BinOp::Mod => l.checked_rem(r).ok_or_else(|| self.arith())?,
                        BinOp::Shl => u32::try_from(r)
                            .ok()
                            .and_then(|r| l.checked_shl(r))
                            .ok_or_else(|| self.arith())?,
                        BinOp::Shr => u32::try_from(r)
                            .ok()
                            .and_then(|r| l.checked_shr(r))
                            .ok_or_else(|| self.arith())?,
                        BinOp::And => l & r,
                        BinOp::Or => l | r,
                        BinOp::Xor => l ^ r,
                        BinOp::Eq => (l == r) as u64,
                        BinOp::Ne => (l != r) as u64,
                        BinOp::Lt => (l < r) as u64,
                        BinOp::Le => (l <= r) as u64,
                        BinOp::Gt => (l > r) as u64,
                        BinOp::Ge => (l >= r) as u64,
                    };
                    self.push(v)?;
                }
                Op::Min | Op::Max => {
                    let r = self.pop()?;
                    let l = self.pop()?;
                    self.push(if op == Op::Min { l.min(r) } else { l.max(r) })?;
                }
                Op::Read { width, endian } => {
                    let (s, e) = Self::range(self.pos, width as u64, self.base, self.end)?;
                    let v = self.int(&self.data[s..e], endian.unwrap_or(self.little));
                    self.pos = e as u64;
                    self.push(v)?;
                }
                Op::Peek { width } => {
                    let off = self.pop()?;
                    let (s, e) = Self::range(off, width as u64, 0, self.data.len() as u64)?;
                    let v = self.int(&self.data[s..e], self.little);
                    self.push(v)?;
                }
                Op::Expect { konst, msg } => {
                    let k = self
                        .p
                        .consts
                        .get(konst as usize)
                        .ok_or(ExecError::InvalidProgram("bad const"))?;
                    self.charge(k.len() as u64 / 16)?;
                    let (s, e) = Self::range(self.pos, k.len() as u64, self.base, self.end)?;
                    if self.data[s..e] != k[..] {
                        return Err(self.violation(msg));
                    }
                    self.pos = e as u64;
                }
                Op::Skip => {
                    let n = self.pop()?;
                    let (_, e) = Self::range(self.pos, n, self.base, self.end)?;
                    self.pos = e as u64;
                }
                Op::Seek => {
                    let off = self.pop()?;
                    Self::range(off, 0, self.base, self.end)?;
                    self.pos = off;
                }
                Op::Require { msg } => {
                    if self.pop()? == 0 {
                        return Err(self.violation(msg));
                    }
                }
                Op::Once { msg } => {
                    let v = self.pop()?;
                    if self.once.contains(&v) {
                        return Err(self.violation(msg));
                    }
                    if self.once.len() >= self.lim.max_once {
                        return Err(ExecError::LimitExceeded("once set"));
                    }
                    self.once.insert(v);
                }
                Op::Jmp(t) => pc = t as usize,
                Op::Jz(t) => {
                    if self.pop()? == 0 {
                        pc = t as usize;
                    }
                }
                Op::RegionEnter | Op::AtEnter => {
                    if self.frames.len() >= self.lim.max_frames {
                        return Err(ExecError::LimitExceeded("nested regions"));
                    }
                    let v = self.pop()?;
                    if op == Op::RegionEnter {
                        let (_, e) = Self::range(self.pos, v, self.base, self.end)?;
                        self.frames.push(Frame::Region {
                            saved_base: self.base,
                            saved_end: self.end,
                        });
                        self.base = self.pos;
                        self.end = e as u64;
                    } else {
                        Self::range(v, 0, self.base, self.end)?;
                        self.frames.push(Frame::At {
                            saved_pos: self.pos,
                        });
                        self.pos = v;
                    }
                }
                Op::RegionExit => match self.frames.pop() {
                    Some(Frame::Region {
                        saved_base,
                        saved_end,
                    }) => {
                        self.pos = self.end;
                        self.base = saved_base;
                        self.end = saved_end;
                    }
                    _ => return Err(ExecError::InvalidProgram("unbalanced region")),
                },
                Op::AtExit => match self.frames.pop() {
                    Some(Frame::At { saved_pos }) => self.pos = saved_pos,
                    _ => return Err(ExecError::InvalidProgram("unbalanced at")),
                },
                Op::SetEndian(l) => self.little = l,
                Op::Call(f) => pc = self.enter(f, pc)?,
                Op::Ret => {
                    let c = self
                        .calls
                        .pop()
                        .ok_or(ExecError::InvalidProgram("return without call"))?;
                    if self.frames.len() != c.frames_len {
                        return Err(ExecError::InvalidProgram("unbalanced frames at return"));
                    }
                    self.locals.truncate(self.locals_base);
                    self.locals_base = c.locals_base;
                    if self.calls.is_empty() {
                        return Ok(());
                    }
                    pc = c.ret_pc;
                }
                Op::Crc32 => {
                    let len = self.pop()?;
                    let off = self.pop()?;
                    let (s, e) = Self::range(off, len, 0, self.data.len() as u64)?;
                    self.charge(len / 64)?;
                    self.push(crc32fast::hash(&self.data[s..e]) as u64)?;
                }
            }
        }
    }
}

/// Run `prog` over `data`. `Ok` means the file conforms to the schema.
pub fn run(prog: &Program, data: &[u8], lim: Limits) -> Result<ExecStats, (ExecError, ExecStats)> {
    let mut vm = Vm {
        p: prog,
        data,
        lim,
        fuel: lim.fuel,
        pos: 0,
        base: 0,
        end: data.len() as u64,
        little: prog.little_endian,
        stack: Vec::with_capacity(32),
        locals: Vec::new(),
        locals_base: 0,
        calls: Vec::new(),
        frames: Vec::new(),
        once: HashSet::new(),
    };
    let r = vm.exec();
    let stats = ExecStats {
        fuel_used: lim.fuel - vm.fuel,
    };
    match r {
        Ok(()) => Ok(stats),
        Err(e) => Err((e, stats)),
    }
}

/// Whether `data` starts with one of the program's detect magics.
pub fn detects(prog: &Program, data: &[u8]) -> bool {
    prog.detect.iter().any(|(off, magic)| {
        let o = *off as usize;
        o.checked_add(magic.len()).and_then(|e| data.get(o..e)) == Some(&magic[..])
    })
}

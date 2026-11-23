//! Compiled schema IR and its structural validator.
//!
//! The IR is a flat stack-machine program. Every value is a `u64`. Each
//! function owns a contiguous code range and its own locals. Programs loaded
//! from a bundle are validated before execution; the interpreter additionally
//! checks every index at runtime, so an invalid program yields an error, not a
//! panic.

use serde::{Deserialize, Serialize};

pub use super::parser::BinOp;

pub const IR_VERSION: u32 = 1;
pub const MAX_CODE: usize = 1 << 16;
pub const MAX_LOCALS: u16 = 64;
pub const MAX_FUNCS: usize = 256;
pub const MAX_IR_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Push(u64),
    Load(u16),
    Store(u16),
    Pos,
    End,
    Size,
    Bin(BinOp),
    Not,
    /// Read an integer at the cursor and advance. `endian`: None = current.
    Read {
        width: u8,
        endian: Option<bool>,
    },
    /// Pop offset, push integer at that absolute file offset (current endian).
    Peek {
        width: u8,
    },
    Expect {
        konst: u32,
        msg: u32,
    },
    Skip,
    Seek,
    Require {
        msg: u32,
    },
    Once {
        msg: u32,
    },
    Jmp(u32),
    Jz(u32),
    RegionEnter,
    RegionExit,
    AtEnter,
    AtExit,
    /// true = little endian.
    SetEndian(bool),
    Call(u16),
    Ret,
    Crc32,
    Min,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Func {
    pub entry: u32,
    pub nlocals: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub version: u32,
    pub name: String,
    /// (offset, magic) pairs for format sniffing.
    pub detect: Vec<(u64, Vec<u8>)>,
    pub little_endian: bool,
    pub consts: Vec<Vec<u8>>,
    pub messages: Vec<String>,
    /// funcs[0] is `main`. Function i occupies code[entry_i .. entry_{i+1}].
    pub funcs: Vec<Func>,
    pub code: Vec<Op>,
}

impl Program {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode and validate a program from (signed) bundle bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Program, String> {
        if b.len() > MAX_IR_BYTES {
            return Err("IR too large".into());
        }
        let p: Program = postcard::from_bytes(b).map_err(|e| format!("IR decode: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    /// Code range of function `i`.
    pub fn func_range(&self, i: usize) -> Option<(usize, usize)> {
        let start = self.funcs.get(i)?.entry as usize;
        let end = self
            .funcs
            .get(i + 1)
            .map(|f| f.entry as usize)
            .unwrap_or(self.code.len());
        Some((start, end))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != IR_VERSION {
            return Err(format!("unsupported IR version {}", self.version));
        }
        if self.code.is_empty() || self.code.len() > MAX_CODE {
            return Err("bad code length".into());
        }
        if self.funcs.is_empty() || self.funcs.len() > MAX_FUNCS {
            return Err("bad function count".into());
        }
        if self.funcs[0].entry != 0 {
            return Err("main must start at 0".into());
        }
        if self.detect.is_empty()
            || self
                .detect
                .iter()
                .any(|(o, m)| m.is_empty() || m.len() > 64 || *o > 4096)
        {
            return Err("bad detect entries".into());
        }
        for i in 0..self.funcs.len() {
            let f = self.funcs[i];
            let (start, end) = self.func_range(i).ok_or("bad function")?;
            if start >= end || end > self.code.len() {
                return Err(format!("function {i} has an empty or invalid range"));
            }
            if f.nlocals > MAX_LOCALS {
                return Err(format!("function {i} has too many locals"));
            }
            if self.code[end - 1] != Op::Ret {
                return Err(format!("function {i} does not end with Ret"));
            }
            for op in &self.code[start..end] {
                let ok = match *op {
                    Op::Load(v) | Op::Store(v) => v < f.nlocals,
                    Op::Read { width, .. } | Op::Peek { width } => matches!(width, 1 | 2 | 4 | 8),
                    Op::Expect { konst, msg } => {
                        (konst as usize) < self.consts.len() && (msg as usize) < self.messages.len()
                    }
                    Op::Require { msg } | Op::Once { msg } => (msg as usize) < self.messages.len(),
                    Op::Jmp(t) | Op::Jz(t) => (t as usize) >= start && (t as usize) < end,
                    Op::Call(c) => (c as usize) < self.funcs.len(),
                    _ => true,
                };
                if !ok {
                    return Err(format!("invalid operand in function {i}: {op:?}"));
                }
            }
        }
        Ok(())
    }
}

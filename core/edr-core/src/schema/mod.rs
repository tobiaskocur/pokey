//! Structural schema language.
//!
//! A schema describes a binary container format declaratively: fields read
//! from the cursor, constraints (`require`), repetition, nested regions and
//! subroutines. The compiler ([`compile`]) turns source text into a compact IR
//! ([`ir::Program`]) that ships inside the signed rule bundle. The inspector
//! runs it with [`interp::run`], a fuel-limited interpreter whose every read is
//! bounds-checked against the current region and the file.
//!
//! Language overview (see `rules/schemas/*.schema` for full examples):
//!
//! ```text
//! schema png                          # schema (= format) name
//! detect at 0 hex"89504E470D0A1A0A"   # magic used for format sniffing
//! endian big                          # default byte order
//!
//! def name { ... }                    # subroutine with its own locals
//! main { ... }                        # entry point
//!
//! statements:
//!   expect hex"..." "msg"   field x u32 | u16le | u64be ...   let x = expr
//!   require expr "msg"      fail "msg"   skip expr   seek expr
//!   while expr { }          if expr { } else if expr { } else { }   break
//!   region len { }          at offset { }   call name   once expr "msg"
//!   endian little|big
//! expressions: integers, fourcc"ABCD", locals, pos, end, size,
//!   u8(off) u16(off) u32(off) u64(off) crc32(off, len) min(a,b) max(a,b),
//!   || && | ^ & == != < <= > >= << >> + - * / % !
//! ```

pub mod codegen;
pub mod interp;
pub mod ir;
pub mod parser;

pub use interp::{run, ExecError, ExecStats, Limits};
pub use ir::Program;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("line {line}: {msg}")]
pub struct CompileError {
    pub line: usize,
    pub msg: String,
}

/// Compile schema source text into a validated IR program.
pub fn compile(src: &str) -> Result<Program, CompileError> {
    let ast = parser::parse(src)?;
    let prog = codegen::generate(&ast)?;
    prog.validate().map_err(|e| CompileError { line: 0, msg: format!("internal: generated invalid IR: {e}") })?;
    Ok(prog)
}

#[cfg(test)]
mod tests;

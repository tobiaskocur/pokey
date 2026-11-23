use super::interp::{detects, run, ExecError, Limits};
use super::ir::{Op, Program};
use super::compile;

const PNG: &str = include_str!("../../../../rules/schemas/png.schema");
const TIFF: &str = include_str!("../../../../rules/schemas/tiff.schema");
const ISOBMFF: &str = include_str!("../../../../rules/schemas/isobmff.schema");

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/../../rules/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn exec(src: &str, data: &[u8]) -> Result<u64, ExecError> {
    let p = compile(src).unwrap();
    run(&p, data, Limits::default()).map(|s| s.fuel_used).map_err(|(e, _)| e)
}

fn wrap(body: &str) -> String {
    format!("schema t\ndetect at 0 hex\"00\"\nmain {{\n{body}\n}}\n")
}

fn violation(r: Result<u64, ExecError>) -> String {
    match r {
        Err(ExecError::Violation { msg, .. }) => msg,
        other => panic!("expected violation, got {other:?}"),
    }
}

#[test]
fn shipped_schemas_compile_and_round_trip_through_bytes() {
    for src in [PNG, TIFF, ISOBMFF] {
        let p = compile(src).unwrap();
        let back = Program::from_bytes(&p.to_bytes()).unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn png_fixtures() {
    let p = compile(PNG).unwrap();
    let ok = |n: &str| run(&p, &fixture(n), Limits::default()).map(|_| ()).map_err(|(e, _)| e);
    assert_eq!(ok("png_valid.png"), Ok(()));
    assert_eq!(ok("png_text_chunk.png"), Ok(()));
    assert!(violation(ok("png_trailing_data.png").map(|_| 0)).starts_with("data after IEND"));
    assert!(violation(ok("png_bad_crc.png").map(|_| 0)).starts_with("chunk CRC mismatch"));
    assert!(violation(ok("png_huge_dimensions.png").map(|_| 0)).starts_with("image dimension exceeds"));
    assert!(detects(&p, &fixture("png_valid.png")));
    assert!(!detects(&p, &fixture("tiff_valid.tif")));
}

#[test]
fn png_every_truncation_is_rejected_without_panic() {
    let p = compile(PNG).unwrap();
    let data = fixture("png_text_chunk.png");
    for n in 0..data.len() {
        assert!(run(&p, &data[..n], Limits::default()).is_err(), "prefix {n}");
    }
}

#[test]
fn tiff_fixtures() {
    let p = compile(TIFF).unwrap();
    let r = |n: &str| run(&p, &fixture(n), Limits::default()).map(|s| s.fuel_used).map_err(|(e, _)| e);
    assert!(r("tiff_valid.tif").is_ok());
    assert!(violation(r("tiff_ifd_loop.tif")).starts_with("IFD chain loops"));
    assert!(violation(r("tiff_tag_outside.tif")).starts_with("tag data outside file"));
    // Big-endian header with no IFD.
    assert!(violation(exec(TIFF, b"MM\x00\x2a\x00\x00\x00\x00")).starts_with("no IFD"));
}

#[test]
fn isobmff_fixtures() {
    let p = compile(ISOBMFF).unwrap();
    let r = |n: &str| run(&p, &fixture(n), Limits::default()).map(|s| s.fuel_used).map_err(|(e, _)| e);
    assert!(r("heic_valid.heic").is_ok());
    assert!(violation(r("heic_box_overflow.heic")).starts_with("box extends past its parent"));
    assert_eq!(r("heic_deep_nesting.heic"), Err(ExecError::LimitExceeded("call depth")));
}

#[test]
fn infinite_loop_runs_out_of_fuel() {
    let p = compile(&wrap("while 1 { }")).unwrap();
    let lim = Limits { fuel: 10_000, ..Limits::default() };
    let (e, stats) = run(&p, b"\x00", lim).unwrap_err();
    assert_eq!(e, ExecError::FuelExhausted);
    assert_eq!(stats.fuel_used, 10_000);
}

#[test]
fn unbounded_recursion_hits_call_depth() {
    let src = "schema t\ndetect at 0 hex\"00\"\ndef f {\ncall f\n}\nmain {\ncall f\n}\n";
    assert_eq!(exec(src, b"\x00"), Err(ExecError::LimitExceeded("call depth")));
}

#[test]
fn reads_are_bounds_checked() {
    assert_eq!(exec(&wrap("field x u32"), b"\x00\x01"), Err(ExecError::OutOfBounds { offset: 0, len: 4 }));
    assert_eq!(exec(&wrap("let x = u64(0xffffffffffffffff)"), b"\x00"), Err(ExecError::OutOfBounds { offset: u64::MAX, len: 8 }));
    assert_eq!(exec(&wrap("let x = crc32(1, 0xffffffffffffffff)"), b"\x00"), Err(ExecError::OutOfBounds { offset: 1, len: u64::MAX }));
    assert_eq!(exec(&wrap("skip 2"), b"\x00"), Err(ExecError::OutOfBounds { offset: 0, len: 2 }));
    assert_eq!(exec(&wrap("seek 9"), b"\x00"), Err(ExecError::OutOfBounds { offset: 9, len: 0 }));
    // A region confines reads even though the file has more bytes.
    assert!(matches!(exec(&wrap("region 2 { field x u32 }"), b"\x00\x00\x00\x00"), Err(ExecError::OutOfBounds { .. })));
    // Leaving a region moves the cursor to its end.
    assert_eq!(exec(&wrap("region 2 { }\nrequire pos == 2 \"pos\""), b"\x00\x00\x00").map(|_| ()), Ok(()));
}

#[test]
fn arithmetic_is_checked() {
    assert!(matches!(exec(&wrap("let x = 0 - 1"), b"\x00"), Err(ExecError::Arithmetic { .. })));
    assert!(matches!(exec(&wrap("let x = 1 / 0"), b"\x00"), Err(ExecError::Arithmetic { .. })));
    assert!(matches!(exec(&wrap("let x = 1 << 64"), b"\x00"), Err(ExecError::Arithmetic { .. })));
    assert!(matches!(exec(&wrap("let x = 0xffffffffffffffff * 2"), b"\x00"), Err(ExecError::Arithmetic { .. })));
}

#[test]
fn language_semantics() {
    let src = wrap(
        "field a u16le\nfield b u16\nrequire a == 0x0201 \"le\"\nrequire b == 0x0304 \"be default\"\n\
         let n = 0\nwhile 1 { let n = n + 1\nif n == 5 { break } }\nrequire n == 5 \"break\"\n\
         require (1 || 0) && !(0 && 1) \"logic\"\nrequire min(3, 4) + max(3, 4) == 7 \"minmax\"\n\
         at 0 { field c u8\nrequire c == 1 \"at\" }\nrequire pos == 4 \"at restores pos\"\n\
         require fourcc\"ABCD\" == 0x41424344 \"fourcc\"\nrequire size == 4 && end == 4 \"size\"",
    );
    assert_eq!(exec(&src, b"\x01\x02\x03\x04").map(|_| ()), Ok(()));
}

#[test]
fn break_inside_region_restores_frames() {
    // Leaving a region by break still moves the cursor to the region end.
    let src = wrap("while 1 {\nregion 1 {\nbreak\n}\n}\nrequire pos == 1 \"pos\"\nfield x u8");
    assert_eq!(exec(&src, b"\x00\x00").map(|_| ()), Ok(()));
}

#[test]
fn once_detects_repeats() {
    let src = wrap("once 1 \"a\"\nonce 2 \"b\"\nonce 1 \"repeat\"");
    assert!(violation(exec(&src, b"\x00")).starts_with("repeat"));
}

#[test]
fn compile_errors_have_lines() {
    let e = compile(&wrap("let x = y")).unwrap_err();
    assert_eq!(e.line, 4);
    assert!(compile(&wrap("break")).is_err());
    assert!(compile(&wrap("call nope")).is_err());
    assert!(compile(&wrap("field x u24")).is_err());
    assert!(compile(&wrap("let pos = 1")).is_err());
    assert!(compile("schema t\nmain { }\n").is_err(), "detect required");
    assert!(compile(&wrap(&"if 1 {".repeat(100))).is_err());
    assert!(compile(&wrap(&format!("let x = {}1{}", "(".repeat(100), ")".repeat(100)))).is_err());
}

#[test]
fn invalid_ir_is_rejected_before_execution() {
    let good = compile(&wrap("let x = 1")).unwrap();
    let mut cases = Vec::new();
    let mut p = good.clone();
    p.code[0] = Op::Jmp(999);
    cases.push(p);
    let mut p = good.clone();
    p.code[1] = Op::Store(7);
    cases.push(p);
    let mut p = good.clone();
    p.code.pop(); // no trailing Ret
    cases.push(p);
    let mut p = good.clone();
    p.code[0] = Op::Read { width: 3, endian: None };
    cases.push(p);
    let mut p = good.clone();
    p.code[0] = Op::Call(5);
    cases.push(p);
    let mut p = good.clone();
    p.version = 99;
    cases.push(p);
    for p in cases {
        assert!(Program::from_bytes(&p.to_bytes()).is_err(), "{:?}", p.code);
    }
    assert!(Program::from_bytes(b"\xff\xff\xff").is_err());
}

#[test]
fn unvalidated_ir_errors_instead_of_panicking() {
    // Bypasses validate(): the interpreter must still not panic.
    let mut p = compile(&wrap("let x = 1")).unwrap();
    p.code = vec![Op::Bin(super::parser::BinOp::Add), Op::RegionExit, Op::Ret];
    assert_eq!(run(&p, b"\x00", Limits::default()).unwrap_err().0, ExecError::InvalidProgram("stack underflow"));
    p.code = vec![Op::Load(40), Op::Ret];
    assert_eq!(run(&p, b"\x00", Limits::default()).unwrap_err().0, ExecError::InvalidProgram("local out of range"));
    p.code = vec![Op::Push(0), Op::Jmp(0)];
    assert_eq!(run(&p, b"\x00", Limits::default()).unwrap_err().0, ExecError::InvalidProgram("stack overflow"));
}

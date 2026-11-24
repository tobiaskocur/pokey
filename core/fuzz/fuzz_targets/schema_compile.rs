//! Schema compiler on arbitrary text; whatever compiles must also round-trip
//! through the IR loader and run safely.
#![no_main]
use pokey_core::schema::{compile, run, Limits, Program};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else { return };
    if let Ok(p) = compile(src) {
        let p2 = Program::from_bytes(&p.to_bytes()).expect("compiled IR reloads");
        let _ = run(&p2, data, Limits { fuel: 100_000, ..Limits::default() });
    }
});

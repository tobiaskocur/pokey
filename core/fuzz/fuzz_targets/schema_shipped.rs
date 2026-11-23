//! The shipped schemas against arbitrary file contents.
#![no_main]
use std::sync::OnceLock;

use pokey_core::schema::{compile, run, Limits, Program};
use libfuzzer_sys::fuzz_target;

fn programs() -> &'static [Program] {
    static P: OnceLock<Vec<Program>> = OnceLock::new();
    P.get_or_init(|| {
        [
            include_str!("../../../rules/schemas/png.schema"),
            include_str!("../../../rules/schemas/tiff.schema"),
            include_str!("../../../rules/schemas/isobmff.schema"),
        ]
        .iter()
        .map(|s| compile(s).expect("shipped schema compiles"))
        .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    for p in programs() {
        let _ = run(p, data, Limits { fuel: 2_000_000, ..Limits::default() });
    }
});

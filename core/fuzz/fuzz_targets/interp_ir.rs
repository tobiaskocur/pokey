//! Arbitrary IR bytes + data: the loader must reject anything invalid and the
//! interpreter must never panic or run past its fuel on what it accepts.
#![no_main]
use pokey_core::schema::{run, Limits, Program};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((&n, rest)) = input.split_first() else { return };
    let (ir, data) = rest.split_at((n as usize * 4).min(rest.len()));
    if let Ok(p) = Program::from_bytes(ir) {
        let lim = Limits { fuel: 200_000, ..Limits::default() };
        if let Ok(st) = run(&p, data, lim) {
            assert!(st.fuel_used <= lim.fuel);
        }
    }
});

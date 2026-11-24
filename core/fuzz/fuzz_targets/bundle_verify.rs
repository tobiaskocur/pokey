//! Bundle verification on arbitrary bytes must fail cleanly (no panic, no
//! manifest parse before signatures).
#![no_main]
use pokey_core::bundle::{verify, TrustAnchors, VerifyMode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let roots = [1u8, 2, 3].map(|i| ed25519_dalek::SigningKey::from_bytes(&[i; 32]).verifying_key());
    let a = TrustAnchors::new(roots.to_vec(), 2).expect("anchors");
    let _ = verify(data, &a, VerifyMode::Load { now: 0 });
    let _ = verify(data, &a, VerifyMode::Activation { now: 0, current_version: Some(1) });
});

use std::ffi::CStr;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use pokey_core::bundle::{self, Channel, ReleaseCert, CHANNEL_STABLE};

use super::*;

const HEADER: &str = include_str!("../include/pokey_core.h");

fn define(name: &str) -> i64 {
    let line = HEADER
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name))
        .unwrap_or_else(|| panic!("{name} missing from pokey_core.h"));
    line.split_whitespace().nth(2).unwrap().parse().unwrap()
}

#[test]
fn header_constants_match_rust() {
    for (n, v) in [
        ("POKEY_OK", POKEY_OK),
        ("POKEY_ERR_ARGUMENT", POKEY_ERR_ARGUMENT),
        ("POKEY_ERR_BUNDLE", POKEY_ERR_BUNDLE),
        ("POKEY_ERR_ENGINE", POKEY_ERR_ENGINE),
        ("POKEY_ERR_SELF_TEST", POKEY_ERR_SELF_TEST),
        ("POKEY_ERR_NOT_FOUND", POKEY_ERR_NOT_FOUND),
        ("POKEY_ERR_PANIC", POKEY_ERR_PANIC),
    ] {
        assert_eq!(define(n), v as i64, "{n}");
    }
    assert_eq!(
        define("POKEY_MODE_ACTIVATION"),
        POKEY_MODE_ACTIVATION as i64
    );
    assert_eq!(define("POKEY_MODE_LOAD"), POKEY_MODE_LOAD as i64);
    for o in Outcome::ALL {
        assert_eq!(define(&format!("POKEY_OUTCOME_{}", o.name())), o as i64);
    }
    assert_eq!(define("POKEY_CHANNEL_STABLE"), CHANNEL_STABLE as i64);
    assert_eq!(
        define("POKEY_CHANNEL_CANARY"),
        bundle::CHANNEL_CANARY as i64
    );
}

#[test]
fn every_exported_function_is_declared() {
    let src = include_str!("lib.rs");
    let mut n = 0;
    for l in src.lines() {
        let Some(rest) = l.split("extern \"C\" fn ").nth(1) else {
            continue;
        };
        let name = rest.split('(').next().unwrap();
        assert!(
            HEADER.contains(&format!(" {name}(")) || HEADER.contains(&format!("*{name}(")),
            "{name} not in header"
        );
        n += 1;
    }
    assert!(n >= 17, "found only {n} exports");
}

struct Fixture {
    bytes: Vec<u8>,
    roots: Vec<u8>,
}

fn signed_bundle(version: u64) -> Fixture {
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let rs = pokey_rulec::RuleSet::load(&rules).unwrap();
    let roots: Vec<SigningKey> = (1..=3u8)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect();
    let release = SigningKey::from_bytes(&[9; 32]);
    let mut cert = ReleaseCert::unsigned(
        release.verifying_key().to_bytes(),
        0,
        i64::MAX / 2,
        CHANNEL_STABLE,
    );
    cert.add_root_signature(&roots[0]);
    cert.add_root_signature(&roots[2]);
    let unsigned = bundle::build_unsigned(
        rs.manifest(version, Channel::Stable, 1_000, 2_000),
        &rs.artifacts().unwrap(),
    )
    .unwrap();
    let bytes = bundle::sign(&unsigned, &cert, &mut |m| Ok(release.sign(m).to_bytes())).unwrap();
    Fixture {
        bytes,
        roots: roots
            .iter()
            .flat_map(|k| k.verifying_key().to_bytes())
            .collect(),
    }
}

unsafe fn open(
    f: &Fixture,
    now: i64,
    mode: u32,
    current: Option<u64>,
) -> Result<*mut PokeyBundle, (i32, String)> {
    let mut out = ptr::null_mut();
    let mut err = [0 as c_char; 256];
    let cur = current.as_ref().map_or(ptr::null(), |c| c as *const u64);
    let rc = pokey_bundle_open(
        f.bytes.as_ptr(),
        f.bytes.len(),
        f.roots.as_ptr(),
        3,
        2,
        now,
        mode,
        cur,
        &mut out,
        err.as_mut_ptr(),
        err.len(),
    );
    if rc == POKEY_OK {
        Ok(out)
    } else {
        assert!(out.is_null());
        Err((
            rc,
            CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned(),
        ))
    }
}

#[test]
fn activation_load_scan_and_self_test() {
    let f = signed_bundle(5);
    unsafe {
        // Activation: expired at now=3000, rollback, then success.
        assert_eq!(
            open(&f, 3_000, POKEY_MODE_ACTIVATION, None).unwrap_err().0,
            POKEY_ERR_BUNDLE
        );
        let (rc, msg) = open(&f, 1_500, POKEY_MODE_ACTIVATION, Some(5)).unwrap_err();
        assert_eq!(rc, POKEY_ERR_BUNDLE);
        assert!(msg.contains("not newer"), "{msg}");
        let b = open(&f, 1_500, POKEY_MODE_ACTIVATION, Some(4)).unwrap();
        pokey_bundle_free(b);

        // Load mode keeps an expired bundle usable and says so.
        let b = open(&f, 3_000, POKEY_MODE_LOAD, None).unwrap();
        let mut info = PokeyBundleInfo::default();
        assert_eq!(pokey_bundle_info(b, &mut info), POKEY_OK);
        assert_eq!(
            (info.version, info.expired, info.channel, info.self_tests),
            (5, true, 1, 5)
        );

        let mut name = [0 as c_char; 32];
        assert_eq!(
            pokey_bundle_format_for_extension(b, c"HEIC".as_ptr(), name.as_mut_ptr(), 32),
            POKEY_OK
        );
        assert_eq!(CStr::from_ptr(name.as_ptr()).to_str().unwrap(), "isobmff");
        assert_eq!(
            pokey_bundle_format_for_extension(b, c"exe".as_ptr(), name.as_mut_ptr(), 32),
            POKEY_ERR_NOT_FOUND
        );
        assert_eq!(
            pokey_bundle_format_for_extension(b, c"png".as_ptr(), name.as_mut_ptr(), 3),
            POKEY_ERR_ARGUMENT
        );
        let mut fp = PokeyFormatPolicy::default();
        assert_eq!(
            pokey_bundle_format_policy(b, ptr::null(), &mut fp),
            POKEY_OK
        );
        assert!(!fp.decode);
        assert_eq!(
            pokey_bundle_format_policy(b, c"png".as_ptr(), &mut fp),
            POKEY_OK
        );
        assert!(fp.decode && fp.deadline_ms == 5000);
        let mut act = PokeyAction::default();
        assert_eq!(
            pokey_bundle_action(b, Outcome::StaticMatch as u32, &mut act),
            POKEY_OK
        );
        assert_eq!((act.severity, act.action), (3, 2));
        assert_eq!(pokey_bundle_action(b, 99, &mut act), POKEY_ERR_ARGUMENT);

        let mut e = ptr::null_mut();
        assert_eq!(pokey_engine_new(b, &mut e, ptr::null_mut(), 0), POKEY_OK);
        let mut passed = 0;
        assert_eq!(
            pokey_engine_self_test(e, b, &mut passed, ptr::null_mut(), 0),
            POKEY_OK
        );
        assert_eq!(passed, 5);

        let data = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../rules/fixtures/png_trailing_macho.png"),
        )
        .unwrap();
        let r = pokey_engine_scan(e, data.as_ptr(), data.len(), c"png".as_ptr());
        assert!(!r.is_null());
        assert_eq!(pokey_report_outcome(r), Outcome::StaticMatch as u32);
        assert_eq!(
            CStr::from_ptr(pokey_report_format(r)).to_str().unwrap(),
            "png"
        );
        let hits: Vec<_> = (0..pokey_report_hit_count(r))
            .map(|i| {
                CStr::from_ptr(pokey_report_hit(r, i))
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(
            hits.contains(&"image_with_embedded_macho".to_string()),
            "{hits:?}"
        );
        assert!(pokey_report_hit(r, 99).is_null());
        pokey_report_free(r);

        let r = pokey_engine_scan(e, ptr::null(), 0, ptr::null());
        assert_eq!(pokey_report_outcome(r), Outcome::Clean as u32);
        assert!(pokey_report_format(r).is_null());
        pokey_report_free(r);
        assert!(pokey_engine_scan(e, ptr::null(), 1, ptr::null()).is_null());
        assert_eq!(pokey_report_outcome(ptr::null()), Outcome::Crash as u32);

        pokey_engine_free(e);
        pokey_bundle_free(b);
    }
}

#[test]
fn rejected_inputs() {
    let mut f = signed_bundle(1);
    unsafe {
        // Below threshold: only 1 of the 3 pinned roots matches.
        let other: Vec<u8> = (20..=22u8)
            .flat_map(|i| SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes())
            .collect();
        let g = Fixture {
            bytes: f.bytes.clone(),
            roots: [&f.roots[..32], &other[32..]].concat(),
        };
        assert_eq!(
            open(&g, 1_500, POKEY_MODE_LOAD, None).unwrap_err().0,
            POKEY_ERR_BUNDLE
        );

        let n = f.bytes.len();
        f.bytes[n - 1] ^= 0x80;
        assert_eq!(
            open(&f, 1_500, POKEY_MODE_LOAD, None).unwrap_err().0,
            POKEY_ERR_BUNDLE
        );
        assert_eq!(open(&f, 1_500, 7, None).unwrap_err().0, POKEY_ERR_ARGUMENT);

        let mut out = ptr::null_mut();
        let rc = pokey_bundle_open(
            ptr::null(),
            10,
            f.roots.as_ptr(),
            3,
            2,
            0,
            1,
            ptr::null(),
            &mut out,
            ptr::null_mut(),
            0,
        );
        assert_eq!(rc, POKEY_ERR_ARGUMENT);
        let rc = pokey_bundle_open(
            f.bytes.as_ptr(),
            f.bytes.len(),
            f.roots.as_ptr(),
            3,
            4,
            0,
            1,
            ptr::null(),
            &mut out,
            ptr::null_mut(),
            0,
        );
        assert_eq!(rc, POKEY_ERR_ARGUMENT);
        let mut info = PokeyBundleInfo::default();
        assert_eq!(
            pokey_bundle_info(ptr::null(), &mut info),
            POKEY_ERR_ARGUMENT
        );
    }
}

#[test]
fn error_message_is_truncated_and_terminated() {
    let mut buf = [1 as c_char; 8];
    unsafe { write_err(buf.as_mut_ptr(), buf.len(), "a long message") };
    assert_eq!(
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap(),
        "a long "
    );
}

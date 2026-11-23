//! C ABI over `pokey-core` for the Swift components. The header is
//! `include/pokey_core.h`; keep both in sync (a test checks the constants).
//!
//! Conventions:
//! - Every entry point catches panics and returns `POKEY_ERR_PANIC` (or NULL).
//! - Errors write a NUL-terminated, truncated message into a caller buffer
//!   (`err`, `err_cap`; both may be NULL/0).
//! - Handles are owned by the caller and released with the matching `_free`.
//!   They are immutable after creation and safe to share across threads.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use pokey_core::bundle::{self, Channel, Manifest, TrustAnchors, VerifyMode};
use pokey_core::engine::{Engine, Outcome, ScanReport};
use pokey_core::policy::{ActionKind, FormatPolicy, Policy, Severity};

pub const POKEY_OK: i32 = 0;
pub const POKEY_ERR_ARGUMENT: i32 = 1;
pub const POKEY_ERR_BUNDLE: i32 = 2;
pub const POKEY_ERR_ENGINE: i32 = 3;
pub const POKEY_ERR_SELF_TEST: i32 = 4;
pub const POKEY_ERR_NOT_FOUND: i32 = 5;
pub const POKEY_ERR_PANIC: i32 = 6;

pub const POKEY_MODE_ACTIVATION: u32 = 0;
pub const POKEY_MODE_LOAD: u32 = 1;

/// Upper bound for a bundle handed across the ABI (header limits allow less).
const MAX_BUNDLE_LEN: usize = 80 << 20;

/// A verified rule bundle. Owns a copy of the bytes.
pub struct PokeyBundle {
    bytes: Vec<u8>,
    anchors: TrustAnchors,
    now: i64,
    manifest: Manifest,
    expired: bool,
    policy: Policy,
}

impl PokeyBundle {
    /// Re-verify the owned bytes (load mode) to borrow a `VerifiedBundle`.
    fn verified(&self) -> Result<bundle::VerifiedBundle<'_>, String> {
        bundle::verify(
            &self.bytes,
            &self.anchors,
            VerifyMode::Load { now: self.now },
        )
        .map_err(|e| e.to_string())
    }
}

pub struct PokeyEngine {
    engine: Engine,
}

pub struct PokeyReport {
    outcome: u32,
    offset: u64,
    fuel_used: u64,
    format: Option<CString>,
    detail: CString,
    hits: Vec<CString>,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PokeyBundleInfo {
    pub version: u64,
    pub created: i64,
    pub expires: i64,
    /// `POKEY_CHANNEL_*`
    pub channel: u8,
    /// Load mode only: the manifest expiry is in the past (keep scanning,
    /// raise a stale-rules alert).
    pub expired: bool,
    pub memory_limit_mb: u32,
    pub self_tests: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PokeyFormatPolicy {
    pub decode: bool,
    pub max_bytes: u64,
    pub max_pixels: u64,
    pub deadline_ms: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PokeyAction {
    /// `POKEY_SEVERITY_*`
    pub severity: u8,
    /// `POKEY_ACTION_*`
    pub action: u8,
}

fn guard<F: FnOnce() -> i32>(f: F) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(POKEY_ERR_PANIC)
}

unsafe fn write_err(err: *mut c_char, cap: usize, msg: &str) {
    if err.is_null() || cap == 0 {
        return;
    }
    let b = msg.as_bytes();
    let n = b.len().min(cap - 1);
    ptr::copy_nonoverlapping(b.as_ptr(), err.cast::<u8>(), n);
    *err.add(n) = 0;
}

unsafe fn slice<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if p.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(p, len))
    }
}

unsafe fn opt_str<'a>(p: *const c_char) -> Result<Option<&'a str>, ()> {
    if p.is_null() {
        return Ok(None);
    }
    CStr::from_ptr(p).to_str().map(Some).map_err(|_| ())
}

fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "\u{fffd}")).unwrap_or_default()
}

fn format_policy(f: &FormatPolicy) -> PokeyFormatPolicy {
    PokeyFormatPolicy {
        decode: f.decode,
        max_bytes: f.max_bytes,
        max_pixels: f.max_pixels,
        deadline_ms: f.deadline_ms,
    }
}

/// Verify `bytes` against `n_roots` pinned 32-byte Ed25519 root keys
/// (`roots`, concatenated) with `threshold`. `mode` is `POKEY_MODE_ACTIVATION`
/// (cert window, expiry and `current_version` enforced; `current_version`
/// may be NULL when no bundle is active) or `POKEY_MODE_LOAD`.
#[no_mangle]
pub unsafe extern "C" fn pokey_bundle_open(
    bytes: *const u8,
    len: usize,
    roots: *const u8,
    n_roots: usize,
    threshold: usize,
    now: i64,
    mode: u32,
    current_version: *const u64,
    out: *mut *mut PokeyBundle,
    err: *mut c_char,
    err_cap: usize,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return POKEY_ERR_ARGUMENT;
        }
        *out = ptr::null_mut();
        let fail = |code, msg: &str| {
            write_err(err, err_cap, msg);
            code
        };
        if len > MAX_BUNDLE_LEN {
            return fail(POKEY_ERR_BUNDLE, "bundle too large");
        }
        let (Some(data), Some(root_bytes)) =
            (slice(bytes, len), slice(roots, n_roots.saturating_mul(32)))
        else {
            return fail(POKEY_ERR_ARGUMENT, "null pointer");
        };
        let raw: Vec<[u8; 32]> = root_bytes
            .chunks_exact(32)
            .map(|c| c.try_into().unwrap_or([0; 32]))
            .collect();
        let anchors = match TrustAnchors::from_raw(&raw, threshold) {
            Ok(a) => a,
            Err(m) => return fail(POKEY_ERR_ARGUMENT, m),
        };
        let vmode = match mode {
            POKEY_MODE_ACTIVATION => VerifyMode::Activation {
                now,
                current_version: if current_version.is_null() {
                    None
                } else {
                    Some(*current_version)
                },
            },
            POKEY_MODE_LOAD => VerifyMode::Load { now },
            _ => return fail(POKEY_ERR_ARGUMENT, "unknown mode"),
        };
        let (manifest, expired, policy) = match bundle::verify(data, &anchors, vmode) {
            Ok(v) => {
                let Some((_, pol)) = v.artifacts_of(bundle::ArtifactKind::Policy).next() else {
                    return fail(POKEY_ERR_BUNDLE, "bundle has no policy");
                };
                match Policy::parse(pol) {
                    Ok(p) => (v.manifest, v.expired, p),
                    Err(m) => return fail(POKEY_ERR_BUNDLE, &m),
                }
            }
            Err(e) => return fail(POKEY_ERR_BUNDLE, &e.to_string()),
        };
        *out = Box::into_raw(Box::new(PokeyBundle {
            bytes: data.to_vec(),
            anchors,
            now,
            manifest,
            expired,
            policy,
        }));
        POKEY_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn pokey_bundle_free(b: *mut PokeyBundle) {
    if !b.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(b))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pokey_bundle_info(
    b: *const PokeyBundle,
    out: *mut PokeyBundleInfo,
) -> i32 {
    guard(|| {
        let (Some(b), false) = (b.as_ref(), out.is_null()) else {
            return POKEY_ERR_ARGUMENT;
        };
        let m = &b.manifest;
        *out = PokeyBundleInfo {
            version: m.version,
            created: m.created,
            expires: m.expires,
            channel: match m.channel {
                Channel::Stable => bundle::CHANNEL_STABLE,
                Channel::Canary => bundle::CHANNEL_CANARY,
            },
            expired: b.expired,
            memory_limit_mb: b.policy.memory_limit_mb,
            self_tests: m.self_tests.len() as u32,
        };
        POKEY_OK
    })
}

/// Format name for a file extension (without dot, any case). Writes the
/// NUL-terminated name into `name`; returns `POKEY_ERR_NOT_FOUND` when the
/// extension is not mapped (use format `other`).
#[no_mangle]
pub unsafe extern "C" fn pokey_bundle_format_for_extension(
    b: *const PokeyBundle,
    ext: *const c_char,
    name: *mut c_char,
    name_cap: usize,
) -> i32 {
    guard(|| {
        let (Some(b), Ok(Some(ext))) = (b.as_ref(), opt_str(ext)) else {
            return POKEY_ERR_ARGUMENT;
        };
        match b.policy.format_for_extension(ext) {
            Some(n) if n.len() < name_cap && !name.is_null() => {
                write_err(name, name_cap, n);
                POKEY_OK
            }
            Some(_) => POKEY_ERR_ARGUMENT,
            None => POKEY_ERR_NOT_FOUND,
        }
    })
}

/// Limits for `format` (NULL or unknown falls back to `other`).
#[no_mangle]
pub unsafe extern "C" fn pokey_bundle_format_policy(
    b: *const PokeyBundle,
    format: *const c_char,
    out: *mut PokeyFormatPolicy,
) -> i32 {
    guard(|| {
        let (Some(b), Ok(format), false) = (b.as_ref(), opt_str(format), out.is_null()) else {
            return POKEY_ERR_ARGUMENT;
        };
        match b.policy.format(format.unwrap_or("other")) {
            Some(f) => {
                *out = format_policy(f);
                POKEY_OK
            }
            None => POKEY_ERR_NOT_FOUND,
        }
    })
}

/// Severity and action the bundle policy assigns to `outcome` (`POKEY_OUTCOME_*`).
#[no_mangle]
pub unsafe extern "C" fn pokey_bundle_action(
    b: *const PokeyBundle,
    outcome: u32,
    out: *mut PokeyAction,
) -> i32 {
    guard(|| {
        let (Some(b), false) = (b.as_ref(), out.is_null()) else {
            return POKEY_ERR_ARGUMENT;
        };
        let Some(o) = Outcome::ALL.into_iter().find(|o| *o as u32 == outcome) else {
            return POKEY_ERR_ARGUMENT;
        };
        let Some(a) = b.policy.outcomes.get(o.name()) else {
            return POKEY_ERR_NOT_FOUND;
        };
        *out = PokeyAction {
            severity: match a.severity {
                Severity::None => 0,
                Severity::Low => 1,
                Severity::Medium => 2,
                Severity::High => 3,
                Severity::Critical => 4,
            },
            action: match a.action {
                ActionKind::Allow => 0,
                ActionKind::Log => 1,
                ActionKind::Alert => 2,
                ActionKind::Quarantine => 3,
            },
        };
        POKEY_OK
    })
}

/// Build the scan engine (compiles YARA; call during inspector pre-warm,
/// before entering the sandbox profile if compilation needs it).
#[no_mangle]
pub unsafe extern "C" fn pokey_engine_new(
    b: *const PokeyBundle,
    out: *mut *mut PokeyEngine,
    err: *mut c_char,
    err_cap: usize,
) -> i32 {
    guard(|| {
        let (Some(b), false) = (b.as_ref(), out.is_null()) else {
            return POKEY_ERR_ARGUMENT;
        };
        *out = ptr::null_mut();
        let engine = b
            .verified()
            .and_then(|v| Engine::from_bundle(&v).map_err(|e| e.to_string()));
        match engine {
            Ok(engine) => {
                *out = Box::into_raw(Box::new(PokeyEngine { engine }));
                POKEY_OK
            }
            Err(m) => {
                write_err(err, err_cap, &m);
                POKEY_ERR_ENGINE
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn pokey_engine_free(e: *mut PokeyEngine) {
    if !e.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(e))));
    }
}

/// Run the bundle's self-test vectors. `passed` receives the vector count.
#[no_mangle]
pub unsafe extern "C" fn pokey_engine_self_test(
    e: *const PokeyEngine,
    b: *const PokeyBundle,
    passed: *mut u32,
    err: *mut c_char,
    err_cap: usize,
) -> i32 {
    guard(|| {
        let (Some(e), Some(b)) = (e.as_ref(), b.as_ref()) else {
            return POKEY_ERR_ARGUMENT;
        };
        match b.verified().and_then(|v| e.engine.self_test(&v)) {
            Ok(n) => {
                if !passed.is_null() {
                    *passed = n as u32;
                }
                POKEY_OK
            }
            Err(m) => {
                write_err(err, err_cap, &m);
                POKEY_ERR_SELF_TEST
            }
        }
    })
}

/// Stage-1 scan of `len` bytes. `hint` is the sensor's extension-derived
/// format name or NULL. Returns NULL only on invalid arguments or panic
/// (treat as `POKEY_OUTCOME_CRASH`).
#[no_mangle]
pub unsafe extern "C" fn pokey_engine_scan(
    e: *const PokeyEngine,
    data: *const u8,
    len: usize,
    hint: *const c_char,
) -> *mut PokeyReport {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(e), Some(data), Ok(hint)) = (e.as_ref(), slice(data, len), opt_str(hint)) else {
            return ptr::null_mut();
        };
        let r: ScanReport = e.engine.scan(data, hint);
        Box::into_raw(Box::new(PokeyReport {
            outcome: r.outcome as u32,
            offset: r.offset,
            fuel_used: r.fuel_used,
            format: r.format.as_deref().map(cstring),
            detail: cstring(&r.detail),
            hits: r.hits.iter().map(|h| cstring(h)).collect(),
        }))
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pokey_report_free(r: *mut PokeyReport) {
    if !r.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(r))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pokey_report_outcome(r: *const PokeyReport) -> u32 {
    r.as_ref().map_or(Outcome::Crash as u32, |r| r.outcome)
}

#[no_mangle]
pub unsafe extern "C" fn pokey_report_offset(r: *const PokeyReport) -> u64 {
    r.as_ref().map_or(0, |r| r.offset)
}

#[no_mangle]
pub unsafe extern "C" fn pokey_report_fuel_used(r: *const PokeyReport) -> u64 {
    r.as_ref().map_or(0, |r| r.fuel_used)
}

/// Detected format name, or NULL. Valid until `pokey_report_free`.
#[no_mangle]
pub unsafe extern "C" fn pokey_report_format(r: *const PokeyReport) -> *const c_char {
    r.as_ref()
        .and_then(|r| r.format.as_ref())
        .map_or(ptr::null(), |s| s.as_ptr())
}

/// Human-readable detail (never NULL for a valid report).
#[no_mangle]
pub unsafe extern "C" fn pokey_report_detail(r: *const PokeyReport) -> *const c_char {
    r.as_ref().map_or(ptr::null(), |r| r.detail.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn pokey_report_hit_count(r: *const PokeyReport) -> usize {
    r.as_ref().map_or(0, |r| r.hits.len())
}

/// Rule or schema name `i`, or NULL when out of range.
#[no_mangle]
pub unsafe extern "C" fn pokey_report_hit(r: *const PokeyReport, i: usize) -> *const c_char {
    r.as_ref()
        .and_then(|r| r.hits.get(i))
        .map_or(ptr::null(), |s| s.as_ptr())
}

/// Engine version compared against the bundle's `min_engine`.
#[no_mangle]
pub extern "C" fn pokey_engine_version() -> u32 {
    pokey_core::ENGINE_VERSION
}

#[cfg(test)]
mod tests;

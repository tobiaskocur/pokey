//! C ABI over `edr-core` for the Swift components. The header is
//! `include/edr_core.h`; keep both in sync (a test checks the constants).
//!
//! Conventions:
//! - Every entry point catches panics and returns `EDR_ERR_PANIC` (or NULL).
//! - Errors write a NUL-terminated, truncated message into a caller buffer
//!   (`err`, `err_cap`; both may be NULL/0).
//! - Handles are owned by the caller and released with the matching `_free`.
//!   They are immutable after creation and safe to share across threads.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use edr_core::bundle::{self, Channel, Manifest, TrustAnchors, VerifyMode};
use edr_core::engine::{Engine, Outcome, ScanReport};
use edr_core::policy::{ActionKind, FormatPolicy, Policy, Severity};

pub const EDR_OK: i32 = 0;
pub const EDR_ERR_ARGUMENT: i32 = 1;
pub const EDR_ERR_BUNDLE: i32 = 2;
pub const EDR_ERR_ENGINE: i32 = 3;
pub const EDR_ERR_SELF_TEST: i32 = 4;
pub const EDR_ERR_NOT_FOUND: i32 = 5;
pub const EDR_ERR_PANIC: i32 = 6;

pub const EDR_MODE_ACTIVATION: u32 = 0;
pub const EDR_MODE_LOAD: u32 = 1;

/// Upper bound for a bundle handed across the ABI (header limits allow less).
const MAX_BUNDLE_LEN: usize = 80 << 20;

/// A verified rule bundle. Owns a copy of the bytes.
pub struct EdrBundle {
    bytes: Vec<u8>,
    anchors: TrustAnchors,
    now: i64,
    manifest: Manifest,
    expired: bool,
    policy: Policy,
}

impl EdrBundle {
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

pub struct EdrEngine {
    engine: Engine,
}

pub struct EdrReport {
    outcome: u32,
    offset: u64,
    fuel_used: u64,
    format: Option<CString>,
    detail: CString,
    hits: Vec<CString>,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EdrBundleInfo {
    pub version: u64,
    pub created: i64,
    pub expires: i64,
    /// `EDR_CHANNEL_*`
    pub channel: u8,
    /// Load mode only: the manifest expiry is in the past (keep scanning,
    /// raise a stale-rules alert).
    pub expired: bool,
    pub memory_limit_mb: u32,
    pub self_tests: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EdrFormatPolicy {
    pub decode: bool,
    pub max_bytes: u64,
    pub max_pixels: u64,
    pub deadline_ms: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EdrAction {
    /// `EDR_SEVERITY_*`
    pub severity: u8,
    /// `EDR_ACTION_*`
    pub action: u8,
}

fn guard<F: FnOnce() -> i32>(f: F) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(EDR_ERR_PANIC)
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

fn format_policy(f: &FormatPolicy) -> EdrFormatPolicy {
    EdrFormatPolicy {
        decode: f.decode,
        max_bytes: f.max_bytes,
        max_pixels: f.max_pixels,
        deadline_ms: f.deadline_ms,
    }
}

/// Verify `bytes` against `n_roots` pinned 32-byte Ed25519 root keys
/// (`roots`, concatenated) with `threshold`. `mode` is `EDR_MODE_ACTIVATION`
/// (cert window, expiry and `current_version` enforced; `current_version`
/// may be NULL when no bundle is active) or `EDR_MODE_LOAD`.
#[no_mangle]
pub unsafe extern "C" fn edr_bundle_open(
    bytes: *const u8,
    len: usize,
    roots: *const u8,
    n_roots: usize,
    threshold: usize,
    now: i64,
    mode: u32,
    current_version: *const u64,
    out: *mut *mut EdrBundle,
    err: *mut c_char,
    err_cap: usize,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return EDR_ERR_ARGUMENT;
        }
        *out = ptr::null_mut();
        let fail = |code, msg: &str| {
            write_err(err, err_cap, msg);
            code
        };
        if len > MAX_BUNDLE_LEN {
            return fail(EDR_ERR_BUNDLE, "bundle too large");
        }
        let (Some(data), Some(root_bytes)) =
            (slice(bytes, len), slice(roots, n_roots.saturating_mul(32)))
        else {
            return fail(EDR_ERR_ARGUMENT, "null pointer");
        };
        let raw: Vec<[u8; 32]> = root_bytes
            .chunks_exact(32)
            .map(|c| c.try_into().unwrap_or([0; 32]))
            .collect();
        let anchors = match TrustAnchors::from_raw(&raw, threshold) {
            Ok(a) => a,
            Err(m) => return fail(EDR_ERR_ARGUMENT, m),
        };
        let vmode = match mode {
            EDR_MODE_ACTIVATION => VerifyMode::Activation {
                now,
                current_version: if current_version.is_null() {
                    None
                } else {
                    Some(*current_version)
                },
            },
            EDR_MODE_LOAD => VerifyMode::Load { now },
            _ => return fail(EDR_ERR_ARGUMENT, "unknown mode"),
        };
        let (manifest, expired, policy) = match bundle::verify(data, &anchors, vmode) {
            Ok(v) => {
                let Some((_, pol)) = v.artifacts_of(bundle::ArtifactKind::Policy).next() else {
                    return fail(EDR_ERR_BUNDLE, "bundle has no policy");
                };
                match Policy::parse(pol) {
                    Ok(p) => (v.manifest, v.expired, p),
                    Err(m) => return fail(EDR_ERR_BUNDLE, &m),
                }
            }
            Err(e) => return fail(EDR_ERR_BUNDLE, &e.to_string()),
        };
        *out = Box::into_raw(Box::new(EdrBundle {
            bytes: data.to_vec(),
            anchors,
            now,
            manifest,
            expired,
            policy,
        }));
        EDR_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn edr_bundle_free(b: *mut EdrBundle) {
    if !b.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(b))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn edr_bundle_info(b: *const EdrBundle, out: *mut EdrBundleInfo) -> i32 {
    guard(|| {
        let (Some(b), false) = (b.as_ref(), out.is_null()) else {
            return EDR_ERR_ARGUMENT;
        };
        let m = &b.manifest;
        *out = EdrBundleInfo {
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
        EDR_OK
    })
}

/// Format name for a file extension (without dot, any case). Writes the
/// NUL-terminated name into `name`; returns `EDR_ERR_NOT_FOUND` when the
/// extension is not mapped (use format `other`).
#[no_mangle]
pub unsafe extern "C" fn edr_bundle_format_for_extension(
    b: *const EdrBundle,
    ext: *const c_char,
    name: *mut c_char,
    name_cap: usize,
) -> i32 {
    guard(|| {
        let (Some(b), Ok(Some(ext))) = (b.as_ref(), opt_str(ext)) else {
            return EDR_ERR_ARGUMENT;
        };
        match b.policy.format_for_extension(ext) {
            Some(n) if n.len() < name_cap && !name.is_null() => {
                write_err(name, name_cap, n);
                EDR_OK
            }
            Some(_) => EDR_ERR_ARGUMENT,
            None => EDR_ERR_NOT_FOUND,
        }
    })
}

/// Limits for `format` (NULL or unknown falls back to `other`).
#[no_mangle]
pub unsafe extern "C" fn edr_bundle_format_policy(
    b: *const EdrBundle,
    format: *const c_char,
    out: *mut EdrFormatPolicy,
) -> i32 {
    guard(|| {
        let (Some(b), Ok(format), false) = (b.as_ref(), opt_str(format), out.is_null()) else {
            return EDR_ERR_ARGUMENT;
        };
        match b.policy.format(format.unwrap_or("other")) {
            Some(f) => {
                *out = format_policy(f);
                EDR_OK
            }
            None => EDR_ERR_NOT_FOUND,
        }
    })
}

/// Severity and action the bundle policy assigns to `outcome` (`EDR_OUTCOME_*`).
#[no_mangle]
pub unsafe extern "C" fn edr_bundle_action(
    b: *const EdrBundle,
    outcome: u32,
    out: *mut EdrAction,
) -> i32 {
    guard(|| {
        let (Some(b), false) = (b.as_ref(), out.is_null()) else {
            return EDR_ERR_ARGUMENT;
        };
        let Some(o) = Outcome::ALL.into_iter().find(|o| *o as u32 == outcome) else {
            return EDR_ERR_ARGUMENT;
        };
        let Some(a) = b.policy.outcomes.get(o.name()) else {
            return EDR_ERR_NOT_FOUND;
        };
        *out = EdrAction {
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
        EDR_OK
    })
}

/// Build the scan engine (compiles YARA; call during inspector pre-warm,
/// before entering the sandbox profile if compilation needs it).
#[no_mangle]
pub unsafe extern "C" fn edr_engine_new(
    b: *const EdrBundle,
    out: *mut *mut EdrEngine,
    err: *mut c_char,
    err_cap: usize,
) -> i32 {
    guard(|| {
        let (Some(b), false) = (b.as_ref(), out.is_null()) else {
            return EDR_ERR_ARGUMENT;
        };
        *out = ptr::null_mut();
        let engine = b
            .verified()
            .and_then(|v| Engine::from_bundle(&v).map_err(|e| e.to_string()));
        match engine {
            Ok(engine) => {
                *out = Box::into_raw(Box::new(EdrEngine { engine }));
                EDR_OK
            }
            Err(m) => {
                write_err(err, err_cap, &m);
                EDR_ERR_ENGINE
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn edr_engine_free(e: *mut EdrEngine) {
    if !e.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(e))));
    }
}

/// Run the bundle's self-test vectors. `passed` receives the vector count.
#[no_mangle]
pub unsafe extern "C" fn edr_engine_self_test(
    e: *const EdrEngine,
    b: *const EdrBundle,
    passed: *mut u32,
    err: *mut c_char,
    err_cap: usize,
) -> i32 {
    guard(|| {
        let (Some(e), Some(b)) = (e.as_ref(), b.as_ref()) else {
            return EDR_ERR_ARGUMENT;
        };
        match b.verified().and_then(|v| e.engine.self_test(&v)) {
            Ok(n) => {
                if !passed.is_null() {
                    *passed = n as u32;
                }
                EDR_OK
            }
            Err(m) => {
                write_err(err, err_cap, &m);
                EDR_ERR_SELF_TEST
            }
        }
    })
}

/// Stage-1 scan of `len` bytes. `hint` is the sensor's extension-derived
/// format name or NULL. Returns NULL only on invalid arguments or panic
/// (treat as `EDR_OUTCOME_CRASH`).
#[no_mangle]
pub unsafe extern "C" fn edr_engine_scan(
    e: *const EdrEngine,
    data: *const u8,
    len: usize,
    hint: *const c_char,
) -> *mut EdrReport {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(e), Some(data), Ok(hint)) = (e.as_ref(), slice(data, len), opt_str(hint)) else {
            return ptr::null_mut();
        };
        let r: ScanReport = e.engine.scan(data, hint);
        Box::into_raw(Box::new(EdrReport {
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
pub unsafe extern "C" fn edr_report_free(r: *mut EdrReport) {
    if !r.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(r))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn edr_report_outcome(r: *const EdrReport) -> u32 {
    r.as_ref().map_or(Outcome::Crash as u32, |r| r.outcome)
}

#[no_mangle]
pub unsafe extern "C" fn edr_report_offset(r: *const EdrReport) -> u64 {
    r.as_ref().map_or(0, |r| r.offset)
}

#[no_mangle]
pub unsafe extern "C" fn edr_report_fuel_used(r: *const EdrReport) -> u64 {
    r.as_ref().map_or(0, |r| r.fuel_used)
}

/// Detected format name, or NULL. Valid until `edr_report_free`.
#[no_mangle]
pub unsafe extern "C" fn edr_report_format(r: *const EdrReport) -> *const c_char {
    r.as_ref()
        .and_then(|r| r.format.as_ref())
        .map_or(ptr::null(), |s| s.as_ptr())
}

/// Human-readable detail (never NULL for a valid report).
#[no_mangle]
pub unsafe extern "C" fn edr_report_detail(r: *const EdrReport) -> *const c_char {
    r.as_ref().map_or(ptr::null(), |r| r.detail.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn edr_report_hit_count(r: *const EdrReport) -> usize {
    r.as_ref().map_or(0, |r| r.hits.len())
}

/// Rule or schema name `i`, or NULL when out of range.
#[no_mangle]
pub unsafe extern "C" fn edr_report_hit(r: *const EdrReport, i: usize) -> *const c_char {
    r.as_ref()
        .and_then(|r| r.hits.get(i))
        .map_or(ptr::null(), |s| s.as_ptr())
}

/// Engine version compared against the bundle's `min_engine`.
#[no_mangle]
pub extern "C" fn edr_engine_version() -> u32 {
    edr_core::ENGINE_VERSION
}

#[cfg(test)]
mod tests;

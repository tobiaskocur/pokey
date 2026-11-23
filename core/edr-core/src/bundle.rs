//! Signed rule bundle: format, builder, signing and verification.
//!
//! Layout (all integers little endian):
//!
//! ```text
//! [fixed header 32 B][manifest (JSON)][signature block][artifacts]
//! ```
//!
//! Verification order is enforced by types: [`split`] only bounds-checks the
//! fixed header and slices the input; the manifest stays opaque bytes until
//! [`Unverified::verify_signatures`] has checked the release certificate
//! against the pinned roots and the release signature over header+manifest.
//! Only [`Authenticated::parse`] parses the manifest, then checks version,
//! expiry, engine compatibility and artifact hashes.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ENGINE_VERSION;

pub const MAGIC: [u8; 8] = *b"EDRBNDL1";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const MAX_MANIFEST_LEN: u32 = 256 * 1024;
pub const MAX_SIG_LEN: u32 = 4096;
pub const MAX_ARTIFACTS_LEN: u64 = 64 << 20;
pub const MAX_ROOT_SIGS: usize = 8;
pub const MAX_ARTIFACTS: usize = 256;

const CERT_FIXED_LEN: usize = 52;
const ROOT_SIG_LEN: usize = 8 + 64;
const CERT_DOMAIN: &[u8] = b"EDR-RELEASE-CERT\x00\x01";
const BUNDLE_DOMAIN: &[u8] = b"EDR-BUNDLE-SIG\x00\x01";

pub const CHANNEL_STABLE: u8 = 1;
pub const CHANNEL_CANARY: u8 = 2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("input shorter than the fixed header")]
    Truncated,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported bundle format version {0}")]
    UnsupportedFormat(u16),
    #[error("reserved header field is not zero")]
    ReservedNonZero,
    #[error("header length field out of bounds: {0}")]
    LengthOutOfBounds(&'static str),
    #[error("header lengths do not add up to the input length")]
    LengthMismatch,
    #[error("malformed signature block")]
    MalformedSignatureBlock,
    #[error("duplicate root key in certificate")]
    DuplicateRoot,
    #[error("invalid root signature on release certificate")]
    BadCertSignature,
    #[error("release certificate has {got} valid root signatures, {need} required")]
    InsufficientRootSignatures { got: usize, need: usize },
    #[error("release certificate not yet valid")]
    CertNotYetValid,
    #[error("release certificate expired")]
    CertExpired,
    #[error("invalid release key in certificate")]
    BadReleaseKey,
    #[error("bundle signature invalid")]
    BadSignature,
    #[error("manifest is not valid: {0}")]
    ManifestParse(String),
    #[error("manifest invalid: {0}")]
    ManifestInvalid(&'static str),
    #[error("channel not allowed by release certificate")]
    ChannelNotAllowed,
    #[error("bundle version {got} is not newer than active version {current}")]
    VersionNotIncreasing { got: u64, current: u64 },
    #[error("bundle expired")]
    Expired,
    #[error("bundle requires engine {need}, this engine is {have}")]
    IncompatibleEngine { need: u32, have: u32 },
    #[error("artifact {0} hash mismatch")]
    ArtifactHashMismatch(String),
    #[error("signer failed: {0}")]
    Signer(String),
}

/// Fixed header, parsed and bounds-checked before anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub manifest_len: u32,
    pub sig_len: u32,
    pub artifacts_len: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..8].copy_from_slice(&MAGIC);
        h[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        h[12..16].copy_from_slice(&self.manifest_len.to_le_bytes());
        h[16..20].copy_from_slice(&self.sig_len.to_le_bytes());
        h[20..28].copy_from_slice(&self.artifacts_len.to_le_bytes());
        h
    }

    /// Bounds-check the fixed header against `total_len` (the full input).
    pub fn decode(bytes: &[u8], total_len: usize) -> Result<Header, BundleError> {
        let h = bytes.get(..HEADER_LEN).ok_or(BundleError::Truncated)?;
        if h[0..8] != MAGIC {
            return Err(BundleError::BadMagic);
        }
        let ver = u16::from_le_bytes([h[8], h[9]]);
        if ver != FORMAT_VERSION {
            return Err(BundleError::UnsupportedFormat(ver));
        }
        if h[10..12] != [0, 0] || h[28..32] != [0, 0, 0, 0] {
            return Err(BundleError::ReservedNonZero);
        }
        let manifest_len = u32::from_le_bytes(h[12..16].try_into().unwrap_or_default());
        let sig_len = u32::from_le_bytes(h[16..20].try_into().unwrap_or_default());
        let artifacts_len = u64::from_le_bytes(h[20..28].try_into().unwrap_or_default());
        if manifest_len == 0 || manifest_len > MAX_MANIFEST_LEN {
            return Err(BundleError::LengthOutOfBounds("manifest_len"));
        }
        if sig_len > MAX_SIG_LEN {
            return Err(BundleError::LengthOutOfBounds("sig_len"));
        }
        if artifacts_len > MAX_ARTIFACTS_LEN {
            return Err(BundleError::LengthOutOfBounds("artifacts_len"));
        }
        let total = (HEADER_LEN as u64)
            .checked_add(manifest_len as u64)
            .and_then(|t| t.checked_add(sig_len as u64))
            .and_then(|t| t.checked_add(artifacts_len))
            .ok_or(BundleError::LengthMismatch)?;
        if total != total_len as u64 {
            return Err(BundleError::LengthMismatch);
        }
        Ok(Header { manifest_len, sig_len, artifacts_len })
    }
}

/// Pinned root keys and the number of distinct roots that must sign a
/// release certificate.
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    roots: Vec<VerifyingKey>,
    threshold: usize,
}

impl TrustAnchors {
    pub fn new(roots: Vec<VerifyingKey>, threshold: usize) -> Result<Self, &'static str> {
        if threshold == 0 || threshold > roots.len() {
            return Err("threshold must be between 1 and the number of roots");
        }
        let ids: HashSet<_> = roots.iter().map(key_id).collect();
        if ids.len() != roots.len() {
            return Err("duplicate root key");
        }
        Ok(TrustAnchors { roots, threshold })
    }

    pub fn from_raw(roots: &[[u8; 32]], threshold: usize) -> Result<Self, &'static str> {
        let keys = roots
            .iter()
            .map(|r| VerifyingKey::from_bytes(r).map_err(|_| "invalid root key"))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(keys, threshold)
    }
}

pub fn key_id(k: &VerifyingKey) -> [u8; 8] {
    let d = Sha256::digest(k.as_bytes());
    let mut id = [0u8; 8];
    id.copy_from_slice(&d[..8]);
    id
}

/// Time-limited release-key certificate signed by `threshold` offline roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCert {
    pub release_key: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
    pub channels: u8,
    pub root_sigs: Vec<([u8; 8], [u8; 64])>,
}

impl ReleaseCert {
    pub fn unsigned(release_key: [u8; 32], not_before: i64, not_after: i64, channels: u8) -> Self {
        ReleaseCert { release_key, not_before, not_after, channels, root_sigs: Vec::new() }
    }

    fn fixed(&self) -> [u8; CERT_FIXED_LEN] {
        let mut b = [0u8; CERT_FIXED_LEN];
        b[0] = 1;
        b[1] = self.root_sigs.len() as u8;
        b[2..34].copy_from_slice(&self.release_key);
        b[34..42].copy_from_slice(&self.not_before.to_le_bytes());
        b[42..50].copy_from_slice(&self.not_after.to_le_bytes());
        b[50] = self.channels;
        b
    }

    /// Bytes signed by each root (excludes the signature count).
    pub fn tbs(&self) -> Vec<u8> {
        let f = self.fixed();
        let mut m = CERT_DOMAIN.to_vec();
        m.extend_from_slice(&f[2..CERT_FIXED_LEN]);
        m
    }

    pub fn add_root_signature(&mut self, root: &SigningKey) {
        let sig = root.sign(&self.tbs());
        self.root_sigs.push((key_id(&root.verifying_key()), sig.to_bytes()));
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.fixed().to_vec();
        for (id, sig) in &self.root_sigs {
            b.extend_from_slice(id);
            b.extend_from_slice(sig);
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<ReleaseCert, BundleError> {
        let f = b.get(..CERT_FIXED_LEN).ok_or(BundleError::MalformedSignatureBlock)?;
        if f[0] != 1 || f[51] != 0 {
            return Err(BundleError::MalformedSignatureBlock);
        }
        let k = f[1] as usize;
        if k == 0 || k > MAX_ROOT_SIGS || b.len() != CERT_FIXED_LEN + k * ROOT_SIG_LEN {
            return Err(BundleError::MalformedSignatureBlock);
        }
        let mut root_sigs = Vec::with_capacity(k);
        for e in b[CERT_FIXED_LEN..].chunks_exact(ROOT_SIG_LEN) {
            let mut id = [0u8; 8];
            let mut sig = [0u8; 64];
            id.copy_from_slice(&e[..8]);
            sig.copy_from_slice(&e[8..]);
            root_sigs.push((id, sig));
        }
        let mut release_key = [0u8; 32];
        release_key.copy_from_slice(&f[2..34]);
        Ok(ReleaseCert {
            release_key,
            not_before: i64::from_le_bytes(f[34..42].try_into().unwrap_or_default()),
            not_after: i64::from_le_bytes(f[42..50].try_into().unwrap_or_default()),
            channels: f[50],
            root_sigs,
        })
    }

    /// Verify root signatures (threshold of distinct pinned roots) and, when
    /// `now` is given, the validity window. Returns the release key.
    pub fn verify(&self, anchors: &TrustAnchors, now: Option<i64>) -> Result<VerifyingKey, BundleError> {
        let tbs = self.tbs();
        let mut seen = HashSet::new();
        let mut valid = 0usize;
        for (id, sig) in &self.root_sigs {
            if !seen.insert(*id) {
                return Err(BundleError::DuplicateRoot);
            }
            let Some(root) = anchors.roots.iter().find(|r| key_id(r) == *id) else {
                continue; // not one of our pinned roots; does not count
            };
            root.verify_strict(&tbs, &Signature::from_bytes(sig))
                .map_err(|_| BundleError::BadCertSignature)?;
            valid += 1;
        }
        if valid < anchors.threshold {
            return Err(BundleError::InsufficientRootSignatures { got: valid, need: anchors.threshold });
        }
        if let Some(now) = now {
            if now < self.not_before {
                return Err(BundleError::CertNotYetValid);
            }
            if now >= self.not_after {
                return Err(BundleError::CertExpired);
            }
        }
        VerifyingKey::from_bytes(&self.release_key).map_err(|_| BundleError::BadReleaseKey)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Canary,
}

impl Channel {
    fn bit(self) -> u8 {
        match self {
            Channel::Stable => CHANNEL_STABLE,
            Channel::Canary => CHANNEL_CANARY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    Yara,
    Schema,
    Policy,
    Fixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEntry {
    pub name: String,
    pub kind: ArtifactKind,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfTest {
    pub fixture: String,
    pub format: Option<String>,
    /// Expected outcome name, e.g. `CLEAN`, `STATIC_MATCH`, `SCHEMA_VIOLATION`.
    pub expect: String,
    /// Rule or schema expected to fire (for non-CLEAN outcomes).
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub version: u64,
    pub channel: Channel,
    pub created: i64,
    pub expires: i64,
    pub min_engine: u32,
    pub artifacts: Vec<ArtifactEntry>,
    #[serde(default)]
    pub self_tests: Vec<SelfTest>,
}

/// Input split along the header lengths. Nothing inside has been parsed or
/// trusted yet; the manifest is deliberately not accessible.
pub struct Unverified<'a> {
    header_bytes: &'a [u8],
    manifest_bytes: &'a [u8],
    sig_block: &'a [u8],
    artifacts: &'a [u8],
}

/// Header and manifest bytes are authenticated by a valid release key.
pub struct Authenticated<'a> {
    inner: Unverified<'a>,
    cert: ReleaseCert,
}

/// Fully verified bundle.
#[derive(Debug)]
pub struct VerifiedBundle<'a> {
    pub manifest: Manifest,
    pub cert: ReleaseCert,
    /// True when the manifest `expires` is in the past (load mode only).
    pub expired: bool,
    artifacts: Vec<&'a [u8]>,
}

impl<'a> VerifiedBundle<'a> {
    pub fn artifact(&self, name: &str) -> Option<&'a [u8]> {
        let i = self.manifest.artifacts.iter().position(|a| a.name == name)?;
        self.artifacts.get(i).copied()
    }

    pub fn artifacts_of(&self, kind: ArtifactKind) -> impl Iterator<Item = (&ArtifactEntry, &'a [u8])> + '_ {
        self.manifest
            .artifacts
            .iter()
            .zip(self.artifacts.iter().copied())
            .filter(move |(e, _)| e.kind == kind)
    }
}

/// What the caller is doing with the bundle.
#[derive(Debug, Clone, Copy)]
pub enum VerifyMode {
    /// Sensor activating a new bundle: certificate validity window, manifest
    /// expiry and strictly increasing version are enforced.
    Activation { now: i64, current_version: Option<u64> },
    /// Loading an already activated bundle (inspector, self-test). Signatures
    /// and hashes are still verified; an expired bundle keeps scanning and is
    /// reported through `VerifiedBundle::expired`.
    Load { now: i64 },
}

/// Step 1: bounds-check the fixed header and slice the input.
pub fn split(bytes: &[u8]) -> Result<Unverified<'_>, BundleError> {
    let h = Header::decode(bytes, bytes.len())?;
    let m_end = HEADER_LEN + h.manifest_len as usize;
    let s_end = m_end + h.sig_len as usize;
    Ok(Unverified {
        header_bytes: &bytes[..HEADER_LEN],
        manifest_bytes: &bytes[HEADER_LEN..m_end],
        sig_block: &bytes[m_end..s_end],
        artifacts: &bytes[s_end..],
    })
}

fn signed_message(header: &[u8], manifest: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(BUNDLE_DOMAIN.len() + header.len() + manifest.len());
    m.extend_from_slice(BUNDLE_DOMAIN);
    m.extend_from_slice(header);
    m.extend_from_slice(manifest);
    m
}

impl<'a> Unverified<'a> {
    /// Step 2: verify the certificate chain and the release signature over
    /// header+manifest. In load mode the validity window is not enforced.
    pub fn verify_signatures(self, anchors: &TrustAnchors, mode: VerifyMode) -> Result<Authenticated<'a>, BundleError> {
        if self.sig_block.len() < 64 {
            return Err(BundleError::MalformedSignatureBlock);
        }
        let (cert_bytes, sig) = self.sig_block.split_at(self.sig_block.len() - 64);
        let cert = ReleaseCert::decode(cert_bytes)?;
        let now = match mode {
            VerifyMode::Activation { now, .. } => Some(now),
            VerifyMode::Load { .. } => None,
        };
        let release = cert.verify(anchors, now)?;
        let sig = Signature::from_bytes(sig.try_into().map_err(|_| BundleError::MalformedSignatureBlock)?);
        release
            .verify_strict(&signed_message(self.header_bytes, self.manifest_bytes), &sig)
            .map_err(|_| BundleError::BadSignature)?;
        Ok(Authenticated { inner: self, cert })
    }
}

fn valid_artifact_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && !n.starts_with('/')
        && !n.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..")
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

impl<'a> Authenticated<'a> {
    /// Step 3: parse the authenticated manifest and enforce policy checks.
    pub fn parse(self, mode: VerifyMode) -> Result<VerifiedBundle<'a>, BundleError> {
        let m: Manifest = serde_json::from_slice(self.inner.manifest_bytes)
            .map_err(|e| BundleError::ManifestParse(e.to_string()))?;
        if m.format != 1 {
            return Err(BundleError::ManifestInvalid("unsupported manifest format"));
        }
        if m.created > m.expires {
            return Err(BundleError::ManifestInvalid("created after expires"));
        }
        if self.cert.channels & m.channel.bit() == 0 {
            return Err(BundleError::ChannelNotAllowed);
        }
        if m.min_engine > ENGINE_VERSION {
            return Err(BundleError::IncompatibleEngine { need: m.min_engine, have: ENGINE_VERSION });
        }
        let expired = match mode {
            VerifyMode::Activation { now, current_version } => {
                if let Some(cur) = current_version {
                    if m.version <= cur {
                        return Err(BundleError::VersionNotIncreasing { got: m.version, current: cur });
                    }
                }
                if now >= m.expires {
                    return Err(BundleError::Expired);
                }
                false
            }
            VerifyMode::Load { now } => now >= m.expires,
        };
        if m.artifacts.len() > MAX_ARTIFACTS {
            return Err(BundleError::ManifestInvalid("too many artifacts"));
        }
        let mut names = HashSet::new();
        let mut policies = 0;
        let mut offset = 0u64;
        let mut slices = Vec::with_capacity(m.artifacts.len());
        for a in &m.artifacts {
            if !valid_artifact_name(&a.name) || !names.insert(a.name.as_str()) {
                return Err(BundleError::ManifestInvalid("bad or duplicate artifact name"));
            }
            if a.kind == ArtifactKind::Policy {
                policies += 1;
            }
            let end = offset.checked_add(a.size).ok_or(BundleError::ManifestInvalid("artifact size overflow"))?;
            let data = self
                .inner
                .artifacts
                .get(offset as usize..end as usize)
                .ok_or(BundleError::ManifestInvalid("artifact outside artifact region"))?;
            let want = hex::decode(&a.sha256).map_err(|_| BundleError::ManifestInvalid("bad sha256 hex"))?;
            if want.len() != 32 || Sha256::digest(data).as_slice() != want.as_slice() {
                return Err(BundleError::ArtifactHashMismatch(a.name.clone()));
            }
            slices.push(data);
            offset = end;
        }
        if offset != self.inner.artifacts.len() as u64 {
            return Err(BundleError::ManifestInvalid("artifact sizes do not cover artifact region"));
        }
        if policies != 1 {
            return Err(BundleError::ManifestInvalid("exactly one policy artifact required"));
        }
        for t in &m.self_tests {
            let fixture = m.artifacts.iter().find(|a| a.name == t.fixture);
            if fixture.map(|a| a.kind) != Some(ArtifactKind::Fixture) {
                return Err(BundleError::ManifestInvalid("self-test references a missing fixture"));
            }
        }
        Ok(VerifiedBundle { manifest: m, cert: self.cert, expired, artifacts: slices })
    }
}

/// Full verification pipeline: split -> verify signatures -> parse manifest.
pub fn verify<'a>(bytes: &'a [u8], anchors: &TrustAnchors, mode: VerifyMode) -> Result<VerifiedBundle<'a>, BundleError> {
    split(bytes)?.verify_signatures(anchors, mode)?.parse(mode)
}

/// Build an unsigned bundle (signature block empty). Artifact entries are
/// derived from `artifacts`; the manifest's `artifacts` field is overwritten.
pub fn build_unsigned(mut manifest: Manifest, artifacts: &[(String, ArtifactKind, Vec<u8>)]) -> Result<Vec<u8>, BundleError> {
    manifest.artifacts = artifacts
        .iter()
        .map(|(name, kind, data)| ArtifactEntry {
            name: name.clone(),
            kind: *kind,
            size: data.len() as u64,
            sha256: hex::encode(Sha256::digest(data)),
        })
        .collect();
    let mbytes = serde_json::to_vec_pretty(&manifest).map_err(|e| BundleError::ManifestParse(e.to_string()))?;
    let alen: usize = artifacts.iter().map(|a| a.2.len()).sum();
    if mbytes.len() > MAX_MANIFEST_LEN as usize {
        return Err(BundleError::LengthOutOfBounds("manifest_len"));
    }
    if alen as u64 > MAX_ARTIFACTS_LEN {
        return Err(BundleError::LengthOutOfBounds("artifacts_len"));
    }
    let h = Header { manifest_len: mbytes.len() as u32, sig_len: 0, artifacts_len: alen as u64 };
    let mut out = h.encode().to_vec();
    out.extend_from_slice(&mbytes);
    for a in artifacts {
        out.extend_from_slice(&a.2);
    }
    Ok(out)
}

/// Sign an unsigned bundle with the release key behind `signer`. The signer
/// receives the exact message and returns a 64-byte Ed25519 signature (local
/// key, HSM or KMS). The produced signature is verified against the
/// certificate's release key before the bundle is returned.
pub fn sign(
    unsigned: &[u8],
    cert: &ReleaseCert,
    signer: &mut dyn FnMut(&[u8]) -> Result<[u8; 64], String>,
) -> Result<Vec<u8>, BundleError> {
    let h = Header::decode(unsigned, unsigned.len())?;
    if h.sig_len != 0 {
        return Err(BundleError::ManifestInvalid("bundle is already signed"));
    }
    let m_end = HEADER_LEN + h.manifest_len as usize;
    let manifest = &unsigned[HEADER_LEN..m_end];
    let artifacts = &unsigned[m_end..];
    let cert_bytes = cert.encode();
    let sig_len = (cert_bytes.len() + 64) as u32;
    let header = Header { sig_len, ..h }.encode();
    let msg = signed_message(&header, manifest);
    let sig = signer(&msg).map_err(BundleError::Signer)?;
    let release = VerifyingKey::from_bytes(&cert.release_key).map_err(|_| BundleError::BadReleaseKey)?;
    release
        .verify_strict(&msg, &Signature::from_bytes(&sig))
        .map_err(|_| BundleError::Signer("signature does not match certificate release key".into()))?;
    let mut out = header.to_vec();
    out.extend_from_slice(manifest);
    out.extend_from_slice(&cert_bytes);
    out.extend_from_slice(&sig);
    out.extend_from_slice(artifacts);
    Ok(out)
}

#[cfg(test)]
mod tests;

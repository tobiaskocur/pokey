use super::*;

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn anchors(threshold: usize) -> TrustAnchors {
    TrustAnchors::new(
        vec![
            key(1).verifying_key(),
            key(2).verifying_key(),
            key(3).verifying_key(),
        ],
        threshold,
    )
    .unwrap()
}

fn cert_with(roots: &[u8], release: &SigningKey, nb: i64, na: i64, channels: u8) -> ReleaseCert {
    let mut c = ReleaseCert::unsigned(release.verifying_key().to_bytes(), nb, na, channels);
    for r in roots {
        c.add_root_signature(&key(*r));
    }
    c
}

fn cert() -> ReleaseCert {
    cert_with(
        &[1, 2],
        &key(9),
        NOW - DAY,
        NOW + 90 * DAY,
        CHANNEL_STABLE | CHANNEL_CANARY,
    )
}

fn manifest(version: u64) -> Manifest {
    Manifest {
        format: 1,
        version,
        channel: Channel::Stable,
        created: NOW - 10,
        expires: NOW + 30 * DAY,
        min_engine: 1,
        artifacts: Vec::new(),
        self_tests: vec![SelfTest {
            fixture: "fixtures/a.bin".into(),
            format: None,
            expect: "CLEAN".into(),
            rule: None,
        }],
    }
}

fn artifacts() -> Vec<(String, ArtifactKind, Vec<u8>)> {
    vec![
        ("policy.json".into(), ArtifactKind::Policy, b"{}".to_vec()),
        (
            "yara/a.yar".into(),
            ArtifactKind::Yara,
            b"rule a { condition: false }".to_vec(),
        ),
        (
            "fixtures/a.bin".into(),
            ArtifactKind::Fixture,
            vec![0u8; 100],
        ),
    ]
}

fn local_signer(k: SigningKey) -> impl FnMut(&[u8]) -> Result<[u8; 64], String> {
    move |m| Ok(k.sign(m).to_bytes())
}

fn signed_with(m: Manifest, c: &ReleaseCert, release: SigningKey) -> Vec<u8> {
    let u = build_unsigned(m, &artifacts()).unwrap();
    sign(&u, c, &mut local_signer(release)).unwrap()
}

fn signed(version: u64) -> Vec<u8> {
    signed_with(manifest(version), &cert(), key(9))
}

fn activate(b: &[u8], current: Option<u64>) -> Result<VerifiedBundle<'_>, BundleError> {
    verify(
        b,
        &anchors(2),
        VerifyMode::Activation {
            now: NOW,
            current_version: current,
        },
    )
}

/// Re-sign `header+manifest` after a test mutated them, so the signature is
/// valid and later checks are reached.
fn resign(b: &mut [u8]) {
    let h = Header::decode(b, b.len()).unwrap();
    let m_end = HEADER_LEN + h.manifest_len as usize;
    let s_end = m_end + h.sig_len as usize;
    let sig = key(9)
        .sign(&signed_message(&b[..HEADER_LEN], &b[HEADER_LEN..m_end]))
        .to_bytes();
    b[s_end - 64..s_end].copy_from_slice(&sig);
}

#[test]
fn round_trip_verifies() {
    let b = signed(5);
    let v = activate(&b, Some(4)).unwrap();
    assert_eq!(v.manifest.version, 5);
    assert_eq!(
        v.artifact("yara/a.yar"),
        Some(&b"rule a { condition: false }"[..])
    );
    assert_eq!(v.artifacts_of(ArtifactKind::Fixture).count(), 1);
    assert!(!v.expired);
}

#[test]
fn signature_is_checked_before_manifest_is_parsed() {
    // Replace the manifest with garbage of the same length. If the manifest
    // were parsed first this would be ManifestParse; it must be BadSignature.
    let mut b = signed(5);
    let h = Header::decode(&b, b.len()).unwrap();
    for x in &mut b[HEADER_LEN..HEADER_LEN + h.manifest_len as usize] {
        *x = b'{';
    }
    assert_eq!(activate(&b, None).unwrap_err(), BundleError::BadSignature);
}

#[test]
fn any_flipped_byte_in_signed_region_is_rejected() {
    let b = signed(5);
    let h = Header::decode(&b, b.len()).unwrap();
    for i in HEADER_LEN..HEADER_LEN + h.manifest_len as usize {
        let mut c = b.clone();
        c[i] ^= 0x01;
        assert!(activate(&c, None).is_err(), "byte {i}");
    }
}

#[test]
fn artifact_tampering_is_a_hash_mismatch() {
    let mut b = signed(5);
    let n = b.len();
    b[n - 1] ^= 0xff; // last byte of the fixture
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::ArtifactHashMismatch("fixtures/a.bin".into())
    );
}

#[test]
fn version_must_increase_on_activation() {
    let b = signed(5);
    assert_eq!(
        activate(&b, Some(5)).unwrap_err(),
        BundleError::VersionNotIncreasing { got: 5, current: 5 }
    );
    assert_eq!(
        activate(&b, Some(9)).unwrap_err(),
        BundleError::VersionNotIncreasing { got: 5, current: 9 }
    );
    // Loading an already active bundle does not compare versions.
    assert!(verify(&b, &anchors(2), VerifyMode::Load { now: NOW }).is_ok());
}

#[test]
fn expired_bundle_rejected_on_activation_but_loads_flagged() {
    let mut m = manifest(5);
    m.expires = NOW - 1;
    m.created = NOW - DAY;
    let b = signed_with(m, &cert(), key(9));
    assert_eq!(activate(&b, None).unwrap_err(), BundleError::Expired);
    let v = verify(&b, &anchors(2), VerifyMode::Load { now: NOW }).unwrap();
    assert!(v.expired);
}

#[test]
fn certificate_window_enforced_on_activation() {
    let expired = cert_with(&[1, 2], &key(9), NOW - 100 * DAY, NOW - DAY, CHANNEL_STABLE);
    let b = signed_with(manifest(5), &expired, key(9));
    assert_eq!(activate(&b, None).unwrap_err(), BundleError::CertExpired);

    let future = cert_with(&[1, 2], &key(9), NOW + DAY, NOW + 100 * DAY, CHANNEL_STABLE);
    let b = signed_with(manifest(5), &future, key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::CertNotYetValid
    );
}

#[test]
fn threshold_of_distinct_pinned_roots() {
    // One root is not enough for threshold 2.
    let one = cert_with(&[1], &key(9), NOW - DAY, NOW + DAY, CHANNEL_STABLE);
    let b = signed_with(manifest(5), &one, key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::InsufficientRootSignatures { got: 1, need: 2 }
    );

    // The same root twice is rejected, not counted twice.
    let dup = cert_with(&[1, 1], &key(9), NOW - DAY, NOW + DAY, CHANNEL_STABLE);
    let b = signed_with(manifest(5), &dup, key(9));
    assert_eq!(activate(&b, None).unwrap_err(), BundleError::DuplicateRoot);

    // An unknown root does not count.
    let stranger = cert_with(&[1, 7], &key(9), NOW - DAY, NOW + DAY, CHANNEL_STABLE);
    let b = signed_with(manifest(5), &stranger, key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::InsufficientRootSignatures { got: 1, need: 2 }
    );

    // A pinned root id with a wrong signature is a hard error.
    let mut forged = cert_with(&[1, 2], &key(9), NOW - DAY, NOW + DAY, CHANNEL_STABLE);
    forged.root_sigs[1].1[0] ^= 1;
    let b = signed_with(manifest(5), &forged, key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::BadCertSignature
    );
}

#[test]
fn certificate_fields_are_covered_by_root_signatures() {
    let mut c = cert();
    c.not_after += 1000 * DAY; // extend validity after roots signed
    let b = signed_with(manifest(5), &c, key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::BadCertSignature
    );
}

#[test]
fn bundle_signed_by_other_key_is_rejected() {
    let u = build_unsigned(manifest(5), &artifacts()).unwrap();
    // sign() refuses a signature that does not match the certificate.
    assert!(matches!(
        sign(&u, &cert(), &mut local_signer(key(8))),
        Err(BundleError::Signer(_))
    ));
    // A certificate for key 8 that roots never signed.
    let rogue = cert_with(&[], &key(8), NOW - DAY, NOW + DAY, CHANNEL_STABLE);
    let mut rogue = rogue;
    rogue.root_sigs = cert().root_sigs; // copy root sigs from the real cert
    let b = sign(&u, &rogue, &mut local_signer(key(8))).unwrap();
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::BadCertSignature
    );
}

#[test]
fn channel_must_be_allowed_by_certificate() {
    let stable_only = cert_with(&[1, 2], &key(9), NOW - DAY, NOW + DAY, CHANNEL_STABLE);
    let mut m = manifest(5);
    m.channel = Channel::Canary;
    let b = signed_with(m, &stable_only, key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::ChannelNotAllowed
    );
}

#[test]
fn newer_engine_required_is_rejected() {
    let mut m = manifest(5);
    m.min_engine = ENGINE_VERSION + 1;
    let b = signed_with(m, &cert(), key(9));
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::IncompatibleEngine {
            need: ENGINE_VERSION + 1,
            have: ENGINE_VERSION
        }
    );
}

#[test]
fn header_lengths_are_bounds_checked() {
    let b = signed(5);
    assert_eq!(split(&b[..10]).err(), Some(BundleError::Truncated));
    assert_eq!(
        split(&b[..b.len() - 1]).err(),
        Some(BundleError::LengthMismatch)
    );
    let mut extra = b.clone();
    extra.push(0);
    assert_eq!(split(&extra).err(), Some(BundleError::LengthMismatch));

    let mut c = b.clone();
    c[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        split(&c).err(),
        Some(BundleError::LengthOutOfBounds("manifest_len"))
    );
    let mut c = b.clone();
    c[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        split(&c).err(),
        Some(BundleError::LengthOutOfBounds("artifacts_len"))
    );
    let mut c = b.clone();
    c[0] = b'X';
    assert_eq!(split(&c).err(), Some(BundleError::BadMagic));
    let mut c = b.clone();
    c[30] = 1;
    assert_eq!(split(&c).err(), Some(BundleError::ReservedNonZero));
}

#[test]
fn unsigned_bundle_is_rejected() {
    let u = build_unsigned(manifest(5), &artifacts()).unwrap();
    assert_eq!(
        activate(&u, None).unwrap_err(),
        BundleError::MalformedSignatureBlock
    );
}

#[test]
fn manifest_checks_after_valid_signature() {
    // Artifact name with path traversal, signed correctly.
    let mut arts = artifacts();
    arts[1].0 = "../evil.yar".into();
    let u = build_unsigned(manifest(5), &arts).unwrap();
    let b = sign(&u, &cert(), &mut local_signer(key(9))).unwrap();
    assert!(matches!(
        activate(&b, None).unwrap_err(),
        BundleError::ManifestInvalid(_)
    ));

    // Self-test referencing a missing fixture.
    let mut m = manifest(5);
    m.self_tests[0].fixture = "fixtures/missing.bin".into();
    let b = signed_with(m, &cert(), key(9));
    assert!(matches!(
        activate(&b, None).unwrap_err(),
        BundleError::ManifestInvalid(_)
    ));

    // No policy artifact.
    let arts: Vec<_> = artifacts()
        .into_iter()
        .filter(|a| a.1 != ArtifactKind::Policy)
        .collect();
    let u = build_unsigned(manifest(5), &arts).unwrap();
    let b = sign(&u, &cert(), &mut local_signer(key(9))).unwrap();
    assert!(matches!(
        activate(&b, None).unwrap_err(),
        BundleError::ManifestInvalid(_)
    ));
}

#[test]
fn manifest_sizes_must_cover_artifact_region_exactly() {
    // Smuggle an unlisted byte after the last artifact; header is consistent.
    let mut u = build_unsigned(manifest(5), &artifacts()).unwrap();
    u.push(0x90);
    let mut hdr = Header::decode(&u[..u.len() - 1], u.len() - 1).unwrap();
    hdr.artifacts_len += 1;
    u[..HEADER_LEN].copy_from_slice(&hdr.encode());
    let b = sign(&u, &cert(), &mut local_signer(key(9))).unwrap();
    assert_eq!(
        activate(&b, None).unwrap_err(),
        BundleError::ManifestInvalid("artifact sizes do not cover artifact region")
    );
}

#[test]
fn unknown_manifest_fields_are_rejected() {
    let mut b = signed(5);
    let h = Header::decode(&b, b.len()).unwrap();
    let m = HEADER_LEN..HEADER_LEN + h.manifest_len as usize;
    let text = String::from_utf8(b[m.clone()].to_vec()).unwrap();
    let patched = text.replacen("\"format\"", "\"formax\"", 1);
    b[m].copy_from_slice(patched.as_bytes());
    resign(&mut b);
    assert!(matches!(
        activate(&b, None).unwrap_err(),
        BundleError::ManifestParse(_)
    ));
}

#[test]
fn trust_anchor_construction() {
    assert!(TrustAnchors::new(vec![key(1).verifying_key()], 0).is_err());
    assert!(TrustAnchors::new(vec![key(1).verifying_key()], 2).is_err());
    assert!(TrustAnchors::new(vec![key(1).verifying_key(), key(1).verifying_key()], 1).is_err());
}

#[test]
fn certificate_encoding_round_trips() {
    let c = cert();
    assert_eq!(ReleaseCert::decode(&c.encode()).unwrap(), c);
    let mut e = c.encode();
    e.pop();
    assert_eq!(
        ReleaseCert::decode(&e).unwrap_err(),
        BundleError::MalformedSignatureBlock
    );
}

/// Pins the Ed25519 library to RFC 8032 (section 7.1, test 1) so a dependency
/// upgrade cannot silently change key derivation or signatures: bundles signed
/// by an older engine must still verify, and the reverse.
#[test]
fn ed25519_matches_rfc8032_test_vector() {
    let seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let want_sig = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap();
    let k = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(k.verifying_key().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig = k.sign(b"");
    assert_eq!(sig.to_bytes().as_slice(), want_sig.as_slice());
    k.verifying_key().verify_strict(b"", &sig).unwrap();
}

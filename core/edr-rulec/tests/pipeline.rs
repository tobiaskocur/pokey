//! Rules directory tests and the full release pipeline through the CLI:
//! keygen -> cert-new -> cert-sign (2 of 3 roots) -> compile -> sign
//! (key file and signer command) -> verify with self-tests -> scan.

use std::path::{Path, PathBuf};
use std::process::Command;

use edr_rulec::{run_tests, Budget, RuleSet};

fn rules_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

#[test]
fn shipped_rules_pass_their_fixtures_and_benign_corpus() {
    let rs = RuleSet::load(&rules_dir()).expect("rules load");
    assert!(rs.warnings.is_empty(), "{:?}", rs.warnings);
    let benign = rules_dir().join("benign");
    let rep = run_tests(&rs, Some(&benign), Budget::default()).expect("run");
    assert!(rep.failures.is_empty(), "{:#?}", rep.failures);
    assert_eq!(
        rep.passed,
        rs.tests.len() + edr_rulec::walk(&benign).unwrap().len()
    );
}

#[test]
fn wrong_expectation_is_reported() {
    let mut rs = RuleSet::load(&rules_dir()).unwrap();
    rs.tests.truncate(1);
    rs.tests[0].expect = "STATIC_MATCH".into();
    let rep = run_tests(&rs, None, Budget::default()).unwrap();
    assert_eq!(rep.passed, 0);
    assert_eq!(rep.failures.len(), 1);
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let p = base.join(format!("rulec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn s(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rulec(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_edr-rulec"))
        .args(args)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn ok(args: &[&str]) -> String {
    let (good, text) = rulec(args);
    assert!(good, "edr-rulec {args:?} failed:\n{text}");
    text
}

#[test]
fn release_pipeline_end_to_end() {
    let t = Tmp::new("e2e");
    let rules = rules_dir().to_string_lossy().into_owned();
    for k in ["root1", "root2", "root3", "release"] {
        ok(&["keygen", "--out", &t.s(k)]);
    }
    let roots: String = ["root1", "root2", "root3"]
        .iter()
        .map(|k| std::fs::read_to_string(t.s(&format!("{k}.pub"))).unwrap())
        .collect();
    std::fs::write(t.s("roots.txt"), format!("# pinned roots\n{roots}")).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (nb, na) = ((now - 60).to_string(), (now + 90 * 86_400).to_string());
    ok(&[
        "cert-new",
        "--release-pub",
        &t.s("release.pub"),
        "--not-before",
        &nb,
        "--not-after",
        &na,
        "--channels",
        "stable,canary",
        "--out",
        &t.s("release.cert"),
    ]);
    ok(&[
        "cert-sign",
        "--cert",
        &t.s("release.cert"),
        "--root-key",
        &t.s("root1.key"),
    ]);
    // Same root twice is refused.
    assert!(
        !rulec(&[
            "cert-sign",
            "--cert",
            &t.s("release.cert"),
            "--root-key",
            &t.s("root1.key")
        ])
        .0
    );

    ok(&[
        "compile",
        "--rules",
        &rules,
        "--version",
        "7",
        "--channel",
        "stable",
        "--expires-days",
        "30",
        "--out",
        &t.s("unsigned.bundle"),
    ]);
    ok(&[
        "sign",
        "--in",
        &t.s("unsigned.bundle"),
        "--cert",
        &t.s("release.cert"),
        "--key-file",
        &t.s("release.key"),
        "--out",
        &t.s("one-root.bundle"),
    ]);
    // One root signature is below the 2-of-3 threshold.
    let (good, text) = rulec(&[
        "verify",
        "--bundle",
        &t.s("one-root.bundle"),
        "--roots",
        &t.s("roots.txt"),
        "--threshold",
        "2",
    ]);
    assert!(!good, "{text}");

    ok(&[
        "cert-sign",
        "--cert",
        &t.s("release.cert"),
        "--root-key",
        &t.s("root3.key"),
    ]);
    assert!(
        ok(&["cert-show", "--cert", &t.s("release.cert")])
            .matches("root_sig")
            .count()
            == 2
    );
    ok(&[
        "sign",
        "--in",
        &t.s("unsigned.bundle"),
        "--cert",
        &t.s("release.cert"),
        "--key-file",
        &t.s("release.key"),
        "--out",
        &t.s("rules.bundle"),
    ]);
    let out = ok(&[
        "verify",
        "--bundle",
        &t.s("rules.bundle"),
        "--roots",
        &t.s("roots.txt"),
        "--threshold",
        "2",
        "--self-test",
    ]);
    assert!(
        out.contains("version 7") && out.contains("self-test: 5 vector(s) passed"),
        "{out}"
    );

    // Rollback: a device already on version 7 refuses version 7 again.
    assert!(
        !rulec(&[
            "verify",
            "--bundle",
            &t.s("rules.bundle"),
            "--roots",
            &t.s("roots.txt"),
            "--threshold",
            "2",
            "--current-version",
            "7"
        ])
        .0
    );

    // External signer contract (HSM/KMS wrapper): message on stdin, signature
    // on stdout. A wrong signature is refused at signing time; capture the
    // message that way, sign it as the HSM would, then sign for real.
    let capture = format!("cat > '{}'; printf '%0128d' 0", t.s("msg.bin"));
    let (good, text) = rulec(&[
        "sign",
        "--in",
        &t.s("unsigned.bundle"),
        "--cert",
        &t.s("release.cert"),
        "--signer-cmd",
        &capture,
        "--out",
        &t.s("hsm.bundle"),
    ]);
    assert!(!good && text.contains("does not match"), "{text}");
    let key_hex = std::fs::read_to_string(t.s("release.key")).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&edr_rulec::parse_key32(&key_hex).unwrap());
    let sig = ed25519_dalek::Signer::sign(&key, &std::fs::read(t.s("msg.bin")).unwrap());
    std::fs::write(t.s("sig.hex"), hex::encode(sig.to_bytes())).unwrap();
    let hsm = format!("cat > /dev/null; cat '{}'", t.s("sig.hex"));
    ok(&[
        "sign",
        "--in",
        &t.s("unsigned.bundle"),
        "--cert",
        &t.s("release.cert"),
        "--signer-cmd",
        &hsm,
        "--out",
        &t.s("hsm.bundle"),
    ]);
    assert_eq!(
        std::fs::read(t.s("hsm.bundle")).unwrap(),
        std::fs::read(t.s("rules.bundle")).unwrap()
    );

    let fixture = rules_dir()
        .join("fixtures/png_trailing_macho.png")
        .to_string_lossy()
        .into_owned();
    let scan = ok(&[
        "scan",
        "--bundle",
        &t.s("rules.bundle"),
        "--roots",
        &t.s("roots.txt"),
        "--threshold",
        "2",
        &fixture,
    ]);
    assert!(scan.contains("STATIC_MATCH"), "{scan}");

    // Tampering with any byte breaks verification.
    let mut b = std::fs::read(t.s("rules.bundle")).unwrap();
    let n = b.len();
    b[n - 10] ^= 1;
    std::fs::write(t.s("tampered.bundle"), b).unwrap();
    assert!(
        !rulec(&[
            "verify",
            "--bundle",
            &t.s("tampered.bundle"),
            "--roots",
            &t.s("roots.txt"),
            "--threshold",
            "2"
        ])
        .0
    );
}

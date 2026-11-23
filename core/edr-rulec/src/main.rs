//! `edr-rulec`: rule pipeline CLI (lint, test, compile, keys, certificates,
//! signing, verification, scanning). Run without arguments for usage.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use edr_core::bundle::{self, Channel, ReleaseCert, TrustAnchors, VerifyMode, CHANNEL_CANARY, CHANNEL_STABLE};
use edr_core::engine::Engine;
use edr_rulec::{parse_key32, parse_roots, run_tests, walk, Args, Budget, Error, RuleSet};

const USAGE: &str = "\
edr-rulec <command> [options]

Rules:
  lint     --rules DIR [--deny-warnings]
  test     --rules DIR [--benign DIR] [--max-ms N] [--max-fuel-pct N]
  compile  --rules DIR --version N --channel stable|canary --expires-days N
           [--created UNIX] --out FILE            (writes an unsigned bundle)
  scan     (--rules DIR | --bundle FILE --roots FILE --threshold N) FILE...

Keys and certificates (roots stay offline; one cert-sign per root ceremony):
  keygen    --out PREFIX                          (PREFIX.key 0600, PREFIX.pub)
  cert-new  --release-pub FILE --not-before UNIX --not-after UNIX
            --channels stable[,canary] --out FILE
  cert-sign --cert FILE --root-key FILE
  cert-show --cert FILE

Signing and verification:
  sign     --in FILE --cert FILE (--key-file FILE | --signer-cmd CMD) --out FILE
           CMD gets the message on stdin and prints a 64-byte Ed25519
           signature (raw or hex) on stdout (HSM/KMS wrapper).
  verify   --bundle FILE --roots FILE --threshold N [--now UNIX]
           [--current-version N] [--self-test]
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = argv.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let r = match cmd.as_str() {
        "lint" => lint(rest),
        "test" => test(rest),
        "compile" => compile(rest),
        "scan" => scan(rest),
        "keygen" => keygen(rest),
        "cert-new" => cert_new(rest),
        "cert-sign" => cert_sign(rest),
        "cert-show" => cert_show(rest),
        "sign" => sign(rest),
        "verify" => verify(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other}\n\n{USAGE}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn read(p: &str) -> Result<Vec<u8>, Error> {
    fs::read(p).map_err(|e| format!("{p}: {e}"))
}

fn read_text(p: &str) -> Result<String, Error> {
    String::from_utf8(read(p)?).map_err(|_| format!("{p}: not utf-8"))
}

/// Write `data` to `path` via a temp file and rename.
fn write_atomic(path: &str, data: &[u8]) -> Result<(), Error> {
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, data).map_err(|e| format!("{tmp}: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("{path}: {e}"))
}

fn load_key(p: &str) -> Result<SigningKey, Error> {
    Ok(SigningKey::from_bytes(&parse_key32(&read_text(p)?).map_err(|e| format!("{p}: {e}"))?))
}

fn anchors(a: &Args) -> Result<TrustAnchors, Error> {
    let roots = parse_roots(&read_text(a.req("roots")?)?)?;
    let threshold = a.num::<usize>("threshold")?.ok_or("missing --threshold")?;
    TrustAnchors::from_raw(&roots, threshold).map_err(str::to_string)
}

fn lint(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &["deny-warnings"])?;
    let rs = RuleSet::load(Path::new(a.req("rules")?))?;
    for w in &rs.warnings {
        eprintln!("warning: {w}");
    }
    println!(
        "ok: {} yara file(s), {} schema(s), {} format(s), {} fixture test(s)",
        rs.yara.len(),
        rs.schemas.len(),
        rs.policy.formats.len(),
        rs.tests.len()
    );
    if a.has("deny-warnings") && !rs.warnings.is_empty() {
        return Err(format!("{} warning(s)", rs.warnings.len()));
    }
    Ok(())
}

fn test(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let rs = RuleSet::load(Path::new(a.req("rules")?))?;
    let mut budget = Budget::default();
    if let Some(ms) = a.num::<u64>("max-ms")? {
        budget.max_scan = Duration::from_millis(ms);
    }
    if let Some(p) = a.num::<u64>("max-fuel-pct")? {
        budget.max_fuel_pct = p;
    }
    let rep = run_tests(&rs, a.get("benign").map(Path::new), budget)?;
    for f in &rep.failures {
        println!("FAIL {f}");
    }
    let slow = rep.slowest.as_ref().map(|(n, d)| format!("{n} {d:?}")).unwrap_or_default();
    println!("{} passed, {} failed; max fuel {}; slowest {slow}", rep.passed, rep.failures.len(), rep.max_fuel);
    if rep.failures.is_empty() {
        Ok(())
    } else {
        Err("rule tests failed".into())
    }
}

fn compile(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let rs = RuleSet::load(Path::new(a.req("rules")?))?;
    let version = a.num::<u64>("version")?.ok_or("missing --version")?;
    let channel = match a.req("channel")? {
        "stable" => Channel::Stable,
        "canary" => Channel::Canary,
        c => return Err(format!("unknown channel {c}")),
    };
    let days = a.num::<i64>("expires-days")?.ok_or("missing --expires-days")?;
    if !(1..=365).contains(&days) {
        return Err("--expires-days must be 1..=365".into());
    }
    let created = a.num::<i64>("created")?.unwrap_or_else(now);
    let manifest = rs.manifest(version, channel, created, created + days * 86_400);
    let out = bundle::build_unsigned(manifest, &rs.artifacts()?).map_err(|e| e.to_string())?;
    write_atomic(a.req("out")?, &out)?;
    println!("wrote unsigned bundle version {version} ({} bytes)", out.len());
    Ok(())
}

fn scan(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let bundle_bytes;
    let (engine, policy_hint): (Engine, _) = if let Some(dir) = a.get("rules") {
        let rs = RuleSet::load(Path::new(dir))?;
        (rs.engine()?, rs.policy)
    } else {
        bundle_bytes = read(a.req("bundle")?)?;
        let b = bundle::verify(&bundle_bytes, &anchors(&a)?, VerifyMode::Load { now: now() })
            .map_err(|e| e.to_string())?;
        let e = Engine::from_bundle(&b).map_err(|e| e.to_string())?;
        let p = e.policy.clone();
        (e, p)
    };
    if a.positional.is_empty() {
        return Err("no files to scan".into());
    }
    let mut files = Vec::new();
    for p in &a.positional {
        let p = Path::new(p);
        if p.is_dir() {
            files.extend(walk(p)?);
        } else {
            files.push(p.to_path_buf());
        }
    }
    for p in files {
        let data = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let hint = p.extension().and_then(|e| e.to_str()).and_then(|e| policy_hint.format_for_extension(e));
        let r = engine.scan(&data, hint);
        println!(
            "{}\t{}\tformat={}\thits={}\tfuel={}\t{}",
            p.display(),
            r.outcome.name(),
            r.format.as_deref().unwrap_or("-"),
            r.hits.join(","),
            r.fuel_used,
            r.detail
        );
    }
    Ok(())
}

fn keygen(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let prefix = a.req("out")?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let key_path = format!("{prefix}.key");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&key_path).map_err(|e| format!("{key_path}: {e}"))?;
    writeln!(f, "{}", hex::encode(key.to_bytes())).map_err(|e| e.to_string())?;
    let pub_hex = hex::encode(key.verifying_key().to_bytes());
    fs::write(format!("{prefix}.pub"), format!("{pub_hex}\n")).map_err(|e| e.to_string())?;
    println!("{pub_hex}");
    Ok(())
}

fn cert_new(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let release = parse_key32(&read_text(a.req("release-pub")?)?)?;
    let nb = a.num::<i64>("not-before")?.ok_or("missing --not-before")?;
    let na = a.num::<i64>("not-after")?.ok_or("missing --not-after")?;
    if na <= nb {
        return Err("--not-after must be after --not-before".into());
    }
    let mut channels = 0u8;
    for c in a.req("channels")?.split(',') {
        channels |= match c.trim() {
            "stable" => CHANNEL_STABLE,
            "canary" => CHANNEL_CANARY,
            other => return Err(format!("unknown channel {other}")),
        };
    }
    let cert = ReleaseCert::unsigned(release, nb, na, channels);
    write_atomic(a.req("out")?, &cert.encode())?;
    println!("wrote unsigned certificate; sign it with cert-sign on each root");
    Ok(())
}

fn cert_sign(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let path = a.req("cert")?;
    let mut cert = ReleaseCert::decode(&read(path)?).map_err(|e| e.to_string())?;
    let root = load_key(a.req("root-key")?)?;
    let id = bundle::key_id(&root.verifying_key());
    if cert.root_sigs.iter().any(|(i, _)| *i == id) {
        return Err("this root already signed the certificate".into());
    }
    cert.add_root_signature(&root);
    write_atomic(path, &cert.encode())?;
    println!("certificate now has {} root signature(s)", cert.root_sigs.len());
    Ok(())
}

fn cert_show(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let c = ReleaseCert::decode(&read(a.req("cert")?)?).map_err(|e| e.to_string())?;
    println!("release_key {}", hex::encode(c.release_key));
    println!("not_before  {}\nnot_after   {}\nchannels    {:#04x}", c.not_before, c.not_after, c.channels);
    for (id, _) in &c.root_sigs {
        println!("root_sig    {}", hex::encode(id));
    }
    Ok(())
}

fn signer_cmd(cmd: &str, msg: &[u8]) -> Result<[u8; 64], String> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn signer: {e}"))?;
    child.stdin.take().ok_or("no stdin")?.write_all(msg).map_err(|e| format!("signer stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("signer: {e}"))?;
    if !out.status.success() {
        return Err(format!("signer exited with {}", out.status));
    }
    let raw = if out.stdout.len() == 64 {
        out.stdout
    } else {
        let text = String::from_utf8(out.stdout).map_err(|_| "signer output is neither 64 raw bytes nor hex")?;
        hex::decode(text.trim()).map_err(|_| "signer output is neither 64 raw bytes nor hex")?
    };
    raw.try_into().map_err(|_| "signer output must be 64 bytes".to_string())
}

fn sign(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &[])?;
    let unsigned = read(a.req("in")?)?;
    let cert = ReleaseCert::decode(&read(a.req("cert")?)?).map_err(|e| format!("cert: {e}"))?;
    let signed = match (a.get("key-file"), a.get("signer-cmd")) {
        (Some(k), None) => {
            let key = load_key(k)?;
            bundle::sign(&unsigned, &cert, &mut |m| Ok(key.sign(m).to_bytes()))
        }
        (None, Some(cmd)) => bundle::sign(&unsigned, &cert, &mut |m| signer_cmd(cmd, m)),
        _ => return Err("give exactly one of --key-file or --signer-cmd".into()),
    }
    .map_err(|e| e.to_string())?;
    write_atomic(a.req("out")?, &signed)?;
    println!("signed bundle ({} bytes)", signed.len());
    Ok(())
}

fn verify(argv: &[String]) -> Result<(), Error> {
    let a = Args::parse(argv, &["self-test"])?;
    let bytes = read(a.req("bundle")?)?;
    let now = a.num::<i64>("now")?.unwrap_or_else(now);
    let mode = VerifyMode::Activation { now, current_version: a.num::<u64>("current-version")? };
    let b = bundle::verify(&bytes, &anchors(&a)?, mode).map_err(|e| e.to_string())?;
    println!(
        "ok: version {} channel {:?} expires {} artifacts {} self-tests {}",
        b.manifest.version,
        b.manifest.channel,
        b.manifest.expires,
        b.manifest.artifacts.len(),
        b.manifest.self_tests.len()
    );
    if a.has("self-test") {
        let engine = Engine::from_bundle(&b).map_err(|e| e.to_string())?;
        let n = engine.self_test(&b)?;
        println!("self-test: {n} vector(s) passed");
    }
    Ok(())
}

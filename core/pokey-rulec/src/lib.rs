//! Rule pipeline library behind the `pokey-rulec` CLI: load a rules directory,
//! lint it, run fixtures and the benign corpus, and produce unsigned bundles.
//! Signing and verification live in `pokey_core::bundle`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pokey_core::bundle::{ArtifactKind, Channel, Manifest, SelfTest};
use pokey_core::engine::{compile_yara, Engine, Outcome};
use pokey_core::policy::Policy;
use pokey_core::schema::{self, Program};
use serde::Deserialize;

pub type Error = String;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    pub fixture: String,
    pub expect: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    /// Ship the fixture in the bundle as an activation self-test vector.
    #[serde(default)]
    pub self_test: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestFile {
    fixtures: Vec<TestCase>,
}

/// A rules directory:
///
/// ```text
/// policy.json  yara/*.yar  schemas/*.schema  fixtures/*  tests.json
/// ```
#[derive(Debug)]
pub struct RuleSet {
    pub root: PathBuf,
    pub policy_json: Vec<u8>,
    pub policy: Policy,
    /// (artifact name, source)
    pub yara: Vec<(String, String)>,
    /// (artifact name of compiled IR, program)
    pub schemas: Vec<(String, Program)>,
    pub tests: Vec<TestCase>,
    pub warnings: Vec<String>,
}

fn read(p: &Path) -> Result<Vec<u8>, Error> {
    fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn sorted_files(dir: &Path, ext: &str) -> Result<Vec<PathBuf>, Error> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some(ext))
        .collect();
    out.sort();
    Ok(out)
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

impl RuleSet {
    /// Load and compile everything; any error in policy, YARA or schema
    /// source fails the load.
    pub fn load(root: &Path) -> Result<RuleSet, Error> {
        let policy_json = read(&root.join("policy.json"))?;
        let policy = Policy::parse(&policy_json)?;
        let mut yara = Vec::new();
        for p in sorted_files(&root.join("yara"), "yar")? {
            let src =
                String::from_utf8(read(&p)?).map_err(|_| format!("{}: not utf-8", p.display()))?;
            yara.push((format!("yara/{}", file_name(&p)), src));
        }
        let (_, warnings) = compile_yara(&yara).map_err(|e| e.to_string())?;
        let mut schemas: Vec<(String, Program)> = Vec::new();
        for p in sorted_files(&root.join("schemas"), "schema")? {
            let src =
                String::from_utf8(read(&p)?).map_err(|_| format!("{}: not utf-8", p.display()))?;
            let prog = schema::compile(&src).map_err(|e| format!("{}: {e}", p.display()))?;
            if schemas.iter().any(|(_, q)| q.name == prog.name) {
                return Err(format!(
                    "{}: duplicate schema name {}",
                    p.display(),
                    prog.name
                ));
            }
            schemas.push((format!("schemas/{}.ir", prog.name), prog));
        }
        let tests_path = root.join("tests.json");
        let tests = if tests_path.exists() {
            let t: TestFile = serde_json::from_slice(&read(&tests_path)?)
                .map_err(|e| format!("tests.json: {e}"))?;
            t.fixtures
        } else {
            Vec::new()
        };
        for t in &tests {
            if Outcome::from_name(&t.expect).is_none() {
                return Err(format!(
                    "tests.json: {}: unknown outcome {}",
                    t.fixture, t.expect
                ));
            }
            if t.fixture.contains('/') || t.fixture.starts_with('.') {
                return Err(format!(
                    "tests.json: fixture {} must be a plain file name",
                    t.fixture
                ));
            }
        }
        let rs = RuleSet {
            root: root.to_path_buf(),
            policy_json,
            policy,
            yara,
            schemas,
            tests,
            warnings,
        };
        rs.engine()?; // cross-checks policy -> schema references
        Ok(rs)
    }

    pub fn engine(&self) -> Result<Engine, Error> {
        let (rules, _) = compile_yara(&self.yara).map_err(|e| e.to_string())?;
        let progs = self.schemas.iter().map(|(_, p)| p.clone()).collect();
        Engine::new(rules, progs, self.policy.clone()).map_err(|e| e.to_string())
    }

    pub fn fixture_path(&self, name: &str) -> PathBuf {
        self.root.join("fixtures").join(name)
    }

    /// Artifacts in bundle order: policy, YARA sources, schema IR, self-test
    /// fixtures.
    pub fn artifacts(&self) -> Result<Vec<(String, ArtifactKind, Vec<u8>)>, Error> {
        let mut out = vec![(
            "policy.json".to_string(),
            ArtifactKind::Policy,
            self.policy_json.clone(),
        )];
        for (name, src) in &self.yara {
            out.push((name.clone(), ArtifactKind::Yara, src.as_bytes().to_vec()));
        }
        for (name, prog) in &self.schemas {
            out.push((name.clone(), ArtifactKind::Schema, prog.to_bytes()));
        }
        for t in self.tests.iter().filter(|t| t.self_test) {
            out.push((
                format!("fixtures/{}", t.fixture),
                ArtifactKind::Fixture,
                read(&self.fixture_path(&t.fixture))?,
            ));
        }
        Ok(out)
    }

    pub fn manifest(&self, version: u64, channel: Channel, created: i64, expires: i64) -> Manifest {
        Manifest {
            format: 1,
            version,
            channel,
            created,
            expires,
            min_engine: pokey_core::ENGINE_VERSION,
            artifacts: Vec::new(),
            self_tests: self
                .tests
                .iter()
                .filter(|t| t.self_test)
                .map(|t| SelfTest {
                    fixture: format!("fixtures/{}", t.fixture),
                    format: t.format.clone(),
                    expect: t.expect.clone(),
                    rule: t.rule.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Maximum wall-clock scan time per file.
    pub max_scan: Duration,
    /// Maximum share of the policy fuel budget a fixture may use (percent).
    pub max_fuel_pct: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_scan: Duration::from_millis(250),
            max_fuel_pct: 10,
        }
    }
}

#[derive(Debug, Default)]
pub struct TestReport {
    pub passed: usize,
    pub failures: Vec<String>,
    pub max_fuel: u64,
    pub slowest: Option<(String, Duration)>,
}

impl TestReport {
    fn timing(&mut self, name: &str, d: Duration, fuel: u64, budget: &Budget, policy_fuel: u64) {
        self.max_fuel = self.max_fuel.max(fuel);
        if self.slowest.as_ref().is_none_or(|(_, s)| d > *s) {
            self.slowest = Some((name.to_string(), d));
        }
        if d > budget.max_scan {
            self.failures.push(format!(
                "{name}: scan took {d:?}, budget {:?}",
                budget.max_scan
            ));
        }
        if fuel.saturating_mul(100) > policy_fuel.saturating_mul(budget.max_fuel_pct) {
            self.failures.push(format!(
                "{name}: used {fuel} fuel, over {}% of policy max_fuel",
                budget.max_fuel_pct
            ));
        }
    }
}

/// Run every fixture in tests.json plus every file in `benign` (which must
/// scan CLEAN), enforcing the perf budget.
pub fn run_tests(rs: &RuleSet, benign: Option<&Path>, budget: Budget) -> Result<TestReport, Error> {
    let engine = rs.engine()?;
    let mut rep = TestReport::default();
    for t in &rs.tests {
        let data = read(&rs.fixture_path(&t.fixture))?;
        let start = Instant::now();
        let r = engine.scan(&data, t.format.as_deref());
        let d = start.elapsed();
        rep.timing(&t.fixture, d, r.fuel_used, &budget, rs.policy.max_fuel);
        let mut ok = r.outcome.name() == t.expect;
        if let Some(rule) = &t.rule {
            ok &= r.hits.contains(rule);
        }
        if ok {
            rep.passed += 1;
        } else {
            rep.failures.push(format!(
                "{}: expected {}{}, got {} hits={:?} ({})",
                t.fixture,
                t.expect,
                t.rule
                    .as_ref()
                    .map(|r| format!(" [{r}]"))
                    .unwrap_or_default(),
                r.outcome.name(),
                r.hits,
                r.detail
            ));
        }
    }
    if let Some(dir) = benign {
        for p in walk(dir)? {
            let data = read(&p)?;
            let hint = p
                .extension()
                .and_then(|e| e.to_str())
                .and_then(|e| rs.policy.format_for_extension(e));
            let start = Instant::now();
            let r = engine.scan(&data, hint);
            let d = start.elapsed();
            let name = p.display().to_string();
            rep.timing(&name, d, r.fuel_used, &budget, rs.policy.max_fuel);
            if r.outcome == Outcome::Clean {
                rep.passed += 1;
            } else {
                rep.failures.push(format!(
                    "benign {name}: {} hits={:?} ({})",
                    r.outcome.name(),
                    r.hits,
                    r.detail
                ));
            }
        }
    }
    Ok(rep)
}

/// Regular files under `dir`, recursively, sorted; symlinks are skipped.
pub fn walk(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let e = e.map_err(|e| e.to_string())?;
            let ft = e.file_type().map_err(|e| e.to_string())?;
            let name = e.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                out.push(e.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Parse a roots file: one hex Ed25519 public key per line, `#` comments.
pub fn parse_roots(text: &str) -> Result<Vec<[u8; 32]>, Error> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.split('#').next().unwrap_or_default().trim();
        if l.is_empty() {
            continue;
        }
        out.push(parse_key32(l).map_err(|e| format!("roots line {}: {e}", i + 1))?);
    }
    Ok(out)
}

pub fn parse_key32(hex_str: &str) -> Result<[u8; 32], Error> {
    let v = hex::decode(hex_str.trim()).map_err(|e| format!("bad hex: {e}"))?;
    v.try_into().map_err(|_| "expected 32 bytes".to_string())
}

/// Simple `--flag value` / `--switch` / positional argument parser.
#[derive(Debug, Default)]
pub struct Args {
    pub flags: BTreeMap<String, String>,
    pub switches: Vec<String>,
    pub positional: Vec<String>,
}

impl Args {
    pub fn parse(argv: &[String], switches: &[&str]) -> Result<Args, Error> {
        let mut a = Args::default();
        let mut it = argv.iter();
        while let Some(x) = it.next() {
            if let Some(name) = x.strip_prefix("--") {
                if switches.contains(&name) {
                    a.switches.push(name.to_string());
                } else {
                    let v = it.next().ok_or(format!("--{name} needs a value"))?;
                    if a.flags.insert(name.to_string(), v.clone()).is_some() {
                        return Err(format!("--{name} given twice"));
                    }
                }
            } else {
                a.positional.push(x.clone());
            }
        }
        Ok(a)
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.flags.get(k).map(String::as_str)
    }

    pub fn req(&self, k: &str) -> Result<&str, Error> {
        self.get(k).ok_or(format!("missing --{k}"))
    }

    pub fn num<T: std::str::FromStr>(&self, k: &str) -> Result<Option<T>, Error> {
        self.get(k)
            .map(|v| v.parse::<T>().map_err(|_| format!("--{k}: bad number {v}")))
            .transpose()
    }

    pub fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }
}

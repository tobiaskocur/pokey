//! Stage-1 scan engine: YARA-X signatures + structural schemas + policy.
//!
//! YARA rules ship as source in the signed bundle and are compiled inside the
//! sandboxed inspector during pre-warm. Shipping serialized `yara_x::Rules`
//! would mean shipping precompiled native code; source keeps the bundle
//! data-only and independent of the exact YARA-X build.

use std::time::Duration;

use crate::bundle::{ArtifactKind, VerifiedBundle};
use crate::policy::Policy;
use crate::schema::{self, ExecError, Limits, Program};

/// Inspection outcome. Codes are shared with the Swift side through the C
/// header (`EDR_OUTCOME_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Outcome {
    Clean = 0,
    StaticMatch = 1,
    SchemaViolation = 2,
    DecodeError = 3,
    Timeout = 4,
    ResourceExceeded = 5,
    Crash = 6,
    ProtocolViolation = 7,
}

impl Outcome {
    pub const ALL: [Outcome; 8] = [
        Outcome::Clean,
        Outcome::StaticMatch,
        Outcome::SchemaViolation,
        Outcome::DecodeError,
        Outcome::Timeout,
        Outcome::ResourceExceeded,
        Outcome::Crash,
        Outcome::ProtocolViolation,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Outcome::Clean => "CLEAN",
            Outcome::StaticMatch => "STATIC_MATCH",
            Outcome::SchemaViolation => "SCHEMA_VIOLATION",
            Outcome::DecodeError => "DECODE_ERROR",
            Outcome::Timeout => "TIMEOUT",
            Outcome::ResourceExceeded => "RESOURCE_EXCEEDED",
            Outcome::Crash => "CRASH",
            Outcome::ProtocolViolation => "PROTOCOL_VIOLATION",
        }
    }

    pub fn from_name(n: &str) -> Option<Outcome> {
        Outcome::ALL.into_iter().find(|o| o.name() == n)
    }

    /// Precedence when stage-1 checks disagree (higher wins).
    fn rank(self) -> u8 {
        match self {
            Outcome::Clean => 0,
            Outcome::ResourceExceeded | Outcome::Timeout => 1,
            Outcome::DecodeError => 2,
            Outcome::SchemaViolation => 3,
            Outcome::StaticMatch => 4,
            Outcome::Crash | Outcome::ProtocolViolation => 5,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("policy: {0}")]
    Policy(String),
    #[error("yara: {0}")]
    Yara(String),
    #[error("schema {0}: {1}")]
    Schema(String, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub outcome: Outcome,
    /// Detected (or hinted) format name.
    pub format: Option<String>,
    /// Every YARA rule that matched and every schema that was violated.
    pub hits: Vec<String>,
    pub detail: String,
    pub offset: u64,
    pub fuel_used: u64,
}

pub struct Engine {
    rules: Option<yara_x::Rules>,
    schemas: Vec<Program>,
    pub policy: Policy,
}

/// Compile YARA sources (name, text). Returns compiled rules and warnings.
pub fn compile_yara(sources: &[(String, String)]) -> Result<(Option<yara_x::Rules>, Vec<String>), EngineError> {
    if sources.is_empty() {
        return Ok((None, Vec::new()));
    }
    let mut c = yara_x::Compiler::new();
    for (name, src) in sources {
        let ns: String = name.chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' }).collect();
        c.new_namespace(&ns);
        c.add_source(yara_x::SourceCode::from(src.as_str()).with_origin(name.as_str()))
            .map_err(|e| EngineError::Yara(e.to_string()))?;
    }
    let warnings = c.warnings().iter().map(|w| w.to_string()).collect();
    Ok((Some(c.build()), warnings))
}

impl Engine {
    pub fn new(rules: Option<yara_x::Rules>, schemas: Vec<Program>, policy: Policy) -> Result<Engine, EngineError> {
        policy.validate().map_err(EngineError::Policy)?;
        for (name, f) in &policy.formats {
            if let Some(s) = &f.schema {
                if !schemas.iter().any(|p| &p.name == s) {
                    return Err(EngineError::Policy(format!("format {name} references missing schema {s}")));
                }
            }
        }
        Ok(Engine { rules, schemas, policy })
    }

    /// Build the engine from a verified bundle.
    pub fn from_bundle(b: &VerifiedBundle<'_>) -> Result<Engine, EngineError> {
        let policy_bytes = b.artifacts_of(ArtifactKind::Policy).next().map(|(_, d)| d).unwrap_or_default();
        let policy = Policy::parse(policy_bytes).map_err(EngineError::Policy)?;
        let mut sources = Vec::new();
        for (e, d) in b.artifacts_of(ArtifactKind::Yara) {
            let s = std::str::from_utf8(d).map_err(|_| EngineError::Yara(format!("{} is not utf-8", e.name)))?;
            sources.push((e.name.clone(), s.to_string()));
        }
        let (rules, _) = compile_yara(&sources)?;
        let mut schemas = Vec::new();
        for (e, d) in b.artifacts_of(ArtifactKind::Schema) {
            schemas.push(Program::from_bytes(d).map_err(|m| EngineError::Schema(e.name.clone(), m))?);
        }
        Engine::new(rules, schemas, policy)
    }

    /// Format by content sniffing; the sensor's extension hint is only a
    /// fallback (the sensor never looks at content).
    pub fn detect_format(&self, data: &[u8], hint: Option<&str>) -> Option<String> {
        for (name, f) in &self.policy.formats {
            if let Some(s) = &f.schema {
                if self.schemas.iter().any(|p| &p.name == s && schema::interp::detects(p, data)) {
                    return Some(name.clone());
                }
            }
        }
        hint.filter(|h| self.policy.formats.contains_key(*h)).map(str::to_string)
    }

    pub fn scan(&self, data: &[u8], hint: Option<&str>) -> ScanReport {
        let format = self.detect_format(data, hint);
        let fpol = self.policy.format(format.as_deref().unwrap_or("other"));
        let mut rep = ScanReport {
            outcome: Outcome::Clean,
            format: format.clone(),
            hits: Vec::new(),
            detail: String::new(),
            offset: 0,
            fuel_used: 0,
        };
        let set = |rep: &mut ScanReport, o: Outcome, detail: String, offset: u64| {
            if o.rank() > rep.outcome.rank() {
                rep.outcome = o;
                rep.detail = detail;
                rep.offset = offset;
            }
        };
        if let Some(f) = fpol {
            if data.len() as u64 > f.max_bytes {
                set(&mut rep, Outcome::ResourceExceeded, format!("file exceeds max_bytes {}", f.max_bytes), 0);
                return rep;
            }
        }
        if let Some(rules) = &self.rules {
            let mut scanner = yara_x::Scanner::new(rules);
            if let Some(f) = fpol {
                scanner.set_timeout(Duration::from_millis(f.deadline_ms as u64));
            }
            match scanner.scan(data) {
                Ok(res) => {
                    for r in res.matching_rules() {
                        rep.hits.push(r.identifier().to_string());
                    }
                    if let Some(first) = rep.hits.first().cloned() {
                        set(&mut rep, Outcome::StaticMatch, format!("rule {first}"), 0);
                    }
                }
                Err(yara_x::ScanError::Timeout) => set(&mut rep, Outcome::Timeout, "yara timeout".into(), 0),
                Err(e) => set(&mut rep, Outcome::DecodeError, format!("yara: {e}"), 0),
            }
        }
        if let Some(sname) = fpol.and_then(|f| f.schema.as_ref()) {
            if let Some(prog) = self.schemas.iter().find(|p| &p.name == sname) {
                let lim = Limits { fuel: self.policy.max_fuel, ..Limits::default() };
                match schema::run(prog, data, lim) {
                    Ok(st) => rep.fuel_used = st.fuel_used,
                    Err((e, st)) => {
                        rep.fuel_used = st.fuel_used;
                        let (o, off) = match &e {
                            ExecError::Violation { offset, .. } | ExecError::Arithmetic { offset } => {
                                (Outcome::SchemaViolation, *offset)
                            }
                            ExecError::OutOfBounds { offset, .. } => (Outcome::SchemaViolation, *offset),
                            ExecError::FuelExhausted | ExecError::LimitExceeded(_) => (Outcome::ResourceExceeded, 0),
                            ExecError::InvalidProgram(_) => (Outcome::DecodeError, 0),
                        };
                        if o == Outcome::SchemaViolation {
                            rep.hits.push(prog.name.clone());
                        }
                        set(&mut rep, o, format!("{}: {e}", prog.name), off);
                    }
                }
            }
        }
        rep
    }

    /// Run the bundle's self-test vectors. Used by the sensor (in a fresh
    /// inspector) before a bundle becomes current.
    pub fn self_test(&self, b: &VerifiedBundle<'_>) -> Result<usize, String> {
        for t in &b.manifest.self_tests {
            let data = b.artifact(&t.fixture).ok_or_else(|| format!("missing fixture {}", t.fixture))?;
            let r = self.scan(data, t.format.as_deref());
            if r.outcome.name() != t.expect {
                return Err(format!("{}: expected {}, got {} ({})", t.fixture, t.expect, r.outcome.name(), r.detail));
            }
            if let Some(rule) = &t.rule {
                if !r.hits.contains(rule) {
                    return Err(format!("{}: expected hit {rule}, got {:?}", t.fixture, r.hits));
                }
            }
        }
        Ok(b.manifest.self_tests.len())
    }
}

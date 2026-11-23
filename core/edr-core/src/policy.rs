//! Policy as data: formats, limits, deadlines and outcome -> action mapping.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::engine::Outcome;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatPolicy {
    /// Lower-case file extensions the sensor maps to this format hint.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Structural schema to run (by schema name).
    pub schema: Option<String>,
    /// Run the stage-2 OS decoder (ImageIO) for this format.
    pub decode: bool,
    pub max_bytes: u64,
    pub max_pixels: u64,
    pub deadline_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Allow,
    Log,
    Alert,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub severity: Severity,
    pub action: ActionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    /// Fuel budget per schema run.
    pub max_fuel: u64,
    /// Physical footprint budget enforced by the sensor watchdog.
    pub memory_limit_mb: u32,
    /// Format name -> policy. Must contain `other` for unknown formats.
    pub formats: BTreeMap<String, FormatPolicy>,
    /// Outcome name (e.g. `STATIC_MATCH`) -> action. Must cover every outcome.
    pub outcomes: BTreeMap<String, Action>,
}

pub const MAX_FILE_BYTES: u64 = 1 << 30;

impl Policy {
    pub fn parse(bytes: &[u8]) -> Result<Policy, String> {
        let p: Policy = serde_json::from_slice(bytes).map_err(|e| format!("policy: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("policy: unsupported version".into());
        }
        if self.max_fuel == 0 || self.max_fuel > 1_000_000_000 {
            return Err("policy: max_fuel out of range".into());
        }
        if !(16..=4096).contains(&self.memory_limit_mb) {
            return Err("policy: memory_limit_mb out of range".into());
        }
        if !self.formats.contains_key("other") {
            return Err("policy: formats must contain `other`".into());
        }
        let mut seen_ext = std::collections::HashSet::new();
        for (name, f) in &self.formats {
            if f.max_bytes == 0 || f.max_bytes > MAX_FILE_BYTES {
                return Err(format!("policy: {name}: max_bytes out of range"));
            }
            if f.deadline_ms == 0 || f.deadline_ms > 60_000 {
                return Err(format!("policy: {name}: deadline_ms out of range"));
            }
            for e in &f.extensions {
                if e.is_empty() || !e.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
                    return Err(format!("policy: {name}: bad extension {e:?}"));
                }
                if !seen_ext.insert(e.as_str()) {
                    return Err(format!("policy: extension {e} mapped twice"));
                }
            }
        }
        for o in Outcome::ALL {
            if !self.outcomes.contains_key(o.name()) {
                return Err(format!("policy: no action for outcome {}", o.name()));
            }
        }
        if self.outcomes.keys().any(|k| Outcome::from_name(k).is_none()) {
            return Err("policy: unknown outcome name".into());
        }
        Ok(())
    }

    /// Policy for `name`, falling back to `other` (always present after validation).
    pub fn format(&self, name: &str) -> Option<&FormatPolicy> {
        self.formats.get(name).or_else(|| self.formats.get("other"))
    }

    pub fn format_for_extension(&self, ext: &str) -> Option<&str> {
        let ext = ext.to_ascii_lowercase();
        self.formats.iter().find(|(_, f)| f.extensions.contains(&ext)).map(|(n, _)| n.as_str())
    }
}

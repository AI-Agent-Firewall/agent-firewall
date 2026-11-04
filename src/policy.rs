use anyhow::{Context, Result, bail, ensure};
use fancy_regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: String,
    pub policy_id: String,
    pub last_updated: String,
    pub engine: Engine,
    pub taint_policy: TaintPolicy,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engine {
    pub enforcement_mode: EnforcementMode,
    pub default_action: Decision,
    pub hot_reload: HotReload,
    pub jit_elevation: JitElevation,
    pub telemetry: Telemetry,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Enforcing,
    Permissive,
    AuditOnly,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    StepUp,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotReload {
    pub enabled: bool,
    pub watch_interval_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JitElevation {
    pub tty_device: String,
    pub timeout_seconds: u64,
    pub timeout_action: Decision,
    pub prompt_banner: String,
    pub headless_ci_fallback: HeadlessCiFallback,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadlessCiFallback {
    pub enabled: bool,
    pub env_flag: String,
    pub on_taint_rule: Decision,
    pub on_standard_rule: Decision,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    pub log_path: String,
    pub async_flush: bool,
    pub include_arguments: bool,
    pub redact_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintPolicy {
    pub enabled: bool,
    pub session_ttl_seconds: u64,
    pub tainted_sinks: Vec<TaintedSink>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintedSink {
    pub sink_id: String,
    pub name: String,
    pub description: String,
    pub tool_regex: String,
    pub arg_regex: String,
    pub action: Action,
    pub severity: Severity,
    pub wazuh_rule_level: u8,
    pub telemetry_tags: TelemetryTags,
    pub compliance: Compliance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub rule_id: String,
    pub priority: u32,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    #[serde(rename = "match")]
    pub matcher: Match,
    pub action: Action,
    pub taint_session: bool,
    pub severity: Severity,
    pub wazuh_rule_level: u8,
    pub telemetry_tags: TelemetryTags,
    pub compliance: Compliance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub tool_regex: String,
    pub arg_regex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryTags {
    pub mitre_atlas_technique: String,
    pub owasp_llm: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compliance {
    pub iso_27001_2022: Vec<String>,
    pub soc2_type2: Vec<String>,
    pub nist_ai_rmf: Vec<String>,
    pub eu_ai_act: Vec<String>,
}

/// Metadata and compiled patterns stay together, in ascending priority order.
#[derive(Debug)]
pub struct CompiledRule {
    pub rule: Rule,
    pub tool_regex: Regex,
    pub arg_regex: Regex,
}

#[derive(Debug)]
pub struct CompiledSink {
    pub sink: TaintedSink,
    pub tool_regex: Regex,
    pub arg_regex: Regex,
}

/// Constructible only through validation. Store behind Arc to share immutable snapshots.
#[derive(Debug)]
pub struct CompiledPolicy {
    schema_version: String,
    policy_id: String,
    last_updated: String,
    engine: Engine,
    taint_policy_enabled: bool,
    session_ttl_seconds: u64,
    rules: Vec<CompiledRule>,
    sinks: Vec<CompiledSink>,
    redact_patterns: Vec<Regex>,
}

impl CompiledPolicy {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let text = fs::read_to_string(path.as_ref()).context("cannot read policy file")?;
        Self::from_yaml(&text)
    }

    pub fn from_yaml(text: &str) -> Result<Self> {
        let mut policy: Policy =
            serde_saphyr::from_str(text).context("invalid policy YAML/schema")?;
        ensure!(
            policy.schema_version == "1.1.0",
            "unsupported schema_version (expected 1.1.0)"
        );
        nonblank("policy_id", &policy.policy_id)?;
        chrono::DateTime::parse_from_rfc3339(&policy.last_updated)
            .context("last_updated must be RFC3339")?;
        let engine = &policy.engine;
        ensure!(
            (1..=86_400_000).contains(&engine.hot_reload.watch_interval_ms),
            "watch_interval_ms must be 1..=86400000"
        );
        ensure!(
            engine.jit_elevation.timeout_seconds > 0,
            "timeout_seconds must be positive"
        );
        ensure!(
            policy.taint_policy.session_ttl_seconds > 0,
            "session_ttl_seconds must be positive"
        );
        nonblank("tty_device", &engine.jit_elevation.tty_device)?;
        nonblank("prompt_banner", &engine.jit_elevation.prompt_banner)?;
        nonblank("log_path", &engine.telemetry.log_path)?;
        let flag = &engine.jit_elevation.headless_ci_fallback.env_flag;
        ensure!(
            !flag.is_empty()
                && flag.bytes().enumerate().all(|(i, c)| c == b'_'
                    || c.is_ascii_alphabetic()
                    || (i > 0 && c.is_ascii_digit())),
            "env_flag must be an environment variable identifier"
        );
        // Stable sorting preserves YAML order for equal priorities.
        policy.rules.sort_by_key(|r| r.priority);
        let mut ids = HashSet::new();
        let mut rules = Vec::new();
        for rule in policy.rules {
            nonblank("rule_id", &rule.rule_id)?;
            ensure!(
                ids.insert(rule.rule_id.clone()),
                "duplicate rule_id: {}",
                rule.rule_id
            );
            metadata(
                &rule.name,
                &rule.description,
                rule.wazuh_rule_level,
                &rule.telemetry_tags,
                &rule.compliance,
            )
            .with_context(|| format!("rule {}", rule.rule_id))?;
            rules.push(CompiledRule {
                tool_regex: compile(
                    &format!("{}.match.tool_regex", rule.rule_id),
                    &rule.matcher.tool_regex,
                )?,
                arg_regex: compile(
                    &format!("{}.match.arg_regex", rule.rule_id),
                    &rule.matcher.arg_regex,
                )?,
                rule,
            });
        }
        let mut ids = HashSet::new();
        let mut sinks = Vec::new();
        for sink in policy.taint_policy.tainted_sinks {
            nonblank("sink_id", &sink.sink_id)?;
            ensure!(
                ids.insert(sink.sink_id.clone()),
                "duplicate sink_id: {}",
                sink.sink_id
            );
            ensure!(
                sink.action == Action::Block,
                "sink {} action must be block",
                sink.sink_id
            );
            metadata(
                &sink.name,
                &sink.description,
                sink.wazuh_rule_level,
                &sink.telemetry_tags,
                &sink.compliance,
            )
            .with_context(|| format!("sink {}", sink.sink_id))?;
            sinks.push(CompiledSink {
                tool_regex: compile(&format!("{}.tool_regex", sink.sink_id), &sink.tool_regex)?,
                arg_regex: compile(&format!("{}.arg_regex", sink.sink_id), &sink.arg_regex)?,
                sink,
            });
        }
        let redact_patterns = policy
            .engine
            .telemetry
            .redact_patterns
            .iter()
            .enumerate()
            .map(|(i, p)| compile(&format!("telemetry.redact_patterns[{i}]"), p))
            .collect::<Result<_>>()?;
        Ok(Self {
            schema_version: policy.schema_version,
            policy_id: policy.policy_id,
            last_updated: policy.last_updated,
            engine: policy.engine,
            taint_policy_enabled: policy.taint_policy.enabled,
            session_ttl_seconds: policy.taint_policy.session_ttl_seconds,
            rules,
            sinks,
            redact_patterns,
        })
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub fn last_updated(&self) -> &str {
        &self.last_updated
    }
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    pub fn taint_policy_enabled(&self) -> bool {
        self.taint_policy_enabled
    }
    pub fn session_ttl_seconds(&self) -> u64 {
        self.session_ttl_seconds
    }
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }
    pub fn sinks(&self) -> &[CompiledSink] {
        &self.sinks
    }
    pub fn redact_patterns(&self) -> &[Regex] {
        &self.redact_patterns
    }
}

fn nonblank(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be blank");
    }
    Ok(())
}

fn metadata(
    name: &str,
    description: &str,
    level: u8,
    tags: &TelemetryTags,
    compliance: &Compliance,
) -> Result<()> {
    nonblank("name", name)?;
    nonblank("description", description)?;
    ensure!(level <= 15, "wazuh_rule_level must be 0..=15");
    nonblank("mitre_atlas_technique", &tags.mitre_atlas_technique)?;
    nonblank("owasp_llm", &tags.owasp_llm)?;
    for (name, values) in [
        ("iso_27001_2022", &compliance.iso_27001_2022),
        ("soc2_type2", &compliance.soc2_type2),
        ("nist_ai_rmf", &compliance.nist_ai_rmf),
        ("eu_ai_act", &compliance.eu_ai_act),
    ] {
        for value in values {
            nonblank(name, value)?;
        }
    }
    Ok(())
}

fn compile(field: &str, pattern: &str) -> Result<Regex> {
    nonblank(field, pattern)?;
    RegexBuilder::new(pattern)
        .backtrack_limit(100_000)
        .build()
        .with_context(|| format!("invalid regex in {field}"))
}

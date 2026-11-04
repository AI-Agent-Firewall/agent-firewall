use agent_firewall_core::{
    policy::{Action, CompiledPolicy, Decision},
    reload::PolicyManager,
};
use std::{
    fs,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const YAML: &str = include_str!("../configs/policy.yaml");

fn fixture(enabled: bool) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let yaml = YAML.replace("watch_interval_ms: 1000", "watch_interval_ms: 20");
    let yaml = if enabled {
        yaml
    } else {
        yaml.replacen(
            "hot_reload:\n    enabled: true",
            "hot_reload:\n    enabled: false",
            1,
        )
    };
    fs::write(&path, yaml).unwrap();
    (dir, path)
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for worker");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn complete_enterprise_contract_and_regexes() {
    let p = CompiledPolicy::from_yaml(YAML).unwrap();
    assert_eq!(p.schema_version(), "1.1.0");
    assert_eq!(p.last_updated(), "2026-10-24T22:50:00Z");
    assert_eq!(p.rules().len(), 5);
    assert_eq!(p.sinks().len(), 2);
    assert!(p.taint_policy_enabled());
    assert_eq!(p.session_ttl_seconds(), 3600);
    assert_eq!(p.engine().default_action, Decision::Allow);
    assert_eq!(p.rules()[1].rule.action, Action::StepUp);
    assert!(p.rules()[1].rule.taint_session);
    assert_eq!(
        p.rules()[0].rule.compliance.iso_27001_2022,
        ["A.8.24", "A.5.15"]
    );
    assert_eq!(
        p.rules()[1].rule.compliance.eu_ai_act,
        ["Article-14", "Article-15"]
    );
    assert_eq!(
        p.sinks()[0].sink.telemetry_tags.mitre_atlas_technique,
        "AML.T0024"
    );
    assert_eq!(p.sinks()[0].sink.compliance.soc2_type2, ["CC6.6", "CC6.1"]);
    assert!(
        p.rules()[0]
            .arg_regex
            .is_match("/home/user/.aws/credentials")
            .unwrap()
    );
    assert!(p.rules()[0].arg_regex.is_match(r"C:\id_rsa").unwrap());
    assert!(
        p.rules()[1]
            .arg_regex
            .is_match("/project/.env.production")
            .unwrap()
    );
    assert!(
        p.rules()[2]
            .arg_regex
            .is_match("/project/configs/policy.yaml")
            .unwrap()
    );
    assert!(p.rules()[3].arg_regex.is_match("sudo whoami").unwrap());
    let net = &p.rules()[4].arg_regex;
    assert!(net.is_match("https://example.com/api").unwrap());
    assert!(!net.is_match("http://localhost/api").unwrap());
    assert!(!net.is_match("http://127.0.0.1/api").unwrap());
    assert!(
        p.redact_patterns()[0]
            .is_match("api_key=abcdefgh123")
            .unwrap()
    );
}

#[test]
fn rejects_missing_invalid_and_unknown_configuration() {
    for invalid in [
        String::new(),
        YAML.replace("schema_version: \"1.1.0\"", "schema_version: \"2.0.0\""),
        YAML.replace("policy_id: \"pol-ent-mcp-prod-001\"\n", ""),
        YAML.replace(
            "enforcement_mode: \"enforcing\"",
            "enforcement_mode: \"disabled\"",
        ),
        YAML.replace("default_action: \"allow\"", "default_action: \"step_up\""),
        YAML.replace("watch_interval_ms: 1000", "watch_interval_ms: 0"),
        YAML.replace("timeout_seconds: 60", "timeout_seconds: 0"),
        YAML.replace("session_ttl_seconds: 3600", "session_ttl_seconds: 0"),
        YAML.replace("2026-10-24T22:50:00Z", "yesterday"),
        YAML.replace("wazuh_rule_level: 13", "wazuh_rule_level: 16"),
        YAML.replace("severity: \"high\"", "severity: \"urgent\""),
        YAML.replace("AGENT_FIREWALL_CI_MODE", "BAD-FLAG"),
        YAML.replace("policy_id: \"pol-ent-mcp-prod-001\"", "policy_id: \"\""),
        YAML.replace("async_flush: true", "async_fluh: true"),
        YAML.replace("    taint_session: false\n", ""),
        YAML.replace("      action: \"block\"", "      action: \"allow\""),
        format!("{YAML}\nunknown_field: true\n"),
    ] {
        assert!(
            CompiledPolicy::from_yaml(&invalid).is_err(),
            "unexpectedly accepted {invalid}"
        );
    }
}

#[test]
fn rejects_duplicate_ids_and_all_regex_locations() {
    for (from, to, expected) in [
        ("RULE-ENV-002", "RULE-CRYPTO-001", "duplicate rule_id"),
        ("SINK-EXEC-002", "SINK-NET-001", "duplicate sink_id"),
        (
            "^(read_file|get_file_contents|cat|head|tail|view_file|write_file|edit_file|bash|sh)$",
            "[",
            "RULE-CRYPTO-001.match.tool_regex",
        ),
        (
            "^(curl|wget|http_request|fetch|websocket_send|mcp_http_.*)$",
            "[",
            "SINK-NET-001.tool_regex",
        ),
        (
            "arg_regex: \".*\"",
            "arg_regex: \"[\"",
            "SINK-NET-001.arg_regex",
        ),
    ] {
        let error = CompiledPolicy::from_yaml(&YAML.replace(from, to)).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
    // Even disabled rules must be valid before publication.
    let invalid = YAML
        .replace("    enabled: true", "    enabled: false")
        .replace("(?i)https?://", "[");
    assert!(CompiledPolicy::from_yaml(&invalid).is_err());
    let start = YAML.find("      - ").unwrap();
    let end = start + YAML[start..].find('\n').unwrap();
    let invalid = format!("{}      - \"[\"{}", &YAML[..start], &YAML[end..]);
    assert!(
        format!("{:#}", CompiledPolicy::from_yaml(&invalid).unwrap_err())
            .contains("redact_patterns[0]")
    );
}

#[test]
fn priorities_are_ascending_and_ties_stable() {
    let p = CompiledPolicy::from_yaml(
        &YAML
            .replace("priority: 10", "priority: 90")
            .replace("priority: 50", "priority: 20"),
    )
    .unwrap();
    let ids: Vec<_> = p.rules().iter().map(|r| r.rule.rule_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "RULE-ENV-002",
            "RULE-NET-005",
            "RULE-IPI-003",
            "RULE-JIT-004",
            "RULE-CRYPTO-001"
        ]
    );
}

#[test]
fn invalid_initial_policy_and_missing_file_refuse_startup() {
    let (_dir, path) = fixture(false);
    fs::write(&path, "invalid: [").unwrap();
    assert!(PolicyManager::start(&path).is_err());
    fs::remove_file(&path).unwrap();
    assert!(PolicyManager::start(&path).is_err());
}

#[test]
fn failed_reload_preserves_snapshot_then_recovers() {
    let (_dir, path) = fixture(false);
    let manager = PolicyManager::start(&path).unwrap();
    let reader = manager.reader();
    let original = reader.snapshot();
    assert!(!manager.reload_now().unwrap());
    for invalid in [b"invalid: [".as_slice(), b"\xff"] {
        fs::write(&path, invalid).unwrap();
        assert!(manager.reload_now().is_err());
        assert!(Arc::ptr_eq(&original, &reader.snapshot()));
    }
    fs::remove_file(&path).unwrap();
    assert!(manager.reload_now().is_err());
    assert!(Arc::ptr_eq(&original, &reader.snapshot()));
    fs::write(&path, YAML.replace("pol-ent-mcp-prod-001", "updated")).unwrap();
    assert!(manager.reload_now().unwrap());
    assert_eq!(reader.snapshot().policy_id(), "updated");
    assert_eq!(original.policy_id(), "pol-ent-mcp-prod-001");
}

#[test]
fn polling_reload_handles_atomic_replace_invalid_update_and_recovery() {
    let (dir, path) = fixture(true);
    let manager = PolicyManager::start(&path).unwrap();
    let reader = manager.reader();
    let original = reader.snapshot();
    fs::write(&path, "invalid: [").unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(Arc::ptr_eq(&original, &reader.snapshot()));
    let replacement = dir.path().join("replacement.yaml");
    fs::write(
        &replacement,
        YAML.replace("pol-ent-mcp-prod-001", "atomic-update"),
    )
    .unwrap();
    fs::rename(&replacement, &path).unwrap();
    wait_until(|| reader.snapshot().policy_id() == "atomic-update");
    assert_eq!(original.policy_id(), "pol-ent-mcp-prod-001");
}

#[test]
fn disabled_reload_and_live_settings_are_respected() {
    let (_dir, path) = fixture(true);
    let manager = PolicyManager::start(&path).unwrap();
    let reader = manager.reader();
    let disabled = YAML
        .replace("pol-ent-mcp-prod-001", "disabled")
        .replacen(
            "hot_reload:\n    enabled: true",
            "hot_reload:\n    enabled: false",
            1,
        )
        .replace("watch_interval_ms: 1000", "watch_interval_ms: 15");
    fs::write(&path, disabled).unwrap();
    wait_until(|| reader.snapshot().policy_id() == "disabled");
    assert_eq!(reader.snapshot().engine().hot_reload.watch_interval_ms, 15);
    fs::write(&path, YAML).unwrap();
    thread::sleep(Duration::from_millis(150));
    assert_eq!(reader.snapshot().policy_id(), "disabled");
    assert!(manager.reload_now().unwrap());
    assert!(reader.snapshot().engine().hot_reload.enabled);
}

#[test]
fn concurrent_readers_see_complete_snapshots() {
    let (_dir, path) = fixture(false);
    let manager = PolicyManager::start(&path).unwrap();
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let reader = manager.reader();
            thread::spawn(move || {
                for _ in 0..1000 {
                    let policy = reader.snapshot();
                    match policy.policy_id() {
                        "pol-ent-mcp-prod-001" => {
                            assert_eq!(policy.engine().default_action, Decision::Allow)
                        }
                        "new-policy" => assert_eq!(policy.engine().default_action, Decision::Block),
                        other => panic!("unexpected snapshot: {other}"),
                    }
                    assert_eq!(policy.rules().len(), 5);
                }
            })
        })
        .collect();
    fs::write(
        &path,
        YAML.replace("pol-ent-mcp-prod-001", "new-policy")
            .replace("default_action: \"allow\"", "default_action: \"block\""),
    )
    .unwrap();
    manager.reload_now().unwrap();
    for reader in readers {
        reader.join().unwrap();
    }
    assert_eq!(manager.reader().snapshot().policy_id(), "new-policy");
}

#[test]
fn cli_rejects_invalid_policy_on_stderr_only() {
    let (_dir, path) = fixture(false);
    fs::write(&path, "invalid: [").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-firewall-core"))
        .arg(path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("initial policy rejected"));
}

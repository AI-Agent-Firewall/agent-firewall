# Agent Firewall Core

Rust policy configuration subsystem for the AI Agent Firewall. It loads the complete enterprise policy schema version `1.1.0`, validates configuration, compiles patterns, and publishes immutable snapshots. This version does not intercept or enforce tool calls.

Run from the project root:

```sh
cargo run -- configs/policy.yaml
```

All diagnostics go to stderr; stdout stays empty. Startup fails with exit status 1 if the initial file cannot be read or validated. Ctrl-C stops and joins the polling worker.

To demonstrate reload without changing the authoritative policy, use a temporary copy:

```sh
cp configs/policy.yaml /tmp/firewall-policy-demo.yaml
cargo run -- /tmp/firewall-policy-demo.yaml
```

In another terminal, change `policy_id` in that copy and save. Within the configured interval (initially one second), stderr prints `policy activated` and the new ID. Save malformed YAML to see a rejection; the last valid snapshot stays active. Fix the copy to resume updates. Atomic file replacement is supported.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The integration tests cover the actual supplied policy, metadata, pattern compilation (including negative lookahead), validation failures, priority ordering, reload failure/recovery, atomic replacement, disabled reload, concurrent readers, and startup stderr behavior.

## Files

- `configs/policy.yaml`: supplied policy values and expressions, with condensed comments and inline compliance lists.
- `src/policy.rs`: complete typed schema, validation, compiled policy snapshots.
- `src/reload.rs`: concurrent reader handle, polling worker, explicit reload and shutdown.
- `src/main.rs`: runnable policy watcher.
- `tests/policy.rs`: integration tests.
- `docs/policy-ingestion.md`: Rust walkthrough and schema decisions.
- `Cargo.toml`, `Cargo.lock`: crate configuration and reproducible dependency versions.

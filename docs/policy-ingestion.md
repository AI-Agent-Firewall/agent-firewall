# Understanding the policy subsystem

## Structs and deserialization

A Rust `struct` groups named fields, much like a YAML mapping. `Policy` contains an `Engine`, a `TaintPolicy`, and a `Vec<Rule>` (a growable list of rules). Nested structs mirror the nested YAML. `String` owns text; `bool` holds true/false; unsigned integers hold counts and priorities.

`#[derive(Deserialize)]` asks Serde to generate the code that fills these structs from parsed input. `serde_saphyr::from_str` reads YAML using that generated code. Every field is required, including fields inside disabled sections. `#[serde(deny_unknown_fields)]` rejects spelling mistakes and unexpected fields instead of silently ignoring them. YAML's `match` is called `matcher` in Rust because `match` is a Rust keyword; `#[serde(rename = "match")]` connects the names.

Enums describe a fixed choice: `Action` can be `Allow`, `Block`, or `StepUp`. Serde accepts their snake_case YAML names. An unsupported string is an error. `Decision` restricts fallback choices to allow/block. Parsing returns a `Result`: either the value (`Ok`) or an explanation (`Err`). The `?` operator passes an error back to the caller.

Parsing is only the first check. Validation checks schema version, timestamps, nonblank strings, positive durations, reload interval bounds, environment flag syntax, unique IDs, Wazuh levels, and sink actions. Compliance frameworks and tags have typed fields; their identifiers are retained verbatim, without claiming to verify regulatory correctness. Empty compliance lists and empty rule/sink lists are accepted as explicit configuration choices.

`CompiledPolicy` has private fields and read-only accessors so it cannot be constructed externally without validation. Each compiled rule and sink retains its complete metadata alongside its patterns. Rules sort by ascending numeric priority; ties keep YAML order. Disabled rules are retained and validated. Redaction expressions are compiled too.

## Regex choice

The supplied network expression contains `(?!...)`, a negative lookahead. The basic Rust `regex` crate rejects that syntax. `fancy-regex` supports it and delegates ordinary patterns to `regex` where possible. Patterns are compiled during candidate loading and reused through snapshots, never compiled by the reader API. The backtracking limit is explicitly 100,000. Future enforcement code must handle `is_match`'s error result as an error, rather than assuming a failed match means permission to proceed. This subsystem does not make access decisions.

Dependencies use maintained `serde-saphyr` (2.1.0) and `fancy-regex` (0.20.0), rather than serde_yaml/serde_yml. Cargo.lock pins the resolved versions. Source documentation: https://docs.rs/serde-saphyr/2.1.0/serde_saphyr/ and https://docs.rs/fancy-regex/0.20.0/fancy_regex/.

## Sharing a consistent policy

`Arc<T>` is a shared owner of a value: cloning an Arc adds an owner without copying all the policy data. The data lives until the last owner releases it.

`RwLock<Arc<CompiledPolicy>>` protects the pointer to the current policy. A reader takes a short read lock, clones the Arc, then releases the lock. The future proxy should call `reader.snapshot()` once per request and use that snapshot for the entire request. It can keep reading the old policy while a reload publishes a new one. It never sees half of each version.

A separate `Mutex` serializes candidate loads. If an explicit reload and the worker both try to load, one waits, preventing stale candidates from overtaking newer ones. Parsing and compilation happen without holding the active-policy write lock. The write lock is held only while replacing the whole snapshot. Poisoned internal locks fail loudly; they do not produce an allow-all fallback.

## Reload lifecycle

1. Startup reads, parses, validates, sorts, and compiles the file synchronously. Any failure prevents the subsystem from starting.
2. A standard Rust thread waits using a condition variable for the active policy's interval. No async runtime or filesystem event dependency is needed.
3. If reload is enabled, it reads and compares actual bytes, so rapid writes and atomic renames are detected without relying on modification timestamps. Unchanged valid content is skipped.
4. A changed candidate goes through the entire load pipeline before publication. Read failures, invalid UTF-8, malformed YAML, missing fields, invalid values, and regex errors leave the existing snapshot intact.
5. A valid candidate replaces the shared Arc. An activation diagnostic reports its ID, timestamp, rule/sink counts, and reload settings. The next wait uses the new interval and enabled flag.
6. Repeated identical errors are reported once until the result changes. Invalid files are retried each enabled interval, so correcting a file recovers automatically.
7. Dropping the manager sets a stop flag, wakes the condition variable, and joins the worker. Existing readers remain usable but no longer receive updates. Shutdown may wait for an in-progress load to finish.

A change that sets `hot_reload.enabled: false` becomes active and stops subsequent automatic loads. Changes to the file cannot then turn polling back on; restart or call `reload_now()` explicitly. This follows the active policy's disable setting. The worker remains interruptible even with a long interval. Polling can observe an intermediate save and reject it temporarily; atomic replacement avoids that window.

## Schema decisions and questions for enforcement

Only schema `1.1.0` is supported. Strict unknown-field rejection makes future schema additions explicit. Reload intervals are constrained to 1..=86,400,000 ms (one day), and timeout/TTL values must be positive. Severity accepts low/medium/high/critical; Wazuh levels accept 0..=15. All current sinks must use block, consistent with the schema's stated immediate-drop behavior. These are loader decisions, not modifications to supplied rules.

The policy does not specify tie behavior; the loader uses stable YAML order for equal priorities. Compliance IDs are opaque strings, and metadata is preserved without asserting that the controls or technique descriptions are correct.

Before enforcement, the team should define exactly what text arg_regex sees (a path, command, individual argument, or serialized JSON). End-anchored path patterns behave differently on those inputs. The network rule excludes URL prefixes such as localhost, so localhost.example.com also falls outside that expression; URL parsing and hostname boundary behavior need a team decision. Expressions and default_action=allow remain as supplied.

Session identity, CI fallback authorization, JIT prompt behavior, mode semantics, and telemetry redaction execution belong to later tasks. Loading this policy does not authorize a CI bypass, open the telemetry path, start a session tracker, or execute any tool.

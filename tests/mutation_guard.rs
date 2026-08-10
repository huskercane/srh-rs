//! Pre-release mutation sweep.
//!
//! A green suite is necessary, not sufficient. Every Phase 5 defect found so far was found by
//! breaking the implementation and watching the suite stay green — including tests that passed
//! against the exact violation they existed to catch, and one regression lock that a later fix
//! silently disarmed. This file turns that manual method into a repeatable gate.
//!
//! It is deliberately NOT part of CI. `.github/workflows/ci.yml` runs
//! `cargo test --all-features`, which skips `#[ignore]`d tests, so the sweep only runs when a
//! human asks for it before cutting a release tag:
//!
//! ```text
//! cargo test --test mutation_guard -- --ignored --nocapture
//! ```
//!
//! The sweep never touches the working tree. It copies the crate (minus `target/` and VCS
//! directories) into `target/mutation-guard/tree`, applies one mutation at a time there, and runs
//! that copy's `cargo test` with its own `CARGO_TARGET_DIR`. Expect about eight minutes once
//! the scratch target directory is warm, and a few more on the first run.
//!
//! ## Adding a mutation
//!
//! Every invariant that has a regression lock should have an entry here. When you add a lock, add
//! the mutation that the lock is supposed to kill, and confirm it is reported `killed`. A
//! mutation whose search text no longer matches exactly once is a hard failure, not a pass: a
//! silent no-op reads as "the invariant is covered" when nothing ran at all.
//!
//! ## Expected survivors
//!
//! Two kinds of mutation are expected to survive, and both must say why in `Expectation`:
//!
//! - `Equivalent` — the mutation does not change behavior, so no test can distinguish it.
//! - `KnownGap` — the mutation changes behavior and nothing catches it. This is a real hole,
//!   recorded rather than hidden.
//!
//! The assertion is set equality, so fixing a `KnownGap` fails this test until the entry is
//! removed. That is intentional: it keeps the recorded gaps honest instead of letting them rot
//! into permanent excuses.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const ACL: &str = "src/domain/acl.rs";
const RATE_LIMIT: &str = "src/domain/rate_limit.rs";
const COMMAND: &str = "src/http/command.rs";
const PIPELINE: &str = "src/http/pipeline.rs";
const MULTI_EXEC: &str = "src/http/multi_exec.rs";
const EXTRACTORS: &str = "src/http/extractors.rs";
const MAIN: &str = "src/main.rs";
const PORTS: &str = "src/ports/mod.rs";
const JWT_AUTH: &str = "src/adapters/jwt_auth.rs";
const HTTP_JWKS: &str = "src/adapters/http_jwks.rs";
const OUTBOUND_HTTP: &str = "src/adapters/outbound_http.rs";
const CONFIG: &str = "src/config.rs";
const COMPAT: &str = "src/domain/compat.rs";
const HEALTH: &str = "src/http/health.rs";
const OBSERVABILITY: &str = "src/http/observability.rs";
const HTTP_MOD: &str = "src/http/mod.rs";
const LOAD_WORKFLOW: &str = ".github/workflows/load.yml";
const MUTATION_WORKFLOW: &str = ".github/workflows/mutation.yml";

/// Directories that must not be copied into the scratch tree. `target` would make the copy
/// enormous and recursive; the rest are editor and VCS state the build never reads.
const SKIP_DIRECTORIES: &[&str] = &["target", ".git", ".idea", ".claude"];

/// This file must not be copied into the scratch tree.
///
/// Its meta-tests read the crate source through `CARGO_MANIFEST_DIR`, which inside the scratch
/// copy resolves to the *mutated* tree. Every mutation would therefore break
/// `every_mutation_search_string_matches_its_target_file_exactly_once` and be reported `killed`
/// — a sweep in which every invariant looks locked because the harness only ever detects itself.
const SELF: &str = "tests/mutation_guard.rs";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expectation {
    /// The suite must fail when this mutation is applied.
    Killed,
    /// The mutation is semantically a no-op; surviving proves nothing is wrong.
    Equivalent(&'static str),
    /// The mutation changes behavior and no test notices. A recorded hole.
    KnownGap(&'static str),
}

/// Resolves the byte range of a file that a mutation is allowed to match inside.
type Region = fn(&str) -> (usize, usize);

struct Mutation {
    name: String,
    file: &'static str,
    find: String,
    replace: String,
    /// Range the search text must match inside, or the whole file when absent. Needed because
    /// the regression locks deliberately repeat production data verbatim, so a whole-file search
    /// would find the constant *and* its own assertion.
    region: Option<Region>,
    expectation: Expectation,
}

impl Mutation {
    /// Applies the mutation, or reports how many times the search text matched when that was not
    /// exactly once. A search string that matches zero or many times is a silent no-op, which
    /// would be reported as a surviving mutation when in fact nothing was tested.
    fn apply(&self, source: &str) -> Result<String, usize> {
        let (start, end) = self
            .region
            .map_or((0, source.len()), |region| region(source));
        let region = &source[start..end];
        match region.matches(&self.find).count() {
            1 => Ok(format!(
                "{}{}{}",
                &source[..start],
                region.replacen(&self.find, &self.replace, 1),
                &source[end..]
            )),
            other => Err(other),
        }
    }
}

fn mutation(
    name: &str,
    file: &'static str,
    find: &str,
    replace: &str,
    expectation: Expectation,
) -> Mutation {
    Mutation {
        name: name.to_owned(),
        file,
        find: find.to_owned(),
        replace: replace.to_owned(),
        region: None,
        expectation,
    }
}

/// Deleting any single `HARD_DENY` entry must fail the suite.
///
/// The regression lock in `acl.rs` repeats all of these as a literal list precisely so that
/// deleting a production entry does not delete its own assertion. An earlier version of that test
/// iterated `HARD_DENY` itself, which made twenty of the entries individually deletable with a
/// green suite. These mutations are what proves the literal list has not drifted back.
///
/// The search text is scoped to the constant's own block: after the fix, `    "CONFIG",` appears
/// both in the constant and in the test literal, and an unscoped replace would silently match
/// neither exactly-once nor the intended site.
fn hard_deny_mutations(root: &Path) -> Vec<Mutation> {
    let source = read(&root.join(ACL));
    let (start, end) = hard_deny_span(&source);
    let block = &source[start..end];
    let names = block
        .split('\n')
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix('"')
                .and_then(|line| line.strip_suffix("\","))
        })
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        names.len() >= 40,
        "HARD_DENY parse found only {} entries; the constant's shape has changed",
        names.len()
    );

    names
        .into_iter()
        .map(|name| Mutation {
            name: format!("hard-deny-drop-{}", name.to_ascii_lowercase()),
            file: ACL,
            find: format!("    \"{name}\",\n"),
            replace: String::new(),
            region: Some(hard_deny_span),
            expectation: Expectation::Killed,
        })
        .collect()
}

/// Byte range of the `HARD_DENY` element list, exclusive of the `&[` and `];` delimiters but
/// inclusive of the final entry's newline, so that every entry is a uniform `    "NAME",\n` line.
fn hard_deny_span(source: &str) -> (usize, usize) {
    const OPEN: &str = "const HARD_DENY: &[&str] = &[\n";
    let start = source
        .find(OPEN)
        .expect("HARD_DENY constant must be present")
        + OPEN.len();
    let end = start
        + source[start..]
            .find("\n];")
            .expect("HARD_DENY constant must be terminated")
        + 1;
    (start, end)
}

fn mutations(root: &Path) -> Vec<Mutation> {
    let mut all = hard_deny_mutations(root);

    // --- domain/acl.rs -------------------------------------------------------------------
    all.push(mutation(
        "acl-name-not-uppercased",
        ACL,
        "        .to_ascii_uppercase();",
        "        .to_owned();",
        Expectation::Killed,
    ));
    all.push(mutation(
        "scripting-allows-evalsha",
        ACL,
        "if !matches!(name, \"EVAL\" | \"EVAL_RO\") || identity.allowed_script_sha256.is_empty() {",
        "if identity.allowed_script_sha256.is_empty() {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "scripting-allows-empty-allowlist",
        ACL,
        "if !matches!(name, \"EVAL\" | \"EVAL_RO\") || identity.allowed_script_sha256.is_empty() {",
        "if !matches!(name, \"EVAL\" | \"EVAL_RO\") {",
        Expectation::Equivalent(
            "the is_empty() short-circuit only skips work: with an empty allowlist the digest \
             membership check below denies every script anyway, so removing the guard cannot \
             change any outcome",
        ),
    ));
    all.push(mutation(
        "scripting-skips-digest-match",
        ACL,
        "    if !identity.allowed_script_sha256.contains(&digest) {\n        return Err(denied(name));\n    }\n",
        "",
        Expectation::Killed,
    ));
    all.push(mutation(
        "xread-block-guard-case-sensitive",
        ACL,
        "argument.eq_ignore_ascii_case(\"BLOCK\")",
        "argument == \"BLOCK\"",
        Expectation::Killed,
    ));
    all.push(mutation(
        "admin-gate-becomes-grant",
        ACL,
        "    let admin_allowed = identity.is_admin && admin_allow(&name, command.get(1));",
        "    let admin_allowed = identity.is_admin && admin_allow(&name, command.get(1));\n    if admin_allowed { return Ok(()); }",
        Expectation::Killed,
    ));
    all.push(mutation(
        "default-block-ignores-legacy",
        ACL,
        "    if !identity.legacy\n        && DEFAULT_BLOCK",
        "    if false\n        && DEFAULT_BLOCK",
        Expectation::Killed,
    ));
    all.push(mutation(
        "blocked-commands-ignored",
        ACL,
        "    if identity.blocked_commands.contains(&name) {\n        return Err(denied(&name));\n    }\n",
        "",
        Expectation::Killed,
    ));
    all.push(mutation(
        "read-only-ignored",
        ACL,
        "    if identity.read_only && !READ_COMMANDS.contains(&name.as_str()) {\n        return Err(denied(&name));\n    }\n",
        "",
        Expectation::Killed,
    ));

    // --- domain/rate_limit.rs ------------------------------------------------------------
    all.push(mutation(
        "rate-refill-uncapped",
        RATE_LIMIT,
        "bucket.balance = (bucket.balance + elapsed * rate as f64).min(capacity);",
        "bucket.balance = bucket.balance + elapsed * rate as f64;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "rate-bound-removed",
        RATE_LIMIT,
        "        if buckets.entries.len() >= self.max_buckets && evict_one(buckets) {\n            self.debt_forgiven_evictions.fetch_add(1, Ordering::Relaxed);\n        }\n",
        "",
        Expectation::Killed,
    ));
    all.push(mutation(
        "evict-prefers-debt",
        RATE_LIMIT,
        "if let Some(candidate) = buckets.credit_lru.pop_first()",
        "if let Some(candidate) = buckets.debt_lru.pop_first()",
        Expectation::Killed,
    ));
    all.push(mutation(
        "rate-no-debt",
        RATE_LIMIT,
        "        let result = if bucket.balance <= 0.0 {\n            Err(self.exceeded(bucket.balance))\n        } else {\n            bucket.balance -= command_count.max(1) as f64;",
        "        let result = if bucket.balance < command_count.max(1) as f64 {\n            Err(self.exceeded(bucket.balance))\n        } else {\n            bucket.balance -= command_count.max(1) as f64;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "rate-sweep-evicts-debt",
        RATE_LIMIT,
        "            if bucket.balance >= 0.0\n                && now",
        "            if true\n                && now",
        Expectation::Killed,
    ));

    // --- http admission order ------------------------------------------------------------
    all.push(mutation(
        "probe-removed",
        EXTRACTORS,
        "        let probe = state\n            .rate_limiter\n            .probe(&identity.bucket_key)\n            .map_err(|error| {\n                metrics::counter!(\"srh_rate_limit_rejections_total\").increment(1);\n                AppError::RateLimited {\n                    retry_after_secs: error.retry_after_secs,\n                }\n            });\n        super::command::record_debt_forgiveness(state);\n        probe?;\n",
        "",
        Expectation::Killed,
    ));
    all.push(mutation(
        "single-acl-after-acquire",
        COMMAND,
        "    crate::domain::acl::check(&identity.0, &values)?;\n    let command = crate::domain::compat::normalize(json_args_to_redis(&values)?);\n    let handle = state\n        .provider\n        .acquire(&identity.0.pool)\n        .await\n        .map_err(|error| map_acquire_error(error, &state))?;",
        "    let command = crate::domain::compat::normalize(json_args_to_redis(&values)?);\n    let handle = state\n        .provider\n        .acquire(&identity.0.pool)\n        .await\n        .map_err(|error| map_acquire_error(error, &state))?;\n    crate::domain::acl::check(&identity.0, &values)?;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "multi-exec-acl-removed",
        MULTI_EXEC,
        "    for command in &values {\n        crate::domain::acl::check(&identity.0, command)?;\n    }\n",
        "",
        Expectation::Killed,
    ));
    all.push(mutation(
        "multi-exec-runtime-error-result-dropped",
        MULTI_EXEC,
        "            Err(ExecError::Redis(message)) => Ok(json!({ \"error\": message })),",
        "            Err(ExecError::Redis(message)) => Ok(json!({ \"result\": message })),",
        Expectation::Killed,
    ));
    all.push(mutation(
        "pipeline-sends-denied",
        PIPELINE,
        "            Err(crate::domain::acl::AclError::Forbidden(message)) => {\n                slots.push(Some(json!({ \"error\": message })));\n            }",
        "            Err(crate::domain::acl::AclError::Forbidden(_)) => {\n                allowed_commands.push(json_args_to_redis(command)?);\n                slots.push(None);\n            }",
        Expectation::Killed,
    ));
    all.push(mutation(
        "pipeline-acquires-when-all-denied",
        PIPELINE,
        "    let results = if allowed_commands.is_empty() {",
        "    let results = if false {",
        Expectation::Killed,
    ));

    // --- rate-limit charging -------------------------------------------------------------
    all.push(mutation(
        "single-charge-removed",
        COMMAND,
        "    audit.command(values.first().and_then(serde_json::Value::as_str), 1);\n    charge_rate_limit(&state, &identity.0.bucket_key, 1)?;\n    crate::domain::acl::check",
        "    audit.command(values.first().and_then(serde_json::Value::as_str), 1);\n    crate::domain::acl::check",
        Expectation::Killed,
    ));
    all.push(mutation(
        "multi-exec-charge-is-one",
        MULTI_EXEC,
        "charge_rate_limit(&state, &identity.0.bucket_key, values.len())?;",
        "charge_rate_limit(&state, &identity.0.bucket_key, 1)?;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "empty-multiexec-charge-removed",
        MULTI_EXEC,
        "    if values.is_empty() {\n        charge_rate_limit(&state, &identity.0.bucket_key, 1)?;\n",
        "    if values.is_empty() {\n",
        Expectation::Killed,
    ));
    for (name, file) in [
        ("malformed-charge-removed-single", COMMAND),
        ("malformed-charge-removed-pipeline", PIPELINE),
        ("malformed-charge-removed-multiexec", MULTI_EXEC),
    ] {
        all.push(mutation(
            name,
            file,
            "            charge_rate_limit(&state, &identity.0.bucket_key, 1)?;\n            return Err(match error {",
            "            return Err(match error {",
            Expectation::Killed,
        ));
    }

    // --- pool lease ownership ------------------------------------------------------------
    all.push(mutation(
        "release-boundary-noop-single",
        PORTS,
        "        let result = self.executor.execute(command).await;\n        drop(self);\n        result",
        "        let result = self.executor.execute(command).await;\n        std::mem::forget(self);\n        result",
        Expectation::Killed,
    ));
    all.push(mutation(
        "release-boundary-noop-pipeline",
        PORTS,
        "        let results = self.executor.pipeline(commands).await;\n        drop(self);\n        results",
        "        let results = self.executor.pipeline(commands).await;\n        std::mem::forget(self);\n        results",
        Expectation::Killed,
    ));
    all.push(mutation(
        "release-boundary-noop-multiexec",
        PORTS,
        "        let results = self.executor.transaction(commands).await;\n        drop(self);\n        results",
        "        let results = self.executor.transaction(commands).await;\n        std::mem::forget(self);\n        results",
        Expectation::Killed,
    ));
    all.push(mutation(
        "handler-borrows-lease-single",
        COMMAND,
        "        .execute_and_release(command)",
        "        .executor().execute(command)",
        Expectation::Killed,
    ));
    all.push(mutation(
        "handler-borrows-lease-pipeline",
        PIPELINE,
        "        handle.pipeline_and_release(allowed_commands).await",
        "        handle.executor().pipeline(allowed_commands).await",
        Expectation::Killed,
    ));
    all.push(mutation(
        "handler-borrows-lease-multiexec",
        MULTI_EXEC,
        "        .transaction_and_release(commands)",
        "        .executor().transaction(commands)",
        Expectation::Killed,
    ));

    // --- background maintenance ------------------------------------------------------------
    all.push(mutation(
        "maintenance-sweep-removed",
        MAIN,
        "                let limiter = Arc::clone(&rate_limiter);\n                match tokio::task::spawn_blocking(move || limiter.sweep_idle()).await {\n                    Ok(evicted) if evicted > 0 => tracing::info!(evicted, \"evicted idle rate-limit buckets\"),\n                    Ok(_) => {}\n                    Err(error) => tracing::error!(%error, \"rate-limit maintenance failed\"),\n                }\n",
        "",
        Expectation::Killed,
    ));

    // --- Phase 6 JWT, JWKS, and outbound HTTP --------------------------------------------
    all.push(mutation(
        "jwt-format-recognition-removed",
        JWT_AUTH,
        "        if bearer.bytes().filter(|byte| *byte == b'.').count() != 2",
        "        if bearer.bytes().filter(|byte| *byte == b'.').count() == 2",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-malformed-header-claimed",
        JWT_AUTH,
        "            return if has_json_header(bearer) {",
        "            return if true {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-json-header-falls-through",
        JWT_AUTH,
        "            return if has_json_header(bearer) {",
        "            return if false {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-trusts-header-algorithm",
        JWT_AUTH,
        "        let algorithm = algorithm(cached.algorithm);",
        "        let algorithm = header.alg;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-nbf-validation-disabled",
        JWT_AUTH,
        "        validation.validate_nbf = true;",
        "        validation.validate_nbf = false;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-unknown-kid-becomes-outage",
        JWT_AUTH,
        "crate::domain::identity::JwksError::NotFound => AuthError::Rejected,",
        "crate::domain::identity::JwksError::NotFound => AuthError::ServiceUnavailable(\"missing key\".to_owned()),",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-azp-fallback-removed",
        JWT_AUTH,
        "            || (!claims.aud.contains(&self.config.audience)\n                && claims.azp.as_deref() != Some(self.config.audience.as_str()))",
        "            || !claims.aud.contains(&self.config.audience)",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-token-type-ignored",
        JWT_AUTH,
        "        if claims.typ != \"Bearer\"",
        "        if false",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-no-role-becomes-write",
        JWT_AUTH,
        "            return Err(AuthError::Forbidden(\"NOPERM no redis role\".to_owned()));",
        "            (false, false)",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-admin-role-ignored",
        JWT_AUTH,
        "        let (read_only, is_admin) = if role(\"admin\") {",
        "        let (read_only, is_admin) = if false {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-default-pool-changed",
        JWT_AUTH,
        "        let pool = claims.srh_pool.unwrap_or_else(|| \"default\".to_owned());",
        "        let pool = claims.srh_pool.unwrap_or_else(|| \"missing\".to_owned());",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-pool-script-policy-dropped",
        JWT_AUTH,
        "            allowed_script_sha256: allowed_script_sha256.clone(),",
        "            allowed_script_sha256: HashSet::new(),",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-inactive-introspection-accepted",
        JWT_AUTH,
        "            if !active {",
        "            if false {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-introspection-cache-bypassed",
        JWT_AUTH,
        "            let active = if let Some(active) = self.introspection_cache.get(&digest) {",
        "            let active = if let Some(active) = None {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwt-introspection-cache-bound-changed",
        JWT_AUTH,
        "const MAX_INTROSPECTION_ENTRIES: usize = 100_000;",
        "const MAX_INTROSPECTION_ENTRIES: usize = 200_000;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwks-signing-use-filter-reversed",
        HTTP_JWKS,
        "!matches!(usage, PublicKeyUse::Signature)",
        "matches!(usage, PublicKeyUse::Signature)",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwks-unknown-kid-refetch-removed",
        HTTP_JWKS,
        "        self.refresh(true).await?;",
        "        self.refresh(false).await?;",
        Expectation::Killed,
    ));
    all.push(mutation(
        "jwks-forced-refresh-throttle-removed",
        HTTP_JWKS,
        "            self.cache.write().await.last_forced_refresh = Some(now);\n",
        "",
        Expectation::Killed,
    ));
    all.push(mutation(
        "outbound-response-limit-removed",
        OUTBOUND_HTTP,
        "        Limited::new(response.into_body(), max_response_bytes)",
        "        Limited::new(response.into_body(), usize::MAX)",
        Expectation::Killed,
    ));
    all.push(mutation(
        "auth-forbidden-becomes-unauthorized",
        EXTRACTORS,
        "                AuthError::Forbidden(reason) => {\n                    metrics::counter!(\"srh_auth_failures_total\", \"kind\" => \"forbidden\")\n                        .increment(1);\n                    AppError::Forbidden(reason)\n                }",
        "                AuthError::Forbidden(_) => {\n                    metrics::counter!(\"srh_auth_failures_total\", \"kind\" => \"forbidden\")\n                        .increment(1);\n                    AppError::Unauthorized\n                }",
        Expectation::Killed,
    ));
    all.push(mutation(
        "main-omits-jwt-auth-link",
        MAIN,
        "Arc::new(AuthChain::new(vec![jwt_link, static_auth]))",
        "Arc::new(AuthChain::new(vec![static_auth]))",
        Expectation::Killed,
    ));
    all.push(mutation(
        "main-introspection-sweep-removed",
        MAIN,
        "move || jwt.sweep_introspection_cache()",
        "move || 0",
        Expectation::Killed,
    ));

    // --- Phase 7 observability, readiness, and parity compatibility ---------------------
    all.push(mutation(
        "env-mode-loses-legacy-policy",
        CONFIG,
        "static_tokens.insert(digest, default_token(\"default\", true));",
        "static_tokens.insert(digest, default_token(\"default\", false));",
        Expectation::Killed,
    ));
    all.push(mutation(
        "geodist-unit-normalization-removed",
        COMPAT,
        "    if command.name == \"GEODIST\"\n        && command.args.len() == 4\n        && let Some(unit) = command.args.last_mut()",
        "    if false\n        && command.args.len() == 4\n        && let Some(unit) = command.args.last_mut()",
        Expectation::Killed,
    ));
    all.push(mutation(
        "geodist-arity-guard-removed",
        COMPAT,
        "        && command.args.len() == 4",
        "        && true",
        Expectation::Killed,
    ));
    all.push(mutation(
        "readiness-loopback-gate-removed",
        HEALTH,
        "    if !peer.ip().is_loopback() {",
        "    if false {",
        Expectation::Killed,
    ));
    all.push(mutation(
        "readiness-skips-real-provider-check",
        HEALTH,
        "        .readiness()\n        .await",
        "        .readiness()\n        .await.into_iter().take(0).collect::<Vec<_>>()",
        Expectation::Killed,
    ));
    all.push(mutation(
        "audit-subject-omitted",
        OBSERVABILITY,
        "        subject = fields.subject.as_deref().unwrap_or(\"-\"),",
        "        subject = \"-\",",
        Expectation::Killed,
    ));
    all.push(mutation(
        "endpoint-label-cardinality-unbounded",
        OBSERVABILITY,
        "        _ => \"other\",",
        "        _ => \"/\",",
        Expectation::Killed,
    ));
    all.push(mutation(
        "http-request-metric-unregistered",
        OBSERVABILITY,
        "metrics::counter!(\"srh_http_requests_total\", \"endpoint\" => \"-\", \"status\" => \"-\")",
        "metrics::counter!(\"srh_http_requests_total_broken\", \"endpoint\" => \"-\", \"status\" => \"-\")",
        Expectation::Killed,
    ));
    all.push(mutation(
        "main-omits-peer-connect-info",
        MAIN,
        "app.clone().layer(Extension(ConnectInfo(peer)))",
        "app.clone()",
        Expectation::Killed,
    ));

    // --- Phase 9 bend-not-break verification ------------------------------------------
    all.push(mutation(
        "rate-debt-forgiveness-unreported",
        RATE_LIMIT,
        "self.debt_forgiven_evictions.fetch_add(1, Ordering::Relaxed);",
        "self.debt_forgiven_evictions.fetch_add(0, Ordering::Relaxed);",
        Expectation::Killed,
    ));
    all.push(mutation(
        "backend-timeout-becomes-500",
        COMMAND,
        "        ExecError::Timeout => AppError::PoolOpen {\n            retry_after_secs: state.cfg.server.load.shed_retry_after_secs,\n            reason: \"Redis command timed out\".to_owned(),\n        },",
        "        ExecError::Timeout => AppError::Internal(\"Redis command timed out\".to_owned()),",
        Expectation::Killed,
    ));
    all.push(mutation(
        "trace-layer-amplifies-shed-logs",
        HTTP_MOD,
        "TraceLayer::new_for_http().on_failure(())",
        "TraceLayer::new_for_http()",
        Expectation::Killed,
    ));
    all.push(mutation(
        "tcp-nodelay-disabled",
        MAIN,
        "stream.set_nodelay(true)",
        "stream.set_nodelay(false)",
        Expectation::Killed,
    ));
    all.push(mutation(
        "debt-forgiveness-shed-cause-unregistered",
        OBSERVABILITY,
        "        \"debt_forgiven_by_eviction\",",
        "        \"debt_forgiven_by_eviction_broken\",",
        Expectation::Killed,
    ));
    all.push(mutation(
        "nightly-load-schedule-removed",
        LOAD_WORKFLOW,
        "  schedule:\n    - cron: \"17 5 * * *\"",
        "  schedule_broken:\n    - cron: \"17 5 * * *\"",
        Expectation::Killed,
    ));
    all.push(mutation(
        "scheduled-mutation-sweep-removed",
        MUTATION_WORKFLOW,
        "        run: cargo test --test mutation_guard -- --ignored --nocapture",
        "        run: cargo test --test mutation_guard",
        Expectation::Killed,
    ));

    all
}

#[test]
#[ignore = "pre-release mutation sweep: rewrites a scratch copy of the crate and runs the suite \
            once per mutation (~15 min warm, needs no Docker). Ordinary CI runs plain `cargo \
            test`, which skips this; a scheduled workflow runs it weekly. Run with: cargo test \
            --test mutation_guard -- --ignored --nocapture"]
fn every_locked_invariant_fails_the_suite_when_it_is_broken() {
    let root = crate_root();
    let scratch = root.join("target/mutation-guard/tree");
    let scratch_target = root.join("target/mutation-guard/target");
    let mutations = mutations(&root);

    copy_crate(&root, &scratch);
    assert!(
        run_suite(&scratch, &scratch_target),
        "the unmutated scratch copy must pass before any mutation is meaningful"
    );

    let mut survivors = BTreeMap::new();
    for (index, mutation) in mutations.iter().enumerate() {
        let pristine = read(&root.join(mutation.file));
        let mutated = mutation.apply(&pristine).unwrap_or_else(|occurrences| {
            panic!(
                "mutation `{}` matches {occurrences} times in {} (expected exactly 1); \
                 update its search text rather than letting it silently do nothing",
                mutation.name, mutation.file
            )
        });

        let target = scratch.join(mutation.file);
        write(&target, &mutated);
        let passed = run_suite(&scratch, &scratch_target);
        write(&target, &pristine);

        let verdict = if passed { "SURVIVED" } else { "killed" };
        println!(
            "[{:>3}/{}] {:<42} {verdict}",
            index + 1,
            mutations.len(),
            mutation.name
        );
        if passed {
            survivors.insert(mutation.name.clone(), mutation.expectation);
        }
    }

    let expected = mutations
        .iter()
        .filter(|mutation| mutation.expectation != Expectation::Killed)
        .map(|mutation| mutation.name.clone())
        .collect::<Vec<_>>();
    let actual = survivors.keys().cloned().collect::<Vec<_>>();

    let unexpected = actual
        .iter()
        .filter(|name| !expected.contains(name))
        .cloned()
        .collect::<Vec<_>>();
    let newly_killed = expected
        .iter()
        .filter(|name| !actual.contains(name))
        .cloned()
        .collect::<Vec<_>>();

    for (name, expectation) in &survivors {
        if let Expectation::KnownGap(reason) = expectation {
            println!("KNOWN GAP  {name}: {reason}");
        }
    }

    assert!(
        unexpected.is_empty(),
        "these mutations were not caught by any test, and are not recorded as expected \
         survivors: {unexpected:?}. Either add the missing regression lock, or record the \
         mutation as Equivalent/KnownGap with a reason."
    );
    assert!(
        newly_killed.is_empty(),
        "these mutations are recorded as expected survivors but are now killed: \
         {newly_killed:?}. If the gap was fixed, delete the entry so the record stays honest."
    );
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

fn write(path: &Path, contents: &str) {
    fs::write(path, contents)
        .unwrap_or_else(|error| panic!("{} must be writable: {error}", path.display()));
}

fn copy_crate(source: &Path, destination: &Path) {
    if destination.exists() {
        fs::remove_dir_all(destination).expect("previous scratch tree must be removable");
    }
    copy_tree(source, destination, &PathBuf::new());
    assert!(
        !destination.join(SELF).exists(),
        "the scratch tree must not contain {SELF}; see the constant's documentation"
    );
}

fn copy_tree(source: &Path, destination: &Path, relative: &Path) {
    fs::create_dir_all(destination).expect("scratch directory must be creatable");
    for entry in fs::read_dir(source).expect("source directory must be readable") {
        let entry = entry.expect("source entry must be readable");
        let name = entry.file_name();
        let relative = relative.join(&name);
        if entry.path().is_dir() {
            if SKIP_DIRECTORIES.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            copy_tree(&entry.path(), &destination.join(&name), &relative);
        } else if !is_transient(&name) && relative != Path::new(SELF) {
            fs::copy(entry.path(), destination.join(&name)).expect("file must be copyable");
        }
    }
}

/// Editor swap files and the like; copying them is harmless but noisy.
fn is_transient(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    name.ends_with('~') || name.starts_with(".#")
}

/// Runs the scratch copy's default-feature suite. Default features keep the sweep Docker-free:
/// the `testcontainers` suites only compile tests under `--all-features`, and re-running Redis
/// containers once per mutation would dominate the runtime without covering more domain logic.
fn run_suite(directory: &Path, target_directory: &Path) -> bool {
    let output = Command::new(env!("CARGO"))
        .args(["test", "--quiet"])
        .current_dir(directory)
        .env("CARGO_TARGET_DIR", target_directory)
        // The outer `cargo test` publishes a jobserver; letting the inner build join it makes the
        // sweep contend with the process that launched it.
        .env_remove("CARGO_MAKEFLAGS")
        .output()
        .expect("nested cargo invocation must start");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !compilation_failed(&combined),
        "the mutated tree failed to compile, which is not a meaningful result:\n{combined}"
    );
    output.status.success()
}

/// A mutation that does not compile proves nothing, so it must be distinguished from a kill.
/// Cargo prints `error: test failed` for an ordinary failing test, which is *not* a compile
/// error — matching on a bare `error:` prefix would misreport every kill as a build break.
fn compilation_failed(output: &str) -> bool {
    output.lines().any(|line| {
        (line.starts_with("error[E") && line.contains(']'))
            || line.starts_with("error: cannot")
            || line.starts_with("error: expected")
            || line.starts_with("error: unexpected")
            || line.starts_with("error: mismatched")
            || line.starts_with("error: no method")
            || line.starts_with("error: no rules")
            || line.starts_with("error: this function")
            || line.starts_with("error: could not compile")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mutation_search_string_matches_its_target_file_exactly_once() {
        let root = crate_root();
        for mutation in mutations(&root) {
            let source = read(&root.join(mutation.file));
            let mutated = mutation.apply(&source).unwrap_or_else(|occurrences| {
                panic!(
                    "mutation `{}` matches {} {occurrences} times, expected exactly once",
                    mutation.name, mutation.file
                )
            });
            assert_ne!(
                mutated, source,
                "mutation `{}` must actually change something",
                mutation.name
            );
        }
    }

    #[test]
    fn every_hard_deny_entry_has_its_own_mutation() {
        let root = crate_root();
        let source = read(&root.join(ACL));
        let (start, end) = hard_deny_span(&source);
        let entries = source[start..end]
            .lines()
            .filter(|line| line.trim_start().starts_with('"'))
            .count();
        assert_eq!(
            hard_deny_mutations(&root).len(),
            entries,
            "the generated mutation set must cover every HARD_DENY entry"
        );
    }

    /// The reason `Mutation::region` exists. `acl.rs` intentionally repeats every `HARD_DENY`
    /// entry in the regression lock's literal list, so an unscoped search matches twice and the
    /// mutation would quietly do nothing — which is indistinguishable from "the invariant is
    /// covered" unless the harness insists on exactly one match.
    #[test]
    fn hard_deny_mutations_would_be_ambiguous_without_their_region() {
        let root = crate_root();
        let source = read(&root.join(ACL));
        let mutations = hard_deny_mutations(&root);
        let unscoped = mutations
            .iter()
            .filter(|mutation| source.matches(&mutation.find).count() != 1)
            .count();
        assert_eq!(
            unscoped,
            mutations.len(),
            "every HARD_DENY entry must appear both in the constant and in the literal list \
             asserted by `hard_denies_have_no_non_admin_escape_hatch`"
        );
        for mutation in &mutations {
            assert!(mutation.apply(&source).is_ok(), "{}", mutation.name);
        }
    }

    #[test]
    fn expected_survivors_all_carry_a_reason() {
        let root = crate_root();
        for mutation in mutations(&root) {
            match mutation.expectation {
                Expectation::Killed => {}
                Expectation::Equivalent(reason) | Expectation::KnownGap(reason) => assert!(
                    reason.len() > 40,
                    "expected survivor `{}` needs a real explanation",
                    mutation.name
                ),
            }
        }
    }

    #[test]
    fn known_gap_expectation_remains_available_when_a_real_hole_is_recorded() {
        let expectation = Expectation::KnownGap(
            "a real behavior-changing survivor must carry a durable explanation here",
        );
        assert!(matches!(expectation, Expectation::KnownGap(_)));
    }

    /// If this file is renamed and `SELF` is not updated, the exclusion silently stops working
    /// and every mutation is reported `killed` because the harness detects only itself.
    #[test]
    fn the_self_exclusion_path_still_names_this_file() {
        assert_eq!(SELF, file!());
        assert!(crate_root().join(SELF).is_file());
    }

    #[test]
    fn ordinary_test_failures_are_not_misread_as_compilation_failures() {
        assert!(!compilation_failed(
            "test result: FAILED. 3 passed; 1 failed\nerror: test failed, to rerun pass `--lib`"
        ));
        assert!(compilation_failed(
            "error[E0308]: mismatched types\nerror: could not compile `srh-rs`"
        ));
    }
}

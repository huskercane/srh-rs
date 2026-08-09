# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`srh-rs` is a Rust rewrite of [hiett/serverless-redis-http](https://github.com/hiett/serverless-redis-http):
an Upstash-compatible Redis HTTP proxy with hardened security (Keycloak JWT auth,
Redis-side ACL enforcement, read-only tokens, command ACLs, script allowlisting, rate
limiting, circuit breaking).

**Wire compatibility with the `@upstash/redis` JavaScript SDK is the top-level
requirement.** Where the spec says "exactly", match exactly — including the deliberate
divergences in §1.7 that must NOT be "fixed".

It is its own git repository (currently with no remote), sitting under `~/work/whiskerwatch/`
because WhiskerWatch's NextAuth `@auth/upstash-redis-adapter` is the first consumer,
talking to the auth-session Redis under a single `ww:auth:` key root. The parent
`~/work/whiskerwatch/CLAUDE.md` will also load; its per-service rules (api/ml-service/
ios/android/webui) do not apply here, though its general engineering rules do.

## `srh-rust-spec.md` is normative

`srh-rust-spec.md` (untracked, in the repo root) is the source of truth, not a sketch.
Before writing code:

- **Work through phases IN ORDER.** Each phase has acceptance criteria; do not start the
  next until they pass. Phase 8 (key-prefix isolation) is explicitly OUT of the first
  delivery — build 1–7 and 9, ship, then reconsider.
- **Do not invent features not in the spec.** It has an explicit Non-goals list (path-based
  commands, token-in-query-param, RESP3, pub/sub, cluster routing, web UI, config hot-reload).
- **Verify every dependency API name against docs.rs for the version in `Cargo.lock`.**
  The spec's type names are indicative and known to drift — e.g. fred 10 uses
  `fred::types::Value`, `fred::clients::Pool`, `fred::clients::Client`, not the older
  `RedisValue`/`RedisPool`/`RedisClient`.

Repo conventions (commands, commit style, PR expectations) live in `AGENTS.md`. The README
tracks implementation status; Phases 5–7 add operational guidance such as the
timeout/rate sizing rules, Layer B ACL provisioning, and deployment checklist.

## Commands

```bash
cargo build
cargo test                                                # incl. tests/dependency_rule.rs
cargo test --features testsupport                         # exposes the hand-written fakes
cargo test --test dependency_rule                          # single integration test file
cargo test --lib ports::                                   # single unit-test module
cargo test --lib -- --nocapture executor_handle_owns        # single test by name substring
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings   # -D warnings is the gate
```

The toolchain is pinned to Rust 1.97 by `rust-toolchain.toml`. Integration tests use
`testcontainers` (Redis) and `wiremock` (JWKS/introspection), so a working Docker daemon is
needed from Phase 2 onward.

## Architecture

Ports and adapters. The layout is `src/{domain,ports,adapters,http,testsupport}` with
`main.rs` as the composition root — but the file tree is the least important part. These
are the rules that require reading several files to reconstruct:

### The dependency rule

`domain/` imports only std, `serde_json`, `bytes`, `base64`, `sha2`, and `ports/` types — never fred,
axum, tower, hyper, or reqwest (tokio sync primitives such as `Semaphore` and atomics are
allowed; tokio I/O is not). `ports/` imports only domain types. `adapters/` and `http/` may
import anything. **`main.rs` is the only place a concrete adapter type is named outside its
own module.**

`tests/dependency_rule.rs` enforces this for imports and fully-qualified paths while ignoring
comments and Rust string/character literals. Treat a green run as necessary, not sufficient;
the single-crate layout cannot make the dependency boundary compiler-enforced. `reqwest` stays
in its forbidden list even though the crate is gone — the entry is now a tripwire against
reintroduction (see below).

### HTTP clients use hyper — never add reqwest

Outbound HTTP uses `hyper` directly, which is already a dependency for the inbound listener.
Do not add `reqwest` back, in this repo or elsewhere in Rust work here. Phase 6 (JWKS and
token introspection) is the only phase needing a client; it adds `hyper/client`,
`hyper-util` (`client`, `client-legacy` for pooling), `hyper-rustls`, and `http-body-util`
**at that point**, not in advance — an unused dependency carried across phases is exactly
how the rustls dual-provider panic got in.

Pair `hyper-rustls` with `rustls-native-certs`, not `webpki-roots`. fred already trusts the
OS store, and a client on bundled Mozilla roots fails against a Keycloak behind an internal
CA with an unknown-issuer error that installing the CA system-wide does not fix.

For URL parsing alone use the `url` crate (`config.rs` validates `auth.jwt.issuer` with it);
never pull an HTTP client to parse a string.

### Exactly six ports

Five async + the sync `Clock`, all in `ports/mod.rs`: `CommandExecutor`, `ExecutorProvider`,
`Authenticator`, `JwksSource`, `Introspector`, `Clock`. Adding a seventh requires written
justification in the PR. Keep them small (ISP) — no `RedisPort` god-trait, no methods added
"while you're in there".

All async ports use `async_trait`: native `async fn` in traits is not dyn-compatible and the
wiring is `Arc<dyn Port>` throughout. Do not attempt `Arc<dyn Trait>` with native async trait
methods. Use `Arc<dyn _>`, never generic type parameters, so no type parameters propagate
through the handler stack.

### Extension is by decorator, not modification

Cross-cutting `CommandExecutor` behavior is added by wrapping (`breaker_executor.rs`, and
optionally a metrics decorator in Phase 7) — never by editing `fred_executor.rs`. New auth
methods are new `Authenticator` impls appended to the chain; `auth_chain.rs` itself never
changes. Phase 6 flips auth from `[StaticAuth]` to `[JwtAuth, StaticAuth]` by changing one
line in `main.rs`.

Chain semantics matter: `Ok(None)` means "not my token format, try the next link";
`Err` is a definitive rejection that must NOT fall through (a JWT failing signature
verification must never be retried as a static token).

### Fakes are held to the same contract as real adapters

`testsupport/` exposes `executor_contract(executor: Arc<dyn CommandExecutor>)`,
exercising raw-error passthrough, pipeline-never-aborts, transaction atomicity, and nil
handling. The same suite runs against `FredExecutor` (testcontainers) and `FakeExecutor`
(unit tests) — that is what makes fake-based unit tests trustworthy. Fakes are hand-written;
do not add a mocking framework.

### Anti-over-engineering guardrails (equally normative)

Do not abstract axum, tower, serde, tracing, or the metrics crate behind ports — they are
the application, not the domain's collaborators. No port for config, logging, or time
formatting. Any `if` in an HTTP handler about commands, permissions, or encodings is a review
defect; those rules belong in `domain/`.

## Invariants that are easy to break

**Base64 encoding is a conversion input, not a post-pass.** `Upstash-Encoding: base64` must be
threaded into `redis_value_to_json` so bulk values encode from the ORIGINAL raw bytes. A
post-pass over the finished JSON would base64 the lossy-UTF-8 string and destroy the exact
bytes the encoding exists to preserve. Lossy conversion applies only in non-encoded mode.

**Redis errors pass through verbatim.** Clients pattern-match them; never rewrite. Single
command → 400 with the raw error including its prefix. Pipelines are always HTTP 200 with
per-slot `{"result"}`/`{"error"}` — the one exception is `ResponseTooLarge`, which fails the
whole request with 502 on every endpoint.

**Command timeouts are enforced inside fred, never by dropping the response future.**
Dropping a future mid-command leaves an unconsumed RESP reply on a pooled connection and every
later command on it reads the wrong reply. Fred 10 does not always reset a responsive blocked
socket after its caller timeout, so `FredExecutor` explicitly forces reconnection when Fred
reports `ErrorKind::Timeout`, coalesced to one reset per request executor even when many
pipeline slots time out together. The tower `TimeoutLayer` is an HTTP backstop only.
Startup must validate
`acquire_timeout_ms + 2 * command_timeout_ms < http_timeout_ms` for every pool: the second
command-timeout budget covers the bounded forced reset after a Fred timeout.

**The breaker is checked before any permit or waiter slot is taken**, in
`PoolManager::acquire`, not in the decorator (the decorator only records outcomes). An open
circuit must consume no permits, or a dead backend still starves the pool. It counts
`ExecError::Transport`/`Timeout` only — `Redis(_)` is a healthy backend saying no.

**Rate limiting is per COMMAND with debt.** A request costs `max(1, n)` tokens; balances may
go negative; a request is admitted whenever the balance is positive before charging; rejected
requests are not charged. Without debt, any pipeline larger than the bucket capacity would be a
permanent 429 — and the SDK auto-batches, so that fires in normal use. Bucket key is the FULL
credential (whole token digest / whole `sub`), never `identity.subject`, which is only an
8-hex-char log label.

**Health endpoints live outside the admission stack.** The three API routes go in a "limited"
router wrapped in load-shed/concurrency-limit/timeout/body-limit; `/health` and `/ready` are
merged in afterward so they are never shed or queued behind API traffic.

**Pool permits are acquired only after the body is fully read and parsed.** A slow-trickled
body must never hold a Redis permit.

## Security model

- **Layer A (proxy ACL) is defense-in-depth; Layer B (Redis-side ACL user per pool) is the
  boundary that actually holds**, because Lua `redis.call` runs under the connection's Redis
  user. Make Layer B easy and Layer A strict enough that Layer B is rarely reached.
- **Claims may only narrow.** `srh_blocked_commands` (narrowing) may come from a JWT.
  Script allowlists (widening) come from server config only — per static token or per pool —
  because a widening claim sourced from a user-editable Keycloak attribute is self-service
  privilege escalation. `srh_pool` must come from an admin-controlled protocol mapper.
- **`HARD_DENY` has no escape hatch.** `is_admin` gets a bounded, explicit `ADMIN_ALLOW`
  allowlist checked subcommand-aware BEFORE the deny list — and it is a **gate, not a grant**:
  passing it still runs the remaining rules, so a narrowing claim applies even to admin commands.
  An exemption-with-carve-outs shape would make every future Redis command admin-allowed by default.
- **The implicit default-block set keys on `!identity.legacy`, not on token format.** JWT
  identities get the same `FLUSHALL/FLUSHDB/KEYS/RANDOMKEY/INFO/DBSIZE` block as new-format
  static tokens; only legacy-format tokens are exempt, for original-SRH parity.
- **Tokens exist only as 32-byte digests.** Plaintext keys in config are hashed at load and
  dropped; auth is a uniform digest lookup with no plaintext comparison and no length leak.
- **JWT algorithm comes from the JWK, never from the token header** (closes alg-confusion,
  `none`, and HS256-with-public-key). Skip JWKs whose `use`/`key_ops` are not for signing —
  Keycloak publishes RSA encryption keys in the same JWKS.
- **Never log** tokens, JWTs, connection strings, command arguments, or `Upstash-Telemetry-*`
  headers. Secrets live in a newtype whose `Debug` prints `<redacted>` and which zeroizes on drop.

## Global engineering rules (from the spec)

- No `unwrap()`/`expect()` outside tests and startup validation. All handlers return
  `Result<_, AppError>`. `#![forbid(unsafe_code)]` on every crate root; clippy clean at `-D warnings`.
- **Everything bounded**: no unbounded channels, queues, caches, or maps. Anything keyed by
  client-controlled input (tokens, subjects) needs a max size and an eviction path. If a bound
  seems unnecessary, add it anyway and make it large.
- **Never block the runtime**: no std blocking I/O on tokio threads, no std lock guard held
  across `.await`, CPU work over ~1ms goes to `spawn_blocking` (JWT verification at ~100µs is
  fine inline). Every spawned task is awaited, aborted on shutdown, or documented
  fire-and-forget with its own error logging.
- **Reject before you buffer**: every limit check happens at the cheapest feasible point —
  before body read where possible, before Redis work always.
- Doc comments and unit tests for every public fn in `convert.rs`, `acl.rs`, and the auth adapters.

## Current implementation status

Phases 0–6 are complete. All three command routes authenticate static or Keycloak JWT
credentials, enforce the global admission stack, command ACLs, and debt-aware per-credential
rate limits, execute through Fred, and convert RESP2 results. JWKS discovery and optional token
introspection use bounded Hyper/rustls adapters. Deferred work is marked with `TODO(phaseN)`
comments where later phases attach to the current implementation.

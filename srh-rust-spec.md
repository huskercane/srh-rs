# SRH-RS: Upstash-compatible Redis HTTP proxy in Rust — Implementation Spec v2

Rust rewrite of [hiett/serverless-redis-http](https://github.com/hiett/serverless-redis-http)
with hardened security: JWT auth (Keycloak), Redis-side ACL enforcement, read-only tokens,
command ACLs, script allowlisting, rate limiting, safe timeouts.

**Instructions for the coding agent:** Work through phases IN ORDER. Each phase has
acceptance criteria; do not proceed until they pass. Do not invent features not in this
spec. Wire compatibility with the `@upstash/redis` JavaScript SDK is the top-level
requirement — where the spec says "exactly", match exactly.

**Implementation status (2026-08-09):** Phases 0–7 and 9 are complete. Phase 8 remains deferred
as specified.

**API-name caution:** dependency APIs change between versions. Type/method names in this
spec are indicative; ALWAYS verify signatures against docs.rs for the exact version in
Cargo.lock before writing code (fred 10 uses `fred::types::Value`, `fred::clients::Pool`,
`fred::clients::Client` — NOT the older `RedisValue`/`RedisPool`/`RedisClient` names).

---

## 0. Project setup

Binary crate `srh-rs`, **edition 2024**, pin toolchain in `rust-toolchain.toml` to a
specific stable (e.g. `1.85`). `#![forbid(unsafe_code)]`.

```toml
[dependencies]
axum = { version = "0.8", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
tower = { version = "0.5", features = ["limit", "load-shed", "timeout", "util"] }
tower-http = { version = "0.6", features = ["limit", "trace", "timeout"] }
fred = { version = "10", features = ["enable-rustls-ring"] }
futures-util = "0.3"
hyper = { version = "1", features = ["http1", "server"] }
hyper-util = { version = "0.1", features = ["http1", "server-graceful", "service", "tokio"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
jsonwebtoken = "9"
url = "2"
dashmap = "6"
thiserror = "2"
anyhow = "1"
sha2 = "0.10"
zeroize = "1"
async-trait = "0.1"
bytes = "1"
metrics = "0.24"
metrics-exporter-prometheus = { version = "0.16", default-features = false, features = ["http-listener"] }

[dev-dependencies]
testcontainers = "0.23"
wiremock = "0.6"
```

Note: `subtle` is no longer needed — all token comparison is digest-vs-digest (see Phase 1).

**No `reqwest`, here or in any later phase.** HTTP client work uses `hyper` directly, which
is already a direct dependency for the inbound listener. Phase 6 is the only phase that
needs an outbound client; it adds `hyper/client`, `hyper-util` (`client`, `client-legacy`
for pooling), `hyper-rustls`, and `http-body-util` AT THAT POINT, not before — an unused
dependency carried across phases is how an unnoticed transitive feature conflict gets in
(see the `metrics-exporter-prometheus` / rustls-provider incident). Dropping reqwest costs
about two crates net, so the reason is stack consistency and request-path performance,
not tree size.

**Pair `hyper-rustls` with `rustls-native-certs`, never `webpki-roots`.** fred already
trusts the OS store; a client trusting bundled Mozilla roots instead would fail against a
Keycloak behind an internal or corporate CA — with an unknown-issuer TLS error that adding
the CA to the system store does not fix. Both TLS paths must share one trust story.

`url` is used only for config validation (`auth.jwt.issuer`); do not pull an HTTP client
to parse a URL.

Module layout (hexagonal — see §0.5; phase labels show where each file is built):

```
src/
  main.rs                # COMPOSITION ROOT: construct adapters, wire AppState, serve
  config.rs              # Phase 1
  error.rs               # Phase 1 (HTTP-facing AppError)
  domain/                # PURE CORE — no fred/axum/reqwest/hyper imports, no I/O
    mod.rs
    resp.rs              # RespValue enum + ExecError (Phase 2)
    convert.rs           # Phase 2
    identity.rs          # Phase 1
    acl.rs               # Phase 5
    breaker.rs           # Phase 4 — state machine only, Clock-injected
    rate_limit.rs        # Phase 5 — token bucket, Clock-injected
  ports/
    mod.rs               # ALL trait definitions live here (Phase 1, extended later)
  adapters/
    fred_executor.rs     # Phase 2: CommandExecutor over fred (+ frame→RespValue map)
    pool_manager.rs      # Phase 4: ExecutorProvider (lazy pools, semaphore, eviction)
    breaker_executor.rs  # Phase 4: decorator, CommandExecutor wrapping CommandExecutor
    static_auth.rs       # Phase 1: Authenticator
    jwt_auth.rs          # Phase 6: Authenticator
    auth_chain.rs        # Phase 1: composite Authenticator
    http_jwks.rs         # Phase 6: JwksSource
    http_introspect.rs   # Phase 6: Introspector
    system_clock.rs      # Phase 1: Clock
  http/                  # inbound adapter (axum) — Phases 1–3
    mod.rs
    extractors.rs        # AuthedIdentity
    command.rs
    pipeline.rs
    multi_exec.rs
    health.rs
  testsupport/           # fakes behind #[cfg(any(test, feature = "testsupport"))]
    fake_executor.rs     # scriptable replies/failures
    fake_clock.rs        # manually advanced
    fake_jwks.rs
```

---

## 0.5 Architecture — ports & adapters, SOLID (normative)

### The dependency rule

`domain/` imports only std, `serde_json`, `bytes`, `base64`, `sha2`, and `ports/` types. It NEVER
imports fred, axum, tower, hyper, reqwest, or tokio's I/O — tokio sync primitives
(Semaphore, atomics) are allowed. `ports/` imports only domain types. `adapters/` and
`http/` may import anything. `main.rs` is the ONLY place a concrete adapter type is
named outside its own module. Enforce mechanically: a CI step greps `src/domain` and
`src/ports` for `use fred|use axum|use reqwest|use hyper|use tower` and fails on match.

### The six ports (exactly these — five async + the sync Clock; adding a seventh requires written justification in the PR)

All async ports use the `async_trait` crate: native `async fn` in traits is NOT
dyn-compatible, and wiring is via `Arc<dyn Port>`. This is a known Rust footgun —
do not attempt `Arc<dyn Trait>` with native async trait methods.

```rust
// ports/mod.rs — indicative signatures, keep them this small (ISP)

pub struct RedisCommand { pub name: String, pub args: Vec<bytes::Bytes> }

#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn execute(&self, cmd: RedisCommand) -> Result<RespValue, ExecError>;
    async fn pipeline(&self, cmds: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>>;
    async fn transaction(&self, cmds: Vec<RedisCommand>) -> Result<Vec<RespValue>, ExecError>;
}

#[async_trait]
pub trait ExecutorProvider: Send + Sync {
    /// Bounded acquisition happens INSIDE this call (Phase 4); the returned handle
    /// carries the pool permit and releases it on drop.
    async fn acquire(&self, pool: &str) -> Result<ExecutorHandle, AcquireError>;
    /// For /ready ONLY: PING each ALREADY-BUILT pool and report status. MUST NOT
    /// build absent pools (acquire() builds; this must not). Narrowly scoped by
    /// design — do not extend it into general pool introspection.
    async fn readiness(&self) -> Vec<PoolReadiness>;
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Ok(None) = "not mine, try next in chain"; Err = rejection or service outage.
    async fn authenticate(&self, bearer: &str) -> Result<Option<Identity>, AuthError>;
}

#[async_trait]
pub trait JwksSource: Send + Sync {
    async fn key_for(&self, kid: &str) -> Result<CachedKey, JwksError>;
}

#[async_trait]
pub trait Introspector: Send + Sync {
    async fn is_active(&self, token: &str) -> Result<bool, IntrospectError>;
}

pub trait Clock: Send + Sync {          // sync — no async_trait needed
    fn unix_secs(&self) -> u64;
    fn instant(&self) -> std::time::Instant;
}
```

`AuthError` distinguishes `Rejected` from `ServiceUnavailable(String)`. Extractors map the
former to 401 and the latter to 503; they must not flatten dependency outages into invalid
credentials. Error details never contain bearer material.

`ExecError` (domain): `Transport(String)`, `Timeout`, `Redis(String /* raw error, verbatim */)`,
`ResponseTooLarge`. The breaker counts `Transport`/`Timeout` only — `Redis(_)` is a
healthy backend saying no (Phase 4).

### Composition (DIP)

```rust
pub struct AppState {
    pub provider: Arc<dyn ExecutorProvider>,
    pub authenticator: Arc<dyn Authenticator>,   // the chain composite
    pub clock: Arc<dyn Clock>,
    pub cfg: Arc<Config>,
}
```
Handlers and extractors depend on `AppState` only. Use `Arc<dyn _>`, not generics —
no type-parameter proliferation through the handler stack.

### SOLID, applied (not aspirational)

- **SRP**: `http/` handlers do parse → auth → ACL → acquire → execute → convert →
  respond, and contain NO business rules; every rule lives in `domain/`. Any `if`
  about commands, permissions, or encodings found in a handler is a review defect.
- **OCP**: cross-cutting behavior extends by DECORATOR on `CommandExecutor`
  (`breaker_executor.rs` now; a metrics decorator in Phase 7 if desired) — never by
  editing `fred_executor.rs`. New auth methods are new `Authenticator` impls appended
  to the chain — `auth_chain.rs` itself never changes.
- **LSP — enforced by contract tests**: `testsupport` exposes
  `pub async fn executor_contract(make: impl Fn() -> Arc<dyn CommandExecutor>)`
  exercising the semantics every impl must share (raw error passthrough, pipeline
  never aborts on per-command error, transaction atomicity, nil handling). The SAME
  suite runs against `FredExecutor` (testcontainers, CI job 2) and `FakeExecutor`
  (unit tests). A fake that drifts from real behavior fails CI — this is what makes
  fake-based unit tests trustworthy. Same pattern, smaller, for `Authenticator` impls.
- **ISP**: ports stay as printed above. No `RedisPort` god-trait; no adding methods
  "while you're in there".
- **DIP**: the dependency rule + composition root. Concrete types named in `main.rs`
  and their own modules only.

### Guardrails (anti-over-engineering — equally normative)

- Do NOT abstract axum, tower, serde, tracing, or the metrics crate behind ports.
  They are the application, not the domain's collaborators.
- Do NOT introduce generic type parameters where `Arc<dyn _>` works.
- Do NOT create a port for config, logging, or time-formatting.
- Fakes are hand-written in `testsupport/`; no mocking framework crates.

---

## 1. Wire protocol (normative — read fully before coding)

### 1.1 Endpoints

Only these three. Other paths → 404 `{"error":"Not found"}`. Non-POST → 405
`{"error":"Method not allowed"}`.

| Endpoint | Body | Behavior |
|---|---|---|
| `POST /` | JSON array: one command, e.g. `["SET","foo","bar","EX",100]` | Run one command |
| `POST /pipeline` | JSON array of command arrays | Pipelined; per-command errors do NOT abort; always HTTP 200 |
| `POST /multi-exec` | JSON array of command arrays | MULTI/EXEC; atomic |

### 1.2 Authentication and headers

`Authorization: Bearer <token>`. Missing/invalid → 401 `{"error":"Unauthorized"}`.
Do NOT implement token-in-query-param or path-based commands.

Header tolerance (required):
- **Ignore all unrecognized headers**, including `upstash-sync-token`,
  `Upstash-Telemetry-*`, and any other `Upstash-*` header this spec doesn't define.
  Never 400 on them. (The SDK sends `upstash-sync-token` when readYourWrites is on,
  which is its default; real SRH ignores it and the SDK tolerates that.)
- **Never log** `Authorization` or any `Upstash-Telemetry-*` header values.

### 1.3 Request argument encoding

Body elements are JSON values; convert each to a Redis argument:
- string → raw bytes as-is
- number → canonical string (`100` → `"100"`, `1.5` → `"1.5"`)
- bool → `"true"` / `"false"`
- null → `"null"`
- object/array → `serde_json::to_string(v)`

First element = command name; must be a non-empty string; else 400
`{"error":"Invalid command"}`.

### 1.4 Response shape

Single success → 200 `{"result": <converted reply>}`.
Single Redis error → 400 `{"error":"<raw redis error incl. prefix>"}` (clients
pattern-match these; do not rewrite).
Pipeline → always 200, ordered `[{"result":..}|{"error":..}, ...]`.
Non-Redis per-slot failures remain HTTP 200: timeout uses
`{"error":"Redis command timed out"}` and transport failures use the redacted
`{"error":"Internal server error"}`. These are synthetic application errors, not
raw Redis errors, and transport details are logged server-side only.
Multi-exec success → 200 array mapped 1:1 from EXEC reply. Queue-time failure →
DISCARD, then 400 `{"error":"<raw>"}`. EXEC-time slot failure → 400 raw after
Redis has executed the transaction; successful commands are not rolled back (§1.7).

### 1.5 RESP → JSON (`convert.rs::redis_value_to_json`)

Force RESP2 on all connections (fred config `resp3: false`):

| RESP2 | JSON |
|---|---|
| Simple string | string |
| Bulk string | string; non-UTF8: lossy conversion when encoding off (see 1.6) |
| Integer | number |
| Nil | null |
| Array | array, recurse |
| Error | routed to `error` field, never `result` |

### 1.6 Response encoding (`Upstash-Encoding: base64`)

The SDK sends this by default. When present (case-insensitive `base64`), encoding
happens INSIDE conversion, not as a post-pass over the JSON — a post-pass would
base64 the LOSSY UTF-8 string and destroy the very bytes the encoding exists to
preserve:
- `Bulk` values → base64 (standard alphabet, padded) of the ORIGINAL raw bytes
- `Simple` string values → base64 of the string bytes, EXCEPT the exact reply
  `"OK"` which stays `"OK"`
- numbers/bools/null unchanged; arrays recurse; `error` field NEVER encoded
Lossy UTF-8 conversion of non-UTF8 bulks applies ONLY in non-encoded mode (§1.5).
Applies identically to all three endpoints.

### 1.7 Deliberate differences vs Upstash (do not "fix")

- `UNLINK` with 0 keys returns the real Redis error
- `ZRANGE` requires BYSCORE/BYLEX for LIMIT
- RedisJSON responses may differ subtly
- Fred's public transaction API collapses valid UTF-8 bulk and simple strings into
  the same `Value::String`. Therefore, in base64 mode only, a bulk value whose bytes
  are exactly `OK` inside `/multi-exec` is returned as `"OK"` rather than `"T0s="`.
  Single-command and pipeline execution use raw frames and do not have this divergence.
- An EXEC-time command error does not roll back Redis transactions. `/multi-exec`
  returns 400 with the raw failing-slot error and omits successful slot results,
  but other queued commands may already have committed. `DISCARD` applies only to
  queue-time failure before EXEC begins.

The Phase 7 upstream parity gate scopes out SDK tests whose command is intentionally denied by
the Phase 5 ACL. Those are authorization-policy cases, not wire-protocol comparisons. Protocol
failures may be skipped only for the deliberate differences above; the two lists remain separate
and reviewable under `ci/`.

---

## Phase 1 — Config, errors, static auth, HTTP skeleton

### config.rs

`SRH_MODE` env (default `"file"`).

**env mode**: requires `SRH_TOKEN`, `SRH_CONNECTION_STRING`; optional
`SRH_MAX_CONNECTIONS` (default 3). Normalize to one pool `"default"` + one legacy-compatible
static token, preserving the original SRH Docker interface and command policy.

**file mode**: `SRH_CONFIG_PATH` (default `./srh-config/tokens.json`). Support legacy
AND new formats; detect legacy by top-level values containing `connection_string`.

Legacy (each key is a token):
```json
{ "example_token": { "srh_id": "id", "connection_string": "redis://localhost:6379", "max_connections": 3 } }
```
Legacy normalization: pool = `srh_id` (or sha256-prefix of token); token is read-write;
**legacy tokens keep FLUSHALL/FLUSHDB rights** (compat with original SRH).

New format:
```json
{
  "server": {
    "port": 80,
    "bind": "127.0.0.1",
    "tls": null,
    "max_body_bytes": 10485760,
    "max_pipeline_commands": 1000,
    "max_request_elements": 10000,
    "http_timeout_ms": 10000,
    "rate_limit": { "per_token_commands_per_sec": 0 },
    "load": {
      "max_in_flight": 512,
      "max_response_bytes": 33554432,
      "shed_retry_after_secs": 1,
      "body_read_timeout_ms": 2000
    },
    "metrics_bind": "127.0.0.1:9422"
  },
  "auth": {
    "jwt": {
      "issuer": "https://kc.example.com/realms/infra",
      "audience": "srh",
      "jwks_refresh_secs": 600,
      "role_prefix": "redis:",
      "client_id": "srh",
      "introspection": { "enabled": false, "url": "", "client_id": "", "client_secret": "", "cache_secs": 30 }
    },
    "static_tokens": {
      "sha256:ab12...": {
        "pool": "authkv",
        "read_only": false,
        "allowed_commands": ["GET", "SET", "DEL", "EXPIREAT"],
        "blocked_commands": [],
        "allowed_script_sha256": []
      },
      "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": { "pool": "local" }
    }
  },
  "pools": {
    "authkv": {
      "connection_string": "rediss://srh-authkv:PASS@redis.internal:6379/1",
      "max_connections": 10,
      "command_timeout_ms": 1000,
      "acquire_timeout_ms": 250,
      "max_waiters": 40,
      "breaker": { "failure_threshold": 10, "cooldown_ms": 2000 }
    },
    "local": { "connection_string": "redis://localhost:6379", "max_connections": 3, "command_timeout_ms": 2000 }
  }
}
```

Rules:
- Defaults as shown. `server.bind` default is **127.0.0.1** (secure by default; the
  Docker image sets `SRH_BIND=0.0.0.0` — see Phase 7). `SRH_BIND`, `SRH_PORT`,
  `SRH_IPV6` (true → `::1`, or `::` when SRH_BIND=0.0.0.0) env overrides.
- `server.tls` (`{cert, key}` paths) optional; absent → plain HTTP. TLS support is a
  LOW-priority optional feature — primary deployments front this with a reverse proxy.
  Warn once if binding non-loopback without TLS.
- Implicit default-block set — keyed on `!identity.legacy`, NOT on token format:
  unless explicitly listed in `allowed_commands`, every non-legacy identity
  (new-format static tokens AND all JWT identities) has
  `FLUSHALL, FLUSHDB, KEYS, RANDOMKEY, INFO, DBSIZE` in its effective blocked set
  (destructive, or whole-keyspace/introspective against a possibly shared Redis —
  DBSIZE leaks total key count, the weaker sibling of the KEYS leak). Only
  legacy-format tokens are exempt (original SRH parity). A JWT `redis:write`
  identity MUST NOT be more privileged than a new-format static token — the
  Keycloak path is the primary one; it gets the defaults, not an exemption.
  MEMORY is HARD_DENY (its three read
  subcommands are ADMIN_ALLOW-only: MEMORY PURGE is not a read, and MEMORY STATS
  leaks keyspace shape).
- Static token keys: `sha256:<hex>` = digest of the real token; plaintext keys allowed
  but **hashed immediately at load** — the config struct stores ONLY 32-byte digests.
  Plaintext keys are a dev/CI convenience; every EXAMPLE in docs and README uses
  `sha256:`, because examples get copied into production configs.
- `command_timeout_ms` per pool, default 2000. **Startup invariant (validate, exit
  on violation): `acquire_timeout_ms + 2 * command_timeout_ms < http_timeout_ms` for
  EVERY pool.** The pairwise checks (each < http_timeout) are insufficient: both can
  hold while the sum exceeds the HTTP timeout, in which case the tower TimeoutLayer
  fires mid-command, the handler future is dropped, and the permit guard drops with
  it while fred's command is still in flight — no RESP desync (fred owns the
  socket), but the permits-in-use gauge under-counts real work, corrupting exactly
  the signal Phase 9 tunes against. The sum invariant is also the per-attempt term
  of the timeout budgeting rule below.
- Load defaults: `max_in_flight` 512; `max_response_bytes` 32 MiB;
  `shed_retry_after_secs` 1; `body_read_timeout_ms` 2000. Per pool: `max_waiters`
  default 4 × `max_connections`;
  `acquire_timeout_ms` default 500 (the binding invariant is the SUM check above:
  acquire + command + reset < http_timeout, per pool);
  `breaker.failure_threshold` default 10 consecutive failures,
  `breaker.cooldown_ms` default 2000. All of these MUST be finite; a config value of
  0 for any bound is a startup validation error, not "unlimited".
- **Timeout budgeting rule (README):** a client's worst case per logical operation is
  `retries × (acquire_timeout_ms + 2 * command_timeout_ms)`. The second command
  timeout covers the bounded forced reset. Size pool timeouts so that the product
  fits inside the CALLER's deadline — e.g. the authkv example totals
  250 + 2 × 1000 = 2250ms per attempt, not the general defaults' 4.5s.
- **Rate sizing rule (README):** `per_token_commands_per_sec` is a COMMAND budget.
  Worst-case throttle after one max-size pipeline is
  `max_pipeline_commands / rate` seconds of debt — size the rate to cover the
  token's peak command throughput (including SDK auto-batching), not its request
  count.
- Validate: every token's `pool` exists; issuer parses as URL; clear exit message.
- Secrets (`connection_string`, `client_secret`) in a newtype: `Debug` prints
  `"<redacted>"`, `Zeroize` on drop. Plaintext tokens are dropped after hashing.

### error.rs

`AppError`: `Unauthorized` (401), `Forbidden(String)` (403), `BadRequest(String)` (400),
`RedisError(String)` (400), `RateLimited { retry_after_secs: u64 }` (429, MUST set
`Retry-After: <retry_after_secs>` — with debt semantics this is the status where
the header matters most: a large pipeline can leave a deficit of tens of seconds,
and the SDK's default retries (3 × ~50ms backoff) are all guaranteed to fail
inside it; the header lets clients back off honestly or give up deliberately
instead of by accident), `AuthServiceUnavailable` (503),
`Overloaded { retry_after_secs: u64 }` (503, body `{"error":"Server overloaded"}`, MUST set a
`Retry-After: <shed_retry_after_secs>` response header),
`PoolOpen { retry_after_secs: u64, reason: String }` (503, `{"error":"Backend unavailable"}`, also Retry-After — circuit
breaker open), `ResponseTooLarge` (502, `{"error":"Response too large"}` — fails the
WHOLE request on ALL endpoints, overriding pipeline's "always 200" rule: partial
conversion cannot safely continue in a spent budget, and a 200 with a synthetic slot
error would misrepresent execution. NOTE the semantics for clients, documented in
README: the commands DID execute on Redis; 502 means the response could not be
rendered, not that work was rolled back — treat it as indeterminate, like any
timeout after send),
`Internal(String)` (500). `IntoResponse` → `{"error":"<msg>"}`; `Internal` logs the real
error via `tracing::error!` but returns only `{"error":"Internal server error"}`.

### adapters/static_auth.rs + adapters/auth_chain.rs + http/extractors.rs

```rust
pub struct Identity {
    pub subject: String,       // LOG-ONLY label: digest hex prefix (8 chars) or JWT sub
    pub bucket_key: String,    // rate-limit key: FULL digest hex (static) or full sub (JWT) — never the prefix
    pub pool: String,
    pub read_only: bool,
    pub is_admin: bool,                       // JWT redis:admin only; static tokens never
    pub legacy: bool,                         // legacy-format token (FLUSH parity)
    pub allowed_commands: Option<HashSet<String>>,   // uppercase
    pub blocked_commands: HashSet<String>,           // uppercase
    pub allowed_script_sha256: HashSet<String>,      // lowercase hex; SERVER CONFIG ONLY (per token or per pool) — never from JWT claims
    pub key_prefix: Option<String>,           // Phase 8
}
```

Static lookup: sha256 the presented token → look up the digest in a
`HashMap<[u8;32], TokenEntry>`. Every configured token was hashed at load, so this is a
uniform 32-byte lookup with no plaintext comparison and no length leak. NEVER log the
token; `subject` = first 8 hex chars of the digest.

Auth composition: `AuthChain` (composite `Authenticator`) holds an ordered
`Vec<Arc<dyn Authenticator>>`. Each link returns `Ok(None)` for "not my token format,
try next" (e.g. `JwtAuth` when the token doesn't have exactly two `.` separators),
`Ok(Some(identity))` on success, `Err` for a definitive rejection (recognized format,
failed verification — do NOT fall through to the next link: a JWT that fails signature
must never be retried as a static token). Chain exhausted → 401. Phase 1 wires
`[StaticAuth]`; Phase 6 changes ONE line in main.rs to `[JwtAuth, StaticAuth]`.

`http/extractors.rs`: `AuthedIdentity: FromRequestParts` extracts the bearer
(missing → 401) and delegates to `state.authenticator`.

### main.rs skeleton

- tracing_subscriber (env filter; JSON when `SRH_LOG_FORMAT=json`).
- **Two-router split — this ordering is load-bearing:** the three API routes live in a
  "limited" router wrapped in the admission-control stack; `/health` (and later
  `/ready`) live OUTSIDE it, merged after, so observability endpoints are NEVER shed
  or queued behind API traffic. An overloaded proxy that can't answer health checks
  gets restarted by the orchestrator mid-recovery — worse than the overload itself.
- Admission stack on the API router (tower `ServiceBuilder`, top = outermost):
  1. `HandleErrorLayer` mapping tower `Overloaded`/timeout errors → `AppError::Overloaded`
  2. `load_shed()` — when the concurrency limit below is at capacity, reject
     IMMEDIATELY with 503 + Retry-After instead of queueing. Rejection must happen
     before body read: shedding costs microseconds, queueing costs memory.
  3. `GlobalConcurrencyLimitLayer(load.max_in_flight)` — one shared semaphore across all
     three API routes. Do not use `Router::layer` with `ConcurrencyLimitLayer`: Axum applies
     that layer per route and would create three independent limits.
  4. `TimeoutLayer(http_timeout_ms)` — HTTP backstop ONLY; real Redis timeouts are
     enforced inside fred (Phase 4).
  5. `RequestBodyLimitLayer(max_body_bytes)`.
- **Slow-transfer defenses** (a trickled body inside http_timeout_ms would otherwise
  hold one of the `max_in_flight` slots for the full 10s — 512 such connections is a
  full outage from one cheap client): set hyper's `http1_header_read_timeout` (~3s),
  and enforce a distinct BODY-read timeout `body_read_timeout_ms` (default 2000) by
  wrapping the body-collection future in `tokio::time::timeout` inside the handlers
  — exceeding it → 408 `{"error":"Request body timeout"}`. Pool permits are acquired
  only AFTER the body is fully read and parsed (verify in code review — a slow body
  must never hold a Redis permit).
- `TraceLayer` wraps everything (both routers).
- The direct listener is HTTP/1.1 only so Hyper's three-second header-read timeout can be
  configured explicitly. Deployments needing HTTP/2 terminate it at the reverse proxy.
- `GET /health` (any interface): 200 `{"status":"ok"}`, liveness only, no Redis I/O,
  never shed.
- Bind per config. **Graceful shutdown:** on SIGTERM/SIGINT, stop accepting new
  connections, drain in-flight requests with a 15s deadline using Hyper Util's
  `GracefulShutdown`, then `quit()` all pools, then exit. In-flight work
  finishes; new work is refused at the socket.
- **Async discipline (applies to the whole codebase):** never hold a `std::sync`
  Mutex/RwLock guard across an `.await` (use tokio's or drop the guard first); no
  blocking I/O or >1ms CPU bursts on runtime threads without `spawn_blocking`
  (JWT signature verification is fine inline — it's ~100µs); every channel is bounded;
  every spawned task is either awaited, aborted on shutdown, or a documented
  fire-and-forget with its own error logging.

### Phase 1 acceptance
- Unit tests: legacy parse, new parse, env normalization, plaintext-hashed-at-load,
  `sha256:` match, missing-pool failure, timeout-ordering validation failure.
- Wrong token → 401 JSON; right token → 501.
- Grep test: no plaintext token ever appears in any log line.

---

## Phase 2 — convert.rs + POST /

- `json_args_to_redis(&[serde_json::Value]) -> Result<RedisCommand, AppError>` per §1.3.
- `domain/resp.rs`: define
  `RespValue { Simple(String), Bulk(bytes::Bytes), Int(i64), Nil, Array(Vec<RespValue>) }`.
  The domain NEVER sees fred types; `adapters/fred_executor.rs` maps
  raw `fred::types::Resp3Frame → RespValue` (exhaustive match — RESP2 is forced, so RESP3-only
  variants map to `ExecError::Transport` with a "protocol violation" message, never a
  silent lossy conversion).
- `redis_value_to_json(v: RespValue, encoding: Encoding, budget: &mut usize) -> Result<serde_json::Value, AppError>`
  per §1.5/§1.6 — `Encoding::None | Base64` is a conversion INPUT (there is no
  separate `apply_base64` post-pass; see §1.6 for why). In Base64 mode, Bulk bytes
  are encoded from the ORIGINAL bytes and budget-charged at the exact padded size
  `4 * ceil(len / 3)`; in None mode, non-UTF8 bulks are lossy-converted and charged
  at byte length. The **size budget**: `budget` starts at `load.max_response_bytes`
  per HTTP request (shared across all commands in a pipeline); decrement per string
  and a small fixed cost per node; on exhaustion return
  `AppError::ResponseTooLarge` immediately — do NOT finish converting.
  **What this bounds, honestly:** fred fully buffers each RESP reply before the
  executor returns, so the raw reply bytes are ALREADY resident when conversion
  starts — the budget cannot prevent that. What it bounds is the AMPLIFICATION on
  top: the JSON tree, string escaping (up to ~6× for binary-ish data), and base64
  (4/3), plus the serialized response body. The raw-reply bound belongs on the Redis
  server: set `proto-max-bulk-len` (bounds any single bulk string; note it does NOT
  bound aggregate replies like a huge LRANGE — that residual risk is accepted and
  mitigated by ACLs and the amplification budget). Added to the Phase 7 deployment
  checklist.

http/command.rs:
1. `AuthedIdentity`; parse body `Vec<serde_json::Value>`; bad JSON/shape → 400.
2. ACL check (Phase 5; permissive stub until then, marked `// TODO(phase5)`).
3. Pool via PoolManager (implemented in Phase 4).
4. Send raw via fred custom-command API — never interpret the command.
5. Redis error → 400 raw; success → 200, base64 per header.

### Phase 2 acceptance (table-driven unit + testcontainers redis:7)
- Arg conversion: string/int/float/bool/null/object.
- Value conversion: simple, bulk, integer, nil, nested array, non-UTF8 bulk —
  all pure unit tests on `RespValue`, no Redis.
- fred→RespValue mapping: exhaustive-match compile check + integration assertions.
- **Executor contract suite** (testsupport): raw-error passthrough, pipeline
  never-aborts, transaction atomicity, nil handling — passes against BOTH
  `FredExecutor` (testcontainers) and `FakeExecutor`. This suite is extended in later
  phases and re-run in CI job 2; it is the LSP gate.
- base64: `"OK"` untouched; `"bar"`→`"YmFy"`; nested; numbers/null untouched;
  **binary round-trip:** SET a key to bytes `[0xFF, 0xFE, 0x00, 0x01]`, GET it back
  with `Upstash-Encoding: base64` → the decoded result equals the ORIGINAL bytes
  exactly (proves encoding happens on raw bulk bytes, not on a lossy UTF-8
  intermediate).
- Integration: SET/GET/missing-GET/INCR/LPUSH+LRANGE/WRONGTYPE(400 raw)/base64 GET.
- Request with `upstash-sync-token: whatever` header → processed normally.
- Dependency-rule grep (CI): `src/domain` and `src/ports` contain no
  fred/axum/reqwest/hyper/tower imports.

---

## Phase 3 — /pipeline and /multi-exec

**pipeline.rs**: parse `Vec<Vec<serde_json::Value>>` (400 on shape). Enforce
`max_pipeline_commands` → 400 `{"error":"Pipeline too large"}`. ACL-check every command
UP FRONT; denied commands get their slot's `error` pre-filled and are NOT sent.
Execute the remainder by polling ordered `custom_raw` futures together with
`futures_util::future::join_all`. Do NOT spawn one task per command: task scheduling
can reorder dependent commands before they enter Fred's queue. The order-dependent
integration test is the regression lock for Fred's first-poll enqueue behavior.
Do NOT issue sequential awaited round-trips. Preserve original slot order. Always
HTTP 200 — with ONE exception: `ResponseTooLarge` (budget exhaustion
during conversion) fails the whole request with 502 per error.rs; see the caveat
there about already-executed commands. Base64 per result.

The outer pipeline array and inner command arrays use bounded serde `SeqAccess`
visitors. `max_pipeline_commands` caps only the number of commands;
`max_request_elements` (default 10,000) is a separate budget shared across every
JSON value node and object key in the request, including nested array/object
arguments. The node beyond the element budget is rejected before materialization;
the command beyond the pipeline cap is consumed as `IgnoredAny`. Budget exhaustion
returns 400 `{"error":"Request too complex"}`.

**multi_exec.rs**: validate ALL commands (shape + ACL) before touching Redis. An ACL
denial → 403, while an invalid command shape → 400; either way nothing is sent. Use
fred's transaction API — and
**verify against the locked fred version that its transaction pins/buffers onto a
single connection such that no other request's commands can interleave between MULTI
and EXEC** (fred multiplexes and the Pool round-robins; the semaphore bounds
requests, NOT connections, so nothing in srh-rs's own design prevents interleaving —
the guarantee must come from fred's transaction implementation, and the test below
proves it rather than assumes it). Queue-time failure → DISCARD + 400 raw;
EXEC-time slot failure → 400 raw with no rollback (§1.7). Success → 200 mapped array.

### Phase 3 acceptance
- Pipeline, failing middle command: 200; slot 1 error, slots 0/2 succeed.
- Pipeline with an ACL-denied command mixed in: 200; denied slot has NOPERM; others ran.
- Pipeline of 1001 commands with default cap → 400.
- Multi-exec happy path; invalid-command multi-exec → 400 and no keys written.
- **Transaction isolation under concurrency:** against a `max_connections: 1` pool,
  run 20 concurrent multi-exec requests interleaved with 50 concurrent single
  commands; assert every transaction's results correspond exactly to its own
  commands and every single command's reply is its own (no cross-enrollment, no
  reply misattribution). This test is the proof for the fred-pinning requirement
  above.
- Empty body: pipeline → 200 `[]`; multi-exec → 400.

---

## Phase 4 — Lazy pools, timeouts, idle eviction (adapters/pool_manager.rs)

`PoolManager` implements the `ExecutorProvider` port. The breaker lives in
`domain/breaker.rs` (pure, Clock-injected state machine) and is applied via the
`breaker_executor.rs` DECORATOR: `PoolManager::acquire` returns a handle whose
executor is `BreakerExecutor(FredExecutor)`. Test the breaker state machine against
`FakeClock` + `FakeExecutor` with zero real I/O.

```rust
pub struct PoolManager { pools: DashMap<String, PoolEntry>, cfg: Arc<Config>, clock: Arc<dyn Clock> }
struct PoolEntry {
    pool: fred::clients::Pool,
    last_used: AtomicU64,
    permits: Arc<tokio::sync::Semaphore>,   // bounds concurrent REQUESTS on this pool (not 1:1 with connections)
    waiters: Arc<AtomicUsize>,              // bounded by max_waiters
    breaker: Arc<domain::breaker::Breaker>,
}
```

- `get(name)`: `entry().or_try_insert_with(build)`; touch `last_used` per access.
- **Bounded acquisition (the backpressure core).** The semaphore permits bound
  concurrent REQUESTS using the pool — they are NOT 1:1 with TCP connections (fred
  multiplexes and round-robins internally). Acquisition protocol per request:
  1. **Breaker check FIRST**: if the pool's breaker is Open (and not yet due for a
     HalfOpen probe), return `AppError::PoolOpen` immediately — before the waiter
     counter, before the semaphore, before any Redis contact. This ordering is the
     entire point of the breaker: an open circuit must consume NO permits and NO
     waiter slots, or a dead backend still starves the pool. (This is a design
     requirement, not an implementation detail — the breaker DECORATOR cannot do
     this because permits are acquired before the executor is called; the decorator
     only RECORDS outcomes into the breaker.)
  2. Fast waiter bound: an `AtomicUsize` waiter counter; if incrementing it would
     exceed `max_waiters`, decrement and return `AppError::Overloaded` immediately.
  3. `tokio::time::timeout(acquire_timeout_ms, semaphore.acquire())`; on timeout,
     return `AppError::Overloaded`. On success, decrement the waiter counter and hold
     the `OwnedSemaphorePermit` for the duration of the Redis work (single command,
     whole pipeline, or whole transaction), releasing on drop.
  This gives a fixed-depth queue per pool: accepted-request latency stays bounded
  under overload because at most `max_waiters` requests ever wait, and each waits at
  most `acquire_timeout_ms`. Everything beyond that is converted into a fast, cheap
  503 the client can retry — bend, not break.
- **Circuit breaker per pool** (hand-rolled, ~60 lines; do not add a crate):
  states Closed → Open → HalfOpen, pure state machine in `domain/breaker.rs`
  (Clock-injected). `failure_threshold` consecutive Redis connection/timeout errors
  (`ExecError::Transport`/`Timeout` — NOT `Redis(_)` command errors like WRONGTYPE;
  those are a healthy Redis saying no) → Open. State is CHECKED in
  `PoolManager::acquire` (step 1 above); outcomes are RECORDED by the
  `breaker_executor.rs` decorator. While Open, acquisition fails in microseconds
  with `AppError::PoolOpen` — this is what prevents the timeout pileup where every
  request burns `command_timeout_ms` holding a permit while Redis is down. After
  `cooldown_ms`, HalfOpen: exactly ONE request is
  allowed through as a probe (CAS on the state); probe success → Closed and reset the
  failure counter, probe failure → Open with a fresh cooldown. Starting the probe also
  restarts Fred's connection task so exponential reconnect backoff cannot extend recovery
  beyond the breaker cooldown. While a backend remains down this deliberately produces one
  reconnect attempt per cooldown rather than letting Fred remain at its 5s backoff cap.
  Breaker state changes
  emit `tracing::warn!` and a metrics gauge.
- Build: fred Pool from connection string, `max_connections`, RESP2 forced, rustls for
  `rediss://`, exponential reconnect (100ms–5s), NO ping at build (lazy connect —
  preserves the CI no-race property).
- **Timeouts — critical correctness rule:** the per-command timeout
  (`command_timeout_ms`) MUST be enforced inside fred (its command/response timeout
  config), NOT by racing/dropping the response future at the HTTP layer. Dropping a
  future mid-command leaves an unconsumed RESP reply on a pooled connection and every
  subsequent command on that connection reads the wrong reply. Fred 10 marks the command
  timed out but does not necessarily tear down a responsive socket (for example, one
  blocked in `BLPOP`), so the adapter MUST call `force_reconnection()` after a fred-level
  timeout. Coalesce concurrent pipeline timeouts to at most one reset per request executor.
  Never return a connection to reuse after a timeout without reset. The tower
  `TimeoutLayer` remains only as an HTTP backstop; startup validates the full
  acquire + command + reset budget described above.
- `readiness()` PINGs only already-built pools but deliberately bypasses request permits,
  waiter slots, and breaker admission. Readiness measures backend health, not saturation;
  it must not remove a busy healthy instance from rotation or consume a half-open traffic
  probe. It still uses Fred's bounded command timeout/reset path and does not touch idle
  timestamps.
- Background task (60s): evict entries idle > 900s via `pool.quit()`; also sweeps rate
  buckets (Phase 5). `tracing::info!` + metrics counter per eviction.

### Phase 4 acceptance
- First request builds pool; second reuses (assert via metrics counter).
- Redis down at startup → server healthy; request errors cleanly; Redis up → next
  request succeeds without restart.
- Timeout test: against a redis where a command is artificially slow (e.g. `DEBUG SLEEP`
  on a raw client outside the proxy holding the single connection, or a TCP proxy that
  stalls), a timed-out request returns an error AND the following request on the same
  pool returns the CORRECT reply (no desync).
- Saturation test (pool max_connections=1, max_waiters=2): fire 10 concurrent slow
  requests; assert exactly ≤3 enter Redis work, ≥7 get fast 503s, and the 503s return
  in <50ms (i.e. shed, not queued).
- Breaker test: point a pool at a closed port; fire 50 concurrent requests; assert the
  first `failure_threshold` take up to connection-error time and the remainder fail in
  <5ms with `Backend unavailable`; then open the port and assert recovery within one
  cooldown (probe succeeds, subsequent requests 200).
- Eviction unit test with injected clock.

---

## Phase 5 — ACL enforcement (acl.rs)

Two layers. Understand the model before coding:

**Layer A (proxy ACL, this phase):** fast argv[0] screening. It is defense-in-depth,
NOT the security boundary, because scripts (EVAL) execute commands server-side.
**Layer B (Redis-side ACL, deployment):** each pool's connection string authenticates
as a restricted Redis ACL user. Lua `redis.call` is subject to the calling user's ACL,
so Layer B is the boundary that actually holds. The spec's job: make Layer B easy
(per-pool users in connection strings, documented example below) and make Layer A
strict enough that Layer B is rarely reached.

```rust
pub fn check(identity: &Identity, cmd: &[serde_json::Value]) -> Result<(), AppError>
```
Takes the full command (some checks need args). Uppercase argv[0]. Order:

1. **HARD_DENY** (every identity, including admin unless noted):
```
# server/introspection/topology
CONFIG, SHUTDOWN, DEBUG, SLAVEOF, REPLICAOF, MIGRATE, MODULE, SAVE, BGSAVE,
BGREWRITEAOF, LASTSAVE, ACL, CLIENT, CLUSTER, LATENCY, MONITOR, PSYNC, SYNC,
FAILOVER, RESET, SLOWLOG, COMMAND, MEMORY,
# protocol/session state on pooled connections — correctness, not just security
HELLO, SELECT, SWAPDB, AUTH, QUIT,
# pub/sub
SUBSCRIBE, PSUBSCRIBE, UNSUBSCRIBE, PUNSUBSCRIBE, SSUBSCRIBE, SUNSUBSCRIBE, PUBLISH, PUBSUB,
# blocking — would pin pool connections
BLPOP, BRPOP, BLMOVE, BRPOPLPUSH, BLMPOP, BZPOPMIN, BZPOPMAX, BZMPOP, WAIT, WAITAOF,
# scripting managed separately (rule 2)
SCRIPT, FUNCTION
```
   Rationale comments required in code: HELLO switches RESP version on a pooled
   connection and corrupts it for all subsequent users; SELECT/SWAPDB escape DB-index
   isolation; blocking commands pin pool connections indefinitely.
   **HARD_DENY has no escape hatch; `is_admin` identities get a bounded, explicit
   allowlist evaluated first.** The **ADMIN_ALLOW** set, checked subcommand-aware
   (argv[0]+argv[1]) BEFORE rule 1:
   ```
   CONFIG GET, CLIENT LIST, CLIENT INFO, SLOWLOG GET, SLOWLOG LEN,
   INFO, COMMAND COUNT, COMMAND INFO, COMMAND DOCS, LATENCY HISTORY,
   LATENCY LATEST, MEMORY USAGE, MEMORY STATS, MEMORY DOCTOR, ACL WHOAMI
   ```
   Nothing else. Rationale (comment in code): an exemption-with-carve-outs shape
   makes every command Redis adds in the future admin-allowed by default — MODULE
   LOAD is native code execution on the Redis host, MIGRATE exfiltrates keys,
   SLAVEOF repoints replication; an allowlist fails safe. Note `CONFIG GET` is
   allowed but `CONFIG SET/REWRITE/RESETSTAT` are not — the subcommand check is
   what makes this possible.
   **Gate, not grant (same rule as scripting below):** an ADMIN_ALLOW hit exempts
   the command from rule 1 and counts as an explicit server-side listing only for
   rule 4's implicit default-block set (which keeps the listed `INFO` permission live).
   It still runs the explicit `identity.blocked_commands` check, rules 2–3, rule 5's
   configured `allowed_commands`, and rule 6. Otherwise an admin's
   `srh_blocked_commands` claim would silently stop applying to exactly these
   commands, breaking the "claims may only narrow" invariant (Phase 6).

2. **Scripting**: `EVAL`, `EVALSHA`, `EVALSHA_RO`, `EVAL_RO`, `FCALL`, `FCALL_RO` —
   denied UNLESS the identity's effective script allowlist is non-empty AND:
   - EVAL/EVAL_RO: sha256 of the script body (argv[1], exact bytes) is in the set
   - EVALSHA*/FCALL*: DENY always (sha1/function-name can't be mapped to an approved
     sha256 body; comment this rationale)
   **Sourcing — claims may only narrow (security invariant):** the script allowlist
   comes from SERVER CONFIG ONLY — per static token (`allowed_script_sha256`) or per
   pool (`pools.<name>.allowed_script_sha256`, applying to identities on that pool).
   It is NEVER read from a JWT claim: a claim that widens privilege is an escalation
   path if it can be emitted from a user-editable Keycloak attribute. Claims that
   narrow (`srh_blocked_commands`) are safe by construction.
   **Gate, not grant:** passing rule 2 does NOT short-circuit; the command still runs
   rules 4–6. So EVAL must also appear in `allowed_commands` when that is Some, and
   is NEVER permitted for `read_only` identities (EVAL is not in READ_COMMANDS) — an
   allowlisted script must not silently make a read-only token read-write.

3. **Arg-level guards**: `XREAD`/`XREADGROUP` — scan args case-insensitively; any arg
   equal to `BLOCK` → deny `{"error":"NOPERM blocking XREAD is not allowed"}`.
   `SORT`/`SORT_RO` with `BY` or `GET` args → deny for identities with `key_prefix`
   (Phase 8) — the `_RO` suffix means read-only with respect to WRITES, not with
   respect to which KEYS it can dereference; same reasoning as EVALSHA in rule 2 —
   for now just leave a marked hook.

4. `identity.blocked_commands`, followed by the implicit default-block set for every
   `!identity.legacy` identity — new-format static AND JWT — see config rules:
   FLUSHALL, FLUSHDB, KEYS, RANDOMKEY, INFO, DBSIZE — unless explicitly listed in
   `allowed_commands` or by the server's explicit ADMIN_ALLOW set; legacy tokens exempt. SCAN remains
   available to rw tokens deliberately: it is the paginated, non-blocking iteration
   primitive, and blocking it pushes users toward worse patterns).

5. `allowed_commands` if Some → must contain the command.

6. `read_only` → must be in `READ_COMMANDS`.

**READ_COMMANDS** (const, uppercase; mirrors Upstash's read-only token which also
blocks SCAN/KEYS/RANDOMKEY; corrected list — GETEX and GETDEL are writes, HELLO
removed, XREAD allowed but rule 3 blocks its blocking form):
```
GET, MGET, GETRANGE, STRLEN, EXISTS, TYPE, TTL, PTTL, EXPIRETIME, PEXPIRETIME,
HGET, HMGET, HGETALL, HKEYS, HVALS, HLEN, HEXISTS, HSTRLEN, HRANDFIELD,
LRANGE, LLEN, LINDEX, LPOS,
SMEMBERS, SISMEMBER, SMISMEMBER, SCARD, SRANDMEMBER, SINTER, SUNION, SDIFF, SINTERCARD,
ZRANGE, ZRANGEBYSCORE, ZRANGEBYLEX, ZREVRANGE, ZREVRANGEBYSCORE, ZREVRANGEBYLEX,
ZSCORE, ZMSCORE, ZCARD, ZCOUNT, ZLEXCOUNT, ZRANK, ZREVRANK, ZRANDMEMBER,
GETBIT, BITCOUNT, BITPOS, BITFIELD_RO,
XRANGE, XREVRANGE, XLEN, XREAD, XINFO,
GEOPOS, GEODIST, GEOHASH, GEOSEARCH,
PFCOUNT, OBJECT, DUMP, TOUCH, TIME, PING, ECHO,
SORT_RO, LCS, SUBSTR
```

Denial: 403 `{"error":"NOPERM this token does not have permission to run '<CMD>'"}`
(single); inside pipelines: 200 with that string in the slot's `error`.

**Rate limiting** (`per_token_commands_per_sec > 0` — the unit is COMMANDS, not
requests; the cost model below is why, and the name says so because someone sizing
"10 requests/sec" from the old rps name would get a token that stalls for minutes
on one legitimate batch): token bucket, capacity 2×rate, refill on access,
exceeded → 429.
**Bucket key: the FULL credential identifier** — the full 32-byte token digest for
static tokens, the full `sub` string for JWTs — NOT `identity.subject` (that is the
8-hex-char log prefix, 32 bits chosen for readability; before debt a prefix
collision meant two tokens transiently sharing a bucket, with debt it means one
token can park another in a multi-second throttle). Add a `bucket_key` field to
Identity; `subject` remains for logs only.
**Cost model matches
the work:** a request is charged `max(1, number_of_commands)` tokens — a
1000-command pipeline costs 1000, not 1, otherwise the "fairness" limit lets one
token drive `rate × max_pipeline_commands` commands/sec through it.
**Debt semantics (required):** the bucket balance MAY go negative. A request is
admitted whenever the balance is > 0 BEFORE charging; the charge is then applied
in full, possibly driving the balance negative, and the token is throttled until
refill brings it positive again. **Rejected requests are NOT charged.** Rationale: a classic bucket can never admit a
request costing more than capacity, which would silently turn the rate limit
into a hard pipeline-size cap (with rps=10/capacity 20, every pipeline over 20
commands would be a permanent 429 — and `@upstash/redis` batches automatically,
so that fires in normal use, not under attack). Debt admits the oversized
pipeline once and makes the sender pay it off in time. Every 429 carries
`Retry-After: ceil(|deficit| / rate)` (minimum 1) so the throttle is legible to
the client — see error.rs.
**Two-stage check:** (a) PRE-parse, immediately after auth: if the balance is
already ≤ 0, reject 429 without reading the body — an already-throttled attacker
is shed at the cheapest point and cannot buy max_body_bytes of JSON parsing for
free; (b) POST-parse: charge `max(1, n)`. Honest clients are charged accurately;
abusive ones pay one body-parse per throttling window at most. Swept by the
Phase 4 background task.
If parsing fails, charge the minimum cost of one command before returning the 400;
otherwise a credential sending only malformed JSON never becomes throttled and can
buy an unlimited number of maximum-size parses.

**Redis-side ACL (Layer B) — document in README, verify in CI job 2:** example
provisioning for an auth-KV pool:
```
ACL SETUSER srh-authkv on >STRONG_PASSWORD ~ww:auth:* +get +set +del +expireat +ttl +ping +command|info
```
Two traps to document alongside it:
- **Key patterns must match the client's ACTUAL key roots.** The
  `@auth/upstash-redis-adapter` writes under seven `user:`-rooted prefixes by
  default; unify them under one root by passing `baseKeyPrefix` (e.g.
  `"ww:auth:"`) in the adapter options — otherwise the pattern above locks the
  client out with NOPERM on every write. A single root is also what makes Phase 8's
  single `key_prefix` expressible.
- **`+command|info` is for the PROXY, not clients.** COMMAND stays in HARD_DENY for
  clients, but Phase 8 runs `COMMAND INFO` at pool build over this same Layer B
  user; without the grant, every properly-provisioned Phase 8 pool fails at startup.
CI job 2 runs the integration suite against a Redis provisioned with a restricted ACL
user and asserts that an EVAL smuggled past a hypothetically-broken Layer A still fails
at Redis with a NOPERM error.

### Phase 5 acceptance
- read_only: GET ok; SET/SCAN/KEYS → 403.
- HELLO → 403 for EVERY identity including admin.
- **Admin surface:** is_admin identity: CONFIG GET → 200, CONFIG SET → 403,
  MODULE LOAD → 403, MIGRATE → 403, SLAVEOF → 403, CLIENT LIST → 200,
  CLIENT KILL → 403 (subcommand-aware allow).
- **Admin gate-not-grant:** is_admin identity WITH `srh_blocked_commands: ["CONFIG"]`
  → CONFIG GET → 403 (a narrowing claim applies even to ADMIN_ALLOW commands).
- MEMORY USAGE: admin → 200, read_only token → 403, rw token → 403 (HARD_DENY;
  only the ADMIN_ALLOW path reaches it). DBSIZE: new-format rw → 403, legacy → 200.
- SORT_RO with BY/GET on a key_prefix identity → 403 (Phase 8 wiring; unit-test the
  rule-3 hook now).
- SELECT/SUBSCRIBE/BLPOP/WAIT → 403 for every identity.
- New-format rw token: FLUSHALL → 403; KEYS → 403; INFO → 403; SCAN → 200.
  Legacy token: FLUSHALL → 200, KEYS → 200 (parity tests).
- CONFIG GET → 403 for non-admin identities.
- allowed_commands=["GET"]: GET ok, MGET 403.
- EVAL with matching sha256 in a CONFIG-sourced allowlist AND EVAL present in
  allowed_commands → passes Layer A; same script on a read_only identity → 403;
  same script when allowed_commands=["GET","SET"] (no EVAL) → 403;
  EVAL not allowlisted → 403; EVALSHA → 403 even with allowlist.
- XREAD without BLOCK → allowed (ro token); XREAD ... BLOCK 0 ... → 403.
- Pipeline mixed allowed/denied per Phase 3.
- Burst over the rate → 429. **Pipeline cost with debt:** token with
  per_token_commands_per_sec=10 (capacity 20): a single 100-command pipeline is
  ADMITTED (balance was positive) and drives the balance to −80; the immediate
  next request → 429 at the PRE-parse stage (balance ≤ 0, body never read —
  assert via a body that would fail parsing) with `Retry-After: 8` (ceil(80/10));
  after ~8s of refill the token works again. By contrast, 100 sequential singles
  succeed for the first ~20 and then 429 (rejected requests are NOT charged, so
  the balance floors near 0 and the deep deficit never forms). The asymmetry is
  the debt model's deliberate trade: batches get burst admission and pay it back
  in throttle time; amortized throughput converges to the configured rate for
  both workloads.
- **Bucket isolation:** two static tokens crafted to share the same 8-hex-char
  digest prefix: driving one into deep debt leaves the other unthrottled (buckets
  keyed on full digest, not the log subject).

---

## Phase 6 — JWT auth via Keycloak (adapters/jwt_auth.rs, adapters/http_jwks.rs)

`JwtAuth` implements `Authenticator` and depends on `Arc<dyn JwksSource>` (and
`Arc<dyn Introspector>` when enabled) — NOT on the HTTP client. All Phase 6 unit tests run
against `FakeJwks`; wiremock is used only in the integration tests that exercise
`HttpJwks` itself.

### adapters/http_jwks.rs (implements JwksSource)
- Lazy: on first JWT request fetch `<issuer>/.well-known/openid-configuration` →
  `jwks_uri` → JWKS. Cache `HashMap<kid, CachedKey>` in `RwLock` with `fetched_at`.
- `CachedKey { decoding_key: DecodingKey, alg: Algorithm }` — **the allowed algorithm
  is derived from the JWK itself** (its `alg` field, or from `kty`+`crv`: RSA→RS256
  family per `alg`, EC P-256→ES256, P-384→ES384). If a JWK has no `alg` and kty=RSA,
  default RS256. Ignore JWKs with `kty` other than RSA/EC, AND ignore JWKs where
  `use` is present and != `"sig"` or where `key_ops` is present and lacks
  `"verify"` — Keycloak publishes RSA-OAEP ENCRYPTION keys in the same JWKS with
  the same kty; ingesting one produces baffling verification failures on kid
  collision.
- Refresh when kid unknown (≤1 forced refresh per 30s) or age > `jwks_refresh_secs`.
- Transport: `hyper` + `hyper-util`'s pooling client over `hyper-rustls`
  (`rustls-native-certs` roots, ring provider — matching fred). 5s timeout via
  `tokio::time::timeout`. Bound the response body with `http_body_util::Limited` before
  parsing: a JWKS reply has a known small size, and "everything bounded" applies to
  outbound responses too. Redirects are NOT followed — a discovery document or JWKS URI
  that redirects is a misconfiguration worth surfacing, not silently chasing.

### adapters/jwt_auth.rs — validation
- Parse header for `kid` ONLY. Resolve the cached key.
- Build `Validation` with `algorithms = [cached_key.alg]` — **never take the algorithm
  from the token header** (attacker-controlled; this closes alg-confusion including
  `none` and HS256-with-public-key). Any header/key alg mismatch fails verification
  naturally.
- Validate: signature; `iss` exact match; `exp`/`nbf` with 30s leeway; audience:
  `aud` contains config audience OR `azp == audience` (Keycloak default omits custom
  aud unless a mapper adds it); **`typ` claim must equal `"Bearer"`** — rejects ID
  tokens and refresh tokens. (Correct for stock Keycloak access tokens; NOTE in the
  README that a realm/client-scope override of the token type would make this a
  deployment-wide hard 401 — verify against the target realm's actual tokens during
  rollout, since this is the one check that fails closed on an IdP CONFIG change
  rather than a code change.)
- Claims → Identity:
  - `subject` = `sub`; roles from `resource_access[client_id].roles` filtered by
    `role_prefix`:
    - `redis:read` → read_only=true
    - `redis:write` → read_only=false
    - `redis:admin` → read_only=false, is_admin=true (grants the explicit
      ADMIN_ALLOW set per Phase 5 rule 1 — HARD_DENY remains absolute)
    - none → 403 `{"error":"NOPERM no redis role"}`
  - `pool` = claim `srh_pool`, else `"default"` if configured, else 403. Must exist.
  - `srh_blocked_commands` (optional array) → blocked_commands. **Claims may only
    NARROW privileges** — this is the invariant that makes claim mappers safe even
    if misconfigured. Widening data (script allowlists) lives in server config only
    (Phase 5 rule 2); a widening claim sourced from a user-editable Keycloak
    attribute would be self-service privilege escalation.
  - `srh_pool` must be emitted by an ADMIN-controlled protocol mapper (client scope
    or role-based), never a user-editable attribute — pool selection is adjacent to
    widening. Document this in the Keycloak setup section of the README. **Admin
    identities need a pool to match:** ADMIN_ALLOW is decorative unless the
    `srh_pool` for `redis:admin` identities points at a pool whose Layer B Redis
    user actually holds those grants (`+config|get +client|list +client|info
    +slowlog|get +info +latency|history +memory|usage ...`) — on a
    least-privilege pool like the authkv example, admin commands pass Layer A and
    get NOPERM from Redis.
  - `srh_key_prefix` → stored (Phase 8).
- Do NOT cache positive verifications; verification is CPU-only and cheap.

### Introspection (RFC 7662, config-gated, default OFF)
When enabled: after local validation, POST introspection with client credentials;
`active:false` → 401. Cache boolean per sha256(token) for `cache_secs`, in a bounded
map: cap 100k entries, LRU-evicted by the 60s background sweep (same "everything
bounded" rule as the rate buckets — token-spraying must not grow it without limit).
Endpoint
unreachable → 503 `AuthServiceUnavailable` (fail closed — enabling introspection means
choosing revocation over availability; the availability escape hatch is a break-glass
static token, below, not fail-open).

**Break-glass pattern (README, not code):** deployments using JWT for primary access
SHOULD configure one high-entropy static `sha256:` token, tightly scoped
(allowed_commands, own pool), stored offline, so operators retain KV access during an
IdP outage. The auth chain already supports static+JWT side by side.

### Phase 6 acceptance (wiremock JWKS + locally minted tokens; no live Keycloak)
- Valid RS256 + redis:write → SET 200.
- Token header claims alg=HS256 (signed however) → 401; token header alg=none → 401.
- Token signed with a DIFFERENT valid algorithm than the JWK's declared alg → 401.
- Expired / wrong iss / wrong aud+azp / `typ:"ID"` → 401 each.
- redis:read → SET 403, GET 200. No role → 403.
- **JWT gets the defaults:** valid redis:write token → FLUSHALL 403, KEYS 403,
  SCAN 200 (the implicit block set applies to JWT identities — a Keycloak identity
  is never more privileged than a new-format static token).
- Unknown kid → exactly one JWKS refetch, then 401; second unknown-kid within 30s does
  NOT trigger another fetch (assert via wiremock request count).
- Static tokens continue working alongside.
- Introspection enabled + wiremock down → 503.

---

## Phase 7 — Hardening, observability, packaging

**Implementation status: complete (2026-08-08).**

- **Audit log**: one `tracing::info!` per request: `subject`, `pool`, `command` (name
  only — NEVER args), `status`, `latency_ms`, `pipeline_len`. No bodies at info level.
- **/health**: liveness, no Redis I/O (Phase 1). **/ready**: responds ONLY when the
  request's peer address is loopback (else 404) — NOTE: axum only exposes a peer
  address when served via
  `into_make_service_with_connect_info::<SocketAddr>()`; without that wiring the
  extractor fails and /ready silently 404s for everyone, including systemd. Performs
  a real `PING` on each
  configured pool that has been built via `ExecutorProvider::readiness()` (the
  method exists for this endpoint alone and does NOT force-build pools); 200
  `{"status":"ready","pools":{...}}` or 503 with per-pool status. For systemd/LB checks.
- **Metrics — NOT feature-gated, always compiled**: Prometheus on `metrics_bind`
  (loopback default): request count by endpoint+status, latency histogram, per-pool
  active connections gauge, pool builds/evictions, auth failures by kind, rate-limit
  rejections — plus saturation observability: global in-flight gauge, per-pool
  permits-in-use and waiter-depth gauges, shed counter by cause
  (global_limit | pool_queue_full | acquire_timeout | breaker_open | response_too_large),
  breaker state gauge per pool (0=closed 1=half 2=open). The shed-by-cause counter is
  what tells you WHICH bound is the bottleneck when you're bending; without it,
  capacity tuning is guesswork. Metrics server itself never routes through the
  admission stack.
- **Artifacts — two first-class outputs:**
  1. **Static binary**: `x86_64-unknown-linux-musl`, `--release`, stripped. This is the
     primary deployment artifact for native hosts.
  2. **Docker image**: multi-stage (cargo-chef → scratch/distroless-static), non-root
     USER, `ENV SRH_BIND=0.0.0.0`, EXPOSE 80. Must run the legacy README docker command
     verbatim. CI publishes with digest; downstream consumers pin by digest, never
     `:latest`.
- **systemd unit** (ship in `deploy/srh-rs.service`):
  ```ini
  [Service]
  ExecStart=/usr/local/bin/srh-rs
  Environment=SRH_CONFIG_PATH=/etc/srh-rs/tokens.json
  DynamicUser=yes
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  NoNewPrivileges=yes
  CapabilityBoundingSet=
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  SystemCallFilter=@system-service
  Restart=on-failure
  ```
  Config file mode 0600, owned by root, readable via `LoadCredential` or group ACL —
  document both options. Bind loopback; TLS/WAF terminate at the host reverse proxy.
- **Deployment checklist (README, verify before shipping to any shared host):**
  - The Redis holding sessions/auth data runs `maxmemory-policy noeviction` and AOF
    persistence — otherwise sessions are evicted under memory pressure (random
    signouts) or lost on restart. Verify with `CONFIG GET maxmemory-policy`.
  - Prefer a dedicated Redis instance for auth KV; minimum: dedicated DB index +
    Redis-side ACL user (Layer B) + Phase 8 prefix enforcement.
  - Redis must not be reachable except from the proxy host (bind/network policy) and
    must have AUTH/ACL configured — the proxy ACL is not the security boundary.
  - Set `proto-max-bulk-len` on the Redis server to bound raw reply/argument bulk
    sizes at the source — the proxy's response budget bounds AMPLIFICATION, not the
    raw reply, which fred has fully buffered before conversion begins (see Phase 2).
  - The proxy's rate limiter is per-IDENTITY and runs post-auth, so JWT signature
    verification itself is unmetered (bounded only by max_in_flight). Acceptable for
    a loopback-bound service, but the fronting reverse proxy must carry the per-IP
    rate limit — the proxy cannot see an attacker until after the signature check.
- **CI (GitHub Actions), three jobs:**
  1. `cargo fmt --check`, `clippy -D warnings`, `cargo test`.
  2. Integration: redis:7 provisioned with a restricted ACL user; run the repo's
     integration suite including the Layer B assertion (Phase 5).
  3. **Upstash parity gate**: services `redis/redis-stack-server:6.2.6-v6` + built
     image (SRH_MODE=env, SRH_TOKEN=example_token); container `denoland/deno`; checkout
     `upstash/upstash-redis`; `deno test -A ./pkg` with
     `UPSTASH_REDIS_REST_URL=http://srh:80`. Failures attributable ONLY to §1.7 items
     get documented skip-list entries; anything else is a bug.

### Phase 7 acceptance
- All CI jobs green; legacy docker command works; image < 25 MB; musl binary runs on a
  clean debian container with no shared-lib deps (`ldd` reports "not a dynamic
  executable").
- `/ready` from loopback reflects real pool state; from non-loopback → 404.

---

## Phase 8 — Key-prefix isolation (NOT in the initial delivery)

**Delivery scope:** OUT of the first delivery. The first target deployment satisfies
this phase's own conditionality below (dedicated DB index + Layer B ACL key patterns
+ a single client-side key root); build Phases 1–7 and 9, ship, and pick this up only
if a shared-keyspace deployment materializes.

**Conditionality:** OPTIONAL when every pool points at a dedicated Redis instance (or
dedicated DB index + Layer B ACL with key patterns). **MANDATORY** when any identity's
pool shares a keyspace with other applications.

For identities with `key_prefix`, when built:
- **Discovery is lazy and per-command, not enumerated.** "At pool build" means at
  LAZY build time (first request — the Phase 4 no-startup-I/O property is preserved),
  and even then no bulk enumeration: `COMMAND` with no args and `COMMAND DOCS` are
  denied to a properly-provisioned Layer B user, whose grant is `+command|info`.
  Instead, on first use of each distinct command name by a prefixed identity, query
  `COMMAND INFO <name>` over that pool, cache the key-position spec
  (first_key/last_key/step) in a bounded per-pool map, and reuse it thereafter.
- **Fail closed:** a command that is unknown to the server (COMMAND INFO returns
  nil), has the `movablekeys` flag, or reports `first_key = 0` (no fixed key
  positions) → 403 for prefixed identities. If `COMMAND INFO` itself fails
  (transport error, or NOPERM from a misprovisioned Layer B user), deny the request
  with 403 and log a loud warning naming the missing grant — never fall through to
  unvalidated execution.
- Per request, every key-position arg must start with the prefix → else 403
  `{"error":"NOPERM key outside allowed prefix"}`.
- Commands with dynamic key specs (EVAL family — already gated, SORT/SORT_RO with
  BY/GET,
  GEORADIUS* with STORE, XREAD multi-stream, COPY, RENAME across prefix, etc.) →
  denied for prefixed identities. Validate only; never rewrite keys.
- Note: Redis-side ACL key patterns (`~prefix:*`) provide the same guarantee at Layer B
  and should be configured regardless; this phase makes the failure mode a clean proxy
  403 instead of a Redis NOPERM mid-pipeline.

---

## Phase 9 — Load handling verification (bend-not-break gate)

**Implementation status: complete (2026-08-09).**

Most of the machinery is built in Phases 1/4 (admission stack, bounded pool queues,
breaker, response budget). This phase verifies the SYSTEM property under real load and
adds the last pieces.

### Degradation model (protection PRIORITY — not execution order)

Under rising load the proxy sheds via these protections, each shed cheaper than the
work it replaces (listed by what each protects, most-targeted first):
1. Per-token rate limit (429) — protects fairness between tokens.
2. Per-pool queue bound / acquire timeout (503) — protects accepted-request latency.
3. Global in-flight cap via load_shed (503) — protects proxy memory/CPU; triggers
   before body read.
4. Circuit breaker (503, fast) — protects against backend-down timeout pileups.
5. Response budget (502) — protects against single-request memory blowups.

The RUNTIME execution order per request is different, and implementers should build
to this sequence (each check at its cheapest feasible point):
```
accept → load_shed + in-flight cap (pre-body) → auth →
rate limit stage (a): pre-parse probe, reject if balance ≤ 0 →
body read (body_read_timeout) → parse →
rate limit stage (b): charge max(1, n) →
ACL → pool acquire [breaker check → waiter bound → semaphore] →
execute (fred command timeout) → convert (response budget) → respond
```
The rate check cannot precede body read in full — counting commands requires the
parse — which is exactly why it is split into the two stages of Phase 5.

Invariants that define "bending": accepted requests keep bounded latency; rejected
requests are fast (<5ms) and honest (correct status + Retry-After); memory is flat;
`/health`, `/ready`, metrics always answer; the system returns to full service with no
restart when load subsides.

### Remaining implementation items
- Retry-After header on every 503-family response (verify it made it through the
  HandleErrorLayer path, not just AppError's own IntoResponse).
- Rate-bucket and waiter maps: cap total entries (e.g. 100k) and evict LRU in the 60s
  sweep — per-identity state must not grow unboundedly under token-spraying.
  **Debt-aware eviction:** the sweep must NEVER evict a bucket with a negative
  balance — evicting a deficit hands the token a clean slate, so idle-based LRU
  (written when balances were non-negative and dropping one was free) now forgives
  up to `max_pipeline_commands / rate` seconds of throttle to anyone who goes
  quiet. Evict only non-negative entries in the normal sweep. If the 100k cap is
  GENUINELY hit and only negative entries remain, evict oldest-negative first and
  count each in the shed-by-cause metric (`debt_forgiven_by_eviction`) — bounded,
  visible forgiveness under adversarial spraying instead of silent forgiveness in
  normal operation.
- Socket options: TCP_NODELAY on accepted connections (hyper default — verify), and
  document `somaxconn`/listen backlog in the deployment README.

### Phase 9 acceptance (scripted in CI as a nightly job, `oha` or `vegeta`)
- **Overload test:** capacity-size the proxy (e.g. max_in_flight=64, one pool
  max_connections=4 against local Redis), then drive 4× estimated capacity for 60s.
  Assert: (a) RSS growth < 20% over the run and returns to baseline after; (b) every
  response is 200 or 503-with-Retry-After — zero connection resets, zero 5xx other
  than 503; (c) p99 of the 200s stays under 5× the unloaded p99; (d) p99 of the 503s
  < 10ms; (e) after load stops, 100 sequential requests all return 200 with correct
  values (no desync, no restart needed).
- **Backend-death-under-load test:** same load profile; at t=20s SIGSTOP the Redis
  container; assert error responses transition to fast breaker 503s within 5s (no
  window where p99 ≈ command_timeout pileup longer than that); at t=40s SIGCONT;
  assert 200-rate recovers to baseline within 10s with no proxy restart.
- **Slow-client test:** open `max_in_flight` (the configured value, not 50)
  connections that send headers then trickle the body one byte per second; assert
  each is terminated by the body-read timeout (~2s, 408) rather than surviving to
  http_timeout. Run it in two stages: (a) attack alone — assert the per-pool
  permits-in-use gauge stays 0 for the entire attack (a real assertion via the
  metrics endpoint, replacing the code-review note: permits are acquired only after
  the body is parsed); (b) attack plus concurrent normal traffic — assert the
  normal traffic's p99 stays within 2× baseline (i.e. the attack does not
  exhaust the in-flight slots for real users).

---

## Non-goals (do not build)

- Path-based commands, token in query param
- RESP3 to clients or upstream; pub/sub; blocking semantics (denied, per Phase 5)
- Cluster-aware routing (fred handles sentinel strings natively if provided)
- Web UI; config hot-reload (log a note; future work)

## Global engineering rules

- No `unwrap()`/`expect()` outside tests and startup validation.
- All handlers return `Result<_, AppError>`.
- `#![forbid(unsafe_code)]`; clippy clean with `-D warnings`.
- Doc comments + unit tests for every public fn in convert.rs, acl.rs, auth/*.
- Never log tokens, JWTs, connection strings, command arguments, or Upstash-Telemetry
  headers.
- Verify all dependency API names against docs.rs for locked versions before use.
- **Everything bounded:** no unbounded channels, queues, caches, or maps anywhere; any
  collection keyed by client-controlled input (tokens, subjects) has a max size and an
  eviction path. If a bound seems unnecessary, add it anyway and make it large.
- **Never block the runtime:** no std blocking I/O on tokio threads; no std lock guard
  held across `.await`; CPU work >1ms goes to `spawn_blocking`.
- Reject before you buffer: every limit check happens at the cheapest possible point
  (before body read where feasible, before Redis work always).
- **Architecture rules (§0.5) are normative:** dependency rule enforced by CI grep;
  exactly the five listed ports; decorators over modification for cross-cutting
  executor behavior; business rules live in `domain/` only; fakes must pass the same
  contract suites as real adapters.

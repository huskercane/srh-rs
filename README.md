# srh-rs

An Upstash-compatible Redis HTTP proxy, in Rust.

`srh-rs` speaks the [`@upstash/redis`](https://github.com/upstash/upstash-redis) REST wire
protocol in front of a plain Redis server, so serverless and edge runtimes that can only make
HTTP requests can use a Redis you host yourself. It is a rewrite of
[hiett/serverless-redis-http](https://github.com/hiett/serverless-redis-http) (SRH) with a
hardened security model: Keycloak JWT auth, per-token command ACLs, read-only tokens, script
allowlisting, per-identity rate limiting, bounded pool queues, and circuit breaking.

Wire compatibility with the `@upstash/redis` SDK is the top-level design requirement.

> ### Status: specification-complete, implementation in progress
>
> Phases 0–4 are implemented: the architecture scaffold, configuration, static-token
> authentication, admission controls, RESP conversion, and all three Redis execution routes are
> working with lazy bounded pools, Fred-level timeouts, circuit breaking, and idle eviction.
> Command ACLs remain permissive until Phase 5. The normative
> specification is [`srh-rust-spec.md`](./srh-rust-spec.md), which defines ten phases; this
> README documents the system that spec describes.
>
> | Phase | Scope | Status |
> |---|---|---|
> | 0 | Project setup, hexagonal skeleton, ports | Done |
> | 1 | Config, errors, static auth, HTTP skeleton | Done |
> | 2 | RESP↔JSON conversion, `POST /` | Done |
> | 3 | `POST /pipeline`, `POST /multi-exec` | Done |
> | 4 | Lazy pools, timeouts, circuit breaker, eviction | Done |
> | 5 | Command ACLs, rate limiting | Not started |
> | 6 | Keycloak JWT auth, JWKS, introspection | Not started |
> | 7 | Hardening, observability, packaging | Not started |
> | 8 | Key-prefix isolation | Deferred — out of the first delivery |
> | 9 | Load-handling verification | Not started |
>
> Treat every command, config key, and endpoint below as the target contract, not as
> documentation of running software.

---

## Why not just use SRH

The original SRH is a single shared token with full access to a Redis. That is fine for local
development, which is what it was built for. `srh-rs` targets shared and production hosts,
where the proxy is an authorization boundary:

- **Identity, not a password.** Keycloak JWTs with `redis:read` / `redis:write` / `redis:admin`
  roles, alongside static tokens for machine access and break-glass.
- **Least privilege per token.** Per-identity pool routing, command allowlists and blocklists,
  read-only tokens, and script allowlisting.
- **Defense in depth.** The proxy ACL is deliberately *not* the security boundary — each pool
  authenticates to Redis as a restricted Redis ACL user, which is what actually holds when a
  Lua script runs server-side.
- **Bend, don't break.** Bounded pool queues, per-identity rate limits with debt, a per-pool
  circuit breaker, a response-size budget, and admission control that sheds cheaply rather
  than queueing.

Legacy SRH token files are still supported, and legacy tokens keep their original permissions
so existing deployments migrate unchanged.

---

## Quick start

### Environment mode

The simplest configuration — one Redis, one token:

```bash
docker run -d -p 8079:80 --name srh \
  -e SRH_MODE=env \
  -e SRH_TOKEN=your_token_here \
  -e SRH_CONNECTION_STRING="redis://your_server:6379" \
  ghcr.io/<owner>/srh-rs:<digest>
```

Then point the SDK at it:

```ts
import { Redis } from "@upstash/redis";

const redis = new Redis({
  url: "http://localhost:8079",
  token: "your_token_here",
});

await redis.set("foo", "bar");
await redis.get("foo"); // "bar"
```

Pin images by digest, never by `:latest`.

### File mode

For anything beyond one token and one Redis, use a config file (`SRH_MODE=file`, the default).
See [Configuration](#configuration).

---

## Wire protocol

### Endpoints

Only three. Any other path returns 404 `{"error":"Not found"}`; any non-POST method returns
405 `{"error":"Method not allowed"}`.

| Endpoint | Body | Behavior |
|---|---|---|
| `POST /` | One command as a JSON array — `["SET","foo","bar","EX",100]` | Runs one command |
| `POST /pipeline` | JSON array of command arrays | Pipelined; a failing command does not abort the rest; always HTTP 200 |
| `POST /multi-exec` | JSON array of command arrays | `MULTI`/`EXEC`; atomic |

### Authentication

`Authorization: Bearer <token>`, where the token is either a static token or a Keycloak
access token. Missing or invalid credentials return 401 `{"error":"Unauthorized"}`.

Tokens in query parameters and path-based commands are deliberately not supported.

Unrecognized headers are ignored rather than rejected — including `upstash-sync-token`
(which the SDK sends by default, since `readYourWrites` is on) and any `Upstash-Telemetry-*`
header. `Authorization` and telemetry header values are never logged.

### Argument encoding

Each element of the request array becomes one Redis argument. The first element is the
command name and must be a non-empty string, otherwise the request is 400
`{"error":"Invalid command"}`.

| JSON | Redis argument |
|---|---|
| string | raw bytes as-is |
| number | canonical string — `100` → `"100"`, `1.5` → `"1.5"` |
| boolean | `"true"` / `"false"` |
| null | `"null"` |
| object / array | its JSON serialization |

### Responses

Connections are RESP2. Replies map to JSON as simple string → string, bulk string → string,
integer → number, nil → null, array → array (recursively).

| Case | Response |
|---|---|
| Single command, success | 200 `{"result": <value>}` |
| Single command, Redis error | 400 `{"error":"<raw Redis error, prefix included>"}` |
| Pipeline | 200, an ordered array of `{"result":…}` / `{"error":…}` |
| Multi-exec, success | 200, array mapped 1:1 from the `EXEC` reply |
| Multi-exec, queue or exec failure | `DISCARD`, then 400 with the raw error |

Redis errors are passed through verbatim, including the `WRONGTYPE`/`NOPERM`/`ERR` prefix,
because clients pattern-match on them.

### Base64 encoding

When the request carries `Upstash-Encoding: base64` (the SDK sends it by default), bulk
values and simple strings are base64-encoded with the standard padded alphabet. The exact
simple-string reply `OK` is left as `"OK"`. Numbers, booleans, and nulls are unchanged;
arrays recurse; the `error` field is never encoded.

Encoding is applied to the original raw reply bytes, so binary values round-trip exactly.
Without the header, a non-UTF-8 bulk value is lossily converted to a UTF-8 string — if you
store binary data, send the header.

### Status codes

| Code | Body | Meaning |
|---|---|---|
| 400 | `{"error":"<raw>"}` | Redis error, malformed request, `Invalid command`, `Pipeline too large` |
| 401 | `{"error":"Unauthorized"}` | Missing, malformed, or unverifiable credentials |
| 403 | `{"error":"NOPERM …"}` | Authenticated but not permitted to run this command |
| 408 | `{"error":"Request body timeout"}` | Request body was not received within `body_read_timeout_ms` |
| 429 | `{"error":…}` + `Retry-After` | Per-identity rate limit; see [rate sizing](#rate-limit-sizing) |
| 500 | `{"error":"Internal server error"}` | Unexpected failure; details go to the log, not the client |
| 502 | `{"error":"Response too large"}` | Reply exceeded the response budget |
| 503 | `{"error":"Server overloaded"}` + `Retry-After` | Admission control shed the request |
| 503 | `{"error":"Backend unavailable"}` + `Retry-After` | Circuit breaker is open for this pool |
| 503 | `{"error":…}` | Introspection endpoint unreachable while introspection is enabled |

**502 is indeterminate, not a rollback.** The commands did execute on Redis; only the
response could not be rendered. Treat it the way you would treat a timeout after send. It
fails the whole request on every endpoint, including `/pipeline`, which otherwise always
returns 200.

### Deliberate differences from Upstash

These are intentional and will not be "fixed":

- `UNLINK` with zero keys returns the real Redis error rather than a synthesized success.
- `ZRANGE` requires `BYSCORE` or `BYLEX` in order to use `LIMIT`.
- RedisJSON responses may differ subtly.
- In base64 mode, a bulk value containing exactly `OK` inside `/multi-exec` is returned as
  `"OK"`, not `"T0s="`. Fred's public transaction API does not preserve simple-vs-bulk framing.
- Redis transactions do not roll back commands after an EXEC-time command error. The endpoint
  returns 400 with that error and omits successful slot results, but other commands may commit.

---

## Configuration

`SRH_MODE` selects the source: `file` (default) or `env`.

### Environment mode

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `SRH_TOKEN` | yes | — | The single static token |
| `SRH_CONNECTION_STRING` | yes | — | Redis URL (`redis://` or `rediss://`) |
| `SRH_MAX_CONNECTIONS` | no | 3 | Pool size |

This normalizes to one pool named `default` and one read-write static token.

### Process-level overrides

| Variable | Default | Meaning |
|---|---|---|
| `SRH_CONFIG_PATH` | `./srh-config/tokens.json` | Config file location (file mode) |
| `SRH_BIND` | `127.0.0.1` | Listen address |
| `SRH_PORT` | `80` | Listen port |
| `SRH_IPV6` | unset | `true` → `::1`, or `::` when `SRH_BIND=0.0.0.0` |
| `SRH_LOG_FORMAT` | text | `json` for structured logs |

The bind default is loopback on purpose. The Docker image sets `SRH_BIND=0.0.0.0` because it
has its own network namespace. Binding a non-loopback address without TLS logs a warning.

### Legacy file format

Each top-level key is a token. This is the original SRH format and is detected automatically
by the presence of `connection_string` in the values.

```json
{
  "example_token": {
    "srh_id": "id",
    "connection_string": "redis://localhost:6379",
    "max_connections": 3
  }
}
```

Legacy tokens are read-write and **keep `FLUSHALL`/`FLUSHDB` rights**, matching original SRH
behavior. They are the only identities exempt from the default block set below.

### Current file format

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
      "introspection": {
        "enabled": false,
        "url": "",
        "client_id": "",
        "client_secret": "",
        "cache_secs": 30
      }
    },
    "static_tokens": {
      "sha256:ab12…": {
        "pool": "authkv",
        "read_only": false,
        "allowed_commands": ["GET", "SET", "DEL", "EXPIREAT"],
        "blocked_commands": [],
        "allowed_script_sha256": []
      }
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
    "local": {
      "connection_string": "redis://localhost:6379",
      "max_connections": 3,
      "command_timeout_ms": 2000
    }
  }
}
```

**Static token keys are digests.** A `sha256:<hex>` key is the SHA-256 of the real token.
Plaintext keys are accepted as a development convenience but are hashed at load and the
plaintext is dropped — the running process holds only 32-byte digests. Every example in this
README uses `sha256:` deliberately, because examples get copied into production configs.

Compute one with:

```bash
printf %s 'your_token_here' | sha256sum
```

**Defaults.** `command_timeout_ms` 2000, `acquire_timeout_ms` 500, `max_waiters` 4 ×
`max_connections`, `breaker.failure_threshold` 10 consecutive failures,
`breaker.cooldown_ms` 2000. Every bound must be finite: `0` is a startup validation error,
never "unlimited". `max_pipeline_commands` bounds commands in a pipeline;
`max_request_elements` independently bounds all JSON value nodes and object keys across one
request, including nested array/object arguments. A single large MGET can therefore use the
whole element budget without raising the pipeline command cap.

**`server.tls`** takes `{cert, key}` paths and is optional; absent means plain HTTP. TLS here
is low priority — the intended deployment terminates TLS at a reverse proxy.

**Startup validation** rejects the config and exits with a clear message if any token
references a missing pool, the issuer is not a valid URL, a bound is zero, or — for any pool
— `acquire_timeout_ms + 2 * command_timeout_ms >= http_timeout_ms`. The second command-timeout
budget covers the bounded forced connection reset after Fred reports a timeout. Without it,
the HTTP backstop could drop a handler while its connection was still being reset.

Secrets (`connection_string`, `client_secret`) are held in a wrapper whose `Debug` output is
`<redacted>` and which zeroizes on drop.

### Timeout budgeting

A client's worst case for one logical operation is:

```
retries × (acquire_timeout_ms + 2 × command_timeout_ms)
```

Size pool timeouts so that product fits inside the *caller's* deadline. An auth-refresh path
with an 8-second budget, using an SDK that makes 3 attempts, needs less than 2.67 s per attempt
— which is why the `authkv` example totals `250 + 2 × 1000 = 2250` ms rather than the
defaults' 4500 ms.

### Rate limit sizing

`per_token_commands_per_sec` is a **command** budget, not a request budget; `0` disables it.
A request costs `max(1, number_of_commands)`, so a 1000-command pipeline costs 1000. Without
that, one token could drive `rate × max_pipeline_commands` commands per second through a limit
nominally set much lower.

The bucket holds `2 × rate` and **may go negative**. A request is admitted whenever the
balance is positive beforehand; the full charge is then applied, possibly leaving a deficit,
and the token is throttled until refill clears it. Rejected requests are not charged. This
matters because a classic bucket can never admit a request costing more than its capacity —
with a rate of 10, every pipeline over 20 commands would be a permanent 429, and the SDK
batches automatically, so that would fire in normal use rather than under attack.

The practical consequence: worst-case throttle after one maximum-size pipeline is
`max_pipeline_commands / rate` seconds. Size the rate against the token's peak *command*
throughput including SDK auto-batching. Every 429 carries
`Retry-After: ceil(|deficit| / rate)` so clients can back off deliberately instead of
burning their retries inside a deficit they cannot see.

---

## Security model

### Two layers

**Layer A — the proxy ACL** screens `argv[0]` on every command. It is fast and it is defense
in depth, but it is **not** the security boundary, because `EVAL` runs commands server-side
where the proxy cannot see them.

**Layer B — the Redis ACL** is the boundary that actually holds. Each pool's connection string
authenticates as a restricted Redis user, and Lua `redis.call` is subject to that user's ACL.
Provision it for every pool:

```
ACL SETUSER srh-authkv on >STRONG_PASSWORD ~ww:auth:* \
  +get +set +del +expireat +ttl +ping +command|info
```

Two traps worth knowing before you copy that:

- **Key patterns must match the client's actual key roots.** `@auth/upstash-redis-adapter`
  writes under seven separate `user:`-rooted prefixes by default. Pass `baseKeyPrefix` (for
  example `"ww:auth:"`) in the adapter options to unify them, or the pattern above locks the
  client out with `NOPERM` on every write.
- **`+command|info` is for the proxy, not for clients.** `COMMAND` stays denied to clients,
  but key-prefix isolation (Phase 8) runs `COMMAND INFO` over this same Redis user. Without
  the grant, a properly provisioned pool fails at first use.

### Command policy

Denials return 403 `{"error":"NOPERM this token does not have permission to run '<CMD>'"}`.
Inside a pipeline the request is still 200 and that string appears in the failing slot.

**Always denied, for every identity including admin.** Server and topology control (`CONFIG`,
`SHUTDOWN`, `DEBUG`, `SLAVEOF`/`REPLICAOF`, `MIGRATE`, `MODULE`, `SAVE`, `BGSAVE`,
`BGREWRITEAOF`, `LASTSAVE`, `ACL`, `CLIENT`, `CLUSTER`, `LATENCY`, `MONITOR`, `PSYNC`, `SYNC`,
`FAILOVER`, `RESET`, `SLOWLOG`, `COMMAND`, `MEMORY`); connection state that would corrupt a
pooled connection for its next user (`HELLO`, `SELECT`, `SWAPDB`, `AUTH`, `QUIT`); pub/sub;
blocking commands, which would pin a pool connection indefinitely (`BLPOP`, `BRPOP`, `BLMOVE`,
`BRPOPLPUSH`, `BLMPOP`, `BZPOPMIN`, `BZPOPMAX`, `BZMPOP`, `WAIT`, `WAITAOF`); and `SCRIPT` /
`FUNCTION`, which are handled by the scripting rule below.

**Blocked by default, for every non-legacy identity** — every JWT identity and every
current-format static token — unless explicitly listed in that identity's `allowed_commands`:
`FLUSHALL`, `FLUSHDB`, `KEYS`, `RANDOMKEY`, `INFO`, `DBSIZE`. These are destructive or
whole-keyspace against a possibly shared Redis. `SCAN` stays available to read-write tokens
deliberately: it is the paginated, non-blocking iteration primitive, and blocking it pushes
people toward worse patterns.

A `redis:write` JWT is never more privileged than a current-format static token. Only
legacy-format tokens are exempt, for original-SRH parity.

**Admin identities** (`redis:admin`) get a small, explicit allowlist rather than an exemption:
`CONFIG GET`, `CLIENT LIST`, `CLIENT INFO`, `SLOWLOG GET`, `SLOWLOG LEN`, `INFO`,
`COMMAND COUNT`, `COMMAND INFO`, `COMMAND DOCS`, `LATENCY HISTORY`, `LATENCY LATEST`,
`MEMORY USAGE`, `MEMORY STATS`, `MEMORY DOCTOR`, `ACL WHOAMI`. It is matched on the
subcommand, so `CONFIG GET` is allowed while `CONFIG SET` is not. An
exemption-with-carve-outs would make every command Redis adds in future admin-allowed by
default; an allowlist fails safe.

Admin access is also a *gate, not a grant*: matching the allowlist only exempts a command from
the hard-deny list. It still passes through the identity's own blocklist, `allowed_commands`,
and `read_only` check.

Note that admin commands still have to survive Layer B. On a least-privilege pool like the
`authkv` example, they pass Layer A and get `NOPERM` from Redis — an admin identity needs an
`srh_pool` whose Redis user actually holds those grants.

**Read-only identities** are restricted to a fixed read-command list. `GETEX` and `GETDEL`
count as writes. `XREAD` is allowed, but its blocking form is rejected regardless of identity.

### Scripting

`EVAL`, `EVAL_RO`, `EVALSHA`, `EVALSHA_RO`, `FCALL`, and `FCALL_RO` are denied unless the
identity has a non-empty script allowlist, and then only for `EVAL`/`EVAL_RO` whose script
body hashes to an allowlisted SHA-256. `EVALSHA*` and `FCALL*` are always denied — a SHA-1
digest or a function name cannot be mapped back to an approved script body.

The allowlist comes from **server configuration only**, per static token
(`allowed_script_sha256`) or per pool. It is never read from a JWT claim. This is the
narrowing invariant below, applied to the one piece of data that would otherwise widen
privilege.

Passing the scripting rule is a gate, not a grant: `EVAL` must also appear in
`allowed_commands` when that is set, and it is never available to a read-only identity.

### Keycloak

Roles come from `resource_access[client_id].roles`, filtered by `role_prefix` (default
`redis:`):

| Role | Effect |
|---|---|
| `redis:read` | read-only identity |
| `redis:write` | read-write identity |
| `redis:admin` | read-write, plus the admin allowlist above |
| none | 403 `{"error":"NOPERM no redis role"}` |

Additional claims: `srh_pool` selects the pool (falling back to `default` if configured),
`srh_blocked_commands` adds to the blocklist, and `srh_key_prefix` is reserved for Phase 8.

**Claims may only narrow.** `srh_blocked_commands` is safe by construction because it can only
remove privilege. Anything that would widen privilege lives in server config. Emit `srh_pool`
from an admin-controlled protocol mapper — a client scope or role-based mapper — never from a
user-editable Keycloak attribute, since choosing your own pool is adjacent to widening.

Tokens are validated for signature, exact `iss` match, `exp`/`nbf` with 30 s leeway, audience
(`aud` contains the configured audience, or `azp` equals it, since stock Keycloak omits a
custom `aud` unless a mapper adds one), and `typ == "Bearer"`, which rejects ID tokens and
refresh tokens.

> The `typ` check is the one validation that fails closed on an IdP *configuration* change
> rather than a code change. If a realm or client scope overrides the token type, every
> request becomes a hard 401 deployment-wide. Verify against your realm's actual tokens
> during rollout.

The verification algorithm is taken from the JWKS entry, never from the token header, which
closes algorithm-confusion attacks including `none` and HS256-signed-with-a-public-key. JWKS
entries that are not signing keys are ignored — Keycloak publishes RSA encryption keys in the
same document, and ingesting one produces baffling failures on `kid` collision.

**Token introspection** (RFC 7662) is available and off by default. When enabled, an inactive
token is a 401 and an unreachable introspection endpoint is a 503 — enabling it means choosing
revocation over availability.

**Break-glass.** Deployments using JWT as the primary path should configure one
high-entropy static `sha256:` token, tightly scoped to its own pool and `allowed_commands`,
stored offline. The auth chain accepts static and JWT credentials side by side, so this keeps
operators in during an IdP outage. The escape hatch is a break-glass token, never fail-open
authentication.

---

## Operations

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness. No Redis I/O. Never shed, on any interface. |
| `GET /ready` | Readiness. `PING`s each already-built pool. Loopback callers only; returns 404 to everyone else. |
| `metrics_bind` | Prometheus scrape endpoint, on its own listener, loopback by default. |

Health and readiness sit outside the admission-control stack on purpose. An overloaded proxy
that cannot answer its health check gets restarted by the orchestrator mid-recovery, which is
worse than the overload. Readiness PINGs bypass pool request permits and breaker admission:
a saturated but reachable Redis remains ready, and health checks cannot consume a half-open
traffic probe.

Metrics cover request counts and latency by endpoint and status, per-pool connection gauges,
pool builds and evictions, auth failures by kind, rate-limit rejections, and saturation
signals: global in-flight, per-pool permits-in-use and waiter depth, circuit-breaker state,
and a shed counter broken down by cause (`global_limit`, `pool_queue_full`, `acquire_timeout`,
`breaker_open`, `response_too_large`). That last one is what tells you which bound you are
actually hitting; without it, capacity tuning is guesswork.

One audit line per request records subject, pool, command name, status, latency, and pipeline
length. Command *arguments* are never logged, nor are tokens, JWTs, connection strings, or
telemetry headers.

### Behavior under load

Pools are built lazily on first use, so the proxy starts healthy with Redis down and recovers
without a restart when Redis returns. Under rising load it sheds in this order of protection:
per-identity rate limit (429), per-pool queue bound and acquire timeout (503), the global
in-flight cap (503, before the body is even read), the circuit breaker (503, in microseconds),
and the response budget (502).

Each shed is cheaper than the work it replaces. Accepted requests keep bounded latency,
rejected requests are fast and carry an honest status with `Retry-After`, memory stays flat,
health and metrics keep answering, and full service returns without a restart when load
subsides.

### Deployment checklist

Verify before shipping to any shared host:

- The Redis holding session or auth data runs `maxmemory-policy noeviction` with AOF
  persistence. Otherwise sessions are evicted under memory pressure — which surfaces as random
  sign-outs — or lost on restart. Check with `CONFIG GET maxmemory-policy`.
- Prefer a dedicated Redis instance for auth KV. At minimum: a dedicated DB index, a Layer B
  ACL user, and key-pattern restrictions.
- Redis is reachable only from the proxy host, and has AUTH/ACL configured. The proxy ACL is
  not the boundary.
- Set `proto-max-bulk-len` on the Redis server. The proxy's response budget bounds
  *amplification* — JSON structure, string escaping, base64 — but the raw reply is already
  fully buffered by the Redis client before conversion starts, so the raw bound has to come
  from Redis itself.
- The fronting reverse proxy carries the per-IP rate limit. The proxy's own limiter is
  per-identity and runs after authentication, so JWT signature verification itself is
  unmetered — bounded only by `max_in_flight`.
- Document `somaxconn` and the listen backlog for the host.

### systemd

Ship as a static `x86_64-unknown-linux-musl` binary with `deploy/srh-rs.service`:

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

Keep the config file mode 0600 and root-owned, readable via `LoadCredential` or a group ACL.
Bind loopback and terminate TLS at the host reverse proxy.

On `SIGTERM`/`SIGINT` the proxy stops accepting connections, drains in-flight requests with a
15-second deadline, closes its pools, and exits. In-flight work finishes; new work is refused
at the socket.

---

## Non-goals

Deliberately not built: path-based commands or tokens in query parameters; RESP3 to clients or
upstream; pub/sub and blocking semantics; cluster-aware routing (the Redis client handles
sentinel connection strings natively); a web UI; and config hot-reload.

---

## Development

See [`AGENTS.md`](./AGENTS.md) for build, test, and contribution conventions, and
[`CLAUDE.md`](./CLAUDE.md) for the architecture rules that are not obvious from the file tree.
[`srh-rust-spec.md`](./srh-rust-spec.md) is the normative specification and the place to
resolve any disagreement with this README.

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

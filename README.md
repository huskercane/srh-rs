# srh-rs

An Upstash-compatible Redis HTTP proxy, in Rust.

`srh-rs` speaks the [`@upstash/redis`](https://github.com/upstash/upstash-redis) REST wire
protocol in front of a plain Redis server, so serverless and edge runtimes that can only make
HTTP requests can use a Redis you host yourself. It is a rewrite of
[hiett/serverless-redis-http](https://github.com/hiett/serverless-redis-http) (SRH) with a
hardened security model: Keycloak JWT auth, per-token command ACLs, read-only tokens, script
allowlisting, per-identity rate limiting, bounded pool queues, and circuit breaking.

Wire compatibility with the `@upstash/redis` SDK is the top-level design requirement.

> ### Status: ready for the target deployment
>
> Phases 0–7 and 9 are implemented: the architecture scaffold, configuration, static-token and JWT
> authentication, admission controls, RESP conversion, and all three Redis execution routes are
> working with lazy bounded pools, Fred-level timeouts, circuit breaking, idle eviction,
> command ACL enforcement, script allowlisting, debt-aware per-credential rate limiting,
> bounded JWKS discovery, optional token introspection, readiness and Prometheus observability,
> production packaging, and the bend-not-break load gate.
> The normative
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
> | 5 | Command ACLs, rate limiting | Done |
> | 6 | Keycloak JWT auth, JWKS, introspection | Done |
> | 7 | Hardening, observability, packaging | Done |
> | 8 | Key-prefix isolation | Deferred — out of the first delivery |
> | 9 | Load-handling verification | Done |
>
> Sections for later phases describe the target contract; the status table identifies what is
> currently implemented.
>
> Compatibility note: the Bun parity gate tracks the reviewed `@upstash/redis` 1.38.2 release
> commit dated 2026-08-04. The exact SDK, Bun, and Redis Stack pins are recorded in
> [Development](#development).

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
  ghcr.io/huskercane/srh-rs:v1.0.1
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

### Production setup

Start from the checked-in [`tokens.example.json`](./srh-config/tokens.example.json). Copy it to
`tokens.json`, replace the example token digest and Redis URL, and provision the Redis-side ACL
user described in [Security model](#security-model). Keep the finished file root-owned and mode
restricted as described below; it contains Redis and optional introspection credentials.

```bash
cp srh-config/tokens.example.json tokens.json
chmod 0600 tokens.json
# Edit tokens.json before starting the proxy.
```

For Docker, attach Redis and the proxy to a private Docker network, use the Redis service name in
`connection_string` (not `localhost`), and mount the configuration read-only:

```bash
VERSION=1.0.1
sudo chown root:65532 tokens.json
sudo chmod 0640 tokens.json
docker network create srh-backend
docker run -d --name redis --restart unless-stopped --network srh-backend redis:7-alpine
docker run -d --name srh --restart unless-stopped --network srh-backend \
  -p 127.0.0.1:8079:80 \
  -e SRH_MODE=file \
  -e SRH_CONFIG_PATH=/etc/srh-rs/tokens.json \
  -v "$PWD/tokens.json:/etc/srh-rs/tokens.json:ro" \
  "ghcr.io/huskercane/srh-rs:v$VERSION"
```

The numeric group is the distroless image's `nonroot` group. It lets the non-root process read
the bind mount without making the credentials world-readable; the `:ro` mount prevents writes.

For a native systemd installation, download and verify the `x86_64-unknown-linux-gnu` archive
as shown in [Artifacts](#artifacts), then install the binary, unit, and configuration. Use the
`x86_64-unknown-linux-musl` archive instead on a host whose glibc is older than the floor
reported in the release notes:

```bash
RELEASE_DIR="srh-rs-v$VERSION-x86_64-unknown-linux-gnu"
sudo install -m 0755 "$RELEASE_DIR/srh-rs" /usr/local/bin/srh-rs
sudo install -m 0644 "$RELEASE_DIR/deploy/srh-rs.service" /etc/systemd/system/srh-rs.service
sudo install -d -m 0700 /etc/srh-rs
sudo install -m 0600 tokens.json /etc/srh-rs/tokens.json
sudo systemctl daemon-reload
sudo systemctl enable --now srh-rs
```

The shipped unit uses a systemd credential so its `DynamicUser` can consume the root-owned
`0600` configuration without making it broadly readable. In both deployment modes, keep Redis off the
public network, put an HTTPS reverse proxy with a per-IP rate limit in front of the loopback HTTP
listener, and expose the metrics listener only to the monitoring network. Confirm startup with
`curl http://127.0.0.1:8079/health` for Docker or `systemctl status srh-rs` for systemd.

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

### Known differences from Upstash

These are the known Upstash-vs-Redis protocol differences:

- `UNLINK` with zero keys returns the real Redis error rather than a synthesized success.
- `ZRANGE` requires `BYSCORE` or `BYLEX` in order to use `LIMIT`.
- RedisJSON responses may differ subtly.

Direct `MULTI`, `EXEC`, `DISCARD`, `WATCH`, and `UNWATCH` are denied, matching the stateless
Upstash REST surface. Use `/multi-exec`; EXEC-time command errors appear in their individual
`{"error": ...}` slots while the endpoint returns 200 and preserves every other result.

---

## Configuration

`SRH_MODE` selects the source: `file` (default) or `env`.

### Environment mode

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `SRH_TOKEN` | yes | — | The single static token |
| `SRH_CONNECTION_STRING` | yes | — | Redis URL (`redis://` or `rediss://`) |
| `SRH_MAX_CONNECTIONS` | no | 3 | Pool size |

This normalizes to one pool named `default` and one read-write, legacy-compatible static token,
preserving the original SRH command policy for the Docker interface.

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
and the token is throttled until refill clears it. Rate-limit rejections are not charged. This
matters because a classic bucket can never admit a request costing more than its capacity —
with a rate of 10, every pipeline over 20 commands would be a permanent 429, and the SDK
batches automatically, so that would fire in normal use rather than under attack.

The practical consequence: worst-case throttle after one maximum-size pipeline is
`max_pipeline_commands / rate` seconds. Size the rate against the token's peak *command*
throughput including SDK auto-batching. Every 429 carries
`Retry-After: ceil(|deficit| / rate)` so clients can back off deliberately instead of
burning their retries inside a deficit they cannot see.

Malformed JSON is charged the minimum one-command cost after its bounded parse. Once that
credential spends its burst, the next request is rejected before its body is read; malformed
traffic therefore cannot buy unlimited full-size parses without entering the throttle.

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
  +get +set +del +expireat +ttl +ping +info +command|info \
  +multi +exec +discard
```

Two traps worth knowing before you copy that:

- **Key patterns must match the client's actual key roots.** `@auth/upstash-redis-adapter`
  writes under seven separate `user:`-rooted prefixes by default. Pass `baseKeyPrefix` (for
  example `"ww:auth:"`) in the adapter options to unify them, or the pattern above locks the
  client out with `NOPERM` on every write.
- **`+info` and `+command|info` are for the proxy, not for clients.** The Redis client may run
  `INFO` while bootstrapping a connection, and key-prefix isolation (Phase 8) runs
  `COMMAND INFO` over this same Redis user. Both commands stay denied to ordinary HTTP
  identities; without both Redis-side grants, a properly provisioned pool can fail at first use.
- **`+multi +exec +discard` are also for the proxy.** Direct transaction-state commands stay
  denied to HTTP clients because they would contaminate pooled connections, but `/multi-exec`
  uses these commands internally to execute one bounded transaction.
- **Do not add `+hello` to this user.** Fred is forced to RESP2 and authenticates with `AUTH`,
  so the proxy does not need `HELLO` to establish a connection. `HELLO` changes protocol state
  on a pooled connection, so its Layer A denial is a correctness boundary, not merely a
  permission check. Keeping it absent from Layer B preserves defense in depth; the
  `HELLO`-is-always-403 regression test is load-bearing if a deployment grants it for some
  external handshake requirement.

### Command policy

Denials return 403 `{"error":"NOPERM this token does not have permission to run '<CMD>'"}`.
Inside a pipeline the request is still 200 and that string appears in the failing slot.

**Always denied, for every identity including admin.** Server and topology control (`CONFIG`,
`SHUTDOWN`, `DEBUG`, `SLAVEOF`/`REPLICAOF`, `MIGRATE`, `MODULE`, `SAVE`, `BGSAVE`,
`BGREWRITEAOF`, `LASTSAVE`, `ACL`, `CLIENT`, `CLUSTER`, `LATENCY`, `MONITOR`, `PSYNC`, `SYNC`,
`FAILOVER`, `RESET`, `SLOWLOG`, `COMMAND`, `MEMORY`); connection state that would corrupt a
pooled connection for its next user (`HELLO`, `SELECT`, `SWAPDB`, `AUTH`, `QUIT`, `MULTI`,
`EXEC`, `DISCARD`, `WATCH`, `UNWATCH`); pub/sub;
blocking commands, which would pin a pool connection indefinitely (`BLPOP`, `BRPOP`, `BLMOVE`,
`BRPOPLPUSH`, `BLMPOP`, `BZPOPMIN`, `BZPOPMAX`, `BZMPOP`, `WAIT`, `WAITAOF`); and `SCRIPT` /
`FUNCTION`, which are handled by the scripting rule below.

**Blocked by default, for every non-legacy identity** — every JWT identity and every
current-format static token — unless explicitly listed in that identity's `allowed_commands`
or in the server's bounded admin allowlist:
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

Admin access is also a *gate, not a grant*: matching the allowlist exempts a command from the
hard-deny and implicit default-block sets, keeping the explicitly listed `INFO` permission live.
It still passes through the identity's own blocklist, configured `allowed_commands`, and
`read_only` check.

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

Create the roles on the same confidential Keycloak client named by `client_id`. The access
token must actually contain `resource_access.<client_id>.roles`; assigning a client role to a
service account is not sufficient by itself. Realms without Keycloak's built-in `roles` client
scope need an explicit `oidc-usermodel-client-role-mapper` whose claim name is
`resource_access.<client_id>.roles` and whose client-role mapping points at that client. Verify
the emitted claim in a real client-credentials token before exposing the endpoint.

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

Configure `issuer` from the public token's `iss` claim (or the public discovery document),
byte for byte. A reverse proxy may expose Keycloak at `/realms/...` while its upstream service
is mounted below `/auth`; in that layout the internal upstream URL is not the issuer. Using it
causes every otherwise-valid token to fail with 401.

> The `typ` check is the one validation that fails closed on an IdP *configuration* change
> rather than a code change. If a realm or client scope overrides the token type, every
> request becomes a hard 401 deployment-wide. Verify against your realm's actual tokens
> during rollout.

The verification algorithm is taken from the JWKS entry, never from the token header, which
closes algorithm-confusion attacks including `none` and HS256-signed-with-a-public-key. JWKS
entries that are not signing keys are ignored — Keycloak publishes RSA encryption keys in the
same document, and ingesting one produces baffling failures on `kid` collision.

OpenID discovery and JWKS retrieval are lazy and use a pooled Hyper client over rustls with the
ring provider and native OS trust roots. Responses and timeouts are bounded, redirects are
rejected, and an unknown `kid` can force at most one refresh every 30 seconds.

**Token introspection** (RFC 7662) is available and off by default. When enabled, an inactive
token is a 401 and an unreachable introspection endpoint is a 503 — enabling it means choosing
revocation over availability. Results are cached by the token's SHA-256 digest in a bounded
100,000-entry LRU and expired entries are removed by the shared maintenance task.

**Break-glass.** Deployments using JWT as the primary path should configure one
high-entropy static `sha256:` token, tightly scoped to its own pool and `allowed_commands`,
stored offline. The auth chain accepts static and JWT credentials side by side, so this keeps
operators in during an IdP outage. The escape hatch is a break-glass token, never fail-open
authentication. Static credentials may contain dots: dotted text whose first segment is not a
JSON JWT header falls through to static authentication. Once a bearer has a base64url JSON JWT
header, every validation failure is definitive and can never fall through to a same-value static
credential.

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
health checks cannot consume a half-open traffic probe. Built pools are probed concurrently,
each with its own deadline of at most 500 ms; a pool that cannot answer in time is not ready.
`/health` is intentionally also outside `max_in_flight`, so liveness traffic is unbounded inside
the process; deployments should retain the documented reverse-proxy rate limit for public binds.

Metrics cover request counts and latency by endpoint and status, per-pool connection gauges,
pool builds and evictions, auth failures by kind, rate-limit rejections, and saturation
signals: global in-flight, per-pool permits-in-use and waiter depth, circuit-breaker state,
and a shed counter broken down by cause (`global_limit`, `pool_queue_full`, `acquire_timeout`,
`breaker_open`, `response_too_large`, `debt_forgiven_by_eviction`). That last one is what tells
you which bound you are actually hitting; without it, capacity tuning is guesswork.

One audit line per request records subject, pool, command name, status, latency, and pipeline
length. Command *arguments* are never logged, nor are tokens, JWTs, connection strings, or
telemetry headers.

### Artifacts

Prebuilt production artifacts are published on the
[GitHub Releases page](https://github.com/huskercane/srh-rs/releases). Each release contains two
stripped binary archives, each with its SHA-256 checksum, the README, the hardened systemd unit,
and the example config:

| Archive | Linkage | Use it for |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | dynamic (glibc) | **systemd hosts.** The faster artifact: this workload spends roughly a tenth of its CPU in the allocator, and glibc's malloc outperforms musl's mallocng under thread contention. |
| `x86_64-unknown-linux-musl` | fully static | The distroless image, and any host older than the glibc floor printed in the release job summary. |

```bash
VERSION=1.0.1
TARGET=x86_64-unknown-linux-gnu   # or -musl, per the table above
gh release download "v$VERSION" --repo huskercane/srh-rs \
  --pattern 'srh-rs-*.tar.gz' --pattern 'srh-rs-*.tar.gz.sha256'
sha256sum --check "srh-rs-v$VERSION-$TARGET.tar.gz.sha256"
tar -xzf "srh-rs-v$VERSION-$TARGET.tar.gz"
```

The same release is published as a non-root distroless image at
`ghcr.io/huskercane/srh-rs:v$VERSION`. Pin the digest reported by the release workflow when
deploying; do not consume a mutable `latest` tag.

Building both artifacts from source needs the musl compiler installed for the static target:

```bash
./scripts/build-artifacts.sh
ldd target/x86_64-unknown-linux-musl/release/srh-rs
```

`ldd` must report `not a dynamic executable` for the musl binary; the gnu binary is expected to
link `libc.so.6`, and the script prints the glibc version it requires. Build the non-root
distroless image with:

```bash
docker build -t srh-rs:local .
docker image inspect srh-rs:local --format '{{.Size}}'
```

CI publishes release images by digest. Deploy and promote those digests; never consume
`:latest`.

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
- Linux hosts running Redis with AOF or RDB persistence set `vm.overcommit_memory=1`, preferably
  through a dedicated file in `/etc/sysctl.d`, so background persistence is not rejected under
  memory pressure.
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
- The Tokio/Mio listener requests a backlog of 128; Linux caps it at
  `net.core.somaxconn`. Verify `sysctl net.core.somaxconn` is at least 128 (and size the fronting
  reverse proxy's backlog for the same burst envelope). Accepted sockets explicitly enable
  `TCP_NODELAY`.

The nightly Phase 9 gate runs the overload, backend-death, and slow-client profiles at their
normative 60-second timings. Run the same gate locally with Docker and Python 3:

```bash
./scripts/phase9-load.sh
```

For a quick harness check during development, use `PHASE9_SMOKE=1`; it shortens the two load
profiles but retains every assertion and the configured 64 slow clients.

### Profile before a PR

Unit tests are useful for profiling a specific pure function, but they do not profile the running
server: most use fakes, bypass the TCP accept loop, and compile with the test profile. For request
path changes, profile the optimized `srh-rs` binary under the checked-in canonical workload. The
workload repeatedly executes an authenticated `GET` against a local Redis, uses persistent HTTP
connections, warms the pools before recording useful samples, and rejects any non-200 response so
overload behavior cannot accidentally dominate the capture.

On Linux, install `perf`, Docker, Python 3, and `cargo-flamegraph`, then run this before opening a
performance-sensitive PR:

```bash
cargo install flamegraph
./scripts/profile.sh
```

The script builds the dedicated `profiling` Cargo profile with release optimizations, debug symbols,
and forced frame pointers; starts an ephemeral Redis; warms every pool; records only the steady-state
server at 997 Hz for 30 seconds; and writes these ignored artifacts under `target/profiling/`:

- `flamegraph.svg` — interactive CPU flame graph with compiler-expanded inline frames collapsed;
- `perf-report.txt` — text report suitable for attaching to a PR;
- `perf.data` — raw capture for follow-up `perf report` queries.

Keep the canonical workload and defaults unchanged when comparing branches. To make a longer capture
without editing tracked files, set `PROFILE_DURATION` and `PROFILE_CONCURRENCY`:

```bash
PROFILE_DURATION=60 PROFILE_CONCURRENCY=64 ./scripts/profile.sh
```

Record the before/after request rate and p99 printed by the workload, and compare the same stacks in
both flame graphs. Do not commit the generated SVG or `perf.data`; they are host-specific. The regular
pre-PR correctness gate remains:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### systemd

Ship the `x86_64-unknown-linux-gnu` binary with `deploy/srh-rs.service`, falling back to the
static `x86_64-unknown-linux-musl` build on hosts below its glibc floor:

```ini
[Service]
ExecStart=/usr/local/bin/srh-rs
LoadCredential=srh-config:/etc/srh-rs/tokens.json
Environment=SRH_CONFIG_PATH=%d/srh-config
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

Keep the config file mode 0600 and root-owned. The shipped unit loads it through a systemd
credential so the dynamic service user never needs direct access to `/etc/srh-rs`.

If Redis is managed by systemd, order SRH after it with a soft dependency in a unit override:

```ini
[Unit]
After=redis-srh.service
Wants=redis-srh.service
```

Do not use `Requires=` or `BindsTo=` for Redis. SRH deliberately stays alive while a backend is
down, returns fast 503 responses, and recovers when Redis comes back; a hard systemd dependency
would stop SRH and defeat that recovery behavior.

Alternatively, create a dedicated `srh-rs-config` group, add
`SupplementaryGroups=srh-rs-config` in a unit override, and grant that group an explicit read
ACL with `setfacl -m g:srh-rs-config:r /etc/srh-rs/tokens.json`. Do not make the file
world-readable. Bind loopback and terminate TLS and the per-IP rate limit at the host reverse
proxy.

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

Before tagging a release, also run the mutation sweep, which breaks one invariant at a time in a
scratch copy of the crate and asserts that some test notices. It is `#[ignore]`d in ordinary test
runs, runs weekly in the scheduled mutation workflow, takes about fifteen minutes on a warm
cache, and needs no Docker:

```bash
cargo test --test mutation_guard -- --ignored --nocapture
```

The sweep deliberately runs default features so each mutation stays Docker-free. Redis Layer B
behavior is covered by the all-features integration job, but not by the per-mutation runs.
Mutation kills include both behavioral tests and a small set of explicit source-wiring assertions
for the composition root and workflow files; those wiring kills are not behavioral coverage.

CI runs the upstream Bun suite from `@upstash/redis` 1.38.2 commit
`fc3089b69f583bc2a34bb1c4f9b8871891408cdc` (2026-08-04), using Bun 1.3.6 and the pinned
Redis Stack image digest in `.github/workflows/ci.yml`, against the release image built by that
same job. At this pin the gate executes 701 upstream tests: 685 pass and 16 narrowly patched
tests are skipped, in addition to whole-file scope exclusions listed below.

The exclusions are deliberately separated so a security-policy failure cannot be relabeled as
wire compatibility:

- `ci/upstash-parity-policy-scope.txt` and `ci/upstash-parity-policy.patch` cover commands the
  Phase 5 ACL intentionally denies, including scripting, pub/sub, functions, and `MEMORY USAGE`.
- `ci/upstash-parity-skips.txt` and `ci/upstash-parity-protocol.patch` contain only documented
  Upstash-vs-Redis HTTP or response-semantic differences.
- `ci/upstash-parity-backend-scope.txt` and `ci/upstash-parity-backend.patch` cover Upstash
  service features and commands unavailable in the pinned Redis Stack backend.

The upstream suite still has no `/multi-exec` EXEC-time slot-error case. The local raw HTTP and
Redis-backed regression tests remain the load-bearing lock for that response shape.

To refresh the gate, choose the latest stable `@upstash/redis` tag, resolve it to an immutable
commit, record its release date, and update the checkout plus the reviewed Bun and Redis Stack
pins together. Apply every manifest and patch to a clean checkout, run the complete upstream
suite, and review each changed exclusion in its existing category. A policy exclusion must never
move into the protocol list merely to make the gate pass.

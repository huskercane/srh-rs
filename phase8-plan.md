# Phase 8 — Key-prefix isolation: implementation plan

Working plan, drafted 2026-08-12, revised 2026-08-13 after review. Source of truth remains
`srh-rust-spec.md` §"Phase 8 — Key-prefix isolation"; this file records the decisions taken on top
of it and the commit breakdown. Read alongside GitHub issue #7 (non-Keycloak OIDC token profiles),
which shares the `key_prefix` seam.

## Decisions taken

| Question | Decision |
|---|---|
| How key positions are discovered | **Compiled-in static key-spec table** in `domain/`. Every command is one of four states: fixed key specs, reviewed-keyless, keyspace-wide, or **absent → 403**. The spec's lazy `COMMAND INFO` mechanism becomes a documented follow-up. |
| Order relative to issue #7 | **Phase 8 first**, then #7. |
| Table shape | Redis's own model, not a single triple: a command maps to a *slice* of specs, each either `Range { first_key, last_key, step }` or `KeyNum { numkeys_index, first_key, step }`. A command is absent when *any* of its specs is keyword/unknown-position — representability decides, not the `movablekeys` flag. |
| What "no key argument" means | **Two reviewed states, never one.** `Keyless` (`PING`, `ECHO`, `TIME`) is allowed; `KeyspaceWide` (`SCAN`, `KEYS`, `DBSIZE`, `FLUSHDB`, …) is denied. A command that takes no key *because it operates on the whole database* is the opposite of safe. |
| Lookup key | **`NAME` or `NAME|SUB`**, canonicalized identically by the table, the generator, and the drift guard. Container commands never fall back to their top-level entry. |
| `+command|info` Layer B grant | **Stays**, with a corrected rationale: it exists for the admin allowlist (`acl.rs:261` admin-allows `COMMAND COUNT/INFO/DOCS`), not for Phase 8 discovery. No test or CI change. |

### Why a static table instead of `COMMAND INFO`

The spec prescribes lazy per-command `COMMAND INFO`, cached per pool. That path costs:

- a **seventh port** (`CommandSpecSource`) — by the spec's own definition it is genuinely one,
  "an outbound I/O dependency the domain owns", so it would need written justification;
- a bounded single-flight per-pool cache adapter plus RESP reply parsing;
- a new failure mode (NOPERM or a transport error on the lookup itself, mid-request);
- a cold path that takes a pool permit for the lookup and then re-acquires for the real command;
- restructuring `pipeline.rs` into an async spec pre-pass.

The static table costs none of that, plugs into the existing per-slot ACL loop unchanged, fails
closed by construction, and matches how `HARD_DENY` / `READ_COMMANDS` / `DEFAULT_BLOCK` already
work in `acl.rs` — the shape a reviewer of that file already knows.

The price is drift: the table is a compiled-in copy of a fact that lives on the server. Commit 3's
drift guard is the whole reason this option is acceptable, and it is not optional. Two functional
cuts fall out and are stated plainly in the README (commit 4):

- **Module commands** (`JSON.*`, `FT.*`, `TS.*`, `BF.*`, present on the Redis Stack backend the
  parity gate pins) are denied to prefixed identities.
- **`XREAD` / `XREADGROUP` are denied outright** to prefixed identities — not merely
  multi-stream. The `STREAMS k1 k2 id1 id2` split is a keyword spec with a runtime-computed
  arity; neither `Range` nor `KeyNum` expresses it, and Phase 8 does not add a bespoke parser.
- **`SCAN` is denied** to prefixed identities. It is not a table gap but a decision: a cursor over
  the whole database cannot be constrained to a prefix by argument inspection, and it is exactly
  the command an isolated tenant would use to read the keyspace it is isolated from. Prefixed
  callers that need enumeration must be given a Layer B `~prefix:*` user and use `SCAN … MATCH`
  from a non-prefixed operator credential, or key their own index.

**Open item — follow-ups to file:** the `COMMAND INFO` port (module commands) and an `XREAD`
key parser are both consciously-cut scope, which clears `CLAUDE.md`'s filing bar. That is two
issues from one task, i.e. at the soft ceiling, so bring both to the owner in the PR summary
rather than filing unilaterally.

## The security problem this phase opens (why commit 1 exists)

`key_prefix` is inert today — it feeds only the SORT/SORT_RO hook at `src/domain/acl.rs:195`.
Its two sources are:

- `StaticTokenConfig.key_prefix` (`src/config.rs:112`) — admin-controlled, but **completely
  unvalidated**: no non-empty check, no rejection of glob metacharacters, no relation to the pool.
- `srh_key_prefix` straight from the JWT claim into `Identity` (`src/adapters/jwt_auth.rs:293`)
  — with **no server-side floor at all**.

The moment Phase 8 makes this the keyspace boundary, the JWT path becomes self-service: a user
who can influence the claim simply **omits** it and gets an unprefixed identity. Presence
narrows; absence is the escalation. Same class as `srh_pool`, which `CLAUDE.md` already requires
to come from an admin-controlled mapper — but omission-as-bypass makes it worse.

A second, quieter escalation: `Some("")`. An empty prefix passes every `starts_with` check, so an
unvalidated empty string is indistinguishable from no isolation at all — which is why validation
belongs in the resolver, not only in config parsing (a claim never passes through
`Config::validate`).

So the phase starts with the trust rule, not the enforcement.

---

## Commit 1 — Trust rule for `key_prefix`

No enforcement yet, so it reviews in isolation and closes the escalation path before anything
depends on it. Worth landing on its own even if the rest slips.

### `src/domain/key_prefix.rs` (new)

```rust
pub enum PrefixError { Empty, TooLong(usize), IllegalByte(u8), NotUnderFloor }

/// Validates one configured or claimed prefix in isolation.
pub fn validate(prefix: &str) -> Result<(), PrefixError>;

/// Folds a server-side floor and a caller-supplied candidate into the effective prefix.
pub fn resolve(floor: Option<&str>, candidate: Option<&str>)
    -> Result<Option<String>, PrefixError>;
```

`floor` is the pool's server-configured prefix. `candidate` is whatever the credential carried —
`StaticTokenConfig.key_prefix` on the static path, `claims.srh_key_prefix` on the JWT path. One
function, two callers, so the trust rule cannot diverge between token profiles (this is the seam
issue #7 folds into `Grant`).

| `floor` | `candidate` | result |
|---|---|---|
| `None` | `None` | `Ok(None)` — no isolation |
| `None` | `Some(c)` | `Ok(Some(c))` after `validate(c)` |
| `Some(f)` | `None` | **`Ok(Some(f))`** — the escalation lock; omission must not widen |
| `Some(f)` | `Some(c)` where `c.starts_with(f)` | `Ok(Some(c))` — a claim may only extend (equal counts as extending) |
| `Some(f)` | `Some(c)` otherwise | `Err(NotUnderFloor)` — reject the credential, never silently ignore |

`resolve` validates both arguments even though the floor was validated at load time — it is an
O(len) check on a ≤128-byte string, and it keeps the function total rather than relying on a
caller invariant.

`validate` rules, all on **bytes**, because the comparison is `arg.starts_with(prefix.as_bytes())`
against `RedisCommand`'s byte arguments:

- non-empty — `Empty` otherwise (see the `Some("")` escalation above);
- `len() <= 128` — `TooLong(len)` otherwise. 128 bytes is generous for a tenant root and keeps the
  matching cost trivially bounded;
- reject `*`, `?`, `[`, `]`, and `\` — the first four are Redis glob metacharacters and the fifth
  is `stringmatchlen`'s escape, so a prefix containing any of them reads as matching more (or
  less) than it does once it is pasted into a Layer B `~prefix:*` pattern;
- reject ASCII control bytes (`< 0x20`, `0x7f`) and space — they corrupt `ACL SETUSER` patterns
  and log lines. Other UTF-8 is allowed.

### Per-pool policy value

`PoolConfig` gains `key_prefix: Option<String>` (`src/config.rs:116`), the floor for every
identity routed to that pool. Both authenticators need it, and today neither can see it:
`JwtAuth::new` reduces each pool to its script allowlist alone (`jwt_auth.rs:170`) and
`StaticAuth::new` never receives pool config at all (`static_auth.rs:15`). So introduce one small
value in `src/domain/identity.rs`:

```rust
pub struct PoolPolicy {
    pub allowed_script_sha256: HashSet<String>,
    pub key_prefix: Option<String>,
}
```

- `JwtAuth`'s `pools` field becomes `HashMap<String, PoolPolicy>`; its constructor signature is
  unchanged (it already takes `&HashMap<String, PoolConfig>`).
- `StaticAuth::new(tokens, pools: &HashMap<String, PoolConfig>) -> Result<Self, ConfigError>` —
  a signature change, plus the `?` in `main.rs` and three unit-test call sites. It returns
  `Result` rather than silently minting an unusable identity; `Config::validate` should already
  have rejected any conflict, so this arm is startup belt-and-braces, not a live path.
- Parsing: set `normalized.key_prefix` in `Config::from_new_value` (beside the existing
  `allowed_script_sha256` assignment, `config.rs:~283`) and add `key_prefix: Option<String>` to
  `RawPoolConfig` (`config.rs:~864`). Env mode and legacy-file mode keep `None` — legacy tokens
  exist for original-SRH parity and gain no new policy surface.

### Wiring the resolver

- `jwt_auth::identity()` (`:293`) →
  `resolve(policy.key_prefix.as_deref(), claims.srh_key_prefix.as_deref())?`.
- `static_auth::new` (`:31`) → the same call with the token's prefix as candidate.
- `Config::validate` calls the **same** `validate` / `resolve`, so a conflict fails at startup
  rather than producing a permanently 403ing configured credential:
  - each pool's floor → `validate`, error named `pools.{name}.key_prefix`;
  - each static token → `resolve(floor, token.key_prefix)`, error naming the pool and the token's
    digest-hex prefix (switch the loop at `config.rs:431` from `.values()` to `.iter()` to have
    the digest available — never the token itself).

### Error mapping

JWT-path failures are `AuthError::Forbidden`, i.e. **403, not 401**: the signature verified and
the token is well-formed, so this is authorization, not authentication. Per the chain contract an
`Err` is definitive and must not fall through to `StaticAuth`.

- `NotUnderFloor` → `"NOPERM key prefix outside pool policy"`
- `Empty` / `TooLong` / `IllegalByte` → `"NOPERM invalid key prefix claim"`

**No new log line.** The existing audit line already records the request and its status
(`observability.rs:210-232`) and `srh_auth_failures_total{kind="forbidden"}` already counts it
(`extractors.rs:40`); a dedicated `warn` would add a caller-triggerable log-volume lever for
traffic that is rejected anyway. And it would have been mis-scoped: `identity.subject` is the
8-hex-char digest label only on the static path (`static_auth.rs:22`) — on the JWT path it is the
full `sub` (`jwt_auth.rs:281`). The claim value is never logged in any case; it is arbitrary
caller-controlled bytes, i.e. log injection.

### Tests

Pure unit tests on `resolve`/`validate`: every row of the table above; `Some("")` rejected from
each source; each rejected metacharacter; the byte-length boundary at 128/129; a multi-byte UTF-8
prefix counted in bytes. The regression lock that must **fail on the unfixed code** is
*claim absent with a floor configured → floor applies*.

Config-level tests as well, not only pure ones: `pools.<name>.key_prefix` parses from JSON;
an invalid pool floor fails `Config::validate`; a static token whose prefix does not extend its
pool floor fails `Config::validate` with the pool named; `deny_unknown_fields` still holds.

README: `srh_key_prefix` gets the `srh_pool` treatment — admin-controlled protocol mapper only
(replacing the "reserved for Phase 8" line at `README.md:559`).

## Commit 2 — Key-spec table and pure policy

### `src/domain/key_spec.rs` (new)

```rust
pub enum KeySpec {
    Range { first_key: usize, last_key: isize, step: usize },
    KeyNum { numkeys_index: usize, first_key: usize, step: usize },
}

pub enum KeyPolicy {
    Keys(&'static [KeySpec]),
    /// Reviewed: takes no key and cannot reach one. `PING`, `ECHO`, `TIME`.
    Keyless,
    /// Reviewed: takes no key *because it operates on the whole database*. Denied.
    KeyspaceWide,
}

/// Resolves `NAME` or `NAME|SUB`; see the canonicalization rule below.
pub fn key_policy(command: &RedisCommand) -> Option<&'static KeyPolicy>;

/// Visits every key argument the policy resolves, without allocating.
pub fn visit_keys(
    policy: &KeyPolicy,
    args: &[Bytes],
    visit: impl FnMut(&Bytes) -> Result<(), AclError>,
) -> Result<(), AclError>;
```

Four states, and the last two are both the security default:

- `Keys(...)` — fixed positions, checked. Positions are 1-based over the wire command, so
  `args[i]` is position `i + 1`; `last_key` negative counts from the end (`-1` = last argument).
- `Keyless` — reviewed as unable to reach any key. **This entry kind is load-bearing**: without
  it, "absent → 403" would deny `PING` to every prefixed identity and break the SDK's own
  connection handling. It also covers the admin-allowlisted server-introspection commands
  (`INFO`, `COMMAND INFO`, `ACL WHOAMI`, …), which are already role-gated and expose no key names.
- `KeyspaceWide` — **denied**, and denied *explicitly* rather than by omission, so the review
  decision lives in `domain/` where the next reader finds it. `SCAN` is the one that matters:
  it takes no key argument because it iterates the database, and today it is reachable by any
  read-write identity (it is in neither `HARD_DENY`, `DEFAULT_BLOCK`, nor `READ_COMMANDS`, so
  `acl::check` lets it through). A prefixed identity running `SCAN` enumerates every tenant's
  keys. `KEYS`, `RANDOMKEY`, `DBSIZE`, `FLUSHALL`, `FLUSHDB` are in the same bucket; they are
  default-blocked for non-legacy identities today, which is a second lock, not this one.
- **absent → 403** — an unknown command, or one whose key specs are inexpressible.

Classification is by **representability, not the `movablekeys` flag**. Redis marks a command
`movablekeys` whenever `COMMAND GETKEYS` is needed, which includes the entire `numkeys` family —
`EVAL` and `ZUNIONSTORE` are `movablekeys` *and* perfectly representable as `KeyNum`. Keying the
rule off the flag would have demanded `EVAL` be both present and absent. The rule is:

- every key spec representable as `Range`/`KeyNum` → `Keys(...)`;
- any keyword or unknown-position spec → absent (`GEORADIUS`'s optional `STORE key`, `XREAD`'s
  `STREAMS` split, `SORT`'s `STORE dest`);
- one named reviewed exception, `SORT`/`SORT_RO`: the fixed source key is represented and the
  dynamic tokens are denied outright (below).

`KeyNum` exists because a single triple cannot express the `numkeys` family the SDK actually uses
(`EVAL`, `ZUNIONSTORE`, `ZINTERSTORE`, `ZDIFFSTORE`, `ZUNION`, `ZINTER`, `ZDIFF`, `ZINTERCARD`,
`SINTERCARD`, `LMPOP`, `ZMPOP` …), and denying all of them was not a price worth paying. Commands
with a leading fixed key plus a counted tail carry both specs, e.g. `ZUNIONSTORE dest numkeys key…`
→ `[Range{1,1,1}, KeyNum{numkeys_index: 2, first_key: 3, step: 1}]`.

### Subcommands are part of the lookup key

Redis reports key specs per *full* command — `XINFO STREAM`, `OBJECT ENCODING`, `MEMORY USAGE`,
`XGROUP CREATE` — while `RedisCommand` stores `name = "XINFO"`, `args = ["STREAM", key, …]`. A
`key_policy(name: &str)` seam would lose the subcommand on commands that are allowed today:
`OBJECT` and `XINFO` are both in `READ_COMMANDS` (`acl.rs:133,139`), and `MEMORY USAGE` is
admin-allowlisted (`acl.rs:263`). So the lookup takes the whole command:

- canonical name is `NAME` uppercased, or `NAME|SUB` when `NAME` is a **container command**
  (`XINFO`, `XGROUP`, `OBJECT`, `MEMORY`, `COMMAND`, `CLIENT`, `CONFIG`, `ACL`, `LATENCY`,
  `SLOWLOG`, `SCRIPT`, `FUNCTION`, `CLUSTER`, `PUBSUB`);
- a container command with a missing or unrecognized subcommand → `None` → 403. **No fallback to
  the top-level entry** — falling back is exactly how a new `XINFO SOMETHING` would inherit a
  permissive parent. Failing closed here is deliberate, not incidental;
- entries: `XINFO|STREAM`, `XINFO|GROUPS`, `XINFO|CONSUMERS`, `XGROUP|CREATE`, `XGROUP|SETID`,
  `XGROUP|DESTROY`, `XGROUP|CREATECONSUMER`, `XGROUP|DELCONSUMER`, `OBJECT|ENCODING`,
  `OBJECT|FREQ`, `OBJECT|IDLETIME`, `OBJECT|REFCOUNT`, `MEMORY|USAGE` — all `Range{2,2,1}`;
  the keyless container subcommands (`COMMAND|INFO`, `ACL|WHOAMI`, …) are `Keyless`.

`COMMAND DOCS` names these the same way (`xinfo|stream`), so the generator, the table, and the
drift guard share one canonicalization function rather than three conventions.

### Failing closed on malformed input

`visit_keys` returns `AclError::InvalidCommand` when:

- a `numkeys` argument is not a decimal integer, or its count overruns the argument list;
- a `Range` spec resolves to **zero** positions. A command the table says has a key, arriving
  without one, is not a command to wave through on the grounds that Redis will reject it later.

Zero keys is legal for `KeyNum` and must stay legal: `EVAL "return 1" 0` declares no keys and is a
valid call. So the zero-position rule is per-spec-kind, not global — `Range` demands at least one,
`KeyNum` accepts the count the caller declared. What the script then reaches through `redis.call`
is invisible to the proxy either way; Layer B `~prefix:*` is the boundary there.

`visit_keys` takes a closure rather than returning `Vec<usize>` — this runs on every command of
every prefixed identity, including every slot of a pipeline, and a per-command heap allocation to
hold two indices is a cost with nothing to show for it. Unit tests collect through a closure.

Table population is mechanical: generate it once with an `#[ignore]`d helper test that prints the
table source from `COMMAND DOCS`, so a drift failure in commit 3 has a mechanical fix rather than a
hand-audit. The generator emits `Keys(...)` and the absences; **it must not guess `Keyless` versus
`KeyspaceWide`** — it emits keyless commands into a `// REVIEW:` block that a human sorts, because
that split is the security decision this section exists for.

### `acl::check_key_prefix`

```rust
pub fn check_key_prefix(identity: &Identity, command: &RedisCommand) -> Result<(), AclError>;
```

No-op when `identity.key_prefix.is_none()`. Otherwise: `key_policy(command)` absent **or**
`KeyspaceWide` → `denied(name)` (the existing "does not have permission to run" string — truthful,
and it does not tell a caller which of the two reasons applied); `Keyless` → `Ok(())`; `Keys(...)`
→ `visit_keys`, and any key argument not starting with the prefix bytes → `AclError::Forbidden`
with the spec's exact string `NOPERM key outside allowed prefix`.

`EVAL` / `EVAL_RO` get `KeyNum{numkeys_index: 2, first_key: 3, step: 1}` entries, so their
*declared* keys are checked like any other command's. Keys reached from inside the script via
`redis.call` remain invisible to the proxy, so Layer B `~prefix:*` is the boundary there — say so
in a comment next to the entry, and keep the script allowlist as the gate that decides whether
`EVAL` runs at all.

### The dynamic-key guard in `check`

The hook at `acl.rs:194-203` stays where it is, in `check`, rather than moving into
`check_key_prefix`: a handler that forgets the new call then still gets the `SORT` denial. It
grows one token:

- `SORT` / `SORT_RO` carry `Range{1,1,1}` in the table **and** are denied when any argument is
  `BY`, `GET`, or **`STORE`** (case-insensitive). `STORE` is the correction: `SORT` is
  `movablekeys` precisely because `SORT src STORE dest` puts a *destination key* at a position no
  triple can express, so without this token `SORT tenant:src STORE other:dst` would pass Layer A
  on its first key alone. `SORT_RO` has no `STORE`, but denying the token on both is fail-closed
  and costs nothing.

Corrections to the earlier draft, both from reading Redis's actual key specs:

- **`GEOSEARCHSTORE` is not dynamic.** `GEOSEARCHSTORE dst src …` has two fixed leading keys and
  no `STORE` token; `STOREDIST` is a bare flag that changes the stored score, not a key. It gets
  `Range{1,2,1}` and is checked positionally. Conditioning its safety on finding
  `STORE`/`STOREDIST` would have been wrong in both directions.
- **`GEORADIUS` / `GEORADIUSBYMEMBER` need no guard** — their optional `STORE key` /
  `STOREDIST key` is a keyword spec, so they are inexpressible, absent from the table, and denied
  by default. (Not "because they are `movablekeys`" — so are `EVAL` and `ZUNIONSTORE`, which are
  present. Representability decides.) Their `_RO` variants have a single fixed key and get
  `Range{1,1,1}`.
- `RENAME` / `COPY` / `SMOVE` / `LMOVE` / `ZRANGESTORE` need no special case either: fixed
  positions, so the per-key check already rejects cross-prefix use.

Doc comments on every new public fn — `acl.rs` and its neighbours are on the spec's "doc comments
and unit tests for every public fn" list.

### Tests (unit, pure, no Docker)

`MSET` (step 2, all keys checked — not just the first), `DEL` (`last_key = -1`), `GET`, `ZADD`,
`GEOADD`, `GEOSEARCHSTORE` (both keys), `ZUNIONSTORE` (leading key + counted tail), `EVAL`
(declared keys checked; `numkeys = 0` **allowed**; bad `numkeys` → `InvalidCommand`), `PING`
(`Keyless` → allowed for a prefixed identity), **`SCAN` → denied** (`KeyspaceWide`, the
enumeration lock), table-absent → denied, `XREAD` → denied, `GEORADIUS` → denied, and each token
of the `SORT` guard including `STORE`.

Subcommand cases, one per hazard: `XINFO STREAM tenant:s` → allowed, `XINFO STREAM other:s` →
denied on the key; `MEMORY USAGE` and `OBJECT ENCODING` likewise; `XINFO` with no subcommand →
denied; `XINFO NOTASUBCOMMAND tenant:s` → denied (**no fallback to the top-level entry**).

## Commit 3 — Wiring, metric, and the drift guard

- `command.rs:42`, `pipeline.rs:49`, and `multi_exec.rs` call `check_key_prefix` beside
  `acl::check`. The `identity.key_prefix.is_some()` short-circuit lives inside
  `check_key_prefix`, so the non-prefixed hot path is one `Option` check and the call sites stay
  uniform.
  Rejection shape follows the existing ACL convention exactly: per-slot `{"error": ...}` inside a
  200 pipeline, 403 for a single command.
- Run the check on the parsed command **before** `compat::normalize`, matching `acl::check`.
  (`normalize` only touches GEODIST's unit argument, never a key, so either order is correct —
  consistency is the reason.)
- Metric: `srh_acl_rejections_total{cause="key_prefix"}`, **registered** in
  `observability::register_metrics` (`observability.rs:14-40`) like every other family, not merely
  incremented at rejection time — otherwise the family is absent from `/metrics` until the first
  rejection, which is exactly when a dashboard needs it to already exist. Add the family name and
  the `key_prefix` cause to `tests/phase7_metrics.rs`.
  **Counting rule, since registration does not imply it:** every `Err` returned by
  `check_key_prefix` increments the counter exactly once — the table-absent/`KeyspaceWide` denial,
  the out-of-prefix key, and `InvalidCommand` alike — and that includes **per-slot pipeline and
  multi-exec rejections**, which are counted individually even though the request itself returns
  200. A rejected pipeline slot is a rejected command; hiding it behind the envelope status is how
  a tenant misconfiguration stays invisible. Rejections from `acl::check` are not counted here:
  Phase 8 introduces the family with one cause, and widening it to command-policy denials is a
  separate change. `tests/phase8_http.rs` asserts the pipeline count (two out-of-prefix slots in
  one 200 response → `+2`).
- `tests/phase8_http.rs`: in-prefix → 200; out-of-prefix → 403 with the exact error string;
  `MSET` with one out-of-prefix key → denied; pipeline per-slot behaviour; `PING` (`Keyless`)
  allowed; **`SCAN` → 403 for a prefixed read-write identity, 200 without a prefix** (the
  enumeration lock — it must fail on a build that treats keyless as safe); `XINFO STREAM` in- and
  out-of-prefix; table-absent command → 403; **non-prefixed identity unaffected** (regression lock
  on the hot path).
- `tests/phase8_redis.rs` — **the table-drift test, not optional.** Enumerate `COMMAND DOCS`,
  canonicalize with the same `NAME|SUB` function the table uses, and assert **set equality** over
  these categories, so drift in any direction fails:

  | Category | Assertion |
  |---|---|
  | Module-owned (`JSON.*`, `FT.*`, `TS.*`, `BF.*`, …) | absent, categorized `unsupported`, and the category asserted **non-empty** — an empty module set means the test is not really running against Redis Stack and the "module commands are denied" claim is untested |
  | Every key spec representable as `Range`/`KeyNum` | present as `Keys(...)`, and the parsed spec matches `COMMAND DOCS` (begin-search index / find-keys range or keynum) |
  | Any keyword or unknown-position key spec | absent from the table, except the named `SORT`/`SORT_RO` allowance, which must be present *and* carry the token guard |
  | No key specs at all | present as **either `Keyless` or `KeyspaceWide`, in exactly one** — a keyless command in neither set fails the test, which is what forces review when a backend upgrade adds one |

  **The categories are ordered and the first match wins.** Module-owned is checked first because it
  is not disjoint from the others: `JSON.SET key …` has a perfectly representable key spec, so
  without precedence it would be required present by the representable category and absent by the
  module category — an unsatisfiable test. Module ownership comes from `COMMAND DOCS`'s
  `group == "module"`, cross-checked against the dotted-name heuristic; a disagreement between the
  two fails the test rather than picking one, because that disagreement is itself drift worth
  seeing.

  `movablekeys` is **not** a category — it is a drift *signal*. `EVAL` and `ZUNIONSTORE` carry the
  flag and are representable, so a flag-based rule would demand they be present and absent at
  once. Instead the test asserts set equality on a `MOVABLE_REVIEWED: &[(&str, &str)]` map of
  command → one-line reason ("represented via KeyNum", "keyword spec → denied", "SORT: fixed
  source key plus token guard"), so a newly-movable command fails until a human writes down why.

  Scope of the enumeration: a command is out of scope, and asserted absent, only when the real
  `acl::check` denies it for **every identity an operator can actually configure**. The fixture is
  built **per candidate**, not once:

  - a read-write identity with `allowed_commands = { candidate top-level name }`;
  - an admin identity (`is_admin = true`), for the admin-allowlisted subcommands;
  - for `EVAL` / `EVAL_RO`, the candidate command carries a known test script body and the identity
    carries its SHA-256 in `allowed_script_sha256`. `EVALSHA` / `FCALL` variants stay out of scope:
    they fail closed for every identity by construction (`check_scripting`).

  The per-candidate `allowed_commands` is the correction that makes this honest. A "plain"
  read-write identity is denied `KEYS`, `DBSIZE`, `FLUSHDB` and `FLUSHALL` by `DEFAULT_BLOCK`,
  which would have put them out of scope — yet the table must classify them `KeyspaceWide`,
  because `DEFAULT_BLOCK` is *configurable*: `explicitly_allowed` in `acl::check` lets a
  current-format static token's `allowed_commands` bypass it. A configurable denial is not an
  absolute one, and the drift guard must not treat it as though it were. It also keeps module
  commands in scope, since an explicitly-allowing identity accepts any name that is not
  hard-denied.

  Calling the real `acl::check` rather than duplicating `HARD_DENY` keeps the policy in one place,
  and a command that later becomes reachable enters the drift categories automatically.

  Backend: `redis/redis-stack-server` started by testcontainers and **pinned to the same digest
  as the parity job** (`ci.yml:106`), with the digest held in a `const` plus an assertion that
  `.github/workflows/ci.yml` contains it — the `source()`-reads-the-workflow pattern
  `tests/phase9_wiring.rs` already uses. A floating tag would not honour the "pinned backend"
  claim, and a second independent digest would rot.

  **How the digest reference is actually constructed**, because this is a trap: testcontainers
  0.28.0 builds the image reference as an unconditional `format!("{name}:{tag}")`
  (`core/containers/request.rs:182-190`) and has no digest-aware constructor, so the obvious
  `GenericImage::new("redis/redis-stack-server", "sha256:<hex>")` yields
  `redis/redis-stack-server:sha256:<hex>` — a *tag* named `sha256:<hex>`, which pulls nothing and
  pins nothing. Split the reference across the join instead:

  ```rust
  GenericImage::new("redis/redis-stack-server@sha256", DRIFT_BACKEND_DIGEST)  // hex, no prefix
  ```

  and assert the composed descriptor equals `redis/redis-stack-server@sha256:<hex>` so a future
  testcontainers upgrade that changes the formatting fails loudly rather than silently unpinning
  the backend. Re-check the version in `Cargo.lock` at implementation time — a digest-aware
  constructor, if one has appeared, is the better path. This runs in the existing integration job
  (`cargo test --all-features`, which has Docker); the extra image pull is a deliberate cost, and
  `CLAUDE.md`'s "CI cost is not a design constraint" governs.
- Layer B parity test: the same out-of-prefix request also gets NOPERM from a `~tenant:*` Redis
  ACL user — proving the proxy 403 is a clean failure mode, not the security boundary.
- `tests/mutation_guard.rs` — required, and its assertion is set equality, so these are additions
  that must each report `killed` (and whose search text must match exactly once):
  1. `key_prefix.rs`: `(Some(f), None) => Ok(Some(f))` → `Ok(None)` (drops the floor when the
     claim is absent).
  2. `key_prefix.rs`: the `candidate.starts_with(floor)` test → `true`.
  3. `key_prefix.rs`: remove the empty-prefix rejection.
  4. `key_prefix.rs`: remove the metacharacter rejection.
  5. `acl.rs`: `check_key_prefix`'s table-absent arm → `Ok(())`.
  6. `key_spec.rs`: `visit_keys` stops after the first key — the MSET lock.
  7. `acl.rs`: drop `STORE` from the `SORT` guard.
  8. `key_spec.rs`: `KeyspaceWide` treated as `Keyless` — the `SCAN` enumeration lock.
  9. `key_spec.rs`: a container command with an unrecognized subcommand falls back to its
     top-level entry instead of denying.
  10–12. `command.rs`, `pipeline.rs`, `multi_exec.rs`: remove the `check_key_prefix` call, one
     mutation each.
- `tests/dependency_rule.rs` must stay green (everything new is `domain/`, so it should).

## Commit 4 — Documentation

- README, deployment policy: the conditionality (OPTIONAL when every pool has a dedicated
  instance or dedicated DB index + Layer B key patterns; **MANDATORY** when a pool shares a
  keyspace), `~prefix:*` provisioning, the dynamic-key denials, the module-command, `XREAD` and
  **`SCAN`** limitations, and the `srh_key_prefix` admin-mapper warning (replacing
  `README.md:559`). The `SCAN` denial is the one an operator will hit first and must not learn
  about from a 403 — say it in the same paragraph that recommends key prefixes, with the
  "enumerate from an operator credential, or key your own index" workaround.
- README, configuration reference: `pools.<name>.key_prefix` and the static-token `key_prefix` as
  documented fields, in the current-format example JSON as well as prose — the resolve rule
  (floor applies; a credential may only extend it) stated where an operator writing config will
  read it, and the recommendation to end a prefix at a separator (`tenant:`, not `tenant`), since
  byte-prefix matching means `t` covers `tenant2:` too.
- README `:464` and `srh-rust-spec.md:937`: correct the `+command|info` rationale. The grant is
  **not** for Phase 8 discovery any more — it is for the admin allowlist, which admin-allows
  `COMMAND COUNT|INFO|DOCS` at `acl.rs:261`. Keep the grant, keep `tests/phase9_wiring.rs:41`,
  `tests/regressions_redis.rs:184` and `ci.yml:47` unchanged, and note in passing that the sample
  ACL user is provisioned for the app client's needs — other admin-allowlisted commands
  (`COMMAND DOCS`, `CONFIG GET`, `LATENCY`, `MEMORY`, `ACL WHOAMI`) need their own grants if an
  operator wants them to work end to end.
- `srh-rust-spec.md`: record the discovery-mechanism deviation and its rationale in the Phase 8
  section (`:1188-1200`), add `STORE` to the SORT rule at `:853`, refresh `:963` and the
  "single `key_prefix` expressible" note at `:936`, drop the "Phase 8" marker at `:494`, and
  update the implementation-status line at `:12`.
- `CLAUDE.md`: the "Current implementation status" paragraph.

---

## Handoff contract to issue #7

Put these in the Phase 8 PR body so they survive to whoever picks up #7.

1. **Phase 8 adds no `Grant` field.** `key_prefix` is already in #7's proposed struct, so #7's
   golden field-set test is unaffected. Keep it that way.
2. **`domain::key_prefix::resolve(floor, candidate)` is the seam**, and `domain::identity::PoolPolicy`
   is the per-pool value it reads from. #7's fold function calls the same function with the same
   two arguments — a one-line move, not a redesign. This is what keeps #7's hardest acceptance
   criterion ("the Keycloak profile lands as a behavior-preserving move") achievable.
3. **The error semantics are settled**, so #7 inherits rather than re-decides them: a
   non-extending or invalid prefix is `AuthError::Forbidden` (403), definitive, never falling
   through to the next link in the chain; the claim value is never logged.
4. **`token_profile_contract.rs` gains one case**, which Phase 8 pre-builds the domain function
   for: a claim-sourced `key_prefix` that does not extend the server-configured floor widens
   nothing — and the paired case that an *absent* claim does not either. Both belong in the
   contract suite so every future profile inherits them. And #7's per-profile "claims may only
   narrow" README section must cover `srh_key_prefix` alongside `srh_pool` — Okta
   `user.profile.*`, Auth0 `user_metadata`, Entra directory extensions.

### Why Phase 8 goes first

Phase 8 is entirely local. #7's Okta half is blocked on roughly half a day of serial tenant
setup — a custom authorization server plus a claims mapping — before fixtures can be captured at
all. Phase 8 also settles the `key_prefix` trust question in a pure domain function, so #7 does
not have to answer a security design question in the middle of a refactor that is supposed to be
behavior-preserving.

---

## Reference: files this phase touches

| File | Change |
|---|---|
| `src/config.rs:112` | `StaticTokenConfig.key_prefix` — validated via `resolve` at load |
| `src/config.rs:116` | `PoolConfig` — add `key_prefix` floor |
| `src/config.rs` (`RawPoolConfig`, `from_new_value`) | parse the pool floor; env/legacy modes stay `None` |
| `src/config.rs` (`validate`) | prefix charset/length rules; static-token-vs-floor conflict fails at startup |
| `src/domain/key_prefix.rs` | **new** — `validate`, `resolve`, `PrefixError` |
| `src/domain/key_spec.rs` | **new** — `KeySpec`, `KeyPolicy` (`Keys`/`Keyless`/`KeyspaceWide`), the `NAME|SUB` table, `key_policy`, `visit_keys` |
| `src/domain/identity.rs` | **new** `PoolPolicy` |
| `src/domain/acl.rs:194-203` | SORT/SORT_RO guard gains `STORE` |
| `src/domain/acl.rs` | **new** `check_key_prefix` |
| `src/adapters/jwt_auth.rs:170,293` | `pools: HashMap<String, PoolPolicy>`; route through `resolve` |
| `src/adapters/static_auth.rs:15,31` | takes pool config; `new` returns `Result`; route through `resolve` |
| `src/main.rs` | `StaticAuth::new(..., &config.pools)?` |
| `src/http/command.rs:42` | call `check_key_prefix` |
| `src/http/pipeline.rs:49` | call `check_key_prefix` (per-slot) |
| `src/http/multi_exec.rs` | call `check_key_prefix` |
| `src/http/observability.rs` | register `srh_acl_rejections_total{cause="key_prefix"}` |
| `tests/phase7_metrics.rs` | assert the new family and cause |
| `tests/mutation_guard.rs` | twelve new mutations (see commit 3) |
| `tests/phase8_http.rs` | **new** |
| `tests/phase8_redis.rs` | **new** — drift (set equality, digest-pinned Redis Stack) + Layer B parity |
| `README.md`, `srh-rust-spec.md`, `CLAUDE.md` | docs |

Gates before each commit: `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`
(matching CI's integration job). The mutation sweep,
`cargo test --test mutation_guard -- --ignored --nocapture`, runs once before the release tag —
not per commit.

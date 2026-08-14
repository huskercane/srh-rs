# Managed Redis Service — Product Architecture Plan

Status: Proposal  
Last updated: 2026-08-13

> Supersedes the earlier draft of this document, which planned multi-region HA for SRH as a
> *consumer* of Upstash Global. The goal has changed: we are evaluating offering a managed,
> Upstash-compatible Redis service, with SRH as the data-plane front door. Building on Upstash
> itself is therefore off the table, and several items the old draft treated as impediments
> (sync tokens, RDB export, private networking, primary/replica routing) are now roadmap
> features. The still-valid HA, persistence, and backup content is retained below, scoped
> per-tenant.

## Vision

Offer a managed Redis-compatible service with an Upstash-compatible HTTP API:

- SRH is the data plane: wire compatibility with `@upstash/redis` is already its top-level
  requirement, so the SDK contract is the product's API contract.
- Self-hosted Redis-protocol backends (Valkey and/or Kvrocks — see the engine decision below).
  We do not build on a competitor's platform.
- Differentiators over Upstash, rather than parity gaps: Keycloak/JWT authentication,
  Redis-side ACL identities, tenant key restrictions, command policy, script allowlisting,
  and per-credential rate limiting are already implemented in SRH and are features Upstash
  does not offer. BYOC/self-hostable deployment and EU data residency are natural extensions
  of the same posture.

## Decision 1: tenancy and storage engine

This is the first decision, before regions, backups, or pricing — everything else hangs off it.
It is a business decision wearing an architecture costume, because **the economics of serverless
Redis are a RAM problem**: per-request pricing only works if idle tenants do not burn memory.

Candidate models:

1. **Shared instance, key-prefix + ACL isolation** (SRH Phase 8, in progress).
   Cheapest; weakest. Redis has no per-prefix memory quota, so one tenant can evict or OOM
   every other tenant on the instance. Suitable for internal multi-tenancy (e.g. WhiskerWatch
   under `ww:auth:`); not sellable as isolation on its own.
2. **Instance-per-tenant** — a small Valkey process per database. Roughly Upstash's model and
   the sane default for paid tiers: real memory quotas via `maxmemory`, real blast-radius
   isolation, per-tenant backup/restore for free. Cost: orchestrating thousands of small
   processes, and dedicated RAM for idle tenants — free-tier economics do not close here.
3. **Disk-backed engine — Apache Kvrocks.** Speaks the Redis protocol (fred works unchanged),
   stores on RocksDB so cost scales with disk not RAM, and has native namespaces with
   per-namespace tokens — key-prefix isolation at the storage layer instead of in the proxy.
   Directly attacks the free-tier/idle-tenant economics. **Namespaces are logical isolation
   only** (key prefixing plus per-namespace credentials): they prevent cross-tenant key
   access, but tenants still share CPU, disk I/O, RocksDB compaction, caches, replication
   bandwidth, and failure blast radius. Resource isolation must be enforced externally or
   proven adequate — the validation gate in the rollout plan lists the specific criteria.

Likely landing point: a hybrid by tier — Kvrocks-backed shared/serverless tier, Valkey
instance-per-tenant for dedicated/paid tiers. Validate before committing.

Engine licensing: use **Valkey**, not Redis proper, for the in-memory engine — BSD-licensed,
drop-in for fred, and it removes the RSALv2/SSPL question from a commercial offering.

## Data plane: SRH changes required

SRH's current spec assumes a static deployment. A service changes two pillars:

- **The "config hot-reload is a non-goal" pillar collapses.** Tenants are provisioned and
  deleted continuously; pools, tokens, and ACLs cannot live in a static file that requires a
  restart. SRH needs a control-plane-driven dynamic tenant registry. This is the single
  biggest spec change the product implies — bigger than sync tokens or replica routing — and
  it also breaks the "one connection string per pool" model.
- **Replica-aware routing and read-your-writes become product features** (design below).

Smaller but equally mandatory spec changes that fall out of the designs below: a pinned-
connection executor operation for `WAIT`/`WAITAOF` and sync-position capture, and a two-level
readiness model (platform vs. per-tenant). All of these are spec extensions and must be
written into `srh-rust-spec.md` as phases before implementation; none are configuration
tweaks.

### Read-your-writes / `upstash-sync-token`

SRH currently ignores `upstash-sync-token`, so `readYourWrites` in `@upstash/redis` provides no
guarantee through SRH today. The token is a REST-level concept with no RESP equivalent, so it
cannot be forwarded upstream — SRH must manufacture the guarantee itself from the engine's
replication position.

**A bare replication offset is not a dataset version and is unsafe across failover.** Redis
identifies a dataset position as *(replication ID, offset)*; promotion creates a new
replication ID, so after a failover the same numeric offset can describe a different history.
The token must therefore be opaque and versioned, containing at least:

- Tenant/database ID (a token must never validate against another tenant's lineage).
- Replication ID and offset.
- Topology/failover epoch.
- An HMAC for integrity (clients echo the token; they must not be able to forge or splice one).
- Optionally expiry/version fields for future evolution.

Replica eligibility compares **lineage first, then offset**, honoring Redis's secondary
replication ID rules (a replica whose history passed through the token's replication ID up to
at least the token's offset is eligible). Unknown or obsolete lineage falls back to the
primary — never a numeric-offset comparison across lineages.

Mechanics:

- On a write, capture the primary's replication ID and offset **on the same connection that
  executed the write** (see connection pinning below) and return the sealed token; the SDK
  already echoes it on subsequent requests.
- On a read carrying a token, serve from the local replica only if its lineage and applied
  offset satisfy the token; otherwise fall through to the primary.
- Do not call `INFO` per request: poll each replica's replication ID/offset every ~50–100 ms
  and compare against the cached value. The staleness window only means a few reads
  conservatively go to the primary. Bounded, cheap, no new failure modes.

Until this ships, route all commands — including reads — to the primary, and do not advertise
read-your-writes support. Sessions, authentication state, locks, and read-after-write
workflows are the workloads that break without it.

### Durability controls (`WAIT` / `WAITAOF`)

With our own replicas, SRH can issue `WAIT N timeout` after writes on designated pools.
**`WAIT` alone is not a durability guarantee and must not be marketed as one**: it confirms
replicas processed the write *in memory*, not that anything reached durable storage, and
Sentinel is free to promote a replica that never acknowledged. Redis itself describes `WAIT`
as reducing loss probability, not providing consistency. A sellable tier must specify the
whole policy, not just the command:

- **Which replicas must acknowledge**, and **which are eligible for promotion** — the ack set
  and the promotion-candidate set must overlap (replica-priority configuration, or a
  promotion controller that restricts candidates to acknowledged replicas), or the ack buys
  nothing on failover.
- **Whether persistence acknowledgement is required** — use `WAITAOF` where the engine
  supports it for fsync-level acknowledgement; confirm support per engine (Valkey vs.
  Kvrocks) during validation.
- **Timeout semantics**: when fewer than N replicas acknowledge in time, the write has
  already executed and cannot be rolled back. The API response must distinguish success,
  degraded durability, and indeterminate outcome — a timeout is not a failure and must not be
  reported as one.
- **Engine-side floors**: pair with `min-replicas-to-write` / `min-replicas-max-lag` and the
  persistence policy, so the engine refuses writes when the durability floor is unmeetable
  rather than acknowledging into a doomed history.

Specified this way, the tier turns "unbounded replication lag" into a measured, alertable
RPO and prices naturally as a paid option; specified as "we call WAIT", it is marketing on
top of an in-memory ack.

### Connection pinning for `WAIT` and sync capture

Redis tracks the offset relevant to `WAIT` **per client connection**. SRH's current executor
port releases the backend handle after an operation; a naive "write, then separately issue
`WAIT`" could lease a different connection and wait on the wrong offset. The spec amendment
must introduce an atomic executor operation that pins one backend connection for the full
sequence:

    write / pipeline / transaction → WAIT or WAITAOF → capture (replication ID, offset)

This applies to `/pipeline` and `/multi-exec`, not only single-command requests, and it is
the same pinned capture the sync-token design depends on.

### Rate limiting vs. plan enforcement

These are two different controls and must not be conflated:

- **Local safety limits** stay exactly as they are: in-process, debt-aware, per-credential
  buckets protecting each SRH instance and its region. Do **not** centralize these in Redis —
  admission control must not depend on the backend it protects (fails open or takes the front
  door down), and it adds a round-trip per request. With N regional instances the effective
  aggregate is roughly N× the per-instance limit and failover hands out fresh buckets; that
  is acceptable *for a safety limit*, and per-instance sizing should account for N.
- **Global plan quotas** (the commercial "requests per second on plan X") are *not* enforced
  by the local buckets — an N× overshoot is not a quota. Enforce them with asynchronously
  allocated **quota leases from the control plane**: each SRH instance holds a lease for a
  share of the credential's global allowance, refreshed out-of-band, so there is no backend
  round trip on the request path but the global allowance stays meaningful. Lease refresh
  failure degrades toward the local safety limit, never toward unlimited.

## Control plane

Currently zero lines of this plan, and routinely half the engineering effort of a managed
database product. Must be scoped as its own workstream:

- Tenant provisioning and deletion (drives the SRH dynamic registry).
- Metering — SRH accurately meters **commands and HTTP bandwidth**. It cannot infer billable
  storage from commands (overwrites, compression, expiration, deletion, scripts, and engine
  metadata all move storage unpredictably): storage usage comes from the engine — per-instance
  metrics for Valkey tenants, per-namespace disk accounting for Kvrocks — with periodic
  control-plane reconciliation.
- Billing and plan enforcement (global quota leases, memory quotas, durability tiers).
- Token issuance and identity — Keycloak fits; SRH already consumes it.
- Per-tenant backup, restore, and RDB export (a feature we offer, not a workaround we need).
- Console/UI, TLS certificate automation, audit surfaces.

## Per-tenant replication and multi-region HA

SRH is stateless; running it in every region is straightforward. The data layer is the hard
part. Independent writable Redis instances cannot be safely synchronized after the fact:
`INCR`, expirations, transactions, sets, and Lua scripts need a real distributed
conflict-resolution protocol. **Do not build ad hoc multi-primary synchronization, and do not
fork the engine to attempt synchronous replication or consensus** — everything below uses
stock engine features plus SRH-side logic.

Per tenant ("global database" is a per-tenant property, not a platform-wide one):

- A primary in the tenant's chosen write region.
- At least one replica in another availability zone.
- Optional asynchronous replicas in the tenant's read regions.
- Sentinel (or an equivalent managed failover controller) for promotion. Fred consumes
  Sentinel configuration and discovers the new primary itself, so a failover does not require
  an SRH restart.
- All writes routed to the elected primary; replica reads only via the sync-token mechanism
  or for workloads explicitly marked stale-tolerant (caches, noncritical personalization —
  note: rate-limit counters are `INCR`-based writes and go to the primary regardless).

Cross-cloud Sentinel requires careful quorum placement: at least three voting failure domains,
majority required for promotion, and no isolated cloud may promote itself during a partition.

Redis replication is asynchronous. `WAIT` reduces the probability of losing a write; it does
not make the system strongly consistent.

**Active-active / local writes in every region is explicitly deferred** — not offered at
launch. If a tenant truly needs it, that is CRDT territory (Redis Enterprise Active-Active or
application-level per-tenant home regions with an explicit ownership-migration protocol), and
we should resell or partner rather than build.

References:

- [Redis replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/)
- [Redis Sentinel](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/)
- [Valkey](https://valkey.io/) · [Apache Kvrocks](https://kvrocks.apache.org/)

## Persistence and backup

Replication, persistence, and backups address different failures:

- Replication handles instance, zone, or region failure.
- Persistence handles engine process or node restart.
- Backups handle deletion, corruption, faulty deployments, and compromised credentials.

Per tenant (in-memory tier):

- `maxmemory-policy noeviction` for session/authentication data; per-tenant `maxmemory`.
- AOF with `appendfsync everysec` (≈1 s local persistence RPO) plus periodic RDB snapshots.
- Persistent encrypted disks on all failover candidates, not only the primary.
- `BGSAVE` snapshots shipped to encrypted, versioned, cross-region — preferably
  cross-account — object storage. Self-hosting makes this a file on our own disk;
  point-in-time-consistent, and exportable to tenants as a product feature.
- Monitor AOF rewrites, RDB saves, replication lag, disk capacity, restore validity.

Platform retention policy (independent of any per-tenant setting):

- Hourly backups for 48 hours; daily for 30–90 days; weekly for 6–12 months.
- Object lock / immutable retention on the protected tier (defense against compromised
  platform credentials).
- Monthly automated restore into a temporary instance, with checksums, key-count sampling,
  restore-time measurement, and alerts on failed export or validation.

The Kvrocks tier persists via RocksDB; its backup story (checkpoint/export) needs its own
validation during the engine evaluation.

Reference: [Redis persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)

## Traffic management and health

- Regional SRH deployments behind global routing. Be realistic about the mechanism: true
  cross-cloud anycast means owning IP space and BGP or fronting with a third-party edge;
  the practical default is latency-based DNS with health checks. **DNS TTL does not strictly
  bound failover time** — recursive resolvers and clients may cache beyond the advertised
  TTL, and health-check convergence adds its own delay — so treat the failover objective as
  a measured target for conforming resolvers. If the RTO must be contractual, front with a
  third-party edge proxy for deterministic failover.
- `/health` is process liveness only. Readiness must be split into two levels — the current
  SRH semantics (`/ready` fails if any built pool is unready) do not survive multi-tenancy,
  where one broken tenant backend would remove an otherwise healthy regional deployment from
  global routing:
  - **Platform readiness** (drives global traffic): listener, tenant registry, authentication
    dependencies, and enough backend capacity to accept traffic.
  - **Per-tenant backend health**: a scoped 503 for that tenant's requests plus that pool's
    circuit breaker. Per-tenant failure must never cause platform-wide failover.
- Authentication configuration, ACLs, tokens, certificates, and tenant/pool definitions
  deployed consistently to every region (via the control plane, not config files).
- Backends on private networks (VPC / WireGuard between clouds), reachable only from SRH
  egress — achievable because we own the backends.
- Test complete region isolation, not only process termination.

## Initial service objectives

Confirm against product requirements before implementation:

- SRH endpoint failover RTO: < 60 s as a **measured target for conforming resolvers** (state
  the DNS TTL and health-check convergence alongside); contractual guarantees require an edge
  proxy, not DNS.
- Redis leader/region failover RTO: < 2 min.
- Local node restart RPO (AOF everysec): ≈ 1 s.
- **Region-failover RPO: measured replication lag by default.** The `WAIT`/`WAITAOF` tier
  reduces expected loss **only when promotion is restricted to acknowledged replicas** — the
  RPO statement must name both the acknowledgement policy and the promotion policy, or it
  overstates the guarantee. This is the number product must sign off on — it was missing from
  the earlier draft and it is the most likely data-loss event.
- Backup/disaster RPO: 1 hour.
- Backup restore RTO: measured and set after the first full-size restore drill.

## Rollout plan

1. **Engine/tenancy validation**: Kvrocks compatibility pass (commands, Lua, transactions,
   expiry, namespaces) and Valkey instance-per-tenant orchestration spike. Because Kvrocks
   namespaces are logical-only isolation, the gate explicitly includes: per-namespace storage
   quotas or an external enforcement mechanism; CPU/I/O fairness; compaction-induced tail
   latency; backup/restore of one namespace without affecting others; namespace deletion and
   secure reclamation; and noisy-neighbor/overload tests. Also confirm per-engine support for
   `WAIT`/`WAITAOF` and replication ID/offset introspection. Attach the cost model per tier.
   This gates everything.
2. **Spec amendments** to `srh-rust-spec.md`: dynamic tenant registry, replica-aware pools,
   versioned sync-token design, pinned-connection executor operation
   (write → `WAIT`/`WAITAOF` → position capture, covering pipeline and multi-exec),
   two-level readiness, durability-tier policy — written and reviewed before code.
3. Control-plane MVP: provision/delete tenants, token issuance via Keycloak, metering hooks.
4. Deploy SRH in two or three regions behind latency-based routing; all reads to primaries.
5. Per-tenant replication + Sentinel; persistence and platform backup tiers as above.
6. Offset-based sync tokens; enable replica reads for read-your-writes workloads only after
   the mechanism is tested end-to-end through the SDK.
7. `WAIT`/`WAITAOF` durability tier for designated pools (sessions/auth first), including the
   promotion-eligibility controls and timeout/degraded-response semantics — the tier ships as
   a policy, not a command.
8. Failure exercises: SRH process, availability zone, engine primary, entire region, global
   routing provider, and accidental data deletion. Record measured RPO/RTO; revise objectives.

## Non-goals and lines not to cross

- No fork or patch of the engine. Everything above uses stock Valkey/Kvrocks features plus
  SRH-side logic; a fork means owning security patches forever for no unique capability.
- No ad hoc multi-primary synchronization between ordinary Redis instances.
- No active-active at launch.
- No Redis-backed rate limiter in the admission path.
- Building on Upstash or any competitor's data layer.

## Open questions

- Kvrocks compatibility surface vs. the command set SRH's ACL layer already models.
- Per-engine support matrix for `WAIT`, `WAITAOF`, and replication ID/offset introspection
  (Valkey vs. Kvrocks), and how Sentinel-equivalent promotion works for Kvrocks.
- Quota-lease protocol details: lease duration, refresh cadence, and degraded behavior when
  the control plane is unreachable.
- Free-tier economics: idle-tenant cost per engine option, with real numbers from the spike.
- Whether the dynamic tenant registry lives in SRH proper or a sidecar the registry port
  consults (keep the six-port discipline in mind; a seventh port needs written justification).
- Legal review of "Upstash-compatible" positioning (wire compatibility is fine; naming and
  trademark use need checking).

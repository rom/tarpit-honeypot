# tarpit-honeypot — Database backend

Status: design + implementation note. Tracks the shipped `EventStore`
seam and describes the optional PostgreSQL backend it was built for.
Scope: how events are persisted, why the edge stays on embedded SQLite,
and how a client-server database fits the **fleet aggregator** tier.

See also: [`design.md`](design.md) (overall architecture, §8 Persistence),
[`fleet.md`](fleet.md) (sensor → aggregator → hub topology),
[`internals.md`](internals.md), and the schema/queries in
`internal/store/store.go`.

---

## 1. TL;DR

The sensor already has a database: an **embedded SQLite index**
(`modernc.org/sqlite`, pure-Go, CGO-free) at `<data_dir>/events.db`. The
meaningful question is not "add a database" but **"where does a
client-server database belong?"** The answer is a two-tier split:

- **Leaf sensors keep SQLite.** It is correct there and central to the
  project's identity (one static binary, runs on a Raspberry Pi, no
  egress, nothing to operate). Do **not** move the edge to a server DB.
- **Fleet aggregators / hubs get an optional PostgreSQL backend.** This
  is where many forwarders write concurrently, multiple analysts query,
  and HA / replication / backups actually matter.

Recommended engine: **PostgreSQL** via the pure-Go `jackc/pgx` driver
(keeps the binary CGO-free). ClickHouse is the documented scale-out
alternative for very high sustained volume.

The first implementation step has shipped: a single `store.EventStore`
interface that the write path (the SQLite sink) and the read path (the
web UI + `/search`) now depend on, so a second backend can drop in behind
the same contract. See §6.

---

## 2. The two storage roles

The same binary plays different roles in a fleet (see [`fleet.md`](fleet.md)).
Storage requirements diverge sharply by role:

| Tier | Config | Workload | Storage |
|------|--------|----------|---------|
| **Leaf sensor** | `listeners:` | One vantage point; modest write rate; local reads | **Embedded SQLite** (keep) |
| **Forwarder** | `forward:` | Ships events upstream; little local state | SQLite (keep) |
| **Aggregator / hub** | `ingest:` | Many forwarders writing; fleet-wide analytical reads; long retention; multi-analyst | **PostgreSQL** (opt-in) |

Why the edge must **not** move to a server database:

- `design.md` §1/§12 commits to "one static binary… runs from a Raspberry
  Pi… no egress required." A per-leaf server DB breaks all three.
- `design.md` §2 lists "distributed collector with a hosted control
  plane" and "hosted SaaS control plane" as **non-goals**. The Postgres
  backend stays inside that boundary: it is an *optional, self-hostable*
  aggregator store, not a mandatory control plane.
- A leaf is an exposed, attacked host. Putting database credentials and a
  network DB dependency on it enlarges the blast radius for no benefit.

Why the aggregator benefits:

- SQLite is single-writer. A hub ingesting batches from many forwarders
  (`internal/ingest` → `InsertBatch`) serializes every write through one
  lock on one file on one host.
- No concurrent multi-analyst access, no replication, no point-in-time
  recovery for what is effectively an evidence store (it holds captured
  payloads, source IPs, and harvested credentials).
- Fleet-wide aggregations (`Summary`, `SourceAggregates`,
  `EventsPerBucket`) grow with the whole estate's volume, not one node's.

---

## 3. Engine choice: PostgreSQL

The workload is append-heavy event ingest with analytical reads
(time-window `GROUP BY` rollups, top-N, per-source profiles), point
lookups by id, lots of semi-structured `meta_json`, and time-based
retention. PostgreSQL fits each:

- **Keeps the binary CGO-free.** `jackc/pgx` is pure Go, so the ~14 MB
  static-binary story and the `make cross` matrix are unchanged. This
  constraint alone rules out engines that need cgo client libraries.
- **JSONB replaces `meta_json` scans.** Today the hottest meta filters
  (`json_extract(meta_json,'$.asn'/'$.geo_city'/…)` in
  `internal/store/store.go`) are full scans. As **GIN-indexed JSONB**
  they become index lookups, with no schema churn when handlers add new
  meta keys.
- **Native time partitioning turns retention into metadata.** Retention
  today is `DELETE FROM events WHERE time < ?` plus a 10%-oldest prune
  (`internal/retention`, `internal/store` `maybePrune`) — both rewrite
  the table. With `PARTITION BY RANGE (time)`, expiring a day is `DROP
  TABLE events_2026_06_18`: instant, no bloat, no vacuum storm. This is
  the single biggest operational upgrade.
- **Real concurrency + durability.** MVCC lets many forwarders write
  while many analysts read; streaming replication / managed failover give
  the evidence store the durability it deserves.
- **Boring and ubiquitous.** Every cloud (RDS / Cloud SQL / Supabase /
  Neon), backup tool, and monitoring stack already speaks Postgres — the
  right default for a project whose ethos is operability.

### Alternatives considered

| Engine | Verdict |
|--------|---------|
| **ClickHouse** | Best at pure analytical scan/compression + built-in TTL. Document as the scale-out path; reach for it only at sustained tens-of-thousands of events/sec across a large estate — heavier to operate than most fleets need. |
| **MySQL / MariaDB** | Workable, but Postgres's JSONB + declarative partitioning + richer aggregation are a better fit; no reason to prefer it. |
| **MongoDB** | Schemaless suits `meta_json`, but the dashboards are fundamentally SQL aggregations — you'd fight the engine. |
| **Elasticsearch / OpenSearch** | That is a *SIEM sink*, already supported (CEF/LEEF/OCSF, syslog). Keep it downstream, not as the system of record. |
| **DuckDB** | Embedded columnar — great as an analytics layer over exports, but single-writer/embedded like SQLite, so it does not solve the multi-writer aggregator problem. |

**Decision:** PostgreSQL (pgx) at the aggregator, SQLite at the edge,
ClickHouse as a documented scale-out option.

---

## 4. Architecture

```
  leaf sensors (SQLite, no egress)
     │  forward NDJSON batches (internal/forward, HTTPS + bearer/HMAC)
     ▼
  ┌─────────── aggregator / global hub ───────────┐
  │  internal/ingest  ──►  store.EventStore (interface)
  │                          ├─ *store.Store  (embedded SQLite, default)
  │                          └─ pgStore       (PostgreSQL, opt-in)   ← future
  │  web UI · /search · CLI reads ──► same store.EventStore
  └────────────────────────────────────────────────┘
                          │
              pg streaming replica / managed backups
```

The seam is a single interface. Collaborators (the sink that writes, the
UI/search that reads) depend on `store.EventStore`, never on a concrete
engine. The **sensor is the composition root**: it constructs the
concrete store, wires the engine-specific paths, and hands collaborators
the narrower interface.

### 4.1 Schema sketch (PostgreSQL)

A translation of the SQLite schema in `internal/store/store.go`, upgraded
where the server engine allows:

```sql
CREATE TABLE events (
    id          text        NOT NULL,
    time        timestamptz NOT NULL,     -- native type vs. int64 nanoseconds
    sensor      text NOT NULL,
    sensor_id   text,
    rule_id     text NOT NULL,
    severity    smallint NOT NULL,
    src_ip      inet,                     -- real inet type → CIDR/network queries
    dst_ip      inet,
    src_port    int, dst_port int,
    proto       text, handler text, country text,
    banner_id   bigint,
    payload_b64 text, payload_len int,
    meta        jsonb,                    -- replaces meta_json + json_extract scans
    anomalies   jsonb,
    mitre_techniques jsonb, mitre_tactics jsonb, mitre_defenses jsonb,
    PRIMARY KEY (id, time)
) PARTITION BY RANGE (time);

CREATE INDEX ON events (time DESC);
CREATE INDEX ON events (src_ip, time DESC);
CREATE INDEX ON events USING gin (meta);            -- the meta filters, now indexed
CREATE INDEX ON events (handler, time DESC);
-- remaining indexes mirror internal/store indexStmts
```

The `Filter` → `WHERE`/`GROUP BY` query *shapes* are unchanged, so each
`EventStore` method is a dialect port, not a redesign. `inet` and `jsonb`
are strict upgrades the edge SQLite cannot match.

> **v1 implementation note.** The shipped `pgstore` (§6) uses this schema
> as the baseline migration (`migrations/0001_init.sql`), with `events`
> **RANGE-partitioned monthly on `time`** and a DEFAULT partition. Two
> deliberate simplifications keep it a behaviour-identical first cut: event
> time is `bigint` nanoseconds and IPs are `text` (matching the SQLite
> store exactly, so the engine-neutral `Filter`/`event` types are reused
> unchanged). `meta` is already `jsonb` (with a GIN index). Because the
> partition key must be in every unique constraint, the primary key is
> `(id, time)`; `id` is unique in practice, so event-id dedup is preserved.
> `timestamptz`/`inet` are the remaining optimisation path in §6.

### 4.2 Retention by partition drop

Implemented in `internal/store/pgstore/partitions.go`. The runtime keeps
the current + adjacent monthly partitions provisioned (at `Open` and lazily
on the write path); the DEFAULT partition guarantees an insert never fails
for want of a partition. `PruneBefore` then enforces retention by
**dropping whole monthly partitions older than the cutoff** (instant, no
row scan or vacuum), followed by a small boundary `DELETE` over the partial
current month + DEFAULT partition so the cut stays *exact* rather than
rounded to a whole month. `internal/retention` calls this through the same
engine-neutral `PruneBefore` it uses for SQLite.

---

## 5. Configuration (proposed)

One DSN is the entire added surface; the default stays SQLite so existing
deployments and `make` are untouched:

```yaml
sensor:
  data_dir: /var/lib/tarpit        # SQLite path (default, unchanged)
  store:
    backend: postgres              # default: sqlite
    dsn_env: TARPIT_PG_DSN         # DSN read from env, never the file —
                                   # matches the ingest-token convention (fleet.md §2)
```

Reading the DSN from an environment variable (not the YAML) mirrors how
ingest bearer tokens and HMAC keys are already handled.

---

## 6. Implementation status

### Done — the `EventStore` seam

`internal/store/eventstore.go` defines `store.EventStore`, the
engine-neutral persistence contract, and asserts the embedded SQLite
store satisfies it (`var _ EventStore = (*Store)(nil)`). Adopted at the
two seams a second backend must plug into:

- **Write path** — `sink.NewSQLite(id, store.EventStore)` and the
  `sqliteSink` field (`internal/sink/sqlite.go`). The buffered batch
  writer serves any backend unchanged.
- **Read path** — `ui.New(cfg, store.EventStore)`, the `ui.Server.store`
  field, and `runSearch(ctx, store.EventStore, …)`
  (`internal/ui/ui.go`, `internal/ui/search.go`).

### Done — the PostgreSQL backend

- **`pgstore.Store` implements `store.EventStore`**
  (`internal/store/pgstore/pgstore.go`) via `database/sql` + the pure-Go
  pgx stdlib driver (CGO-free), with a compile-time
  `var _ store.EventStore = (*Store)(nil)`. Every `Filter` dimension,
  `Summary`/`SourceAggregates`/`EventsPerBucket`/`Fingerprints`, the IOC
  upsert, and `PruneBefore` are ported to the Postgres dialect. It is
  round-trip tested against PostgreSQL 16 (`pgstore_test.go`, which skips
  unless `TARPIT_PG_TEST_DSN` points at a disposable database).
- **`PruneBefore` is now on the contract.** Retention is engine-neutral:
  `retention.Runner` holds a `Pruner` (satisfied by both backends) instead
  of a raw `*sql.DB`, and both stores implement
  `PruneBefore(ctx, cutoff)`.
- **Backend selection.** `sensor.store.backend` / `dsn_env` config (§5)
  drives `openEventStore` in the sensor; the default stays SQLite, and a
  `postgres` backend reads its DSN from the environment.
- **Engine-specific paths stay off the contract.** `EnsureIndexes`/
  `MissingIndexes` (SQLite index self-heal in `alerts.go`) and `Path()`
  (the `metrics` DB-size gauge) are reached through optional type
  assertions; the file-only `prune-db`/`rotate-db` CLIs remain SQLite
  admin tools that open their own `*store.Store`.
- **Persistence channel follows the backend.** A `type: sqlite` channel
  wraps whatever `EventStore` is configured, so an aggregator with
  `backend: postgres` persists forwarded events to Postgres through the
  same batched sink.
- **Versioned, embedded migrations** (`migrate.go`, `migrations/*.sql`).
  An embedded, ordered SQL migration runner tracked in `schema_migrations`,
  guarded by a `pg_advisory_lock` so two aggregators can't race, applying
  each pending file in its own transaction. Runs at every `Open`;
  already-applied versions are skipped (§7.1).
- **Time partitioning + retention by partition drop** (`partitions.go`).
  `events` is monthly RANGE-partitioned with a DEFAULT catch-all; the
  runtime provisions the active window and `PruneBefore` drops expired
  partitions plus a boundary delete (§4.2). Verified against PostgreSQL 16
  (`TestPgPartitionRetention`).
- **CI runs both dialects.** The `build-test` job runs a `postgres:16`
  service and sets `TARPIT_PG_TEST_DSN`, so the pgstore round-trip +
  partition tests execute against a real server on every build (`.github/
  workflows/ci.yml`).
- **Deployment recipe.** `deploy/aggregator-postgres/` ships a
  docker-compose (Postgres + the aggregator) with a ready aggregator
  config; swap the bundled `postgres` service for a managed DSN to use
  RDS / Cloud SQL / Supabase / Neon (§7.4).

### Remaining

1. **Richer column types** — `timestamptz`/`inet` (the §4.1 sketch); v1
   uses `bigint` nanoseconds + `text` IPs to match the SQLite store
   exactly (see §4.1 note).
2. **ClickHouse backend** for very high sustained volume (§3).

---

## 7. Maintainability

Introducing a server database is where projects usually take on
operational debt. The guardrails:

### 7.1 Versioned, embedded migrations

Implemented for the Postgres backend (`internal/store/pgstore/migrate.go`
+ `migrations/*.sql`). Rather than the SQLite store's hand-rolled
`migrate()` (`ALTER TABLE … ADD COLUMN` guarded by `hasColumn()`), the
server backend uses ordered SQL files embedded with `embed.FS`, tracked in
a `schema_migrations` table, applied in version order each in its own
transaction. Migrations are reviewable, ordered, and idempotent, and ship
*inside* the binary — no external migration step to forget. A
`pg_advisory_lock` serialises migrators so two aggregators starting at once
can't race; multi-statement files apply through a dedicated simple-protocol
connection. A self-contained runner (rather than goose/golang-migrate)
keeps the dependency footprint in line with the project's single-binary
ethos.

### 7.2 Retention by partition drop, not DELETE

Implemented — see §4.2. Whole expired monthly partitions are dropped
(no row-by-row delete, no bloat, no `VACUUM` storm); only the partial
boundary month is deleted, to keep the cut exact.

### 7.3 Postgres stays optional

SQLite remains the zero-dependency default; the server backend is enabled
by one DSN. The promise "clone, `make`, run a single binary" must survive
— only operators who *want* a central database run one.

### 7.4 Prefer managed Postgres; document one self-host path

The lowest-maintenance path is a managed instance (RDS / Cloud SQL /
Supabase / Neon): backups, PITR, patching, and failover are someone
else's job. For self-hosters, `deploy/aggregator-postgres/` ships a
docker-compose (Postgres + the aggregator) with a ready config and
`pg_dump` instructions; its README also shows how to drop the bundled
`postgres` service and point `TARPIT_PG_DSN` at a managed instance. Either
way, one blessed path rather than leaving it to the reader.

### 7.5 Reuse existing observability

The sensor already exposes Prometheus metrics (`design.md` §13). Add
ingest lag, pool in-use/idle, and batch-commit latency; point operators
at `postgres_exporter` for DB-side stats; extend the `/health` probe
(which already surfaces `MissingIndexes()`) to ping the pool.

### 7.6 One query per dialect, behind the interface

The maintenance trap with two backends is divergent SQL. The
`EventStore` interface plus the shared, engine-neutral types (`Filter`,
`Summary`, `SourceAggregate`, …) keep each query defined once per engine;
callers (UI, CLI, correlators) never branch on backend.

### 7.7 Pooling and failure modes

pgx's pool replaces SQLite's `SetMaxOpenConns(12)`. Set sane pool bounds
and statement timeouts (mirror the UI's per-query deadlines), and keep
the batched sink's existing retry/fallback shape (`flushNow` already
falls back to per-row inserts) for a dropped network connection.

---

## 8. Boundaries

This design stays inside the project's stated non-goals
([`design.md`](design.md) §2):

- The Postgres backend is an **optional, self-hostable** aggregator
  store, not a hosted SaaS control plane.
- The **edge stays standalone** on SQLite with no egress requirement.
- Nothing here adds active response, plugin runtimes, or real code
  execution — it is purely how durable events are stored at a hub.

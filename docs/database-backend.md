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

### 4.2 Retention by partition drop

Wire `internal/retention` so that, on a partitioned backend, it `DROP`s
expired partitions and pre-`CREATE`s upcoming ones (a tiny scheduler, or
`pg_partman`). Retention stops being a row-by-row delete and a
performance event.

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

This was a behavior-preserving refactor: the sensor still constructs and
owns the concrete `*store.Store`, all tests pass, and the binary is
unchanged. Engine-specific methods deliberately stay **off** the
interface (on the concrete `*Store`): `DB()` (`*sql.DB` for the retention
runner), `Path()` (the file the `prune-db`/`rotate-db`/metrics CLIs stat),
and `EnsureIndexes`/`MissingIndexes` (SQLite index health).

### Remaining — to land the PostgreSQL backend

1. **`pgStore` implementing `store.EventStore`** (pgx pool, the §4.1
   schema, `Filter` ported to Postgres dialect with JSONB/`inet`).
2. **Backend selection** — `config` plumbing (§5) and a constructor that
   returns `EventStore` by backend; default SQLite.
3. **Abstract the engine-specific paths** so they are not SQLite-only:
   replace the retention runner's raw `DB() *sql.DB` `DELETE` with a
   neutral `PruneBefore(ctx, cutoff)` (partition drop on Postgres); gate
   the `prune-db`/`rotate-db`/`metrics` file-size CLIs on the SQLite
   backend (they operate on a file).
4. **Versioned migrations** — see §7.1.
5. **CI against both backends** — run the `internal/store` suite over
   SQLite and a throwaway Postgres (testcontainers) so the two dialects
   cannot drift.

---

## 7. Maintainability

Introducing a server database is where projects usually take on
operational debt. The guardrails:

### 7.1 Versioned, embedded migrations

Retire the hand-rolled `migrate()` (`ALTER TABLE … ADD COLUMN` guarded by
`hasColumn()` in `internal/store/store.go`) for the server backend. Use
ordered SQL files embedded with `embed.FS` and applied by **goose** or
**golang-migrate**, tracked in a `schema_migrations` table. Migrations
become reviewable, ordered, and idempotent — and still ship *inside* the
binary, so there is no external migration step to forget.

### 7.2 Retention by partition drop, not DELETE

See §4.2. No row-by-row deletes, no bloat, no `VACUUM` pressure.

### 7.3 Postgres stays optional

SQLite remains the zero-dependency default; the server backend is enabled
by one DSN. The promise "clone, `make`, run a single binary" must survive
— only operators who *want* a central database run one.

### 7.4 Prefer managed Postgres; document one self-host path

The lowest-maintenance path is a managed instance (RDS / Cloud SQL /
Supabase / Neon): backups, PITR, patching, and failover are someone
else's job. For self-hosters, ship a `docker-compose.yml` (Postgres + the
aggregator) and document `pg_dump` / `pg_basebackup`. Either way, bless
**one** path rather than leaving it to the reader.

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

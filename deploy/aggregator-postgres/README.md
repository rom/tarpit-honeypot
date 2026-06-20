# PostgreSQL-backed fleet aggregator (docker-compose)

A ready-to-run [fleet aggregator](../../docs/fleet.md) that persists events to
**PostgreSQL** instead of the embedded SQLite file — the backend described in
[`docs/database-backend.md`](../../docs/database-backend.md). Leaf sensors keep
SQLite and forward here; this tier gets concurrent writes, real backups, and
retention by partition drop.

## Quick start

```sh
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD and TARPIT_INGEST_TOKEN to long random values
docker compose up -d --build
```

This starts:

| Service | Purpose | Port |
|---------|---------|------|
| `postgres` | PostgreSQL 16, data in the `pgdata` volume | internal |
| `aggregator` | tarpit-honeypot in aggregator mode | `8470` ingest |

The schema is created and migrated automatically on first start (see
`internal/store/pgstore/migrations`).

The dashboards are **off by default**: reaching the UI through container
port-mapping needs a non-loopback bind, which the sensor (correctly) refuses
without TLS + an auth token. To turn them on, enable the `ui:` block in
`aggregator.yaml` with a cert/key + `auth_token_env`, publish `8080` in
`docker-compose.yml`, and front it with a TLS reverse proxy — see the comments
in those files and [`docs/hardening.md`](../../docs/hardening.md). Until then,
inspect the data with `psql` (below).

## Point leaf sensors at it

On each leaf, forward to this host with the matching token:

```yaml
# leaf config
forward:
  - id: site-agg
    url: https://AGGREGATOR_HOST:8470/ingest
    token_env: TARPIT_FWD_TOKEN     # set to this aggregator's TARPIT_INGEST_TOKEN
```

In production, terminate TLS in front of `:8470` (and `:8080`) — the compose
file exposes plain HTTP for a single-host trial. See
[`docs/hardening.md`](../../docs/hardening.md).

## Operating the database

- **Backups:** `docker compose exec postgres pg_dump -U tarpit tarpit > backup.sql`
  (or use a managed PostgreSQL and point `TARPIT_PG_DSN` at it instead of the
  bundled service — then drop the `postgres` service).
- **Retention:** controlled by `sensor.disk.retention_days` in `aggregator.yaml`;
  the backend drops whole expired monthly partitions.
- **psql:** `docker compose exec postgres psql -U tarpit tarpit`.

## Using managed PostgreSQL

Delete the `postgres` service (and the `depends_on`/`pgdata` volume), then set
`TARPIT_PG_DSN` on the `aggregator` service to your managed instance's
connection string (RDS / Cloud SQL / Supabase / Neon). Nothing else changes.

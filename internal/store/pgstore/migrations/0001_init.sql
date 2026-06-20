-- 0001_init: baseline schema for the PostgreSQL event store.
--
-- events is RANGE-partitioned on time (UnixNano) so retention can DROP whole
-- old partitions instead of deleting rows (see internal/store/pgstore/
-- partitions.go and docs/database-backend.md §4.2). The partition key must be
-- part of every unique constraint, so the primary key is (id, time); id is
-- globally unique in practice, so (id, time) preserves event-id dedup.
--
-- A DEFAULT partition catches any time not covered by an explicit monthly
-- partition (clock-skewed or pre-existing historical rows), so an insert can
-- never fail for want of a partition. The runtime creates the current +
-- adjacent monthly partitions; retention drops the old ones.

CREATE TABLE IF NOT EXISTS events (
  id text NOT NULL,
  time bigint NOT NULL,
  sensor text NOT NULL DEFAULT '',
  sensor_id text NOT NULL DEFAULT '',
  rule_id text NOT NULL DEFAULT '',
  severity int NOT NULL DEFAULT 0,
  src_ip text NOT NULL DEFAULT '',
  src_port int NOT NULL DEFAULT 0,
  dst_ip text NOT NULL DEFAULT '',
  dst_port int NOT NULL DEFAULT 0,
  proto text NOT NULL DEFAULT '',
  handler text NOT NULL DEFAULT '',
  banner_sent text NOT NULL DEFAULT '',
  payload_b64 text NOT NULL DEFAULT '',
  payload_len int NOT NULL DEFAULT 0,
  meta jsonb,
  anomalies jsonb,
  mitre_techniques jsonb,
  mitre_tactics jsonb,
  mitre_defenses jsonb,
  country text NOT NULL DEFAULT '',
  PRIMARY KEY (id, time)
) PARTITION BY RANGE (time);

CREATE TABLE IF NOT EXISTS events_default PARTITION OF events DEFAULT;

CREATE TABLE IF NOT EXISTS iocs (
  type text NOT NULL,
  value text NOT NULL,
  first_seen bigint NOT NULL,
  last_seen bigint NOT NULL,
  count bigint NOT NULL,
  severity int,
  last_rule text,
  last_sensor text,
  last_source text,
  PRIMARY KEY (type, value)
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip_time ON events(src_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_rule_id_time ON events(rule_id, time);
CREATE INDEX IF NOT EXISTS idx_events_handler_time ON events(handler, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip_time ON events(dst_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_country_time ON events(country, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity_time ON events(severity, time);
CREATE INDEX IF NOT EXISTS idx_events_meta_gin ON events USING gin (meta);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);

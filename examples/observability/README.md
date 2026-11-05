# Observability — Prometheus + Grafana

The sensor publishes Prometheus text-format metrics at `/metrics` on the web UI
(enable with `ui.enabled: true`). This directory ships a ready-to-import Grafana
dashboard and a sample Prometheus scrape config.

## Files

| File | What |
|---|---|
| `prometheus-scrape.yml` | A `scrape_configs:` block to add to your `prometheus.yml` (bearer-token auth + TLS matched to the UI). |
| `grafana-dashboard.json` | An importable Grafana dashboard (**Dashboards → New → Import → Upload JSON**). On import, pick the Prometheus datasource that scrapes the sensor. |

## Dashboard panels

- **Overview row** — active listeners, lifetime event total, critical-event rate,
  honey tokens tracked, KEV catalog size, disk used.
- **Detections row** — event rate by severity (critical/high/medium/amber/low,
  semantically coloured), event rate by rule kind
  (`listener`/`cve`/`canary`/`correlate`/…), top detection rules by lifetime
  hits, and the canary + CVE signal rate.
- **Infrastructure row** — sink delivery problems (dropped/failed/retried per
  channel), L2 sniffer frames by protocol, events DB size, recovered panics,
  honeynet host count, uptime.

## Metrics reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tarpit_events_total` | counter | — | All events dispatched since start |
| `tarpit_events_by_severity_total` | counter | `severity` | Events by severity |
| `tarpit_events_by_kind_total` | counter | `kind` | Events by rule-id prefix (`listener`/`cve`/`canary`/`correlate`/…) |
| `tarpit_detect_rule_hits_total` | counter | `rule`,`severity` | Operator detection-rule matches |
| `tarpit_listeners_active` | gauge | — | Currently-bound listeners |
| `tarpit_honey_tokens_tracked` | gauge | — | Distinct synthetic creds the reuse tracker holds |
| `tarpit_kev_catalog_entries` | gauge | — | CISA-KEV entries in the live overlay (absent when the feed is off) |
| `tarpit_kev_last_update_timestamp_seconds` | gauge | — | Unix time of the last KEV refresh |
| `tarpit_sink_dropped_total` / `_failed_total` / `_retried_total` | counter | `channel` | Sink delivery health |
| `tarpit_sniffer_frames_total` | counter | `proto` | L2 frames captured by the AF_PACKET sniffer |
| `tarpit_store_db_bytes` | gauge | — | On-disk SQLite events.db size |
| `tarpit_disk_used_percent` | gauge | — | `data_dir` filesystem usage |
| `tarpit_honeynet_networks` / `tarpit_honeynet_hosts` | gauge | — | Configured topology counts |
| `tarpit_uptime_seconds` | gauge | — | Process uptime |
| `tarpit_build_info` | gauge | `version`,`commit` | Always 1; carries build labels |
| `tarpit_panic_recoveries_total` | counter | — | Recovered panics (should stay 0) |
| `tarpit_panic_recoveries_by_name_total` | counter | `name` | Recovered panics per safego goroutine |

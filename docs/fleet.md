# Sensor fleets & aggregation

A single tarpit-honeypot sensor sees one vantage point. Once events from many
sensors converge on an **aggregator**, patterns invisible to any one node emerge:
the same source IP / ASN / TLS fingerprint hitting many honeypots, a malware hash
or credential recurring across sites, a CVE wave going live, a network that keeps
coming back. This guide covers the whole fleet story — concept, prerequisites,
installation, topologies, building aggregation, the cross-sensor detectors,
downward intel feedback, managing a fleet, common pitfalls, and troubleshooting.

A ready-to-adapt three-tier reference lives in
[`examples/fleet/`](../examples/fleet/).

---

## 1. The concept

Every node is the **same binary** in one (or several) of these roles:

| Role | Config | What it does |
|------|--------|--------------|
| **Sensor** | `listeners:` | Presents decoys, observes attackers, emits events. |
| **Forwarder** | `forward:` | Ships its events to one or more parent aggregators. |
| **Aggregator** | `ingest:` | Accepts forwarded events, feeds them into the same pipeline as local events. |
| **Correlator** | `fleet:` | Runs the cross-sensor detectors over the merged stream (auto-on with `ingest:`). |
| **Intel source** | `fleet.serve_intel` | Derives indicators from its findings and serves them downward. |
| **Intel subscriber** | `intel_feed:` | Pulls a parent's intel and tags its own events with it. |

A node can be all of them at once — a mid-tier aggregator ingests from leaves,
correlates, serves intel down, and forwards (or rolls up) to a higher tier.
**Events flow up; intel flows down.**

```
   leaf ─┐ forward (full)        ┌─ rollup ─┐
   leaf ─┤───────────────►  site-aggregator ──────────►  global-hub
   leaf ─┘ ◄── intel feed ──────┘                       (MISP / STIX / SIEM)
```

### Why aggregate?

A leaf sensor can detect a port scan against *itself*. It cannot see that the
*same* source is scanning ten other honeypots, that a JA3 fingerprint is shared
by a hundred rotating IPs, that a malware sample landed on three sites at once, or
that a brand-new ASN just appeared across the estate. Those are **fleet**
signals, and they are far higher-confidence than any single-node detection.

---

## 2. Prerequisites

- **Network reachability** from each forwarder to its aggregator's `ingest.bind`
  (HTTPS; default port in the examples is `8470`). Open that path in your
  firewall / security groups.
- **A shared secret per ingest endpoint.** Each aggregator has one bearer token
  (and optionally an HMAC key); every child that forwards to it uses the same
  token. Distribute via your secrets manager — they're read from **environment
  variables**, never the config file.
- **TLS in production.** Forwarding and the intel feed go over HTTPS through the
  egress allowlist. Terminate TLS on the ingest endpoint (`ingest.tls_cert` /
  `ingest.tls_key`) or front it with a TLS reverse proxy.
- **A store on aggregators.** The aggregator needs the SQLite store (a `sqlite`
  channel + route, or the UI) so the fleet findings, IOC store, and dashboards
  persist. Leaves can be storeless (pure forwarders).
- **Optional but recommended on aggregators:** GeoIP ASN/city databases
  (`sensor.geoip`) — several fleet detectors (`fleet:asn-*`,
  `geo-distributed-actor`, the ASN IOC type) need ASN/country enrichment. Fetch
  with `scripts/fetch-enrichment.sh`.
- **Clock sync (NTP)** across the fleet. Events carry the originating sensor's
  timestamp; the correlation windows tolerate modest skew, but wild clocks
  distort the temporal detectors (`scan-trajectory`, `synchronized-burst`,
  `recidivist-network`).

---

## 3. Installation & setup

### 3.1 A leaf sensor (forwarder)

Give each leaf a normal sensor config plus a `forward:` block. The forward
destination is **auto-allowlisted**, so it keeps working under `egress.enforce`.

```yaml
forward:
  - id: site
    url: https://agg-site.corp:8470/ingest
    token_env: TARPIT_FWD_TOKEN       # bearer token (from env)
    hmac_secret_env: TARPIT_FWD_HMAC  # optional body signature
    min_severity: low                 # forward everything (default)
```

```
export TARPIT_FWD_TOKEN=...      # must equal the aggregator's ingest token
tarpit-honeypot run -c leaf.yaml
```

Each forwarded event carries the originating `sensor_id` (a stable deployment id,
distinct from the hostname) and a `hops` chain stamped per node — the aggregator
dedups by `sensor_id:id` and detects loops. Delivery is at-least-once toward the
parent (bounded retry keeping the batch); a full queue sheds load with a counter.

### 3.2 An aggregator (ingest)

```yaml
ingest:
  enabled: true
  bind: 0.0.0.0:8470
  token_env: TARPIT_INGEST_TOKEN      # required (unauthenticated ingest is refused)
  hmac_secret_env: TARPIT_INGEST_HMAC # optional; verifies the body signature
  tls_cert: /etc/tarpit-honeypot/ingest.crt   # optional TLS
  tls_key:  /etc/tarpit-honeypot/ingest.key
  max_body_mb: 32                     # reject larger batches
  max_hops: 8                         # drop events that traversed more nodes (loop guard)
  dedup_window: 10m                   # sensor_id:id dedup TTL
# Pair with a store so forwarded events persist + power the fleet/IOC views.
channels: [ { id: db, type: sqlite } ]
routes:   [ { match: {}, channels: [db] } ]
```

`fleet:` correlation, the IOC store, trust scoring, and the intel feed all
**default on** wherever `ingest:` is enabled. The aggregator is a sensor too —
add `listeners:` to present decoys there as well.

### 3.3 Verify

```
tarpit-honeypot validate-config -c agg.yaml      # structural check
tarpit-honeypot run -c agg.yaml                   # look for "ingest endpoint up"
# from a leaf host:
curl -fsS https://agg-site.corp:8470/healthz      # 200 OK
# after some traffic, on the aggregator:
tarpit-honeypot list-events --fleet -c agg.yaml   # cross-sensor findings
tarpit-honeypot list-fleet-rules                  # the detector catalog
```

---

## 4. Topologies

### 4.1 Two-tier (the common case)

Many leaves → one aggregator. The aggregator runs the UI, correlation, the IOC
store, and exports to your SIEM. Start here.

### 4.2 Three-tier (multi-site)

Leaves → per-site aggregator → global hub. Site aggregators **roll up** to the
hub (`forward.mode: rollup`) so the hub gets per-window summaries — top source
IPs / ASNs / fingerprints / rules + a severity histogram — instead of every
event. The hub correlates over the rollups (plus any full streams it chooses to
receive) with wider windows. See [`examples/fleet/`](../examples/fleet/).

```yaml
forward:
  - id: global
    url: https://hub.corp:8470/ingest
    token_env: TARPIT_FWD_TOKEN
    mode: rollup           # one fleet:rollup event per interval, not every event
    rollup_interval: 60s
    min_severity: medium
```

### 4.3 Fan-out / HA

List several `forward:` targets and each event goes to all of them — a site SOC
*and* a global hub, or two aggregators for redundancy. Each target has its own
queue + retry.

### 4.4 Mesh / multi-path

Because every event carries a `hops` chain and is deduped by `sensor_id:id`, a
node can forward to multiple aggregators that themselves forward onward without
double-counting or looping (bounded by `ingest.max_hops`).

---

## 5. The cross-sensor detectors (`fleet:*`)

Run `tarpit-honeypot list-fleet-rules` for the live catalog (rule, what it
detects, the `fleet.*` config keys). The full set, by the vantage axis it
exploits:

**Breadth** — one identity across many sensors
`fleet:source-multi-sensor` · `fleet:asn-multi-sensor` · `fleet:fingerprint-shared`

**Shared-artifact campaigns** — the same thing recurring across sensors
`fleet:payload-campaign` (SHA-256) · `fleet:credential-campaign` (user:pass) ·
`fleet:cve-wave` (CVE) · `fleet:honeytoken-spread` (canary token) ·
`fleet:c2-shared` (harvested URL)

**Coordination** — different sources acting together
`fleet:subnet-coordinated` (one /24, many IPs) ·
`fleet:credential-spray-fleet` (one user, many passwords) ·
`fleet:asn-org-campaign` (one provider, many ASNs)

**Temporal** — sequence / timing only visible across the fleet
`fleet:scan-trajectory` (address-ordered walk, predicts next target) ·
`fleet:synchronized-burst` (many sensors spike at once) ·
`fleet:recidivist-network` (an ASN returning across many days)

**Novelty** — never seen before in the fleet
`fleet:first-fleet-contact` (new ASN/fingerprint) ·
`fleet:cve-emergence` (a brand-new CVE going live)

**Identity / infrastructure**
`fleet:identity-pivot` (one actor across rotating IPs) ·
`fleet:geo-distributed-actor` (one fingerprint from many countries) ·
`fleet:fingerprint-asn-spread` (one fingerprint from many ASNs) ·
`fleet:cross-protocol-actor` (one source across many services) ·
`fleet:target-profile-match` (shared multi-CVE playbook) ·
`fleet:tool-campaign` (an identified tool sweeping the fleet) ·
`fleet:user-agent-shared` (an HTTP scanner family) ·
`fleet:threat-intel-surge` (flagged infra converging) ·
`fleet:tactic-convergence` (one ATT&CK technique surging)

Plus two operational events: `fleet:rollup` (the upward summary) and
`fleet:sensor-untrusted` (a child stream that looks fabricated).

### Broad vs targeted

Every public honeypot is scanned constantly by Censys/Shodan/etc., so a naive
breadth alert is noisy. The breadth/wave detectors stamp a **`coverage`** ratio
(`sensors_hit / active_sensors`) and a **`scope`**: a hit spanning ≥
`broad_coverage` (0.8) of the fleet is `broad` internet background (downgraded to
medium); a hit on a specific subset is `targeted` (high). Tune `broad_coverage`
for your fleet size.

### Tuning

All thresholds live under `fleet:` — see the block in
[`config.md`](config.md#fleet--cross-sensor-correlation-aggregator) and
`list-fleet-rules` for the per-detector keys. Defaults assume a fleet of a few to
a few dozen sensors. On a very large fleet, raise the `*_sensors` thresholds and
`broad_coverage`; on a tiny fleet (2–3 nodes), lower them.

---

## 6. Downward intel feedback

An aggregator derives indicators from its own `fleet:*` findings — hot source
IPs, ASNs, ja3/ja4/hassh fingerprints — and serves them as a small JSON feed at
`GET <ingest>/intel`, plus STIX 2.1 at `/intel/stix` and a TAXII 2.1 read API at
`/taxii2/` (all bearer-gated by the ingest token). On by default where `fleet:`
and `ingest:` are both enabled (`fleet.serve_intel: false` to opt out).

Any node subscribes by pointing `intel_feed:` at a parent's feed:

```yaml
intel_feed:
  enabled: true
  url: https://agg-site.corp:8470/intel
  token_env: TARPIT_FWD_TOKEN
  poll: 60s
```

The subscriber polls and hands the indicators to its enricher, which tags
matching events with `fleet_intel` **and** sets `threat_intel_hit` — so the
existing tarpit / severity / risk / `threat_intel_burst` machinery acts on
fleet-derived knowledge with no extra wiring. Fleet knowledge thus improves every
sensor. See [`threat-intel-exports.md`](threat-intel-exports.md) for the export
formats.

---

## 7. Managing a fleet

- **Identity:** each node's `sensor_id` is a stable deployment id derived once and
  stored under `data_dir` — it survives hostname changes and identical hostnames,
  and is the fleet dedup/attribution key. `tarpit-honeypot list-paths` shows it.
- **Trust scoring:** the aggregator scores each child stream
  (`ingest.trust`); a node whose stream looks fabricated (malformed events,
  loop/dup floods) raises `fleet:sensor-untrusted` and, with `quarantine_below`
  set, is refused until its window rolls. `rate_per_sec` caps per-sensor
  injection so one bad/compromised leaf can't overwhelm the store.
- **Store scale:** SQLite (WAL) with batched transactional inserts carries a busy
  aggregator. Scale *horizontally* — roll up to a higher tier, cap per-sensor
  volume, bound size with `sensor.disk.retention_days` / `disk.sqlite_mb`, and
  push to an external TSDB/SIEM via a `channels:` sink.
- **IOC store:** indicators converge in the `iocs` table (the **iocs** UI tab,
  `/api/iocs`, `export-iocs`). See [`ioc.md`](ioc.md).
- **Visibility:** the web UI's **fleet** and **iocs** tabs, the config canvas's
  "Fleet / aggregation" group (which roles are active), and the `/api/*`
  endpoints. `list-events --fleet` and `list-fleet-rules` on the CLI.
- **Config reload:** `SIGHUP` re-reads the config + enrichment files; most fleet
  settings hot-reload, listener changes swap in place.

---

## 8. Common pitfalls

- **Token mismatch.** A leaf's `forward.token_env` value must equal the
  aggregator's `ingest.token_env` value. A 401 at ingest = wrong/absent token.
  The ingest endpoint **refuses to start** without a token (by design).
- **No store on the aggregator.** Without a `sqlite` channel + route (or the UI),
  forwarded events aren't persisted and the fleet/IOC views are empty. Pair
  `ingest:` with a store.
- **Forgetting timestamps / clock skew.** Events ingested without a `time` field
  (hand-crafted batches) sort to year 1 and fall outside the UI's default
  window; real sensors always set it. Keep NTP running.
- **`egress.enforce` without the dest allowlisted.** The forward and intel-feed
  URLs are auto-allowlisted; *other* outbound (a MISP push, an external SIEM) is
  not — add it to `sensor.egress.allow` or the push will be denied
  (`egress:denied`).
- **Expecting fleet findings on a single node.** Cross-sensor detection needs
  events from several `sensor_id`s converging via `ingest:`. One sensor's local
  events won't trigger `fleet:*` (everything keys to one sensor).
- **Rollup tier missing detail.** A hub fed only `rollup` streams sees summaries,
  not raw events — per-event correlation there is coarser. Send `full` to the
  tier where you want fine-grained correlation; roll up only to the top.
- **Noisy breadth alerts.** If `source-multi-sensor` fires constantly, your
  `broad_coverage` is doing its job (those are `broad`/medium) — filter the UI by
  `scope=targeted`, or raise the `*_sensors` thresholds.

---

## 9. Troubleshooting

| Symptom | Check |
|---------|-------|
| Leaf events not appearing on the aggregator | `curl https://agg:8470/healthz`; leaf logs for `forward: batch dropped`; token match; firewall path; `egress.enforce` allowlisting the forward URL |
| `ingest: env … is empty` at startup | the `ingest.token_env` variable isn't set in the aggregator's environment |
| 401 from `/ingest` or `/intel` | bearer token mismatch between child and parent |
| No `fleet:*` findings | are events from ≥2 `sensor_id`s arriving? (`list-events --fleet`); is `fleet.enabled` (auto-on with ingest)?; thresholds too high for your volume |
| `fleet:asn-*` / `geo-distributed-actor` never fire | GeoIP ASN/city DBs not loaded on the aggregator (`sensor.geoip`) — they need `asn`/`geo_country` enrichment |
| Intel feed empty at the subscriber | the parent has no fleet findings yet, or `fleet.serve_intel` is off, or the URL/token is wrong; check the subscriber log for `intel: feed fetch failed` |
| MISP push failing | `egress.enforce` not allowlisting the MISP URL; wrong `misp.key_env`; check the log for `misp: push failed` |
| A child marked `fleet:sensor-untrusted` / quarantined | that stream is malformed or flooding; inspect its events; adjust `ingest.trust.quarantine_below` if it's a false positive |
| Aggregator store growing fast | lower `disk.retention_days` / `disk.sqlite_mb`, cap children with `ingest.trust.rate_per_sec`, or roll up to a higher tier |

See also: [`config.md`](config.md) (every `fleet:` / `ingest:` / `forward:` /
`intel_feed:` / `ioc:` key), [`ioc.md`](ioc.md), and
[`threat-intel-exports.md`](threat-intel-exports.md).

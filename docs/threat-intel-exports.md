# Threat-intel exports

Everything tarpit-honeypot observes can leave the box as threat intelligence, in
the format your tooling speaks. This document covers every export path: the
standard IOC formats (STIX 2.1 / TAXII 2.1 / MISP), the downward fleet-intel
feed, the SIEM event sinks (CEF / LEEF / OCSF / syslog / webhook / MQTT), and the
offline `export-iocs` CLI — plus the field mappings and auth model.

For *what* becomes an indicator and the IOC store itself, see [`ioc.md`](ioc.md).
For the fleet/aggregation side, see [`fleet.md`](fleet.md).

---

## 1. Export paths at a glance

| Path | Format | Transport | Source | Direction |
|------|--------|-----------|--------|-----------|
| `/intel` | JSON feed | HTTPS GET (bearer) | fleet findings | down (to child sensors) |
| `/intel/stix` | STIX 2.1 bundle | HTTPS GET (bearer) | fleet findings | pull (to a TIP/SIEM) |
| `/taxii2/…` | TAXII 2.1 | HTTPS GET (bearer) | fleet findings | pull (TAXII clients) |
| `misp:` | MISP events | HTTPS POST (key) | fleet findings | push (to MISP) |
| `export-iocs` | STIX/CSV/txt/JSON | stdout | stored fleet findings | offline |
| `channels:` sinks | CEF/LEEF/OCSF/JSON | syslog/webhook/MQTT/… | every event | push (to a SIEM) |

The first four + `export-iocs` carry **indicators**; the `channels:` sinks carry
**events** (each ATT&CK/D3FEND-tagged), which a SIEM turns into detections.

---

## 2. The downward intel feed (`/intel`)

An aggregator (fleet correlation + `ingest:`) derives indicators from its own
`fleet:*` findings — hot source IPs, ASNs, and ja3/ja4/hassh fingerprints — and
serves them as a compact JSON feed. On by default; `fleet.serve_intel: false` to
opt out. Tune lifetime/size with `fleet.intel_ttl` (default 6h) and
`fleet.intel_max`.

```
GET /intel        Authorization: Bearer <ingest token>
```

```json
{
  "generated": "2026-05-25T18:07:46Z",
  "ttl_seconds": 21600,
  "ips":          [ { "value": "203.0.113.50", "reason": "source-multi-sensor" } ],
  "asns":         [ { "value": "AS64500", "reason": "asn-multi-sensor" } ],
  "fingerprints": [ { "value": "ja3:abc", "reason": "fingerprint-shared" } ]
}
```

A node **subscribes** with `intel_feed:` (url + token_env + poll); the indicators
are handed to its enricher, which tags matching events with `fleet_intel` **and**
sets `threat_intel_hit` so the existing tarpit / severity / risk /
`threat_intel_burst` machinery acts on them. This is how fleet knowledge flows
back down to every sensor. See [`fleet.md`](fleet.md#6-downward-intel-feedback).

---

## 3. STIX 2.1 (`/intel/stix`)

The same indicators as a STIX 2.1 **bundle** of Indicator SDOs:

```
GET /intel/stix   Authorization: Bearer <ingest token>
```

```json
{
  "type": "bundle", "id": "bundle--…",
  "objects": [
    {
      "type": "indicator", "spec_version": "2.1",
      "id": "indicator--<uuidv5 of the pattern>",
      "created": "…", "modified": "…",
      "name": "ip 203.0.113.50",
      "description": "tarpit-honeypot fleet finding: source-multi-sensor",
      "indicator_types": ["malicious-activity"],
      "pattern": "[ipv4-addr:value = '203.0.113.50']",
      "pattern_type": "stix",
      "valid_from": "…",
      "labels": ["malicious-activity"]
    }
  ]
}
```

**Pattern mapping:**

| IOC | STIX pattern |
|-----|--------------|
| IPv4 | `[ipv4-addr:value = '…']` |
| IPv6 | `[ipv6-addr:value = '…']` |
| ASN | `[autonomous-system:number = N]` |
| ja3 / ja4 / hassh | `[x-tarpit-fingerprint:value = '…']` (custom object — no native STIX type) |

Indicator **IDs are deterministic** (UUIDv5 of the pattern under a fixed
namespace), so the same indicator keeps a stable id across snapshots and a
downstream TIP dedups cleanly.

---

## 4. TAXII 2.1 (`/taxii2/…`)

A minimal **read-only** TAXII 2.1 server so any TAXII client can discover and
pull the `fleet-iocs` collection. All endpoints are bearer-gated by the ingest
token and return `application/taxii+json;version=2.1`.

| Endpoint | Returns |
|----------|---------|
| `GET /taxii2/` | discovery (the API root) |
| `GET /taxii2/api/` | API-root info |
| `GET /taxii2/api/collections/` | the collection list |
| `GET /taxii2/api/collections/fleet-iocs/` | collection metadata |
| `GET /taxii2/api/collections/fleet-iocs/objects/` | the STIX objects envelope |

```
curl -H "Authorization: Bearer $TOKEN" https://agg:8470/taxii2/
curl -H "Authorization: Bearer $TOKEN" https://agg:8470/taxii2/api/collections/fleet-iocs/objects/
```

---

## 5. MISP push (`misp:`)

Push the fleet's indicators to a MISP instance as periodic **delta** events
(only indicators not pushed before), so a TIP operator gets fresh IOCs without
duplicate events.

```yaml
misp:
  enabled: true
  url: https://misp.corp        # MISP base URL (POSTs to /events)
  key_env: TARPIT_MISP_KEY      # MISP automation key (from env)
  interval: 5m                  # push period
  event_info: "tarpit fleet IOCs"
  distribution: "0"             # MISP distribution level (0 = your org only)
  threat_level: "2"             # threat_level_id
```

**Attribute mapping:** IP → `ip-src`, ASN → `AS`, ja3 → `ja3-fingerprint-md5`,
hassh → `hassh-md5` (others → `other`). On a push failure the not-yet-sent set is
rolled back so the next tick retries. The pusher dials through the **egress
allowlist** — under `egress.enforce`, add the MISP URL to `sensor.egress.allow`.

---

## 6. Offline export — `export-iocs`

For air-gapped / scheduled export without a running aggregator. Reads the local
event store and prints the indicators derived from its stored `fleet:*` findings:

```
tarpit-honeypot export-iocs -c cfg.yaml --format stix    # STIX 2.1 bundle
tarpit-honeypot export-iocs -c cfg.yaml --format csv      # kind,value,reason
tarpit-honeypot export-iocs -c cfg.yaml --format txt      # plain values (blocklist)
tarpit-honeypot export-iocs -c cfg.yaml --format json --since 720h
```

Drop it in cron to publish a daily STIX bundle, or pipe `--format txt` into a
firewall/DNS blocklist. See [`cli.md`](cli.md#export-iocs).

---

## 7. Event sinks → SIEM (CEF / LEEF / OCSF)

Beyond indicators, **every event** can stream to a SIEM in its native schema via
`channels:`, each event already stamped with ATT&CK techniques/tactics + D3FEND
defenses (the router stamps them at dispatch and the store persists them):

```yaml
channels:
  - { id: siem, type: syslog, network: tcp, address: siem.corp:514, format: cef }
  # also: format: leef | ocsf | json ; type: webhook | mqtt | sns | …
routes:
  - { match: { severity: ">=medium" }, channels: [siem] }
```

Supported formats: `cef`, `leef`, `ocsf`, `json`. Supported transports:
`syslog` (tcp/udp/tls/local/unix), `webhook`, `smtp`, `mqtt`, `sns`, `discord`,
`twilio`, `snmptrap`, plus the local `jsonlog` / `sqlite` / `stdout`. See
[`config.md`](config.md) and [`INTEGRATIONS.md`](INTEGRATIONS.md).

A common pattern: stream all events to the SIEM via CEF (detection), and publish
the curated IOC bundle via STIX/TAXII/MISP (blocking/enrichment).

---

## 8. Auth & containment

- **Inbound** (`/intel`, `/intel/stix`, `/taxii2/`): bearer token =
  `ingest.token_env`; constant-time compared; an unauthenticated request gets
  401.
- **Outbound** (MISP push, intel-feed pull, SIEM webhooks): dialled through the
  **egress allowlist**. The forward and intel-feed URLs are auto-allowlisted;
  add MISP / webhook / SIEM destinations to `sensor.egress.allow` when running
  `egress.enforce`, or the dial is refused and logged as `egress:denied`.
- **TLS:** terminate on the ingest endpoint (`ingest.tls_cert`/`tls_key`) or
  front it with a reverse proxy; the subscriber/MISP clients use HTTPS.

---

## 9. Quick reference

| I want to… | Use |
|------------|-----|
| Improve every sensor with fleet knowledge | `fleet.serve_intel` + `intel_feed:` |
| Pull IOCs into a TIP (STIX/TAXII) | `GET /intel/stix` · `/taxii2/…` |
| Push IOCs to MISP | `misp:` block |
| Publish a daily blocklist / bundle | `export-iocs` in cron |
| Stream tagged events to a SIEM | `channels:` with `format: cef\|leef\|ocsf` |

---

## 10. CISA KEV coverage sync + gap-scan

The sensor's CVE catalog (`internal/cve`, `list-cves`) is curated and stable;
the CISA **Known Exploited Vulnerabilities (KEV)** catalog moves daily. The
`internal/kevsync` package keeps a live KEV overlay so the sensor can mark a
`cve:<id>` event as actively-exploited (with the date added and whether it is
used by ransomware), and so you can see, at runtime, which KEV-listed CVEs the
sensor does not yet model.

**Run the gap-scan**

```
tarpit-honeypot kev-gap                         # live: pull the KEV feed, print the gaps
tarpit-honeypot kev-gap --covered               # the KEV CVEs already modeled
tarpit-honeypot kev-gap --file kev.json --json  # offline, machine-readable
```

The gap report lists the actively-exploited CVEs worth adding next, newest-first,
with the ransomware flag and affected vendor/product.

**Network:** the live fetch pulls `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
That host must be reachable from the sensor — add it to `sensor.egress.allow`
when running `egress.enforce`. If egress blocks it, download the KEV JSON on
another host and pass it with `--file`.

**Background auto-sync:** `kevsync.NewPuller(url, header, interval, client, store)`
refreshes a `kevsync.Store` on an interval (default 6h) through the
egress-governed HTTP client, retaining the last good snapshot across a failed
refresh — the same pattern as the external-reputation `feeds` puller. Wire the
`Store` into the event-enrichment path to stamp KEV status on `cve:<id>` events.

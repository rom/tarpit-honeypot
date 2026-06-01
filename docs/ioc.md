# Indicators of compromise (IOCs)

tarpit-honeypot turns the heterogeneous information it already collects on every
event into typed, de-duplicated **indicators of compromise** — stored, browsable,
emitted as events, and exportable to standard threat-intel tooling. This document
covers what becomes an IOC, where they live, and every way to get them out.

There are two complementary IOC layers:

| Layer | Source | Surfaces | Scope |
|-------|--------|----------|-------|
| **IOC store** (`ioc:`) | every event's indicators | `iocs` UI tab, `/api/iocs`, `export-iocs` | the whole sensor's observations |
| **Fleet intel** (`fleet.serve_intel`) | the aggregator's `fleet:*` findings | `/intel`, `/intel/stix`, `/taxii2/`, MISP push | high-confidence cross-sensor indicators |

The IOC store is broad (everything seen); the fleet intel feed is curated (only
indicators a cross-sensor pattern surfaced). See
[`threat-intel-exports.md`](threat-intel-exports.md) for the fleet-intel side.

---

## 1. What becomes an IOC

On every event, the extractor (`internal/ioc`) pulls these indicator types:

| Type | Source field | Example |
|------|--------------|---------|
| `ip` | `source.ip` | `203.0.113.7` |
| `asn` | `meta.asn` (GeoIP) | `AS64500` |
| `ja3` / `ja4` / `hassh` | TLS/SSH fingerprints | `ja3:771,4865-…` |
| `ja4h` | HTTP client fingerprint (`meta.ja4h`) | `ge11nn050000…` |
| `ja4t` | client TCP-stack fingerprint (`meta.ja4t`, OS-level) | `64240_2-4-8-…` |
| `user-agent` | HTTP `meta.user_agent` (tool attribution) | `sqlmap/1.7` |
| `ssh-key` | offered SSH public-key fingerprint (`meta.ssh_pubkey_fps`) | `ssh-rsa:SHA256:…` |
| `ssh-client` | SSH client version string (`meta.client_id`) | `SSH-2.0-libssh2_1.10.0` |
| `email` | SMTP envelope sender (`meta.mail_from`) | `spammer@evil.test` |
| `domain` | `meta.qname` (DNS) + `meta.sni` (requested SNI) | `evil.example.com` |
| `cve` | `cve:<id>` rule | `CVE-2021-44228` |
| `sha256` | captured-payload hash (`payload_artifacts`) | `deadbeef…` |
| `url` | harvested C2 / dropper URL (`harvested_urls`) | `http://evil.test/x.sh` |
| `credential` | captured `username:password` | `admin:Summer2025!` |
| `mac` | `client_mac` / `sender_mac` / `mac` | `02:42:ac:11:00:01` |

The high-value types (`sha256`, `url`, `domain`, `ja3`, `ja4`, `ja4h`, `hassh`,
`ssh-key`, `cve`, `credential`) also emit a one-off `ioc:<type>` event on first
sighting so they are stored and forwarded to aggregators; bare `ip` / `asn` /
`mac` / `ja4t` / `user-agent` / `ssh-client` / `email` are tracked in the store
but not emitted (too voluminous, and already present on every event).

Each indicator is de-duplicated by `(type, value)` and tracked with **first
seen**, **last seen**, **count**, **max severity**, and the **last rule /
sensor / source** that exhibited it.

---

## 2. The IOC store

Enabled by default wherever a SQLite store exists. Configure under `ioc:`:

```yaml
ioc:
  enabled: true        # default: on when a sqlite store is configured
  emit_types:          # which first-sights also emit an ioc:<type> event
    - sha256
    - url
    - domain
    - ja3
    - ja4
    - hassh
    - cve
    - credential
```

- **All types** (including `ip` / `asn` / `mac`) are *tracked* in the store.
- Only the **high-value types** in `emit_types` *also* emit an `ioc:<type>` event
  on first sighting (bare IPs/ASNs/MACs are too voluminous and already on every
  event). Add them to `emit_types` to change that.

Stale indicators — not seen for `sensor.disk.retention_days` — are pruned by the
hourly retention runner (last-seen basis), so the store self-bounds.

---

## 3. `ioc:<type>` events (local + remote)

The first time a high-value indicator is seen, the sensor emits an `ioc:<type>`
event (e.g. `ioc:sha256`, `ioc:url`, `ioc:credential`). These are ordinary
events: they are **stored locally**, routed to every configured sink, and
**forwarded** to aggregators like any other event. The event carries:

```json
{
  "rule_id": "ioc:sha256",
  "severity": "medium",
  "source": { "ip": "45.0.0.1" },
  "meta": { "ioc_type": "sha256", "ioc_value": "deadbeef…", "first_rule": "malware:capture" }
}
```

Because a forwarded `ioc:*` event re-yields its indicator at the receiver, an
**aggregator harvests child IOCs** from these events even in `rollup` mode (where
the underlying raw events aren't forwarded). At each tier the first sighting
re-emits and propagates further up.

---

## 4. The web UI (`/iocs` tab)

A dedicated **iocs** tab:

- a **by-type breakdown** bar chart (each bar filters to that type);
- the **indicator list** — value, count, severity, first/last seen, last rule —
  each row linking to the events that exhibited it (`/events?source=…` for IPs,
  a meta text-search otherwise);
- filters: `type`, `contains` (substring on value), `since`.

`GET /api/iocs?type=&q=&since=` returns the same rows as JSON.

---

## 5. CLI export — `export-iocs`

The offline counterpart to the live feed: it derives indicators from the stored
`fleet:*` findings and prints them for piping into a TIP / SIEM / blocklist.

```
tarpit-honeypot export-iocs -c cfg.yaml                  # STIX 2.1 bundle (default)
tarpit-honeypot export-iocs -c cfg.yaml --format txt      # one value per line (blocklist)
tarpit-honeypot export-iocs -c cfg.yaml --format csv      # kind,value,reason
tarpit-honeypot export-iocs -c cfg.yaml --format json --since 720h
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-c <config>` | `/etc/tarpit-honeypot/config.yaml` | config (for the `data_dir` holding `events.db`) |
| `--since <dur>` | `168h` | derive from fleet findings newer than this |
| `--format` | `stix` | `stix` \| `csv` \| `txt` \| `json` |

Example pipelines:

```
# Feed a firewall blocklist from the last 30 days of fleet-flagged IPs:
tarpit-honeypot export-iocs -c cfg.yaml --since 720h --format txt | grep -E '^[0-9]' > blocklist.txt

# Push a STIX bundle into a TIP:
tarpit-honeypot export-iocs -c cfg.yaml | curl -XPOST --data-binary @- https://tip/stix
```

> `export-iocs` reads the local event store, so it works on any node that
> persists events (no running aggregator needed). It currently derives from the
> `fleet:*` findings; the live `/api/iocs` endpoint exposes the broader IOC store.

---

## 6. STIX 2.1 / TAXII 2.1 (served on an aggregator)

Wherever a node serves intel (fleet correlation + `ingest:`), it also exposes, on
the bearer-gated ingest endpoint:

- `GET /intel/stix` — a STIX 2.1 **bundle** of Indicator SDOs. IPs →
  `ipv4-addr`/`ipv6-addr` patterns, ASNs → `autonomous-system`, fingerprints → an
  `x-tarpit-fingerprint` custom pattern. Indicator ids are deterministic (UUIDv5
  of the pattern) so downstreams dedup cleanly.
- A read-only **TAXII 2.1** API: `/taxii2/` (discovery), `/taxii2/api/`,
  `/taxii2/api/collections/`, and the `fleet-iocs` collection's `objects/`
  envelope — so any TAXII client can discover and pull the collection.

```
curl -H "Authorization: Bearer $TOKEN" https://agg:8470/intel/stix
curl -H "Authorization: Bearer $TOKEN" https://agg:8470/taxii2/api/collections/fleet-iocs/objects/
```

See [`threat-intel-exports.md`](threat-intel-exports.md) for the STIX/TAXII/MISP
details and field mappings.

---

## 7. MISP push

Add a `misp:` block on a node that serves intel to push the fleet's indicators to
a MISP instance as periodic **delta** events (only not-yet-sent indicators):

```yaml
misp:
  enabled: true
  url: https://misp.corp
  key_env: TARPIT_MISP_KEY
  interval: 5m
```

IP → `ip-src`, ASN → `AS`, ja3 → `ja3-fingerprint-md5`, hassh → `hassh-md5`.
Egress-allowlisted (add the MISP URL to `sensor.egress.allow` under
`egress.enforce`).

---

## 8. ATT&CK / D3FEND on every IOC event

`ioc:*` events (and the `cve:*` / `malware:capture` / `fleet:*` events the IOCs
come from) carry persisted ATT&CK technique/tactic + D3FEND attribution
(`/api/events`, the event-detail page, and the CEF/LEEF/OCSF sinks). So an
indicator is never just a value — it ships with the technique it represents and
the defensive countermeasure that answers it.

---

## 9. Quick reference

| I want… | Use |
|---------|-----|
| Browse all indicators | web UI **iocs** tab |
| JSON of the IOC store | `GET /api/iocs` |
| A blocklist of flagged IPs | `export-iocs --format txt` |
| A STIX bundle for a TIP | `export-iocs --format stix` or `GET /intel/stix` |
| A TAXII feed | `GET /taxii2/api/collections/fleet-iocs/objects/` |
| Push to MISP | `misp:` config block |
| IOCs forwarded to a SOC aggregator | `forward:` (ioc:* events ride along) |

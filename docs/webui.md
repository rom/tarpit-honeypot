# The web UI — a walkthrough

The built-in web UI is a **read-only** console over the SQLite event store. It
binds loopback by default, ships no external JavaScript (strict CSP — charts and
tables are server-rendered), and auto-refreshes. This document walks through every
tab and explains the cross-cutting concepts — the event model, ATT&CK/D3FEND
attribution, the fleet view, and the IOC view.

> Access: loopback `http://127.0.0.1:<port>` by default. For remote access the
> validator requires both TLS (`ui.tls_cert`/`ui.tls_key`) and an auth token
> (`ui.auth_token_env`), or front it with a TLS reverse proxy. The UI cannot
> change config, delete events, or trigger alerts (one opt-in, token-gated
> exception: device delete/whitelist).

---

## The navigation

`summary · events · search · timeline · att&ck · correlation · campaigns ·
map · captures · fleet · iocs · tunnels · profiles · fingerprints · devices ·
topology · charts · health · alerting · errors · config · docs`

Every page auto-refreshes (meta-refresh; interval `ui.refresh_seconds`) so the
console stays live during an attack without JavaScript. With JavaScript on, the
refresh is **state-preserving**: a column sort you chose, the live-pause toggle,
and the timeline order all survive the reload (persisted per-page in
`localStorage`), so a periodic refresh never resets your view.

## Presentation options

- **Pervasive linking.** Source IPs everywhere (event lists, detail, timeline,
  campaigns, map, IOCs) link to that actor's `/profiles/<ip>`; rule_ids link to
  the filtered `/events?rule=`; fingerprints to `/fingerprints/<kind>/<value>`;
  techniques to `/attack/technique`. Click any observable to pivot to the
  attack / profile / campaign behind it.
- **CVE labels are hyperlinks** to the authoritative record. `ui.cve_source`
  selects the source: `nvd` (default, `nvd.nist.gov/vuln/detail/<id>`) or
  `cve.org` (`www.cve.org/CVERecord?id=<id>`).
- **ATT&CK labels are hyperlinks** to attack.mitre.org. With `ui.attack_links`
  on (default), every `T####` technique chip — on the event detail, profile,
  campaign and ATT&CK heatmap — links to `attack.mitre.org/techniques/<ID>/`
  (sub-techniques to `…/<base>/<NNN>/`). The matrix (Enterprise `T1xxx` vs ICS
  `T0xxx`) lives in the ID, so there's no `/enterprise/` or `/ics/` path
  segment; it's shown in the tooltip and on the drill-down. Set
  `attack_links: false` to keep the chips on the internal `/attack/technique`
  drill-down instead.
- **Coloured counters.** The summary and map counter strips are tinted by
  category (transport + severity) so the shape of the day reads at a glance.
- **GeoIP attack-source map.** The "attack source map (GeoIP)" plots each
  origin as a severity-coloured bubble over a **built-in world map** — coarse
  continent outlines drawn client-side in the equirectangular projection, so a
  recognizable geography shows with zero configuration (no longer just a bare
  lat/lon grid). Set `ui.map_tiles_url` to an equirectangular world image to
  replace the built-in vector with a real map raster (prefer a self-hosted
  `/static` image). Bubbles need geo-located events — set `sensor.geoip.city_db`
  (MaxMind GeoLite2-City) to populate coordinates.
- **Rows per page.** With JavaScript on, every multi-row list (events,
  profiles, fingerprints, captures, IOCs, recent attacks, …) gets a **Rows**
  selector (10 / 25 / 50 / 100 / All, default 25) capping how many rows show at
  once. It composes with the column sort and persists per-page in `localStorage`
  across the auto-refresh. With JavaScript off, the full server-rendered list
  shows.
- **Display hide list.** `ui.hidden_ips` (IPs / CIDRs) removes a source from
  **every** view and JSON endpoint at the presentation layer — the events stay
  in the store and in exports, they're just not shown. Edit + reload to change.

---

## Core views

### summary (`/`)
A 24-hour rollup: counts by severity, rule, and transport; the top source IPs;
and an at-a-glance **counters strip**. The counters are colour-tinted by
category — transport (events / TCP / UDP / ICMP) and severity (critical / high /
medium / low) each get a distinct, theme-aware background so the shape of the
day reads at a glance. The starting point each shift.

### events (`/events`)
The filterable event log — by `source`, `rule`, `severity`, `since`, free-text
`q`, and `--fleet`-style `fleet:*` filtering. Each row links to the **event
detail** page, which now shows:

- the full record (time, sensor, rule, severity, source/dest, proto/handler);
- an **ATT&CK / D3FEND** section — technique chips (linking to the technique
  view, with hover descriptions), tactics, and the D3FEND countermeasures;
- the banner sent, a hexdump of any captured payload, and the full meta;
- download links (per-connection pcap, session recording, a ZIP of everything
  from that source).

`/api/events` returns the same records as JSON, including the persisted
ATT&CK/D3FEND fields.

### search (`/search`) & timeline (`/timeline`)
Full-text search across rule/banner/meta, and a per-source **attack timeline**.
Each source's events are shown **newest-first** by default; the *order:
newest/oldest first* button flips every source's sequence (and the choice
persists across refresh).

### att&ck (`/attack`)
The live ATT&CK coverage built from the observed events — every technique seen,
with its events and D3FEND countermeasures. `/attack/technique?id=Txxxx` drills
into one technique. (Audit the *static* mapping with `tarpit-honeypot
list-techniques`.)

### correlation (`/correlation`)
Per-source **pivot chains**: IP → fingerprints → User-Agents → ASN/country →
domains → tools → credentials → malware → sessions. The single-sensor
counterpart to the fleet view.

### campaigns (`/campaign`)
Two lenses on the last 24h. The **attacker journey** is a sankey of the
ATT&CK tactic→tactic transitions every source moved through (recovered from
each source's chronological tactic sequence) — at a glance, how attackers
progress from reconnaissance toward impact against this sensor. **Campaigns**
link distinct source IPs into one operation when they share a strong network
fingerprint (JA3 / JA4 / JA4H / JA3S / HASSH) — high-confidence evidence of a
single toolset behind multiple hosts. Each campaign card shows its members, the
shared fingerprints (the linking evidence), the kill-chain it reached, the
handlers it touched, the techniques, and how many credential attempts it made;
a linkage graph ties campaigns ↔ fingerprints ↔ handlers. JSON at
`/api/campaign`.

### map (`/map`)
A live **GeoIP attack map** plus geo/threat dashboards on one screen: an
attack-source bubble map (over a configurable world-map backdrop —
`ui.map_tiles_url`), colour-tinted **counters**, top-country / top-ASN /
network-class breakdowns, threat-intelligence counters (events from known-bad
sources, Tor exits, feed matches), and a ticker of the most recent
high-severity attacks with their origin (each source links to its profile).
Geo, ASN and network-class data require `sensor.geoip` (MaxMind
GeoLite2-City/ASN); the intel counters light up when threat feeds / the Tor
list are configured. Auto-refreshes, so it doubles as a wall display. JSON at
`/api/map`.

### captures (`/captures`)
The one-stop **loot** tab for retrieving everything harvested from attackers:

- **captured malware / payload artifacts** (from `sensor.payloads`) — listed by
  `sha256.ext` with size + capture time, each downloadable;
- **captured credentials** — every `username:password` the handlers captured,
  with the source IP, service, and time (from the event store);
- **pcaps** — the per-connection packet captures (listeners with
  `capture: true`);
- **session recordings** — asciicast (`.cast`) replays of interactive
  shell sessions.

Files download as attachments (`application/octet-stream`, `nosniff`) via the
`/loot/` route — never rendered inline, so a captured sample can't execute in
the browser. The route is basename-only and symlink-safe. A "download all" link
streams every pcap + session as a ZIP. **The artifacts are live malware — handle
them only in an isolated environment.**

---

## Fleet view (`/fleet`)

Cross-sensor findings — the patterns no single honeypot can see. Present on an
**aggregator** (a node with `ingest:` enabled, receiving events from several
sensors). It shows:

- a **detectors-fired** bar chart — each bar links to that detector's filtered
  event log (`/events?rule=fleet:<name>`);
- a **findings-over-time** chart (bucketed across the window);
- the **findings list** with a per-detector summary (the primary identity +
  breadth counts + broad/targeted scope), each linking to the full event.

The detectors span breadth (one source/ASN/fingerprint across sensors),
shared-artifact campaigns (malware hash, credential, CVE, canary token, C2 URL),
coordination (subnet, credential spray, AS-org), temporal patterns (scan
trajectory, synchronized burst, recidivist network), novelty (new ASN/fingerprint
/ CVE), and identity/infrastructure links. `/api/fleet` returns the findings as
JSON. Full concept + setup: [fleet.md](fleet.md).

**Broad vs targeted:** breadth/wave findings carry a `coverage` ratio and a
`scope` — `broad` (internet-wide background, down-weighted) vs `targeted` (a
specific subset of your fleet). Filter for `targeted` to cut scanner noise.

---

## IOC view (`/iocs`)

The de-duplicated indicators distilled from every event: source IPs, TLS/SSH
fingerprints, ASNs, DNS names, CVE ids, captured-payload SHA-256s, harvested C2
URLs, credentials, MACs. It shows:

- a **by-type breakdown** bar chart (each bar filters to that type);
- the **indicator list** — value, count, severity, first/last seen, last rule —
  each row linking to the events that exhibited it;
- filters: `type`, `contains`, `since`.

First sightings of the high-value types are also logged as `ioc:<type>` events
(stored and forwarded). `/api/iocs` returns the store as JSON. Full detail +
exports: [ioc.md](ioc.md).

---

## Attacker & asset views

### profiles (`/profiles`)
Per-source-IP **attacker dossiers** compiled over time: a synthesized assessment
+ threat score, the tools/scanners identified (with confidence), fingerprints
(JA3/JA4/JA4H/JA4T/JA3S/HASSH), credentials tried, ATT&CK coverage, and targeted
services. Also surfaces the forensic observables that used to live only in
per-event meta: **captured malware artifacts** (kind:sha256), **harvested
C2/dropper URLs**, the **domains/SNIs** the source requested, the **web-attack
classes** it threw at the app, the **SSH public keys** it offered, the **SMTP
senders** it used, and a **confirmed-compromise banner** when the source
replayed a planted honeytoken (`canary:token_used`). The assessment escalates
accordingly — *honeytoken reuse*, *malware delivery / staging*, and *web
application attack* (3+ distinct attack classes) rank above generic
exploitation.

### fingerprints (`/fingerprints`)
JA3 / JA4 / JA4H / JA3S / HASSH reputation — pivot from a client TLS/SSH stack to
every source IP, ASN, country, protocol, port, attack type, captured malware, and
**which sensors in the fleet** observed it.

### devices (`/devices`)
The learned / seen / whitelisted device inventory (IPv4 / IPv6 / MAC) with the
services they touched and learned attributes. Optional delete/whitelist actions
(`ui.allow_device_actions` + auth token).

### topology (`/topology`)
The virtual networks / hosts / services this sensor presents.

---

## Operations views

### charts (`/charts`)
Client-side analytics figures (the one place that uses the packaged charts.js;
with JS off each figure shows a fallback note).

### health (`/health`)
Sensor health: uptime, disk usage vs caps, listener/collector status, queue
drops.

### alerting (`/alerting`)
How events are routed outbound — the configured channels (syslog / webhook /
email / SMS / SNMP / MQTT) and their formats.

### config (`/config`)
A **UI theme picker** (default · dark · solarized-dark · nord · high-contrast)
that persists per browser via the `tarpit_theme` cookie — every element themes
(headings, tables, charts, badges, bars). Below it, the **infrastructure canvas**
— every subsystem with live on/off state, grouped: Passive capture · Network
responders · Enrichment · Detection · **Fleet / aggregation** (fleet correlation
+ detector count, fleet forwarding, ingest endpoint, trust scoring, intel feed
serving + subscribing, MISP push, IOC store) · Forensics · Output — followed by
the full effective YAML (secrets shown as env-var names, never values).
`/api/config/canvas` returns the board as JSON.

### errors (`/errors`)
Operational / health events (a listener or canary watcher stopped, accept-cap
overflow, a recovered panic) — separated from attacker interaction.

### docs (`/docs`)
This documentation, rendered in-product: HTML versions of the standard docs
(config, usage, CLI, fleet, IOC, threat-intel exports, internals, FAQ, …) plus
this walkthrough. `/docs/<name>` renders one document.

---

## The event model (cross-cutting)

Everything above is a view over one record type. An **event** carries: a stable
id; the time; the originating `sensor` name and `sensor_id` (a stable deployment
id that survives hostname changes — the fleet dedup/attribution key); the
`rule_id` and `severity`; source/dest endpoints; proto/handler; an optional
captured payload (+ length); anomaly markers; the `meta` map (enrichment: asn,
geo, net_class, fingerprints, credentials, tools, …); and the ATT&CK
techniques/tactics + D3FEND defenses. The same record feeds the local store, the
SIEM sinks, the fleet correlator, and the IOC extractor.

---

## JSON API (read-only)

| Endpoint | Returns |
|----------|---------|
| `/api/events` | events (filterable; includes ATT&CK/D3FEND) |
| `/api/attack`, `/api/campaign` | ATT&CK tactic/technique rollup / campaign clusters + journey |
| `/api/map` | geo/threat dashboard: source map + country/ASN/intel rollups |
| `/api/fleet` | cross-sensor `fleet:*` findings |
| `/api/iocs` | the de-duplicated IOC store |
| `/api/profiles`, `/api/fingerprints` | attacker dossiers / fingerprint reputation |
| `/api/summary`, `/api/config`, `/api/config/canvas` | dashboard / effective config / subsystem board |
| `/api/topology`, `/api/hosts`, `/api/alerting` | topology / devices / routing |
| `/metrics` | Prometheus exposition |

On an aggregator the same bind also serves the threat-intel exports: `/intel`,
`/intel/stix`, `/taxii2/…` (bearer-gated). See
[threat-intel-exports.md](threat-intel-exports.md).

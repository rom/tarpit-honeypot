# FAQ

Common questions about tarpit-honeypot, grouped by topic. See also
[`usage.md`](usage.md) (operating guide), [`webui.md`](webui.md) (the console),
[`config.md`](config.md) (every setting), [`cli.md`](cli.md) (commands),
[`fleet.md`](fleet.md) (aggregation), [`ioc.md`](ioc.md) +
[`threat-intel-exports.md`](threat-intel-exports.md) (indicators & exports), and
[`hardening.md`](hardening.md) (running it safely).

> Every guide here is also rendered **in-product** under the web UI's **docs**
> tab (`/docs/<name>`), so you can read all of this from the console.

## General

**What is it?**
A deception + detection sensor. It presents believable services (banners,
120+ protocol emulators, virtual hosts), optionally wastes attacker time
(tarpits), and turns every interaction into a structured, ATT&CK/D3FEND-tagged
event for your SIEM. A fleet of sensors can correlate cross-sensor and exchange
threat intel.

**Is it a high-interaction honeypot?**
Medium-interaction by design. It emulates protocols deeply enough to capture the
*next* request (credentials, exploit payloads, shell commands, ICS writes)
without ever executing attacker input or becoming exploitable. The interactive
shell, web app, and ICS consoles are simulated. See
[`list-unavailable-capabilities`](cli.md) for what's deliberately not real.

**How is it different from Cowrie / Dionaea / Honeyd / a T-Pot stack?**
It's a single binary that combines what those do separately: many protocol
emulators (not just SSH/Telnet), OS/device **archetypes** that keep every
fingerprint coherent, a userspace TCP stack so honeynet decoys answer
`nmap -O` without an IP per host, built-in ATT&CK/D3FEND tagging and
correlation, and — the part no single-box honeypot has — **fleet aggregation**
with cross-sensor detectors and threat-intel exports. No CGO, no external
datastore, no orchestration stack required.

**What does it depend on?**
A single static, CGO-free Go binary. The only embedded datastore is
modernc.org/sqlite (pure Go). Enrichment databases (GeoIP, threat-intel lists,
OUI) are operator-supplied and optional.

**Which platforms?**
Linux is the primary target (the AF_PACKET sniffer, honeynet responders,
seccomp/Landlock sandbox, and nftables egress enforcement are Linux-only). The
core sensor + handlers run anywhere Go runs; non-Linux just no-ops those layers.
`list-unavailable-capabilities -c <cfg>` prints what's inactive on the current
host.

## Getting started

**How do I try it in a minute?**
Build (or grab a release binary), then run the example config and open the UI:

```bash
tarpit-honeypot validate-config -c configs/tarpit-honeypot.example.yaml
tarpit-honeypot run -c configs/tarpit-honeypot.example.yaml
# in another shell: generate some events, then browse http://127.0.0.1:8088
```

See [`usage.md` §1](usage.md#1-quickstart). `configs/tarpit-honeypot.example-MINIMAL.yaml`
is the smallest useful deployment.

**`listeners:` vs `honeynets:` vs `archeservices:` — which do I use?**
- `listeners:` — bind one port to one handler. The direct way to stand up a
  service (`{ id: ssh, proto: tcp, bind: 0.0.0.0:22, handler: ssh }`).
- `honeynets:` — present whole *virtual hosts/networks* (CIDR + gateway + hosts,
  each with its own IP/MAC/identity and service list) behind the honeynet
  responders / TUN stack — many decoy machines without an OS interface per host.
- `archeservices:` — declare a *role* (`webserver`, `adserver`, `printserver`, …)
  and it expands into the right listeners for that role, wearing the chosen
  archetype's software. Start with `listeners:`; reach for the others as you
  model more.

**What's an archetype and why does it matter?**
An archetype pins every fingerprint a handler emits — SSH/HTTP/FTP banners, SNMP
identity, MAC OUI, TLS posture, ICMP TTL, CLI prompt, advertised CVEs — to one
coherent device (e.g. `debian 12`, `active-directory`, a Moxa switch). Without it
a scanner can catch an internal inconsistency (a TLS-1.3 box claiming Windows
2008). `tarpit-honeypot list-archetypes` lists all 162; set `sensor.archetype`,
`listener.archetype`, or a per-honeynet-host `archetype`.

**How do I pick which ports/services to expose?**
Expose what fits the story you're telling (an "AD server" should answer 88/389/445,
not 502/Modbus). Browse `list-handlers` for what's available and the
[`examples/`](../examples/) directory for ready-made shapes (office LAN, DMZ,
IT/OT, data center, OT Purdue model, …).

**Can I run it under systemd / in Docker?**
Yes — see [`usage.md` §5](usage.md#5-systemd-integration) (a shipped unit with
the right `AmbientCapabilities`) and [`usage.md` §6](usage.md#6-docker) (a
~14 MB scratch image). `tarpit-honeypot init` writes a defaulted config skeleton
to start from.

## Deployment & safety

**Will it attack other hosts / amplify traffic?**
No. It never initiates unsolicited outbound connections; UDP responders are
rate-limited and built to avoid reflection/amplification. With `egress.enabled`
it routes its own telemetry through an **allowlist** and refuses everything else;
with `egress.enforce` it adds an OS-level nftables backstop. Any blocked dial is
reported as `egress:denied`.

**Is it safe to expose to the internet?**
That's the intended deployment — the whole point is to be reached by attackers.
The sensor never executes attacker input, bounds every read, and sanitizes every
byte before logs/SIEM/email. Harden the host as defense-in-depth: run as an
unprivileged user (`drop_user`/`drop_group`), enable `sensor.sandbox`
(seccomp + Landlock) and `egress.enforce`, and keep the UI on loopback (or
behind TLS + a token). See [`hardening.md`](hardening.md).

**Is the web UI safe to expose?**
It's read-only by default, binds loopback, and uses a strict CSP (no inline JS).
The validator **refuses** a non-loopback bind without both TLS and an auth token.
Front it with a TLS reverse proxy for remote access. The one write path (device
delete/whitelist) is opt-in and always token-gated.

**Can an exploit in a parser pop a shell on the sensor?**
The handlers never exec attacker input. As defense-in-depth, enable
`sensor.sandbox` (seccomp denies execve/ptrace/module-load/…; Landlock makes the
FS read-only except `data_dir`), drop privileges (`drop_user`/`drop_group`), and
turn on `egress.enforce`. See [`hardening.md`](hardening.md).

**Can a scanner tell it's a honeypot?**
Counter-fingerprinting makes that hard: every "fixed" string (SSH version, HTTP
Server header, MySQL version, SMB challenge, …) is derived from
`sensor.deployment_id`, so two sensors look different to Shodan-class scanners;
`sensor.jitter` randomizes reply latency; `sensor.tls_rotate.days` rotates the
self-signed cert; and the archetype keeps the TLS/TTL/banner story consistent.
Nothing defeats a determined analyst, but bulk fingerprinting is thwarted.

**Do I need root?**
Only for privileged setup: binding ports <1024, the AF_PACKET sniffer/responders
(CAP_NET_RAW), and installing the nftables egress firewall (CAP_NET_ADMIN). The
sensor drops to `drop_user`/`drop_group` after setup.

**Where is data stored?**
Under `sensor.data_dir`: the SQLite store (`events.db`), JSON logs, captures
(pcap), sessions, payloads, the device inventory, and the stable `sensor_id`.
`tarpit-honeypot list-paths` prints them all.

## Detection & events

**What's an "event"?**
A structured record of one interaction: id, time, sensor/sensor_id, rule_id,
severity, source/dest, proto/handler, captured payload, anomaly markers, and the
ATT&CK techniques/tactics + D3FEND defenses. `/api/events` returns them as JSON.

**What's the difference between an anomaly, a correlator, and a CVE event?**
- An **anomaly** is a per-request marker a handler flags (`uri-log4shell-jndi`,
  `ssh-id-non-printable`, `modbus-write-attempt`) — it rides on the event.
- A **correlator** (`correlate:*`, `storyline:*`, `fleet:*`) is a *windowed,
  multi-event* detector that fires when a pattern crosses a threshold
  (port-scan, brute-force, beacon, a cross-sensor sweep).
- A **CVE event** (`cve:<id>`) means a request matched a known exploit signature.
  All three are ATT&CK/D3FEND-tagged.

**How does ATT&CK/D3FEND tagging work?**
The `internal/mitre` table maps every rule_id / handler / anomaly marker (and CVE
exploit) to ATT&CK technique(s)/tactic(s), and each technique to its D3FEND
countermeasures. The router stamps them at dispatch (so every sink sees them) and
the store persists them (so `/api/events` and the UI carry them). Audit the
coverage with `tarpit-honeypot list-techniques`.

**What CVEs does it know about?**
A curated catalog of 100+ entries (run `tarpit-honeypot list-cves`), each with
CVSS, CWE, CPE, EPSS, and the ATT&CK technique. Vuln-emulation (advertise an
unpatched version + recognize the matching exploit) is per-listener
(`sensor.vuln_emulation`); exploit-attempt detection (`cve:<id>` events) runs
regardless.

**What's a tarpit and when should I use one?**
A tarpit holds a connection open to waste a scanner's/worm's time —
`mode: tarpit` with `strategy: sticky` (hold), `trickle` (one byte every N s), or
`keepalive` (slow nulls). With `tarpit.emulate: true` the handler runs first
(real banner + captured request) and *then* tarpits, so any emulator becomes a
tarpit. Use it on commodity-scanned ports where slowing mass tooling is worth
more than a clean banner.

**What are canary tokens?**
Tripwires that fire the instant they're touched: **file** canaries (fsnotify +
Linux fanotify catches plain reads), **URL** canaries (a secret path on any
HTTP/S listener), and **DNS** canaries (any subdomain of a registered name).
Mint them with `tarpit-honeypot gen-token --type=dns|url|hex`.

**Does it record attacker sessions?**
With `sensor.session_recording`, interactive `telnet` / `ssh_interactive`
sessions are saved as replayable asciinema v2 casts under `<data_dir>/sessions/`
(the filename lands on the event); the UI can play them back. Per-cast and total
size are capped.

**What is device learning / "new device" alerts?**
With `devices.enabled`, the sensor learns hosts seen via DHCP, the ARP sniffer,
broadcast/multicast discovery, and connection sources (MAC-OUI vendor, passive
TTL OS-guess, the services each touched) and raises `device:new` for
never-before-seen, non-allow-listed hosts. Browse the **devices** tab or
`list-devices`.

**Can it detect scans that never complete a connection?**
Yes, on Linux with the AF_PACKET sniffer: NULL/FIN/Xmas stealth probes, SYN/ACK
scans by volume, and fragmented probes are flagged (`sniffer:tcp_*_scan`) even
though no socket ever accepts them — reconnaissance the connection-level
correlator can't see.

**How do I reduce false positives from my own scanners?**
Put admin/patch-management/monitoring sources in `allowlist` (suppresses
forwarding/alerting for those IPs; local events still recorded), and tune the
correlator thresholds. On a fleet, the broad-vs-targeted classifier already
down-weights internet-wide background scanning.

## Web UI & API

**How do I access the UI?**
It binds `127.0.0.1:8088` by default. For remote access, set `ui.tls_cert` +
`ui.tls_key` and `ui.auth_token_env`, or front it with a TLS reverse proxy — a
non-loopback bind without both is refused at validate-time. Full tour:
[`webui.md`](webui.md).

**Can the UI change anything?**
No — it's read-only. It can't edit config, delete events, or trigger alerts. The
single exception is the opt-in, token-gated device delete/whitelist
(`ui.allow_device_actions`), off by default.

**Is there a JSON API?**
Yes, read-only: `/api/events`, `/api/summary`, `/api/fleet`, `/api/iocs`,
`/api/profiles`, `/api/fingerprints`, `/api/topology`, `/api/devices`,
`/api/alerting`, `/api/config`, and `/api/config/canvas`. On an aggregator the
same bind also serves the bearer-gated `/intel`, `/intel/stix`, and `/taxii2/…`.

**Does it expose Prometheus metrics?**
Yes — `GET /metrics` (text exposition): sink delivery/drops/retries, honeynet
network/host gauges, the on-disk store size, and more. `/healthz` is an
auth-free liveness check.

**Can I read the docs without leaving the console?**
Yes — the **docs** tab lists a documentation library and renders each guide at
`/docs/<name>` (the same Markdown shipped under `docs/`).

## Fleet & aggregation

**What's the difference between a sensor and an aggregator?**
Same binary, different config. A sensor has `listeners:`; an aggregator has
`ingest:` (accepts forwarded events) and auto-runs the cross-sensor correlator.
A node can be both. See [`fleet.md`](fleet.md).

**What can a fleet detect that one sensor can't?**
One source/ASN/fingerprint hitting many sensors, a malware hash or credential
recurring across sites, a CVE wave, a coordinated /24, a fingerprint from many
ASNs/countries, a network returning across days, and more — 27 `fleet:*`
detectors. `tarpit-honeypot list-fleet-rules`.

**How many sensors do I need before fleet detection is useful?**
Breadth detectors need events from **several** distinct `sensor_id`s converging,
so two is the floor and the signal sharpens with more vantage points. Thresholds
scale with fleet size — tune `fleet.*` so "many sensors" means a meaningful
fraction of yours (see broad-vs-targeted below).

**Do I have to forward everything?**
No. `forward.min_severity` filters by severity, and `forward.mode: rollup` ships
a periodic summary instead of every event (keeps upward volume sane at a global
hub).

**Do I need TLS between sensors?**
For any non-loopback `ingest:` bind, yes — terminate TLS on the endpoint
(`ingest.tls_cert`/`tls_key`) or front it with a reverse proxy; the forwarders
use HTTPS. Ingest is bearer-gated by `ingest.token_env` (constant-time compared).

**Can I build more than two tiers?**
Yes — a mid-tier aggregator can ingest from leaves *and* forward (or roll up) to
a higher hub. `ioc:*` first-sights re-emit at each tier, so a global hub still
harvests child IOCs even when the middle tier only rolls up.

**What stops a forwarding loop?**
Each forwarder appends its node id to the event's `Hops`; the ingest side drops
anything that already contains this node or exceeds `ingest.max_hops`, and dedups
on `sensor_id:id`.

**What's "broad" vs "targeted"?**
Breadth/wave findings carry a `coverage` ratio (`sensors_hit / active_sensors`)
and a scope: **broad** (≥ `fleet.broad_coverage`, i.e. internet-wide background —
down-weighted) vs **targeted** (a specific subset of your fleet — higher
severity). Filter the fleet view for `targeted` to cut scanner noise.

**How does intel flow back to sensors?**
An aggregator serves a downward intel feed (`/intel`, plus STIX/TAXII); sensors
subscribe with `intel_feed:` and the indicators tag their events (setting
`fleet_intel` + `threat_intel_hit`, which drives the existing tarpit/risk/burst
machinery). Events flow up, intel flows down.

**Why aren't my `fleet:*` detectors firing?**
Cross-sensor detection needs events from **several** `sensor_id`s converging via
`ingest:`. One sensor's local events all key to one sensor, so they won't trigger
breadth detectors. Also check `fleet.enabled` (auto-on with ingest) and that your
thresholds suit your fleet size. See [`fleet.md`](fleet.md#9-troubleshooting).

## IOCs & threat intel

**Where do I see/extract indicators?**
The **iocs** UI tab and `/api/iocs` (the de-duplicated store), the `ioc:<type>`
events (stored + forwarded), `export-iocs` (STIX/CSV/txt/JSON), and on an
aggregator the `/intel/stix` + `/taxii2/` feeds and MISP push. See
[`ioc.md`](ioc.md) and [`threat-intel-exports.md`](threat-intel-exports.md).

**What becomes an IOC?**
Per event: source `ip`, `asn`, TLS/SSH `ja3`/`ja4`/`hassh`, DNS `domain`, `cve`
id, captured-payload `sha256`, harvested C2 `url`, captured `credential`, and
`mac`. Each is de-duplicated by `(type, value)` with first/last-seen, count, max
severity, and the last rule/sensor/source.

**Which IOCs get their own events?**
Only the high-value types in `ioc.emit_types` (sha256/url/domain/ja3/ja4/hassh/
cve/credential by default) emit an `ioc:<type>` event on first sighting — bare
IPs/ASNs/MACs are tracked silently because they're on every event already. All
types are stored regardless.

**How do I feed a firewall/DNS blocklist?**
`tarpit-honeypot export-iocs -c cfg.yaml --since 720h --format txt` prints one
value per line — pipe it into your blocklist. `--format stix` produces a bundle
for a TIP; it reads the local store, so no running aggregator is needed.

**Can I push IOCs to MISP / pull them into a TIP?**
Yes — `misp:` pushes delta events; `/intel/stix` and `/taxii2/` serve STIX 2.1 /
TAXII 2.1 for a TIP to pull.

**Do IOCs expire?**
The IOC store is pruned by the hourly retention runner: indicators not seen for
`sensor.disk.retention_days` are dropped (last-seen basis). The served fleet
intel feed has its own `fleet.intel_ttl`.

## SIEM & integrations

**What SIEM formats does it speak?**
Events stream in `cef`, `leef`, `ocsf`, or `json`, each already stamped with
ATT&CK/D3FEND, over `syslog` (tcp/udp/tls/unix), `webhook`, or `mqtt` (among
others). Configure under `channels:` with a `format:` and route with `routes:`.
See [`threat-intel-exports.md` §7](threat-intel-exports.md#7-event-sinks-siem-cef-leef-ocsf)
and [`INTEGRATIONS.md`](INTEGRATIONS.md).

**How do I send only some events to a channel?**
`routes:` match on severity (`>=medium`, `=critical`) and other fields and pick
the target channels; each channel also has its own `min_severity` gate and rate
limit. Local sinks (`stdout`/`jsonlog`/`sqlite`) always receive so the on-disk
record stays complete.

**What outbound channels exist?**
`webhook` (HMAC-signed), `discord`, `smtp` (STARTTLS), `syslog` (incl. TLS),
`mqtt`, `twilio` (SMS), `sns` (AWS, no SDK), and `snmptrap` — plus the local
`stdout` / `jsonlog` / `sqlite`. Test wiring with `tarpit-honeypot test-alert`.

**Does syslog support TLS?**
Yes — `type: syslog, network: tls` does RFC 5424 with octet-counting over TLS.

## Performance & scale

**How much does it handle?**
A leaf sensor is light. An aggregator uses SQLite in WAL mode with batched
transactional inserts; for very large fleets, scale horizontally — roll up to a
higher tier, cap per-sensor injection with `ingest.trust.rate_per_sec`, bound the
store with `disk.retention_days` / `disk.sqlite_mb`, and push to an external SIEM.

**How big does the database get, and how do I bound it?**
It self-bounds: the hourly retention runner prunes events, captures, and IOCs
older than `sensor.disk.retention_days`, and `sensor.disk.sqlite_mb` caps the
store size. `/metrics` exposes the live on-disk size (`tarpit_store_db_bytes`).

**Is it heavy on CPU/RAM?**
No. It's a single Go process with one event-consumer goroutine and bounded
queues; the high-volume producers drop onto the bus non-blockingly so a flood
can't wedge it. The biggest cost is whatever enrichment DBs you load (GeoIP/OUI),
which are memory-mapped.

**A noisy/compromised sensor is flooding my aggregator. Help?**
Trust scoring (`ingest.trust`) rate-limits per sensor and can `quarantine_below`
a trust score; a fabricated-looking stream raises `fleet:sensor-untrusted`.

## Operations

**How do I change config without downtime?**
`SIGHUP` re-reads the config + enrichment files. Most settings hot-reload;
listener changes swap in place. `validate-config --diff` previews the change.

**How do I validate a config before deploying it?**
`tarpit-honeypot validate-config -c new.yaml` parses + checks it without binding;
add `--diff current.yaml` to classify each change as hot-reloadable vs
restart-required. `run --dry-run` builds the whole sensor and exits before
binding (CI-friendly).

**How do I see what's running?**
The config canvas (`/config`, `/api/config/canvas`) lists every subsystem with
live state, including the "Fleet / aggregation" group. `show-config` prints the
effective post-defaults config; `list-paths` the files.

**How do I upgrade?**
Replace the binary and restart (or, for config-only changes, `SIGHUP`). The
SQLite schema **self-migrates additively on open** (it backfills the ATT&CK/D3FEND
columns and creates the `iocs` table on an older store), so no manual migration
step is needed.

**How do I back it up?**
Copy `sensor.data_dir`. Because the store runs in WAL mode, take a consistent
snapshot (stop the sensor, or use SQLite's online backup / `VACUUM INTO`) rather
than copying `events.db` mid-write. The stable `sensor_id` file lives there too —
keep it so the deployment's fleet identity survives a rebuild.

**Where do I look when something's wrong?**
The **errors** UI tab and the structured `slog` output (journal under systemd)
cover operational/health events; the [`usage.md` §15](usage.md#15-troubleshooting)
table lists the common symptoms (ports, capabilities, correlator windows) and
fixes.

**Where are the docs in the product itself?**
The web UI **docs** tab renders HTML versions of these documents and a dedicated
web-UI walkthrough; `tarpit-honeypot help <topic>` covers CLI topics; `man
tarpit-honeypot`.

## Customizing & extending

**Can I emulate a custom protocol without writing Go?**
Two ways: `handler: scripted` defines a believable TCP service entirely in YAML
(greeting + match/respond rules, stages, credential capture), and `handler: lua`
drives a service from a sandboxed Lua script (per-session/per-source state,
deterministic rng, timers). Shipped examples live in
[`configs/scripts/`](../configs/scripts/).

**Can I run a fake-vulnerable web app to draw attackers in?**
Set `webapp: true` on an `http`/`https` listener: a believable multi-page app
with the juicy paths scanners probe, which *detects* (never executes) SQLi / XSS /
LFI / RFI / SSTI / Log4Shell etc. and plants per-deployment honeytokens.

**Can I change an event's severity for my environment?**
Yes — `severity_overrides:` re-maps a `rule_id` (exact or `prefix:*`) at the
dispatch chokepoint, so it drives routing, sinks, and the store; the event is
marked as a local override so it's never silent.

**Can I add my own CVE signatures or archetypes?**
The CVE catalog (`internal/cve`) and archetype catalog (`internal/archetype`) are
in-source tables; adding an entry is a small, test-backed code change. Audit the
current coverage with `list-cves` / `list-archetypes` / `list-techniques`.

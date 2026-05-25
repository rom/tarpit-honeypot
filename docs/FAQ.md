# FAQ

Common questions about tarpit-honeypot, grouped by topic. See also
[`usage.md`](usage.md) (operating guide), [`config.md`](config.md) (every
setting), [`cli.md`](cli.md) (commands), [`fleet.md`](fleet.md) (aggregation),
and [`hardening.md`](hardening.md) (running it safely).

## General

**What is it?**
A deception + detection sensor. It presents believable services (banners,
~100 protocol emulators, virtual hosts), optionally wastes attacker time
(tarpits), and turns every interaction into a structured, ATT&CK/D3FEND-tagged
event for your SIEM. A fleet of sensors can correlate cross-sensor and exchange
threat intel.

**Is it a high-interaction honeypot?**
Medium-interaction by design. It emulates protocols deeply enough to capture the
*next* request (credentials, exploit payloads, shell commands, ICS writes)
without ever executing attacker input or becoming exploitable. The interactive
shell, web app, and ICS consoles are simulated. See
[`list-unavailable-capabilities`](cli.md) for what's deliberately not real.

**What does it depend on?**
A single static, CGO-free Go binary. The only embedded datastore is
modernc.org/sqlite (pure Go). Enrichment databases (GeoIP, threat-intel lists,
OUI) are operator-supplied and optional.

**Which platforms?**
Linux is the primary target (the AF_PACKET sniffer, honeynet responders,
seccomp/Landlock sandbox, and nftables egress enforcement are Linux-only). The
core sensor + handlers run anywhere Go runs; non-Linux just no-ops those layers.

## Deployment & safety

**Will it attack other hosts / amplify traffic?**
No. It never initiates unsolicited outbound connections; UDP responders are
rate-limited and built to avoid reflection/amplification. With `egress.enabled`
it routes its own telemetry through an **allowlist** and refuses everything else;
with `egress.enforce` it adds an OS-level nftables backstop. Any blocked dial is
reported as `egress:denied`.

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

**How does ATT&CK/D3FEND tagging work?**
The `internal/mitre` table maps every rule_id / handler / anomaly marker (and CVE
exploit) to ATT&CK technique(s)/tactic(s), and each technique to its D3FEND
countermeasures. The router stamps them at dispatch (so every sink sees them) and
the store persists them (so `/api/events` and the UI carry them). Audit the
coverage with `tarpit-honeypot list-techniques`.

**What CVEs does it know about?**
A curated catalog with CVSS, CWE, CPE, EPSS, and the ATT&CK technique per entry —
`tarpit-honeypot list-cves`. Vuln-emulation (advertise an unpatched version +
recognize the matching exploit) is per-listener; exploit-attempt detection
(`cve:<id>` events) runs regardless.

**How do I reduce false positives from my own scanners?**
Put admin/patch-management/monitoring sources in `allowlist` (suppresses
forwarding/alerting for those IPs; local events still recorded), and tune the
correlator thresholds. On a fleet, the broad-vs-targeted classifier already
down-weights internet-wide background scanning.

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

**Do I have to forward everything?**
No. `forward.min_severity` filters by severity, and `forward.mode: rollup` ships
a periodic summary instead of every event (keeps upward volume sane at a global
hub).

**How does intel flow back to sensors?**
An aggregator serves a downward intel feed (`/intel`, plus STIX/TAXII); sensors
subscribe with `intel_feed:` and the indicators tag their events. Events flow up,
intel flows down.

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

**Can I push IOCs to MISP / pull them into a TIP?**
Yes — `misp:` pushes delta events; `/intel/stix` and `/taxii2/` serve STIX 2.1 /
TAXII 2.1 for a TIP to pull.

**Do IOCs expire?**
The IOC store is pruned by the hourly retention runner: indicators not seen for
`sensor.disk.retention_days` are dropped (last-seen basis). The served fleet
intel feed has its own `fleet.intel_ttl`.

## Performance & scale

**How much does it handle?**
A leaf sensor is light. An aggregator uses SQLite in WAL mode with batched
transactional inserts; for very large fleets, scale horizontally — roll up to a
higher tier, cap per-sensor injection with `ingest.trust.rate_per_sec`, bound the
store with `disk.retention_days` / `disk.sqlite_mb`, and push to an external SIEM.

**A noisy/compromised sensor is flooding my aggregator. Help?**
Trust scoring (`ingest.trust`) rate-limits per sensor and can `quarantine_below`
a trust score; a fabricated-looking stream raises `fleet:sensor-untrusted`.

## Operations

**How do I change config without downtime?**
`SIGHUP` re-reads the config + enrichment files. Most settings hot-reload;
listener changes swap in place. `validate-config --diff` previews the change.

**How do I see what's running?**
The config canvas (`/config`, `/api/config/canvas`) lists every subsystem with
live state, including the "Fleet / aggregation" group. `show-config` prints the
effective post-defaults config; `list-paths` the files.

**Where are the docs in the product itself?**
The web UI **docs** tab renders HTML versions of these documents and a dedicated
web-UI walkthrough; `tarpit-honeypot help <topic>` covers CLI topics; `man
tarpit-honeypot`.

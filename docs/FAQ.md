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

**Does it replace my IDS / firewall?**
No — it complements them. An IDS inspects *real* traffic and lives with false
positives; this is a *sensor on space nothing should touch*, so a single hit is
high-confidence with near-zero noise. Run it alongside your IDS/firewall and feed
its events into the same SIEM.

**How is it versioned / is it stable?**
Single-binary infrastructure, so semver is applied loosely — the contract is the
**YAML schema + CLI surface** documented in `docs/`. The SQLite schema
self-migrates additively on open, so upgrading the binary doesn't need a manual
migration. `tarpit-honeypot version` prints the build.

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

## Configuration

**How is the config put together / can I split it across files?**
Four layers, applied in order: the base YAML (`-c`), then sibling `conf.d/*.yaml`
deep-merged in lexical order, then `TARPIT_<KEY_PATH>` environment variables, then
`--set key.path=value` (wins). So you can keep a shared base and override per-host
bits in `conf.d/` or the environment without forking the file. See
[`cli.md`](cli.md).

**How are secrets and tokens kept out of the config?**
Every secret is a `*_env` reference (`ui.auth_token_env`, `ingest.token_env`,
`misp.key_env`, …) — the value comes from the environment, never the file. They
are **never** expanded in `show-config` output or logs, so config is safe to paste
in a ticket.

**Can I override one setting without editing the file?**
Yes — `--set sensor.name=edge-1` (repeatable, auto-typed) or
`TARPIT_SENSOR_NAME=edge-1` in the environment. Handy for templating one config
across a fleet.

**What's `sensor.deployment_id` and should I set it?**
A stable random seed that feeds every "fixed" string a handler emits (so two
sensors look different to scanners). Leave it blank and it's auto-generated and
persisted to `<data_dir>/.deployment-id` on first run. Set it explicitly only to
make two sensors present an *identical* fingerprint on purpose.

**Can it emulate cloud / Kubernetes / container services?**
Yes. Four handlers model that attack surface: `cloud_metadata` answers the
AWS/GCP/Azure instance metadata service on `169.254.169.254`, serving *synthetic
honeytoken* IAM/OAuth credentials and flagging the credential-theft call;
`etcd` emulates the etcd KV store (`2379`); `kubernetes_api` poses as a
kube-apiserver (`6443`/`8080`/`10250`) and captures the `Authorization: Bearer`
service-account token; and `vault` emulates HashiCorp Vault (`8200`) and
captures the `X-Vault-Token`. Each flags the credential-theft / takeover calls.
There's a ready-made `kubernetes` archeservice role, and the `containerhost` /
`secretstore` roles wire these handlers up.

**Does it support WebSocket or gRPC?**
Yes. The `websocket` handler completes the RFC 6455 handshake and captures
(unmasks) client frames, flagging credential/command payloads. The `grpc`
handler recognizes the HTTP/2 connection preface and extracts the gRPC
`/package.Service/Method` path from the HEADERS frame (without a full HPACK
decode), flagging reflection probes.

## Sensor placement & networking

**Where should I put a sensor?**
On address space nothing legitimate should touch — unused IPs on an internal
VLAN, a DMZ, or a public IP. The value comes from that: any connection is
inherently suspicious, so false positives are near-zero. Cover more unused space
(more virtual hosts / claimed IPs) for more signal.

**How do I attract traffic to it?**
Bind the real service ports on the sensor's IP, claim unused IPs with the
honeynet `arp_responder` (the sensor answers ARP for a free address), or
NAT/`REDIRECT` unused ports on a gateway to the sensor. The honeynet dispatch is
per-destination-IP, so one bound port can serve many virtual hosts. See
[`INTEGRATIONS.md`](INTEGRATIONS.md).

**Can I run it on a cloud VM?**
Yes. Bind the listeners on the public interface, open exactly the
security-group/firewall ports you want probed, and keep the UI on loopback (or
behind TLS + an auth token). Nothing about the core needs a special host.

**Does it need outbound internet?**
No, for core operation. Only the channels and feeds you configure (SIEM webhooks,
SMTP, MISP, intel pull) dial out — and those go through the `egress` allowlist,
with `egress.enforce` adding an OS-level backstop. A blocked dial is logged as
`egress:denied`.

**Can I run several instances on one host?**
Yes — give each its own `sensor.data_dir` and non-overlapping binds (listeners +
UI). They're independent processes; aggregate them with a fleet `ingest:` node if
you want one view.

## Honeynets & virtual hosts

**Do I need a real IP or interface for each virtual host?**
No. The honeynet responders answer ARP/ICMP/LLDP for each virtual IP, and the
TUN userspace TCP stack (`internal/tcpstack`) completes a fingerprint-shaped
handshake and answers one request/response — all without `ip addr add` per host.
The L2/L3 parts are Linux-only; on macOS use `ifconfig <iface> alias <ip>` per
host. See [`tcp-stack.md`](tcp-stack.md).

**How many virtual hosts can I run?**
Many — each host is cheap (no socket or OS interface per host). Each one's
identity (SSH banner, MySQL version, SMB challenge, MAC, …) is derived from
`sensor.deployment_id` + the host id, so every decoy machine looks distinct.
`tarpit-honeypot list-honeynets` prints the synthesized topology.

**Does it support IPv6?**
Yes. Listeners and honeynet hosts take IPv6 (`[::]:22`, `fd00::` host IPs), and
the AF_PACKET sniffer detects scans, fragmentation, encapsulation, and ICMP
tunnels over **both** IPv4 and IPv6. The honeynet TUN responder now answers IPv6
TCP SYNs too — an open port replies with a SYN-ACK and emits a
`honeynet:tcp_connect` event — so IPv6 port scans are observed just like IPv4.
The stateful data phase (the request/response exchange after the handshake)
stays IPv4-only.

**Can an attacker pivot between virtual hosts?**
No — there's no real OS behind them. The TUN stack is deliberately a *decoy*:
in-order data only, one request/response, no routing or forwarding. Deep
multi-segment interaction (a full SSH session, large uploads) wants a real
socket bound alongside the TUN (`ip addr add` / a real listener).

**Can one HTTPS port serve different certs by hostname (SNI)?**
Yes — set `https.vhosts:`. Each entry's `server_name` (an exact name or a
`*.domain` leading-wildcard) presents its own certificate, with its own `cn` /
`org` / `key_type` (blank fields derive a stable persona from the deployment
seed). The name that matched the client's TLS SNI lands in the event's
`tls_vhost` field.

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

**What do the severity levels mean?**
`low` / `medium` / `high` / `critical`. Each rule ships a sensible default —
recon/connects sit low, auth attempts and exploit signatures sit high, canary
trips and honeytoken hits sit critical — and severity gates routing/min-severity
and weights the per-source risk score. Re-map any rule for your environment with
`severity_overrides:`.

**What's the difference between `drop`, `banner`, and `tarpit` modes?**
`drop` accepts and immediately closes (records the connect only); `banner` runs
the protocol handler (real reply + captured request); `tarpit` holds the
connection open to waste the client's time. `tarpit.emulate: true` runs the
handler first, *then* tarpits the same connection.

**Does it deduplicate repeated events?**
Yes — a `dedup` window collapses identical repeated events, and outbound sinks
have their own per-`(source, rule)` window so one hammering source doesn't flood a
channel. The local store still records the full picture.

**What CVEs does it know about?**
A curated catalog of 100+ entries (run `tarpit-honeypot list-cves`), each with
CVSS, CWE, CPE, EPSS, and the ATT&CK technique. Vuln-emulation (advertise an
unpatched version + recognize the matching exploit) is per-listener
(`sensor.vuln_emulation`); exploit-attempt detection (`cve:<id>` events) runs
regardless.

**What's a tarpit, and what are canary tokens?**
Two deception features with their own sections below — see [Tarpits](#tarpits)
(holding connections open to waste attacker time) and
[Canary tokens](#canary-tokens) (file/URL/DNS tripwires).

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

## Tarpits

**What is a tarpit?**
A listener in `mode: tarpit` holds the connection open instead of answering and
hanging up — so a scanner, worm, or brute-forcer spends its time and sockets on
you instead of on real targets. It's the "honeypot wastes the attacker's day"
half of the name.

**What strategies are there?**
Set `tarpit.strategy:`:
- `sticky` — accept and never read/write; the kernel's TCP keepalive eventually
  notices a dead peer. The cheapest way to pin a persistent scanner.
- `trickle` — write one byte of `tarpit.trickle.text` every
  `tarpit.trickle.byte_interval` (e.g. 2s), cycling — banner-grabbers wait
  forever for content.
- `keepalive` — write a NUL byte every `tarpit.keepalive.interval` (e.g. 30s) —
  minimal-bandwidth persistent presence.

That's the start of **12 strategies** in all. The rest: `jitter` (trickle on a
randomized interval), `backoff` (an interval that grows over the engagement),
`ssh_banner` (endlessh-style endless SSH preamble), `http_headers` (endless HTTP
response headers, never the blank line), `http_chunked` (a chunked body that
never ends), `echo` (slowly echo whatever the client sends), `babble` (endless
plausible junk), and the two **aggressive, opt-in** ones: `zipbomb` (a gzip
decompression bomb) and `zero_window` (a LaBrea-style TCP zero-window clamp).
The aggressive pair are *retaliatory* and are **never** a default — choose them
deliberately.

**Can a tarpit still capture what the attacker sent?**
Yes — set `tarpit.emulate: true` and the listener runs its real `handler:` first
(genuine banner + captured request), *then* tarpits the same connection. Any
emulator becomes a tarpit, and the captured banner/request rides on the
`tarpit_start` event (`tarpit_emulated_handler` in meta).

**Won't holding connections open exhaust the sensor?**
Cap them: `tarpit.max_per_source` limits concurrent held connections per source
(with overall accept caps via `max_concurrent`). Tarpits are TCP-only and never
amplify, so they can't be turned into a reflection primitive.

**What events does a tarpit emit?**
`listener:<id>:tarpit_start`, `tarpit_end`, and `tarpit_drop` mark the lifecycle,
so you can see how long each engagement lasted and how many were shed at the cap.

**When should I use one?**
On commodity-scanned ports where slowing mass tooling is worth more than a clean
banner — and `emulate: true` gives you both. Mix tarpit and banner listeners
across your decoys.

## Canary tokens

**What's a canary token?**
An unguessable tripwire embedded somewhere it should never be touched — a file, a
URL, a DNS name. The instant it's accessed, the sensor emits a high/critical
event. There's nothing to tune for false positives: a hit *is* the signal.

**What kinds are there?**
- **File canaries** (`canaries:`) — honeyfiles watched via fsnotify
  (modify/remove/rename/chmod); on Linux with the capability, fanotify also
  catches plain `OPEN`/reads that fsnotify can't. Fires `canary:<id>`.
- **URL canaries** (`url_canaries:`) — a secret path; any HTTP/HTTPS handler that
  sees it (query string stripped) fires `canary:url:<id>` *in addition to* the
  normal listener event.
- **DNS canaries** (`dns:` + `dns_canaries:`) — a minimal DNS listener that
  answers NXDOMAIN but fires `canary:dns:<id>` on any subdomain of a registered
  name, so even a *resolution attempt* trips it.

**How do I create the tokens?**
`tarpit-honeypot gen-token --type=dns|url|hex [--label LBL] [--bits N]
[--domain D]` mints an unguessable value; paste it into a `url_canaries:` /
`dns_canaries:` block (or name a honeyfile) and embed it in fake docs, emails,
configs, or scripts.

**Where should I plant them?**
Anywhere an attacker who's already inside would look: a `passwords.xlsx` on a
share, a fake `.env`/API path in a repo or web root, a `db-host` DNS name in a
deploy script. Because DNS resolution alone trips a DNS canary, those reach even
into egress-filtered networks.

**How are these different from honeytokens?**
A canary is bait *you* place and watch. A **honeytoken** is a per-deployment-unique
secret the fake web app *serves* (a DB password, an `AKIA…` AWS key) — register it
in your SIEM and alert if it ever shows up in real auth logs.

**How do I detect SSRF / XXE / webhook abuse?**
Use the `ssrf_canary` handler with a token from `gen-token --type=ssrf`, which
mints a callback URL. Plant it where a coerced system will fetch it — an SSRF
parameter, a webhook field, an XXE entity. When something fetches it, the
callback is recorded (the token plus the `User-Agent` / `X-Forwarded-For` / `Via`
chain) and flagged `ssrf-callback`, and `ssrf-server-side-fetch` when the
fetcher's UA is an HTTP client library rather than a browser. It's the *inverse*
of the inbound URL/DNS canaries: those trip when an attacker reaches *in*, this
trips when a coerced server reaches *out*.

## Enrichment

**What does enrichment add to an event?**
For each source IP: **GeoIP** city + **ASN** (+ org), reverse DNS,
**threat-intel** list membership (`threat_intel_hit`), a **Tor-exit** flag, a
**net-class** tag (bogon/hosting), and — for L2-learned hosts — **MAC vendor**
(IEEE OUI). All optional, best-effort (a missing file warns and is skipped), and
hot-reloaded on `SIGHUP`. Configure the paths under `sensor.geoip` / `oui_file` /
`tor` / `threat_intel` / `net_class` (see [`config.md`](config.md)).

**Where do the databases come from?**
They're operator-supplied — public feeds, not bundled with the binary. Two
shipped scripts manage them as a deliberate two-stage, air-gap-friendly workflow:
`scripts/fetch-enrichment.sh` downloads them on an internet-connected box, and
`scripts/install-enrichment.sh` places them on the sensor and reloads it. You can
also fetch/manage the files by hand and just point the config at them.

**What does `fetch-enrichment.sh` do?**
Run it on an **internet-connected machine** (not the sensor); it needs only bash
+ curl-or-wget (+ tar/gunzip for GeoIP). It downloads into a bundle directory
(default `./enrichment-data`):

- **Tor exit list** — `check.torproject.org` → `tor-exits.txt`
- **IEEE MAC-vendor OUI** — `standards-oui.ieee.org` → `oui.csv`
- **IP-reputation feeds** → `threat/` — blocklist.de, abuse.ch Feodo, Spamhaus
  DROP, FireHOL level-1
- **GeoIP city + ASN** → `geoip/city.mmdb`, `geoip/asn.mmdb` — MaxMind GeoLite2
  if `MAXMIND_LICENSE_KEY` is set, otherwise the no-key **DB-IP "lite"** databases
  (same MaxMind-DB format the sensor reads)

It writes atomically (a failed feed never clobbers a good copy), and emits a
`MANIFEST.txt`, a `SHA256SUMS`, a `suggested-config.yaml` snippet, and a single
`enrichment-data.tar.gz` (+ `.sha256`) for easy transfer. Useful env vars:
`MAXMIND_LICENSE_KEY` (use GeoLite2), `SKIP_GEOIP=1` (skip the large GeoIP
files), `NO_ARCHIVE=1`, `INSECURE=1`.

```bash
# on a connected box:
MAXMIND_LICENSE_KEY=… scripts/fetch-enrichment.sh ./enrichment-data
```

**What does `install-enrichment.sh` do?**
Run it **on the sensor** against a bundle (the directory or its `.tar.gz`). It:

1. verifies the bundle's `SHA256SUMS` (refuses to install on mismatch; `--skip-verify` to override),
2. asks the **running config** where each file belongs via
   `tarpit-honeypot list-paths --format tsv` — so destinations always match the
   live config (no hard-coded paths), and it only touches `read`-access
   enrichment inputs, never sensor-written state,
3. atomically copies each file into its configured destination, and
4. signals the sensor to re-read (`SIGHUP`).

```bash
# on the sensor:
sudo scripts/install-enrichment.sh /tmp/enrichment-data -c /etc/tarpit-honeypot/config.yaml
```

Flags: `-c CONFIG`, `--bin PATH` (locate the binary), `--dry-run` (show the plan,
change nothing), `--no-reload`, `--reload-cmd "systemctl reload tarpit-honeypot"`,
`--skip-verify`. It maps the canonical bundle names (`oui.csv`, `tor-exits.txt`,
`geoip/*.mmdb`, `threat/<label>.txt`) onto the config keys (`oui_file`,
`tor.exit_file`, `geoip.city_db`/`asn_db`, `threat_intel:<label>`), so only the
inputs you've actually configured get installed.

**What's the end-to-end import workflow?**
Fetch on a connected box → transfer the bundle → install on the sensor (which
reloads itself):

```bash
# 1. connected box
scripts/fetch-enrichment.sh ./enrichment-data
# 2. transfer (the script prints the exact scp/rsync line for your bundle)
scp enrichment-data.tar.gz* sensor:/tmp/
# 3. sensor
ssh sensor 'tar -xzf /tmp/enrichment-data.tar.gz -C /tmp && \
            sudo scripts/install-enrichment.sh /tmp/enrichment-data -c /etc/tarpit-honeypot/config.yaml'
```

**Do I need a MaxMind license for GeoIP?**
No. Without `MAXMIND_LICENSE_KEY` the fetch script grabs the no-key **DB-IP lite**
city/ASN databases (same `.mmdb` format the sensor reads). Set the key to use
**GeoLite2** instead, or `SKIP_GEOIP=1` to skip GeoIP entirely (the geo/ASN
fields are then just absent).

**Can it run fully offline / air-gapped?**
Yes — that's what the split is for. The sensor never phones home; only the
*fetch* step needs the internet, on a separate box. Transfer the bundle (verified
by `SHA256SUMS`) and install it. With no enrichment files the sensor still starts;
the fields are simply absent.

**How do I keep the databases fresh?**
Schedule both ends: a cron job runs `fetch-enrichment.sh` on the connected box and
syncs the bundle, and a sensor-side cron/systemd-timer runs
`install-enrichment.sh` (which `SIGHUP`s the sensor, so the lists hot-reload with
no restart). Use `--reload-cmd` if you manage the process with systemd. Fleet
knowledge can also flow back as a downward intel feed (see
[`fleet.md`](fleet.md#6-downward-intel-feedback)).

## ICS / OT

**What ICS/OT protocols does it emulate?**
modbus, s7 / s7comm_plus, iec104, opcua, ethernetip, dnp3, bacnet, fins, knx,
melsec, codesys, hartip, mms (IEC 61850), profinet-DCP, atg (Veeder-Root),
ge_srtp, pcworx, ads (Beckhoff TwinCAT), plus passive L2 **GOOSE** detection.
`tarpit-honeypot list-handlers` for the live set; OT archetypes (Moxa, SCALANCE,
Siemens S7, Allen-Bradley, …) keep the identity coherent.

**Is it safe to put in an OT segment?**
Yes — it's passive and decoy by design: it answers but never initiates, never
talks to a real PLC, rate-limits UDP, and refuses to be a reflection/
amplification primitive. ICS writes / mode-changes / program-downloads are
*detected as events*, never performed.

**Can it talk to or control real PLCs?**
No. It only *presents* ICS services and *captures* what an attacker sends. There
is no code path to a real field device.

**What OT-specific detections fire?**
ICS-control, OT-recon, PLC program-download (Stuxnet/Triton-shaped),
ICS-mode-change, and OT-kill-chain correlators, GOOSE / PROFINET-DCP recon
events, and ICS-matrix ATT&CK tags on the relevant handlers.

## Attacker intelligence

**What does it learn about an attacker?**
A per-source-IP **dossier** (`/profiles`): first/last seen, a severity-weighted
threat score, identified tools/scanners, JA3/JA4/HASSH fingerprints, credentials
tried, ATT&CK coverage, CVE attempts, and the services/ports targeted — built up
over time. The **fingerprints** tab pivots a TLS/SSH stack to every IP/ASN/
country/tool that used it (across the fleet).

**What credentials get captured?**
Username/password from every auth-bearing handler (SSH, FTP, HTTP/web login,
Telnet, LDAP bind, MySQL/Postgres/MSSQL, Redis, SMB, …), matched against a
default-credential corpus. Captured pairs ride on the brute-force aggregates and
become `credential` IOCs.

**What are JA3/JA4/HASSH and what do I do with them?**
Client TLS (JA3/JA4) and SSH (HASSH) stack fingerprints, stable across GREASE
shuffling. Pivot from a fingerprint to every source that used it, export them as
IOCs, or feed them into the fleet intel — the same tuple your threat-intel feeds
key on. v2.2 adds two more: **JA4S** (the server-side TLS fingerprint, meta
`ja4s`, computed by the https handler) and **JA4T** (a client TCP fingerprint
read straight off the SYN — window size, options, MSS, window-scale — meta `ja4t`
on `honeynet:tcp_connect` events), plus `fingerprint.JARM` as a library
primitive.

**Does it identify the scanning tool?**
Yes — nmap / masscan / sqlmap / nikto / hydra / nuclei / metasploit / gobuster /
curl-wget-python / Mirai-style probes, with an automation-vs-human flag, from
UA / SSH-banner / path heuristics. `tarpit-honeypot identify` runs the same
engine offline on a string you paste. See [`attribution.md`](attribution.md).

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

**Can I query the database directly?**
Yes — `<data_dir>/events.db` is plain SQLite (WAL mode); open it read-only with
any SQLite client. The schema lives in `internal/store/store.go`. For
programmatic use prefer `/api/events` or `list-events`, which apply the same
filters.

**Does the UI update on its own?**
Yes — every page auto-refreshes via `<meta refresh>` at `ui.refresh_seconds`
(default 10; `0` disables), so the console stays live during an attack with no
JavaScript required.

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

**Can sensors in a fleet run different configs / archetypes?**
Yes — each sensor is independent (its own listeners, archetypes, honeynets). The
aggregator keys on the stable `sensor_id`, so a heterogeneous fleet (a Windows-AD
decoy here, an OT cell there, a DMZ web host elsewhere) correlates fine; in fact
diverse vantage points sharpen the cross-sensor signal.

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

## Alerting & logging

**How do I get paged on a critical event?**
Route it to an outbound channel — `twilio` (SMS), `discord`, `webhook`, `smtp`,
or `snmptrap` — gated by severity in `routes:`. `tarpit-honeypot test-alert`
injects a synthetic event through the full pipeline so you can confirm the wiring
before a real trigger.

**Won't a scan flood me with alerts?**
No — three brakes collapse bursts: a dedup window, a per-channel rate limit, and
a min-severity gate. Your own scanners go in `allowlist` (outbound suppressed,
local record kept), and the correlators turn many raw hits into one aggregate
(`correlate:port_scan`, `brute_force`, …).

**What do the logs look like?**
Structured `slog` — `--log-format text|json`, to stderr or `--log-file`, level via
`--log-level` (`--quiet`/`--verbose` shortcuts). Separately, the `jsonlog` sink
writes rotated JSONL events and `stdout` streams them; both are local sinks that
always receive.

**Is there Prometheus / Grafana support?**
Yes — `GET /metrics` exposes sink delivery / drops / retries, honeynet network &
host gauges, the on-disk store size, panic counts, and L2 frame counters. Scrape
it for dashboards and alert rules; `/healthz` is an auth-free liveness probe.

## Captures & forensics

**Does it capture packets?**
Per-connection, when a TCP listener has `capture: true`: a synthesized libpcap
file at `<data_dir>/captures/<event_id>.pcap` (pure-Go, no raw sockets). Pull one
with `tarpit-honeypot export-pcap --event <id>`, open in Wireshark, and "Follow
TCP Stream" reconstructs the exchange.

**Can I replay an attacker's shell session?**
Yes — with `sensor.session_recording`, interactive telnet / `ssh_interactive`
sessions are saved as asciinema v2 casts (with timing) under
`<data_dir>/sessions/`; the UI plays them back and the filename lands on the
event.

**Where do captured malware / payloads go?**
`<data_dir>/payloads/` (size-capped), each with a `sha256` IOC and a
`malware:capture` event. The event-detail page shows a hexdump and links the
artifact.

**How do I export everything from one source for analysis?**
The event-detail page offers a ZIP of everything from that source IP (the
per-connection pcaps, session casts, and payloads); for scripting, combine
`/api/events` with `export-pcap`.

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

**How do I rotate an auth token or other secret?**
Secrets are `*_env` references, so rotate the value in the environment (or your
secret manager) and restart — `SIGHUP` re-reads the environment for most. Because
the secret never lives in the YAML, there's no file to scrub.

**How do I wipe the store and start fresh?**
`tarpit-honeypot reset-db -c <cfg>` empties the local event store / device
inventory / captures while keeping your config. Useful after a test run or before
handing a box on; the schema is recreated on next start.

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
deterministic rng, timers). **200 Lua personas ship in the box** under
[`configs/scripts/`](../configs/scripts/). See the full guide — API, limits,
warnings, recipes — in [`docs/lua.md`](lua.md).

**Is the Lua sandbox safe? Can a persona be exploited into running code on the
sensor?**
No. The VM opens only `base`/`string`/`table`/`math` — there is **no `io`, `os`,
`debug`, `require`, `load`, or `print`** — so a script cannot touch the
filesystem, spawn a process, open a socket, or load more code. Reads are capped
at 64 KiB and writes at 256 KiB per connection (the write cap is an
anti-amplification guarantee), sleeps at 30 s, and the listener timeout bounds
the whole run. A persona *emulates* a vulnerable service; it never executes
attacker input.

**Which scanners / attack tools does the sensor recognize, and how?**
It fingerprints the tool from the User-Agent, the request path, the SSH client
banner, and JA3/JA4/HASSH — tagging the event `tool:<name>`, a confidence, and a
category (`vuln-scanner` / `c2-framework` / `headless-browser`). 300+ signatures
ship (nmap, sqlmap, Nuclei, sn1per, xray, Cobalt Strike, …) plus IP-level
attribution of research scanners (Censys/Shodan/…). See
[`docs/attack-tools.md`](attack-tools.md).

**Can the DNS handler decoy a vulnerable server or trap a zone transfer?**
Yes — `listener.dns_responder.version_bind` answers `version.bind` CHAOS queries
with a configurable old/exploitable BIND banner, and `fake_zone: true` answers an
AXFR/IXFR with a fabricated juicy zone (NS/MX + dozens of service hostnames + TXT
"secrets") instead of refusing. Zone-transfer attempts are flagged regardless.

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

## Legal & ethical

**Is it legal to run a honeypot?**
Generally yes for monitoring a network you own or operate, but wiretap, privacy,
and computer-misuse laws vary by jurisdiction — get sign-off from legal /
management first. This is not legal advice, and you should never deploy it on a
network you don't control.

**Does it "hack back" or entrap anyone?**
No. It's passive: it never attacks, never initiates unsolicited outbound
connections (telemetry is allowlisted, and `egress.enforce` adds an OS-level
backstop), and only records what is sent to it. It presents bait but doesn't
induce anyone to act.

**How should I treat the captured data?**
As sensitive — it can contain credentials, payloads, and attacker-supplied
bytes. Restrict access to the `data_dir` / store, set `disk.retention_days`, and
don't place a sensor where it would capture legitimate user traffic. Output is
sanitized before logs/SIEM/email so captured bytes can't inject into your tools.

**Can I rely on it for attribution?**
Treat source IPs and fingerprints as *indicators*, not identities — attackers use
proxies, Tor, and botnets. Enrichment flags (Tor-exit, hosting/bogon net-class)
and the fleet's broad-vs-targeted scoring help you weight them, but attribution
is always a judgement call.

## Troubleshooting

**I scanned it but only see `sensor:started` — no attack events.**
You probably scanned ports it isn't bound to. Some example configs remap services
to high ports to run without root, so a scan of 22/80/443 hits nothing. Check the
bound ports (`tarpit-honeypot show-config -c <cfg> | grep -E 'id:|bind:'`) or run
`configs/tarpit-honeypot.example.yaml`, which binds real service ports.

**`bind: permission denied` on a low port.**
Binding <1024 needs `CAP_NET_BIND_SERVICE` (the shipped systemd unit grants it),
or run as root and let the sensor drop to `drop_user`/`drop_group` after setup.
In Docker, add `--cap-add=NET_BIND_SERVICE`.

**`arp_responder disabled: needs AF_PACKET (linux-only)` / `need CAP_NET_RAW`.**
The sniffer and L2/L3 responders are Linux-only and need `CAP_NET_RAW`. Pair
`User=tarpit` with `AmbientCapabilities=CAP_NET_RAW`; on macOS use
`ifconfig <iface> alias <ip>` instead. See [`usage.md` §14](usage.md#14-platform-support).

**My `fleet:*` detectors never fire.**
Breadth detection needs events from **several** `sensor_id`s converging via
`ingest:` — one sensor's events all key to one id. Check `fleet.enabled` (auto-on
with ingest) and your thresholds. See [`fleet.md` §9](fleet.md#9-troubleshooting).

**I keep seeing `WARN ui: request failed … /events … context canceled` in the log.**
Harmless, and fixed as of v2.9.0. The auto-refreshing dashboard cancels an
in-flight `/events` request whenever it navigates/refreshes; that surfaces as
`context canceled`. The UI now logs it at debug (not WARN) and skips the 500.
A genuine query *timeout* (`context deadline exceeded`) still warns.

**Where do I look first?**
The web UI **errors** tab and the structured `slog` output (journal under
systemd) for operational/health events; [`usage.md` §15](usage.md#15-troubleshooting)
is the symptom→fix table.

## Glossary

- **Aggregator** — a node with `ingest:` that accepts forwarded events from many
  sensors and runs the cross-sensor `fleet:*` correlator over the merged stream.
- **Allowlist** — source IPs/CIDRs whose events are still recorded locally but
  suppressed from forwarding/alerting (e.g. your own scanners); distinct from the
  egress allowlist.
- **Anomaly marker** — a per-request flag a handler raises (`uri-log4shell-jndi`,
  `ssh-id-non-printable`, `modbus-write-attempt`) that rides on the event and
  refines its ATT&CK tags.
- **Archetype** — an OS/device personality that pins every fingerprint (banners,
  SNMP identity, MAC OUI, TLS posture, ICMP TTL, advertised CVEs) to one coherent
  machine. `list-archetypes`.
- **Archeservice** — a service *role* (`webserver`, `adserver`, …) that expands into
  the right listeners for that role. `list-archeservices`.
- **ATT&CK / D3FEND** — MITRE's adversary-technique matrix and its
  defensive-countermeasure counterpart; every event is tagged with both.
- **Banner mode** — a listener that runs its protocol handler (a believable reply
  plus a captured request). Contrast `drop` and `tarpit`.
- **Broad vs targeted** — a fleet finding's scope: *broad* = internet-wide
  background (down-weighted), *targeted* = a specific subset of your fleet.
- **Canary token** — an unguessable file/URL/DNS tripwire that fires the instant
  it's touched. See [Canary tokens](#canary-tokens).
- **Capture / pcap** — optional per-connection synthesized libpcap under
  `<data_dir>/captures/`; pull it with `export-pcap`.
- **Channel** — a configured outbound destination (syslog, webhook, smtp, mqtt,
  twilio, sns, snmptrap, discord) plus the local stdout/jsonlog/sqlite sinks.
- **Correlator** — a windowed, multi-event detector (`correlate:*`) that fires when
  a per-source pattern crosses a threshold (port-scan, brute-force, beacon).
- **Coverage** — a fleet finding's `sensors_hit / active_sensors` ratio, the basis
  of the broad-vs-targeted call.
- **CVE / CWE / CPE / EPSS** — the vulnerability id, weakness class,
  affected-product identifier, and exploit-probability score stamped on `cve:*`
  events.
- **Dedup** — the window that collapses identical repeated events (with a separate
  per-`(source, rule)` window for outbound sinks).
- **deployment_id** — a stable random seed (persisted to
  `<data_dir>/.deployment-id`) that makes every "fixed" handler string unique per
  sensor.
- **Device learning** — the opt-in registry of hosts seen on the segment; raises
  `device:new` for never-before-seen, non-allow-listed devices.
- **Egress allowlist** — the outbound destinations the sensor may dial
  (`egress.allow`); `egress.enforce` adds an nftables backstop and a block is
  logged `egress:denied`.
- **Enrichment** — per-source decoration (GeoIP/ASN/rDNS/threat-intel/Tor/MAC) added
  to every event; optional and hot-reloaded.
- **Event** — the one record type for every interaction: id, time,
  sensor/sensor_id, rule_id, severity, source/dest, proto/handler, payload,
  anomalies, ATT&CK/D3FEND.
- **Fleet** — several sensors aggregated so cross-sensor patterns surface; events
  flow up, intel flows down.
- **Fleet detector** — a cross-sensor rule (`fleet:*`) only an aggregator fires.
  `list-fleet-rules`.
- **Forwarder** — a node with `forward:` that ships its events to one or more parent
  aggregators (full or `rollup`).
- **Handler** — the protocol emulator bound to a listener (`ssh`, `http`, `modbus`,
  …). `list-handlers`.
- **Honeynet** — a virtual network (CIDR + gateway + hosts) the sensor presents
  without an OS interface per host.
- **Honeytoken** — a per-deployment-unique secret the fake web app serves (DB
  password, AWS key) so you can alert if it surfaces in real logs.
- **Intel feed** — the downward indicators an aggregator serves (`/intel`, STIX,
  TAXII) that sensors subscribe to via `intel_feed:`.
- **IOC** — a typed, de-duplicated indicator of compromise
  (ip/asn/ja3/domain/cve/sha256/url/credential/mac) mined from events. See
  [`ioc.md`](ioc.md).
- **JA3 / JA4 / JA4H / JA3S / JA4S / JA4T / HASSH** — TLS client/server, TCP-SYN
  (`ja4t`), and SSH client stack fingerprints, stable across GREASE shuffling.
  `fingerprint.JARM` is also available as a library primitive.
- **net-class** — an enrichment tag classifying a source network (bogon, hosting, …).
- **Risk score** — a decaying per-source threat score that emits
  `risk:elevated|high|critical` on a threshold crossing.
- **Rollup** — a forwarding mode that ships a periodic `fleet:rollup` summary
  instead of every event.
- **Route** — a `routes:` rule matching events (by severity/fields) to the channels
  that should receive them.
- **rule_id** — the event's stable type key (`listener:ssh-bait`,
  `correlate:port_scan`, `cve:<id>`, `fleet:*`, `ioc:*`).
- **Sandbox** — the Linux self-confinement layer: a seccomp syscall denylist plus a
  Landlock read-only-FS policy (`sensor.sandbox`).
- **Sensor** — a node with `listeners:` that presents decoys and emits events; the
  base role.
- **sensor_id** — the stable per-deployment id (the fleet dedup/attribution key)
  that survives a hostname change.
- **Severity** — `low | medium | high | critical`; gates routing/min-severity and
  weights the risk score. Re-map with `severity_overrides:`.
- **Sink** — the delivery side of a channel (where an event is written/sent), each
  with a bounded retry queue.
- **Sniffer** — the Linux AF_PACKET layer that catches L2 abuse and L3/L4 stealth
  scans that never complete a connection.
- **Storyline** — the cross-protocol correlator (`storyline:multi_stage`) that fires
  when one source touches 3+ ATT&CK tactics in a window.
- **Tarpit** — a listener that holds a connection open to waste attacker time. See
  [Tarpits](#tarpits).
- **Trust scoring** — per-sensor windowed scoring on an aggregator that rate-limits
  and can quarantine a noisy/compromised sensor (`ingest.trust`).
- **TUN / userspace TCP stack** — the Linux adapter + pure-Go stack that lets
  virtual hosts complete fingerprint-shaped handshakes with no socket per host.
- **Virtual host** — one decoy machine inside a honeynet (its own IP/MAC/identity
  and service list).
- **Vuln emulation** — advertising an archetype's deliberately-unpatched version (+
  fake patch level) so a scanner records an exploitable box
  (`sensor.vuln_emulation`).

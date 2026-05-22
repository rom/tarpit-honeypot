# Usage Guide

This document is the end-to-end "I just got the binary, what do I do" reference. For the YAML schema see [`docs/config.md`](config.md); for the CLI reference see [`docs/cli.md`](cli.md).

## 1. Quickstart

```bash
# Build (or download a release binary from dist/)
make build

# Validate the example config without starting anything
./bin/tarpit-honeypot validate-config -c configs/tarpit-honeypot.example.yaml

# Start the sensor in the foreground
./bin/tarpit-honeypot run -c configs/tarpit-honeypot.example.yaml
```

The example config ships with sensible defaults: a few low-interaction honeypots on high ports, JSON log + SQLite + stdout sinks, a loopback-only web UI on `127.0.0.1:8088`, and a sample honeynet skeleton (no virtual hosts active until you uncomment them).

In another shell:

```bash
# Generate some events
nc -v localhost 2222                              # ssh honeypot
printf 'GET /admin HTTP/1.0\r\n\r\n' | nc -v localhost 8000

# Watch them
./bin/tarpit-honeypot list-events -c configs/tarpit-honeypot.example.yaml

# Open the web UI
xdg-open http://127.0.0.1:8088
```

## 2. Daily operations

### Generating canary tokens

Operators commonly leave decoy URLs/DNS names lying around to catch lateral-movement. The `gen-token` subcommand prints unguessable tokens shaped for three common bait surfaces:

```bash
./bin/tarpit-honeypot gen-token --type=dns --label=prod-cdb
# 6191564a98496be6-prod-cdb.canary.example.com

./bin/tarpit-honeypot gen-token --type=url --bits=128
# /__canary__/8ed2a49c8ef9639a1234567890abcdef
```

Paste the output into a `dns_canaries:` or `url_canaries:` entry in the config, drop a reference in fake docs / shell history / config files, and the sensor fires a critical event the moment any resolver or HTTP client touches it.

### Hot reload

```bash
sudo systemctl reload tarpit-honeypot
# or:
sudo kill -HUP $(pgrep tarpit-honeypot)
```

The sensor logs a diff for every change. **Hot-reloadable**: channels, routes, allowlist, dedup window, correlator thresholds, canary lists, URL canary lists. **Requires restart**: anything under `sensor.*`, the UI bind, the DNS listener bind, the sniffer interface.

Listener changes are *also* hot-reloadable — the old listener is stopped and a new one is started with the new bind / handler / mode. In-flight handler goroutines drain per the `sensor.shutdown.drain_timeout`.

### Comparing two configs before you reload

```bash
./bin/tarpit-honeypot validate-config \
  -c /etc/tarpit-honeypot/config.yaml \
  --diff /tmp/proposed.yaml
```

Prints a categorized diff: which changes hot-reload vs which require restart. Same logic the SIGHUP path uses.

### Showing the effective post-defaults config

```bash
./bin/tarpit-honeypot show-config -c /etc/tarpit-honeypot/config.yaml
```

YAML output with all defaults filled in. Secrets stay as env var names (`auth_token_env: TARPIT_UI_TOKEN`) rather than expanded values, so the output is safe to paste in tickets.

### Pulling a specific event's pcap

When a TCP listener has `capture: true`, every accepted connection is written as a synthesized libpcap file under `<data_dir>/captures/<event_id>.pcap`. To grab one:

```bash
./bin/tarpit-honeypot list-events -c cfg.yaml --rule listener:ssh-bait --limit 5
# ... copy the event id ...
./bin/tarpit-honeypot export-pcap -c cfg.yaml --event 7c0574dd1015ac2c142e30ca -o /tmp/ssh.pcap
wireshark /tmp/ssh.pcap
```

### Inspecting the built-in catalogs (offline)

These read-only subcommands dump the in-source catalogs (no config or
network needed) so you can discover what the sensor can impersonate and
detect, and tune detections:

```bash
./bin/tarpit-honeypot list-archetypes                 # all 99 device personas
./bin/tarpit-honeypot list-archetypes xerox-versalink # one archetype's full fingerprint
./bin/tarpit-honeypot list-handlers --proto tcp       # handlers valid on a listener
./bin/tarpit-honeypot list-cves --service ipp         # emulated/detected CVEs by service
./bin/tarpit-honeypot list-techniques --kind anomaly  # MITRE ATT&CK -> D3FEND coverage
# Triage a log line: what would the sensor make of this?
./bin/tarpit-honeypot identify --ua "sqlmap/1.7" --payload '${jndi:ldap://x/a}'
```

## 3. Honeynets

A *honeynet* is a configured artificial network with virtual hosts. One sensor can present as many distinct virtual machines, each with its own deterministic identity (SSH banner version, MAC, MySQL build string, SMB challenge, etc.).

The base mode (v1.1+) is **destination-IP dispatch**: when an incoming connection's destination matches a configured virtual host IP, the listener dispatches to a per-host handler instance. That requires the OS to actually route the virtual IPs to the sensor — typically via `ip addr add 10.99.0.10/24 dev eth0` or iptables DNAT.

Five optional Linux-only adapters make the honeynet more discoverable **without** that OS plumbing:

- **`arp_responder`** (v1.2): the sensor opens an AF_PACKET socket and answers ARP requests for every virtual host IP. `arp-scan` sees the network as populated.
- **`icmp_responder`** (v1.3): the sensor answers IPv4 ICMP echo (ping) for every virtual host IP via the same AF_PACKET path.
- **`tun`** (v1.5): the sensor opens a Linux TUN device. The operator routes the honeynet CIDR into the TUN. The sensor answers ICMP/ICMPv6 echo and sends TCP RST for unbound ports. `nmap -sS` reports the host as up. Synthesized replies carry each host's archetype **TTL personality** (255 OT / 128 Windows / 64 Linux), so `nmap -O` + traceroute hop-distance match the claimed OS.
- **`lldp_responder`** (v1.10): the sensor emits LLDP (and optionally CDP) frames so every honeynet host appears in `lldpctl` / Cisco `show cdp neighbors` output with archetype-shaped MAC + system description + family-tuned LLDP capabilities. Pairs naturally with the Moxa / SCALANCE / S7 archetypes for industrial deception.
- **`profinet_responder`**: the sensor answers PROFINET-DCP Identify requests (L2, EtherType 0x8892) for industrial hosts, so a PROFINET scan (Siemens PRONETA / TIA Portal / nmap) enumerates the cell. Each request also raises `honeynet:profinet_dcp_identify` (ATT&CK T0846) — a strong ICS-recon signal.

None of these adapters provide a full userspace TCP stack — real protocol termination still goes through real sockets. For "scanner sees the network as populated" they are sufficient.

On macOS the AF_PACKET-based adapters are not available; see [Platform support](#10-platform-support) below for the `ifconfig alias` workaround.

### Pattern A — virtual hosts behind one listener (the simplest setup)

```yaml
listeners:
  - id: ssh-bait
    proto: tcp
    bind: 0.0.0.0:22          # one real listener, many virtual hosts
    mode: banner
    handler: ssh

honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    arp_responder: { enabled: true, interface: eth0 }
    icmp_responder: { enabled: true, interface: eth0 }
    hosts:
      - { ip: 10.99.0.10, hostname: web-prod-01, os: linux,
          services: [{port: 22, handler: ssh}] }
      - { ip: 10.99.0.11, hostname: db-prod-01, os: linux,
          services: [{port: 22, handler: ssh}] }
```

Then on the host:

```bash
ip addr add 10.99.0.10/24 dev eth0
ip addr add 10.99.0.11/24 dev eth0
```

When a scanner connects to `10.99.0.10:22` vs `10.99.0.11:22`, the sensor sends two **different** SSH banner versions (derived deterministically from each host's identity).

### Pattern B — TUN-routed network

```yaml
honeynets:
  - id: edge
    cidr: 10.50.0.0/16
    tun: { enabled: true, device: tarpit0 }
    hosts: [...]
```

Then on the host:

```bash
ip link set tarpit0 up
ip route add 10.50.0.0/16 dev tarpit0
```

The sensor responds to all `nmap -sn`-style probes for that range; for actual protocol interaction, configure listeners that bind real sockets and use NAT to forward traffic from the TUN-bound network into the sensor.

## 4. Web UI

Default bind is `127.0.0.1:8088`. Enable in `ui:`. Endpoints:

- `/` — last-24h summary (event counts by severity, top rules, top sources)
- `/events?source=<ip>&rule=<id>&severity=<sev>&since=24h&limit=N` —
  filterable event table; click a column header (time / severity / rule /
  source / handler) to sort, click again to reverse (`?sort=&order=`)
- `/events/<id>` — full event detail (banner sent, base64 payload, meta)
- `/hosts?q=<substr>&status=seen|allow` — learned hosts, filterable
- `/topology` — the virtual networks / hosts / services the sensor presents
- `/alerting` — how events are forwarded (channels / routes / allowlist)
- `/errors?since=168h` — operational / health events (listener or
  canary-watcher stopped, listener start error, accept-cap overflow)
- `/config` — the effective running config (secrets shown as `*_env` names)
- `/docs` — built-in reference reflecting this deployment
- `/api/events`, `/api/summary`, `/api/config`, `/api/topology`,
  `/api/hosts`, `/api/alerting` — JSON equivalents
- `/metrics` — Prometheus text-format (v1.3+)
- `/healthz` — liveness check (bypasses auth)

Non-loopback binds are rejected at validate-time unless both `tls_cert + tls_key` and `auth_token_env` are configured. There is **no write endpoint** — the UI cannot delete events, change config, or trigger alerts.

## 5. systemd integration

The shipped unit at `packaging/systemd/tarpit-honeypot.service` runs as `tarpit:tarpit` with `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW` (and `CAP_NET_ADMIN` if you enable the TUN adapter). `ExecReload=/bin/kill -HUP $MAINPID` ties into the hot-reload path.

Standard install:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tarpit
sudo install -o root -g root -m 0755 bin/tarpit-honeypot /usr/local/bin/
sudo install -d -o tarpit -g tarpit -m 0750 /var/lib/tarpit-honeypot
sudo install -o root -g root -m 0640 configs/tarpit-honeypot.example.yaml /etc/tarpit-honeypot/config.yaml
sudo install -o root -g root -m 0644 packaging/systemd/tarpit-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tarpit-honeypot
```

Verify it's healthy:

```bash
sudo systemctl status tarpit-honeypot
sudo journalctl -u tarpit-honeypot -f
curl http://127.0.0.1:8088/healthz
curl http://127.0.0.1:8088/metrics
```

## 6. Docker

```bash
docker build -t tarpit-honeypot:latest .
docker run --rm \
  -p 2222:2222 -p 8000:8000 -p 8088:8088 \
  -v "$PWD/var:/var/lib/tarpit-honeypot" \
  -v "$PWD/configs/tarpit-honeypot.example.yaml:/etc/tarpit-honeypot/config.yaml:ro" \
  tarpit-honeypot:latest
```

The image is a multi-stage scratch build (~14 MB final). Privileged port binding inside the container needs either `--user 0` or `--cap-add=NET_BIND_SERVICE`. Honeynet ARP / ICMP responders additionally need `--cap-add=NET_RAW`, and the TUN adapter needs `--cap-add=NET_ADMIN --device=/dev/net/tun`.

## 7. Watching live activity

```bash
# tail -f equivalent
journalctl -u tarpit-honeypot -f -o cat | jq .

# Or just stdout if you configure a stdout channel
./bin/tarpit-honeypot run -c cfg.yaml 2>/dev/null | jq .

# By rule
./bin/tarpit-honeypot list-events -c cfg.yaml --since 5m --rule correlate:port_scan

# By source IP
./bin/tarpit-honeypot list-events -c cfg.yaml --since 1h --source 198.51.100.42

# Just critical
./bin/tarpit-honeypot list-events -c cfg.yaml --since 24h --limit 50 \
  | grep critical
```

## 8. SIEM integration

Pick the format per channel:

```yaml
channels:
  - id: ops-arcsight
    type: syslog
    network: tcp
    address: arcsight:514
    format: cef
  - id: ops-qradar
    type: syslog
    network: tcp
    address: qradar:514
    format: leef
  - id: ops-securitylake
    type: webhook
    url: https://lake.example.com/ingest
    format: ocsf
```

For Prometheus, scrape `/metrics`:

```yaml
- job_name: tarpit-honeypot
  bearer_token_file: /etc/secrets/tarpit-ui-token
  scrape_interval: 30s
  static_configs:
    - targets: ['sensor.example.internal:8088']
```

## 9. Archetypes

An **archetype** is an OS-shaped fingerprint pack: setting one makes every
banner-aware handler report values consistent with a stock install of
that OS, so a scanner can't catch the sensor by spotting a "Debian 12
host running OpenSSH 8.4p1 (Debian 11's version)" mismatch.

```yaml
sensor:
  archetype: debian 12              # or "ubuntu 24.04 lts", "centos 7", ...

listeners:
  - id: ssh-bait
    archetype: red hat enterprise linux 9   # overrides sensor for this listener
    proto: tcp
    bind: 0.0.0.0:22
    handler: ssh

honeynets:
  - id: factory
    hosts:
      - ip: 10.99.1.10
        archetype: moxa eds-208                # overrides listener for this host
        services: [{ port: 23, handler: telnet }]
```

**Precedence** (most specific wins): honeynet host > listener > sensor > no archetype (the v1.0 identity-pool fallback).

**Names are case- and separator-insensitive**: `"Debian 12"`, `"debian-12"`, `"debian_12"`, `"DEBIAN.12"` all resolve.

**Ship list (`tarpit-honeypot help archetypes`):**

| Family | Profiles |
|---|---|
| Debian | Debian 9 (stretch) → Debian 13 (trixie) |
| Ubuntu | Ubuntu 24.04 LTS, Ubuntu 26.04 LTS |
| RHEL / clones | RHEL 8/9/10, CentOS 5/6/7/8 + Stream 10, Rocky 9, AlmaLinux 9, Oracle 8/9 |
| BSD | FreeBSD 13/14, OpenBSD 7.5/7.6 |
| Other Linux | Arch Linux |
| Industrial network | Moxa (EDS / NPort / AWK / MGate), Westermo (WeOS), Hirschmann, Phoenix Contact, Advantech, Cisco IE-2000/IE-3400/IR1101, SCALANCE |
| Industrial controller | Siemens S7-1200/1500, Allen-Bradley ControlLogix, Schneider Modicon, Omron, ABB, Honeywell, WAGO, Beckhoff CX |
| Printers / MFD | HP LaserJet, Brother, Canon, Epson, Xerox VersaLink, Lexmark, Ricoh, Konica Minolta, Kyocera, Sharp, Zebra |
| Appliances | pfSense, FortiGate, Synology, QNAP, Hikvision/Axis cameras, MikroTik, Ubiquiti, Asterisk PBX |

This is an abbreviated view — see [`archetypes.md`](archetypes.md) for the
**complete 99-archetype catalog** with each device's services/protocols and
emulated CVEs, or run `tarpit-honeypot list-archetypes`.

**Each archetype carries:** SSH / HTTP / FTP / Telnet / SMTP / MySQL
banner strings; MAC vendor OUI (Moxa 00:90:E8, Siemens 28:63:36); CLI
prompt for shell engagement; SNMP MIB-2 identity (sysDescr,
sysObjectID, sysName, ifTable); LLDP neighbor TLVs; default-service
list; web-UI HTML body; TLS posture; ICMP TTL; advertised CVEs;
per-archetype protocol quirks.

**Printers / MFD:** pair a printer archetype with the `pjl` (9100), `ipp`
(631) and `lpd` (515) handlers for a coherent multi-function device. The
PJL handler is PRET-aware (decoys a fake filesystem, flags FSINIT format /
password set / PostScript `exitserver` / ZPL config); IPP flags the CUPS
foomatic-rip RCE chain; LPD flags control-file injection. The IPP reply
takes its make/model from the bound archetype, so IPP, SNMP and the web UI
agree.

## 10. Interactive engagement (post-login shell + web login capture)

The v1.10 engagement layer keeps the attacker on the wire after the
banner-grab phase so the sensor captures the full TTP trail instead of
just "scanner touched port 22".

### SSH interactive (`handler: ssh_interactive`)

Runs a full `golang.org/x/crypto/ssh` server. Captures every password +
public-key authentication attempt (with SHA-256 fingerprint for keys),
accepts the third credential, and drops into the archetype's shell on
the session channel.

```yaml
listeners:
  - id: ssh-engage
    proto: tcp
    bind: 0.0.0.0:2223
    mode: banner
    handler: ssh_interactive
    severity: high
    read_timeout: 30s
    capture: true
    max_concurrent: 16     # rate-limit; engagements consume more CPU than banner-grab
```

The host key is an ed25519 keypair persisted under
`<data_dir>/tls/ssh_host_ed25519_key`. Same fingerprint across
restarts so a scanner that re-touches the sensor doesn't see a
"key changed" warning.

### Telnet (`handler: telnet`)

After a fake "Login incorrect" first attempt, accepts the second one
and drops into the same archetype shell. Plaintext, simpler — useful
for the Moxa / SCALANCE archetypes where telnet is the documented
device CLI.

### What the shell captures

Per-command capture lands in `event.meta.shell_commands` (a list).
Each line is also scanned against a 24-marker ATT&CK-aligned anomaly
catalog (reverse shells, credential dumping, persistence, AD recon,
defense evasion, coin miners, …) and any hits flow into `event.anomalies`
for SIEM-side routing — each marker carries its own ATT&CK technique:

| Marker | ATT&CK |
|---|---|
| `shell-reverse-shell` | T1059 / T1071 |
| `shell-download-tool` | T1105 |
| `shell-persistence-ssh-key` | T1098.004 |
| `shell-persistence-cron` | T1053.003 |
| `shell-persistence-systemd` | T1543.002 |
| `shell-shadow-read` | T1003.008 |
| `shell-passwd-read` / `shell-passwd-write` | T1003 |
| `shell-priv-esc-suid` | T1548.001 |
| `shell-priv-esc-sudo` | T1548.003 |
| `shell-defense-evade-history` | T1070.003 |
| `shell-defense-evade-logclean` | T1070.002 |
| `shell-disable-fw` | T1562.004 |
| `shell-living-off-the-land` | T1059.004 |
| `shell-coin-miner` | T1496 |
| `shell-network-recon` | T1018 |
| `shell-encoded-payload` | T1027 |
| `shell-creds-file-access` | T1552.001 |

Bounded: `MaxCommands=32`, `MaxBytesPerCommand=8 KiB`, `IdleTimeout=60s`, `SessionTimeout=5min`.

### Web login capture (`handler: http` / `https`)

The HTTP handler routes on method + path. `GET /` serves the
archetype's index page; GET on a login path (`/login`, `/admin`,
`/Portal/Login.html`, `/cgi-bin/luci`, `/wp-login.php`,
`/manager/html`, etc.) serves a login form; POST with
`application/x-www-form-urlencoded` body extracts user + password
(accepts `username`/`user`/`login`/`name`/`uname`/`u` and
`password`/`pass`/`passwd`/`pwd`/`p`), emits the
`http-login-attempt` anomaly, and re-renders the form with an
"auth failed" line.

## 11. ATT&CK tagging, storyline correlation, anomaly detection

Every event the sensor emits carries `mitre_techniques` (e.g.
`["T1110.001","T1078"]`) and `mitre_tactics` (e.g.
`["credential-access","initial-access"]`). The mapping is
rule_id + handler-aware: listener:ssh-bait gets brute-force +
valid-accounts; listener:http-bait gets exploit-public-facing-app;
listener:modbus-bait gets the ICS-matrix equivalents.

The **storyline correlator** (`storyline:multi_stage`) fires when a
single source IP touches 3+ distinct ATT&CK tactics inside a 30-minute
window. The emitted event meta carries:

- `stages`: tactics in kill-chain order
- `chain`: human-readable arrow-joined ("discovery -> credential-access -> lateral-movement")
- `hit_count`, `dest_ports`, `handlers`, `distinct_rules`

So the SOC sees one timeline instead of dozens of independent
listener hits.

**Protocol-anomaly markers** (`event.anomalies`) flagged today:

- SSH: `ssh-id-non-printable`, `ssh-id-overlong`, `ssh-id-not-ssh`
- HTTP: `http-method-unknown`, `http-request-line-non-printable`,
  `uri-path-traversal`, `uri-log4shell-jndi`, `uri-wordpress-probe`,
  `uri-source-leak-probe`, `uri-mgmt-endpoint-probe`,
  `uri-secret-file-probe`, `uri-xss-or-rce-payload`,
  `http-login-attempt`; behavioral: `http-malformed-header`,
  `http-duplicate-host`, `http-impossible-browser`
- DNS: `dns-tunnel-suspected`, `dns-qname-overlong`, `dns-dga-suspected`,
  `dns-over-https`, `dns-over-tls`, `dnscrypt-probe`, `mdns-service-enumeration`
- Active Directory / Kerberos: `kerberos-tgs-request`,
  `kerberos-rc4-requested`, `ldap-spn-enumeration`,
  `ldap-asrep-roast-recon`, `ldap-enumeration`
- MSRPC (port 135): `dcerpc-samr-enum`, `dcerpc-lsarpc-enum`,
  `dcerpc-srvsvc-enum`, `dcerpc-svcctl-access`, `dcerpc-winreg-access`,
  `dcerpc-dcsync`, `dcerpc-netlogon-access`
- FTP (post-auth): `ftp-upload-attempt`, `ftp-download-attempt`,
  `ftp-site-command`, `ftp-bounce-scan`, `ftp-delete-attempt`, `ftp-listing`
- Data stores: `memcached-stats-probe`, `memcached-write-attempt`,
  `memcached-flush`; `unknown-protocol` (the `auto` catch-all)
- All shell-* markers listed in §10

The L3/L4 sniffer additionally flags scans (`sniffer:tcp_*_scan`,
`sniffer:udp_scan`), fragmentation (`sniffer:ip_fragmented`), covert
tunnelling (`sniffer:encapsulation` — GRE / 6in4 / 6to4 / ISATAP / DS-Lite /
GRE-over-IPv6 / VXLAN / …, `sniffer:icmp_tunnel`), and spanning-tree abuse
(`sniffer:stp_bpdu`) — over **both IPv4 and IPv6**.

## 12. Platform support

The sensor builds and runs on Linux (amd64 / arm64 / armv7 / armv6) and
macOS (amd64 / arm64). Every protocol handler, archetype, ATT&CK
tagging, storyline, anomaly detector, interactive shell engagement,
file canary (write/remove/rename/chmod), URL canary, DNS canary, and
outbound channel runs natively on both.

The Linux-only subsystems all need raw-L2/L3 kernel APIs that macOS
doesn't expose the same way. Each returns a clear error on non-Linux
with a workaround:

| Feature | Linux | macOS workaround |
|---|---|---|
| `arp_responder` | AF_PACKET ✓ | `ifconfig <iface> alias <ip>` per honeynet host — the kernel answers ARP for the alias |
| `icmp_responder` | AF_PACKET ✓ | Same `ifconfig alias` — the kernel answers ICMP echo natively |
| `lldp_responder` (LLDP/CDP advertise) | AF_PACKET ✓ | Unavailable; the rest of the deception still works |
| `profinet_responder` (PROFINET-DCP) | AF_PACKET ✓ | Unavailable; the rest of the deception still works |
| AF_PACKET sniffer (ARP + IPv4/IPv6 scan / tunnel detection) | ✓ | Unavailable; protocol-level brute-force / port-scan correlators still work |
| File canary OPEN events (read detection) | fanotify ✓ | Unavailable; fsnotify still catches write/remove/rename/chmod |
| TUN/utun adapter | TUN ✓ | Use `ifconfig <iface> alias <ip>` to attract L4 traffic for virtual hosts |
| Privilege drop | `setresuid` ✓ | `setuid` ✓ (saved-uid also dropped on darwin) |

For macOS deployments where the honeynet's L2/L3 presence matters
(typical: industrial-segment deception with the Moxa / SCALANCE / S7
archetypes), the recommended pattern is to run the sensor on a small
Linux box that already sees the segment, and use macOS workstations
as the SIEM / dashboard consumers via the outbound channels.

For macOS deployments where only the protocol handlers + archetype
deception matter (typical: dev/research workstation, cloud-instance
honeypot exposed via service mesh), the sensor is fully featured.

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Scanning produces no events — only `sensor:started`/`sensor:stopped` show | the listeners aren't on the ports you scanned | `example-FULL` / `example-LARGE` **remap** every service to high ports (20000+/10000+) so they run without root/conflicts, so a scan of 22/80/443 hits nothing. Scan the bound ports (`tarpit-honeypot show-config -c <cfg> \| grep -E 'id:\|bind:'` for the map), or run `example.yaml`, which binds real service ports. |
| `sensor stopped: listen 0.0.0.0:53: bind: permission denied` | privileged port, no caps | systemd unit has `AmbientCapabilities=CAP_NET_BIND_SERVICE` already; verify with `systemctl show -p CapabilityBoundingSet tarpit-honeypot`. For Docker, `--cap-add=NET_BIND_SERVICE`. |
| `sensor stopped: listen 0.0.0.0:53: bind: address already in use` | systemd-resolved owns :53 | Either disable systemd-resolved DNSStubListener (`/etc/systemd/resolved.conf`: `DNSStubListener=no`) or use a non-standard port and NAT. |
| Listener events fire but `correlate:brute_force` never does | per-rule dedup window covers the burst | Lower `dedup.default_window` or set `correlate.brute_force.window` shorter. |
| `arp_responder disabled: need CAP_NET_RAW` | running as a non-privileged user without the cap | Pair `User=tarpit` with `AmbientCapabilities=CAP_NET_RAW` in the unit. |
| `arp_responder disabled: needs AF_PACKET (linux-only)` | running on macOS | See §12 — use `ifconfig alias` per honeynet host or run the responder on a Linux gateway. |
| `lldp_responder disabled: needs AF_PACKET (linux-only)` | running on macOS | LLDP advertising is unavailable on macOS today; the rest of the deception still works. |
| TUN listener fails with `open /dev/net/tun: no such file` | running inside an unprivileged container | `docker run --device=/dev/net/tun --cap-add=NET_ADMIN ...` |
| `tunnet: TUN/utun adapter not implemented on darwin` | running on macOS | macOS supports utun but no native backend yet; use `ifconfig alias` per virtual host. |
| Prometheus `/metrics` returns 503 | UI started before sensor finished construction | wait a second after startup; the sensor lazily registers stats once it's fully up. |
| `validate-config` rejects `format: cef` on `sqlite` channel | structured-row sinks can't take text formats | Use the format on `stdout`/`jsonlog`/`webhook`/`smtp`/`syslog` instead. |
| `sensor.archetype "..." is not a known archetype` | typo / unsupported name | Run `tarpit-honeypot help archetypes` to see the full list (99 entries). |
| `ssh_interactive` engagements piling up | crypto/ssh handshakes are CPU-heavier than banner-grab | Set `max_concurrent: 16` (or lower) on the listener to cap parallel sessions. |

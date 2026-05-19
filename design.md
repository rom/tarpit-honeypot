# tarpit-honeypot — Design

Status: draft v0, agreed via interview 2026-05-19.
Scope: single-binary deception sensor with alerting, on-prem fleet-friendly,
closed source for now.

---

## 1. Goals

- **Tripwire**: detect unauthorized interaction with bait services, files,
  and tokens on internal networks where any interaction is suspicious.
- **Friction**: slow down opportunistic attackers via tarpit listeners,
  so that "scanning the subnet" actually costs them time.
- **Forensics**: produce enough metadata + payload + small packet captures
  to triage an event without needing a separate network tap.
- **Operability**: one static binary, YAML config, sane defaults, runs on
  everything from a Raspberry Pi to a Windows server, no internet egress
  required.

## 2. Non-goals (v1)

- Distributed/fleet collector with a hosted control plane. Sensors are
  standalone; they can forward to a remote sink, but the collector itself
  is a later phase.
- Plugin system or embedded scripting. Detectors and channels are
  built-in.
- Mac/Darwin support.
- High-interaction emulation. Banners and minimal handshakes only — no
  full shell, no full SCADA stack emulation.
- Active response (blocking, firewalling, retaliating). Detect + alert
  only.

## 3. Architecture

```
                   ┌─────────────────────────────────────────────┐
                   │                  sensor                      │
                   │                                              │
  TCP/UDP ports ──►│  listeners ──┐                               │
  ICS handshakes ─►│  protocols ──┤                               │
  ARP/multicast ──►│  L2 sniffer ─┼──► event bus ──► correlator ──┼──► event store (JSON log + SQLite + pcap ring)
  fs canaries ────►│  fsnotify  ──┤        │                       │
  DNS/URL tokens ─►│  HTTP rcvr ──┘        ▼                       │
                   │                  alert router ────────────────┼──► channels
                   │                                              │      • webhook
                   │  ┌─ config (YAML, hot reload) ─┐             │      • SMTP
                   │  ┌─ web UI (read-only, 127.0.0.1) ─┐         │      • syslog
                   │  ┌─ CLI ─┐                                   │      • SNMP trap
                   └─────────────────────────────────────────────┘      • Twilio
                                                                        • AWS SNS
                                                                        • HTTP-SMS
                                                                        • forward-to-peer
```

Single Go process, internal channels for the event bus. No external
queue/broker dependency.

## 4. Detection sources

1. **TCP/UDP listeners** on arbitrary configured ports.
2. **Protocol handlers** with minimal-but-credible handshakes:
   - IT: SSH, HTTP, HTTPS, Telnet, FTP, SMB, RDP, MySQL, Postgres, Redis,
     MongoDB, Elasticsearch.
   - ICS/IoT: Modbus TCP, IEC-104, OPC-UA, S7comm, BACnet, EtherNet/IP,
     MQTT, SNMP, NTP, ICMP echo, TFTP.
3. **L2 sniffer** for ARP requests, unsolicited mDNS/SSDP/LLMNR/NBT-NS,
   broadcast probes. Implemented via AF_PACKET on Linux and Npcap on
   Windows. (Closed-source license decision unblocks Npcap.)
4. **Filesystem canaries** via fsnotify (modify/delete/rename/create).
   Read-detection is best-effort: `fanotify` on Linux when running as
   root and kernel ≥ 5.x; documented gap on Windows v1.
5. **DNS/URL tokens**: tool ships an HTTP endpoint and a wildcard DNS
   responder so that planted URLs / hostnames trigger alerts when
   resolved or fetched.

## 5. Listener modes (per port)

Each TCP/UDP port in config has a `mode`:

- `drop` — accept and immediately close. Just records the connect event.
- `banner` — send a configured banner / minimal protocol handshake,
  accept a small bounded amount of client data, then close cleanly.
- `tarpit` — first-class. Sub-modes:
  - `sticky` — accept, send tiny TCP window, never advance. LaBrea-style.
  - `trickle` — send banner one byte every N seconds.
  - `keepalive` — accept, send periodic null bytes, never close.
  - Bounded by max-per-source connection count and max total tarpit
    connections so the sensor itself isn't DoS'd.

## 6. Aggregate detection (in-sensor correlator)

In-memory sliding-window state, persisted to SQLite on shutdown / SIGHUP.

- **Port scan**: `N` distinct destination ports from same source within
  window `W`. Emits a `port_scan` event with the port list and elevates
  severity above the per-port events.
- **Brute force**: `N` connection or auth-attempt events on the same
  port from the same source within window `W`.
- **LAN sweep / lateral movement**: same source touching `N` distinct
  destination IPs on the local segment within window `W`. Requires the
  L2 sniffer.

Aggregate rules emit *in addition to* per-event signals; the SIEM can
choose which to ingest.

## 7. Alert channels

Always-on local sinks:

- Append-only rotated JSON log (`events-YYYYMMDD-NN.jsonl`).
- Stdout (when run in foreground).

Configurable outbound sinks (each with its own dedup, rate-limit, and
severity filter):

- Webhook (HMAC-signed JSON body, configurable headers).
- SMTP (TLS).
- Syslog (RFC 5424, UDP/TCP/TLS).
- SNMP trap v2c / v3 (`gosnmp`).
- Twilio SMS.
- AWS SNS.
- Generic HTTP-SMS gateway (templated).
- Forward-to-peer (push events to another tarpit-honeypot acting as a
  collector — used in later phase for fleet aggregation).

### Air-gapped behavior

Local sinks (JSON, syslog to LAN host, SNMP trap to LAN host) must work
with no outbound network. Outbound channels:

- start in a "best-effort" state,
- queue alerts in a bounded on-disk buffer (capped, oldest-dropped),
- emit a self-event when the channel transitions degraded ↔ healthy,
- never block detection.

### Noise control

- Global + per-rule + per-channel **dedup window**: identical
  `(source, rule, target)` collapses to one event per window.
- Per-channel **token-bucket rate limits**.
- Global **allowlist** (IP/CIDR) and **denylist** with per-rule overrides.
  Allowlisted sources still log to the JSON sink but skip outbound
  channels by default.

## 8. Persistence

- JSON events log, rotated by size.
- Embedded **SQLite** index for queryable history (`list-events`, web UI).
- **Per-event mini-pcap**: ring directory, capped to N events per source,
  bounded total bytes. First M packets + first K bytes of payload per
  packet of the offending flow.
- Bounded disk budget (v1 default):

  | store      | default cap | rotation                |
  |------------|-------------|-------------------------|
  | JSON log   | 500 MB      | size-based, oldest pruned |
  | SQLite     | 500 MB      | row-count + vacuum       |
  | pcap ring  | 1 GB        | LRU eviction by event id |

  All overridable in YAML.

## 9. Configuration

Single YAML file. Hot-reload via SIGHUP or file-watch. `validate-config`
subcommand for offline validation. Sketch:

```yaml
sensor:
  name: ""                # blank = hostname
  data_dir: /var/lib/tarpit-honeypot
  disk:
    json_log_mb: 500
    sqlite_mb: 500
    pcap_mb: 1024
  privilege:
    drop_to_user: tarpit
    drop_to_group: tarpit
    keep_caps: [NET_BIND_SERVICE, NET_RAW]

listeners:
  - id: ssh-bait
    proto: tcp
    port: 22
    mode: banner
    handler: ssh
    banner:
      version: "SSH-2.0-OpenSSH_8.4p1 Debian-5"
    severity: high

  - id: telnet-tarpit
    proto: tcp
    port: 23
    mode: tarpit
    tarpit:
      strategy: sticky
      max_connections_per_source: 4

  - id: modbus
    proto: tcp
    port: 502
    mode: banner
    handler: modbus
    severity: critical

canaries:
  files:
    - path: /srv/share/passwords.xlsx
      severity: critical
    - path: C:\Users\Public\creds.docx
      severity: critical
  tokens:
    dns:
      zone: tokens.example.internal
    http:
      listen: 0.0.0.0:8080

sniffer:
  enabled: true
  interface: eth0
  detect:
    arp: true
    mdns: true
    llmnr: true
    nbt_ns: true

correlate:
  port_scan:    { distinct_ports: 5, window: 30s, severity_bump: +1 }
  brute_force:  { attempts: 10, window: 60s, severity_bump: +1 }
  lan_sweep:    { distinct_dst: 10, window: 60s, severity_bump: +1 }

dedup:
  default_window: 5m

allowlist:
  - 10.0.0.0/8       # mgmt VLAN
  - 192.168.99.5     # vuln scanner

channels:
  - id: ops-webhook
    type: webhook
    url: https://hooks.example.com/tarpit
    hmac_secret_env: TARPIT_WEBHOOK_SECRET
    min_severity: medium
    rate_limit: 60/m
  - id: oncall-sms
    type: twilio
    account_sid_env: TWILIO_SID
    auth_token_env: TWILIO_TOKEN
    from: "+15555550100"
    to: ["+15555550200"]
    min_severity: high
  - id: siem-syslog
    type: syslog
    proto: tcp+tls
    address: siem.example.internal:6514
    min_severity: low

routes:
  - match: { severity: ">=high" }
    channels: [ops-webhook, oncall-sms, siem-syslog]
  - match: { severity: "<high" }
    channels: [siem-syslog]

web_ui:
  enabled: true
  bind: 127.0.0.1:8443
  # required to allow non-loopback bind:
  # auth: { ... }
  # tls:  { ... }
```

## 10. Operations

**Process model**

- Static Go binary (cgo only on Linux pcap path; AF_PACKET path is pure
  Go and preferred where it suffices).
- Linux: granted `CAP_NET_BIND_SERVICE` + `CAP_NET_RAW`, then drops to
  unprivileged `tarpit` user.
- Windows: runs as a service under a constrained service account.
- systemd unit ships in the package; Windows service via `sc.exe`
  install helper inside the binary.

**CLI**

```
tarpit-honeypot run [-c config.yaml]
tarpit-honeypot validate-config -c config.yaml
tarpit-honeypot test-alert --channel ops-webhook --severity high
tarpit-honeypot list-events [--since 1h] [--source <ip>] [--rule <id>]
tarpit-honeypot install-service / uninstall-service     (Windows + systemd)
tarpit-honeypot version
```

**Signals**

- `SIGHUP` → reload config + flush correlator state to SQLite.
- `SIGUSR1` → rotate logs.
- `SIGTERM` → graceful drain of in-flight alerts (bounded grace period),
  flush state, exit.

**Web UI**

- Read-only event browser, live tail, pcap download per event.
- Defaults to `127.0.0.1` only.
- Refuses to start with a non-loopback bind unless both `auth` and
  `tls` blocks are configured.
- CSRF token on every form, rate-limited.

**HTTPS honeypot**

- Auto-generates a self-signed cert + key on first run, scoped to the
  configured hostname/SAN list, cached in `data_dir`. Regenerated on
  rotation.

**No NTP/quiet-hours/maintenance-window features in v1** (explicit user
decision). System clock trusted as-is.

## 11. Platforms & builds

- Linux amd64
- Linux arm64
- Linux armv6
- Linux armv7
- Windows amd64

Release artifacts: signed binaries + tarball per platform, internally
distributed (no public release page while closed-source).

## 12. Phasing

- **v0.1 — tripwire MVP**
  - YAML config + `validate-config` + `test-alert`
  - Low-interaction TCP/UDP listeners (drop / banner modes), no tarpit
    yet
  - JSON log + stdout sinks always-on
  - Webhook + SMTP + syslog outbound channels
  - Dedup + token-bucket rate-limit + allowlist
  - systemd unit + Linux amd64/arm64 build

- **v0.2 — bait + canaries + UI**
  - Banner catalog for SSH/HTTP/Telnet/FTP/SMB
  - Tarpit modes (sticky / trickle / keepalive) on TCP listeners
  - Filesystem canaries (fsnotify; fanotify when available)
  - Self-signed TLS for HTTPS honeypot
  - SQLite event index
  - Read-only loopback web UI
  - Per-event mini-pcap (AF_PACKET on Linux)
  - Port-scan + brute-force correlators

- **v0.3 — ICS + advanced channels + Windows**
  - Modbus, S7, IEC-104, OPC-UA, BACnet, EtherNet/IP, MQTT minimal
    handlers
  - Twilio + AWS SNS + HTTP-SMS + SNMP trap channels
  - GeoIP (user-supplied MaxMind .mmdb) + rDNS enrichment
  - Hot reload via SIGHUP + file-watch
  - Windows service install + Npcap pcap path
  - armv6 / armv7 builds

- **v0.4 — fleet & lateral**
  - Forward-to-peer collector sink
  - URL / DNS token canaries
  - ARP / multicast / mDNS / LLMNR / NBT-NS sniffer
  - LAN-sweep correlator
  - Air-gapped outbound queue with bounded on-disk buffer

## 13. Open risks

- **Fingerprintability.** Honeypots get fingerprinted (Shodan/Censys
  classify Conpot, Cowrie, etc.). Banners must be parameterizable and
  defaults must not be unique strings.
- **CGO drag.** libpcap pulls cgo into release builds. AF_PACKET-only
  on Linux avoids it; Windows always needs Npcap. Plan: AF_PACKET
  Linux, Npcap Windows, document the difference.
- **Honeyfile read events.** True read-detection on Linux requires
  `fanotify` + root; on Windows requires an ETW provider. v0.2 ships
  modify/delete/rename, v0.3+ adds fanotify, Windows read-detect TBD.
- **Self-DoS via tarpit.** Tarpit holds sockets open by design; needs
  bounded total connections, per-source caps, and circuit-breaker that
  trips back to `drop` mode under load.
- **Pcap on small sensors.** 1 GB ring on a Pi is reasonable but the
  default may need to scale down by platform.
- **Closed-source means no community review.** Plan internal threat
  model + dependency audit cadence.

## 14. Out of scope (will not be built, even later, unless re-scoped)

- macOS support
- Active blocking / firewall hooks / retaliation
- Plugin runtime / embedded scripting language
- Hosted SaaS control plane

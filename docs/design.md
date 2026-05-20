# tarpit-honeypot — Design

Status: living design document, tracks the shipped implementation.
Scope: single static Go binary — a **deception + detection** sensor for
internal / OT networks, on-prem and fleet-friendly, no internet egress
required. CGO-free; Linux (amd64/arm64/armv7/armv6) + macOS (amd64/arm64).

This document explains *why* the sensor is built the way it is and how
the pieces fit together. For the YAML schema see
[`config.md`](config.md); for the CLI see [`cli.md`](cli.md); for the
end-to-end operator guide see [`usage.md`](usage.md); for SIEM/channel
recipes see [`INTEGRATIONS.md`](INTEGRATIONS.md).

---

## 1. Goals

- **Tripwire.** Detect unauthorized interaction with bait services,
  files, and tokens on networks where *any* interaction is suspicious.
- **Deception.** Look like a real, fingerprint-consistent host (or a
  whole network of them) so a scanner can't trivially classify the
  sensor as a honeypot, and so an attacker spends real effort.
- **Friction.** Waste opportunistic attacker time with tarpits and
  emulate-then-tarpit endpoints.
- **Forensics.** Produce structured, ATT&CK/D3FEND-tagged events plus
  per-connection pcaps and harvested payloads — enough to triage without
  a separate tap.
- **Operability.** One static binary, YAML config, sane defaults, runs
  from a Raspberry Pi to a server, no egress required.
- **Be a safe target.** The sensor is itself exposed, so it is hardened
  (input bounds-checking + output sanitization, anti-amplification,
  privilege drop, optional seccomp + Landlock self-confinement) and is
  never a reflection/amplification primitive or actually exploitable.

## 2. Non-goals

- Distributed collector with a hosted control plane. Sensors are
  standalone; they forward to remote sinks, but the collector tier is
  not built.
- Plugin system / embedded scripting. Handlers and channels are built-in.
- Active response (blocking, firewalling, retaliating). Detect, deceive,
  delay, and alert only.
- *Real* code execution. The interactive shells, PLC/CLI consoles, and
  "vulnerable" services are canned-response emulations — they capture and
  classify, they never execute attacker input or become exploitable.

## 3. Architecture

Single Go process; internal channels for the event bus; per-sink worker
goroutines with bounded queues. No external broker.

```
                     ┌──────────────────────────── sensor ────────────────────────────┐
  TCP/UDP connects ─►│ listeners ─► handlers (76: IT/OT/mgmt/small-svc/dns) ─┐         │
  ICMP / ARP ───────►│ AF_PACKET responders + ARP-scan sniffer ─────────────┤         │
  fs/url/dns tokens ►│ canaries ────────────────────────────────────────────┤         │
                     │                                                       ▼         │
                     │  per-conn capture + payload harvest        ┌──► enrich (geoip/rdns)
                     │                                            event bus              │
                     │                                              │  ├─ ATT&CK + D3FEND tag
                     │                                              │  ├─ device learning
                     │                                              │  ├─ scan analysis
                     │                                              ▼  └─ correlator + storyline
                     │  config (YAML, hot reload) · web UI · CLI    router ──────────────┼─► channels
                     └──────────────────────────────────────────────────────────────────┘
   state in data_dir: SQLite · rotated JSONL · pcaps · payloads · TLS certs · devices.json · deployment-id
```

Event flow (sensor bus loop, serialized): listener/responder/canary emits
→ enrich → ATT&CK/D3FEND tag → device learning → payload harvest →
scan analysis → correlator + storyline → router.Dispatch → sinks.

## 4. Deception layer

What makes the sensor *look real*:

- **Archetypes** (`internal/archetype`, 43 profiles). `sensor.archetype`
  (overridable per-listener and per-honeynet-host) pins every
  banner-aware handler (SSH/HTTP(S)/FTP/Telnet/SMTP/MySQL), SNMP MIB-2
  identity, MAC OUI, CLI prompt, **TLS posture** (old boxes negotiate
  old TLS + weak ciphers), **ICMP TTL personality** (255 OT / 128
  Windows / 64 Linux-BSD), and web-UI body to a stock install. Ship
  list spans Linux distros, *BSD, Windows client+server, **Active
  Directory DC**, **Cisco IOS**, Moxa, and Siemens SCALANCE / S7.
- **Counter-fingerprinting** (`internal/identity`). Every otherwise-fixed
  string (SSH version, HTTP Server, MySQL build, SMB challenge/session
  key, VNC challenge, EtherNet/IP serial, SMTP hostname) is derived from
  `sensor.deployment_id`, so two sensors present distinct fingerprints to
  Shodan-class scanners. Plus per-reply `jitter` and HTTPS cert rotation.
- **Vulnerable-banner + fake-patch-level emulation** (`sensor.vuln_emulation`).
  Banner-aware handlers can advertise a deliberately-unpatched version
  (e.g. Apache 2.4.49 / OpenSSH 7.2 / vsFTPd 2.3.4) and surface a fake
  patch level so a version scanner records an exploitable box. Detection
  of the follow-up exploit runs regardless; the service is never
  exploitable.
- **Command emulation** (`internal/shell`). After a fake login, SSH
  (`ssh_interactive`, full `crypto/ssh` server with a persistent host
  key) and Telnet drop into a per-family canned-response console:
  POSIX shells, **PowerShell** (incl. AD cmdlets), **Windows cmd.exe**,
  **Cisco IOS**, **Moxa** / **SCALANCE** switch CLIs, and the **Siemens
  S7 PLC** console. Every typed line is captured + TTP-scanned.
- **Honeynets** (`internal/honeynet`). Zero-to-many virtual networks of
  virtual hosts; each host has its own derived Identity (distinct
  banners/serials) and answers on its own IP/MAC. Optional Linux
  AF_PACKET ARP / ICMP / LLDP+CDP responders make the network
  discoverable; an optional TUN device answers ICMP + TCP-RST for
  unbound ports.

## 5. Detection layer

What turns interaction into signal:

- **76 protocol handlers** (1 generic + 52 TCP + 23 UDP; IT, remote-access
  / OOB-management personas, ICS/OT, discovery/UDP, a resolving DNS
  server, RFC small services). Each captures the application-layer
  exchange (credentials, requested objects, fingerprints) and replies
  credibly. See README "Protocol handlers in detail".
- **Protocol-anomaly detection** (`event.anomalies`). Per-handler markers
  for malformed / smuggled / hostile input (non-printable SSH banners,
  unknown HTTP methods + suspicious URIs, DNS tunneling shapes, abnormal
  ICMP payloads, UDP amplifier probes, shell TTPs).
- **Client fingerprinting** (`internal/fingerprint`, `internal/toolfp`):
  JA3 + JA4 (TLS), JA4H (HTTP), HASSH (SSH), plus tool/scanner
  identification (nmap/masscan/sqlmap/…/Mirai) and a
  human-vs-automation verdict.
- **CVE exploit-attempt recognition** (`internal/cve`). A curated catalog
  of high-signal exploit signatures (Log4Shell, Shellshock, Spring4Shell,
  ProxyLogon/Shell, FortiOS/Pulse/Citrix traversals, Apache 2.4.49,
  EternalBlue/SMBGhost, BlueKeep, …) → CVSS-scaled `cve:<id>` events.
- **Scan analysis** (`internal/scananalysis`). Per-source nmap profiling:
  timing template (`-T0`..`-T5`), `-A`/`-O`/`-sV`, NSE + service-probe
  matching, connect scans → `scananalysis:profile`. Half-open / frag /
  decoy scans are honestly scoped to the AF_PACKET layer.
- **In-sensor correlators** (`internal/correlate`): port-scan,
  brute-force (with extracted credential pairs), slow-scan (hour-scale),
  ICMP ping-sweep.
- **Attack-storyline correlator** (`storyline:multi_stage`). Joins a
  source's events across ATT&CK tactics; tracks CVE exploits / captured
  malware / tools, flags `objective_reached`, and scales severity to
  Critical for a confirmed multi-stage intrusion.
- **Device learning** (`internal/devices`). Learns hosts from DHCP, the
  ARP sniffer, and connection source IPs; raises `device:new` for
  never-before-seen, non-allow-listed hosts.
- **Malware capture + payload harvesting** (`internal/payload`).
  Classifies captured bytes (ELF/PE/Mach-O/archive/script + x86
  shellcode heuristics), decodes base64 droppers, harvests ingress URLs,
  persists artifacts to `<data_dir>/payloads/` → `malware:capture`.
- **Canary tokens**: filesystem (fsnotify + Linux fanotify read-detect),
  URL, and DNS.
- **ATT&CK + D3FEND tagging** (`internal/mitre`). Every event carries
  `mitre_techniques`, `mitre_tactics`, and the `mitre_defenses` (D3FEND
  countermeasures) that answer them.

## 6. Listener modes

Per listener `mode`:

- `drop` — accept + immediately close (records the connect).
- `banner` — run the configured `handler:` and capture both sides.
- `tarpit` — hold the connection: `sticky` (never read/write),
  `trickle` (one byte every interval), `keepalive` (slow NUL bytes),
  bounded by `max_per_source` + `max_total`. `tarpit.emulate: true` runs
  the handler first (real banner + captured request) then tarpits the
  same connection — any emulator becomes a tarpit.

## 7. Event pipeline, enrichment, routing, channels

- **Enrichment**: optional GeoIP (operator MaxMind .mmdb) + bounded rDNS,
  added to source-IP meta before correlation.
- **Output formats** per channel: `json` (default), `cef` (ArcSight),
  `leef` (QRadar), `ocsf` (cloud SIEMs).
- **Local sinks** always receive: `stdout`, `jsonlog` (rotated), `sqlite`.
- **Outbound channels** (allowlist + dedup + rate-limit + min-severity
  gated, bounded retry queue with backoff): `webhook` (HMAC-SHA256),
  `smtp` (STARTTLS), `syslog` (RFC 5424), `twilio`, `sns` (hand-rolled
  Sigv4), `snmptrap`, `mqtt`.
- **Routing**: severity-match expressions + meta match (`honeynet`,
  `honeynet_os`, `rule_id`).
- **Defensive output handling** (`internal/safe`): every attacker-supplied
  string is bounds-checked on input and sanitized before any log / SIEM /
  email path (control-byte escaping, RLO/ANSI/CRLF neutralization).

## 8. Persistence

All durable state under `sensor.data_dir`: SQLite index, rotated JSONL,
per-event pcaps (synthesized libpcap, no raw sockets), harvested
payloads, cached TLS certs, `devices.json`, `.deployment-id`. Size caps +
time-based retention (`disk.retention_days`) prune each store.

## 9. Self-confinement & hardening

Defense-in-depth, because the sensor is a target. Layered, all optional /
composable:

1. **Privilege drop** (`internal/privdrop`). Bind privileged ports / open
   AF_PACKET with `CAP_NET_BIND_SERVICE`+`CAP_NET_RAW`, then
   `setresuid/gid` to an unprivileged user (refuses uid 0).
2. **seccomp** (`sensor.sandbox.seccomp`, `internal/sandbox`). A pure-Go
   seccomp-bpf denylist (returns EPERM) for syscalls a connection
   honeypot never makes — execve/execveat, ptrace, process_vm_*, module
   load/unload, mount, kexec, pivot_root/chroot, setns/unshare, reboot,
   swap, bpf, perf_event_open. Default-allow so it can't crash the Go
   runtime; the headline guarantee is "a parser 0-day can't spawn a
   shell".
3. **Landlock** (`sensor.sandbox.landlock`, Linux 5.13+). Filesystem
   becomes read-only everywhere, writable only under `data_dir` (+
   configured `write_paths`). ABI-version-aware, best-effort.
4. **AppArmor** (`packaging/apparmor/`) and **SELinux**
   (`packaging/selinux/`) profiles for operators who enforce a host LSM —
   same intent as the in-process sandbox, enforced by the kernel from
   outside the process.
5. **systemd unit** (`packaging/systemd/`) with `NoNewPrivileges`,
   `ProtectSystem=strict`, `RestrictNamespaces`, capability bounding set,
   etc.

Anti-amplification is a hard rule across UDP handlers: NTP mode-7 silent,
chargen/echo single bounded reply, no unbounded DNS answers.

## 10. Configuration

Single YAML file, hot-reloaded on `SIGHUP` (channels / routes / allowlist
/ dedup / correlator / canary lists swap live; listeners restart
individually). `conf.d/*.yaml` deep-merge; `--set key=val` + `TARPIT_*`
env overrides; `validate-config` (with `--diff`) for offline checks. The
annotated reference is [`config.md`](config.md) + the `configs/*.example*`
files.

## 11. CLI & signals

`run`, `validate-config`, `show-config`, `test-alert`, `list-events`,
`export-pcap`, `list-honeynets`, `list-devices`, `gen-token`, `init`,
`completion`, `help`, `version`. Signals: `SIGHUP` reload, `SIGTERM`
graceful drain (`shutdown.drain_timeout`). See [`cli.md`](cli.md).

## 12. Platforms & builds

`make build` (native), `make cross` (linux/{amd64,arm64,armv7,armv6} +
darwin/{amd64,arm64}). CGO never required (~14 MB static binary, mostly
the pure-Go SQLite engine). The Linux-kernel features (AF_PACKET
responders/sniffer, fanotify read-detect, TUN, seccomp/Landlock,
`setresuid`) degrade to clean errors on macOS.

## 13. Phases delivered

- **v0.1–v0.4** — tripwire MVP → bait/canaries/UI → ICS + advanced
  channels + enrichment → fleet sinks + sniffer + correlators.
- **v1.0–v1.5** — counter-fingerprinting + deployment-id; honeynets (L2
  ARP, L3 ICMP, TUN, routing); SIEM formats (CEF/LEEF/OCSF) + GeoIP/rDNS;
  Prometheus metrics; SNMP/LDAP/DCE-RPC topology exposure.
- **v1.6–v1.10** — CLI ergonomics + fuzz/test infra; 10+ new protocols +
  MQTT sink + .deb/.rpm; archetypes; ATT&CK + storyline + `internal/safe`
  hardening; interactive shell engagement + `ssh_interactive` + LLDP/CDP
  responder + multi-page archetype web UI.
- **v1.11** — 15 protocol emulators (mgmt/remote-access) + VNC variety;
  Windows + SCALANCE-S archetypes (TLS posture, ICMP TTL); tool
  fingerprinting + human-vs-automation; abnormal ICMP/DNS detection;
  device-learning registry; default-creds + fake-files + `ftp_files`;
  ICMP-sweep correlation; macOS first-class.
- **v1.12** — scan analysis; RFC small services (TCP+UDP); resolving DNS;
  emulate-then-tarpit; web UI topology + docs tabs.
- **current** — CVE catalog + vulnerable-banner emulation; ATT&CK→D3FEND
  mapping; Active Directory + Cisco archetypes; PowerShell / cmd / Cisco
  / PLC command emulation; malware/shellcode/payload harvesting;
  storyline CVE/malware/objective awareness; web UI hosts + alerting
  tabs; seccomp + Landlock self-confinement + AppArmor/SELinux policies.

## 14. Open risks

- **Fingerprintability.** Mitigated by per-deployment identity + archetype
  consistency + jitter + cert rotation, but a determined classifier may
  still cluster behaviors; archetypes need ongoing tuning.
- **Self-DoS via tarpit.** Bounded by per-source + total caps and
  per-listener accept caps; sticky mode is cheapest.
- **Vulnerable-banner emulation is loud by design.** It advertises
  exploitable versions; gated off by default and never actually
  exploitable, but operators should scope where they enable it.
- **seccomp/Landlock are best-effort.** Old kernels / restrictive
  containers may not apply them; the sensor logs and runs on, so confirm
  enforcement (`journalctl`) where it matters.
- **Detection vs. capture gaps.** Half-open/fragmented/decoy scans and
  raw ICMP need the AF_PACKET layer; the connection layer honestly marks
  these as needing packet capture rather than guessing.

## 15. Out of scope (unless re-scoped)

- Active blocking / firewall hooks / retaliation.
- Plugin runtime / embedded scripting.
- Hosted SaaS control plane.
- Real code execution in any emulated service.

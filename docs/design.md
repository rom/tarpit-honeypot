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
- General plugin runtime / pluggable channels. Handlers and channels are
  built-in. (The `lua` handler is a deliberate, narrow exception: a
  *sandboxed* per-service response-scripting VM — no io/os, bounded — not
  a general plugin system that can load Go code or new channels.)
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
  TCP/UDP connects ─►│ listeners ─► handlers (81: IT/OT/mgmt/small-svc/dns) ─┐         │
  ICMP/ARP/L2/L3 ───►│ AF_PACKET responders + ARP/TCP-scan + PROFINET-DCP ───┤         │
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
  S7 PLC** console. Every typed line is captured + TTP-scanned. Sessions
  can be recorded as replayable asciinema casts
  (`sensor.session_recording`, `internal/sessionrec`).
- **Lua dynamic responses** (`handler: lua`, `internal/luaengine`). An
  operator Lua script drives a service in a sandboxed pure-Go VM (no
  io/os, context deadline + read/write/sleep budgets). API: per-session
  state, per-source persistent `host` state, `personality()` (stable
  hostname/version/firmware per source), deterministic `rng` (seeded from
  `deployment_id`), `sleep` timers, `log`/`flag`/`meta`. This is the
  mechanism for deep app emulation and rotating dynamic banners without
  recompiling.
- **Honeynets** (`internal/honeynet`). Zero-to-many virtual networks of
  virtual hosts; each host has its own derived Identity (distinct
  banners/serials) and answers on its own IP/MAC. Optional Linux
  AF_PACKET ARP / ICMP / LLDP+CDP responders make the network
  discoverable; a **PROFINET-DCP** responder answers DCP Identify (L2,
  EtherType 0x8892) for industrial hosts so a PROFINET scan enumerates the
  cell; an optional TUN device answers ICMP + TCP-RST for unbound ports.
- **TCP/IP stack personality.** The TUN responder stamps each virtual
  host's synthesized ICMP echo replies + closed-port RSTs with the initial
  IP TTL of its archetype (255 OT / 128 Windows / 64 Linux-BSD) instead of
  echoing the prober's, so `nmap -O` + traceroute hop-distance are
  consistent with the claimed OS. Open-port SYN-ACKs still come from the
  host kernel (a full userspace TCP/IP stack is out of scope).

## 5. Detection layer

What turns interaction into signal:

- **81 protocol handlers** (1 generic + 57 TCP + 23 UDP; IT, remote-access
  / OOB-management personas, ICS/OT, discovery/UDP, a resolving DNS
  server, RFC small services, plus the scriptable `lua` handler). Each
  captures the application-layer exchange (credentials, requested objects,
  fingerprints) and replies credibly. ICS/OT coverage includes Modbus, S7
  + **S7comm-Plus**, IEC-104, **DNP3**, EtherNet/IP, **GE-SRTP**,
  **CODESYS**, OPC-UA, BACnet (incl. WriteProperty), MELSEC, FINS. See
  README "Protocol handlers in detail".
- **Protocol-anomaly detection** (`event.anomalies`). Per-handler markers
  for malformed / smuggled / hostile input (non-printable SSH banners,
  unknown HTTP methods + suspicious URIs, DNS tunneling shapes, abnormal
  ICMP payloads, UDP amplifier probes, shell TTPs).
- **TLS / client fingerprinting** (`internal/fingerprint`, `internal/toolfp`):
  JA3 + JA4 (client TLS ClientHello), **JA3S** (server-side TLS — the
  ServerHello we send back; the `(ja3, ja3s)` pair is the threat-intel
  tuple), JA4H (HTTP), HASSH (SSH), plus tool/scanner identification
  (nmap/masscan/sqlmap/…/Mirai) and a human-vs-automation verdict.
- **CVE exploit-attempt recognition** (`internal/cve`). A curated catalog
  of high-signal exploit signatures (Log4Shell, Shellshock, Spring4Shell,
  ProxyLogon/Shell, FortiOS/Pulse/Citrix traversals, Apache 2.4.49,
  EternalBlue via the smb handler, BlueKeep via the rdp handler, …) →
  CVSS-scaled `cve:<id>` events. Only substring-detectable signatures are
  catalogued (TLS-record-layer CVEs like Heartbleed are out of scope
  since the https handler sees the decrypted stream).
- **Scan analysis** (`internal/scananalysis`). Per-source nmap profiling:
  timing template (`-T0`..`-T5`), `-A`/`-O`/`-sV`, NSE + service-probe
  matching, connect scans → `scananalysis:profile`.
- **Packet-capture scan-detection layer** (`internal/sniffer`, opt-in,
  Linux AF_PACKET). A second socket classifies inbound IPv4 TCP by flags
  and reports scans that never establish a session — **NULL/FIN/Xmas**
  stealth probes, **SYN/ACK** scans (by volume), and fragmented probes —
  emitting `sniffer:tcp_{syn,null,fin,xmas,ack}_scan` / `sniffer:ip_fragmented`.
  This is the closed-port / dropped-stealth visibility the connection
  layer can't have. (Decoy detection is still out of scope.)
- **In-sensor correlators** (`internal/correlate`): port-scan,
  brute-force (with extracted credential pairs), slow-scan (hour-scale),
  ICMP ping-sweep. The PROFINET-DCP responder also emits a detection
  event (`honeynet:profinet_dcp_identify`, ATT&CK T0846) for every DCP
  Identify it observes — ICS reconnaissance on the segment.
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
payloads, session-recording casts (`sessions/`), cached TLS certs,
`devices.json`, `.deployment-id`, and the windowed-correlator checkpoint
(`correlate-state.json`, written every 60s + on shutdown, restored on
startup and carried across hot reload so slow-scan survives a restart).
Size caps + time-based retention (`disk.retention_days`) prune each store.

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
   runtime; installed with TSYNC so it covers every thread. The headline
   guarantee is "a parser 0-day can't spawn a shell".
3. **Landlock** (`sensor.sandbox.landlock`, Linux 5.13+). Restricts the
   filesystem to read-only except `data_dir` (+ configured `write_paths`).
   ABI-version-aware. Best-effort: Landlock has no TSYNC, so it confines
   the calling thread + threads created afterward but not the Go runtime's
   pre-existing threads — use AppArmor / SELinux / systemd for
   kernel-enforced full-process FS confinement.
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
- **v1.12** (cont.) — CVE catalog + vulnerable-banner emulation;
  ATT&CK→D3FEND mapping; Active Directory + Cisco archetypes; PowerShell /
  cmd / Cisco / PLC command emulation; malware/shellcode/payload
  harvesting; storyline CVE/malware/objective awareness; web UI hosts +
  alerting tabs; seccomp + Landlock self-confinement + AppArmor/SELinux;
  topology-coherent DNS (SRV/PTR/HINFO/LOC/SOA); web UI sortable/filterable
  + errors view.
- **v1.13** — Lua dynamic-response engine (`handler: lua`); attacker
  session recording (asciinema casts); persistent + reload-durable
  correlator state.
- **current (v1.14)** — more ICS/OT protocols (DNP3, S7comm-Plus, GE-SRTP,
  CODESYS, BACnet WriteProperty); **JA3S** server-side TLS fingerprint;
  packet-capture TCP scan-detection layer (NULL/FIN/Xmas/SYN/ACK/frag);
  TCP/IP stack personality (per-archetype TTL on TUN responses);
  **PROFINET-DCP** L2 responder + ICS-discovery detection.

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
- **Detection vs. capture gaps.** Half-open/fragmented/stealth scans are
  now caught by the opt-in AF_PACKET packet-capture layer (`sniffer.tcp_scan`),
  which needs CAP_NET_RAW; **decoy** scans remain out of scope (one real
  source among many spoofed is hard to disambiguate passively). Without the
  sniffer enabled, the connection layer still only sees scans that reach a
  listener.

## 15. Out of scope (unless re-scoped)

- Active blocking / firewall hooks / retaliation.
- General plugin runtime / pluggable channels (the sandboxed `lua`
  response-scripting handler is the only scripting surface).
- Hosted SaaS control plane.
- Real code execution in any emulated service.
- **Full userspace TCP/IP stack.** The TUN responder controls TTL on
  synthesized RST/ICMP, but open-port SYN-ACK quirks (window/options/ISN)
  come from the host kernel — a complete `nmap -O` match would need a
  userspace stack.
- **OPC-DA (classic, DCOM/MSRPC).** OPC-UA is supported (`opcua`); the
  legacy DCOM-based OPC-DA is not. A future minimal approach would extend
  the `dcerpc` endpoint-mapper to advertise the OPCEnum interface UUID
  rather than implement the full DCOM marshaling.
- **Decoy-scan attribution.** See "Open risks".

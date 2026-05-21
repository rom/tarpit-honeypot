# tarpit-honeypot

A single static Go binary that runs a deception **and** detection sensor:
protocol-shaped honeypots on configurable ports, OS-archetype-aware
banners and CLI emulation, interactive SSH/Telnet engagement that captures
every command an attacker types, MITRE ATT&CK-tagged events, cross-
protocol attack-storyline correlation, protocol-anomaly detection, file
/ URL / DNS canary tokens, port-scan / brute-force / slow-scan
detectors, per-event pcap capture, hostile-input hardening + output
sanitization, and pluggable outbound alerting.

CGO-free. Static builds for `linux/amd64`, `linux/arm64`, `linux/armv7`,
`linux/armv6`, `darwin/amd64`, `darwin/arm64`.

See [`docs/design.md`](docs/design.md) for the architecture + design
rationale covering the current implementation.

## Features at a glance

- **TCP honeypots** in three modes: `drop`, `banner` (protocol handler),
  or `tarpit` (sticky / trickle / keepalive). `tarpit.emulate: true`
  runs the listener's protocol handler first (real banner + captured
  request), then tarpits the same connection — any emulator becomes a
  tarpit.
- **UDP honeypots** in `drop` or `banner` mode with protocol handlers.
- **81 built-in protocol handlers** (1 generic + 57 TCP + 23 UDP), including a scriptable `lua` handler for dynamic responses. See [Protocol handlers in detail](#protocol-handlers-in-detail) for what each one captures and replies with.
  - **Generic**: `raw`
  - **TCP / IT**: `ssh`, `ssh_interactive`, `http`, `https`, `telnet`, `ftp`, `ftp_files`, `smb`, `vnc`, `smtp_recv`, `rdp`, `winrm`, `dcerpc`, `ldap`, `kerberos`, `postgres`, `mysql`, `mssql`, `oracle_tns`, `redis`, `syslog_tcp`, `rtsp`, `dockerapi`, `melsec`, `xmpp`, `amqp`, `ipp`
  - **TCP / remote-access + mgmt**: `teamviewer`, `anydesk`, `openvpn`, `citrix_ica`, `intel_amt`, `ilo`, `idrac`, `esxi`, `fortinet`, `pulse`, `citrix_gateway`, `horizon`, `moxa_mgmt`
  - **TCP / ICS**: `modbus`, `s7`, `s7comm_plus`, `iec104`, `mqtt`, `opcua`, `ethernetip`, `dnp3`, `ge_srtp`, `codesys`, `atg` (Veeder-Root TLS-350), `fox` (Niagara/Tridium), `hartip`, `pcworx`
  - **UDP**: `raw`, `snmp`, `ntp`, `bacnet`, `tftp`, `ipmi`, `syslog_udp`, `radius`, `sip`, `ssdp`, `cldap`, `llmnr`, `nbns`, `fins`, `coap`, `knx`, `dhcp`, `dns`
  - **Small services (TCP + UDP)**: `echo`, `discard`, `daytime`, `qotd`, `chargen`, `time` — RFC 862-868 / 1340. `chargen`/`echo` reply with a single bounded datagram and never amplify (reflection-safe).
  - **DNS resolver** (`dns`, UDP): answers `A`/`AAAA`/`MX`/`TXT`/`NS`/`CNAME` with deterministic-per-deployment fake records; every query runs through tunneling/exfil detection.
  - **ICMP** (L3, Linux AF_PACKET responder): virtual hosts answer echo / timestamp / address-mask requests with the archetype's TTL personality; `internal/icmp` builds the full message family (Dest-Unreachable, Frag-Needed/PMTUD, Time-Exceeded, Redirect, Param-Problem, IPv6 NDP) and `internal/icmp.Anomalies` flags tunneling / oversize / teardrop-overlap evasion.
- **58 OS / device archetypes**: set `sensor.archetype: "debian 12"` (or
  `listener.archetype`, or per-honeynet-host `archetype`) and every
  banner-aware handler (SSH / HTTP(S) / FTP / Telnet / SMTP / MySQL),
  SNMP MIB-2 (sysDescr / sysObjectID / ifTable), MAC OUI, CLI prompt,
  TLS posture, ICMP TTL personality, and Web UI body report values
  consistent with a stock install of that OS. Spans Linux distros, *BSD,
  Windows client + server, Active Directory, Cisco Catalyst (IOS / IOS-XE),
  MikroTik RouterOS, Teltonika RUT240, Moxa / Siemens OT gear, more PLC
  vendors (Allen-Bradley / Schneider / Omron), firewalls (pfSense /
  FortiGate), NAS (Synology / QNAP), IP cameras (Hikvision / Axis), a
  network printer, and a VoIP PBX — see the full
  [OS / device archetypes](#os--device-archetypes) table.
  `tarpit-honeypot help archetypes` lists them all.
- **CVE emulation + exploit-attempt capture** (`internal/cve`): the
  http/https/appliance handlers recognize known exploit signatures
  (Log4Shell, Shellshock, Spring4Shell, ProxyLogon/Shell, FortiOS /
  Pulse / Citrix traversals, Apache 2.4.49, EternalBlue, …) and emit a
  CVSS-scaled `cve:<id>` event without ever being exploitable. With
  `sensor.vuln_emulation` (per-listener overridable) a banner-aware
  handler advertises the archetype's deliberately-unpatched version +
  **fake patch level** so a version scanner records an exploitable box.
- **Command emulation per device family**: believable POSIX shells, plus
  **PowerShell** (incl. Active Directory cmdlets), **Windows cmd.exe**,
  **Cisco IOS** (enable + show version/run/vlan/cdp), the **Moxa** and
  **SCALANCE** switch CLIs, and the **Siemens S7 PLC** console — routed
  by the archetype. The shell anomaly scanner flags Linux *and*
  Windows/PowerShell TTPs (download cradles, encoded commands,
  credential dumping, AD recon, Defender/AMSI tamper, persistence).
- **Malware capture + shellcode extraction + payload harvesting**
  (`internal/payload`): classifies captured bytes (ELF / PE / Mach-O /
  archive / script magic + x86 shellcode heuristics), decodes
  base64-wrapped droppers, harvests ingress URLs, and persists artifacts
  to `<data_dir>/payloads/` (size-capped). Emits `malware:capture`.
- **Lua dynamic-response engine** (`handler: lua`, `internal/luaengine`):
  drive a service from an operator Lua script in a sandboxed pure-Go VM
  (no io/os, context deadline + read/write/sleep budgets). Scripts get
  per-session state, per-source persistent `host` state, `personality()`
  (stable hostname/version/firmware per source), deterministic `rng`
  (seeded from `deployment_id`), `sleep` timers, a `time` clock
  (`now`/`ms`/`utc`/`uptime` — for live timestamps, TTL, uptime counters),
  and `log`/`flag`/`meta` — for deeper app emulation + rotating dynamic
  banners. Shipped scripts in [`configs/scripts/`](configs/scripts/):
  `iot-login`, `redis-mini`, `memcached-stats`, `smtp-greeting`,
  `telnet-switch`, `pop3`, `finger`, `http-status`, `irc` (botnet-C2
  capture), `whois`, `ident`, `rsync` (counters, live timestamps, rotating
  versions, per-source state, engagement + capture).
- **Full fake-vulnerable web application** (`webapp: true` on an
  `http`/`https` listener): a believable multi-page PHP/MySQL-flavored app
  (login, search, product, file download, JSON API, plus the juicy paths
  scanners probe — `/.env`, `/.git/config`, `/config.php.bak`, `robots.txt`)
  whose endpoints LOOK exploitable so an attacker engages and reveals TTPs.
  Detects — never executes — SQLi / XSS / LFI / RFI / SSRF / command
  injection / SSTI / Log4Shell / XXE / deserialization, flagging each as a
  `webapp:<class>` anomaly. Active deception: LFI toward `/etc/passwd` and
  `/.env` return fake "loot" (decoy creds) to draw the attacker deeper;
  reflected input is always HTML-escaped so the honeypot is never itself a
  real XSS vector.
- **Declarative fake-protocol routing** (`handler: scripted`): stand up a
  believable custom TCP service entirely in YAML — no Lua. An optional
  on-connect `greeting`, then top-down `rules` that match each client
  message by `prefix` / `contains` / `regex` (RE2) / `hex_prefix` / `any`
  and write a `respond` (text-escapes or `respond_hex` for binary), with
  optional per-rule `anomaly` flag and `close`. Bounded rounds + per-reply
  size cap; TCP-only so it can't be a spoofed-source amplifier. Validated
  at config-load (regex compiles, hex decodes).
- **Attacker session recording** (`sensor.session_recording`): interactive
  `telnet` / `ssh_interactive` sessions are recorded as asciinema v2 casts
  under `<data_dir>/sessions/` (replayable with timing); the cast filename
  lands in event meta. Per-cast + total-size capped.
- **Persistent correlator state**: the windowed detectors (port-scan /
  brute-force / slow-scan / icmp-sweep) checkpoint to
  `<data_dir>/correlate-state.json` and restore on startup + carry across
  hot reload, so long-window detection (slow-scan) survives a restart.
- **Archetype consistency**: each archetype keeps its firmware era,
  banners, SNMP identity, MAC OUI, login pages, ICMP TTL, **and TLS
  posture** aligned — e.g. a "Windows Server 2008" archetype caps TLS
  at 1.0 with legacy CBC ciphers and an IIS 7.0 splash, so a scanner
  can't catch a TLS-1.3-with-modern-ciphers tell on an ancient box.
- **Switch archetypes expose OT topology**: SCALANCE-class archetypes
  serve MRP rings, a PROFINET device tree, VLANs, connected HMIs, and
  LLDP neighbors from their web UI (`/topology`, `/status`, `/vlan`, …)
  + advertise LLDP/CDP on the segment.
- **Tool fingerprinting + human-vs-automation**: the HTTP handler
  identifies the scanner/tool (nmap, masscan, sqlmap, nikto, hydra,
  nuclei, metasploit, gobuster, zgrab, censys, curl/wget/python, Mirai
  + router-exploit probe paths) and tags each request `automation` vs
  browser-like. Surfaced as `meta.tools` / `meta.automation` +
  `tool:<name>` / `automation-client` anomalies.
- **Interactive CLI shell engagement**: after a fake "Login incorrect"
  the attacker is dropped into the archetype's shell (telnet) or a
  full `crypto/ssh` session (`ssh_interactive`). Every typed command
  is captured and the new `internal/shell` anomaly scanner flags 14
  ATT&CK-aligned TTPs (reverse shells, ingress tool transfer, SSH-key
  persistence, cron/systemd persistence, /etc/shadow reads, SUID/sudo
  abuse, history/log cleaning, crypto-miners, network recon, firewall
  disable, base64-encoded payloads). `ssh_interactive` persists an
  ed25519 host key so its fingerprint is stable across restarts.
- **Multi-page archetype web UI**: HTTP handler routes on method +
  path. `GET /` serves the archetype's index (Moxa / SCALANCE / S7
  device summaries); GETs on login-shaped paths serve a form; POSTs
  parse the form body (6 alias names each for user/pass), capture
  credentials, and emit `http-login-attempt`.
- **Client + server TLS fingerprinting**:
  - **JA3** + **JA4** from the TLS ClientHello (HTTPS handler).
  - **JA3S** (server-side TLS fingerprint) from the ServerHello we send
    back — the `(ja3, ja3s)` pair is the tuple threat-intel feeds key on.
  - **JA4H** from the HTTP request line + headers (HTTP/HTTPS handlers).
  - **HASSH** from the SSH KEXINIT.
  - All are stable across browser / scanner GREASE shuffling.
- **Honeynets**: configure zero-to-many artificial networks via the
  `honeynets:` block. Each has a CIDR + gateway + DNS + domain + a
  list of virtual hosts; each host has an IP + hostname + OS hint +
  service list. When a connection arrives at a virtual host's IP+port,
  the sensor dispatches to a handler instance whose Identity is
  derived from `sensor.deployment_id` + the virtual host id — so each
  virtual machine has its own stable but distinct SSH banner / MySQL
  version / SMB challenge / etc. Events get `honeynet`,
  `honeynet_host`, `honeynet_hostname`, `honeynet_os` meta keys. The
  DNS canary listener forward-resolves honeynet hostnames to virtual
  IPs.
- **Counter-fingerprinting** (anti-honeypot detection):
  - **Per-deployment uniqueness** via `sensor.deployment_id` — every
    "fixed" string the sensor emits (SSH banner version pool, HTTP
    Server header, MySQL version, SMB session key + challenge bytes,
    EtherNet/IP serial, VNC challenge, SMTP greeting hostname) is
    deterministically derived from this seed. Two sensors with
    different seeds present distinct fingerprints to Shodan-class
    scanners. Auto-generated and persisted on first run.
  - **Response jitter** via `sensor.jitter` — handlers sleep a random
    [min_ms, max_ms] before replying, so scanners can't fingerprint on
    microsecond-identical reply latency.
  - **TLS cert rotation** via `sensor.tls_rotate.days` — the
    auto-generated self-signed HTTPS cert is regenerated after the
    configured age so a long-running sensor doesn't leak a stable SNI
    cert hash.
- **Tarpit modes**: `sticky` (hold open), `trickle` (one byte every N
  seconds), `keepalive` (slow null bytes), with per-source and total
  connection caps.
- **Canary tokens**:
  - **File canaries** via fsnotify (modify/remove/rename/chmod) plus
    Linux fanotify (open/read detection — catches plain `cat`).
  - **URL canaries**: any HTTP/HTTPS listener that sees a configured
    unguessable path fires a separate critical event.
  - **DNS canaries**: a minimal UDP DNS listener that replies NXDOMAIN
    but fires on any subdomain of a registered name.
- **Packet-capture sniffer** (Linux AF_PACKET, opt-in, needs CAP_NET_RAW):
  - **L2** — ARP scans (one MAC asking about many distinct IPs) and
    unsolicited replies (ARP-cache poisoning).
  - **L3/L4** (`sniffer.tcp_scan`) — a scan-detection layer that classifies
    inbound TCP by flags on the wire: **NULL / FIN / Xmas** stealth probes
    (`-sN`/`-sF`/`-sX`), **SYN** and **ACK** scans by volume, and
    fragmented probes. This catches reconnaissance the connection-level
    correlator never sees because no session is ever established — closed
    ports that only get a RST, and stealth probes the kernel silently
    drops. Emits `sniffer:tcp_{syn,null,fin,xmas,ack}_scan` and
    `sniffer:ip_fragmented`, ATT&CK-tagged T1046 / T1595.001. (IPv4 +
    decoy detection is out of scope; ICMP sweeps are handled by the
    correlator's `icmp_sweep`.)
- **ICMP responder + personality + anomaly detection**: virtual hosts
  answer echo / timestamp / address-mask requests (Linux AF_PACKET),
  each stamped with the archetype's **initial-TTL personality** (255 OT
  / 128 Windows / 64 Linux-BSD) so OS fingerprinting + traceroute
  hop-distance stay consistent. The `internal/icmp` toolkit builds the
  full message family — Dest-Unreachable, Frag-Needed-with-MTU (PMTUD),
  Time-Exceeded (traceroute), Redirect, Param-Problem, IPv6 NDP — and
  `internal/icmp.Anomalies` flags ICMP tunneling, oversize payloads, and
  teardrop / overlapping-fragment evasion. The honeynet **TUN responder**
  (`internal/tunnet`) shares the same TTL personality: its synthesized
  echo replies + closed-port RSTs carry the per-host archetype TTL instead
  of echoing the prober's, so `nmap -O` against a virtual host's closed
  ports + ping matches the claimed OS. (Open-port SYN-ACKs still come from
  the kernel — a full userspace TCP/IP stack is out of scope.)
- **Device learning + "new device" alerts**: an opt-in learned-device
  registry (`devices.enabled`) records every host seen via DHCP (MAC +
  hostname + DHCP fingerprint), the ARP sniffer, and connection source
  IPs, does MAC-OUI vendor lookup, and raises `device:new` for
  never-before-seen, non-allow-listed hosts (learn-baseline or strict
  allow-list mode). Inspect with `list-devices`.
- **LLDP / CDP active responder** (Linux AF_PACKET): each honeynet host
  advertises itself in `lldpctl` / Cisco `show cdp neighbors` output
  with archetype-shaped MAC, hostname, system description, and
  family-tuned LLDP capabilities (bridge/router for switches + PLCs,
  station-only for hosts). Pairs naturally with the Moxa / SCALANCE
  / S7 archetypes for industrial deception.
- **PROFINET-DCP responder** (Linux AF_PACKET, `profinet_responder`):
  answers PROFINET DCP **Identify** requests (L2, EtherType 0x8892) for
  industrial hosts so a PROFINET scan (Siemens PRONETA / TIA Portal / nmap)
  enumerates the cell — NameOfStation, DeviceVendor, Device ID, Device
  Role, IP parameters per station, sourced from the archetype's PROFINET
  device tree. A received Identify is itself ICS recon, so each one raises
  `honeynet:profinet_dcp_identify` (ATT&CK T0846). (OPC-DA over
  DCOM/MSRPC is out of scope.)
- **MITRE ATT&CK + D3FEND tagging**: every event is decorated with
  `mitre_techniques` (e.g. `["T1110.001","T1078"]`), `mitre_tactics`
  (e.g. `["credential-access","initial-access"]`), and `mitre_defenses`
  — the MITRE **D3FEND** countermeasures (e.g. `["D3-MFA","D3-DE"]`)
  that answer those techniques — via the `internal/mitre` rule-id +
  handler-aware mapping. SIEMs pivot on these IDs directly.
- **Attack-storyline correlator** (`storyline:multi_stage`): fires
  when a single source IP touches 3+ distinct ATT&CK tactics inside
  a 30-minute window. The emitted event carries the kill-chain-
  ordered stages plus a "->"-joined chain summary
  ("discovery -> credential-access -> lateral-movement"), so the SOC
  sees one timeline instead of dozens of independent listener hits.
- **Protocol-anomaly detection** (`event.Anomalies`): handlers flag
  deviations from expected protocol shape — SSH banner with non-
  printable bytes / overlong / non-SSH; HTTP unknown methods;
  suspicious URIs (path traversal, Log4Shell JNDI, WordPress probes,
  .git / .env leakage, mgmt-endpoint scans).
- **Defensive hardening + output sanitization**: `internal/safe`
  package centralizes hostile-input handling — bounds-checked
  Slice / BoundedString / AllocBytes (capped at 32 KiB), plus
  SanitizeForLog / SanitizeUTF8ForLog / SanitizeHeader /
  SanitizeEmailSubject for output paths. CEF/LEEF/OCSF formatters
  escape every control byte (not just CRLF); SMTP sink scrubs
  every header. Prevents log injection, terminal-jacking via ANSI
  escapes, RLO filename spoofing, and HTTP/SMTP header smuggling
  from attacker-supplied banners and captured credentials.
- **Kernel self-confinement** (`sensor.sandbox`, Linux): a pure-Go
  **seccomp**-bpf denylist (execve / ptrace / module-load / mount /
  kexec / bpf / … return EPERM, so a parser 0-day can't spawn a shell)
  and a **Landlock** policy that makes the filesystem read-only except
  `data_dir`. Applied after privilege drop; best-effort. Shipped
  **AppArmor** + **SELinux** policies enforce the same intent from the
  host LSM. See [`docs/hardening.md`](docs/hardening.md).
- **Per-event pcap capture**: optional bidirectional byte capture on TCP
  connections, written as synthesized libpcap files Wireshark loads
  directly. Pure-Go, no raw sockets, no CAP_NET_RAW.
- **In-sensor correlator**:
  - **Port-scan**: N distinct ports from one source within a short window.
  - **Brute-force**: N attempts within a window. Aggregate carries the
    extracted credential pairs (from `auth_user`/`auth_pass`,
    `bind_dn`/`bind_pw`, MySQL/Postgres `username`, Redis `auth_password`,
    etc.) so the operator sees what was actually tried.
  - **Slow-scan**: long-window detector (default 24h, 10 distinct ports).
    Per-port state ages out individually, so a one-port-per-hour scan
    accumulates instead of resetting.
  - **ICMP sweep**: one source pinging N distinct virtual host IPs
    within a window (`correlate:icmp_sweep`, T1018).
- **Scan analysis / nmap fingerprinting** (`scananalysis:profile`):
  per-source profiling of an active scan. Estimates the nmap timing
  template (`-T0` paranoid .. `-T5` insane) from inter-connection
  cadence, detects aggressive scans (`-A`), OS-probe scans (`-O`),
  service/version probes (`-sV`, matched against the nmap
  service-probe strings), NSE-script signatures (`/nmaplowercheck`,
  `.git`/`.svn` discovery, robots, smbghost), and bare connect scans
  (`-sT`). Half-open SYN / FIN / NULL / Xmas / ACK scans, raw
  fragmentation, and decoy floods (`-D`) are honestly scoped as
  needing the AF_PACKET sniffer rather than guessed at the
  connection layer.
- **DNS amplifier-probe detection**: the DNS canary listener flags
  any `ANY` (qtype=255) query immediately, or `N` queries from one
  source within a window, with a separate `dnscanary:amplifier_probe`
  event.
- **Embedded SQLite event index** for queryable history, with WAL-mode
  concurrent reads.
- **Read-only web UI** on loopback: 24h summary + a filterable,
  **sortable** event table (click any column to sort/reverse) + per-event
  detail, plus **profiles** (per-source-IP attacker dossiers — see below),
  **hosts** (learned IPv4/IPv6/MAC inventory, filterable),
  **topology** (the virtual networks / hosts / services presented),
  **alerting** (how events forward), **errors** (operational/health
  events — listener or canary-watcher stopped, accept-cap overflow),
  **config**, and **docs** tabs. JSON at `/api/events`, `/api/summary`,
  `/api/profiles`, `/api/profiles/<ip>`, `/api/config`, `/api/topology`,
  `/api/hosts`, `/api/alerting`. Non-loopback binds refused without TLS +
  auth token.
- **Attacker profiles** (`/profiles`): a per-source-IP dossier compiled
  from every event that source produced — first/last seen, a
  severity-weighted **threat score**, identified **tools/scanners**
  (UA + SSH-banner fingerprinting), **JA3/JA4/HASSH** fingerprints,
  **credentials tried**, **ATT&CK** techniques/tactics, **CVE** exploit
  attempts, anomalies, and the services/ports targeted. The list ranks
  actors by threat; each detail page builds up as the source keeps
  interacting. Top-sources on the summary link straight to the profile.
- **Routing**: per-channel rate-limit, min-severity gate, severity-match
  route expressions (`>=high`, `<medium`, `=critical`), IP/CIDR allowlist
  (outbound-only — local sinks always receive).
- **Outbound channels**: `webhook` (HMAC-SHA256), `discord` (severity
  embeds), `smtp` (STARTTLS), `syslog` (RFC 5424 over local/tcp/udp/unix +
  **TLS** with octet-counting), `mqtt` (tcp/tls brokers), `twilio` (SMS),
  `sns` (AWS SNS via hand-rolled Sigv4 — no AWS SDK dependency), `snmptrap`
  (SNMPv2c via gosnmp).
- **Local sinks**: `stdout`, `jsonlog` (rotated JSONL), `sqlite`. These
  always receive every event so the local record stays complete even
  when an attacker matches the allowlist.
- **Full hot reload**: `SIGHUP` diffs old vs new config, hot-swaps
  channels / routes / allowlist / dedup window / correlator / canary
  lists, and per-listener restarts (added / removed / modified
  individually) without taking the rest of the sensor down. A
  `sensor:reload` event with the change list is emitted into the bus.
- **Outbound retry queue**: each sink has a bounded backlog (default
  64) with exponential backoff (1s → 60s) when Send returns a
  transient error. Per-channel Dropped / Failed / Retried counters
  exposed via `Router.Stats()` and the final-stats log line on Stop.
- **Per-listener accept-rate caps** (`max_concurrent`): non-blocking
  semaphore acquire on every accept; overflow closes the connection
  and emits a `listener:<id>:accept_cap` event. Stops a SYN flood
  from exhausting goroutines.
- **Graceful drain on shutdown** via `sensor.shutdown.drain_timeout`:
  SIGTERM closes accept sockets first, then waits up to the timeout
  for in-flight handler goroutines to finish before force-cancelling.
- **Time-based retention** via `sensor.disk.retention_days`: a runner
  ticks hourly and prunes `<data_dir>/events/*.jsonl`,
  `<data_dir>/captures/*.pcap`, and SQLite `events` rows older than
  the cutoff. Complements the existing size caps.
- **Privilege drop**: `setresuid` / `setresgid` after privileged setup
  on Linux; `setuid` / `setgid` on macOS. Refuses uid 0. Pairs with
  `systemd AmbientCapabilities` (Linux) or launchd's port-binding
  helpers (macOS) for privileged port binding.
- **Static cross-compile** for `linux/{amd64,arm64,armv7,armv6}` and
  `darwin/{amd64,arm64}`. CGO never required.

### Platform support

| Subsystem | Linux | macOS | Notes |
|---|---|---|---|
| All TCP/UDP protocol handlers | yes | yes | pure Go |
| Archetypes, ATT&CK, storyline, anomaly | yes | yes | pure Go |
| Interactive shell + `ssh_interactive` | yes | yes | crypto/ssh, pure Go |
| File canaries (write/remove/rename/chmod) | yes | yes | fsnotify (inotify on Linux, kqueue on darwin) |
| File canaries (read/OPEN events) | yes | — | linux-only, needs fanotify |
| URL canaries, DNS canaries, DNS amplifier detection | yes | yes | pure Go |
| Per-event pcap capture | yes | yes | synthesized libpcap, no raw sockets |
| Outbound channels (webhook/smtp/syslog/twilio/sns/snmptrap/mqtt) | yes | yes | pure Go |
| Privilege drop | yes | yes | `setresuid` on Linux, `setuid` on darwin |
| seccomp syscall filter (`sensor.sandbox.seccomp`) | yes | — | pure-Go BPF denylist |
| Landlock FS restriction (`sensor.sandbox.landlock`) | yes | — | Linux 5.13+; best-effort |
| ARP responder | yes | — | needs AF_PACKET; on macOS use `ifconfig <iface> alias <ip>` |
| ICMP responder | yes | — | needs AF_PACKET; aliased IPs answer ICMP echo natively |
| LLDP / CDP responder | yes | — | needs AF_PACKET; `/dev/bpf` backend planned |
| AF_PACKET ARP-scan sniffer | yes | — | `/dev/bpf` backend planned |
| TUN adapter for honeynet L3 | yes | — | utun backend planned; use `ifconfig alias` as workaround |

## Documentation

In-tree:

- [`docs/design.md`](docs/design.md) — architecture + design rationale covering the current implementation.
- [`docs/usage.md`](docs/usage.md) — quickstart, daily ops, honeynet patterns, web UI, systemd, Docker, troubleshooting.
- [`docs/config.md`](docs/config.md) — annotated YAML reference per top-level section.
- [`docs/cli.md`](docs/cli.md) — every subcommand, flag, and signal.
- [`docs/hardening.md`](docs/hardening.md) — the layered self-confinement model (privilege drop, seccomp, Landlock, AppArmor, SELinux, systemd).
- [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) — channel-by-channel cookbook for SIEMs, IoT, pagers, K8s.
- [`EXAMPLES.md`](EXAMPLES.md) — walkthrough of every example config (OT Purdue-model decoys + edge + IT), how to adapt and combine them.
- [`configs/tarpit-honeypot.example.yaml`](configs/tarpit-honeypot.example.yaml) — canonical default-values reference.

## Status

**v1.13 — scriptable + recorded + durable.** A Lua dynamic-response
engine (`handler: lua`) drives services from sandboxed operator scripts
with per-session state, per-source `host` state, deterministic `rng`,
`personality()` rotation, and timers — the mechanism for deep app
emulation + dynamic banners. Interactive `telnet` / `ssh_interactive`
sessions are recorded as replayable asciinema casts
(`sensor.session_recording`). The windowed correlators now persist their
state to disk and across hot reload, so slow-scan detection survives a
restart.

**Current — macOS first-class.** `darwin/amd64` and `darwin/arm64`
ship via `make cross`. Every feature except the four Linux-kernel-
specific ones (AF_PACKET raw sockets, fanotify OPEN events,
Linux TUN/TAP, `setresuid`) runs natively on macOS; the Linux-only
subsystems return clean errors with platform-specific workarounds
documented in [`docs/usage.md`](docs/usage.md#platform-support).

**v1.12 — scan analysis + service breadth + UI tabs.** Per-source nmap
scan profiling (`scananalysis:profile`: timing template `-T0`..`-T5`,
`-A`/`-O`/`-sV`, NSE + service-probe matching, connect scans). inetd
"small services" (echo / discard / daytime / qotd / chargen / time over
TCP **and** UDP) that are reflection-safe by construction. A resolving
`dns` handler that answers A/AAAA/MX/TXT/NS/CNAME with
deterministic-per-deployment fake records and runs every query through
tunneling/exfil detection. Emulate-then-tarpit (`tarpit.emulate`) turns
any protocol emulator into a tarpit. Two new read-only web-UI tabs
(topology + docs). 76 protocol handlers total.

**v1.11 — archetype depth + device intelligence + fingerprinting.** 15
new protocol emulators (mssql, oracle_tns, and the remote-access /
out-of-band-mgmt personas: teamviewer, anydesk, openvpn, citrix_ica,
intel_amt, ilo, idrac, esxi, fortinet, pulse, citrix_gateway, horizon,
moxa_mgmt) + per-deployment VNC version variety. 11 Windows + 3 Siemens
SCALANCE archetypes with era-correct **TLS posture** and per-host
**ICMP TTL personality**; switch archetypes expose MRP / PROFINET /
VLAN / HMI / LLDP topology from their web UI + the L2 segment. Tool
fingerprinting + human-vs-automation heuristics (`internal/toolfp`).
Abnormal-payload detection for ICMP (tunneling / frag abuse) and DNS
(exfil shapes). Learned-device registry with `device:new` alerts +
MAC-OUI vendor lookup. Default-credential corpus, fake-files tree, and
the medium-interaction `ftp_files` handler. ICMP ping-sweep correlation.

**v1.10 — attacker engagement.** Interactive CLI shell engagement
(`internal/shell`) wired into both the existing `telnet` handler
and a new `ssh_interactive` handler running a full
`golang.org/x/crypto/ssh` server with persistent ed25519 host key.
Per-archetype response tables (Linux distros / Moxa CLI / SCALANCE
CLI) + 14-marker ATT&CK-aligned anomaly scanner on every typed
command (reverse shells, persistence, recon, defense evasion,
crypto-miners, encoded payloads). LLDP / CDP active responder makes
honeynet hosts appear in `lldpctl` / `show cdp neighbors` on the L2
segment with archetype-shaped MAC + system description. Multi-page
archetype web UI with credential-capturing POST handler for
login-shaped paths.

**v1.9 — deception+detection sensor.** Adds MITRE ATT&CK technique +
tactic tags to every emitted event, a cross-protocol storyline
correlator that fires `storyline:multi_stage` when a source touches
3+ kill-chain tactics in 30 minutes (emitting an ordered chain
summary), and protocol-anomaly detection on the SSH and HTTP
handlers. New `internal/safe` package hardens input parsing and
sanitizes attacker-supplied strings before they touch any log /
SIEM / email / webhook path. 14 new archetypes (FreeBSD 13/14,
OpenBSD 7.5/7.6, Arch, Rocky 9, AlmaLinux 9, Oracle 8/9, Moxa
EDS-208 / NPort 5210, Siemens SCALANCE XB-208, S7-1200, S7-1500)
with the deeper fingerprint surface those devices need: MAC OUI,
SNMP MIB-2 identity, CLI prompt, web-UI body, LLDP neighbors,
default services, protocol quirks. SNMP/HTTP/Telnet handlers
consume the new fields.

**v1.8 — archetypes + 5 new protocols.** Sensor-level
`sensor.archetype` (overridable at listener and per-honeynet-host
level) pins SSH / HTTP / FTP / Telnet / SMTP / MySQL banners to
values consistent with a stock install of 15 ship distributions
(CentOS 5–8 + Stream 10, Debian 9–13, RHEL 8–10, Ubuntu 24.04 / 26.04
LTS). 5 new protocol handlers: CoAP (UDP/5683), KNXnet/IP (UDP/3671),
XMPP (TCP/5222), AMQP (TCP/5672), IPP/CUPS (TCP/631).

**v1.7 — 10 new protocols + MQTT sink + .deb / .rpm packaging.**
syslog_tcp, syslog_udp, radius, sip, ssdp, cldap, llmnr, nbns, fins,
rtsp, dockerapi, melsec. Outbound MQTT client. Debian + RPM
packages with shell completions, systemd unit, and `tarpit-honeypot
help` long-form subcommand docs.

**v1.6 — CLI ergonomics + testing infrastructure + lifecycle.**
Global `--version` / `-V`, per-subcommand `--help`, shared logging
flags (`--log-level`, `--log-format=json|text`, `--log-file`,
`--quiet`, `--verbose`), `--set key=value` overrides, `TARPIT_*`
env-var overrides, `conf.d/*.yaml` includes deep-merged in lexical
order, `run --dry-run`, `init` skeleton subcommand, shell
completions (bash / zsh / fish). Panic recovery wrapper around every
handler goroutine. Fuzz tests for the TLS ClientHello (JA3/JA4),
SSH KEXINIT (HASSH), HTTP request line (JA4H), LDAP BER decoder,
MQTT varint parser, DNS query parser; `make cover` / `make race`
/ `make fuzz` targets.

**v1.5 — TUN adapter, IPv6, SNMP/LDAP/DCE-RPC topology exposure, docs.**
Each honeynet can open a Linux TUN device (`CAP_NET_ADMIN`) that
answers ICMP/ICMPv6 echo for any virtual host IP and TCP-RST for
unbound ports without `ip addr add`. IPv4 + IPv6 honeynet hosts and
listener binds work uniformly. The SNMP, LDAP, and DCE-RPC handlers
now include the honeynet topology in their event meta
(`honeynet_neighbors`, `honeynet_computer_accounts`,
`honeynet_endpoints`) so a scanner walking those services sees an
inventory of the virtual network. New `docs/` directory with three
substantial guides.

**v1.4 — SIEM enrichment + output formats.** Adds GeoIP / ASN /
reverse-DNS enrichment that decorates every event's meta from
operator-supplied MaxMind GeoLite2 databases plus a bounded
synchronous rDNS resolver. Each sink can now emit in JSON (default),
CEF (ArcSight), LEEF (QRadar), or OCSF (cloud SIEMs like Snowflake,
Athena, AWS Security Lake) — pick per-channel via the new `format:`
field.

**v1.3 — honeynet ICMP + Prometheus metrics.** Virtual hosts now
respond to ping via an opt-in Linux AF_PACKET ICMP echo responder
(same model as the v1.2 ARP responder; reuses the per-host
deterministic MAC). The web UI exposes a Prometheus-format
`/metrics` endpoint with per-channel retry counters, honeynet
topology gauges, and the SQLite store size.

**v1.2 — honeynet L2 + routing.** Adds an opt-in Linux ARP responder
so virtual networks are discoverable without `ip addr add` (each
virtual host advertises a stable deterministic MAC derived from
`sensor.deployment_id`), and extends the routing predicate so events
from a specific honeynet, OS family, or rule id can fan out to their
own channels.

**v1.1 — honeynets.** Adds artificial networks of artificial hosts:
one sensor can present as N distinct virtual machines via the new
`honeynets:` config block. Each virtual host gets a deterministically-
derived Identity (so banners / versions / serials differ per host),
and the DNS canary listener now forward-resolves honeynet hostnames
to their virtual IPs. New `list-honeynets` subcommand dumps the
configured topology.

**v1.0 — counter-fingerprinting, advanced detection, lifecycle.** Adds
per-deployment uniqueness (the `deployment_id` seed derives every
"fixed" string the sensor emits: SSH banner version, MySQL version,
HTTP `Server:` header, SMB challenge bytes, EtherNet/IP serial, VNC
challenge, SMTP greeting hostname), randomized per-reply jitter,
automatic HTTPS self-signed cert rotation, HTTP/2 client
fingerprinting (JA4H), credential extraction from the brute-force
correlator, slow-scan correlation over hour-scale windows, DNS
amplifier-probe detection, time-based retention pruning, graceful
shutdown drain with a configurable timeout, and the `export-pcap`
subcommand.

## Build

```
make build         # native binary in bin/
make cross         # all four linux ELF binaries in dist/
make test          # full unit test suite
```

The binary is statically linked and uses no CGO. Final size is ~14 MB,
mostly the pure-Go SQLite engine.

## Try it locally

```
./bin/tarpit-honeypot validate-config -c configs/tarpit-honeypot.example.yaml
./bin/tarpit-honeypot run            -c configs/tarpit-honeypot.example.yaml
```

In another shell, generate some events:

```
# Banner-mode listeners
nc -v localhost 2222                              # SSH handler
printf 'GET / HTTP/1.0\r\n\r\n' | nc -v localhost 8000   # HTTP handler

# ICS handlers (need privileged port redirect or change the bind)
printf '\x00\x01\x00\x00\x00\x06\x11\x03\x00\x00\x00\x02' | nc -u localhost 502
echo 'evil' | nc -u localhost 161                 # SNMP scan

# Tarpit — connection will be held forever (or until you Ctrl-C)
nc -v localhost 2323

# Canary — modify the bait file
echo dropped >> ./var/canary/passwords.xlsx

# Web UI
open http://127.0.0.1:8088
```

## Subcommands

```
tarpit-honeypot run            -c <config>
tarpit-honeypot validate-config -c <config> [--diff <other.yaml>]
tarpit-honeypot show-config    -c <config>
tarpit-honeypot gen-token      --type=dns|url|hex [--label LBL] [--bits N] [--domain D]
tarpit-honeypot test-alert     -c <config> [--severity high] [--note "..."]
tarpit-honeypot list-events    -c <config> [--since 24h] [--source <ip>] [--rule <id>] [--limit N]
tarpit-honeypot export-pcap    -c <config> --event <id> [-o file|-]
tarpit-honeypot list-honeynets -c <config>
tarpit-honeypot list-devices   -c <config>
tarpit-honeypot init           [-o <config>]
tarpit-honeypot completion     bash|zsh|fish
tarpit-honeypot help           [subcommand|topic]
tarpit-honeypot version
```

`export-pcap` copies `<data_dir>/captures/<event_id>.pcap` to stdout
(default) or a file. Read-only; never touches sensor state. Used
together with `list-events` to grab the per-connection capture for a
specific event:

```
tarpit-honeypot list-events  -c cfg.yaml --rule listener:ssh-bait --limit 1
# ... pick the event id from the output ...
tarpit-honeypot export-pcap -c cfg.yaml --event 7c0574dd1015ac2c142e30ca -o /tmp/ssh.pcap
wireshark /tmp/ssh.pcap
```

`validate-config --diff` compares two configs and classifies each
change as hot-reloadable (channels, routes, allowlist, dedup,
correlator, canary lists) vs restart-required (sensor.*, ui, dns,
sniffer). Listeners now hot-reload too, but the diff still surfaces
them so operators see what will be restarted.

`show-config` prints the post-defaults effective YAML. Secrets stay
as env-var names (`auth_token_env: TARPIT_UI_TOKEN`) rather than
expanded values, so the output is safe to paste in tickets.

`gen-token` prints unguessable canary tokens shaped for the three
common bait surfaces:
```
$ tarpit-honeypot gen-token --type=dns --label=prod
6c50957e8e94f661-prod.canary.example.com

$ tarpit-honeypot gen-token --type=url --bits=128
/__canary__/8ed2a49c8ef9639a1234567890abcdef
```

`run` responds to `SIGHUP` by reloading the config. Channels, routes,
allowlist, dedup window, and correlator thresholds get hot-swapped;
listener or `sensor.*` changes log a warning and require a restart.

`test-alert` injects a synthetic event through the routing pipeline so
you can validate outbound channels end-to-end without waiting for a real
trigger.

`list-events` reads from the SQLite store when one exists, falling back
to the rotating JSONL log for tripwire-only configs.

## Configuration

The full annotated schema lives in
[`configs/tarpit-honeypot.example.yaml`](configs/tarpit-honeypot.example.yaml)
(plus the `-FULL` / `-SMALL-OT` / `-ADVANCED-OT` variants in `configs/`),
with a per-section reference in [`docs/config.md`](docs/config.md). Key
sections:

### `sensor`

Global identity + behavior. All optional; sane defaults apply.

| Field | Purpose |
|---|---|
| `name`, `data_dir` | Sensor name stamped on events; root for all durable state. |
| `archetype` | OS/device persona pinning every banner-aware handler, SNMP MIB-2, MAC OUI, CLI prompt, **TLS posture**, **ICMP TTL**, FTP `FEAT` set, and SMTP `EHLO` extensions to a stock install (e.g. `"debian 12"`, `"Windows Server 2019"`, `"Siemens SCALANCE S615"`, `"fortigate"`). Overridable per `listener` and per honeynet host. `help archetypes` lists all 58. |
| `deployment_id` | Stable seed deriving every "fixed" string the sensor emits (SSH/HTTP/MySQL versions, SMB challenge, VNC challenge, …) so two sensors look distinct. Auto-generated + persisted on first run. See [Counter-fingerprinting](#counter-fingerprinting). |
| `jitter` | `{enabled, min_ms, max_ms}` per-reply latency jitter to defeat timing fingerprints. |
| `tls_rotate.days` | Regenerate the self-signed HTTPS cert after N days (0 = never). |
| `geoip` / `rdns` | Source-IP enrichment (GeoIP city/ASN + bounded rDNS). See [Enrichment](#enrichment). |
| `disk` | Size caps + `retention_days` for events / captures / SQLite. See [pcap](#per-event-pcap-capture). |
| `shutdown.drain_timeout` | Grace period for in-flight handlers after SIGTERM. |
| `vuln_emulation` | Advertise the archetype's deliberately-unpatched banner + fake patch level (per-listener `vuln_emulation` overrides). CVE exploit-attempt detection runs regardless. Never makes the service exploitable. |
| `payloads` | `{enabled, max_bytes, max_total_mb}` — harvest malware/shellcode/droppers to `<data_dir>/payloads/`. |
| `drop_user` / `drop_group` | uid/gid to switch to after privileged setup (refuses uid 0). |

### `listeners`

Each listener has `id`, `proto` (`tcp` or `udp`), `bind`, and a `mode`:

| Mode | What it does |
|---|---|
| `drop` | Accept and immediately close. Logs source. |
| `banner` | Run the configured `handler:` and capture both sides. |
| `tarpit` | Hold the connection per the `tarpit.strategy:` setting. |

Per-listener `capture: true` writes a synthesized pcap of the
bidirectional bytes under `<data_dir>/captures/<event_id>.pcap`.

### `canaries`, `url_canaries`, `dns` + `dns_canaries`

File canaries watch real filesystem paths. URL canaries match exact paths
against incoming HTTP/HTTPS requests. DNS canaries fire when any
subdomain of a registered name is queried at the UDP DNS listener.

### `sniffer`

Optional Linux-only AF_PACKET sniffer. Needs `CAP_NET_RAW`. Detects ARP
scans and unsolicited replies. Off by default.

### `correlate`

In-memory windowed counters that emit higher-severity aggregate events
when thresholds are crossed. Aggregate events are deduped within the
window so a sustained scan doesn't flood sinks. Four detectors, each
independently toggled:

| Block | Fires | Key knobs |
|---|---|---|
| `correlate.port_scan` | `correlate:port_scan` — N distinct ports from one source in a short window. | `distinct_ports`, `window` |
| `correlate.brute_force` | `correlate:brute_force` — N attempts on a port in the window (carries the extracted credential pairs). | `attempts`, `window`, `per_port` |
| `correlate.slow_scan` | `correlate:slow_scan` — long-window scan (per-port state ages out individually). | `distinct_ports`, `window` (default 24h) |
| `correlate.icmp_sweep` | `correlate:icmp_sweep` — one source pinged N distinct virtual IPs. | `distinct_ips`, `window`, `severity` |
| `correlate.password_spray` | `correlate:password_spray` — one source tried N distinct usernames in the window (breadth, vs brute-force depth). | `distinct_users`, `window`, `severity` |
| `correlate.credential_reuse` | `correlate:credential_reuse` — the same credential pair came from N distinct sources (credential stuffing); password never logged. | `distinct_sources`, `window`, `severity` |

Per-source scan **profiling** (nmap `-T`/`-A`/`-O`/`-sV`/NSE
fingerprinting → `scananalysis:profile`) and the cross-protocol
`storyline:multi_stage` correlator are always-on and need no config.

### `devices`

Learned-device inventory + "new device" alerting. When
`devices.enabled: true` the sensor records every host it sees (from the
`dhcp` handler's MAC + hostname + DHCP fingerprint, the ARP sniffer, and
the source IP of every handled connection) into
`<data_dir>/devices.json`, and raises a `device:new` event for hosts
that are neither allow-listed nor part of the learned baseline.

| Field | Meaning |
|---|---|
| `learn` | `true` = first run silently records a baseline, later unseen hosts alert; `false` = strict allow-list mode (every non-allowed host alerts on first sight). |
| `allow` | IPs / CIDRs / MACs that never alert. |
| `severity` | Severity of the `device:new` event (default `high`). |

Review with `tarpit-honeypot list-devices`.

### `channels` and `routes`

Channels are sinks; routes wire severity-match expressions to lists of
channel ids. Local sinks (`stdout`, `jsonlog`, `sqlite`) always receive;
outbound sinks honor allowlist + dedup + per-channel rate limit +
min-severity gate.

### `sensor.drop_user` / `sensor.drop_group`

Linux uid/gid to switch to after privileged setup (binding low ports,
opening data dirs). Refuses uid 0. On non-Linux platforms the setting is
logged as ignored.

### `ui`

Read-only HTML/JSON web UI. Default `bind: 127.0.0.1:8088`. Non-loopback
binds are rejected at validate-time unless both `tls_cert` + `tls_key`
and `auth_token_env` are configured. Tabs: summary, events, **topology**,
**config**, **docs** — see [Web UI](#web-ui).

### `dedup` + `allowlist`

`dedup.default_window` collapses repeat events with the same
`(rule_id, source)` within the window before they reach **outbound**
sinks (local sinks always get the full stream). `allowlist` is a list of
IPs / CIDRs whose events skip outbound dispatch but are still recorded
locally — keep a forensic trail without paging on internal scanners.

### `honeynets`

Zero-to-many artificial networks of virtual hosts (CIDR + gateway + DNS +
domain + per-host `{ip, hostname, os, archetype, services}`), each with
optional `arp_responder` / `icmp_responder` / `lldp_responder` / `tun`.
See [Honeynets](#honeynets) for the dispatch model and examples.

## OS / device archetypes

Set `sensor.archetype`, `listener.archetype`, or a per-honeynet-host
`archetype` to any **config name** below (names are matched
case-insensitively with flexible separators — `"Cisco Catalyst Switch"`,
`cisco-catalyst-switch`, and `cisco_catalyst_switch` all resolve). The
archetype then drives every banner-aware handler (SSH/HTTP(S)/FTP/Telnet/
SMTP/MySQL), the SNMP MIB-2 identity (sysDescr/sysObjectID/ifTable), MAC
OUI, interactive-shell CLI, TLS posture, and the initial IP TTL so the
host is internally consistent end to end. `tarpit-honeypot help archetypes`
prints the live list.

| Category | Archetype | Config name(s) | Family | Init TTL | Signature highlights |
|---|---|---|---|---|---|
| Linux | Debian 9 (stretch) | `debian-9` | debian | 64 | OpenSSH 7.4 / Apache 2.4.25 / vsFTPd / Postfix / MariaDB |
| Linux | Debian 10 (buster) | `debian-10` | debian | 64 | OpenSSH 7.9 / Apache 2.4.38 |
| Linux | Debian 11 (bullseye) | `debian-11` | debian | 64 | OpenSSH 8.4 / Apache 2.4.62 |
| Linux | Debian 12 (bookworm) | `debian-12` | debian | 64 | OpenSSH 9.2 / Apache 2.4.x |
| Linux | Debian 13 (trixie) | `debian-13` | debian | 64 | current Debian banners |
| Linux | Ubuntu 24.04 LTS | `ubuntu-24-04-lts` | ubuntu | 64 | OpenSSH 9.x (Ubuntu) / nginx |
| Linux | Ubuntu 26.04 LTS | `ubuntu-26-04-lts` | ubuntu | 64 | current Ubuntu banners |
| Linux | CentOS 5 | `centos-5` | rhel | 64 | OpenSSH 4.3 / Apache 2.2.3 (legacy) |
| Linux | CentOS 6 | `centos-6` | rhel | 64 | OpenSSH 5.3 / Apache 2.2.15 |
| Linux | CentOS 7 | `centos-7` | rhel | 64 | OpenSSH 7.4 / Apache 2.4.6 |
| Linux | CentOS 8 | `centos-8` | rhel | 64 | OpenSSH 8.0 / Apache 2.4.37 |
| Linux | CentOS Stream 10 | `centos-stream-10` | rhel | 64 | OpenSSH 9.9 |
| Linux | RHEL 8 | `red-hat-enterprise-linux-8` | rhel | 64 | RHEL banners |
| Linux | RHEL 9 | `red-hat-enterprise-linux-9` | rhel | 64 | RHEL banners |
| Linux | RHEL 10 | `red-hat-enterprise-linux-10` | rhel | 64 | RHEL banners |
| Linux | Rocky Linux 9 | `rocky-linux-9` | rhel | 64 | RHEL-compatible |
| Linux | AlmaLinux 9 | `almalinux-9` | rhel | 64 | RHEL-compatible |
| Linux | Oracle Linux 8 | `oracle-linux-8` | rhel | 64 | RHEL-compatible |
| Linux | Oracle Linux 9 | `oracle-linux-9` | rhel | 64 | RHEL-compatible |
| Linux | Arch Linux | `arch-linux` | arch | 64 | rolling-release banners |
| BSD | FreeBSD 13 | `freebsd-13` | bsd | 64 | OpenSSH / FreeBSD web console |
| BSD | FreeBSD 14 | `freebsd-14` | bsd | 64 | OpenSSH / FreeBSD web console |
| BSD | OpenBSD 7.5 | `openbsd-7-5` | bsd | 64 | OpenSSH / httpd |
| BSD | OpenBSD 7.6 | `openbsd-7-6` | bsd | 64 | OpenSSH / httpd |
| Windows | Windows 7 | `windows-7` | windows | 128 | legacy SMB/RDP, weak TLS |
| Windows | Windows 8 | `windows-8` | windows | 128 | legacy posture |
| Windows | Windows 10 | `windows-10` | windows | 128 | modern client |
| Windows | Windows 11 | `windows-11` | windows | 128 | modern client |
| Windows | Windows Server 2008 | `windows-server-2008` | windows | 128 | TLS 1.0, legacy ciphers |
| Windows | Windows Server 2012 | `windows-server-2012` | windows | 128 | legacy server |
| Windows | Windows Server 2012 R2 | `windows-server-2012-r2` | windows | 128 | legacy server |
| Windows | Windows Server 2016 | `windows-server-2016` | windows | 128 | server |
| Windows | Windows Server 2019 | `windows-server-2019` | windows | 128 | server |
| Windows | Windows Server 2022 | `windows-server-2022` | windows | 128 | server |
| Windows | Active Directory (Server 2019 DC) | `active-directory`, `domain-controller`, `windows-server-2019-dc` | windows | 128 | PowerShell shell + full AD protocol mix; pre-rollup patch level (ZeroLogon/PrintNightmare/ProxyLogon advisory) |
| Network | Cisco Catalyst 2960 (IOS 15) | `cisco-ios`, `cisco-catalyst-2960` | cisco | 255 | IOS CLI emulator, SSH-2.0-Cisco, SNMP ifTable/VLAN/LLDP, weak TLS, CVE-2018-0171 (Smart Install) |
| Network | Cisco Catalyst 9300 (IOS-XE 17) | `cisco-catalyst-switch`, `cisco-catalyst-9300` | cisco | 255 | IOS-XE identity, cat9k sysObjectID |
| Network | MikroTik RouterOS | `mikrotik-router`, `mikrotik-routeros`, `mikrotik-routerboard` | mikrotik | 64 | SSH-2.0-ROSSSH, webfig, Winbox/API ports, RouterOS CLI emulator, MikroTik SNMP OID |
| Network | Teltonika RUT240 | `teltonika-rut240`, `teltonika-router` | teltonika | 64 | RutOS/OpenWrt, Dropbear SSH, lighttpd, LTE wwan0, Teltonika SNMP OID |
| ICS/OT | Moxa EDS-208 | `moxa-eds-208` | moxa | 255 | industrial switch CLI, Moxa OUI/SNMP |
| ICS/OT | Moxa NPort 5210 | `moxa-nport-5210` | moxa | 255 | serial device server, raw TCP 4001/4002 |
| ICS/OT | Siemens SCALANCE XB-208 | `siemens-scalance-xb-208` | siemens | 255 | SCALANCE CLI, MRP ring / PROFINET tree / VLAN exposure |
| ICS/OT | Siemens SCALANCE S615 | `siemens-scalance-s615` | siemens | 255 | industrial security router |
| ICS/OT | Siemens SCALANCE SC-600 | `siemens-scalance-sc-600` | siemens | 255 | industrial firewall |
| ICS/OT | Siemens S7-1200 PLC | `siemens-s7-1200` | siemens | 255 | S7 PLC console, S7comm |
| ICS/OT | Siemens S7-1500 PLC | `siemens-s7-1500` | siemens | 255 | S7 PLC console, S7comm-Plus |
| ICS/OT | Allen-Bradley ControlLogix | `rockwell-controllogix` | ics | 64 | EtherNet/IP (CIP) 44818, Allen-Bradley web, Rockwell OUI |
| ICS/OT | Schneider Modicon M340 | `schneider-modicon` | ics | 64 | Modbus/TCP 502 + EtherNet/IP, Schneider-WEB, Schneider OUI |
| ICS/OT | Omron PLC (FINS) | `omron-plc` | ics | 64 | FINS 9600 + EtherNet/IP, Omron OUI |
| Firewall | pfSense (Netgate) | `pfsense` | pfsense | 64 | nginx, FreeBSD OpenSSH, pfSense login page, X-Frame-Options |
| Firewall | Fortinet FortiGate | `fortigate` | fortios | 255 | SSL-VPN `SVPNCOOKIE`, weak TLS, Fortinet OUI, CVE-2018-13379 (advisory) |
| NAS | Synology DiskStation | `synology-dsm` | synology | 64 | DSM web 5000/5001, MLST/MLSD FTP FEAT, Synology OUI/OID |
| NAS | QNAP Turbo NAS | `qnap-qts` | qnap | 64 | QTS web 8080, FTP FEAT, QNAP OUI/OID |
| Camera | Hikvision IP camera | `hikvision-camera` | hikvision | 64 | `App-webs/` Server, RTSP 554, Digest "IP Camera", CVE-2017-7921 (advisory) |
| Camera | Axis network camera | `axis-camera` | axis | 64 | VAPIX, RTSP 554, Digest realm `AXIS_*`, Axis OUI |
| Network | Ubiquiti EdgeRouter | `ubiquiti-edgerouter` | ubiquiti | 64 | EdgeOS lighttpd, Ubiquiti OUI/OID |
| Printer | HP LaserJet | `hp-printer` | printer | 64 | HP HTTP Server, JetDirect 9100, IPP 631, HP OUI/OID |
| VoIP | Asterisk PBX | `asterisk-voip` | voip | 64 | SIP 5060, FreePBX web, `Asterisk/18.x` Server header |

---

## Protocol handlers in detail

Bold flags: **arch** = consumes `archetype.Profile` for banner shape;
**id** = consumes `identity.Identity` for per-deployment uniqueness.

### TCP — general / IT

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `raw` | any | Sends literal `banner:` field, reads up to `read_bytes`. | — | — |
| `scripted` | any | Declarative fake protocol from the `scripted:` config block: optional on-connect greeting, then top-down `rules` matching each message (`prefix`/`contains`/`regex`/`hex_prefix`/`any`) → `respond` (text or `respond_hex`), with per-rule `anomaly` + `close`. Captures the full transcript. Bounded rounds + 64 KB reply cap. | — | — |
| `ssh` | 22 | Sends archetype/identity-shaped SSH-2.0 banner immediately followed by its own `SSH_MSG_KEXINIT` (algorithm set derived from the version banner — modern OpenSSH / legacy / Dropbear — so the **server HASSH** is realistic and version-consistent, recorded as `hassh_server`). Reads client ID (flags non-printable / non-SSH / overlong), computes the client HASSH from its KEXINIT, then drops the connection. | ✓ | ✓ |
| `ssh_interactive` | 22 | Full `golang.org/x/crypto/ssh` server with persistent ed25519 host key under `<data_dir>/tls/ssh_host_ed25519_key`. Captures every password / pubkey attempt (SHA-256 fingerprint, key type, user, client version), accepts the 3rd credential and drops into `internal/shell.Run` on the session channel. Bounded: `SessionTimeout=5min`, `MaxAuthTries=6`. Also captures non-interactive `ssh host CMD` exec lines + scans them for anomalies. | ✓ | ✓ |
| `http` | 80 | Routes on method+path. `GET /` serves the archetype's index HTML (Moxa / SCALANCE / S7 device pages or nginx 401). `GET /login` and 12 other login-shaped paths serve a form. `POST /login` parses `application/x-www-form-urlencoded` body (accepts 6 alias names each for user/pass) and captures credentials. Computes JA4H from request line + headers. Flags 8 suspicious-URI anomalies (Log4Shell JNDI, path traversal, WordPress / `.git` / `.env` / Tomcat manager probes). | ✓ | ✓ |
| `https` | 443 | Peeks the TLS ClientHello for JA3 + JA4 fingerprints before crypto/tls consumes it. Self-signed ECDSA cert cached + rotated per `sensor.tls_rotate.days` under `<data_dir>/tls/`. Then runs the HTTP handler over the decrypted stream. Captures TLS version + SNI + JA3/JA4. | ✓ | ✓ |
| `telnet` | 23 | IAC WILL ECHO / WILL SGA / DO TERMINAL-TYPE negotiation, archetype-shaped issue banner, captures `user_attempt` + `pass_attempt`, sends "Login incorrect", then drops into the archetype's CLI shell (Linux distros / Moxa / SCALANCE response tables). | ✓ | — |
| `ftp` | 21 | 220 banner (archetype-shaped), then a bounded command loop: answers `FEAT` with the archetype's daemon-specific feature set (vsFTPd default; Synology/QNAP expose MLST/MLSD), `SYST` with `215 UNIX Type: L8`, USER → 331, PASS → 530 Login incorrect. Captures `user_line` + `pass_line` and flags `default-credential-attempt`. | ✓ | — |
| `smb` | 445 | NBSS framing + SMB1 Negotiate Protocol Request handler: captures all offered dialects, selects `NT LM 0.12`, replies with a believable Negotiate Response (8-byte challenge + 8-byte session key derived from identity). SMB2 connections answered with NEGOTIATE_RESPONSE carrying `STATUS_NOT_IMPLEMENTED`. | — | ✓ |
| `vnc` | 5900 | RFB 003.008 version exchange. Sends 16-byte VNC auth challenge (identity-derived), captures `client_version` + raw DES-encrypted `auth_response_hex` from brute-force tools. Always replies SecurityResult `auth failed`. | — | ✓ |
| `smtp_recv` | 25 | ESMTP receive listener. Captures `helo`, `auth_mech`, `auth_user`, `auth_pass` (from AUTH PLAIN / LOGIN), `mail_from`, `rcpt_to`, `message_head`. Archetype-shaped 220 greeting (`Postfix 3.7.11` for debian 12, etc.); multiline `EHLO` advertises an archetype-specific extension set (`SMTPExtensions`, Postfix-style default) using the same host as the greeting. STARTTLS replied with 454 so the client falls back to plaintext credentials. | ✓ | ✓ |
| `rdp` | 3389 | X.224 Connection Request parser. Extracts `mstshash=` Cookie (typically the targeted username from `xfreerdp /u:...`) + `RDP_NEG_REQ` flags. Replies CC with PROTOCOL_SSL selected (so the next-stage scanner enters TLS negotiation we then don't complete). | — | — |
| `winrm` | 5985 | Reads HTTP POST `/wsman`. Decodes `Authorization: Basic` into `basic_user` / `basic_pass`. Replies HTTP 401 advertising `Negotiate, Basic realm="WSMAN"` so non-Kerberos brute-forcers fall back. | — | — |
| `dcerpc` | 135 | Endpoint Mapper bind handler. Parses the first abstract interface UUID + version pair. Replies `bind_ack` with NDR transfer syntax. When honeynet topology is available, advertises the configured endpoints. | — | — |
| `ldap` | 389 | Hand-rolled BER decoder (bounds-checked, fuzz-tested). Captures `bind_dn` + cleartext `bind_pw` for simpleAuth, or `sasl_mechanism` for SASL. Replies BindResponse 49 (invalidCredentials). When honeynet topology is available, advertises computer accounts in search responses. | — | — |
| `kerberos` | 88 | ASN.1 reader for AS-REQ / TGS-REQ. Extracts the principal name(s) and realm. Replies KRB-ERROR `KDC_ERR_PREAUTH_REQUIRED` — what a real KDC sends to invite a pre-auth attempt (the cleartext-derived `enc-timestamp` that AS-REP-Roasting tools harvest). | — | — |
| `postgres` | 5432 | Reads StartupMessage (and SSLRequest / GSSEncRequest fallback). Captures `username`, `database`. Sends AuthenticationCleartextPassword, captures the PasswordMessage `password` (flags `default-credential-attempt`). Sends FATAL `28P01`. | — | — |
| `mysql` | 3306 | Server-first MySQL handshake — archetype-shaped version string (e.g. `10.11.6-MariaDB-0+deb12u1` for debian 12). Captures `username`, `auth_response_hex`, optional `database`. Replies ERR_Packet 1045 Access denied. | ✓ | ✓ |
| `mssql` | 1433 | TDS PRELOGIN exchange — advertises a SQL Server 15.0 version token + ENCRYPT_NOT_SUP, captures the LOGIN7 username, replies with an 18456 login-failed error token. | — | ✓ |
| `oracle_tns` | 1521 | Oracle Net (TNS) listener. Captures the connect descriptor (SERVICE_NAME / SID recon) and replies REFUSE ORA-12514. | — | — |
| `ftp_files` | 21 | Medium-interaction FTP: anonymous / `accept_creds` login, full PASV browse + RETR over a deterministic decoy tree. Flags `honeyfile-download` on bait-file retrieval + `default-credential-attempt`. | ✓ | ✓ |
| `redis` | 6379 | RESP parser (multi-bulk + inline forms). Captures `auth_password` from `AUTH` / `HELLO ... AUTH`, plus a short list of issued `commands` (with arguments). Returns RESP errors so the client keeps trying. | — | — |
| `syslog_tcp` | 514 | Reads syslog messages via both octet-counting (`<N> <msg>`) and non-transparent (newline-terminated) framing. Captures first 16 messages with PRI / facility / severity decoded. | — | — |
| `rtsp` | 554 | Parses RTSP OPTIONS / DESCRIBE request line + headers. Captures `Authorization` (often Digest with the camera password) + `User-Agent`. Replies 401 with a Hikvision-shaped `WWW-Authenticate: Digest`. | — | — |
| `dockerapi` | 2375 | Unauthenticated-Docker-API mimic. Routes `/_ping`, `/version`, `/info`, `/containers/json` to believable canned JSON. Captures the request line + `Authorization` header on every hit. | — | — |
| `melsec` | 1025 | Mitsubishi MELSEC 3E frame parser. Reads `0x5000` request header, replies `0xD000` with a fake `Q03UDVCPU` CPU model + serial. | — | — |
| `xmpp` | 5222 | Reads the client `<stream:stream>` open, extracts `to` / `from` / `xmlns` / `version`. Replies with our own `<stream:stream>` + `<stream:features>` advertising STARTTLS + PLAIN + SCRAM-SHA-1. Captures the follow-up `<auth>` or `<starttls/>` stanza. | — | — |
| `amqp` | 5672 | AMQP 0-9-1 / RabbitMQ. Sends Connection.Start (advertising PLAIN + AMQPLAIN) after the 8-byte protocol header. Decodes the SASL PLAIN response (`\0user\0pass`) from Connection.StartOk. Replies Connection.Close with 530 NOT_ALLOWED. | — | — |
| `ipp` | 631 | IPP / CUPS printer over HTTP. Parses Get-Printer-Attributes body, replies HTTP 200 + `application/ipp` with printer-attributes-tag advertising a fake Brother HL-L8260CDW (idle, accepting jobs). | — | — |

### TCP — remote access / out-of-band management

These personas reproduce the distinctive Server header + auth realm +
landing page that fingerprints the appliance, capture Basic-auth /
login-form credentials (flagging `<kind>-login-attempt` +
`default-credential-attempt`), and answer the protocol's discovery
handshake where it isn't HTTP.

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `teamviewer` | 5938 | TeamViewer relay hello — reads the client's first frame, replies with the `17 24 …TeamViewer` framing. | — | — |
| `anydesk` | 7070 | AnyDesk relay discovery reply (`ad.anynet.relay <ver>`). | — | — |
| `openvpn` | 1194 | OpenVPN TCP control channel — reads the `P_CONTROL_HARD_RESET_CLIENT` and replies `HARD_RESET_SERVER`; flags `openvpn-probe`. | — | — |
| `citrix_ica` | 1494 | Citrix ICA browser hello (`7f 7f ICA …`). | — | — |
| `intel_amt` | 16992 | Intel AMT / vPro web UI (CVE-2017-5689 surface): HTTP 401 Digest with the `Intel(R) Active Management Technology` Server header. | — | — |
| `ilo` | 443 | HP iLO 5 — `HP-iLO-Server/1.30` Server header + iLO realm. | — | — |
| `idrac` | 443 | Dell iDRAC 9 — `Mbedthis-Appweb` Server header + iDRAC realm (captures the `root/calvin` default). | — | — |
| `esxi` | 443 | VMware ESXi 7.0 host management — `VMware ESXi/7.0.3 Reverse Proxy` + `/ui/` + `/sdk` links. | — | — |
| `fortinet` | 10443 | FortiGate SSL-VPN portal (`/remote/logincheck` form). | — | — |
| `pulse` | 443 | Pulse Secure / Ivanti Connect Secure (`/dana-na/auth/...` form). | — | — |
| `citrix_gateway` | 443 | Citrix Gateway / NetScaler (`/cgi/login` form). | — | — |
| `horizon` | 443 | VMware Horizon view portal (`/portal/webclient/`). | — | — |
| `moxa_mgmt` | 80 | Moxa device web console (`MoxaHttp/1.0`, `/Login.asp` form). | — | — |

### TCP — ICS / OT

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `modbus` | 502 | MBAP multi-PDU parser. Captures `function_code` + `unit_id` + `transaction_id`. Plausible replies for reads (FC 1/2/3/4), writes (5/6/0F/10/16/17 — echoes + captures written values), Report Server ID (11), and the FC 0x2B/MEI Read-Device-Identification probe (nmap modbus-discover → Schneider Modicon M340). Write function codes raise the `modbus-write-attempt` anomaly (ICS T0836/T0831); illegal functions get a Modbus exception. | — | — |
| `s7` | 102 | TPKT (RFC 1006) + COTP parser. Replies to ISO-on-TCP Connection Request (TPDU 0xE0) with Connection Confirm (0xD0) echoing the source/destination references and class options. | — | — |
| `iec104` | 2404 | IEC 60870-5-104 APCI parser. Classifies I/S/U-format frames; replies STARTDT_CON to the standard supervisory probe `0x07`. | — | — |
| `mqtt` | 1883 | CONNECT parser (varint remaining-length capped at 4 KiB). Captures `protocol_name`, `version`, `keepalive`, `client_id`, **`username`**, **`password`**. Replies CONNACK 0x00 connection accepted. | — | — |
| `opcua` | 4840 | OPC UA secure-channel transport. Reads HEL message (`endpoint_url`, send/receive buffer sizes), replies ACK with our limits. Captures the endpoint URL the scanner is reaching for. | — | — |
| `ethernetip` | 44818 | EtherNet/IP encapsulation. Handles RegisterSession (returns session handle) + ListIdentity (advertises a fake Rockwell Allen-Bradley 1756-L73 ControlLogix with identity-shaped serial). | — | ✓ |
| `s7comm_plus` | 102 | S7-1200/1500 S7comm-Plus over TPKT/COTP. Answers the COTP Connection Request with a Connection Confirm, then captures + classifies the first data PDU (S7comm-Plus `0x72` vs classic S7comm `0x32`). | — | — |
| `dnp3` | 20000 | DNP3 (IEEE 1815) data-link responder. Parses the frame (start `05 64`, control function, src/dest) and replies with a LINK_STATUS frame (correct DNP3 CRC) so a scanner records a live outstation. | — | — |
| `ge_srtp` | 18245 | GE-SRTP (GE / Emerson PACSystems / Series 90). Captures the 56-byte request and returns a believable success response; flags the probe. Fingerprint-grade. | — | — |
| `codesys` | 1217 | CODESYS V3 gateway/runtime (WAGO / Beckhoff / Schneider / ABB soft-PLCs). Captures the request + returns a minimal channel ack; flags the probe. Fingerprint-grade. | — | — |
| `atg` | 10001 | Veeder-Root TLS-350 Automatic Tank Gauge (the "internet-exposed gas pump" target; nmap atg-info). Answers `^A`+`I20100`/`I20200`/`I20300` with a believable, per-deployment tank report; captures the command, flags `ics-atg-command`. Report-only. | — | ✓ |
| `fox` | 1911 | Niagara / Tridium Fox (building automation; Shodan's `fox` probe). Emits a per-deployment "fox hello" advertising station name / host id / app+VM+OS versions / brand; captures the client follow-up. | — | ✓ |
| `hartip` | 5094 | HART-IP gateway to process field instruments. Parses the 8-byte header, captures the message type (session-initiate / token-passing PDU), replies with a valid response header. Fingerprint-grade. | — | — |
| `pcworx` | 1962 | Phoenix Contact PCWorx (ILC-class PLCs; nmap pcworx-info). Captures the connect/identify probe and returns an identification frame carrying model (`ILC 330 ETH`) + firmware. Fingerprint-grade. | — | — |

### UDP

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `raw` | any | Records the datagram bytes; optionally writes a static reply. | — | — |
| `snmp` | 161 | gosnmp-backed SNMPv1/v2c decoder. Captures `version`, `community`, requested OID list. When an archetype is set, answers the system group (1.3.6.1.2.1.1.x: sysDescr, sysObjectID, sysName, sysContact, sysLocation, sysServices) and ifTable (1.3.6.1.2.1.2.2.1.x: ifIndex / ifDescr / ifType / ifSpeed / ifPhysAddress / ifOperStatus) from the archetype's MIB-2 view. Unknown OIDs return Null. SNMPv3 rejected. | ✓ | — |
| `ntp` | 123 | NTPv4 mode 3 → mode 4 server reply with echoed origin timestamp + plausible reference / receive / transmit timestamps. **Mode 7 (private / monlist) deliberately silent** — refusing to be an amplifier. | — | — |
| `bacnet` | 47808 | BVLC + NPDU + APDU parser. Replies to Who-Is (service 0x08) with an I-Am (object instance 1234), and to a confirmed **WriteProperty** with a SimpleACK while flagging `bacnet-write-attempt` (a value-change against a control point). Other services captured but unacknowledged. | — | — |
| `tftp` | 69 | RFC 1350 RRQ/WRQ parser. Captures **filename**, **transfer mode**, and **RFC 2347 options** (blksize, tsize, timeout). Always replies ERROR opcode 5 code 2 (Access violation) — never serves files. | — | — |
| `ipmi` | 623 | RMCP ASF Presence Ping → Pong reply with IPMI 1.5 + 2.0 supported-entity flag (the classic "is this a BMC" probe). RMCP+ session-open captured but not answered (no real keying material to fake). | — | — |
| `syslog_udp` | 514 | RFC 3164/5424 datagram parser. Decodes PRI into facility + severity, captures the rest as `message`. | — | — |
| `radius` | 1812 | RADIUS Access-Request parser. Captures `user_name` + the encrypted `user_password_encrypted_hex`. Replies Access-Reject (code 3) with the original Identifier. | — | — |
| `sip` | 5060 | SIP-over-UDP. Parses request line + headers, captures `method`, `from`, `to`, `call_id`, `cseq`, `via`, `user_agent`, `authorization`. Replies SIP 200 OK with an Asterisk-shaped Server header. | — | — |
| `ssdp` | 1900 | UPnP M-SEARCH parser. Captures `st` (search target), `host`, `mx`, `user_agent`. Replies HTTP/1.1 200 with a TP-Link-shaped `LOCATION` + `USN` so the scanner records a router on the segment. | — | — |
| `cldap` | 389 | CLDAP SearchRequest parser. Replies searchResDone; when honeynet topology is available, advertises the configured Domain Controllers in the meta. | — | — |
| `llmnr` | 5355 | LLMNR query parser. Replies with our local IP as the A-record — classic poisoning catcher for the common Windows lookup-fallback target `wpad`. | — | — |
| `nbns` | 137 | NetBIOS Name Service query parser. Decodes the encoded NetBIOS name; replies positive name-query response — catches SMB-relay precursors. | — | — |
| `fins` | 9600 | Omron FINS UDP frame parser. Answers CPU-data-read (`CJ2M-CPU33`), CPU-status-read (RUN/MONITOR), memory-area-read (with decoded area name + believable PV data), cycle-time-read, clock-read; generic ACK otherwise. | — | — |
| `coap` | 5683 | RFC 7252 GET parser with bounds-checked option-TLV walker. Extracts `Uri-Path` + token; flags malformed packets. Replies 2.05 Content with a `/.well-known/core` link-format body advertising one fake `/led` resource. | — | — |
| `knx` | 3671 | KNXnet/IP. Replies to SEARCH_REQUEST (0x0201) with a SEARCH_RESPONSE advertising an "MDT KNX IP Router" device-info DIB + a supported-service-families DIB (CORE, DEV_MGMT, TUNNELLING, ROUTING). DESCRIPTION_REQUEST gets a DESCRIPTION_RESPONSE. CONNECT_REQUEST gets status `0x24` (no more connections) so we look live without opening a tunnel. | — | — |
| `dhcp` | 67 | **Passive** DHCP observer — never hands out leases. Parses broadcast DISCOVER/REQUEST/INFORM, captures the client MAC, hostname (opt 12), vendor class (opt 60), requested IP (opt 50), and the option-55 parameter-request-list as a fingerbank-style DHCP fingerprint. Feeds the learned-device registry. | — | — |
| `dns` | 53 | Resolving DNS server. Answers `A`/`AAAA`/`MX`/`TXT`/`NS`/`CNAME` with fabricated, **deterministic-per-deployment** records (same name → same fake IP within a sensor, avoiding RFC1918/loopback so it looks like a real internet host); unsupported qtypes get NOERROR/0-answers. Captures `qname`/`qtype` and runs every query through tunneling/exfil detection (overlong qname, high-entropy labels, TXT/NULL tunneling qtypes, oversize query). | — | ✓ |

### Small services (TCP + UDP)

RFC 862-868 + 1340. Trivial, but heavily probed — and `chargen`/`echo`
are classic UDP reflection/amplification targets, so the honeypot
exposes them **without** ever amplifying: each replies with at most one
bounded datagram and `echo` never returns more than it received.

| Handler | Port | What it does |
|---|---|---|
| `echo` | 7 | Echoes received bytes back **once**, 1:1, capped (TCP: single bounded read+echo; UDP: ≤ request size). Captures `echoed_bytes`. |
| `discard` | 9 | Reads and drops; never replies. Captures `discarded_bytes`. |
| `daytime` | 13 | Sends the RFC 867 human-readable timestamp and closes. |
| `qotd` | 17 | Sends a single fixed quote (RFC 1340) and closes. |
| `chargen` | 19 | Sends **exactly one** bounded 72-char line + CRLF and stops (a real chargen streams forever — we don't). The UDP probe is flagged `udp-amplifier-probe`. |
| `time` | 37 | Sends the RFC 868 4-byte seconds-since-1900 timestamp. |

### ICMP (responder + detection)

ICMP isn't a bind-mode listener (the kernel owns raw ICMP), so it's
handled by a Linux AF_PACKET **responder** plus a protocol-anomaly
layer rather than a `handler:` you wire to a port. Enable it per
honeynet with `icmp_responder.enabled: true` (needs `CAP_NET_RAW`).

| Capability | What it does |
|---|---|
| Echo / timestamp / address-mask responder | Answers type 8→0 (echo), 13→14 (timestamp), 17→18 (address-mask) for every virtual host IP, sourced from that host's deterministic MAC + IP so `ping` / `nmap -sn` see a populated network. |
| **Per-host ICMP TTL personality** | Each reply is stamped with the host archetype's characteristic initial IP TTL — **255** (OT / network gear), **128** (Windows), **64** (Linux/BSD) — so passive OS fingerprinting and traceroute hop-distance estimation stay consistent with the rest of the host's fingerprint. |
| Full ICMP message family (`internal/icmp`) | Builders + tests for Destination-Unreachable, **Fragmentation-Needed with next-hop MTU** (PMTUD), **Time-Exceeded** (traceroute hops), Parameter-Problem, Redirect, plus IPv6 Echo / Neighbor-Advertisement / Router-Advertisement (NDP) — the toolkit the responder and TUN adapter draw on. |
| Abnormal-payload detection (`internal/icmp.Anomalies`) | Flags `icmp-oversize-payload`, `icmp-payload-nonzero-entropy` (tunneling — e.g. Loki / icmpsh), `icmp-frag-abuse` (teardrop / overlapping-fragment IDS evasion), and `icmp-frag-tiny`. Windows-ping filler (the `abcdef…` pattern) is recognized as benign. |
| Ping-sweep correlation | `correlate.icmp_sweep` fires `correlate:icmp_sweep` when one source pings N distinct virtual IPs inside a window — see [Detection coverage](#detection-coverage). |

> **Note:** the abnormal-payload markers are evaluated in the responder
> and logged to the structured `slog` stream; the bus-level
> `correlate:icmp_sweep` event keys off ICMP echo observations. Raw
> half-open / fragmented ICMP that never reaches the responder still
> needs the AF_PACKET sniffer.

## Tarpit strategies

| Strategy | Behavior | Knobs |
|---|---|---|
| `sticky` | Accept and never read/write. Kernel TCP keepalive will eventually notice dead peers. | — |
| `trickle` | Write one byte of the configured `tarpit.trickle.text` every `byte_interval`. Cycles the string forever. | `trickle.text`, `trickle.byte_interval` |
| `keepalive` | Write a NUL byte every `tarpit.keepalive.interval`. Cheapest option. | `keepalive.interval` |

Connection caps bound resource use: `tarpit.max_per_source` limits
concurrent held connections from one IP and `tarpit.max_total` caps the
global tarpit slot pool.

```yaml
listeners:
  - id: ssh-tarpit
    proto: tcp
    bind: 0.0.0.0:2222
    mode: tarpit
    severity: high
    tarpit:
      strategy: trickle          # sticky | trickle | keepalive
      max_per_source: 4
      max_total: 256
      emulate: false             # true = run handler: first, then tarpit
      trickle: { text: "Loading...\n", byte_interval: 2s }
      keepalive: { interval: 30s }
```

All tarpit modes emit a `*:tarpit_start` event (at the listener's
configured severity) when the slot is acquired, and a `*:tarpit_end`
event (at `low` severity, with `duration_ms` in meta) when the
connection terminates. When the per-source or total cap is hit, a
`*:tarpit_drop` event fires instead.

**Emulate-then-tarpit**: set `tarpit.emulate: true` and the listener
runs its protocol `handler:` first — sending the real banner and
capturing the attacker's request — *then* applies the tarpit strategy
on the same connection. The scanner gets a believable SSH / HTTP /
Modbus service, then hangs; the captured banner/request lands in the
`tarpit_start` event (`tarpit_emulated_handler` in meta). This turns
any protocol emulator into a tarpit.

## Detection coverage

Beyond per-listener events, the sensor fires aggregate / token events:

- `correlate:port_scan` — same source touched N distinct ports within a
  configurable window.
- `correlate:brute_force` — same source touched the same port N times in
  the window (optionally per-port). Aggregate meta carries the deduped
  `credentials` array extracted from the contributing events.
- `correlate:password_spray` — same source tried N **distinct usernames**
  in the window (low attempts each): the breadth signal, the inverse of
  brute force. Meta carries `usernames` + `distinct_users`. Tagged
  `T1110.003`.
- `correlate:credential_reuse` — the **same** credential pair was tried
  from N **distinct source IPs** in the window — a shared credential list /
  botnet (credential stuffing). Meta carries `username` + `distinct_sources`
  + `sources`; the password is never logged. Tagged `T1110.004`.
- `risk:elevated` / `risk:high` / `risk:critical` — a source's **decaying
  threat score** (`risk:` config) crossed a threshold. Every event adds
  severity/category-weighted points (CVE / malware / storyline weigh
  heaviest); the score halves over `half_life` of silence so quiet sources
  cool off. Meta carries `score` + `trigger_rule`; the top scorers surface
  in the web UI's `/risk` view. Fires once per escalation.
- **Operational alarms** (`sensor.alerts`): `sensor:started` / `sensor:stopped`
  (lifecycle, always on), `sensor:health` (data_dir disk crossing
  `disk_warn_percent` with hysteresis, or sinks dropping events — always
  on), `source:first_seen` (a source's first ≥ medium event, opt-in,
  deduped), and `sensor:digest` (periodic summary of totals by severity +
  top rules + top risk sources, opt-in via `digest_interval`).
- `correlate:slow_scan` — long-window scan detector (default 24h /
  10 distinct ports). Meta includes `first_seen`, `last_seen`,
  `spread_seconds`, `ports`.
- `correlate:icmp_sweep` — one source pinged N distinct virtual host
  IPs inside `correlate.icmp_sweep.window`. Tagged `T1018` (remote
  system discovery).
- `scananalysis:profile` — per-source nmap fingerprint once a source
  crosses the confidence threshold. Meta: `timing_profile` (`-T0`..
  `-T5`), `distinct_ports`, `connections`, `version_scan` (`-sV`),
  `os_scan` (`-O`), `aggressive` (`-A`), `nse_scripts`. Tagged
  `T1595` (active scanning) + `T1046` (network-service discovery).
- `storyline:multi_stage` — one source touched 3+ distinct ATT&CK
  tactics in a 30-minute window. Meta carries the kill-chain-ordered
  stage list + a `"->"`-joined chain summary, so the SOC sees one
  timeline instead of dozens of independent listener hits.
- `device:new` — a previously-unseen, non-allow-listed host appeared on
  the segment (learned-device registry). Meta: `device_ip`,
  `device_mac`, `device_vendor` (MAC-OUI lookup), `device_hostname`.
  Tagged `T1018`. See [`devices`](#devices) config.
- `cve:<id>` — a known-CVE exploit signature appeared in a request
  (e.g. `cve:CVE-2021-44228`). CVSS-scaled severity (>=9.0 → critical);
  meta carries `cve_name`, `cvss`, `description`. Detection only — the
  service is never actually exploitable.
- `malware:capture` — a binary / script / shellcode / base64 dropper was
  harvested from captured bytes. Meta: `artifacts` (kind:sha256), markers;
  the artifact is persisted to `<data_dir>/payloads/`. Tagged T1105+T1027.
- `webshell-access-attempt` / `webshell-command` — the HTTP handler saw a
  request for a known web-shell filename (c99/r57/wso/b374k/China-Chopper)
  or a command parameter (`?cmd=`, POST `cmd=`). The submitted command is
  captured (`webshell_cmd` meta) and TTP-scanned. With `vuln_emulation` on
  the handler serves a believable fake shell (canned output, never
  executed) so the attacker reveals recon commands.
- `protocol_anomaly` / `event.anomalies` — handler-flagged protocol
  misuse (SSH non-printable / overlong banners, HTTP unknown methods +
  suspicious URIs, DNS tunneling shapes, ICMP abnormal payloads, the
  14-marker interactive-shell TTP scanner). Routed separately so a SIEM
  rule can pivot on the marker.
- `dnscanary:amplifier_probe` — DNS source sent an ANY-type query or
  exceeded the per-window query threshold. Meta: `queries`,
  `any_queries`, `triggered_by_any`.
- `canary:<id>` — file canary (fsnotify path or fanotify-detected read).
- `canary:url:<id>` — URL canary path matched by an HTTP/HTTPS handler.
- `canary:dns:<id>` — DNS canary name (or subdomain) queried.
- `dnscanary:query` — every DNS query received (baseline noise floor).
- `sniffer:arp_scan` — ARP request flood from one MAC.
- `sniffer:arp_reply_unsolicited` — ARP reply with no preceding request
  (possible cache poisoning).
- `listener:*:tarpit_start|tarpit_end|tarpit_drop` — tarpit lifecycle.

## Outbound channels

| Type | Notes |
|---|---|
| `stdout` | JSON-per-line. Always-on. Local. |
| `jsonlog` | Rotated JSONL under `<data_dir>/events/`. Total size capped via `disk.json_log_mb`. Local. |
| `sqlite` | Embedded SQLite at `<data_dir>/events.db`. WAL mode. Powers `list-events` and the web UI. Local. |
| `webhook` | POST JSON event. Optional HMAC-SHA256 signature via `hmac_secret_env`. Configurable timeout. |
| `smtp` | Submits via STARTTLS with PLAIN auth. One mail per event. |
| `syslog` | `local`/`udp`/`unix` use BSD framing (stdlib); `tcp` and `tls` use **RFC 5424 + RFC 6587 octet-counting** (the framing RFC 5425 mandates for syslog/TLS) with reconnect-on-failure. TLS verifies against the system roots unless `ca_cert_file` / `tls_insecure` / `tls_server_name` are set. |
| `discord` | Posts a severity-colored embed to a Discord incoming-webhook `url` (or `url_env` to keep the token out of YAML). Embeds suppress @mentions and meta is sanitized, so a captured payload can't ping a channel. |
| `twilio` | SMS via Twilio REST. One SMS per recipient; failures don't block others. Body capped at 1500 chars. |
| `sns` | AWS SNS Publish via hand-rolled Sigv4 (no AWS SDK). Supports STS session tokens. Region inferred from topic ARN if not set. |
| `snmptrap` | SNMPv2c trap via gosnmp. Five custom OIDs under a configurable enterprise prefix carry event_id / rule_id / severity / source / sensor. |
| `mqtt` | Publishes each event to an MQTT broker (`tcp://` / `tls://` / `ws://` / `wss://`); `tls://` honors `ca_cert_file` / `tls_insecure` / `tls_server_name`. Configurable `topic` / `qos` / `retain`. |

Local sinks always receive events (so the on-disk record stays complete
even for allowlisted sources). Outbound sinks are gated by allowlist,
dedup, per-channel rate limit, and min-severity.

## Per-event pcap capture

Set `capture: true` on any TCP listener (`drop` mode excluded; nothing to
capture). Each completed connection produces
`<data_dir>/captures/<event_id>.pcap`. The pcap uses DLT_RAW (link-type
101) with synthesized IPv4 + TCP headers and tracked sequence numbers,
so Wireshark's "Follow TCP" reconstructs the application-layer stream.

We do NOT touch raw sockets — every byte comes from a tee'd `net.Conn`
in the application-layer goroutine. That means we miss SYN/FIN handshakes
and retransmits, but we don't need `CAP_NET_RAW` and the binary stays CGO-free.

Two size caps prevent runaway disk use:
- `sensor.disk.capture_kb` — per-session truncation threshold (default 64 KB).
- `sensor.disk.pcap_mb` — total captures directory cap with oldest-first
  rotation (default 1024 MB).

Captures truncated at the per-session cap get `capture_truncated: true`
in event meta.

## Web UI

Enabled via `ui.enabled: true`. Default bind `127.0.0.1:8088`.

Endpoints:

- `/` — last-24h summary: total + by severity + top rules + top sources.
- `/events` — filterable table: `?source=`, `?rule=`, `?severity=high`,
  `?since=24h`, `?limit=N`. Click a column header (time / severity / rule
  / source / handler) to sort; click again to reverse (`?sort=&order=`).
- `/events/<id>` — full event detail with banner sent, base64 payload,
  meta table, plus download links for the connection **pcap**, the
  **session recording** (asciinema cast, when present), and an "all pcaps +
  sessions from this source IP" ZIP.
- `/pcap/<id>` / `/session/<id>` — download one event's recorded capture /
  session cast.
- `/download?source=&rule=&since=&what=pcap|session|all` — stream a ZIP of
  every matching event's pcaps and/or session casts (e.g. everything from a
  single source IP). The events list links the current filter to it.
- `/hosts?q=&status=` — learned hosts (IPv4/IPv6/MAC), filterable by
  substring + allow/seen status.
- `/topology` — the virtual networks / hosts / services the sensor
  presents (rendered from the resolved honeynet topology).
- `/alerting` — how events are forwarded (channels + destinations,
  routes, allowlist).
- `/errors?since=` — operational / health events (listener or
  canary-watcher stopped, listener start error, accept-cap overflow).
- `/config` — the effective post-defaults config (secrets shown as
  `*_env` names, never expanded values).
- `/docs` — built-in reference that reflects the running deployment.
- `/api/events`, `/api/summary`, `/api/config`, `/api/topology`,
  `/api/hosts`, `/api/alerting` — JSON equivalents.
- `/metrics` — Prometheus text-format (see [Prometheus metrics](#prometheus-metrics)).
- `/healthz` — auth-bypass liveness check.

Security headers (`Content-Security-Policy: default-src 'none'`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`) are set on
every response. Bearer-token auth via `auth_token_env`. Non-loopback
binds are rejected at validate-time without both TLS and auth.

## systemd integration

A hardened unit lives at `packaging/systemd/tarpit-honeypot.service`. It
runs as user `tarpit:tarpit` with `AmbientCapabilities=CAP_NET_BIND_SERVICE
CAP_NET_RAW`, `NoNewPrivileges=true`, `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp/Devices=true`, and
`RestrictNamespaces=true`. `ExecReload=/bin/kill -HUP $MAINPID` ties into
the hot-reload path.

Install pattern:

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tarpit
sudo install -o root -g root -m 0755 bin/tarpit-honeypot /usr/local/bin/
sudo install -d -o tarpit -g tarpit -m 0750 /var/lib/tarpit-honeypot
sudo install -d -o root  -g root  -m 0755 /etc/tarpit-honeypot
sudo install -o root -g root -m 0640 configs/tarpit-honeypot.example.yaml /etc/tarpit-honeypot/config.yaml
sudo install -o root -g root -m 0644 packaging/systemd/tarpit-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tarpit-honeypot
```

## Operating model

- Single static binary, no daemons-of-daemons.
- Internal channels for the event bus; per-sink worker goroutines with
  bounded queues (depth 256). One slow sink can't back-pressure the
  listeners.
- All durable state lives under `sensor.data_dir`:
  ```
  <data_dir>/
    events.db                # SQLite index (if sqlite sink or UI enabled)
    events/events-*.jsonl    # rotated JSON-lines (if jsonlog sink enabled)
    captures/<event_id>.pcap # per-event pcaps (if any listener has capture: true)
    tls/<sni>.crt|.key       # cached self-signed HTTPS certs
  ```
- Allowlisted source IPs short-circuit outbound dispatch but local sinks
  still record — you keep a complete forensic trail without paging your
  on-call for every internal scanner.

## Dependencies

External dependencies, all pure-Go:

- `gopkg.in/yaml.v3` — config parsing
- `github.com/fsnotify/fsnotify` — filesystem canaries
- `modernc.org/sqlite` — pure-Go SQLite (no CGO)
- `github.com/gosnmp/gosnmp` — SNMP encode/decode for the handler + trap sink
- `golang.org/x/sys/unix` — AF_PACKET sniffer and fanotify

No CGO. No `libpcap`. No AWS SDK. No Twilio SDK.

## Tests

```
make test
```

Coverage includes:

- `event`: severity JSON round-trip + numeric tolerance.
- `filter`: allowlist CIDR/IP matching, dedup window expiration, token-
  bucket rate-limit burst + refill.
- `config`: `SeverityMatches` operator parsing; UI loopback / non-loopback
  validation.
- `correlate`: port-scan threshold + window reset + aggregate dedup,
  brute-force per-port, disabled-correlator no-op.
- `router`: local-vs-outbound dispatch, allowlist outbound-only, dedup
  outbound-only, min-severity gate, severity-match routing.
- `store`: insert/query round-trip with all filters, Get, Summary
  breakdown.
- `capture`: pcap header bytes + record count + total-directory rotation.
- `handlers`: SSH banner echo, HTTP request capture + URL canary hit/miss,
  Modbus read-holding-registers + exception path, MQTT CONNECT with creds,
  S7 connection-confirm, IEC-104 STARTDT_CON, NTP mode-3 echo + mode-7
  silence, SNMP v2c GetRequest round-trip, OPC-UA HEL→ACK with endpoint
  capture, EtherNet/IP RegisterSession + ListIdentity, BACnet Who-Is →
  I-Am + non-Who-Is silence, TFTP RRQ → ERROR with filename capture,
  SMB1 Negotiate roundtrip + SMB2 STATUS_NOT_IMPLEMENTED rejection.
- `dnscanary`: name + qtype parsing, NXDOMAIN shape, subdomain matcher.
- `sink/awssns`: Sigv4 determinism + body-sensitivity + region extraction.

## Client fingerprinting

**TLS** — both fingerprints are emitted on every HTTPS connection:

- `ja3` — md5 of the JA3 string built from version + cipher list + ext
  list + supported_groups + ec_point_formats, with GREASE filtered.
- `ja4` — newer variant designed to survive extension shuffling.
  Emitted as `t13d{nC}{nE}{alpn}_{cipherHash}_{extHash}` format.
- `ja3_raw` — the pre-hash string, for ad-hoc grouping.

**HTTP** — both `http` and `https` handlers compute JA4H from the
request line + sorted-header-list + sorted-cookie-list:

- `ja4h` — first 24 hex of sha256 of the JA4H string.
- `ja4h_raw` — the JA4H string itself
  (`t<v>h<method><n_hdrs><c>_<header_hash>_<cookie_field_hash>_<cookie_value_hash>`).

**SSH** — the handler captures one binary packet after the banner and
computes:

- `hassh` — md5 of `kex_algs;encryption_algs_c2s;mac_algs_c2s;compression_algs_c2s`.
- `hassh_algorithms` — the unhashed semicolon-joined raw form.

Caveat: HASSH relies on the SSH client sending its KEXINIT before the
server. OpenSSH does this by default; some scanners don't.

**Tool / scanner identification** (`internal/toolfp`) — beyond the
cryptographic fingerprints above, the HTTP/HTTPS **and SSH** handlers
classify the *tool* behind a connection:

- `meta.tools` (HTTP) — names matched from ~80 User-Agent + request-path
  signatures across: port scanners (nmap, masscan, zmap, zgrab, l9explore);
  internet-wide recon engines (Shodan, Censys, BinaryEdge, LeakIX,
  Onyphe, Shadowserver, Stretchoid, ProjectDiscovery, …); web vuln
  scanners (sqlmap, nikto, nuclei, Acunetix, Nessus, OpenVAS, Qualys,
  Netsparker/Invicti, AppScan, Arachni, Wapiti, WhatWeb, OWASP ZAP,
  Burp, wpscan/joomscan/droopescan, commix, XSStrike); content-discovery
  fuzzers (gobuster, ffuf, dirsearch, feroxbuster, wfuzz, katana, httpx);
  credential brute-forcers (hydra, medusa, ncrack, patator); exploitation
  frameworks + webshell managers (Metasploit, Cobalt Strike, AntSword,
  Behinder, Godzilla); and generic HTTP libraries (Go, python, java,
  node, ruby, php, powershell, curl, wget). Path signatures also flag
  named-CVE probes (Log4Shell, PHPUnit CVE-2017-9841, FortiOS
  CVE-2018-13379, WebLogic CVE-2017-10271, Citrix/Pulse/Exchange/Confluence
  exploit paths) even when the UA is spoofed.
- `meta.tools` (SSH) — `IdentifySSH` maps the clear-text SSH client banner
  to libssh (hydra/scanners), libssh2, paramiko, Go, PuTTY, zgrab, JSch,
  phpseclib, WinSCP, … (OpenSSH excluded as legitimate-default noise).
- `meta.automation` — a browser-vs-script verdict from header shape
  (missing `Accept`/`Accept-Language`, scripted ordering, etc.).
- A JA3 hash can also map to a known scanner via `IdentifyTLS`.
- Surfaced as `tool:<name>` and `automation-client` anomalies so a SIEM
  can separate hand-driven probes from mass scanners.

## Honeynets

One sensor can host an entire artificial network. The `honeynets:`
config block declares zero or more virtual networks, each with a CIDR,
gateway, DNS, domain, and a list of virtual hosts. Each host has an
IP, hostname, OS hint, and a list of `{port, handler}` services.

### How dispatch works

1. The OS must actually route the virtual IPs to the sensor. On Linux
   that's typically:
   ```
   ip addr add 10.99.0.10/24 dev eth0
   ip addr add 10.99.0.11/24 dev eth0
   ...
   ```
   Or a bridge + NAT or a TUN device. The sensor itself doesn't
   manipulate interfaces — it expects the kernel to deliver SYNs for
   the virtual IPs to a real socket it has bound.

2. The sensor's `listeners:` block must bind `0.0.0.0:<port>` for
   every port any virtual host serves. A single SSH listener bound to
   `0.0.0.0:22` handles all virtual SSH hosts across all honeynets.

3. On `accept()`, the listener inspects the destination IP and looks
   it up in the topology. If it matches a virtual host with a service
   on this port, dispatch goes to a per-host handler instance whose
   Identity is `sensor.deployment_id` derived through
   `honeynet/<network_id>/<host_ip>`. That means each virtual machine
   has its own stable-but-unique banner from the variant pool — two
   virtual hosts on the same listener present as different OpenSSH
   versions, different MySQL builds, different SMB session keys, etc.

4. Emitted events carry `honeynet`, `honeynet_host`,
   `honeynet_hostname`, `honeynet_os` in meta so downstream sinks can
   group / route by virtual machine identity.

### Example

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    gateway: 10.99.0.1
    dns: 10.99.0.2
    domain: corp.example.local
    hosts:
      - ip: 10.99.0.10
        hostname: web-prod-01
        os: linux
        services:
          - { port: 22,  handler: ssh }
          - { port: 80,  handler: http }
          - { port: 443, handler: https }
      - ip: 10.99.0.20
        hostname: dc-01
        os: windows
        services:
          - { port: 88,   handler: kerberos }
          - { port: 389,  handler: ldap }
          - { port: 445,  handler: smb }
          - { port: 3389, handler: rdp }

  - id: ot-cell-A
    cidr: 10.99.5.0/24
    hosts:
      - ip: 10.99.5.50
        hostname: plc-press-01
        os: ics
        services:
          - { port: 102, handler: s7 }
          - { port: 502, handler: modbus }
```

`tarpit-honeypot list-honeynets -c cfg.yaml` prints the topology with
each host's derived identity seed so you can confirm uniqueness:

```
# corp-lan  cidr=10.99.0.0/24 gateway=10.99.0.1 dns=10.99.0.2 domain=corp.example.local
  10.99.0.10  hostname=web-prod-01  os=linux  identity=<seed>/honeynet/corp-lan/10.99.0.10
    :22  handler=ssh
    :80  handler=http
    :443 handler=https
  10.99.0.20  hostname=dc-01        os=windows ...
```

### ARP responder (Linux)

Enable per-honeynet `arp_responder.enabled: true` to make the virtual
network discoverable on the L2 segment without `ip addr add`. The
sensor opens an AF_PACKET socket on the configured interface
(`arp_responder.interface`; empty = first non-loopback interface),
filters for ARP requests, and replies with the requested virtual
host's deterministic MAC.

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    arp_responder:
      enabled: true
      interface: eth0
    hosts:
      - { ip: 10.99.0.10, hostname: web-prod-01, ... }
      - { ip: 10.99.0.20, hostname: dc-01, ... }
```

Each host's MAC is `sha256(deployment_id || "mac" || host_seed)[:6]`
with the locally-administered bit set (`0x02`) and the multicast bit
cleared. `tarpit-honeypot list-honeynets` prints the MAC alongside
the IP so an operator can confirm uniqueness:

```
# corp-lan  cidr=10.99.0.0/24 ...
  10.99.0.10  mac=3e:04:45:bb:fb:79  hostname=web-prod-01  os=linux ...
  10.99.0.20  mac=5e:1f:7d:3d:8b:08  hostname=dc-01        os=windows ...
```

**Limitation:** ARP responding alone is L2 discovery. To route TCP /
UDP traffic for the virtual IPs into the sensor's real sockets, the
operator still needs `ip addr add` or iptables redirection (or a
TUN-based adapter — planned for v1.3). Without that, scanners running
`arp-scan` see a populated network but TCP probes get nowhere.

### ICMP echo responder (Linux)

Pair `arp_responder.enabled: true` with `icmp_responder.enabled:
true` and the virtual hosts respond to ping as well as showing up in
`arp-scan`. Same AF_PACKET pattern + `CAP_NET_RAW` requirement.

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    arp_responder:
      enabled: true
      interface: eth0
    icmp_responder:
      enabled: true
      interface: eth0       # empty = first non-loopback up iface
    hosts: [...]
```

The reply is built at L2 with the virtual host's deterministic MAC
as source, the virtual host IP as the source IP, and the same
ICMP identifier+sequence as the request so the requester's `ping`
matches up. Same caveat as the ARP responder: this makes the host
visible to scanners, but TCP/UDP traffic for the virtual IP still
needs `ip addr add` or iptables redirection.

### Per-honeynet routing

Routes can match on event meta as well as severity. Use this to fan
out per-virtual-network, per-OS-family, or per-rule-id channels:

```yaml
channels:
  - id: ot-pagerduty
    type: webhook
    url: https://events.pagerduty.com/...
  - id: corp-soc
    type: smtp
    ...

routes:
  - match: { severity: ">=critical", honeynet: "ot-cell-A" }
    channels: [ot-pagerduty]
  - match: { severity: ">=high", honeynet_os: "windows" }
    channels: [corp-soc]
  - match: { severity: ">=low" }
    channels: [stdout, jsonlog, sqlite]
```

`Match` fields are AND-ed. Add multiple routes for OR semantics. The
recognized fields are `severity`, `honeynet`, `honeynet_os`, and
`rule_id`.

### DNS forward-resolution

When at least one honeynet is configured AND `dns.enabled: true`, the
DNS canary listener answers A queries for honeynet hostnames with the
matching virtual IP. The listener still emits the baseline
`dnscanary:query` event for every query and the
`canary:dns:<id>`/`dnscanary:amplifier_probe` events as before — the
honeynet resolution is layered on top of NXDOMAIN, not instead of it.

```
$ dig @127.0.0.1 -p 5354 web-prod-01.corp.example.local A +short
10.99.0.10
```

### Counter-fingerprinting

Three knobs make the sensor harder to identify as a honeypot:

### `sensor.deployment_id`

A stable random seed (auto-generated on first run, persisted at
`<data_dir>/.deployment-id`) that deterministically derives every
otherwise-fixed string the sensor emits:

| Surface | Without identity (v0.8 default) | With identity |
|---|---|---|
| SSH banner | `OpenSSH_8.4p1 Debian-5+deb11u1` | one of 6 variants (8.2/8.4/8.9/9.2/9.6/...) |
| HTTP `Server:` | `nginx/1.18.0` | one of 6 (nginx/apache/IIS variants) |
| MySQL version | `5.7.42-honeypot` | one of 5 plausible versions |
| SMTP hostname | `mail.example.com` | `<prefix>NN.example.internal` |
| SMB session key | `0xdeadbeef` | 32 random bits |
| SMB challenge | `11 22 33 44 55 66 77 88` | 8 random bytes |
| VNC challenge | fixed 16 bytes | 16 random bytes |
| EtherNet/IP serial | `0xdeadbeef` | random 32-bit |

Two deployments with different seeds present distinct fingerprints to
Shodan-class scanners. Override via `sensor.deployment_id: "..."` in the
config or rely on auto-generation.

### `sensor.jitter`

Every handler reply sleeps a random `[min_ms, max_ms]` interval before
writing. Defeats microsecond-identical-latency scanner heuristics.
Default disabled; enable with `enabled: true`.

### `sensor.tls_rotate.days`

The auto-generated self-signed HTTPS cert regenerates if older than
this many days. Stops a long-running sensor from leaking a stable
SNI cert hash. Default `0` = never rotate (v0.8 behavior).

## Docker

```
docker build -t tarpit-honeypot:latest .
docker run --rm \
  -p 2222:2222 -p 8000:8000 -p 8088:8088 \
  -v $PWD/var:/var/lib/tarpit-honeypot \
  -v $PWD/configs/tarpit-honeypot.example.yaml:/etc/tarpit-honeypot/config.yaml:ro \
  tarpit-honeypot:latest
```

Final image is a `scratch` base + the static binary + ca-certificates +
a non-root user (uid 65532). About 14 MB total. The container's binary
is built with the same `CGO_ENABLED=0` and `-trimpath` as the host
`make build`.

Privileged ports (53, 88, 102, 110, 135, 161, 389, 445, 502, 623, 636,
2049, 5432, ...) still need either `--user 0` or a host capability
grant; for production, the systemd path with `AmbientCapabilities` is
usually cleaner.

## Output formats

Every event-shaped sink (`stdout`, `jsonlog`, `webhook`, `smtp`, `syslog`)
accepts an optional `format:` field. The default is `json` (legacy
behavior). Three SIEM-friendly alternatives ship:

| Format | Use for | Wire shape |
|---|---|---|
| `json` | Generic JSON consumers, web UI / `list-events` | Full event JSON |
| `cef` | ArcSight | `CEF:0\|tarpit-honeypot\|tarpit\|1.4\|<rule_id>\|<name>\|<sev0-10>\|<ext>` |
| `leef` | QRadar | `LEEF:2.0\|tarpit-honeypot\|tarpit\|1.4\|<rule_id>\|<tab><k=v>...` |
| `ocsf` | Snowflake, Athena, AWS Security Lake | JSON shaped as OCSF Network Activity (class_uid=4001) |

Example:

```yaml
channels:
  - id: jsonlog
    type: jsonlog
    format: json              # default — also writes to events-*.jsonl
  - id: siem-arcsight
    type: syslog
    network: tcp
    address: arcsight:514
    format: cef
  - id: siem-qradar
    type: syslog
    network: tcp
    address: qradar:514
    format: leef
  - id: lake-aws
    type: webhook
    url: https://lake.example.com/ingest
    format: ocsf
```

CEF severity maps low=2, medium=5, high=7, critical=10. OCSF
severity maps low=2, medium=3, high=4, critical=5 (Informational(1) is
unused). Meta keys flow into:

- CEF: `cs1..cs6` slots with their original key in `cs1Label..cs6Label`.
- LEEF: `meta_<key>=<value>` extension keys.
- OCSF: the `unmapped` object (catch-all for honeynet / fingerprint /
  handler-specific keys without a dedicated OCSF slot).

Sinks that aren't event-shaped — `sqlite` (structured rows), `twilio`
(SMS body), `sns` (AWS Publish), `snmptrap` (PDU) — reject non-json
`format:` at validate time.

## Enrichment

When configured, the sensor decorates every event's meta with
location and identity hints for the **source IP** before the
correlator runs. Aggregate events (port_scan / brute_force / slow_scan)
inherit the enrichment without extra lookups.

```yaml
sensor:
  geoip:
    city_db: /var/lib/GeoLite2-City.mmdb
    asn_db:  /var/lib/GeoLite2-ASN.mmdb
  rdns:
    enabled: true
    timeout: 500ms
    cache_size: 1024
```

Both GeoIP paths are optional — configure one or both. The .mmdb files
must be supplied by the operator (MaxMind's GeoLite2 license restricts
redistribution).

Loopback, link-local, and RFC 1918 / RFC 4193 private addresses are
**not** enriched — they don't have meaningful geolocation, and the
rDNS lookup would either hang or return an unhelpful internal name.

Enrichment keys added to event meta:

| Key | From | Example |
|---|---|---|
| `geo_country` | city db | `RU` |
| `geo_country_name` | city db | `Russia` |
| `geo_city` | city db | `Moscow` |
| `geo_lat`, `geo_lon` | city db | `55.7522, 37.6156` |
| `asn` | asn db | `13335` |
| `asn_org` | asn db | `Cloudflare, Inc.` |
| `rdns` | resolver | `host.example.adsl.com` |

## Prometheus metrics

With `ui.enabled: true` the web UI exposes `/metrics` in Prometheus
text-format (v0.0.4). Same auth model as the rest of the UI: bearer
token if `auth_token_env` is set, loopback-only otherwise.

Exposed metrics:

```
# HELP tarpit_sink_dropped_total Events dropped because the sink in-channel was full
# TYPE tarpit_sink_dropped_total counter
tarpit_sink_dropped_total{channel="ops-webhook"} 0
tarpit_sink_dropped_total{channel="jsonlog"} 0

# HELP tarpit_sink_failed_total Events that exhausted the retry backlog and were lost
# TYPE tarpit_sink_failed_total counter
tarpit_sink_failed_total{channel="ops-webhook"} 0

# HELP tarpit_sink_retried_total Events delivered on retry after a transient sink error
# TYPE tarpit_sink_retried_total counter
tarpit_sink_retried_total{channel="ops-webhook"} 0

# HELP tarpit_honeynet_networks Number of configured honeynets
# TYPE tarpit_honeynet_networks gauge
tarpit_honeynet_networks 2

# HELP tarpit_honeynet_hosts Number of configured virtual hosts across all honeynets
# TYPE tarpit_honeynet_hosts gauge
tarpit_honeynet_hosts 8

# HELP tarpit_store_db_bytes On-disk size of the SQLite events.db
# TYPE tarpit_store_db_bytes gauge
tarpit_store_db_bytes 32768
```

Sample Prometheus scrape:

```yaml
- job_name: tarpit-honeypot
  bearer_token_file: /etc/secrets/tarpit-ui-token
  scrape_interval: 30s
  static_configs:
    - targets: ['sensor.example.internal:8088']
```

## What's NOT in v1.5

- **Windows service registration.** The binary will run on Windows but
  there's no SCM integration yet.
- **fanotify on Windows.** ETW-based read detection would be the
  equivalent path.
- **L2 sniffer on Windows.** Would need Npcap (license-sensitive).
- **Full TCP termination over TUN.** The v1.5 TUN adapter is an L3
  responder — it answers ICMP/ICMPv6 echo and TCP RST so the network
  appears alive. Real TCP termination would need a pure-userspace TCP
  stack (gvisor's netstack would be the natural fit, but their module
  ships Bazel-only files Go's build can't handle today). For actual
  protocol interaction with virtual host services, the operator still
  needs `ip addr add` or iptables alongside the TUN.
- **MIB-walkable SNMP topology.** SNMP topology is currently exposed
  via event meta (`honeynet_neighbors`); a real `ipNetToMediaTable`
  walk would need GetNext support over the full MIB-2 tree.

Everything else from the original design is shipped.

## Getting help / reporting issues

Files of interest if you're debugging:

- `<data_dir>/events.db` — open with any SQLite client; the schema is in
  `internal/store/store.go`.
- `<data_dir>/events/events-*.jsonl` — one JSON event per line.
- `<data_dir>/captures/<event_id>.pcap` — Wireshark loads these directly.
- systemd journal (`journalctl -u tarpit-honeypot -f`) — structured `slog`
  output covering listener startup, sink errors, rate-limit drops,
  reload events, and capture failures.

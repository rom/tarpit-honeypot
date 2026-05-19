# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
semantic versioning loosely (this is single-binary infrastructure, not a
library, so the public-API contract is the YAML schema + CLI surface
documented in `docs/`).

## [Unreleased]

### Security — panic-trigger + UDP reflection fixes
- **High**: `modbus` handler — MBAP `length=1` allocated a zero-byte
  PDU buffer; the subsequent function-code dereference panicked. The
  goroutine recover-guard contained the damage but the handler died
  on every connection attempt. Tightened the length check to `>= 2`.
- **High**: `s7` handler — a COTP CR body of exactly 6 bytes (TPKT
  length=10) sliced `body[7:]` and panicked. Tightened the guard to
  `len(body) >= 7` before slicing the parameters.
- **High**: `radius` handler — attacker-controlled `length` field
  used to drive `payload[20:length]` which panicked when `length < 20`
  (low > high) or `length > len(payload)`. Added a bounds check.
- **High**: `ssdp` + `sip` UDP handlers — attacker-supplied headers
  (ST, Via, From, To, Call-ID, CSeq) were reflected verbatim into the
  response. CRLF in any of them gave an off-path attacker a one-shot
  UDP reflection/amplification primitive against a third party. Every
  echoed value now goes through `safe.SanitizeHeader`.
- **Medium**: `rtsp` handler — `CSeq` echoed without sanitization
  (TCP-only so no UDP spoofing, but a downstream proxy / cache could
  still be confused). Now `safe.SanitizeHeader(cseq)`.
- **Medium**: `ssh_interactive` — `xssh.DiscardRequests` and the
  session-channel request loop were raw `go func()` goroutines. A
  panic in crypto/ssh request parsing — possible with a malformed
  payload from a hostile client — would propagate to
  `runtime.fatalpanic` and kill the sensor process. Both now run
  inside `safego.Run` with the standard recovery + counter.
- **Medium**: Central output sanitization gap — `metaToString` (which
  calls `safe.SanitizeForLog`) only ran for CEF/LEEF. JSON / OCSF
  marshalled raw `ev.Meta` directly; control characters survived as
  JSON-escapes (``) but downstream consumers that decoded and
  rendered to a terminal reconstituted the original ANSI/escape
  bytes. `safe.SanitizeMetaStrings` now runs at the listener
  boundary (`tcp.go` + `udp.go`) so every string-typed value is
  scrubbed once, recursively, before any formatter sees it.
- **Low**: `ssh_interactive` host-key write error was silently
  swallowed (`_ = os.WriteFile(...)`); on a read-only filesystem the
  promised "stable host key fingerprint across restarts" property
  broke without warning. Now logs at warn level + continues with the
  in-memory key.
- **Low**: `https` TLS handshake used `context.Background()` instead
  of the caller's `ctx`. Slow-handshake drip couldn't be interrupted
  at sensor shutdown — only when `ReadDeadline` fired. Now uses the
  caller's context.

### Added — protocol depth improvements
- **`iec104`** is now a multi-frame session: it loops over the
  connection, handles STARTDT_ACT / STOPDT_ACT / TESTFR_ACT with the
  matching CONfirm reply, and responds to General Interrogation
  requests (ASDU type 100, COT=6) with the full sequence a real RTU
  emits — activation-confirmation, three M_ME_NB_1 measurement
  frames at IOAs 0x4001–0x4003, then activation-termination. Also
  handles Clock-Sync, Read-Command, Single-Command, and Double-
  Command requests. Every received frame's `asdu_type`, `cot`,
  `common_addr`, and `ioa` land in `meta.frames`.
- **`fins`** extended from one to seven Omron command pairs:
  CPU_UNIT_DATA_READ, CPU_UNIT_STATUS_READ (with RUN/MONITOR mode
  + zero-error fields), MEMORY_AREA_READ (with believable PV-like
  data, decoded `mem_area_name`: DM/CIO/WR/HR/AR/EM), CYCLE_TIME_READ,
  CLOCK_READ, plus generic ACK for everything else. Meta carries
  `mem_addr` and `mem_count` for memory reads.
- **`modbus`** extended:
  - Multi-PDU session loop (was one-shot).
  - **FC 0x2B / 0x0E (Read Device Identification)** — what nmap's
    modbus-discover uses for vendor fingerprinting. Now advertises
    Schneider Electric BMX P34 2020 / Modicon M340 with the full
    objects-table (vendor, product code, revision, vendor URL,
    product name, model name, user app name, conformity class).
  - **FC 0x05 / 0x06 / 0x0F / 0x10 (Write Single/Multiple
    Coils/Registers)** — captures the values the attacker tried to
    write into `meta.written_values`. ICS-relevant TTP capture.
  - Read-register replies (FC 3/4) now return the requested quantity
    of registers (was always 1) with believable process-value
    patterns.
  - Per-PDU `function_name` symbolic decode in meta.

### Documentation
- `README.md` "Protocol handlers in detail" rewritten as three tables
  (TCP IT, TCP ICS, UDP) covering all 46 handlers with archetype +
  identity columns. Each row reflects the actual implementation:
  multi-frame loops, captured fields, reply shape, vendor IDs
  advertised, fingerprints computed.
- Brief feature list updated to "46 built-in protocol handlers" with
  the correct counts per category.

### Added — macOS first-class support
- `darwin/amd64` and `darwin/arm64` build targets in `make cross`.
- Real `privdrop` implementation on darwin (`internal/privdrop/
  privdrop_darwin.go`): `setgid`/`setuid` with the same "refuse uid
  0" guard as the Linux path. On darwin `setuid` also drops the
  saved-uid so a later `setuid(0)` regain attempt fails — same
  posture as Linux's `setresuid`.
- Platform-aware error messages on every Linux-only subsystem (ARP /
  ICMP / LLDP responders, AF_PACKET sniffer, fanotify OPEN events,
  Linux TUN). Each now mentions the runtime GOOS and the documented
  macOS workaround (`ifconfig <iface> alias <ip>` for L2/L3 presence,
  fsnotify for non-OPEN file canaries).
- Comprehensive platform-support matrix in `docs/usage.md` §12 and
  `README.md`. New launchd plist example in `docs/INTEGRATIONS.md`.

### Documentation
- `README.md` rewritten: 37 handlers (was 28), 29 archetypes,
  ATT&CK / storyline / anomaly / hardening / engagement sections,
  full platform support matrix, status blocks for v1.6–v1.10.
- `docs/usage.md` extended with three new top-level sections:
  Archetypes (§9), Interactive engagement (§10), ATT&CK / storyline /
  anomaly (§11), Platform support (§12). Troubleshooting table
  refreshed with macOS-specific entries.
- `docs/cli.md` adds Common flags table, config-layering description,
  `init` / `completion` / `help` subcommand sections, `--version` /
  `-V` flag forms, macOS privileged-setup notes.
- `docs/config.md` documents `ssh_interactive` vs `ssh`, adds
  `honeynets[].lldp_responder` block, updates handler lists.
- `docs/INTEGRATIONS.md` adds §3a (ATT&CK/storyline/anomaly SIEM
  rules), industrial-OT honeynet recipe, launchd deployment pattern,
  macOS `ifconfig alias` workaround note.
- `internal/cli/help.go` archetypes topic enumerates every
  fingerprint surface the archetype controls.

### Added — v1.10 attacker engagement
- **Interactive CLI shell** (`internal/shell`) — post-login command-
  line emulation. After a fake "Login incorrect" first attempt, the
  attacker is dropped into the archetype's shell where every command
  they type is captured and scanned against a 14-marker ATT&CK-
  aligned TTP catalog (reverse shells, persistence, recon, defense
  evasion, log-cleaning, crypto-miners, encoded payloads, etc.).
  Wired into:
  - `telnet` handler (after fake login).
  - New `ssh_interactive` handler running a full
    `golang.org/x/crypto/ssh` server: persists an ed25519 host key
    under `<data_dir>/tls/`, captures every password / pubkey
    attempt (incl. SHA-256 key fingerprints), accepts the 3rd
    credential and drops into shell.Run on the session channel.
  Bounded at MaxCommands=32, MaxBytesPerCommand=8KiB,
  IdleTimeout=60s, SessionTimeout=5min.
- **LLDP / CDP active responder** — each honeynet host now appears
  in `lldpctl` / Cisco `show cdp neighbors` output on the L2 segment,
  advertising the archetype-shaped MAC, hostname, system description,
  and family-tuned LLDP capabilities (bridge/router for switches +
  PLCs, station-only for hosts). Linux-only (AF_PACKET + CAP_NET_RAW).
  Config:
  ```yaml
  honeynets:
    - id: factory
      lldp_responder:
        enabled: true
        interface: eth1
        interval_s: 30
        include_cdp: true
  ```
- **Multi-page web UI + credential capture** — the http handler now
  routes on path + method:
  - `GET /` (and any archetype index): serves the archetype's HTML.
  - `GET /login`, `/admin`, `/Portal/Login.html`,
    `/cgi-bin/luci`, `/wp-login.php`, `/manager/html`, etc.: serves
    a login form.
  - `POST /login` (any of the above): parses the urlencoded body
    (accepts `username`/`user`/`login`/`name`/`uname`/`u` and
    `password`/`pass`/`passwd`/`pwd`/`p` aliases) and emits an
    `http-login-attempt` anomaly with the captured credentials.

### Added — v1.9 deception+detection upgrades
- **14 new archetypes** for full-fleet deception coverage:
  FreeBSD 13/14, OpenBSD 7.5/7.6, Arch Linux, Rocky Linux 9,
  AlmaLinux 9, Oracle Linux 8/9, Moxa EDS-208, Moxa NPort 5210,
  Siemens SCALANCE XB-208, Siemens S7-1200 PLC, Siemens S7-1500 PLC.
  Each carries the full fingerprint surface needed to fool a scanner:
  vendor MAC OUI, SNMP sysDescr/sysObjectID/interface table, default
  service list, web-UI HTML body, SSH/Telnet CLI prompt, LLDP
  neighbors, and per-archetype protocol quirks.
- **MITRE ATT&CK tagging** — every event the sensor emits is
  decorated with `mitre_techniques` (e.g. ["T1110.001","T1078"]) and
  `mitre_tactics` (e.g. ["credential-access","initial-access"]) via
  the new `internal/mitre` package. Mapping is rule_id + handler-aware
  so listener:ssh-bait gets brute-force / valid-accounts technique
  IDs, while listener:http-bait gets exploit-public-facing-app.
- **Storyline correlator** (`storyline:multi_stage`) — fires when a
  single source IP touches 3+ distinct ATT&CK tactics inside a
  30-minute window. The event meta carries the kill-chain-ordered
  stage list and a "->"-joined chain summary
  ("discovery -> credential-access -> lateral-movement"), so the SOC
  sees one timeline instead of dozens of independent listener hits.
- **Protocol anomaly detection** — handlers flag deviations from
  expected protocol shape into a first-class `event.anomalies` array
  that SIEM rules can match on directly. SSH flags non-printable /
  non-SSH / overlong identification strings; HTTP flags unknown
  methods + suspicious URIs (path traversal, Log4Shell JNDI,
  WordPress probes, secret-file probes, .git leakage, mgmt-endpoint
  scans).
- **Defensive hardening** — new `internal/safe` package centralizes
  hostile-input handling: bounds-checked slice/string/alloc helpers
  with a 32 KiB universal cap, plus SanitizeForLog /
  SanitizeUTF8ForLog / SanitizeHeader / SanitizeEmailSubject for
  output paths. CEF/LEEF/OCSF formatters now escape every control
  byte (not just CRLF), and the SMTP sink runs the Subject + every
  header through the sanitizer so a stolen credential or scanner
  banner can't inject extra MIME headers.

### Added — v1.8
- **Archetypes** — set `sensor.archetype: "debian 12"` (or
  `listener.archetype`, or per-honeynet-host `archetype`) and every
  banner-aware handler (SSH / HTTP(S) / FTP / Telnet / SMTP / MySQL)
  reports values consistent with a stock install of that OS, so a
  scanner can't catch the sensor by spotting a version-vs-distro
  mismatch. 15 ship archetypes: `centos 5`, `centos 6`, `centos 7`,
  `centos 8`, `CentOS Stream 10`, `debian 9`–`debian 13`, `Red Hat
  Enterprise Linux 8`–`10`, `Ubuntu 24.04 LTS`, `Ubuntu 26.04 LTS`.
  Override precedence: honeynet-host > listener > sensor > "no
  archetype". `tarpit-honeypot help archetypes` lists them all.
- **5 new protocol handlers**:
  - `coap` (UDP/5683) — RFC 7252 IoT discovery, parses option TLVs,
    replies with `/.well-known/core` link-format.
  - `knx` (UDP/3671) — KNXnet/IP building automation. Answers
    SEARCH_REQUEST and DESCRIPTION_REQUEST as an MDT KNX IP Router.
  - `xmpp` (TCP/5222) — XMPP client stream, advertises PLAIN +
    SCRAM-SHA-1, captures SASL AUTH attempts.
  - `amqp` (TCP/5672) — RabbitMQ-shaped Connection.Start, captures
    PLAIN credentials in Connection.StartOk, replies NOT_ALLOWED.
  - `ipp` (TCP/631) — IPP/CUPS printer. Answers Get-Printer-Attributes
    with a fake Brother HL-L8260CDW.
- `make cover` / `make race` / `make fuzz` targets
- Fuzz tests for the TLS ClientHello (JA3/JA4), SSH KEXINIT (HASSH),
  HTTP request line (JA4H), LDAP BER decoder, MQTT varint/string
  parsers, and DNS query parser. Failing inputs persist under
  `testdata/fuzz/` as regression cases.
- `internal/safego` package — `Run` / `RunWithEvent` goroutine wrappers
  with a `recover()` guard. Panics log + increment counter + emit a
  `sensor:panic:<name>` event into the bus.
- Panic recovery wired into the TCP and UDP listener handler paths and
  the sensor's bus loop.
- `/metrics` now exposes `tarpit_build_info`, `tarpit_uptime_seconds`,
  `tarpit_panic_recoveries_total`, `tarpit_panic_recoveries_by_name_total`.
- Global `--version` / `-V` flag; per-subcommand `-h` / `--help`.
- Logging flags shared across subcommands: `--log-level`,
  `--log-format=text|json`, `--log-file`, `--quiet`, `--verbose`.
- `--set key.path=value` overrides on `run` and `show-config`.
- `TARPIT_*` environment-variable overrides (`TARPIT_SENSOR_NAME=foo`,
  double-underscore escapes a real `_`).
- `conf.d/*.yaml` deep-merge over the base file in lexical order.
- `run --dry-run` validates the config and constructs the sensor
  without binding any listeners.
- New subcommand `init` writes a defaulted YAML skeleton.
- New subcommand `completion bash|zsh|fish` prints shell completions.

### Fixed
- LDAP `stripBERHeader` short-form bounds check now happens before the
  slice (caught by `FuzzLDAPParseMessage` immediately on first run).

## [v1.5] — 2026-05-19

### Added
- Linux TUN-based honeynet adapter (L3 responder for ICMP + TCP RST;
  no full TCP termination).
- IPv6 listener binds and honeynet host IPs throughout.
- SNMP / LDAP / DCE-RPC handlers expose honeynet topology in event
  meta (`honeynet_neighbors`, `honeynet_computer_accounts`,
  `honeynet_endpoints`).
- `docs/` directory: `usage.md`, `config.md`, `cli.md`, `README.md`.

## [v1.4] — 2026-05-19

### Added
- Source-IP enrichment: MaxMind GeoLite2 (city + ASN) and bounded
  synchronous reverse-DNS with LRU cache.
- Per-channel output `format:` field — `json` (default), `cef`
  (ArcSight), `leef` (QRadar), `ocsf` (cloud SIEMs).

## [v1.3] — 2026-05-19

### Added
- Linux AF_PACKET ICMP echo responder per honeynet (matches the
  v1.2 ARP responder model; reuses the per-host MAC).
- Prometheus-format `/metrics` endpoint on the web UI: per-channel
  retry / failure / drop counters, honeynet topology gauges, SQLite
  store size.

## [v1.2] — 2026-05-19

### Added
- Linux AF_PACKET ARP responder per honeynet — virtual hosts
  advertise stable deployment-derived MACs.
- Per-honeynet route matching: routes can filter on `honeynet`,
  `honeynet_os`, `rule_id` in addition to severity.

## [v1.1] — 2026-05-19

### Added
- Honeynets: configurable artificial networks with virtual hosts and
  services. Per-host derived identity (banner / version / serial /
  challenge). DNS canary listener forward-resolves honeynet hostnames.
- `list-honeynets` subcommand.

## [v1.0] — 2026-05-19

### Added
- Counter-fingerprinting: `sensor.deployment_id` seeds all
  fixed-string handler responses; per-reply jitter; TLS cert rotation;
  HTTP JA4H fingerprinting; banner variant pools.
- Brute-force credential extraction in the correlator.
- Slow-scan correlator (24h-default window with per-port aging).
- DNS amplifier-probe detection (ANY queries + per-window rate).
- `sensor.disk.retention_days` time-based pruner.
- Graceful drain on shutdown via `sensor.shutdown.drain_timeout`.
- `export-pcap` subcommand.

## [v0.9] — 2026-05-19

### Added
- CLI ergonomics: `gen-token`, `show-config`, `validate-config --diff`.
- Dockerfile (scratch base, ~14MB).
- Listener hot-reload (per-listener restart on SIGHUP).
- Per-listener `max_concurrent` accept cap.
- Outbound sink retry queue with exponential backoff.
- Diff-on-reload audit log + `sensor:reload` event.
- TLS / HTTP / SSH client fingerprinting: JA3, JA4, HASSH.
- 11 new protocol handlers: VNC, SMTP receive, RDP, WinRM, DCE-RPC,
  LDAP, Kerberos, Postgres, MySQL, Redis, IPMI.

## [v0.8] — 2026-05-19

### Added
- SMB1 / SMB2 handler.
- Comprehensive README.

## [v0.7] — 2026-05-19

### Added
- OPC-UA, EtherNet/IP, BACnet, TFTP handlers.
- linux/armv7 + linux/armv6 cross-build targets.

## [v0.6] — 2026-05-19

### Added
- UDP handler architecture.
- SNMP + NTP UDP handlers (NTP mode-7 explicitly silenced — no
  amplifier path).
- Twilio SMS, AWS SNS (hand-rolled Sigv4), SNMPv2c trap channels.

## [v0.5] — 2026-05-19

### Added
- URL canary tokens via HTTP/HTTPS handlers.
- DNS canary listener.
- Linux fanotify-based file open detection.
- AF_PACKET sniffer (ARP scan + unsolicited reply detection).

## [v0.4] — 2026-05-19

### Added
- ICS handlers: Modbus, S7comm, IEC-104, MQTT.
- Per-event pcap capture (synthesized libpcap; no raw sockets).

## [v0.3] — 2026-05-19

### Added
- SQLite event index (pure-Go).
- Read-only loopback web UI (`/`, `/events`, `/events/<id>`, `/api/*`,
  `/healthz`).
- Privilege drop (Linux setresuid/setresgid).
- SIGHUP hot reload for channels / routes / allowlist / dedup /
  correlator.

## [v0.2] — 2026-05-19

### Added
- Tarpit modes: `sticky`, `trickle`, `keepalive`.
- Built-in protocol handlers: SSH, HTTP, HTTPS (self-signed), Telnet,
  FTP.
- Filesystem honeyfile watcher via fsnotify.
- Port-scan + brute-force correlators.
- Per-sink worker queues with bounded drop.

## [v0.1] — 2026-05-19

### Added
- Tripwire MVP: TCP/UDP listeners (drop + banner modes), YAML config,
  stdout + jsonlog + webhook + SMTP + syslog sinks, dedup +
  rate-limit + allowlist + min-severity gating, systemd unit, Linux
  amd64/arm64 static cross-build.

# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
semantic versioning loosely (this is single-binary infrastructure, not a
library, so the public-API contract is the YAML schema + CLI surface
documented in `docs/`).

## [Unreleased]

### Added
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

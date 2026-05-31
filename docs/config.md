# Configuration Reference

The sensor is configured via a single YAML file (default `/etc/tarpit-honeypot/config.yaml`). Every top-level section is optional; sections with no entries are simply skipped. Validate any config with `tarpit-honeypot validate-config -c <path>`. See [`docs/usage.md`](usage.md) for deployment patterns and [`docs/cli.md`](cli.md) for command-line invocation.

The full annotated example is in [`configs/tarpit-honeypot.example.yaml`](../configs/tarpit-honeypot.example.yaml) — that file is the source of truth for default values; this document explains the **why**.

## Top-level structure

```yaml
sensor:        { ... }     # sensor identity, disk caps, enrichment, jitter
ui:            { ... }     # web UI bind, auth, TLS
listeners:     [ ... ]     # tcp / udp honeypots
canaries:      [ ... ]     # filesystem honeyfiles
url_canaries:  [ ... ]     # tokens matched by http / https handlers
dns:           { ... }     # DNS canary listener
dns_canaries:  [ ... ]     # DNS-side canary names
sniffer:       { ... }     # AF_PACKET ARP + TCP scan detector (linux only)
correlate:     { ... }     # port-scan / brute-force / slow-scan
honeynets:     [ ... ]     # artificial networks of virtual hosts
dedup:         { ... }     # event dedup window
allowlist:     [ ... ]     # source IPs that bypass outbound alerts
channels:          [ ... ] # output sinks (stdout, syslog, webhook, sns, ...)
routes:            [ ... ] # severity / honeynet / rule predicates -> channels
severity_overrides:[ ... ] # operator re-map of reported severity per rule_id
dedup:             { ... } # per (source, rule) dedup window for outbound sinks
allowlist:         [ ... ] # source IPs that bypass outbound alerts
devices:           { ... } # learned-device inventory + new-device alerts
risk:              { ... } # decaying per-source threat score
interaction:       { ... } # interaction depth + experimental-feature guardrails
```

Every section is optional. The table below is the at-a-glance map; each section
has its own reference further down.

| Section | Kind | Purpose |
|---|---|---|
| `sensor` | map | identity, data dir, disk caps, enrichment, jitter, archetype |
| `ui` | map | read-only web UI bind / auth / TLS |
| `listeners` | list | TCP/UDP honeypots (mode + handler + port) |
| `archeservices` | list | service-role bundles that expand into listeners |
| `canaries` / `url_canaries` / `dns_canaries` | list | filesystem / HTTP-path / DNS honey-tokens |
| `dns` | map | DNS canary/resolver listener |
| `sniffer` | map | AF_PACKET L2 ARP/scan detector (Linux) |
| `correlate` | map | in-sensor aggregate detectors (scan, brute, OT, VoIP, …) |
| `honeynets` | list | artificial networks of virtual hosts/services |
| `channels` | list | output sinks |
| `routes` | list | match predicates → channels |
| `forward` | list | ship events to parent aggregator node(s) |
| `ingest` | map | accept events from child nodes (aggregator endpoint) |
| `fleet` | map | cross-sensor correlation over the merged stream |
| `intel_feed` | map | subscribe to a parent's downward fleet-intel feed |
| `misp` | map | push the fleet's observed IOCs to a MISP instance |
| `ioc` | map | indicator-of-compromise store + ioc:* events |
| `severity_overrides` | list | re-map reported severity per `rule_id` |
| `dedup` / `allowlist` | map / list | outbound dedup window / suppression IPs |
| `devices` | map | learned-device inventory + new-device alerts |
| `risk` | map | decaying per-source threat score |
| `interaction` | map | interaction depth + experimental guardrails |

---

## `sensor:` — identity, disk, enrichment

```yaml
sensor:
  name: ""                    # blank = hostname()
  data_dir: /var/lib/tarpit-honeypot
  deployment_id: ""           # blank = auto-generate + persist
  archetype: ""               # see "archetypes" section / `help archetypes`
  interfaces: []              # network interface(s) to use; e.g. [eth0]
  drop_user: ""               # Linux: setresuid/setresgid target after bind
  drop_group: ""
  disk:
    json_log_mb: 500
    sqlite_mb: 500
    pcap_mb: 1024
    capture_kb: 64
    retention_days: 0         # 0 = size-cap only; >0 enables time-based pruning
  jitter:
    enabled: false            # randomize handler reply latency
    min_ms: 5
    max_ms: 50
  shutdown:
    drain_timeout: 10s        # max wait for in-flight handler goroutines
  tls_rotate:
    days: 0                   # 0 = never rotate HTTPS self-signed cert
  geoip:
    city_db: ""               # /path/to/GeoLite2-City.mmdb
    asn_db:  ""               # /path/to/GeoLite2-ASN.mmdb
  rdns:
    enabled: false
    timeout: 500ms
    cache_size: 1024
```

| Key | Effect |
|---|---|
| `name` | Identifies the sensor in every event meta. Blank → hostname. |
| `data_dir` | Where SQLite, jsonlog, captures, certs, and `.deployment-id` live. |
| `interfaces` | Network interface(s) the sensor uses. Supplies the default interface for the AF_PACKET layer (sniffer + honeynet ARP/ICMP/LLDP/PROFINET responders) when those sections leave `interface` blank, and pins wildcard-bound listeners (`0.0.0.0`/`::`) to the first interface's primary IP. Override on the CLI with `-i`/`--interface` (repeatable). Empty = all interfaces. |
| `deployment_id` | Stable random seed feeding every "fixed" handler string. Auto-generated to `<data_dir>/.deployment-id` on first run. Override here to align two sensors that should look identical. |
| `archetype` | OS-shaped banner profile (e.g. `debian 12`, `Ubuntu 24.04 LTS`, `Red Hat Enterprise Linux 9`). Pins SSH / HTTP / FTP / Telnet / SMTP / MySQL banners to values consistent with a stock install of that distro, so a scanner can't catch the sensor by spotting a version-vs-distro mismatch. Blank = fall back to the deployment-id-keyed variant pool. See `tarpit-honeypot help archetypes` for the list. |
| `drop_user` / `drop_group` | After privileged setup, drop to this uid/gid. Refuses uid 0. Linux only — non-Linux warns and ignores. |
| `disk.retention_days` | Hourly runner deletes events / files / DB rows (and IOC indicators not seen) older than this. 0 disables time-based pruning (size caps still apply). |
| `jitter` | Per-handler-reply sleep `[min_ms, max_ms]`. Defeats microsecond-identical-latency scanner fingerprinting. |
| `shutdown.drain_timeout` | After SIGTERM, accept sockets close immediately but in-flight handlers get this long to finish before force-cancel. |
| `tls_rotate.days` | Auto-regenerate the HTTPS handler's self-signed cert if older than this. 0 = stable cert (stable SNI hash → leakable identifier). |
| `geoip.city_db` | MaxMind GeoLite2-City.mmdb path. Decorates events with `geo_country`, `geo_city`, etc. |
| `geoip.asn_db` | MaxMind GeoLite2-ASN.mmdb path. Decorates events with `asn`, `asn_org`. |
| `rdns.*` | Bounded synchronous reverse-DNS with LRU cache. Loopback/private addresses are skipped. |
| `threat_intel` | `{enabled, lists:[{label,file}]}` — tag source IPs found on operator-supplied reputation lists (one IP/CIDR per line; `#` comments allowed). Matching events get `threat_intel` (the matched labels) + `threat_intel_hit`. Enrichment only — never blocks. |
| `tor` | `{enabled, exit_file}` — flag source IPs in an operator-supplied Tor exit-node list with `tor_exit=true`. |
| `net_class` | `{enabled}` — built-in, database-free classification of public sources: `net_class=bogon` for reserved/martian ranges (RFC 5737/6598/etc.) and `net_class=hosting` when the GeoIP-ASN AS-org looks like datacenter/cloud infra. |
| `oui_file` | Path to a MAC-vendor (OUI) database — the IEEE `oui.csv` or a simple `prefix,vendor` CSV. Events carrying a MAC (DHCP/ARP) get `mac_vendor`; the learned-device inventory uses it for the vendor column. Unset = a small built-in OUI table. |

The GeoIP/Tor/reputation/OUI databases are operator-supplied (license and
freshness vary). Two-step workflow:

1. **Download** (internet-connected machine):
   [`scripts/fetch-enrichment.sh`](../scripts/fetch-enrichment.sh) downloads
   every feed, writes `SHA256SUMS` + a `suggested-config.yaml`, and packages a
   single `<dir>.tar.gz` for transfer.
2. **Install/update** (on the sensor, by hand or cron/systemd):
   [`scripts/install-enrichment.sh`](../scripts/install-enrichment.sh) verifies
   the bundle, reads the live config via `tarpit-honeypot list-paths` to learn
   where each file belongs, installs them atomically, and SIGHUPs the sensor —
   which re-reads the enrichment databases without a restart.

`tarpit-honeypot list-paths` (and the web UI `/config` "files in use" panel)
show exactly which config/enrichment/database files a sensor uses.
| `vuln_emulation` | `true` makes banner-aware handlers advertise the archetype's deliberately-unpatched version + fake patch level (e.g. `debian 12` → Apache 2.4.49 / OpenSSH 7.2 / vsFTPd 2.3.4). Per-listener `vuln_emulation` overrides it. CVE exploit-attempt detection (`cve:<id>` events) runs regardless. The service never becomes actually exploitable. |
| `payloads` | `{enabled, max_bytes, max_total_mb}` — harvest attacker-supplied malware / shellcode / droppers to `<data_dir>/payloads/`. Classified (ELF/PE/script/shellcode), base64 droppers decoded, ingress URLs extracted; emits `malware:capture`. Collection only — nothing is executed. |
| `sandbox` | `{seccomp, landlock, read_paths, write_paths}` — Linux kernel self-confinement applied after privilege drop. `seccomp` denies shell-spawn / module-load / debug syscalls; `landlock` makes the FS read-only except `data_dir` (+ `write_paths`). Best-effort; no-op on non-Linux. See [`docs/hardening.md`](hardening.md). |
| `session_recording` | `{enabled, max_bytes, max_total_mb}` — record interactive `telnet` / `ssh_interactive` sessions as asciinema v2 casts under `<data_dir>/sessions/` (replayable, with timing). The cast filename is recorded in event meta (`session_cast`). |

Windowed correlator state (port-scan / brute-force / slow-scan / icmp-sweep) is persisted to `<data_dir>/correlate-state.json` (every 60s + on shutdown) and restored on startup, so long-window detection survives a restart.

---

## `ui:` — read-only web UI

```yaml
ui:
  enabled: false
  bind: 127.0.0.1:8088
  tls_cert: ""
  tls_key:  ""
  auth_token_env: ""    # env var holding the bearer token
  refresh_seconds: 10   # live-view auto-refresh; 0 = off (omit = 10s default)
```

- Bind to anything non-loopback **requires both** `tls_cert + tls_key` and `auth_token_env`. Validation rejects the config otherwise.
- The UI is strictly read-only — no write endpoints.
- **Auto-refresh:** the UI ships a small packaged JS layer (served same-origin under `script-src 'self'`) that provides a pausable live-refresh, client-side table sort/filter, and the correlation graph. It's progressive enhancement — with JavaScript disabled the views fall back to an HTML `<meta http-equiv="refresh">` every `refresh_seconds` (default **10s**; set `0` to disable).
- `/metrics` requires the same auth as the rest of the UI (the `/healthz` endpoint is the only auth-bypass route).

---

## `listeners:` — TCP / UDP honeypots

```yaml
listeners:
  - id: ssh-bait
    proto: tcp                          # tcp | udp
    bind: 0.0.0.0:22                    # supports IPv6 brackets: [::]:22 / [::1]:22
    mode: banner                        # drop | banner | tarpit
    handler: ssh                        # see "Handlers" table below
    severity: high                      # low | medium | high | critical
    read_bytes: 1024
    read_timeout: 5s
    capture: false                      # write per-event pcap of bidirectional bytes
    max_concurrent: 0                   # 0 = unlimited; otherwise SYN-flood guard
    archetype: ""                       # overrides sensor.archetype for this listener
    banner: ""                          # raw banner string for handler: raw
    https:                              # only for handler: https
      hosts: ["honeypot.local"]
    tarpit:                             # only for mode: tarpit
      strategy: sticky                  # sticky | trickle | keepalive | jitter |
                                          #   backoff | ssh_banner | http_headers |
                                          #   http_chunked | echo | babble
      max_per_source: 4
      max_total: 256
      emulate: false                    # run handler: first (banner+capture), then tarpit
      trickle:    { text: "Loading...\n", byte_interval: 2s }
      keepalive:  { interval: 30s }
      jitter:     { text: "Loading...\n", min_interval: 500ms, max_interval: 5s }
      backoff:    { text: "Loading...\n", start: 500ms, max: 60s, factor: 2 }
      ssh_banner: { line_interval: 2s, max_line_bytes: 32 }
      http:       { status_line: "HTTP/1.1 200 OK", header_interval: 2s, chunk_interval: 2s, chunk_text: "." }
      echo:       { byte_interval: 1s }
      babble:     { byte_interval: 2s }
```

### Listener modes

| Mode | Behavior |
|---|---|
| `drop` | Accept + immediately close. Logs source. |
| `banner` | Run `handler:` against the connection. Captures the application-layer exchange. |
| `tarpit` | Hold the connection per `tarpit.strategy:`. Sticky = never read/write; trickle = one byte every `byte_interval`; keepalive = NUL every `interval`. |

### Handlers

The authoritative list is `tarpit-honeypot list-handlers` (it is sourced from
the same whitelist the validator enforces, so it never drifts).

**TCP-only:** `raw`, `ssh`, `ssh_interactive`, `http`, `https`, `telnet`, `ftp`, `ftp_files`, `smb`, `vnc`, `smtp_recv`, `rdp`, `winrm`, `dcerpc`, `ldap`, `kerberos`, `postgres`, `mysql`, `mssql`, `oracle_tns`, `redis`, `memcached`, `mongodb`, `elasticsearch`, `pop3`, `imap`, `smtps`, `imaps`, `pop3s`, `ldaps`, `mqtts`, `ftps`, `syslog_tcp`, `rtsp`, `dockerapi`, `melsec`, `xmpp`, `amqp`, `ipp`, `modbus`, `s7`, `s7comm_plus`, `iec104`, `mqtt`, `opcua`, `ethernetip`, `dnp3`, `ge_srtp`, `codesys`, `atg`, `fox`, `hartip`, `pcworx`, `mms`, `ads`, `pjl`, `lpd`, `teamviewer`, `anydesk`, `openvpn`, `citrix_ica`, `vmware_authd`, `x11`, `rlogin`, `nx`, `redfish`, `intel_amt`, `ilo`, `idrac`, `esxi`, `fortinet`, `pulse`, `citrix_gateway`, `horizon`, `moxa_mgmt`, `scripted`.

The `…s` handlers — `smtps` (465), `imaps` (993), `pop3s` (995), `ldaps` (636),
`mqtts` (8883), `ftps` (990) — are the **implicit-TLS** variants of their
plaintext peers: the sensor performs the TLS handshake (presenting a self-signed
cert from `<data_dir>/tls`, computing JA3/JA4 + JA3S like `https`) and then runs
the underlying protocol over the encrypted channel.

Several plaintext handlers also support **opportunistic TLS** when a cert store
is available (it is, by default — `<data_dir>/tls`): `smtp_recv` advertises and
upgrades on `STARTTLS`, `imap` on `STARTTLS`, `pop3` on `STLS`, and `postgres`
answers an `SSLRequest` with a real handshake. Credentials continue to be
captured over the encrypted channel. These are advertised only when TLS can
actually be negotiated, keeping the advertisement honest.

The printer / multi-function-device handlers — `pjl` (HP JetDirect 9100), `ipp` (CUPS 631), `lpd` (LPD 515) — recognize PJL/PostScript/ZPL abuse, CUPS foomatic-rip RCE, and LPD injection; pair them with a printer archetype (`hp-printer`, `brother-printer`, `xerox-versalink`, …) so the IPP/SNMP/web identities agree. See [`archetypes.md`](archetypes.md).

**UDP-only:** `raw`, `snmp`, `ntp`, `bacnet`, `tftp`, `ipmi`, `syslog_udp`, `radius`, `sip`, `ssdp`, `cldap`, `llmnr`, `nbns`, `mdns`, `fins`, `coap`, `knx`, `dhcp`, `dns`, `auto`.

**Catch-all:** `auto` (TCP + UDP) is the generic handler for unmodelled protocols — it captures the client's opening message, guesses the protocol from the leading bytes (`protocol_guess`: tls / ssh / http / socks / text / binary), and raises an `unknown-protocol` anomaly so a probe on any port is still attributable. On TCP it can send an operator-set `banner` as a server-first nudge; on UDP it never replies (a UDP reply to a spoofable source is a reflection primitive). Point a wide listener at it to cover everything not explicitly modelled.

**TCP + UDP (small services, RFC 862-868 / 1340):** `echo`, `discard`, `daytime`, `qotd`, `chargen`, `time`. `chargen`/`echo` reply with a single bounded datagram and never amplify — safe to expose on UDP.

**Dynamic (Lua):** `lua` — the listener's `script:` path drives the connection via a sandboxed Lua VM (pure-Go, no io/os, context deadline + read/write/sleep budgets). Scripts get `conn:read/readline/write`, `host:get/set` (per-source state), `rng:int/choice/hex` (deterministic per deployment+host), `personality()` (stable hostname/version/firmware), `sleep` (timers), and `log`/`flag`/`meta`. Used for deeper app emulation + dynamic banners. Example: [`configs/scripts/iot-login.lua`](../configs/scripts/iot-login.lua).

**Declarative (scripted):** `scripted` — stand up a custom TCP service entirely in YAML under the listener's `scripted:` block: an optional on-connect `greeting`, then top-down `rules` matching each client message by `prefix` / `contains` / `suffix` / `iprefix` / `icontains` (case-insensitive) / `regex` (RE2) / `hex_prefix` / `any`, each writing a `respond` (or `respond_hex` for binary) with an optional per-rule `anomaly` flag and `close`. **Stateful, multi-step protocols**: a rule can require a `stage` and advance it with `set_stage` (e.g. an `auth` stage gating a `command` stage). **Credential capture**: a `regex` rule with `capture: user` / `capture: pass` records the first capture group into the attacker profile + default-credential matching. Bounded rounds + per-reply size cap; TCP-only (cannot be a spoofed-source amplifier); validated at config load.

**Per-listener extras:** `accept_creds: none|defaults|any` (credential-accept policy for `ftp_files`); `archetype:` (overrides `sensor.archetype`); `https.cn` / `https.org` / `https.ou` / `https.key_type: ecdsa|rsa` (per-service TLS cert identity). See [`docs/usage.md`](usage.md) for the archetype + engagement details.

Validation rejects a TCP-only handler on a UDP listener and vice versa. See [`docs/INTEGRATIONS.md`](INTEGRATIONS.md#protocol-handler-catalog) for per-handler defaults and behavior.

**`ssh_interactive` vs `ssh`:** The plain `ssh` handler does the
banner-grab + HASSH-fingerprint exchange and closes. `ssh_interactive`
runs the full `golang.org/x/crypto/ssh` server with a persistent
ed25519 host key (under `<data_dir>/tls/ssh_host_ed25519_key`),
captures every password + public-key attempt, accepts the third
credential, and drops into the archetype's shell on the session
channel. Use `ssh_interactive` when post-auth TTP capture matters;
use the lighter `ssh` when only credentials and fingerprints do.

## `archeservices:` — service-role bundles

An archeservice declares a service *role* and expands at load time into the
listeners that role needs. Combine it with an `archetype:` so the handlers
answer with the right software, banner strings, versions and TLS posture
for that OS/device. One entry → several listeners.

```yaml
archeservices:
  - id: corp-web                 # listener-id prefix (must be unique)
    role: webserver              # see `tarpit-honeypot list-archeservices`
    archetype: debian 12         # optional; the software/identity to wear
    bind: 0.0.0.0                # host/IP ONLY — the role supplies the ports
    severity: high               # optional; applied to every expanded listener
    mode: banner                 # optional; default banner (raw services -> drop)
    capture: false               # optional
    vuln_emulation: true         # optional; overrides sensor default
```

| Field | Meaning |
|---|---|
| `id` | Unique prefix for the generated listener ids (`<id>-<proto><port>`). |
| `role` | The service role. Run `tarpit-honeypot list-archeservices` for the catalog and each role's ports. |
| `archetype` | OS/device identity the expanded handlers wear (validated like `sensor.archetype`). Optional. |
| `bind` | A bare host/IP (no port). Each role service binds `<bind>:<port>`. |
| `mode` / `severity` / `capture` / `vuln_emulation` | Applied to every expanded listener (sensible defaults). |

Roles: `webserver`, `ftpserver`, `sshserver`, `printserver`, `fileserver`,
`ldapserver`, `adserver`, `mailserver`, `dbserver`, `dnsserver`,
`snmpserver`, `voipserver`, `remoteaccess`. Example:
`webserver` + `debian 12` opens 80/http + 443/https with Debian's Apache
banner; `adserver` + `active-directory` opens the full DC port set
(Kerberos/LDAP/LDAPS/SMB/DCE-RPC/DNS/WinRM/RDP/GC); `printserver` +
`hp-printer` opens 9100/631/515/161 as a coherent HP MFP. Inspect the
result with `tarpit-honeypot show-config`. See
[`configs/tarpit-honeypot.example-archeservices.yaml`](../configs/tarpit-honeypot.example-archeservices.yaml).

### Tarpit strategies

| Strategy | Connection behavior | Use when |
|---|---|---|
| `sticky` | Hold forever, no read/write. Kernel TCP keepalive notices dead peers. | Punish persistent scanners cheaply. |
| `trickle` | Write 1 byte of `trickle.text` every `byte_interval`, cycling. | Make banner-grabbers wait for content. |
| `keepalive` | Write a NUL byte every `keepalive.interval`. | Cheapest persistent presence; minimal bandwidth. |
| `jitter` | Trickle one byte at a random interval in `[jitter.min_interval, jitter.max_interval]`. | Defeat scanners that fingerprint or time out on trickle's regular cadence. |
| `backoff` | Trickle whose interval starts at `backoff.start`, ×`backoff.factor` each byte, capped at `backoff.max`. | Feel responsive at first so the scanner commits, then degrade. |
| `ssh_banner` | endlessh-style: drip endless random SSH preamble lines (never the real `SSH-…` identification), one per `ssh_banner.line_interval`. | Hang SSH clients/scanners indefinitely. Pairs well with `emulate`. |
| `http_headers` | Send a status line then endless `X-…` response headers, never the terminating blank line. | Hang HTTP clients waiting for headers/body to finish (reverse Slowloris). |
| `http_chunked` | Complete the head with `Transfer-Encoding: chunked`, then emit one-byte chunks forever (no terminating chunk). | Make a client believe a large body is still streaming. |
| `echo` | Read attacker input and dribble it back one byte per `echo.byte_interval`. | Keep an interactive client engaged; capture more of what they type. |
| `babble` | Trickle endless generated printable text (not a fixed string). | Keep content-grabbers reading; pollute their capture with junk. |

All modes emit `*:tarpit_start` (configured severity) on slot acquire, `*:tarpit_end` (low severity, `duration_ms` in meta) on connection close, and `*:tarpit_drop` when per-source or total caps are hit.

**`tarpit.emulate: true`** runs the listener's `handler:` to completion first — sending the real protocol banner and capturing the attacker's request — and *then* applies the tarpit strategy on the same connection. The captured banner/request appears in the `tarpit_start` event (`tarpit_emulated_handler` in meta). Use it to make a tarpit look like a live service instead of a black hole.

---

## `canaries:` — filesystem honeyfiles

```yaml
canaries:
  - id: shared-creds
    path: /srv/shared/passwords.xlsx
    recursive: false
    events: [write, remove, rename, chmod]    # subset of fsnotify events
    severity: critical
```

- fsnotify provides `write`, `remove`, `rename`, `create`, `chmod`. Recursive watches walk directories at startup.
- On Linux with `CAP_SYS_ADMIN`, the watcher additionally opens fanotify and detects `OPEN` (plain reads — fsnotify cannot). Failure to set up fanotify is logged and the watcher continues with fsnotify only.

---

## `url_canaries:` — HTTP/HTTPS path tokens

```yaml
url_canaries:
  - id: aws-prod-tarball
    path: /backup/aws-prod.tar.gz
    severity: critical
```

Any HTTP or HTTPS handler that sees this exact path (query string stripped) emits `canary:url:<id>` *in addition to* the regular listener event. Generate paths via `tarpit-honeypot gen-token --type=url`.

---

## `dns:` + `dns_canaries:` — DNS canary listener

```yaml
dns:
  enabled: true
  bind: 127.0.0.1:5354          # bind to :53 in production
  amplifier_detection:
    enabled: false
    window: 60s
    queries: 20                 # per-source threshold
    severity: high

dns_canaries:
  - id: prod-customer-data
    name: prod-cdb-x7q.canary.example.com
    severity: critical
```

The listener:
- Replies NXDOMAIN to all queries by default.
- If a configured honeynet has a matching hostname, returns the virtual IP via an A-record answer (TTL 60s).
- Emits `canary:dns:<id>` for any subdomain match of a configured canary.
- With `amplifier_detection` on, emits `dnscanary:amplifier_probe` when any `ANY` query arrives OR `queries` queries arrive in `window`.

---

## `sniffer:` — Linux AF_PACKET packet-capture detector

```yaml
sniffer:
  enabled: false
  interface: ""                 # blank = all
  severity: high
  arp_scan:
    distinct_ips: 16
    window: 30s
  tcp_scan:                     # L3/L4 scan-detection layer (opt-in)
    enabled: false
    distinct_ports: 16          # SYN/ACK volume threshold per source/window
    stealth_ports: 3            # NULL/FIN/Xmas threshold (lower — always hostile)
    window: 30s
    detect_fragments: true      # flag fragmented inbound probes
```

Watches the local segment (needs `CAP_NET_RAW`).

**L2 (`arp_scan`)** — emits `sniffer:arp_scan` when one MAC asks about `distinct_ips` distinct IPs within `window`, and `sniffer:arp_reply_unsolicited` for ARP replies with no corresponding request (potential cache poisoning).

**L3/L4 (`tcp_scan`)** — a second AF_PACKET socket classifies inbound IPv4 TCP (by flags) and UDP traffic and reports scans that never establish a session:

- `sniffer:tcp_null_scan` / `tcp_fin_scan` / `tcp_xmas_scan` — stealth probes (`nmap -sN/-sF/-sX`), flagged once a source hits `stealth_ports` distinct ports in `window`.
- `sniffer:tcp_syn_scan` / `tcp_ack_scan` / `tcp_maimon_scan` — SYN (`-sS`), ACK/Window (`-sA`/`-sW`), and Maimon (`-sM`, FIN+ACK) scans, flagged at `distinct_ports` (volume — a single connection's normal teardown can't trip Maimon).
- `sniffer:udp_scan` — UDP port scan (`nmap -sU`), flagged when one source sprays `distinct_ports` distinct UDP ports in `window`.
- `sniffer:encapsulation` — tunnelling / overlay traffic on the segment, over **both IPv4 and IPv6** transport: GRE, IP-in-IP, EtherIP, L2TPv3, IPv6-in-IPv4 sub-typed into **6in4 / 6to4 / ISATAP**, **DS-Lite** (IPv4-in-IPv6) and IPv6-in-IPv6 (by IP protocol), plus VXLAN, GENEVE, L2TP, Teredo, GRE-in-UDP (by UDP port). Rate-limited per source per `window`; ATT&CK T1572 / T1095.
- `sniffer:icmp_tunnel` — an ICMP / ICMPv6 echo carrying a large, high-entropy data payload: a covert ICMP tunnel (ptunnel / icmpsh / Loki). Stock pings (small, low-entropy) don't trip it. ATT&CK T1095 / T1572.

The L3/L4 layer binds three AF_PACKET sockets — IPv4, IPv6, and the L2 path — so TCP/UDP scans (all flag types), fragmentation, encapsulation, and ICMP tunnels are detected over **both IP versions**.
- `sniffer:stp_bpdu` — spanning-tree BPDUs (STP/RSTP/MSTP/PVST+) seen on the segment (mis-cabled edge port, or an injected root-bridge / topology-manipulation attempt → AiTM, T1557). Low severity, rate-limited per source MAC + variant.
- `sniffer:ip_fragmented` — fragmented inbound probes (when `detect_fragments`), one event per source per window.

This complements `correlate:port_scan` (which sees only connections that reach a listener) by catching closed-port and dropped-stealth traffic. IPv4 only; decoy-scan detection is out of scope; ICMP sweeps are handled by `correlate:icmp_sweep`.

---

## `correlate:` — in-sensor aggregation

```yaml
correlate:
  port_scan:
    enabled: true
    distinct_ports: 5
    window: 30s
    severity: high
  brute_force:
    enabled: true
    attempts: 10
    window: 60s
    per_port: true
    severity: high
  slow_scan:
    enabled: false
    distinct_ports: 10
    window: 24h
    severity: high
  icmp_sweep:
    enabled: false
    distinct_ips: 10
    window: 30s
    severity: high
  password_spray:
    enabled: false
    distinct_users: 5
    window: 300s
    severity: high
  credential_reuse:
    enabled: false
    distinct_sources: 3
    window: 1h
    severity: high
```

- **port_scan**: same source touched N distinct ports within window → `correlate:port_scan` with the port list in meta.
- **brute_force**: N attempts in window. Captures deduped credential pairs (`auth_user/auth_pass`, `bind_dn/bind_pw`, etc.) from contributing events.
- **slow_scan**: long-window scan detector; per-port state ages individually so a 1-port-per-hour scan accumulates.
- **icmp_sweep**: one source touching N distinct *destination IPs* via ICMP within window → `correlate:icmp_sweep` (a ping-sweep / live-host-mapping precursor). Keys on dest IP, not port, so it also runs for portless ICMP events.
- **password_spray**: one source trying N **distinct usernames** within window → `correlate:password_spray` (the breadth signal — the inverse of brute force, which is depth against one account). Tagged `T1110.003`.
- **credential_reuse**: the **same** credential pair attempted from N **distinct source IPs** within window → `correlate:credential_reuse` (a shared credential list / botnet — credential stuffing). The event reports the username + source count; the password is never logged. Tagged `T1110.004`.
- **path_enumeration**: one source requesting N **distinct HTTP URL paths** within window → `correlate:path_enumeration` (content discovery / dirbusting / forced browsing that per-request UA fingerprinting misses when the UA is spoofed). Tagged `T1595.003` / `T1083`.
- **dns_enumeration**: one source querying N **distinct DNS names** within window → `correlate:dns_enumeration` (subdomain brute force / NXDOMAIN flood / DGA churn). Tagged `T1590.002` / `T1568.002`.
- **beacon**: regularly-spaced call-home contact from one source → `correlate:beacon`. After `min_hits` samples it measures inter-arrival jitter (stddev/mean); a jitter `<= max_jitter_pct` over a mean interval `>= 1s` is the periodic pattern of C2 beaconing (sub-second bursts and irregular timing are excluded). Tagged `T1071`.

Beyond these, the sensor always emits a cross-protocol **`storyline:multi_stage`** event when one source touches 3+ distinct ATT&CK tactics inside 30 minutes (no config — it's driven by the `mitre_tactics` tags every event carries).

---

## `devices:` — learned-device inventory + new-device alerts

```yaml
devices:
  enabled: false
  learn: true            # true: seed a baseline on first run, then alert on new
                         # false: strict allow-list — every non-allowed device alerts
  severity: high
  allow:                 # IPs, CIDRs, and MACs that never alert
    - 10.0.0.0/8
    - aa:bb:cc:dd:ee:ff
```

When enabled the sensor records every host it observes — from the `dhcp` handler (MAC + hostname + DHCP fingerprint), the ARP sniffer, and the source IP of every handled connection — into `<data_dir>/devices.json`, and raises a `device:new` event for hosts that are neither allow-listed nor part of the learned baseline. Review with `tarpit-honeypot list-devices`.

---

## `honeynets:` — artificial networks of virtual hosts

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    gateway: 10.99.0.1
    dns: 10.99.0.2
    domain: corp.example.local

    arp_responder:                # answer ARP for virtual IPs (Linux, CAP_NET_RAW)
      enabled: false
      interface: ""

    icmp_responder:               # answer ICMP echo for virtual IPs (Linux, CAP_NET_RAW)
      enabled: false
      interface: ""

    lldp_responder:               # advertise hosts as LLDP/CDP neighbors (Linux, CAP_NET_RAW)
      enabled: false              # see "Platform support" — Linux only today
      interface: ""
      interval_s: 30
      include_cdp: false          # also emit Cisco CDP frames

    profinet_responder:           # answer PROFINET-DCP Identify (L2, Linux, CAP_NET_RAW)
      enabled: false              # for industrial hosts (siemens/moxa/ics archetypes)
      interface: ""
      severity: high              # severity of honeynet:profinet_dcp_identify

    tun:                          # open a Linux TUN, route the CIDR through it
      enabled: false              # CAP_NET_ADMIN required
      device: ""
      mtu: 1500
      # The TUN adapter answers ICMP echo and embeds a userspace TCP stack
      # (internal/tcpstack) that terminates TCP for the whole CIDR — no
      # `ip addr add` per host. For each host's `services:` ports it
      # completes a handshake with a SYN-ACK shaped to the host archetype's
      # stack fingerprint (TTL/window/MSS/window-scale/SACK/timestamps/
      # option order — what nmap -O / p0f read) and answers a single
      # request/response from the archetype banners; unbound ports RST.
      # ICMP, RST and SYN-ACK all carry the per-host archetype TTL
      # (64 Linux / 128 Windows / 255 OT), derived from `archetype:` (or
      # `os:`), so the OS fingerprint is consistent across open ports,
      # closed ports, and ping. Malformed / illegal / stealth-scan packets
      # (NULL/FIN/Xmas, SYN-FIN, bad checksums, fragments, LAND) are
      # captured as honeynet:tcp_* events. There is no extra config: the
      # open-port set + banners come from each host's `services:` below.
      # See docs/tcp-stack.md for the full design. Decoy stack: in-order
      # data only, one request/response, no retransmit/reassembly.

    hosts:
      - ip: 10.99.0.10
        hostname: web-prod-01
        os: linux
        archetype: debian 12               # overrides sensor / listener archetype
        services:
          - { port: 22,  handler: ssh }
          - { port: 80,  handler: http }
          - { port: 443, handler: https }
      - ip: fd00::20             # IPv6 hosts are supported (in v1.5+)
        hostname: dc-01
        os: windows
        services:
          - { port: 88,   handler: kerberos }
          - { port: 389,  handler: ldap }
          - { port: 445,  handler: smb }
```

When a connection's destination IP matches a virtual host, the listener dispatches to a handler instance whose Identity is `sensor.deployment_id || "honeynet/" || network_id || "/" || host_ip` — so each virtual machine has its own stable SSH banner, MAC, SMB session key, MySQL version, etc.

Per-host `archetype:` lets a single honeynet host a mix of OS shapes — `web-prod-01` can speak `debian 12`-shaped banners while `db-old-02` next door speaks `centos 7`. If omitted, the host inherits the listener archetype (if set) or the sensor archetype.

Events get `honeynet`, `honeynet_host`, `honeynet_hostname`, `honeynet_os` meta keys; SNMP/LDAP/DCE-RPC handlers additionally advertise the topology in their event meta (`honeynet_neighbors`, `honeynet_computer_accounts`, `honeynet_endpoints`).

---

## `channels:` — output sinks

```yaml
channels:
  - id: stdout
    type: stdout                   # stdout | jsonlog | sqlite | webhook | smtp | syslog | twilio | sns | snmptrap
    enabled: true                  # omit/true = on; false = defined but skipped
    format: json                   # json (default) | cef | leef | ocsf
    min_severity: low              # gate per-channel
    rate_limit_per_min: 0          # 0 = unlimited
```

Common fields (every channel type):

| Field | Meaning | Default |
|---|---|---|
| `id` | unique channel name (referenced by `routes`) | required |
| `type` | sink kind (see the table below) | required |
| `enabled` | build the sink? `false` = defined-but-dormant | true |
| `format` | wire format: `json` / `cef` / `leef` / `ocsf` | json |
| `min_severity` | drop events below this level for this channel | low |
| `rate_limit_per_min` | cap outbound sends/min (0 = unlimited) | 0 |

`enabled: false` keeps a channel **defined but off** — it is neither built
nor type-validated at startup, so an outbound sink that needs external infra
(an MQTT broker, a webhook secret, a SIEM collector) can ship in a config
and stay dormant until you set `enabled: true` and provide the
endpoint/secret. A `run` no longer aborts because a disabled broker isn't
reachable. Routes that reference a disabled channel simply don't deliver
there. (This is why the bundled `example-FULL` / `example-ADVANCED-OT`
configs ship their MQTT / webhook / remote-syslog channels disabled — they
run standalone out of the box.)

Type-specific fields (all optional unless noted):

```yaml
  # webhook
  - { id: ops-webhook, type: webhook, url: https://hooks.../tarpit,
      hmac_secret_env: TARPIT_WEBHOOK_SECRET, timeout: 5s }

  # smtp
  - { id: ops-smtp, type: smtp, host: smtp.example.com, port: 587, starttls: true,
      username_env: SMTP_USER, password_env: SMTP_PASS,
      from: "tarpit@example.com", to: ["secops@example.com"] }

  # syslog (Unix only)
  - { id: siem-syslog, type: syslog, network: tcp, address: siem.example:6514, tag: tarpit-honeypot }
  # NOTE: remote syslog (network: tcp/udp) is CLEARTEXT — events carry
  # captured credentials/payloads, so don't send them across an untrusted
  # network in the clear. Use network: local to a host syslog daemon, or
  # forward via a local TLS agent (rsyslog/syslog-ng RELP+TLS, or stunnel).

  # twilio SMS
  - { id: pager, type: twilio,
      account_sid_env: TWILIO_SID, auth_token_env: TWILIO_TOKEN,
      from: "+15555550100", to: ["+15555550111"] }

  # AWS SNS (hand-rolled Sigv4, no AWS SDK)
  - { id: lake, type: sns, topic_arn: arn:aws:sns:us-east-1:123:t,
      access_key_env: AWS_ACCESS_KEY_ID, secret_key_env: AWS_SECRET_ACCESS_KEY }

  # SNMPv2c trap. Prefer community_env (reads the community string from an
  # env var) over inline community so the write credential isn't stored in
  # the config or printed by show-config.
  - { id: nms, type: snmptrap, host: nms.example.internal, port: 162,
      community_env: SNMP_TRAP_COMMUNITY, enterprise_oid: "1.3.6.1.4.1.65535" }
```

### Channel types

| Type | Direction | Key fields | Formats | Use |
|---|---|---|---|---|
| `stdout` | local | — | json | console / journald |
| `jsonlog` | local | (writes under `sensor.data_dir`) | json | newline-JSON event log |
| `sqlite` | local | (writes under `sensor.data_dir`) | json only | powers the web UI + `list-events` / search |
| `syslog` | outbound | `network`, `address`, `tag` | json / cef / leef / ocsf | SIEM via syslog (cleartext if tcp/udp — see note) |
| `webhook` | outbound | `url`, `hmac_secret_env` | json / cef / leef / ocsf | HMAC-signed HTTP POST |
| `smtp` | outbound | `host`, `port`, `from`, `to`, `*_env` creds | json / cef / leef / ocsf | email (STARTTLS) |
| `twilio` | outbound | `account_sid_env`, `auth_token_env`, `from`, `to` | json only | SMS paging |
| `sns` | outbound | `topic_arn`, `access_key_env`, `secret_key_env` | json only | AWS SNS (hand-rolled Sigv4) |
| `snmptrap` | outbound | `host`, `community_env`, `enterprise_oid` | json only | SNMPv2c trap to an NMS |

> Secrets are read from environment variables (the `*_env` fields), never
> stored inline, so `show-config` and the config file never leak them.

### Output formats

- `json` (default) — every channel's wire shape was JSON through v1.3.
- `cef` — ArcSight format: `CEF:0|tarpit-honeypot|tarpit|1.4|<rule_id>|<name>|<sev>|<ext>`.
- `leef` — IBM QRadar v2.0: `LEEF:2.0|tarpit-honeypot|tarpit|1.4|<rule_id>|<tab><k=v>...`.
- `ocsf` — Open Cybersecurity Schema Framework Network Activity (class_uid=4001), JSON.

`sqlite`, `twilio`, `sns`, `snmptrap` reject non-JSON formats — their payloads are structured and can't take CEF/LEEF/OCSF text.

### Local vs outbound

`stdout`, `jsonlog`, `sqlite` are **local sinks**: they always receive every event so the on-disk record stays complete. The `allowlist:` and dedup window only apply to outbound sinks.

---

## `routes:` — match → channel fan-out

```yaml
routes:
  - match: { severity: ">=critical", honeynet: "ot-cell-A" }
    channels: [ot-pagerduty]
  - match: { severity: ">=high", honeynet_os: "windows" }
    channels: [corp-soc]
  - match: { rule_id: "canary:url:aws-prod-tarball" }
    channels: [ops-sms, ops-smtp]
  - match: { severity: ">=low" }
    channels: [stdout, jsonlog, sqlite]
```

`Match` fields are AND-ed; configure multiple routes for OR. Recognized:

| Field | Match against | Example |
|---|---|---|
| `severity` | event.severity, with operator `=`, `<`, `<=`, `>`, `>=` | `">=high"` |
| `honeynet` | exact match on `meta.honeynet` | `"corp-lan"` |
| `honeynet_os` | exact match on `meta.honeynet_os` | `"windows"` |
| `rule_id` | exact match on `rule_id` | `"correlate:port_scan"` |

Empty `match: {}` matches every event (useful for a catch-all archive channel).

## `forward:` — ship events to aggregator node(s)

Forwards this node's events to one or more parent **aggregators** for fleet-wide
correlation (same-source / same-AS hitting many sensors, shared infrastructure,
campaigns). Distinct from `channels:` — forwarding is batched, queued, signed,
and dedup-keyed. Listing several targets **fans out** (HA, or a site SOC plus a
global hub); each target has its own queue + retry.

```yaml
forward:
  - id: site-agg
    url: https://agg-site.corp/ingest   # parent ingest endpoint
    token_env: TARPIT_FWD_TOKEN         # bearer auth from env
    hmac_secret_env: TARPIT_FWD_HMAC    # optional body signature
    min_severity: low                   # forward all (default) ... | high | critical
    max_batch: 500                      # flush after N events (default 500)
    max_age: 2s                         # ...or at least this often (default 2s)
    queue_size: 4096                    # in-memory buffer; full sheds load + counts
  - { id: global, url: https://hub.corp/ingest, min_severity: high }   # fan-out
  - id: hub                                # multi-level: ship a rollup, not raw events
    url: https://hub.corp/ingest
    mode: rollup                           # one periodic summary instead of every event
    rollup_interval: 60s                   # summary period (default 60s)
```

Events ship as NDJSON over HTTPS **through the egress allowlist** (each
`forward.url` host is allowlisted automatically, so forwarding works under
`egress.enforce`). Each event carries the originating `sensor_id` (stable
deployment id) and a `hops` chain stamped per node, so the aggregator dedups by
`sensor_id:id` and detects loops. Delivery is at-least-once toward the parent
(bounded retry keeping the batch); a full queue sheds load with a counter, like
the sinks.

**Rollup mode (multi-level).** A higher tier doesn't need every raw event. Set
`mode: rollup` and the target ships one `fleet:rollup` event per
`rollup_interval` instead: per-window counters of the top source IPs / ASNs /
fingerprints / rules plus a severity histogram and distinct-source count. This
keeps upward volume sane at L2/L3 while preserving the correlation **keys** (who
was active, and how much). A node can mix targets — e.g. `full` to the site SOC,
`rollup` to the global hub.

## `ingest:` — accept events from child nodes (aggregator)

Turns a node into an **aggregator**: it accepts batches forwarded by child
sensors (their `forward:` targets point here) and feeds them into the same
pipeline as local events — so the store, web UI, and correlators see the whole
fleet. Composes with `listeners:` and `forward:`, so one node can be a sensor, a
mid-tier aggregator, and forward upward at once (multi-level).

```yaml
ingest:
  enabled: true
  bind: 0.0.0.0:8470            # where to accept forwarded batches
  token_env: TARPIT_INGEST_TOKEN  # required bearer token (an unauthenticated
                                  # ingest endpoint is rejected at validation)
  hmac_secret_env: ...          # optional: verify the body HMAC the child signs
  tls_cert: ...                 # optional TLS (cert+key together)
  tls_key: ...
  max_body_mb: 32               # reject larger batches (default 32)
  max_hops: 8                   # drop events that traversed more nodes (loop guard)
  dedup_window: 10m             # sensor_id:id dedup TTL (default 10m)
```

Admitted events are deduped by `sensor_id:id` and loop-guarded (an event whose
hop chain already includes this node, or that exceeds `max_hops`, is dropped) —
so a fan-out / multi-path topology can't double-count. Pair the aggregator with
a `sqlite` channel + route so forwarded events are stored and visible in the UI;
add `forward:` to relay onward to a higher tier. Store rows now carry the
originating `sensor_id` (stable, survives identical hostnames) alongside the
sensor name.

**Trust scoring + admission control (`ingest.trust`).** Ingest is
authenticated, but a shared token can't tell a healthy child from a
misconfigured or compromised one fabricating events. The scorer keeps per-sensor
windowed counters (accepted / deduped / dropped / malformed), derives a 0..1
trust score, and raises a high-severity `fleet:sensor-untrusted` event when a
node's score falls. A *malformed* event — missing `sensor_id`/`id`, an
out-of-range severity, or a timestamp implausibly far in the future — is dropped
and penalised hard. On by default wherever `ingest:` is enabled.

```yaml
ingest:
  trust:
    enabled: true            # default on when ingest is enabled
    window: 5m               # counter window
    min_events: 50           # don't score below this volume
    alert_below: 0.5         # emit fleet:sensor-untrusted under this score
    quarantine_below: 0.0    # refuse a sensor under this score (0 = alert only)
    rate_per_sec: 0          # per-sensor admission cap (0 = unlimited); protects the store
    burst: 0                 # token-bucket burst (default = rate_per_sec)
```

With `quarantine_below` set, a low-trust node is **refused** (its events dropped
before the dedup set / bus) until its window rolls and it's re-evaluated.
`rate_per_sec` caps how fast any one sensor can inject events — so a single
flooding (or compromised) node can't overwhelm the aggregator's store.

**Store scale.** The store is SQLite in WAL mode with batched transactional
inserts (the aggregator commits ingested events in one transaction, not per
row), which carries a busy aggregator comfortably. For larger fleets, scale
*horizontally* rather than vertically: ship `mode: rollup` to a higher tier (see
`forward:`) so the top stores summaries not raw events, cap per-sensor volume
with `ingest.trust.rate_per_sec`, bound size with `sensor.disk.retention_days` /
`sqlite_mb`, and push to an external TSDB/SIEM via a `channels:` sink
(syslog / webhook / mqtt / sns).

## `fleet:` — cross-sensor correlation (aggregator)

A single sensor only ever sees one vantage point. Once events from many sensors
converge on an aggregator (via `ingest:`), the **fleet** correlator runs over
the merged local + ingested stream and surfaces patterns no one node can see. It
keys events by attacker identity *and* by shared artifact, tracks the distinct
sensors (and, where useful, sources) each touches within a window, and emits a
`fleet:*` event the first time a pattern crosses its threshold (once per window).
The alerts flow through the same pipeline as everything else (store, UI, routes,
risk scoring, and onward `forward:`).

It is **on by default wherever `ingest:` is enabled** (where the patterns can
appear); a leaf sensor stays off. Set `fleet.enabled` explicitly to force it on
or off. Every threshold has a sensible default — an empty `fleet: {}` (or just
enabling `ingest:`) gets the full set.

```yaml
fleet:
  enabled: true          # default: on when ingest is enabled; set false to opt out
  window: 1h             # how long an identity's activity is remembered
  # breadth — one identity hammering many sensors:
  source_sensors: 3      # one source IP on >= N sensors -> fleet:source-multi-sensor
  asn_sensors: 5         # one ASN on >= N sensors -> fleet:asn-multi-sensor
  fp_sensors: 3          # one ja3/ja4/hassh on >= N sensors ...
  fp_sources: 5          #   ... AND >= M distinct sources -> fleet:fingerprint-shared
  # shared-artifact campaigns — the same thing recurring across sensors:
  payload_sensors: 2     # same malware hash on >= N sensors -> fleet:payload-campaign
  cred_sensors: 2        # same credential pair on >= N sensors -> fleet:credential-campaign
  cve_sensors: 3         # same CVE on >= N sensors -> fleet:cve-wave
  # coordinated infrastructure — many IPs from one block, one per target:
  subnet_sensors: 3      # a /24 (or /64) covering >= N sensors ...
  subnet_sources: 3      #   ... via >= M distinct IPs -> fleet:subnet-coordinated
  # peer-relative outlier — a sensor far louder than its peers:
  outlier_min_events: 100  # min high-sev events before a node is an outlier candidate
  outlier_factor: 4        # ... and its high-sev count must exceed this x the peer median
  outlier_min_peers: 3     # need at least this many other sensors to compare against
  # temporal — sequence / timing only visible across the fleet:
  trajectory_hits: 8       # one source walking >= N destinations in address order ...
  trajectory_sensors: 3    #   ... across >= N sensors -> fleet:scan-trajectory
  trajectory_monotonic: 0.8  # fraction of time-ordered steps moving one way
  burst_window: 5m         # short spike window for fleet:synchronized-burst
  burst_min_events: 20     # a sensor is "spiking" at >= N events in burst_window ...
  burst_sensors: 3         #   ... fire when >= N sensors spike together
  # novelty / linking / geo / playbook:
  first_contact_sensors: 3 # a brand-new ASN/fingerprint on >= N sensors -> fleet:first-fleet-contact
  first_seen_horizon: 168h # how long an identity is remembered as "seen" (novelty memory)
  pivot_sources: 5         # one composite identity from >= N IPs ...
  pivot_sensors: 3         #   ... across >= N sensors -> fleet:identity-pivot
  geo_countries: 3         # one fingerprint/credential from >= N countries ...
  geo_sensors: 2           #   ... across >= N sensors -> fleet:geo-distributed-actor
  profile_cves: 2          # a playbook is a set of >= N CVEs ...
  profile_sources: 3       #   ... shared by >= N sources ...
  profile_sensors: 2       #   ... across >= N sensors -> fleet:target-profile-match
  honeytoken_sensors: 2    # same canary token on >= N sensors -> fleet:honeytoken-spread
  cve_emergence_sensors: 2 # a brand-new CVE on >= N sensors -> fleet:cve-emergence
  cross_proto_handlers: 4  # one source on >= N distinct services ...
  cross_proto_sensors: 2   #   ... across >= N sensors -> fleet:cross-protocol-actor
  fp_asns: 3               # one fingerprint from >= N distinct ASNs ...
  fp_asn_sensors: 2        #   ... across >= N sensors -> fleet:fingerprint-asn-spread
  threat_surge_sources: 10 # >= N flagged (threat-intel/Tor) sources ...
  threat_surge_sensors: 3  #   ... across >= N sensors -> fleet:threat-intel-surge
  tool_sensors: 3          # one identified tool on >= N sensors ...
  tool_sources: 3          #   ... from >= N sources -> fleet:tool-campaign
  c2_sensors: 2            # one harvested C2/dropper URL on >= N sensors -> fleet:c2-shared
  ua_sensors: 3            # one HTTP User-Agent on >= N sensors ...
  ua_sources: 5            #   ... from >= N sources -> fleet:user-agent-shared
  tactic_sources: 8        # >= N sources using one MITRE technique ...
  tactic_sensors: 3        #   ... across >= N sensors -> fleet:tactic-convergence
  recidivist_bucket: 24h   # time bucket ("day") for recidivist tracking ...
  recidivist_windows: 3    #   ... alert at >= N distinct buckets -> fleet:recidivist-network
  port_campaign_sources: 5 # >= N sources on one dest port ...
  port_campaign_sensors: 3 #   ... across >= N sensors -> fleet:port-campaign
  port_campaign_exclude: [22, 80, 443]  # ubiquitous ports to ignore
  cred_spray_passwords: 5  # >= N distinct passwords for one username ...
  cred_spray_sensors: 2    #   ... across >= N sensors -> fleet:credential-spray-fleet
  asn_org_asns: 2          # >= N distinct ASNs under one AS-org ...
  asn_org_sensors: 5       #   ... across >= N sensors -> fleet:asn-org-campaign
  # broad-vs-targeted classifier:
  broad_coverage: 0.8    # hits spanning >= this fraction of the fleet are "broad" (downgraded)
  # downward intel feedback (serving side; needs ingest:) — see intel_feed:
  serve_intel: true      # derive + serve a fleet-intel feed (default on when fleet+ingest)
  intel_ttl: 6h          # how long a served indicator lingers
  intel_max: 10000       # cap per indicator set (ips / asns / fingerprints)
  max_list: 50           # cap the sensor/source list carried in the alert meta
```

The detectors, by the vantage axis they exploit:

| Event | Fires when | Why an aggregator is needed |
|-------|-----------|------------------------------|
| `fleet:source-multi-sensor` | one **source IP** on >= `source_sensors` sensors | a single attacker sweeping the fleet |
| `fleet:asn-multi-sensor` | one **ASN** on >= `asn_sensors` sensors | coordinated / distributed from one network (needs GeoIP-ASN enrichment) |
| `fleet:fingerprint-shared` | one **ja3/ja4/hassh** on >= `fp_sensors` sensors **and** >= `fp_sources` sources | a shared toolkit / botnet — IPs differ, client stack is identical |
| `fleet:payload-campaign` | the same artifact **SHA-256** on >= `payload_sensors` sensors | one malware sample on separate honeypots = one distribution campaign |
| `fleet:credential-campaign` | the same **username:password** on >= `cred_sensors` sensors | shared stuffing list, or a **honeytoken credential** planted on A now used against B |
| `fleet:cve-wave` | the same **CVE** on >= `cve_sensors` sensors | a worm / mass-exploitation wave; coverage tells targeted from internet-wide |
| `fleet:subnet-coordinated` | >= `subnet_sources` IPs from one **/24 (or /64)** covering >= `subnet_sensors` sensors | the one-IP-per-target botnet that slips under every per-sensor threshold |
| `fleet:outlier-sensor` | a **sensor**'s high-sev volume crosses `outlier_min_events` and exceeds `outlier_factor` x the peer median | that node was specifically found / targeted — only visible with peer baselines |
| `fleet:scan-trajectory` | one **source** hitting >= `trajectory_hits` destinations in address order across >= `trajectory_sensors` sensors | the scan's direction + rate, and the **next target** it's about to reach — only the merged view shows the walk |
| `fleet:synchronized-burst` | >= `burst_sensors` sensors each see >= `burst_min_events` within `burst_window` | a fleet-wide changepoint — the moment a new campaign / exploit goes live (no shared source needed) |
| `fleet:first-fleet-contact` | a **brand-new ASN / fingerprint** (unseen for `first_seen_horizon`) reaching >= `first_contact_sensors` sensors | new infrastructure spinning up against the deployment |
| `fleet:identity-pivot` | one composite identity (fingerprint/credential + a 2nd attribute) from >= `pivot_sources` IPs across >= `pivot_sensors` sensors | one actor behind rotating IPs — the link survives the IP change |
| `fleet:geo-distributed-actor` | one fingerprint/credential from >= `geo_countries` countries across >= `geo_sensors` sensors | fleet-scale impossible travel — a distributed proxy / botnet (needs GeoIP) |
| `fleet:target-profile-match` | >= `profile_sources` sources independently running the same >= `profile_cves`-CVE playbook across >= `profile_sensors` sensors | a shared toolkit / runbook, even without a shared fingerprint |
| `fleet:honeytoken-spread` | the same **canary token** tripped on >= `honeytoken_sensors` sensors | a planted token has leaked and is propagating — the fleet blast radius |
| `fleet:cve-emergence` | a **brand-new CVE** (novel within `first_seen_horizon`) on >= `cve_emergence_sensors` sensors | an n-day going live fleet-wide — the first wave of a freshly-weaponised vuln |
| `fleet:cross-protocol-actor` | one **source** on >= `cross_proto_handlers` distinct services across >= `cross_proto_sensors` sensors | fleet-wide service enumeration by a single actor |
| `fleet:fingerprint-asn-spread` | one **fingerprint** from >= `fp_asns` distinct ASNs across >= `fp_asn_sensors` sensors | a toolkit run from many networks (the network-of-origin axis) |
| `fleet:threat-intel-surge` | >= `threat_surge_sources` **flagged** sources (threat-intel list / Tor) across >= `threat_surge_sensors` sensors | known-bad infrastructure converging on the fleet right now (needs enrichment) |
| `fleet:tool-campaign` | one identified **tool** (meta `tools`) on >= `tool_sensors` sensors from >= `tool_sources` sources | one tool / exploit-kit sweeping the fleet (links a campaign across differing IPs/stacks) |
| `fleet:c2-shared` | one **harvested URL** (C2 / dropper) on >= `c2_sensors` sensors | shared command-and-control infra behind otherwise-distinct attacks |
| `fleet:user-agent-shared` | one **User-Agent** on >= `ua_sensors` sensors from >= `ua_sources` sources | a shared HTTP scanner / tool family (the HTTP analogue of fingerprint-shared) |
| `fleet:tactic-convergence` | one **MITRE technique** from >= `tactic_sources` sources across >= `tactic_sensors` sensors | a coordinated push on a TTP (above the CVE/tool level) |
| `fleet:recidivist-network` | an **ASN** active in >= `recidivist_windows` distinct `recidivist_bucket`s | a network that keeps coming back day after day (persistence, not breadth) |
| `fleet:port-campaign` | one **dest port** (not in `port_campaign_exclude`) from >= `port_campaign_sources` sources across >= `port_campaign_sensors` sensors | a service-targeted campaign (e.g. a new botnet on tcp/23) |
| `fleet:credential-spray-fleet` | one **username** tried with >= `cred_spray_passwords` distinct passwords across >= `cred_spray_sensors` sensors | a distributed brute-force of a single account, spread to stay under per-node thresholds |
| `fleet:asn-org-campaign` | one **AS-org** spanning >= `asn_org_asns` distinct ASNs across >= `asn_org_sensors` sensors | a provider-wide campaign that ASN-number keying misses |

Each alert carries the breadth/source counts, the (capped, sorted) `sensors` /
`sources` lists, and the `window`. The detectors run *after* enrichment, so the
ASN / geo detectors see the `asn` / `geo_country` tags — configure
`sensor.geoip.asn_db` (and city DB for geo) on the aggregator. `fleet:*` events
are never re-correlated (loop guard).

**Broad vs targeted.** Every public honeypot is scanned constantly by
Censys/Shodan/etc., so a naive breadth alert is noisy. The breadth/wave
detectors (`source-multi-sensor`, `asn-multi-sensor`, `cve-wave`) therefore add
a `coverage` ratio (`sensors_hit / active_sensors`) and a `scope`: a hit
spanning >= `broad_coverage` of the fleet is **broad** (internet background,
reported `medium`); a hit on a specific subset is **targeted** (`high`). The
shared-artifact and coordination detectors don't need this — a shared malware
hash or honeytoken credential is never background noise.

The full detector catalog (rule, what it detects, the config keys above) is
printable with `tarpit-honeypot list-fleet-rules`. The IOCs the fleet has seen
are exportable offline with `tarpit-honeypot export-iocs` (STIX 2.1 / CSV / txt /
JSON), and `tarpit-honeypot list-events --fleet` tails just the `fleet:*`
findings.

## `intel_feed:` — downward fleet-intel feedback

Events flow *up*; intel flows *down*. An aggregator that runs fleet correlation
derives indicators from its own `fleet:*` findings — the hot source IPs, ASNs,
and ja3/ja4/hassh fingerprints — and serves them as a small JSON feed at GET
`<ingest>/intel` (same bearer token as `ingest:`). This is on by default
wherever fleet correlation **and** `ingest:` are both enabled; set
`fleet.serve_intel: false` to opt out, and tune `fleet.intel_ttl` (how long an
indicator lingers, default 6h) / `fleet.intel_max` (cap per set).

Any node — including a leaf sensor that isn't itself an aggregator —
**subscribes** by pointing `intel_feed:` at a parent's feed. It polls on an
interval and hands the indicators to its enricher, which tags matching events
with `fleet_intel` (the reasons) **and** sets `threat_intel_hit` — so the
existing tarpit / severity / risk / `threat_intel_burst` machinery acts on
fleet-derived knowledge with no extra wiring. Fleet knowledge thus improves
every sensor.

```yaml
intel_feed:
  enabled: true
  url: https://agg-site.corp/intel   # parent feed endpoint (dialled via egress allowlist)
  token_env: TARPIT_FWD_TOKEN        # bearer token (the parent's ingest token)
  poll: 60s                          # poll interval (default 60s)
```

The feed URL is allowlisted automatically (like `forward.url`), so it works
under `egress.enforce`. The puller fetches once immediately so a fresh node gets
intel without waiting a full interval.

### IOC export — STIX 2.1 / TAXII 2.1 / MISP

The same fleet indicators are exportable to standard threat-intel tooling.
Wherever a node serves intel (fleet + `ingest:`), it also exposes, on the same
bearer-gated endpoint:

- `GET /intel/stix` — a **STIX 2.1** bundle of Indicator SDOs (IPs →
  `ipv4-addr`/`ipv6-addr` patterns, ASNs → `autonomous-system`, ja3/ja4/hassh →
  an `x-tarpit-fingerprint` custom pattern). Indicator IDs are deterministic
  (UUIDv5 of the pattern) so downstreams dedup cleanly.
- A minimal read-only **TAXII 2.1** API — `GET /taxii2/` (discovery),
  `/taxii2/api/`, `/taxii2/api/collections/`, and
  `/taxii2/api/collections/fleet-iocs/objects/` — so a TAXII client can discover
  and pull the `fleet-iocs` collection.

To **push** to a MISP instance, add `misp:` — a delta pusher sends only
not-yet-sent indicators as a periodic MISP event (egress-allowlisted):

```yaml
misp:
  enabled: true
  url: https://misp.corp          # MISP base URL
  key_env: TARPIT_MISP_KEY        # MISP auth key from this env var
  interval: 5m                    # push period
  event_info: tarpit fleet IOCs   # MISP event title
  distribution: "0"               # MISP distribution level (0 = your org only)
  threat_level: "2"               # threat_level_id
```

## `ioc:` — indicator-of-compromise store + feed

Every event already carries indicators — source IPs, ja3/ja4/hassh fingerprints,
ASNs, DNS names, CVE ids, captured-payload SHA-256s, harvested C2 URLs,
credentials, MACs. The IOC layer distils them into a **de-duplicated indicator
store** (type + value → first/last seen, count, max severity, last rule/source),
surfaced on the web UI's **iocs** tab and `GET /api/iocs`, and exportable offline
with `export-iocs`. The first time a **high-value** indicator is seen it also
emits an `ioc:<type>` event, which is stored locally and **forwarded** to
aggregators like any event (so a parent harvests child IOCs even in `rollup`
mode). On by default wherever an event store exists.

```yaml
ioc:
  enabled: true        # default: on when a sqlite store is configured
  emit_types:          # first-sight types that emit an ioc:<type> event
    - sha256
    - url
    - domain
    - ja3
    - ja4
    - hassh
    - cve
    - credential
```

Bare `ip` / `asn` / `mac` are tracked in the store but not emitted as events by
default (too voluminous, and already on every event); add them to `emit_types`
to change that. The ATT&CK/D3FEND attribution is persisted per event, so the
`iocs` tab, the event log, and `/api/events` all carry the techniques/defenses.
Stale indicators — not seen for `sensor.disk.retention_days` — are pruned by the
hourly retention runner (last-seen basis), the same age cap as the event store.

## `egress:` — outbound containment (do-no-harm)

A honeypot must never become an SSRF pivot, open relay, reflector, or exfil
channel — but its own telemetry has to leave the box (forwarding to a SIEM,
exporting IOCs). `egress` reconciles the two: when enabled it builds an
**allowlist** of exactly the destinations the sensor is permitted to dial, and
refuses (and records, as a high-severity `egress:denied` event) every other
outbound connection.

```yaml
sensor:
  egress:
    enabled: true            # in-process guard: route sink dials through the allowlist
    enforce: true            # + OS-level nftables backstop (Linux; needs nft + CAP_NET_ADMIN)
    allow:                   # extra destinations not modeled as a channel:
      - collector.corp:8443  #   a central event collector (fleet forwarding)
      - 10.20.0.0/16         #   an IOC / threat-intel feed range
```

The allowlist is the union of: every configured outbound **channel**'s
destination (webhook / syslog / smtp / sns / discord / twilio — derived
automatically) plus `allow` (a host, `host:port`, or CIDR). Off by default →
egress unrestricted (no behavior change).

Two enforcement layers:

- **`enabled`** — the in-process guard: the dialing sinks route through the
  allowlist, so legitimate forwarding/export keeps working while a sink dial to
  anything off the list (e.g. an SSRF redirect) is refused and recorded as a
  high-severity `egress:denied` event. Updates additively on config reload.
- **`enforce`** — additionally installs an **nftables** OUTPUT chain (Linux only;
  needs the `nft` binary + `CAP_NET_ADMIN`, installed at startup before the
  privilege drop / sandbox) that drops the sensor's packets to anything off the
  allowlist. It is scoped to the sensor's **uid** via `meta skuid`, so the rest
  of the host is untouched (run with `drop_user` so the scope is the sensor
  alone, not every root process), and permits established connections (listeners
  reply), loopback, and DNS to the system resolvers. This is the hard backstop —
  it catches even a raw `net.Dial` or a library (e.g. the MQTT paho client) that
  dials outside the in-process guard. `enforce` implies `enabled`.

Caveat: the firewall allowlists hostnames by their resolved IP at install time;
for a destination with rotating DNS, allowlist its CIDR in `allow`. Cleanup on
shutdown is best-effort (a uid-scoped, harmless-when-down table superseded on the
next start).

A second, longer example — OR semantics via multiple routes, a catch-all
archive, and a paging path:

```yaml
routes:
  # page on anything critical, or any recognised CVE exploit attempt
  - match: { severity: ">=critical" }
    channels: [pagerduty]
  - match: { rule_id: "correlate:cve_campaign" }
    channels: [pagerduty]
  # send >=high to the SOC SIEM
  - match: { severity: ">=high" }
    channels: [soc-syslog]
  # archive everything locally
  - match: {}
    channels: [stdout, jsonlog, sqlite]
```

---

## `severity_overrides:` — operator-pinned per-rule severity

You sometimes know better than the built-in default whether an event matters
*in your environment*. `severity_overrides` re-maps the **reported** severity
of matching events, so a quiet rule can be raised (page on it) or a noisy one
lowered (archive it) without patching source. It is applied in the router — the
single dispatch chokepoint — so the new level drives `routes` matching,
per-channel `min_severity`, the local store, and every sink.

```yaml
severity_overrides:
  - rule: correlate:port_scan      # an internal scanner you can't allowlist
    severity: low
  - rule: "cve:*"                  # treat any recognised CVE attempt as worst
    severity: critical
  - rule: listener:ssh-bait        # SSH brute force matters more to you
    severity: high
  - rule: "attack:dos"
    severity: medium
```

### Fields

| Field | Meaning | Values |
|---|---|---|
| `rule` | the event `rule_id` to match | exact id, or a trailing-`*` prefix |
| `severity` | the level matching events are reported at | `low` / `medium` / `high` / `critical` |

`rule` accepts either an **exact** `rule_id` (`correlate:port_scan`,
`cve:CVE-2021-44228`, `listener:http-bait`) or a **prefix** ending in `*`
(`cve:*`, `correlate:*`, `attack:*`, `canary:*`). Listener-hit events use the
id `listener:<listener-id>`; correlators use `correlate:<name>`; CVE attempts
`cve:<id>`. Discover ids from the events table, `list-events`, or the `rule`
column of `list-techniques`.

### Precedence

| Situation | Winner |
|---|---|
| an exact id and a prefix both match | the **exact** id |
| two prefixes both match | the **longest** (most specific) prefix |
| no rule matches | the built-in default severity (unchanged) |
| the override equals the default | no-op (the event is not marked) |

### Severity levels

| Level | Rank | Typical meaning |
|---|---|---|
| `low` | 1 | informational / recon noise |
| `medium` | 2 | notable but not urgent |
| `high` | 3 | likely-malicious — investigate |
| `critical` | 4 | act now (exploit attempt, ICS manipulation, leaked token) |

`routes` operators (`>=high`, …) and a channel's `min_severity` see the
**overridden** level, so an override changes what pages and what is archived.

### How the override is shown (never silent)

| Where | Marker |
|---|---|
| logs | `severity overrides active` (rule count) at start; a `severity overridden` debug line per applied event |
| events | `severity_overridden: true` + `meta.default_severity` + `meta.severity_override_rule`, carried to every sink |
| web UI | an `⌾ override` badge in the events table (tooltip: default + rule) and a spelled-out note on the event detail |

### Recipes

```yaml
# Quiet your own vuln scanner's noise (when you can't allowlist its IP):
severity_overrides:
  - rule: "correlate:*"
    severity: low

# Make every ICS/OT manipulation critical regardless of the protocol default:
severity_overrides:
  - rule: correlate:ot_kill_chain
    severity: critical
  - rule: correlate:plc_program_download
    severity: critical
  - rule: correlate:ics_mode_change
    severity: critical

# Raise one listener's events, lower a chatty discovery rule:
severity_overrides:
  - rule: "listener:mainframe"     # listener events are listener:<listener id>
    severity: high
  - rule: correlate:host_sweep
    severity: low
```

`validate-config` rejects an unknown `severity` or an empty `rule` at load, so a
typo never silently disables an override.

---

## `dedup:` and `allowlist:`

```yaml
dedup:
  default_window: 5m            # per (source_ip, rule_id) dedup for outbound sinks

allowlist:
  - 127.0.0.1/32
  - ::1/128
  - 10.0.0.0/8                  # internal scanners
```

Allowlisted source IPs **don't** trigger outbound channels (webhook, syslog, SMS, SNS, snmptrap) but **do** appear in local sinks. Use this to suppress paging from your own monitoring without losing forensic record.

---

## `listener.snmp:` — walkable SNMP MIB, profiles, walk rate-limit/tarpit

The `snmp` UDP handler answers from a **walkable** MIB, so real `snmpwalk` / `snmpbulkwalk` traverse it (proper lexicographic GetNext + bounded GetBulk). Per-listener:

```yaml
- id: snmp-bait
  proto: udp
  bind: 0.0.0.0:161
  handler: snmp
  snmp:
    mib_profile: network      # minimal | host (default) | network | full
    walk_rate_per_min: 200    # cap GetNext/GetBulk varbinds per source IP / min (0 = unlimited)
    walk_tarpit: 750ms        # delay over-limit responses instead of dropping (slows mass walkers)
```

- **`mib_profile`** — which subtrees the MIB exposes: `minimal` (system group), `host` (+ `ifNumber` + full `ifTable`), `network` (+ ip group + the `ipNetToMediaTable` ARP table synthesized from the honeynet topology, so a walk enumerates the artificial L2/L3 inventory), `full` (everything modelled). Default `host`.
- **`walk_rate_per_min`** — per-source walk budget. Over it, the walk step is **dropped** (or tarpitted), and `snmp-walk-rate-exceeded` (T1046) is flagged.
- **`walk_tarpit`** — when set, over-limit walk responses are delayed by this duration instead of dropped, slowing a mass walker to a crawl while keeping it engaged.

SetRequest is always captured + flagged (`snmp-set-attempt`) and never applied; SNMPv3 is rejected.

---

## `interaction:` — interaction depth + experimental-feature guardrails

The docs note that some signals are infeasible in a low-interaction emulator. The `interaction:` block makes that a **hard guardrail** rather than an assumption: experimental / high-interaction capture knobs only unlock in `medium_experimental` mode, and setting one in `low` mode is a config **error** (not a silent downgrade).

```yaml
interaction:
  mode: low                      # low (default) | medium_experimental
  http2_probe_capture: disabled  # disabled (default) | headers_only  (needs medium_experimental)
  ssh_kex_depth: kexinit_only    # kexinit_only (default) | extended_experimental (needs medium_experimental)
  browser_traps: off             # off only — locked; no real browser is ever driven
```

- **`mode`** — `low` is the safe default: every emitted capture is something a low-interaction emulator can actually produce. `medium_experimental` unlocks the knobs below (best-effort, possibly incomplete — the sensor is still never a real browser / OS / crypto stack).
- **`http2_probe_capture`** — `headers_only` is a future-proof, header-only knob; full HTTP/2 frame / HPACK / multiplexed-stream reconstruction is not implemented in any mode.
- **`ssh_kex_depth`** — `kexinit_only` captures the client KEXINIT (HASSH); `extended_experimental` is a placeholder for deeper best-effort KEX capture.
- **`browser_traps`** — locked to `off`. JavaScript / canvas / beacon traps can't execute without driving a real browser.

**CLI.** `--interaction-mode low|medium_experimental` overrides `interaction.mode` for `run` / `validate-config` / `show-config` (it flows through the normal pre-validation override path, so the guardrail still applies). `tarpit-honeypot list-unavailable-capabilities` prints the exact disabled / locked / infeasible feature matrix for the active config (`--json` for machine output) — so an operator never assumes a capability that the deployment can't produce.

---

## Hot reload classification

Run `tarpit-honeypot validate-config -c new.yaml --diff old.yaml` to see what would happen on SIGHUP. Cheat sheet:

| Change type | Behavior |
|---|---|
| `channels` add/remove/modify | Hot-reloadable. Sinks rebuild; retry queues reset. |
| `routes` change | Hot-reloadable. |
| `allowlist` change | Hot-reloadable. |
| `dedup.default_window` change | Hot-reloadable. |
| `correlate.*` thresholds | Hot-reloadable. |
| `canaries`, `url_canaries`, `dns_canaries` add/remove | Hot-reloadable. |
| `listeners` add/remove/modify | Hot-reloadable (per-listener restart). |
| `sensor.name` / `sensor.data_dir` / `sensor.drop_user` | Restart required. |
| `ui.*` | Restart required (web server stays as-is). |
| `dns.bind` / `dns.enabled` | Restart required. |
| `sniffer.interface` / `sniffer.enabled` | Restart required. |
| `honeynets[].arp_responder` / `icmp_responder` / `tun` | Restart required. |

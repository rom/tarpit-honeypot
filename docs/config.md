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
| `disk.retention_days` | Hourly runner deletes events / files / DB rows older than this. 0 disables time-based pruning (size caps still apply). |
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
      strategy: sticky                  # sticky | trickle | keepalive
      max_per_source: 4
      max_total: 256
      emulate: false                    # run handler: first (banner+capture), then tarpit
      trickle:    { text: "Loading...\n", byte_interval: 2s }
      keepalive:  { interval: 30s }
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

All three modes emit `*:tarpit_start` (configured severity) on slot acquire, `*:tarpit_end` (low severity, `duration_ms` in meta) on connection close, and `*:tarpit_drop` when per-source or total caps are hit.

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
    enabled: true            # off by default → egress unrestricted (no change)
    allow:                   # extra destinations not modeled as a channel:
      - collector.corp:8443  #   a central event collector (fleet forwarding)
      - 10.20.0.0/16         #   an IOC / threat-intel feed range
```

The allowlist is the union of: every configured outbound **channel**'s
destination (webhook / syslog / smtp / sns / discord / twilio — derived
automatically) plus `allow` (a host, `host:port`, or CIDR). The dialing sinks
route through this guard, so legitimate forwarding/export keeps working while
anything off the list is denied. The allowlist updates additively on config
reload. (MQTT brokers reached via the paho client dial outside the in-process
guard; allowlist them at the OS firewall if you enforce egress there too.)

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

# tarpit-honeypot

A single static Go binary that runs a low-to-medium-interaction deception
sensor: protocol-shaped honeypots on configurable ports, file/URL/DNS
canary tokens, network sweep detection, port-scan / brute-force
correlation, per-event pcap capture, and pluggable outbound alerting.

CGO-free. Linux amd64 / arm64 / armv7 / armv6 static builds.

See [`design.md`](design.md) for the full design conversation and
phasing decisions.

## Features at a glance

- **TCP honeypots** in three modes: `drop`, `banner` (protocol handler),
  or `tarpit` (sticky / trickle / keepalive).
- **UDP honeypots** in `drop` or `banner` mode with protocol handlers.
- **Built-in protocol handlers** (28 in total):
  - Generic: `raw`
  - IT/TCP: `ssh`, `http`, `https`, `telnet`, `ftp`, `smb`, `vnc`, `smtp_recv`, `rdp`, `winrm`, `dcerpc`, `ldap`, `kerberos`, `postgres`, `mysql`, `redis`
  - ICS/TCP: `modbus`, `s7`, `iec104`, `mqtt`, `opcua`, `ethernetip`
  - UDP: `snmp`, `ntp`, `bacnet`, `tftp`, `ipmi`
- **Client fingerprinting**:
  - **JA3** + **JA4** from the TLS ClientHello (HTTPS handler).
  - **JA4H** from the HTTP request line + headers (HTTP/HTTPS handlers).
  - **HASSH** from the SSH KEXINIT.
  - All four are stable across browser / scanner GREASE shuffling.
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
- **ARP sniffer** (Linux AF_PACKET): detects ARP scans (one MAC asking
  about many distinct IPs) and unsolicited replies (ARP-cache poisoning).
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
- **DNS amplifier-probe detection**: the DNS canary listener flags
  any `ANY` (qtype=255) query immediately, or `N` queries from one
  source within a window, with a separate `dnscanary:amplifier_probe`
  event.
- **Embedded SQLite event index** for queryable history, with WAL-mode
  concurrent reads.
- **Read-only web UI** on loopback: 24h summary + filterable event table
  + per-event detail. Non-loopback binds refused without TLS + auth token.
- **Routing**: per-channel rate-limit, min-severity gate, severity-match
  route expressions (`>=high`, `<medium`, `=critical`), IP/CIDR allowlist
  (outbound-only — local sinks always receive).
- **Outbound channels**: `webhook` (HMAC-SHA256), `smtp` (STARTTLS),
  `syslog` (RFC 5424 over local/tcp/udp/unix), `twilio` (SMS), `sns`
  (AWS SNS via hand-rolled Sigv4 — no AWS SDK dependency), `snmptrap`
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
  (Linux). Refuses uid 0. Pairs with `systemd AmbientCapabilities` for
  privileged port binding.
- **Static cross-compile** for `linux/amd64`, `linux/arm64`, `linux/armv7`,
  `linux/armv6`. CGO never required.

## Status

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

The full schema is documented inline in
`configs/tarpit-honeypot.example.yaml`. Key sections:

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

### `correlate.port_scan` + `correlate.brute_force`

In-memory windowed counters. Emit higher-severity aggregate events when
thresholds are crossed. Aggregate events are deduped within the window
so a sustained scan doesn't flood sinks.

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
and `auth_token_env` are configured.

## Protocol handlers in detail

| Handler | Port | What it does |
|---|---|---|
| `raw` | any | Sends literal `banner:`, reads up to `read_bytes`. |
| `ssh` | 22 | Sends SSH-2.0 banner, reads client banner, sends "Protocol mismatch". Captures client_id. |
| `http` | 80 | Reads request headers, replies with nginx 401 Unauthorized. Captures request_line + Host + matches URL canaries. |
| `https` | 443 | Auto-generated self-signed ECDSA cert cached under `<data_dir>/tls/`, then runs the HTTP handler. Captures TLS version + SNI. |
| `telnet` | 23 | Sends IAC option negotiation + login prompt. Captures up to one line of input. |
| `ftp` | 21 | 220 banner → USER → 331 → PASS → 530. Captures user + pass lines. |
| `smb` | 445 | SMB1 Negotiate Protocol Request handler: captures offered dialects, selects NT LM 0.12, replies with a believable Negotiate Response. SMB2 clients get a STATUS_NOT_IMPLEMENTED rejection. |
| `vnc` | 5900 | RFB 3.8 version exchange + VNC auth challenge. Captures `client_version` + raw DES-encrypted `auth_response_hex` from brute-force tools. Always replies "auth failed". |
| `smtp_recv` | 25 | ESMTP receive listener. Captures `helo`, `auth_mech`, `auth_user`, `auth_pass` (from AUTH PLAIN / LOGIN), `mail_from`, `rcpt_to`, `message_head`. STARTTLS rejected with 454 so the client falls back to plaintext. |
| `rdp` | 3389 | X.224 Connection Request parser. Extracts `mstshash` Cookie (often the targeted username) and `RDP_NEG_REQ` flags. Replies CC with PROTOCOL_SSL selected. |
| `winrm` | 5985 | HTTP 401 Negotiate+Basic challenge. Decodes `Authorization: Basic` credentials into `basic_user` / `basic_pass`. |
| `dcerpc` | 135 | Endpoint Mapper bind handler. Parses the first abstract interface UUID. Replies bind_ack with NDR transfer syntax. |
| `ldap` | 389 | Hand-rolled BER decoder for BindRequest. Captures `bind_dn` + cleartext `bind_pw` (simple auth) or `sasl_mechanism`. Replies BindResponse 49 (invalidCredentials). |
| `kerberos` | 88 | ASN.1 reader for AS-REQ / TGS-REQ. Replies KRB-ERROR KDC_ERR_PREAUTH_REQUIRED. |
| `postgres` | 5432 | Startup + AuthenticationCleartextPassword + ErrorResponse. Captures `username`, `database`, `password`. Handles SSLRequest / GSSEncRequest fallback. |
| `mysql` | 3306 | Server-first Handshake (v5.7.42-honeypot). Captures `username`, `auth_response_hex`, optional `database`. Replies ERR_Packet 1045. |
| `redis` | 6379 | RESP parser (multi-bulk and inline). Captures `auth_password` from AUTH and a short list of issued `commands`. Returns RESP errors. |
| `ipmi` (UDP) | 623 | RMCP ASF Presence Ping → Pong reply with IPMI 1.5/2.0 entity flag. RMCP+ class logged but not answered (no real keying material). |
| `modbus` | 502 | MBAP header parser. Captures function_code + unit_id + transaction_id. Plausible success for FC 1/2/3/4/11; Modbus exception for everything else. |
| `s7` | 102 | TPKT/COTP parser. Replies to Connection Request (0xE0) with Connection Confirm (0xD0) echoing params. |
| `iec104` | 2404 | BVLC frame parser. Classifies I/S/U-format, replies STARTDT_CON. |
| `mqtt` | 1883 | CONNECT parser. Captures protocol_name, version, keepalive, client_id, **username, password**. Replies CONNACK accepted. |
| `opcua` | 4840 | TCP transport layer. Reads HEL, replies ACK. Captures endpoint URL. |
| `ethernetip` | 44818 | EtherNet/IP encapsulation. Handles RegisterSession + ListIdentity (advertises fake Allen-Bradley 1756-L73). |
| `snmp` (UDP) | 161 | gosnmp-backed SNMPv1/v2c decoder. Captures **community string** + requested OIDs. Replies GetResponse with Null values. SNMPv3 rejected. |
| `ntp` (UDP) | 123 | NTPv4 mode 3 → mode 4 server reply with echoed origin timestamp. **Mode 7 (private / monlist) deliberately silent** — refusing to be an amplifier. |
| `bacnet` (UDP) | 47808 | BVLC + NPDU + APDU parser. Replies only to Who-Is (service 0x08) with an I-Am announcing instance 1234. |
| `tftp` (UDP) | 69 | RFC 1350 RRQ/WRQ parser. Captures **filename + transfer mode + RFC 2347 options**. Always replies ERROR opcode 5 code 2 (Access violation) — never serves files. |

## Tarpit strategies

| Strategy | Behavior |
|---|---|
| `sticky` | Accept and never read/write. Kernel TCP keepalive will eventually notice dead peers. |
| `trickle` | Write one byte of the configured `tarpit.trickle.text` every `byte_interval`. Cycles the string forever. |
| `keepalive` | Write a NUL byte every `tarpit.keepalive.interval`. Cheapest option. |

All tarpit modes emit a `*:tarpit_start` event (at the listener's
configured severity) when the slot is acquired, and a `*:tarpit_end`
event (at `low` severity, with `duration_ms` in meta) when the
connection terminates. When the per-source or total cap is hit, a
`*:tarpit_drop` event fires instead.

## Detection coverage

Beyond per-listener events, the sensor fires aggregate / token events:

- `correlate:port_scan` — same source touched N distinct ports within a
  configurable window.
- `correlate:brute_force` — same source touched the same port N times in
  the window (optionally per-port). Aggregate meta carries the deduped
  `credentials` array extracted from the contributing events.
- `correlate:slow_scan` — long-window scan detector (default 24h /
  10 distinct ports). Meta includes `first_seen`, `last_seen`,
  `spread_seconds`, `ports`.
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
| `syslog` | RFC 5424 over `local`, `tcp`, `udp`, or `unix` (path). |
| `twilio` | SMS via Twilio REST. One SMS per recipient; failures don't block others. Body capped at 1500 chars. |
| `sns` | AWS SNS Publish via hand-rolled Sigv4 (no AWS SDK). Supports STS session tokens. Region inferred from topic ARN if not set. |
| `snmptrap` | SNMPv2c trap via gosnmp. Five custom OIDs under a configurable enterprise prefix carry event_id / rule_id / severity / source / sensor. |

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
- `/events` — filterable table: `?source=`, `?rule=`, `?since=24h`,
  `?severity=high`, `?limit=N`.
- `/events/<id>` — full event detail with banner sent, base64 payload,
  meta table.
- `/api/events`, `/api/summary` — JSON equivalents.
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

## Counter-fingerprinting

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

## What's NOT in v1.0

- **Windows service registration.** The binary will run on Windows but
  there's no SCM integration yet.
- **fanotify on Windows.** ETW-based read detection would be the
  equivalent path.
- **L2 sniffer on Windows.** Would need Npcap (license-sensitive).
- **Prometheus `/metrics` endpoint.** Per-channel counters are
  collected via `Router.Stats()` but not exposed yet over HTTP.
- **GeoIP / rDNS / ASN enrichment.** Original design included these;
  not wired up.
- **CEF / LEEF / OCSF output formats.** SIEMs that prefer those
  formats currently have to transform our JSON.

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

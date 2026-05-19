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
sniffer:       { ... }     # AF_PACKET ARP scan detector (linux only)
correlate:     { ... }     # port-scan / brute-force / slow-scan
honeynets:     [ ... ]     # artificial networks of virtual hosts
dedup:         { ... }     # event dedup window
allowlist:     [ ... ]     # source IPs that bypass outbound alerts
channels:      [ ... ]     # output sinks (stdout, syslog, webhook, sns, ...)
routes:        [ ... ]     # severity / honeynet / rule predicates -> channels
```

---

## `sensor:` — identity, disk, enrichment

```yaml
sensor:
  name: ""                    # blank = hostname()
  data_dir: /var/lib/tarpit-honeypot
  deployment_id: ""           # blank = auto-generate + persist
  archetype: ""               # see "archetypes" section / `help archetypes`
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

---

## `ui:` — read-only web UI

```yaml
ui:
  enabled: false
  bind: 127.0.0.1:8088
  tls_cert: ""
  tls_key:  ""
  auth_token_env: ""    # env var holding the bearer token
```

- Bind to anything non-loopback **requires both** `tls_cert + tls_key` and `auth_token_env`. Validation rejects the config otherwise.
- The UI is strictly read-only — no write endpoints.
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

**TCP-only:** `raw`, `ssh`, `http`, `https`, `telnet`, `ftp`, `smb`, `vnc`, `smtp_recv`, `rdp`, `winrm`, `dcerpc`, `ldap`, `kerberos`, `postgres`, `mysql`, `redis`, `modbus`, `s7`, `iec104`, `mqtt`, `opcua`, `ethernetip`, `syslog_tcp`, `rtsp`, `dockerapi`, `melsec`, `xmpp`, `amqp`, `ipp`.

**UDP-only:** `raw`, `snmp`, `ntp`, `bacnet`, `tftp`, `ipmi`, `syslog_udp`, `radius`, `sip`, `ssdp`, `cldap`, `llmnr`, `nbns`, `fins`, `coap`, `knx`.

Validation rejects a TCP-only handler on a UDP listener and vice versa. See [`README.md`](../README.md#protocol-handlers-in-detail) for per-handler capture detail.

### Tarpit strategies

| Strategy | Connection behavior | Use when |
|---|---|---|
| `sticky` | Hold forever, no read/write. Kernel TCP keepalive notices dead peers. | Punish persistent scanners cheaply. |
| `trickle` | Write 1 byte of `trickle.text` every `byte_interval`, cycling. | Make banner-grabbers wait for content. |
| `keepalive` | Write a NUL byte every `keepalive.interval`. | Cheapest persistent presence; minimal bandwidth. |

All three modes emit `*:tarpit_start` (configured severity) on slot acquire, `*:tarpit_end` (low severity, `duration_ms` in meta) on connection close, and `*:tarpit_drop` when per-source or total caps are hit.

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

## `sniffer:` — Linux AF_PACKET ARP detector

```yaml
sniffer:
  enabled: false
  interface: ""                 # blank = all
  severity: high
  arp_scan:
    distinct_ips: 16
    window: 30s
```

Watches the local segment. Emits `sniffer:arp_scan` when one MAC asks about `distinct_ips` distinct IPs within `window`, and `sniffer:arp_reply_unsolicited` for ARP replies with no corresponding request (potential cache poisoning).

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
```

- **port_scan**: same source touched N distinct ports within window → `correlate:port_scan` with the port list in meta.
- **brute_force**: N attempts in window. Captures deduped credential pairs (`auth_user/auth_pass`, `bind_dn/bind_pw`, etc.) from contributing events.
- **slow_scan**: long-window scan detector; per-port state ages individually so a 1-port-per-hour scan accumulates.

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

    tun:                          # open a Linux TUN, route the CIDR through it
      enabled: false              # CAP_NET_ADMIN required
      device: ""
      mtu: 1500

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
    format: json                   # json (default) | cef | leef | ocsf
    min_severity: low              # gate per-channel
    rate_limit_per_min: 0          # 0 = unlimited
```

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

  # twilio SMS
  - { id: pager, type: twilio,
      account_sid_env: TWILIO_SID, auth_token_env: TWILIO_TOKEN,
      from: "+15555550100", to: ["+15555550111"] }

  # AWS SNS (hand-rolled Sigv4, no AWS SDK)
  - { id: lake, type: sns, topic_arn: arn:aws:sns:us-east-1:123:t,
      access_key_env: AWS_ACCESS_KEY_ID, secret_key_env: AWS_SECRET_ACCESS_KEY }

  # SNMPv2c trap
  - { id: nms, type: snmptrap, host: nms.example.internal, port: 162,
      community: tarpit, enterprise_oid: "1.3.6.1.4.1.65535" }
```

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

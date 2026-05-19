# Integrations Guide

How to wire tarpit-honeypot into the broader security / observability stack. Each section is self-contained: the inbound side (what the tool exposes) and the outbound side (where it sends data) covered separately.

For the YAML reference see [`config.md`](config.md); for CLI invocations see [`cli.md`](cli.md).

---

## 1. Outbound channels — sending events to SIEMs and pagers

The sensor's `channels:` section drives the outbound side. Pick a `type:` and add the type-specific fields; pick a `format:` if the channel emits text events. Every channel has `min_severity` and `rate_limit_per_min` gates.

### Splunk / generic JSON ingest

```yaml
channels:
  - id: splunk
    type: webhook
    url: https://splunk.example.com:8088/services/collector/raw
    hmac_secret_env: SPLUNK_HEC_HMAC
    timeout: 5s
    format: json
    min_severity: low
```

Splunk's HTTP Event Collector accepts the JSON body directly. Use the `Authorization: Splunk <token>` header pattern via a `hmac_secret_env`-driven HMAC if you're routing through a CDN that needs request signing.

### ArcSight (CEF)

```yaml
channels:
  - id: arcsight
    type: syslog
    network: tcp
    address: arcsight.example.com:514
    tag: tarpit-honeypot
    format: cef
    min_severity: medium
```

ArcSight Smart Connectors parse the CEF header (`CEF:0|tarpit-honeypot|tarpit|<v>|<rule_id>|<name>|<sev>|<ext>`). Severity maps low=2, medium=5, high=7, critical=10 per the standard ArcSight convention.

### IBM QRadar (LEEF)

```yaml
channels:
  - id: qradar
    type: syslog
    network: tcp
    address: qradar.example.com:514
    tag: tarpit-honeypot
    format: leef
    min_severity: medium
```

QRadar's DSM Editor auto-discovers the LEEF header. Custom field extraction works against the tab-delimited extension (`src`, `srcPort`, `dst`, `dstPort`, `proto`, `app`, `meta_*`).

### AWS Security Lake / Snowflake / Athena (OCSF)

```yaml
channels:
  - id: aws-lake
    type: webhook
    url: https://lake-ingest.example.com/v1/events
    format: ocsf
    min_severity: low
```

The OCSF formatter emits Network Activity records (`class_uid=4001`) with the metadata.product struct identifying the sensor. AWS Security Lake's S3 ingest expects newline-delimited JSON; pair this webhook with a stream processor (Lambda / Kinesis Firehose) that batches and writes to S3.

### Elastic / OpenSearch (JSON via webhook)

Elastic's ingest API or Logstash HTTP input both accept the default JSON. Use a Logstash filter to map `meta.geo_country` etc. into ECS fields:

```ruby
# logstash.conf snippet
filter {
  mutate {
    rename => { "[meta][geo_country]" => "[source][geo][country_iso_code]" }
    rename => { "[meta][asn]"         => "[source][as][number]" }
    rename => { "[meta][asn_org]"     => "[source][as][organization][name]" }
    rename => { "[meta][rdns]"        => "[source][domain]" }
  }
}
```

### MQTT broker (IoT pipelines)

```yaml
channels:
  - id: mqtt-pipeline
    type: mqtt
    url: tcp://broker.example.internal:1883
    topic: security/honeypot/events
    qos: 1
    retain: false
    username_env: MQTT_USER
    password_env: MQTT_PASS
    format: json
    min_severity: low
```

The MQTT sink uses Paho v3.1.1 over TCP / TLS / WebSocket. URL schemes:

- `tcp://broker:1883` — plain
- `ssl://broker:8883` — TLS
- `ws://broker:8080/mqtt` — WebSocket
- `wss://broker:8081/mqtt` — secure WebSocket

QoS 0 (at-most-once) is the lowest-latency option. QoS 1 (at-least-once) is the default for security data — the broker re-publishes on disconnect. Retain is generally `false` for events (you don't want late subscribers to see the last event as if it were live).

For AWS IoT Core, use `ssl://<endpoint>:8883` with mTLS via the `tls_cert` / `tls_key` env path scheme on the broker side; the sensor's MQTT client uses Go's standard `crypto/tls` and trusts system CAs.

### Twilio SMS pager

```yaml
channels:
  - id: oncall-sms
    type: twilio
    account_sid_env: TWILIO_SID
    auth_token_env: TWILIO_TOKEN
    from: "+15555550100"
    to: ["+15555550199", "+15555550200"]
    min_severity: critical
    rate_limit_per_min: 6
```

Sends one SMS per recipient per event. Body is ~150 chars: `[severity] rule_id from src_ip → dst_ip:dst_port`. Rate-limit aggressively — three pages an hour is usually enough.

### AWS SNS

```yaml
channels:
  - id: sns-critical
    type: sns
    topic_arn: arn:aws:sns:us-east-1:123456789012:tarpit-critical
    access_key_env: AWS_ACCESS_KEY_ID
    secret_key_env: AWS_SECRET_ACCESS_KEY
    # session_token_env: AWS_SESSION_TOKEN     # for STS-issued creds
    min_severity: critical
```

Uses a hand-rolled Sigv4 signer — no AWS SDK on the dependency tree. STS session tokens supported via `session_token_env`. Region is inferred from the topic ARN.

### SNMPv2c trap

```yaml
channels:
  - id: nms
    type: snmptrap
    host: nms.example.internal
    port: 162
    community: tarpit
    enterprise_oid: "1.3.6.1.4.1.65535"
    min_severity: high
```

Sends one v2c trap per event. The trap carries five custom OIDs under `enterprise_oid`: `.1` event id, `.2` rule_id, `.3` severity, `.4` source IP+port, `.5` sensor hostname.

### Prometheus scrape

`/metrics` is the standard Prometheus text-format exposition on the same listener as the web UI. Authenticate the same way the rest of the UI does (bearer token if configured, loopback-only otherwise).

```yaml
- job_name: tarpit-honeypot
  bearer_token_file: /etc/secrets/tarpit-ui-token
  scrape_interval: 30s
  static_configs:
    - targets: ['sensor.example.internal:8088']
```

Exposed metrics: `tarpit_sink_*_total{channel}`, `tarpit_honeynet_*`, `tarpit_store_db_bytes`, `tarpit_build_info{version,commit}`, `tarpit_uptime_seconds`, `tarpit_panic_recoveries_total`, `tarpit_panic_recoveries_by_name_total{name}`.

### Grafana dashboard JSON

A minimal Grafana dashboard JSON for the metrics above is not bundled in-tree — recommended panels:

- `rate(tarpit_sink_dropped_total[5m])` per channel — alert on > 0
- `rate(tarpit_panic_recoveries_total[5m])` — alert on > 0
- `tarpit_honeynet_hosts` — gauge
- `tarpit_store_db_bytes` — gauge (warn at 80% of disk cap)

---

## 2. Inbound — what the sensor accepts

### Non-standard ports

Every protocol handler is configurable to bind anywhere. The handler name (`ssh`, `http`, etc.) selects the application-layer **behavior**; `bind:` selects the **port**. Examples:

```yaml
listeners:
  - { id: ssh-on-2222,   proto: tcp, bind: 0.0.0.0:2222,  mode: banner, handler: ssh }
  - { id: ssh-on-22,     proto: tcp, bind: 0.0.0.0:22,    mode: banner, handler: ssh }
  - { id: http-on-8080,  proto: tcp, bind: 0.0.0.0:8080,  mode: banner, handler: http }
  - { id: modbus-quirk,  proto: tcp, bind: 0.0.0.0:1502,  mode: banner, handler: modbus }
  - { id: ipv6-ssh,      proto: tcp, bind: "[::]:2222",   mode: banner, handler: ssh }
```

A common operator pattern: bind low ports on the real-IP side (via `AmbientCapabilities=CAP_NET_BIND_SERVICE`) and high-port copies on alternative interfaces for testing. The honeynet dispatch (per-destination-IP) supports the same handler on the same port for many virtual hosts.

### Protocol handler catalog

By family, with the most common port. All are configurable to any port via `bind:`.

**IT / general:**

| Handler | Default port | What |
|---|---|---|
| `ssh` | 22 | OpenSSH banner exchange + KEXINIT (for HASSH) |
| `http` | 80 | nginx-shaped 401 with URL canary matching |
| `https` | 443 | self-signed TLS (with cert rotation) wrapping `http` |
| `telnet` | 23 | IAC negotiation + login prompt |
| `ftp` | 21 | USER/PASS capture |
| `smb` | 445 | SMB1 negotiate + SMB2 STATUS_NOT_IMPLEMENTED reject |
| `vnc` | 5900 | RFB 3.8 + DES auth challenge |
| `smtp_recv` | 25 | ESMTP receive with AUTH PLAIN/LOGIN capture |
| `rdp` | 3389 | X.224 CR/CC with PROTOCOL_SSL select |
| `winrm` | 5985 | HTTP 401 Negotiate+Basic |
| `dcerpc` | 135 | bind/bind_ack with abstract UUID parse |
| `ldap` | 389 | BindRequest with simple-auth + SASL capture |
| `cldap` | 389 (UDP) | CLDAP rootDSE / Netlogon search |
| `kerberos` | 88 | AS-REQ → KRB-ERROR PREAUTH_REQUIRED |
| `postgres` | 5432 | startup + cleartext password capture |
| `mysql` | 3306 | server-first handshake + auth_response capture |
| `redis` | 6379 | RESP with AUTH password capture |
| `syslog_tcp` | 514 | octet-counting + non-transparent framing |
| `syslog_udp` | 514 | RFC 3164/5424 capture |
| `rtsp` | 554 | RTSP/1.0 401 Digest |
| `dockerapi` | 2375 | unauthenticated Docker daemon mimic |
| `xmpp` | 5222 | stream:features advertising PLAIN/SCRAM-SHA-1 |
| `amqp` | 5672 | RabbitMQ Connection.Start, captures PLAIN creds |
| `ipp` | 631 | CUPS Get-Printer-Attributes (Brother HL-shaped) |

**ICS / OT:**

| Handler | Default port | What |
|---|---|---|
| `modbus` | 502 | MBAP function-code parser |
| `s7` | 102 | TPKT/COTP Connection Request → Confirm |
| `iec104` | 2404 | BVLC frame parser, STARTDT_CON reply |
| `mqtt` | 1883 | CONNECT parser with username/password capture |
| `opcua` | 4840 | TCP-layer HEL → ACK |
| `ethernetip` | 44818 | RegisterSession + ListIdentity (Allen-Bradley) |
| `bacnet` | 47808 (UDP) | Who-Is → I-Am |
| `fins` | 9600 (UDP) | Omron CPU-data-read response |
| `melsec` | 1025 (TCP) | Mitsubishi 3E frame CPU read |

**Network services / discovery / poisoning:**

| Handler | Default port | What |
|---|---|---|
| `radius` | 1812 (UDP) | Access-Request capture, Access-Reject reply |
| `sip` | 5060 (UDP) | OPTIONS / REGISTER / INVITE parse, 200 OK reply |
| `ssdp` | 1900 (UDP) | M-SEARCH → fake router NOTIFY |
| `llmnr` | 5355 (UDP) | poisoning responder catching Windows fallback lookups |
| `nbns` | 137 (UDP) | NetBIOS-NS responder catching SMB-relay precursors |
| `snmp` | 161 (UDP) | v1/v2c GetRequest with community capture |
| `ntp` | 123 (UDP) | mode-3 → mode-4; mode-7 silenced (no monlist amplifier) |
| `tftp` | 69 (UDP) | RRQ/WRQ filename capture, ERROR access_violation reply |
| `ipmi` | 623 (UDP) | RMCP Presence Ping → Pong |
| `coap` | 5683 (UDP) | RFC 7252 GET parser, /.well-known/core reply |
| `knx` | 3671 (UDP) | KNXnet/IP SEARCH/DESCRIPTION → MDT IP router |

### LLMNR + NetBIOS poisoning catcher

These two handlers are the standout for AD environments. Windows clients running `nslookup myshare` will:

1. First ask DNS — usually NXDOMAIN for typo'd / single-label names.
2. Then broadcast LLMNR (UDP 5355) asking the local segment.
3. Then broadcast NetBIOS-NS (UDP 137) asking the local segment.

Attackers using Responder.py or Inveigh claim to be every name and harvest NTLMv2 challenges from the resulting SMB connect. The honeypot catches these by **observing the queries** at high severity — anyone running Responder shows up in your event stream the moment they answer their first LLMNR broadcast.

```yaml
listeners:
  - { id: llmnr, proto: udp, bind: 0.0.0.0:5355, mode: banner, handler: llmnr, severity: critical }
  - { id: nbns,  proto: udp, bind: 0.0.0.0:137,  mode: banner, handler: nbns,  severity: critical }
  # And the SMB landing trap for when the Windows client follows up:
  - { id: smb,   proto: tcp, bind: 0.0.0.0:445,  mode: banner, handler: smb,   severity: critical, capture: true }
```

Bind these on an unused IP on the same VLAN as Windows clients (or use the honeynet's `arp_responder` so the sensor claims a free IP). The poisoning attempt fires `listener:llmnr` / `listener:nbns` events with the queried name in meta; the follow-on SMB connect fires `listener:smb` with the full NTLM negotiate.

### Docker Remote API

```yaml
listeners:
  - { id: dockerapi, proto: tcp, bind: 0.0.0.0:2375, mode: banner, handler: dockerapi, severity: critical }
```

A `GET /_ping` returning `OK` is what cloud-pivoting tools probe first. Subsequent `/version` and `/info` queries return realistic-looking JSON. Any `POST` (which would normally create / start / exec) gets 401 — and the `Authorization` header is captured for the operator to investigate.

### CLDAP — Active Directory recon

```yaml
listeners:
  - { id: cldap, proto: udp, bind: 0.0.0.0:389, mode: banner, handler: cldap, severity: critical }
```

LDAP scanning tools fall back to CLDAP (LDAP-over-UDP) for the AD `rootDSE` ping when TCP LDAP is filtered. The handler decodes the same BER LDAPMessage we use for TCP LDAP, emits the search request in meta, and (when a honeynet is configured) advertises virtual Windows hosts as fake DCs in `meta.honeynet_domain_controllers`.

### Syslog receivers

```yaml
listeners:
  - { id: syslog-udp, proto: udp, bind: 0.0.0.0:514, mode: banner, handler: syslog_udp, severity: low }
  - { id: syslog-tcp, proto: tcp, bind: 0.0.0.0:514, mode: banner, handler: syslog_tcp, severity: low }
```

Captures legitimate syslog feeds that someone misconfigured to point at our IP — surprisingly common. Both framings (octet-counting and non-transparent) are accepted on the TCP side. The PRI header is decoded into `facility` and `sev` for forensic context.

---

## 3. Honeynets — making the network look populated

See [`usage.md`](usage.md#3-honeynets) for the dispatch model and YAML patterns. Quick integration recipes:

- **Cloud VM with a single public IP**: enable `arp_responder` + `icmp_responder` on the public-facing interface, use `bind: 0.0.0.0:<port>` for the real listeners, and the honeynet host IPs are loopback aliases (`ip addr add 10.99.0.10/24 dev lo`).
- **Bare-metal sensor on a corporate LAN**: same, but `interface: eth0`. The ARP/ICMP responders make the honeynet IPs answer `arp-scan` and `ping` from any host on the segment.
- **TUN-based isolation**: enable per-honeynet `tun.enabled: true`, route the CIDR through the TUN, and run the operator's L4 dispatcher in NAT mode forwarding back to the sensor's real sockets.

---

## 4. Common deployment patterns

### Kubernetes DaemonSet

Run as a DaemonSet on each worker node. The sensor binds to host network so privileged ports work, and connects to a shared log forwarder / collector via the `webhook` or `mqtt` sink.

```yaml
# k8s manifest skeleton
spec:
  hostNetwork: true
  containers:
    - name: tarpit-honeypot
      image: tarpit-honeypot:1.5
      args: ["run", "-c", "/etc/tarpit-honeypot/config.yaml"]
      volumeMounts:
        - { name: config, mountPath: /etc/tarpit-honeypot }
        - { name: data,   mountPath: /var/lib/tarpit-honeypot }
      securityContext:
        capabilities:
          add: [NET_BIND_SERVICE, NET_RAW]
```

### Read-only root filesystem

Set the systemd unit's `ProtectSystem=strict` (it's there by default) and use `ReadWritePaths=/var/lib/tarpit-honeypot`. The sensor never writes anywhere else.

### Multi-tenant / per-customer deployments

Use the `sensor.name` + `--set` overrides + `conf.d/*.yaml` fragments to share a base config across customers:

```
/etc/tarpit-honeypot/
  config.yaml              # site-wide base
  conf.d/
    10-customer-A.yaml     # sensor.name + customer-specific channels
    20-customer-A-honeynet.yaml
```

Events get `sensor: customer-A-edge-01` in their meta; downstream SIEMs route by sensor name.

### Multiple regions / sites

Set `sensor.deployment_id` explicitly per site so every virtual host's MAC / SSH banner / SMB challenge differs between sites — a scanner that hits site A and site B can't fingerprint them as a single deployment.

---

## 5. Threat-intel pull (not built in)

The sensor does NOT subscribe to external threat-intel feeds (STIX / MISP / TAXII). Recommended pattern:

1. Run a sidecar that pulls feed data and writes IP lists to a file.
2. Use `--set allowlist[N]=<cidr>` overrides or a `conf.d/` fragment to rotate the allowlist in based on the file.
3. Downstream SIEMs are usually a better place to do "this IP is on the threat-intel list" enrichment.

---

## 6. CI / development integration

```yaml
# .github/workflows/ci.yml — minimal
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - run: go vet ./...
      - run: go test -race -coverprofile=coverage.out ./...
      - run: go tool cover -func=coverage.out | tail -1
      - run: make cross
      - run: ARCH=amd64 BIN=dist/tarpit-honeypot-linux-amd64 packaging/debian/build.sh
```

The sensor itself has no CI / development integration requirements — it's a single binary; standard Go test infrastructure applies.

---

## 7. Choosing the right output format

| Use case | Recommended sink + format |
|---|---|
| Ad-hoc grepping on the sensor host | `stdout` + `json` |
| Long-term archive on disk | `jsonlog` + `json` |
| Live UI for the local operator | `sqlite` (the web UI reads it) |
| ArcSight ESM | `syslog` (TCP) + `cef` |
| IBM QRadar | `syslog` (TCP) + `leef` |
| Splunk HEC | `webhook` + `json` |
| AWS Security Lake / Snowflake / Athena | `webhook` + `ocsf` |
| Elastic / OpenSearch | `webhook` + `json` (with a Logstash filter for ECS mapping) |
| IoT / pub-sub bus | `mqtt` + `json` |
| Critical-only paging | `twilio` (SMS) + `sns` (PagerDuty bridge) |
| Network management station | `snmptrap` |
| Prometheus | `/metrics` endpoint on the web UI |

# Usage Guide

This document is the end-to-end "I just got the binary, what do I do" reference. For the YAML schema see [`docs/config.md`](config.md); for the CLI reference see [`docs/cli.md`](cli.md).

## 1. Quickstart

```bash
# Build (or download a release binary from dist/)
make build

# Validate the example config without starting anything
./bin/tarpit-honeypot validate-config -c configs/tarpit-honeypot.example.yaml

# Start the sensor in the foreground
./bin/tarpit-honeypot run -c configs/tarpit-honeypot.example.yaml
```

The example config ships with sensible defaults: a few low-interaction honeypots on high ports, JSON log + SQLite + stdout sinks, a loopback-only web UI on `127.0.0.1:8088`, and a sample honeynet skeleton (no virtual hosts active until you uncomment them).

In another shell:

```bash
# Generate some events
nc -v localhost 2222                              # ssh honeypot
printf 'GET /admin HTTP/1.0\r\n\r\n' | nc -v localhost 8000

# Watch them
./bin/tarpit-honeypot list-events -c configs/tarpit-honeypot.example.yaml

# Open the web UI
xdg-open http://127.0.0.1:8088
```

## 2. Daily operations

### Generating canary tokens

Operators commonly leave decoy URLs/DNS names lying around to catch lateral-movement. The `gen-token` subcommand prints unguessable tokens shaped for three common bait surfaces:

```bash
./bin/tarpit-honeypot gen-token --type=dns --label=prod-cdb
# 6191564a98496be6-prod-cdb.canary.example.com

./bin/tarpit-honeypot gen-token --type=url --bits=128
# /__canary__/8ed2a49c8ef9639a1234567890abcdef
```

Paste the output into a `dns_canaries:` or `url_canaries:` entry in the config, drop a reference in fake docs / shell history / config files, and the sensor fires a critical event the moment any resolver or HTTP client touches it.

### Hot reload

```bash
sudo systemctl reload tarpit-honeypot
# or:
sudo kill -HUP $(pgrep tarpit-honeypot)
```

The sensor logs a diff for every change. **Hot-reloadable**: channels, routes, allowlist, dedup window, correlator thresholds, canary lists, URL canary lists. **Requires restart**: anything under `sensor.*`, the UI bind, the DNS listener bind, the sniffer interface.

Listener changes are *also* hot-reloadable — the old listener is stopped and a new one is started with the new bind / handler / mode. In-flight handler goroutines drain per the `sensor.shutdown.drain_timeout`.

### Comparing two configs before you reload

```bash
./bin/tarpit-honeypot validate-config \
  -c /etc/tarpit-honeypot/config.yaml \
  --diff /tmp/proposed.yaml
```

Prints a categorized diff: which changes hot-reload vs which require restart. Same logic the SIGHUP path uses.

### Showing the effective post-defaults config

```bash
./bin/tarpit-honeypot show-config -c /etc/tarpit-honeypot/config.yaml
```

YAML output with all defaults filled in. Secrets stay as env var names (`auth_token_env: TARPIT_UI_TOKEN`) rather than expanded values, so the output is safe to paste in tickets.

### Pulling a specific event's pcap

When a TCP listener has `capture: true`, every accepted connection is written as a synthesized libpcap file under `<data_dir>/captures/<event_id>.pcap`. To grab one:

```bash
./bin/tarpit-honeypot list-events -c cfg.yaml --rule listener:ssh-bait --limit 5
# ... copy the event id ...
./bin/tarpit-honeypot export-pcap -c cfg.yaml --event 7c0574dd1015ac2c142e30ca -o /tmp/ssh.pcap
wireshark /tmp/ssh.pcap
```

## 3. Honeynets

A *honeynet* is a configured artificial network with virtual hosts. One sensor can present as many distinct virtual machines, each with its own deterministic identity (SSH banner version, MAC, MySQL build string, SMB challenge, etc.).

The base mode (v1.1+) is **destination-IP dispatch**: when an incoming connection's destination matches a configured virtual host IP, the listener dispatches to a per-host handler instance. That requires the OS to actually route the virtual IPs to the sensor — typically via `ip addr add 10.99.0.10/24 dev eth0` or iptables DNAT.

Three optional Linux-only adapters make the honeynet more discoverable **without** that OS plumbing:

- **`arp_responder`** (v1.2): the sensor opens an AF_PACKET socket and answers ARP requests for every virtual host IP. `arp-scan` sees the network as populated.
- **`icmp_responder`** (v1.3): the sensor answers IPv4 ICMP echo (ping) for every virtual host IP via the same AF_PACKET path.
- **`tun`** (v1.5): the sensor opens a Linux TUN device. The operator routes the honeynet CIDR into the TUN. The sensor answers ICMP/ICMPv6 echo and sends TCP RST for unbound ports. `nmap -sS` reports the host as up.

None of these adapters provide a full userspace TCP stack — real protocol termination still goes through real sockets. For "scanner sees the network as populated" they are sufficient.

### Pattern A — virtual hosts behind one listener (the simplest setup)

```yaml
listeners:
  - id: ssh-bait
    proto: tcp
    bind: 0.0.0.0:22          # one real listener, many virtual hosts
    mode: banner
    handler: ssh

honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    arp_responder: { enabled: true, interface: eth0 }
    icmp_responder: { enabled: true, interface: eth0 }
    hosts:
      - { ip: 10.99.0.10, hostname: web-prod-01, os: linux,
          services: [{port: 22, handler: ssh}] }
      - { ip: 10.99.0.11, hostname: db-prod-01, os: linux,
          services: [{port: 22, handler: ssh}] }
```

Then on the host:

```bash
ip addr add 10.99.0.10/24 dev eth0
ip addr add 10.99.0.11/24 dev eth0
```

When a scanner connects to `10.99.0.10:22` vs `10.99.0.11:22`, the sensor sends two **different** SSH banner versions (derived deterministically from each host's identity).

### Pattern B — TUN-routed network

```yaml
honeynets:
  - id: edge
    cidr: 10.50.0.0/16
    tun: { enabled: true, device: tarpit0 }
    hosts: [...]
```

Then on the host:

```bash
ip link set tarpit0 up
ip route add 10.50.0.0/16 dev tarpit0
```

The sensor responds to all `nmap -sn`-style probes for that range; for actual protocol interaction, configure listeners that bind real sockets and use NAT to forward traffic from the TUN-bound network into the sensor.

## 4. Web UI

Default bind is `127.0.0.1:8088`. Enable in `ui:`. Endpoints:

- `/` — last-24h summary (event counts by severity, top rules, top sources)
- `/events?source=<ip>&rule=<id>&since=24h&limit=N` — filterable event table
- `/events/<id>` — full event detail (banner sent, base64 payload, meta)
- `/api/events`, `/api/summary` — JSON equivalents
- `/metrics` — Prometheus text-format (v1.3+)
- `/healthz` — liveness check (bypasses auth)

Non-loopback binds are rejected at validate-time unless both `tls_cert + tls_key` and `auth_token_env` are configured. There is **no write endpoint** — the UI cannot delete events, change config, or trigger alerts.

## 5. systemd integration

The shipped unit at `packaging/systemd/tarpit-honeypot.service` runs as `tarpit:tarpit` with `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW` (and `CAP_NET_ADMIN` if you enable the TUN adapter). `ExecReload=/bin/kill -HUP $MAINPID` ties into the hot-reload path.

Standard install:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tarpit
sudo install -o root -g root -m 0755 bin/tarpit-honeypot /usr/local/bin/
sudo install -d -o tarpit -g tarpit -m 0750 /var/lib/tarpit-honeypot
sudo install -o root -g root -m 0640 configs/tarpit-honeypot.example.yaml /etc/tarpit-honeypot/config.yaml
sudo install -o root -g root -m 0644 packaging/systemd/tarpit-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tarpit-honeypot
```

Verify it's healthy:

```bash
sudo systemctl status tarpit-honeypot
sudo journalctl -u tarpit-honeypot -f
curl http://127.0.0.1:8088/healthz
curl http://127.0.0.1:8088/metrics
```

## 6. Docker

```bash
docker build -t tarpit-honeypot:latest .
docker run --rm \
  -p 2222:2222 -p 8000:8000 -p 8088:8088 \
  -v "$PWD/var:/var/lib/tarpit-honeypot" \
  -v "$PWD/configs/tarpit-honeypot.example.yaml:/etc/tarpit-honeypot/config.yaml:ro" \
  tarpit-honeypot:latest
```

The image is a multi-stage scratch build (~14 MB final). Privileged port binding inside the container needs either `--user 0` or `--cap-add=NET_BIND_SERVICE`. Honeynet ARP / ICMP responders additionally need `--cap-add=NET_RAW`, and the TUN adapter needs `--cap-add=NET_ADMIN --device=/dev/net/tun`.

## 7. Watching live activity

```bash
# tail -f equivalent
journalctl -u tarpit-honeypot -f -o cat | jq .

# Or just stdout if you configure a stdout channel
./bin/tarpit-honeypot run -c cfg.yaml 2>/dev/null | jq .

# By rule
./bin/tarpit-honeypot list-events -c cfg.yaml --since 5m --rule correlate:port_scan

# By source IP
./bin/tarpit-honeypot list-events -c cfg.yaml --since 1h --source 198.51.100.42

# Just critical
./bin/tarpit-honeypot list-events -c cfg.yaml --since 24h --limit 50 \
  | grep critical
```

## 8. SIEM integration

Pick the format per channel:

```yaml
channels:
  - id: ops-arcsight
    type: syslog
    network: tcp
    address: arcsight:514
    format: cef
  - id: ops-qradar
    type: syslog
    network: tcp
    address: qradar:514
    format: leef
  - id: ops-securitylake
    type: webhook
    url: https://lake.example.com/ingest
    format: ocsf
```

For Prometheus, scrape `/metrics`:

```yaml
- job_name: tarpit-honeypot
  bearer_token_file: /etc/secrets/tarpit-ui-token
  scrape_interval: 30s
  static_configs:
    - targets: ['sensor.example.internal:8088']
```

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `sensor stopped: listen 0.0.0.0:53: bind: permission denied` | privileged port, no caps | systemd unit has `AmbientCapabilities=CAP_NET_BIND_SERVICE` already; verify with `systemctl show -p CapabilityBoundingSet tarpit-honeypot`. For Docker, `--cap-add=NET_BIND_SERVICE`. |
| `sensor stopped: listen 0.0.0.0:53: bind: address already in use` | systemd-resolved owns :53 | Either disable systemd-resolved DNSStubListener (`/etc/systemd/resolved.conf`: `DNSStubListener=no`) or use a non-standard port and NAT. |
| Listener events fire but `correlate:brute_force` never does | per-rule dedup window covers the burst | Lower `dedup.default_window` or set `correlate.brute_force.window` shorter. |
| `arp_responder disabled: need CAP_NET_RAW` | running as a non-privileged user without the cap | Pair `User=tarpit` with `AmbientCapabilities=CAP_NET_RAW` in the unit. |
| TUN listener fails with `open /dev/net/tun: no such file` | running inside an unprivileged container | `docker run --device=/dev/net/tun --cap-add=NET_ADMIN ...` |
| Prometheus `/metrics` returns 503 | UI started before sensor finished construction | wait a second after startup; the sensor lazily registers stats once it's fully up. |
| `validate-config` rejects `format: cef` on `sqlite` channel | structured-row sinks can't take text formats | Use the format on `stdout`/`jsonlog`/`webhook`/`smtp`/`syslog` instead. |

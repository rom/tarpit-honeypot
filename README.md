# tarpit-honeypot

Tripwire + tarpit deception sensor.

See [`design.md`](design.md) for the full design. This README only covers
what's actually built right now.

## Status

**v0.2 — tarpit + bait + canaries + correlator.** Adds tarpit listener
modes (sticky / trickle / keepalive), built-in protocol handlers for
SSH / HTTP / HTTPS / Telnet / FTP, filesystem honeyfile watching via
fsnotify, port-scan + brute-force correlators that emit aggregate
events, per-sink worker queues with bounded drop, unit tests for the
trickier logic. Linux amd64/arm64.

Not yet implemented (planned in later phases per `design.md`):
SMB + ICS/OT protocol handlers, DNS/URL token canaries, L2 sniffer,
SQLite event index, mini-pcap capture, web UI, Windows service,
Twilio / SNS / SNMP-trap channels, hot reload, privilege drop, and
read-detection for honeyfiles via fanotify.

## Build

```
make build
./bin/tarpit-honeypot version
```

## Try it locally

```
./bin/tarpit-honeypot validate-config -c configs/tarpit-honeypot.example.yaml
./bin/tarpit-honeypot run            -c configs/tarpit-honeypot.example.yaml
```

In another shell:

```
nc -v localhost 2222           # hits the SSH-banner listener in the sample config
echo hello | nc -u localhost 5353   # hits a UDP listener
```

Events stream to stdout (foreground) and the JSON log under `data_dir`.

## Subcommands

```
tarpit-honeypot run            -c <config>
tarpit-honeypot validate-config -c <config>
tarpit-honeypot test-alert     -c <config> [--channel <id>] [--severity high]
tarpit-honeypot list-events    -c <config> [--since 1h] [--source <ip>] [--rule <id>]
tarpit-honeypot version
```

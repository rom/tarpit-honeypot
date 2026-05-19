# tarpit-honeypot

Tripwire + tarpit deception sensor.

See [`design.md`](design.md) for the full design. This README only covers
what's actually built right now.

## Status

**v0.1 — tripwire MVP.** Listeners (drop / banner), JSON + stdout always-on
sinks, webhook / SMTP / syslog outbound sinks, dedup + rate-limit + allowlist,
CLI subcommands, systemd unit. Linux amd64/arm64.

Not yet implemented (planned in later phases per `design.md`): tarpit
listener modes, ICS protocol handlers, filesystem canaries, DNS/URL tokens,
L2 sniffer, in-sensor correlator, SQLite event index, mini-pcap capture,
web UI, Windows service, Twilio / SNS / SNMP-trap channels, hot reload,
privilege drop.

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

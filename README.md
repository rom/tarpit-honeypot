# tarpit-honeypot

Tripwire + tarpit deception sensor.

See [`design.md`](design.md) for the full design. This README only covers
what's actually built right now.

## Status

**v0.7 — ICS handlers (OPC-UA, EtherNet/IP, BACnet, TFTP) + armv6/armv7.**
Adds OPC-UA Hello→Acknowledge, EtherNet/IP RegisterSession + ListIdentity
(advertises a fake Allen-Bradley 1756-L73 ControlLogix), BACnet Who-Is→I-Am
over UDP, and TFTP RRQ/WRQ capture with Access-Violation reply (no actual
file serving — avoids becoming an amplifier). Cross-compile matrix expands
to linux/amd64 + linux/arm64 + linux/armv7 + linux/armv6.

Not yet implemented (planned in later phases per `design.md`):
SMB handler, Windows service, listener hot-reload.

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

`run` also responds to `SIGHUP` by reloading the config. Channels,
routes, allowlist, dedup window, and correlator thresholds get hot-swapped;
listener or `sensor.*` changes still require a restart and get a warning.

## Web UI

With `ui.enabled: true`, the sensor serves a read-only UI at
`ui.bind` (default `127.0.0.1:8088`):

- `/` — last-24h summary (events / severity / top rules / top sources)
- `/events` — table view with `?source=`, `?rule=`, `?since=`, `?limit=`
- `/events/<id>` — full event detail (banner sent, payload, meta)
- `/api/events`, `/api/summary` — JSON equivalents
- `/healthz` — liveness check

Non-loopback binds are refused at validate-time unless both
`tls_cert+tls_key` and `auth_token_env` are set.

# tarpit-honeypot

Tripwire + tarpit deception sensor.

See [`design.md`](design.md) for the full design. This README only covers
what's actually built right now.

## Status

**v0.3 — SQLite + read-only web UI + privilege drop + hot reload.**
Events get indexed in an embedded SQLite database (pure-Go driver, no
CGO). A read-only HTML/JSON UI on loopback shows last-24h summaries
and queryable event tables. Linux uid/gid drop after privileged
setup. SIGHUP reloads channels, routes, correlator thresholds, and
allowlist without dropping connections. Linux amd64/arm64.

Not yet implemented (planned in later phases per `design.md`):
SMB + ICS/OT protocol handlers, DNS/URL token canaries, L2 sniffer,
mini-pcap capture, Windows service, Twilio / SNS / SNMP-trap channels,
listener hot-reload, and read-detection for honeyfiles via fanotify.

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

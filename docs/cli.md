# CLI Reference

The binary is a single static executable. Invoke it as `tarpit-honeypot <subcommand> [flags]`. See [`docs/usage.md`](usage.md) for higher-level scenarios and [`docs/config.md`](config.md) for the YAML schema each `-c` flag points at.

```
tarpit-honeypot run            -c <config> [--dry-run] [common flags]
tarpit-honeypot validate-config -c <config> [--diff <other.yaml>]
tarpit-honeypot show-config    -c <config>
tarpit-honeypot test-alert     -c <config> [--severity high] [--note "..."]
tarpit-honeypot list-events    -c <config> [--since 24h] [--source <ip>] [--rule <id>] [--limit N]
tarpit-honeypot gen-token      --type=dns|url|hex [--label LBL] [--bits N] [--domain D]
tarpit-honeypot export-pcap    -c <config> --event <id> [-o file|-]
tarpit-honeypot list-honeynets -c <config>
tarpit-honeypot list-devices   -c <config> [--json]
tarpit-honeypot init           [-o file]
tarpit-honeypot completion     bash | zsh | fish
tarpit-honeypot help           [subcommand | topic]
tarpit-honeypot version
tarpit-honeypot --version | -V
```

All subcommands exit 0 on success and 1 on error. Errors are written to stderr; data goes to stdout.

### Common flags

Most subcommands accept the shared logging + config-override set:

| Flag | Meaning |
|---|---|
| `-c <path>` | Config file (default `/etc/tarpit-honeypot/config.yaml`). |
| `--set key.path=value` | Override a single YAML key. Repeatable; values are auto-typed (bool/int/float/string). Applied last, after env-var overrides. |
| `--log-level debug\|info\|warn\|error` | Slog level (default `info`). |
| `--log-format text\|json` | Slog handler format (default `text`). |
| `--log-file <path>` | Redirect logs to file (default stderr). |
| `--quiet` | Shortcut for `--log-level=error`. |
| `--verbose` | Shortcut for `--log-level=debug`. |
| `--help`, `-h` | Per-subcommand flag listing. |

### Config layering (applied in order)

1. Base YAML from `-c`.
2. Sibling `conf.d/*.yaml` deep-merged in lexical order.
3. `TARPIT_<KEY_PATH>` env vars (e.g. `TARPIT_SENSOR_NAME=foo`). Use `__` to escape a real underscore inside a key segment.
4. `--set key.path=value` (wins).

### Help topics

`tarpit-honeypot help <topic>` prints the long-form per-subcommand
docs (the same content as this file, distilled). Beyond the
subcommands above, the following non-subcommand topics are
available:

- `tarpit-honeypot help archetypes` — list of the 29 OS / device
  archetypes with usage examples + precedence rules.

---

## `run`

Start the sensor as a foreground process. Returns when SIGINT/SIGTERM arrives. Responds to SIGHUP by reloading the config.

```
tarpit-honeypot run -c /etc/tarpit-honeypot/config.yaml
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file path. |
| `--dry-run` | off | Load + validate config, construct the sensor end-to-end, exit before binding any listener. CI-friendly. |
| Common flags | — | See "Common flags" at the top. |

The sensor brings up, in order: SQLite store + retention pruner; capture manager (when any listener has `capture: true`); sinks; router workers; correlator (port-scan / brute-force / slow-scan + storyline); per-listener accept loops (with hot-reload tracking); canary watchers (fanotify on Linux for OPEN events, fsnotify everywhere else for write/remove/rename/chmod); DNS canary listener; ARP / ICMP / LLDP / TUN responders per honeynet (Linux only); AF_PACKET sniffer (Linux only); Web UI + `/metrics` endpoint.

### Signals

| Signal | Effect |
|---|---|
| `SIGINT` / `SIGTERM` | Graceful shutdown. Accept sockets close immediately; in-flight handler goroutines get `sensor.shutdown.drain_timeout` to finish. |
| `SIGHUP` | Reload config. Diff is logged at info level; hot-reloadable changes are applied; restart-required changes log a warning and stay on the old setting. |

### Privileged setup

Privileged setup happens **before** `drop_user`/`drop_group` takes effect:

1. Bind low-numbered listener ports (needs `CAP_NET_BIND_SERVICE` post-drop)
2. Open data_dir (root-writable in most deployments)
3. Open ARP / ICMP / LLDP responder sockets (needs `CAP_NET_RAW` post-drop)
4. Open TUN device (needs `CAP_NET_ADMIN` post-drop)

The systemd unit pre-grants the necessary `AmbientCapabilities` so the drop is safe.

On **macOS**, the AF_PACKET/TUN steps are no-ops (Linux-only — see [`docs/usage.md` §12](usage.md#12-platform-support)). Privileged port binding works as on any BSD-derived system: bind as root, then `setuid` to the configured `drop_user` (uses `syscall.Setuid`, which on darwin also drops the saved-uid so a later `setuid(0)` regain attempt fails). launchd's `<SoftResourceLimits>` and `<UserName>` keys can replace `AmbientCapabilities`.

---

## `validate-config`

Parse + validate a YAML file. Optionally diff against another file to see what would hot-reload vs require restart.

```
tarpit-honeypot validate-config -c new.yaml
tarpit-honeypot validate-config -c /etc/tarpit-honeypot/config.yaml --diff /tmp/proposed.yaml
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config to validate. |
| `--diff <path>` | — | Compare with this other config; classify each change as hot-reloadable or restart-required. |

Output (no diff):

```
config OK: 17 listeners, 3 channels, 1 routes, 1 canaries, 2 url canaries, 1 dns canaries
```

With `--diff`:

```
config OK: 17 listeners, 3 channels, 1 routes, ...

changes that would hot-reload on SIGHUP (3):
  [channels] modified jsonlog
  [channels] modified sqlite
  [channels] modified stdout

changes that require restart (1):
  [listeners] modified ssh-bait: bind 0.0.0.0:2222 -> 0.0.0.0:2223
```

---

## `show-config`

Print the effective post-defaults config as YAML. Secrets stay as env var names (e.g. `auth_token_env: TARPIT_UI_TOKEN`) — the output is safe to paste in tickets.

```
tarpit-honeypot show-config -c /etc/tarpit-honeypot/config.yaml
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |

---

## `test-alert`

Inject a synthetic event through the **full routing pipeline** so you can validate outbound channels without waiting for a real trigger. Useful right after wiring up a new SMTP / Twilio / SNS channel.

```
tarpit-honeypot test-alert -c cfg.yaml --severity high --note "smoke test"
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |
| `--severity` | `high` | Severity for the synthetic event (`low`/`medium`/`high`/`critical`). |
| `--note` | "synthetic event from test-alert" | Free-form string in `meta.note`. |

The synthetic event uses `rule_id=synthetic:test-alert`, `source=203.0.113.42:65000`, `dest=10.0.0.1:22`. It flows through the same dedup / allowlist / rate-limit / per-channel routing logic as a real event.

---

## `list-events`

Query the local event store. Prefers SQLite if `<data_dir>/events.db` exists; falls back to scanning the rotated JSONL files for tripwire-only configs.

```
tarpit-honeypot list-events -c cfg.yaml --since 1h --rule listener:ssh-bait --limit 20
tarpit-honeypot list-events -c cfg.yaml --since 24h --source 198.51.100.42
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |
| `--since <dur>` | `24h` | Time window relative to now. Go duration syntax (`5m`, `2h`, `7d` — actually only `m/h` for now; multiply for longer). |
| `--source <ip>` | — | Exact-match source IP filter. |
| `--rule <id>` | — | Exact-match rule_id filter (e.g. `listener:ssh-bait`, `correlate:port_scan`). |
| `--limit <N>` | `100` | Max events to return (newest first). |

Output format:

```
2026-05-19T18:30:45Z  critical  canary:shared-creds              -> :0  (cca7b6a945c42b46ecd9e1fb)
2026-05-19T18:30:42Z  high      listener:ssh-bait                127.0.0.1 -> 127.0.0.1:2222  (ed5393fa19ba6613f09010b4)
```

The trailing parenthesized id is the event id — feed it to `export-pcap`.

---

## `gen-token`

Generate an unguessable canary token. Three shapes for the three common bait surfaces; default 64 bits of entropy.

```
tarpit-honeypot gen-token --type=dns --label=prod-cdb --domain=canary.example.com
# 6191564a98496be6-prod-cdb.canary.example.com

tarpit-honeypot gen-token --type=url --bits=128
# /__canary__/8ed2a49c8ef9639a1234567890abcdef

tarpit-honeypot gen-token --type=hex --bits=256
# 64-hex-char string
```

| Flag | Default | Meaning |
|---|---|---|
| `--type` | `dns` | `dns` / `url` / `hex`. |
| `--label` | "" | Optional human-readable suffix (DNS-safe chars only). |
| `--bits` | `64` | Multiple of 8 between 32 and 256. |
| `--domain` | `canary.example.com` | For `--type=dns`, the base domain to append. |

Paste the output into a `dns_canaries:` or `url_canaries:` block and the sensor fires the moment the token gets touched anywhere on the network.

---

## `export-pcap`

Copy one event's per-connection pcap out of the captures directory. Read-only; never touches sensor state.

```
tarpit-honeypot export-pcap -c cfg.yaml --event 7c0574dd1015ac2c142e30ca -o /tmp/ssh.pcap
wireshark /tmp/ssh.pcap
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file (used only to look up `data_dir`). |
| `--event <id>` | **required** | Event id, as printed by `list-events`. |
| `-o <path>` | `-` (stdout) | Output file, or `-` for stdout. |

Only events emitted by TCP listeners with `capture: true` have a pcap. The pcap is synthesized (DLT_RAW, IPv4+TCP headers, tracked sequence numbers) — Wireshark loads it directly and "Follow TCP Stream" reconstructs the application-layer exchange.

---

## `list-honeynets`

Print the configured honeynet topology, one network per header line, indented host listing with per-host derived identity seed and MAC.

```
tarpit-honeypot list-honeynets -c cfg.yaml
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |

Output:

```
# corp  cidr=10.99.0.0/24 gateway=10.99.0.1 dns=10.99.0.2 domain=corp.example.local
  10.99.0.10  mac=3e:04:45:bb:fb:79  hostname=web-prod-01              os=linux    identity=/honeynet/corp/10.99.0.10
    :22  handler=ssh
    :80  handler=http
    :443 handler=https
  10.99.0.20  mac=5e:1f:7d:3d:8b:08  hostname=dc-01                    os=windows  identity=/honeynet/corp/10.99.0.20
    :88  handler=kerberos
    :389 handler=ldap
    :445 handler=smb
```

Confirms each host's identity seed is distinct (so banner / version / serial values differ per virtual machine) and its MAC has the locally-administered bit set (`0x02` on the first byte).

---

## `list-devices`

Print the learned-device inventory the running sensor persisted to
`<data_dir>/devices.json` (see the `devices:` config block). Read-only;
applies the configured allow-list. Use `--json` to snapshot a baseline.

```
tarpit-honeypot list-devices -c cfg.yaml
tarpit-honeypot list-devices -c cfg.yaml --json > baseline.json
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |
| `--json` | off | Emit the inventory as JSON instead of a table. |

Output:

```
IP               MAC                VENDOR                 HOSTNAME             SOURCE    LAST SEEN
10.0.0.10        00:90:e8:11:22:33  Moxa                   plc-press            dhcp      2025-05-19 14:03
10.0.0.50        -                  -                      -                    conn      2025-05-19 14:05
```

---

## `init`

Write a defaulted YAML skeleton suitable as a scaffolding starting
point. Defaults match what `validate-config` produces internally
(applyDefaults), so the output is immediately usable.

```
tarpit-honeypot init > /etc/tarpit-honeypot/config.yaml
tarpit-honeypot init -o cfg.yaml
```

| Flag | Default | Meaning |
|---|---|---|
| `-o <path>` | `-` (stdout) | Output file path. |

---

## `completion`

Print a shell-completion script. Supports `bash`, `zsh`, and `fish`.

```
tarpit-honeypot completion bash > /etc/bash_completion.d/tarpit-honeypot
tarpit-honeypot completion zsh  > "${fpath[1]}/_tarpit-honeypot"
tarpit-honeypot completion fish > ~/.config/fish/completions/tarpit-honeypot.fish
```

The `.deb` and `.rpm` packages drop the completions into the right
location automatically.

---

## `help`

Print the long-form usage for one subcommand or topic. The same
content as this reference, distilled.

```
tarpit-honeypot help                  # subcommand index
tarpit-honeypot help run              # per-subcommand topic
tarpit-honeypot help list-events
tarpit-honeypot help archetypes       # non-subcommand topic
```

Without an argument, prints the subcommand index + common-flag
table. Unknown topics exit 1 with a usage listing on stderr.

---

## `version`

Print version + build commit + build date. Used by ops tooling to confirm the binary in use.

```
tarpit-honeypot version
# tarpit-honeypot 1.10 (commit a1b2c3d, built 2026-05-19T18:30:00Z)

tarpit-honeypot --version
tarpit-honeypot -V
```

The two flag forms (`--version`, `-V`) and the subcommand form all
print the same single-line summary.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Operational error — config parse failure, file not found, listener bind error, etc. The error message went to stderr. |
| `2` | Flag parsing error (Go's `flag.ContinueOnError` convention). |

Long-running subcommands (`run`) exit 0 only on clean shutdown via SIGINT/SIGTERM. Non-zero exits from `run` indicate a setup failure (config invalid, ports refused, store corruption); inspect the journal entries written before exit.

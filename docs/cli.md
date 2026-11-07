# CLI Reference

The binary is a single static executable. Invoke it as `tarpit-honeypot <subcommand> [flags]`. See [`docs/usage.md`](usage.md) for higher-level scenarios and [`docs/config.md`](config.md) for the YAML schema each `-c` flag points at. For the fleet-specific commands see [`docs/fleet.md`](fleet.md); for the IOC / threat-intel exports see [`docs/ioc.md`](ioc.md) and [`docs/threat-intel-exports.md`](threat-intel-exports.md).

```
tarpit-honeypot run            -c <config> [--dry-run] [common flags]
tarpit-honeypot collector      -c <config> [common flags]
tarpit-honeypot validate-config -c <config> [--diff <other.yaml>]
tarpit-honeypot show-config    -c <config>
tarpit-honeypot test-alert     -c <config> [--severity high] [--note "..."]
tarpit-honeypot list-events    -c <config> [--since 24h] [--source <ip>] [--target <ip>] [--handler <name>] [--port N] [--rule <id>] [--fleet] [--limit N]
tarpit-honeypot replay         -c <config> (--event <id> | --handler <name> [--file f|-]) [--udp] [--vuln]
tarpit-honeypot gen-token      --type=dns|url|ssrf|hex|doc|log4shell|aws|css|mcp|wireguard|folder [--label LBL] [--bits N] [--domain D] [-o file]
tarpit-honeypot gen-wallet-decoys [--dir D] [--seed S] [--kind K|all] [--list]
tarpit-honeypot gen-lures      [--dir D] [--seed S] [--kind K|all] [--list]
tarpit-honeypot gen-agent-breadcrumb [--dir D] [--url U]
tarpit-honeypot export-pcap    -c <config> --event <id> [-o file|-]
tarpit-honeypot list-honeynets -c <config>
tarpit-honeypot list-devices   -c <config> [--json] [--stats|--conflicts|--rogues|--class C|--vendor S|--search Q|--stale D|--active D]
tarpit-honeypot list-paths     -c <config> [--format table|json|tsv] [--category config|enrichment|database|state]
tarpit-honeypot list-archetypes [--json] [<name>]
tarpit-honeypot list-handlers  [--proto tcp|udp]
tarpit-honeypot list-archeservices [<role>]
tarpit-honeypot list-cves      [--service <handler>] [--json] [--cwe]
tarpit-honeypot kev-gap        (--file <kev.json> | --url <u> | --covered) [--json]
tarpit-honeypot list-techniques [--kind rule|handler|anomaly] [--json]
tarpit-honeypot export-navigator -c <config> [--observed] [-o file]
tarpit-honeypot list-fleet-rules [--json]
tarpit-honeypot list-unavailable-capabilities -c <config>
tarpit-honeypot export-iocs    -c <config> [--since 168h] [--format stix|csv|txt|json]
tarpit-honeypot export-creds   -c <config> [--kind K] [--format json|xml|yaml|csv|txt]
tarpit-honeypot check-iocs     -c <config> --file <path> [--match src|dst|any] [--since D] [--format text|json] [--fail-on-hit]
tarpit-honeypot identify       [--ua S] [--path S] [--ssh S] [--ja3 S] [--payload S] [--handler H]
tarpit-honeypot jarm           [--timeout D] [--sni NAME] <host:port>
tarpit-honeypot analyze        <file> [--format json] [--yara]
tarpit-honeypot generate-decoys <target...> --yes [--ports P] [--archetype A] [-o file]
tarpit-honeypot reset-db       -c <config> [--yes]
tarpit-honeypot rotate-db      -c <config> [--out file.gz] [--reset --yes]
tarpit-honeypot prune-db       -c <config> (--keep-days N | --keep-rows N | --max-mb N) [--yes]
tarpit-honeypot init           [-o file]
tarpit-honeypot completion     bash | zsh | fish
tarpit-honeypot help           [subcommand | topic]
tarpit-honeypot version
tarpit-honeypot --version | -V
```

All subcommands exit 0 on success and 1 on error. Errors are written to stderr; data goes to stdout.

`tarpit-honeypot --help` (or `-h`, with no subcommand) prints the usage banner and lists **all subcommands in alphabetical order**, followed by the common flags.

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

- `tarpit-honeypot help archetypes` — the full list of OS / device
  archetypes with usage examples + precedence rules (or use
  `list-archetypes` for a machine-readable catalog).

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

The sensor brings up, in order: SQLite store (+ retention pruner, which also prunes the IOC store) + the IOC extractor; capture manager (when any listener has `capture: true`); sinks; router workers; correlator (port-scan / brute-force / slow-scan / spray / path- + dns-enumeration / beacon + storyline); the fleet stack when configured — the `ingest:` endpoint (accepts forwarded events), the cross-sensor `fleet:*` correlator (auto-on with ingest), per-sensor trust scoring, the downward intel feed server (`/intel`, `/intel/stix`, `/taxii2/…`), the MISP pusher, and — on a leaf — the event forwarder and the `intel_feed:` subscriber; per-listener accept loops (with hot-reload tracking); canary watchers (fanotify on Linux for OPEN events, fsnotify everywhere else for write/remove/rename/chmod); DNS canary listener; ARP / ICMP / LLDP / TUN responders per honeynet (Linux only); AF_PACKET sniffer — IPv4 + IPv6 + L2 (Linux only); Web UI + `/metrics` endpoint.

### Signals

| Signal | Effect |
|---|---|
| `SIGINT` / `SIGTERM` | Graceful shutdown. Accept sockets close immediately; in-flight handler goroutines get `sensor.shutdown.drain_timeout` to finish. |
| `SIGHUP` | Reload config. Diff is logged at info level; hot-reloadable changes are applied; restart-required changes log a warning and stay on the old setting. |

### Privileged setup

Order of operations at startup:

1. Install the OS-level egress firewall / active-response blocklist (nftables) — done **while privileged**, since `nft` needs `CAP_NET_ADMIN`, and before the seccomp sandbox blocks `exec`.
2. **Drop** to `drop_user`/`drop_group` (all-threads `setgid`/`setgroups`/`setuid`; refuses to drop *to* uid 0).
3. Apply the in-process sandbox (seccomp + Landlock).
4. Bind listener ports, open ARP / ICMP / LLDP sockets and the TUN device, open data_dir.

The low-numbered port binds and raw/TUN socket opens in step 4 succeed **after** the drop because `CAP_NET_BIND_SERVICE` + `CAP_NET_RAW` (and `CAP_NET_ADMIN` for `--tun`) are retained across the `setuid` in the process's **ambient** (or file) capability set. The systemd unit pre-grants those via `AmbientCapabilities=`; starting as plain root with neither ambient nor file caps makes the post-drop binds fail (see [`hardening.md`](hardening.md)).

On **macOS**, the AF_PACKET/TUN steps are no-ops (Linux-only — see [`docs/usage.md` §14](usage.md#14-platform-support)). Privileged port binding works as on any BSD-derived system: bind as root, then `setuid` to the configured `drop_user` (uses `syscall.Setuid`, which on darwin also drops the saved-uid so a later `setuid(0)` regain attempt fails). launchd's `<SoftResourceLimits>` and `<UserName>` keys can replace `AmbientCapabilities`.

---

## `collector`

Run as a **fleet collector**: the ingest + correlation half of the sensor with no honeypot listeners. Accepts forwarded events on the `ingest:` endpoint, runs the cross-sensor `fleet:*` correlator, serves the downward intel feed, and writes to the aggregator store — but binds no decoy ports itself. Same config/flags as `run`; the config simply has `ingest:` enabled and (typically) no `listeners:`. See [`fleet.md`](fleet.md).

```
tarpit-honeypot collector -c /etc/tarpit-honeypot/aggregator.yaml
```

## `validate-config`

Parse + validate a YAML file. Also reports TLS-cert ↔ deployment-domain coherence warnings (the same the sensor logs at startup and shows on the config page), so a mismatch is caught before deploy. Optionally diff against another file to see what would hot-reload vs require restart.

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

---

## `schema`

Emit a JSON Schema for the config, reflected from the Go config type so it never drifts from the code. Point an editor's YAML language server at it for structural validation + autocomplete — authoring mistakes (a `port:` outside `bind`, a missing listener `id`, an unknown handler) show up as you type instead of as a crash-loop at deploy.

```
tarpit-honeypot schema -o tarpit-honeypot.schema.json
# then, in VS Code settings.json:
#   "yaml.schemas": { "./tarpit-honeypot.schema.json": "tarpit-honeypot*.yaml" }
```

| Flag | Default | Meaning |
|---|---|---|
| `-o <path>` | stdout | Write the schema to a file instead of stdout. |

---

## `doctor`

Preflight / liveness self-check. Loads the effective config and reports whether what a running sensor depends on is actually in place: the data dir is writable, the event store exists, configured enrichment files are present, and — run against a live instance — each configured TCP listener is actually accepting. It closes the gap between "validate-config passed" and "the service is really serving".

```
tarpit-honeypot doctor -c /etc/tarpit-honeypot/config.yaml   # offline checks + probe localhost listeners
tarpit-honeypot doctor --no-probe                            # skip the listener connection probes
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config to check. |
| `--no-probe` | off | Do not try to connect to the configured listeners. |
| `--timeout <dur>` | `1s` | Per-listener connect timeout. |

Exit status is non-zero when a hard problem is found (e.g. data dir not writable); warnings (missing enrichment files, listeners not yet accepting) do not fail.

---

## `firewall-rules`

Print host-firewall rules that open exactly the ports the configured listeners (and honeynet host services) bind — so you never hand-transcribe them. firewalld is the default (RHEL/AlmaLinux/Fedora); `--format` selects nftables, ufw or iptables.

```
tarpit-honeypot firewall-rules -c /etc/tarpit-honeypot/config.yaml            # firewalld
tarpit-honeypot firewall-rules -c cfg.yaml --format nftables --iface eth0
tarpit-honeypot firewall-rules -c cfg.yaml --format ufw
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config whose listener ports to open. |
| `--format` | `firewalld` | `firewalld` \| `nftables` \| `ufw` \| `iptables`. |
| `--zone <z>` | active/default | firewalld zone to add the ports to. |
| `--iface <if>` | — | Restrict the rules to this ingress interface (nftables/iptables). |

The output is a comment block listing each port + what runs there, followed by copy-pasteable commands. Opening these ports to the internet is intentional for a honeypot — just make sure nothing real listens behind them.

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

## `replay`

Re-run a recorded request back through its protocol handler **offline** — no
socket, nothing executed, just the parse + detect path. A deterministic
regression / tuning harness.

```
# Replay what the sensor captured for an event, and report if detection drifted:
tarpit-honeypot replay -c cfg.yaml --event cca7b6a945c42b46ecd9e1fb
# Feed an arbitrary request to a handler from a file or stdin:
printf 'GET /../../etc/passwd HTTP/1.1\r\n\r\n' | tarpit-honeypot replay --handler http
```

| Flag | Meaning |
|---|---|
| `--event <id>` | Replay the bytes captured for this event back through its handler; prints `regression:` match/diff vs the stored anomalies. |
| `--handler <name>` | Handler to drive (inferred from `--event`). |
| `--file <path>` | Request bytes (`-`/unset = stdin). |
| `--udp` | Drive the handler as a UDP datagram. |
| `--vuln` | Enable vulnerable-banner emulation for the replay. |
| `--json` | JSON output (default true). |

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
| `--target <ip>` | — | Exact-match destination/server-IP filter — which of the host's own IPs was hit (the multi-IP pivot). |
| `--handler <name>` | — | Exact-match protocol-handler filter (e.g. `ssh`, `http`, `snmptrap`). |
| `--port <n>` | — | Exact-match destination-port filter. |
| `--rule <id>` | — | Exact-match rule_id filter (e.g. `listener:ssh-bait`, `correlate:port_scan`). |
| `--fleet` | off | Show only cross-sensor `fleet:*` findings (prefix filter). |
| `--limit <N>` | `100` | Max events to return (newest first). |

Output format:

```
2026-05-19T18:30:45Z  critical  canary:shared-creds              -> :0  (cca7b6a945c42b46ecd9e1fb)
2026-05-19T18:30:42Z  high      listener:ssh-bait                127.0.0.1 -> 127.0.0.1:2222  (ed5393fa19ba6613f09010b4)
```

The trailing parenthesized id is the event id — feed it to `export-pcap`.

---

## `gen-token`

Generate an unguessable canary token. Eleven shapes for the common bait surfaces (inspired by the canarytokens.org token zoo); default 64 bits of entropy.

```
tarpit-honeypot gen-token --type=dns --label=prod-cdb --domain=canary.example.com
# 6191564a98496be6-prod-cdb.canary.example.com

tarpit-honeypot gen-token --type=url --bits=128
# /__canary__/8ed2a49c8ef9639a1234567890abcdef

tarpit-honeypot gen-token --type=hex --bits=256
# 64-hex-char string

tarpit-honeypot gen-token --type=ssrf --domain=oob.canary.example.com
# http://oob.canary.example.com/ssrf/6191564a98496be6

tarpit-honeypot gen-token --type=doc --domain=oob.canary.example.com --label=q4-financials -o bait.docx
# wrote bait.docx (callback: http://oob.canary.example.com/doc/6191564a98496be6-q4-financials)
```

| Flag | Default | Meaning |
|---|---|---|
| `--type` | `dns` | `dns` / `url` / `ssrf` / `hex` / `doc` / `log4shell` / `aws` / `css` / `mcp` / `wireguard` / `folder`. |
| `--label` | "" | Optional human-readable suffix (DNS-safe chars only). |
| `--bits` | `64` | Multiple of 8 between 32 and 256. |
| `--domain` | `canary.example.com` | For `--type=dns` / `ssrf` / `doc`, the base domain. |
| `-o` | "" | For `--type=doc`, the output file (default `canary-<token>.docx`). |

Paste a `dns`/`url` token into a `dns_canaries:` or `url_canaries:` block and the sensor fires the moment the token gets touched anywhere on the network. A `--type=ssrf` token is a full callback URL to plant in an SSRF parameter, webhook field, or XXE entity; point it at an `ssrf_canary` listener, which records the out-of-band fetch (token + the fetching system's `User-Agent` / `X-Forwarded-For` / `Via`) and flags `ssrf-callback` / `ssrf-server-side-fetch`.

A `--type=doc` token is a **decoy Word document** (`.docx`): a real, valid Office Open XML file whose `settings.xml` carries an *external* `attachedTemplate` relationship pointing at the callback URL. Word resolves that relationship on open, issuing an outbound GET the `ssrf_canary` (or any HTTP) listener records — so dropping the file on a share named like real sensitive data turns "someone opened the honeydoc" into an alert with the opener's IP and headers. The visible document text is innocuous bait; the beacon is in the relationship, not the content.

---

## `gen-wallet-decoys`

Write believable, structurally-correct **crypto-wallet decoy files** (18 formats: `bitcoin-core` `wallet.dat` that `file` reports as a real Berkeley DB, `ethereum-keystore`, `electrum`, `bip39-seed`/`ledger-recovery`/`trezor-backup`, `metamask-vault`, `monero`, `wif-privkeys`/`paper-wallet`, `solana-keypair`, `exodus`, `litecoin`, `dogecoin`, `dash`, `zcash`, `tron`, `cardano`) to seed honeypot loot. Deterministic in `--seed` (random + printed if omitted); every exposed address/key/mnemonic is a trackable canary. Nothing grants real access.

```
tarpit-honeypot gen-wallet-decoys --dir ./loot/.wallets --seed deploy-A
tarpit-honeypot gen-wallet-decoys --list
```

| Flag | Default | Meaning |
|---|---|---|
| `--dir` | `./wallet-decoys` | output directory |
| `--seed` | random | deterministic seed (stable decoys per deployment) |
| `--kind` | `all` | one wallet kind, or `all` |
| `--list` | — | list the supported kinds and exit |

## `gen-lures`

Write believable **credential/secret decoy files** (14 formats: `aws-credentials`, `ssh-private-key`, `dotenv`, `kubeconfig`, `gcp-service-account`, `npmrc`, `pypirc`, `git-credentials`, `dockerconfig`, `pgpass`, `netrc`, `terraform-state`, `jwt-token`, `slack-token`) for honeypot loot — the files attackers and agentic tooling grep for. Same `--dir`/`--seed`/`--kind`/`--list` flags as `gen-wallet-decoys`; each file's headline value is a trackable canary.

```
tarpit-honeypot gen-lures --dir ./loot --seed deploy-A
```

## `gen-agent-breadcrumb`

Write harmless **breadcrumb files** (`AGENTS.md`, `ops-gateway.txt`, `.env.gateway`, `README.gateway.md`) that describe an "ops gateway" and point a crawling autonomous agent at the [`agent`](AGENTIC.md) honeypot, so it reveals itself when it connects.

```
tarpit-honeypot gen-agent-breadcrumb --url http://10.0.0.9:8080/ --dir ./breadcrumbs
```

| Flag | Default | Meaning |
|---|---|---|
| `--dir` | `./agent-breadcrumbs` | output directory |
| `--url` | `http://ops-gateway.internal:8080/` | the agent-honeypot gateway URL the breadcrumbs point at |

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
tarpit-honeypot list-devices -c cfg.yaml --stats
tarpit-honeypot list-devices -c cfg.yaml --conflicts
tarpit-honeypot list-devices -c cfg.yaml --rogues
tarpit-honeypot list-devices -c cfg.yaml --class ics-endpoint
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |
| `--json` | off | Emit the output as JSON instead of a table (works with every mode below). |
| `--stats` | off | Print an aggregate summary (total / allow-listed / rogue; by source; by class) instead of the table. |
| `--conflicts` | off | List IPs bound to multiple MACs — possible ARP spoofing / impersonation. |
| `--rogues` | off | Show only non-allow-listed (rogue) devices. |
| `--class <c>` | — | Show only devices of an inferred class (`scanner` / `ics-endpoint` / `network-device` / `web-host` / `host`). |
| `--vendor <s>` | — | Show only devices whose OUI vendor contains the substring. |
| `--search <q>` | — | Show only devices matching the substring (ip / mac / hostname / vendor / attrs). |
| `--stale <dur>` | — | Show only devices NOT seen within the duration (e.g. `24h`). |
| `--active <dur>` | — | Show only devices seen within the duration (e.g. `1h`). |

The selector flags (`--rogues` / `--class` / `--vendor` / `--search` / `--stale` /
`--active`) pick which slice of the inventory to list (the first one set wins).
`--stats` and `--conflicts` are standalone report modes. All of these are also
surfaced in the web UI's **/devices** tab (a summary panel + an IP/MAC-conflict
warning), available as JSON at `/api/devices/summary`.

Output:

```
IP               MAC                VENDOR                 HOSTNAME             SOURCE    CLASS          LAST SEEN
10.0.0.10        00:90:e8:11:22:33  Moxa                   plc-press            dhcp      ics-endpoint   2025-05-19 14:03
10.0.0.50        -                  -                      -                    conn      host           2025-05-19 14:05
```

---

## `list-paths`

Print every filesystem path the effective config references — config file(s),
enrichment inputs (Tor / threat-intel / OUI), databases (GeoIP/ASN + the event
store), and the data-dir state — with whether each currently exists. Use it to
audit a deployment and to drive the enrichment installer.

```
tarpit-honeypot list-paths -c cfg.yaml
tarpit-honeypot list-paths -c cfg.yaml --category enrichment
tarpit-honeypot list-paths -c cfg.yaml --format json
tarpit-honeypot list-paths -c cfg.yaml --format tsv   # category<TAB>key<TAB>access<TAB>exists<TAB>path
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <path>` | `/etc/tarpit-honeypot/config.yaml` | Config file. |
| `--format` | `table` | `table` \| `json` \| `tsv` (`--json` is a shortcut for `--format json`). |
| `--category` | (all) | Filter to `config` \| `enrichment` \| `database` \| `state`. |

The same inventory appears in the web UI's `/config` "files in use" panel.
`scripts/install-enrichment.sh` consumes `--format tsv` to learn where to place
downloaded enrichment files. See [`docs/config.md`](config.md) for the
fetch → transfer → install workflow.

---

## `list-archetypes`

Dump the built-in device/OS archetype catalog. With no argument it lists
every archetype (the canonical name you put in `sensor.archetype:`, its
family, and service + CVE counts); with a name — either the canonical
name or the pretty display name — it prints that archetype's full
fingerprint (banners, SNMP identity, ICMP TTL, advertised CVEs, default
services). Reads only the in-source catalog: no config, no network.

```
tarpit-honeypot list-archetypes
tarpit-honeypot list-archetypes debian-12
tarpit-honeypot list-archetypes --json beckhoff-cx
```

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Emit JSON (a summary array, or the detail object with `<name>`). |

---

## `list-handlers`

Print the protocol handlers the sensor ships, split by transport. These
are exactly the values accepted in a listener's `handler:` field — the
list comes from the same whitelist `validate-config` enforces, so it can
never drift from what `run` accepts.

```
tarpit-honeypot list-handlers
tarpit-honeypot list-handlers --proto udp
```

| Flag | Default | Meaning |
|---|---|---|
| `--proto tcp\|udp` | both | Limit to one transport. |

---

## `list-archeservices`

Print the service roles (`webserver`, `ftpserver`, `printserver`,
`fileserver`, `ldapserver`, `adserver`, …) and the port/proto/handler set
each one stands up. Use a role in an `archeservices:` config entry together
with an `archetype:` so the expanded listeners answer with the right
software identity. Read-only; no config or network needed.

```
tarpit-honeypot list-archeservices
tarpit-honeypot list-archeservices adserver
```

---

## `list-cves`

Print the in-source CVE catalog used for vulnerable-banner emulation and
exploit-attempt recognition. The `DET` column marks records that carry an
exploit signature (a live attempt is flagged by `MatchPayload` as a
`cve:<id>` event); the rest are advisory-only (banner / patch-level).

```
tarpit-honeypot list-cves
tarpit-honeypot list-cves --service fortinet
tarpit-honeypot list-cves --json
```

| Flag | Default | Meaning |
|---|---|---|
| `--service <handler>` | all | Filter by service/handler (e.g. `http`, `s7`, `fortinet`). |
| `--json` | off | Emit the catalog as JSON. |

---

## `kev-gap`

Cross-check the built-in CVE catalog against the **CISA Known Exploited Vulnerabilities (KEV)** catalog and report which KEV entries the sensor does/doesn't cover. Offline-friendly: feed a downloaded KEV JSON with `--file` (see `scripts/fetch-kev.sh`), or pull it live with `--url`. `--covered` lists the catalog CVEs that are on the KEV list. Complements the live `kev:` auto-sync (see [`threat-intel-exports.md`](threat-intel-exports.md) §10).

```
tarpit-honeypot kev-gap --file known_exploited_vulnerabilities.json
tarpit-honeypot kev-gap --covered --json
```

## `list-techniques`

Print the sensor's static MITRE ATT&CK coverage: every rule / handler /
anomaly marker mapped to its ATT&CK techniques + tactics, annotated with
the D3FEND countermeasures the router stamps alongside. Use it to audit
detection coverage or to build ATT&CK-navigator layers.

```
tarpit-honeypot list-techniques
tarpit-honeypot list-techniques --kind anomaly
tarpit-honeypot list-techniques --json
tarpit-honeypot list-techniques --defenses    # D3FEND id -> name legend
```

| Flag | Default | Meaning |
|---|---|---|
| `--kind rule\|handler\|anomaly` | all | Limit to one mapping class. |
| `--json` | off | Emit the coverage map (or, with `--defenses`, the D3FEND legend) as JSON. |
| `--defenses` | off | Print the D3FEND countermeasure legend (id → name) and exit. |

---

## `export-navigator`

Write a **MITRE ATT&CK Navigator** layer (JSON) of the sensor's technique coverage, for import at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/). Default is the static catalog coverage; `--observed` colours only the techniques actually seen in the event store.

```
tarpit-honeypot export-navigator -c cfg.yaml --observed -o layer.json
```

## `list-fleet-rules`

Print the cross-sensor (`fleet:*`) detector catalog: every rule the aggregator's
fleet correlator can emit, what it detects, and the `fleet.*` config keys that
tune it. The discovery counterpart to the `fleet:` section of `docs/config.md`.

```
tarpit-honeypot list-fleet-rules
tarpit-honeypot list-fleet-rules --json
```

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Emit the catalog as JSON (id, summary, config keys). |

The same catalog is documented narratively in [`docs/fleet.md`](fleet.md), grouped
by detection axis (breadth, shared-artifact campaign, coordination, temporal,
novelty, identity/infrastructure, …). Fleet detection only fires on an
**aggregator** — a node with `ingest:` receiving events from several sensors.

---

## `list-unavailable-capabilities`

Print the high-interaction / capture features that are **disabled or infeasible** on this platform + config (e.g. a feature gated by `interaction.mode`, or a Linux-only capture path on macOS), with the reason for each. Use it to understand why a given deception depth isn't active.

```
tarpit-honeypot list-unavailable-capabilities -c cfg.yaml
```

## `export-iocs`

Derive the fleet's indicators from the stored `fleet:*` findings and print them
for piping into a TIP / SIEM / blocklist. The offline counterpart to the live
`<ingest>/intel` feed and `/intel/stix` endpoint — it reads the local event
store, so it works on any node that persists events.

```
tarpit-honeypot export-iocs -c cfg.yaml                      # STIX 2.1 bundle
tarpit-honeypot export-iocs -c cfg.yaml --format txt          # one value per line (blocklist)
tarpit-honeypot export-iocs -c cfg.yaml --format csv --since 720h
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <config>` | `/etc/tarpit-honeypot/config.yaml` | Config (for the `data_dir` holding `events.db`). |
| `--since <dur>` | `168h` | Derive IOCs from fleet findings newer than this. |
| `--format stix\|csv\|txt\|json` | `stix` | STIX 2.1 bundle, CSV (`kind,value,reason`), plain values, or raw JSON. |

`export-iocs` derives from the stored `fleet:*` findings (the curated, cross-sensor
indicators); the live `/api/iocs` endpoint and the **iocs** UI tab expose the
broader per-sensor IOC store. See [`docs/ioc.md`](ioc.md) for the two layers and
[`docs/threat-intel-exports.md`](threat-intel-exports.md) for the STIX/TAXII/MISP
field mappings.

---

## `check-iocs`

Retro-hunt: read a file of indicators (attacker source IPs and/or CIDR ranges)
and report which of them appear in the local event store's historical data —
"has this honeypot ever seen any of these hosts?". By default indicators match
each event's **source IP** (the attacker); `--match dst` matches the destination
IP and `--match any` matches either. The inverse of `export-iocs`: that emits
this sensor's indicators, this checks someone else's feed against your history.

```
tarpit-honeypot check-iocs -c cfg.yaml --file threatfeed.txt
tarpit-honeypot check-iocs -c cfg.yaml --file bad-cidrs.txt --since 2160h --format json
tarpit-honeypot export-iocs -c cfg.yaml --format json > mine.json && \
    tarpit-honeypot check-iocs -c cfg.yaml --file mine.json --fail-on-hit
```

The `--file` format is auto-detected and may be any of:

- one IP or CIDR per line (blank lines and `#` / `//` comments ignored);
- several **comma-separated** IPs/CIDRs per line;
- **CIDR** ranges (`10.0.0.0/8`, `2001:db8::/32`) alongside bare IPs;
- **JSON** — an array of strings, an array of objects with a `value`/`ip` field
  (so `export-iocs --format json` round-trips), or an object wrapping an
  `iocs`/`indicators`/`ips`/`values`/`addresses` array.

| Flag | Default | Meaning |
|---|---|---|
| `-c <config>` | `/etc/tarpit-honeypot/config.yaml` | Config (for the `data_dir` holding `events.db`). |
| `--file <path>` | — (required) | The IOC file to check. |
| `--match src\|dst\|any` | `src` | Which event field to match: `src` (attacker), `dst` (honeypot server IP that was hit), or `any` (either). |
| `--since <dur>` | `0` (all history) | Only match events newer than this (e.g. `720h`). |
| `--format text\|json` | `text` | Human table, or JSON with per-hit rollups. |
| `--fail-on-hit` | `false` | Exit non-zero (`2`) when any indicator matched — for cron / CI blocklist sweeps. |

Each hit reports the matched source IP (and the CIDR it fell in, when matched
through a range), the event count, first/last seen, max severity, distinct
rules, and a threat score (∑ severity²), ranked most-threatening first. Drill
into any hit with `list-events --source <ip>`.

---

## `export-creds`

Export the credentials the sensor captured — the same set the web UI's
**captures** page shows (login user/password pairs, SSH `auth_attempts`
including public keys, tokens, API keys, SNMP communities, cookies, Kerberos
pre-auth tickets, honeytokens) — reconstructed from the event store.

```
tarpit-honeypot export-creds -c cfg.yaml                                # all, JSON
tarpit-honeypot export-creds -c cfg.yaml --kind password --format csv
tarpit-honeypot export-creds -c cfg.yaml --kind token,api-key --format yaml
tarpit-honeypot export-creds -c cfg.yaml --since 24h --format txt
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <config>` | `/etc/tarpit-honeypot/config.yaml` | Config (for the `data_dir` holding `events.db`). |
| `--data-dir <dir>` | — | Operate on this directory directly (skips loading the config). |
| `--since <dur>` | `720h` (30d) | Only events newer than this. |
| `--kind <k1,k2>` | — (all) | Comma-separated credential kinds to include (e.g. `password`, `token`, `ssh-pubkey`, `api-key`, `snmp-community`, `kerberos-ticket`, `honeytoken`). |
| `--format <fmt>` | `json` | `json` \| `xml` \| `yaml` \| `csv` \| `txt`. |
| `--dedup` | on | Collapse identical kind/user/secret/service rows. |

---

## `reset-db`

**Destructively empty** the local event store, device inventory and captures, keeping the config and deployment identity. Requires `--yes` to proceed (it is irreversible). Use it to clear test data before going live.

```
tarpit-honeypot reset-db -c cfg.yaml --yes
```

## `rotate-db`

Write a compressed, point-in-time copy of the event database to an archive, then
optionally start fresh — classic log rotation for the `events.db` store. The
snapshot is a `VACUUM INTO` copy (consistent and compacted even while the sensor
is writing, no need to copy the `-wal`/`-shm` sidecars) which is then
gzip-compressed. With `--reset --yes` it empties the live event table and
`VACUUM`s, so the sensor continues with a small, fresh database; the archive is
always kept. Stop the sensor before `--reset`.

```
tarpit-honeypot rotate-db -c cfg.yaml                                   # archive only
tarpit-honeypot rotate-db -c cfg.yaml --out /backups/events-2026-06.db.gz
tarpit-honeypot rotate-db -c cfg.yaml --reset --yes                     # archive, then start fresh
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <config>` | `/etc/tarpit-honeypot/config.yaml` | Config (for the `data_dir` holding `events.db`). |
| `--data-dir <dir>` | — | Operate on this directory directly (skips loading the config). |
| `--out <file.gz>` | `<data_dir>/events-<UTC ts>.db.gz` | Archive destination. Refuses to overwrite. |
| `--reset` | off | After archiving, empty the live event store and `VACUUM`. |
| `--yes` / `-y` | off | Required with `--reset` to actually empty the store (otherwise a dry-run). |

---

## `prune-db`

Delete the oldest events from `events.db` to reclaim disk, choosing the rows to
drop by age, by count, or until the file is under a size budget (the three modes
are mutually exclusive). It **dry-runs unless `--yes`**, reporting how many rows
would go, and `VACUUM`s afterwards so freed pages return to the filesystem. Stop
the sensor first (`VACUUM` needs exclusive access). For continuous, automatic
retention prefer the config `sensor.disk.retention_days` / `sensor.disk.sqlite_mb`
knobs; `prune-db` is the manual, one-shot reclaim.

```
tarpit-honeypot prune-db -c cfg.yaml --keep-days 30            # dry-run
tarpit-honeypot prune-db -c cfg.yaml --keep-days 30 --yes
tarpit-honeypot prune-db -c cfg.yaml --keep-rows 1000000 --yes
tarpit-honeypot prune-db -c cfg.yaml --max-mb 200 --yes
```

| Flag | Default | Meaning |
|---|---|---|
| `-c <config>` | `/etc/tarpit-honeypot/config.yaml` | Config (for the `data_dir` holding `events.db`). |
| `--data-dir <dir>` | — | Operate on this directory directly (skips loading the config). |
| `--keep-days <N>` | — | Delete events older than N days. |
| `--keep-rows <N>` | — | Keep only the newest N events, delete the rest. |
| `--max-mb <N>` | — | Delete oldest events (in batches) until the DB is under N MB. |
| `--vacuum` | on | `VACUUM` after deleting to return freed space to disk. |
| `--yes` / `-y` | off | Actually delete (without this it is a dry-run). |

---

## `identify`

Run the sensor's offline fingerprint engine over signals you supply and
print the same verdict a live listener would attach: the tool / scanner
name, an automation flag, and any CVE exploit signature found in
`--payload`. A tuning / triage aid — paste a string out of a log and see
what the sensor makes of it. No network, no config; supply at least one
signal.

```
tarpit-honeypot identify --ua "sqlmap/1.7"
tarpit-honeypot identify --ssh SSH-2.0-Go
tarpit-honeypot identify --payload '${jndi:ldap://x/a}' --handler http
```

| Flag | Default | Meaning |
|---|---|---|
| `--ua <s>` | — | HTTP User-Agent to classify. |
| `--path <s>` | — | HTTP request path to classify. |
| `--method <m>` | `GET` | HTTP method (with `--path`/`--ua`). |
| `--headers a,b` | — | Comma-separated HTTP header names seen. |
| `--ssh <s>` | — | SSH client id, e.g. `SSH-2.0-libssh2_1.9.0`. |
| `--ja3 <s>` | — | JA3 TLS fingerprint (md5 hex). |
| `--payload <s>` | — | Raw request bytes to scan for CVE exploit signatures. |
| `--handler <h>` | `http` | Service context for `--payload` CVE matching. |

---

## `analyze`

Statically analyze a captured artifact **offline** (a dropped payload, webshell, or shellcode pulled from the captures dir): reports the detected format, entropy, embedded IOCs, and YARA matches from the built-in rule pack. No network, no sensor state.

```
tarpit-honeypot analyze /var/lib/tarpit-honeypot/captures/<id>.bin --yara
```

## `jarm`

Actively probe a TLS server and print its **JARM** fingerprint. JARM opens
several TLS connections with deliberately varied ClientHellos (version window,
cipher ordering, ALPN) and fingerprints how the server negotiates each — a
stable identifier for the server's TLS stack/config.

```
tarpit-honeypot jarm 127.0.0.1:8443
# 27d40d40d29d40d1dc42d43d00041d...   (62-char fingerprint)

tarpit-honeypot jarm --sni mail.corp.local 10.0.0.9:443
```

| Flag | Default | Meaning |
|---|---|---|
| `--timeout` | `5s` | Per-probe dial + handshake timeout. |
| `--sni` | "" | ServerName (SNI) to send; empty = none. |

Point it at your own sensor's `https` listener to confirm its TLS posture
matches the product it impersonates (and hasn't drifted after a cert/profile
change). A probe the server refuses (e.g. it won't speak the offered version)
contributes a "no-response" slot, exactly as in a real JARM scan. The
fingerprint is self-consistent for drift detection; because `crypto/tls`
doesn't expose ClientHello extension ordering / GREASE, it is not guaranteed
byte-identical to the upstream FoxIO JARM corpus.

---

## `generate-decoys`

Scan **your own** network and emit a tarpit-honeypot listener config that
mirrors the live services it finds, so the honeypot blends into the environment
it is deployed in instead of exposing a tell-tale generic service set. This is
a benign **TCP connect scanner**: it completes a normal handshake, optionally
reads a server banner (or sends one minimal, well-formed probe for client-first
protocols like HTTP) and a TLS cert CN, classifies the service, and closes. It
never sends exploit traffic, never does stealth/SYN scanning, and never writes
to the target.

```
# probe one host across the curated default port set, write a config
tarpit-honeypot generate-decoys --yes 10.0.0.10 -o decoys.yaml

# a small subnet, specific ports, stamped with an archetype
tarpit-honeypot generate-decoys --yes --ports 22,80,443,3389 \
    --archetype ubuntu-22 10.0.0.0/28 -o decoys.yaml

# then review + validate before deploying
tarpit-honeypot validate-config -c decoys.yaml
```

Targets are `host`, `host:port`, or a `CIDR`. One listener is generated per
distinct open port (deduped across hosts — a honeypot is a single host that
presents the union of the environment's service ports), with the handler chosen
by the most common classification on that port. A discovered TLS service
contributes its cert Common Name to the generated `https.cn` so the decoy's
identity matches. Unknown services map to the `auto` catch-all.

| Flag | Default | Meaning |
|---|---|---|
| `--yes` | off | **Required.** Confirms you are authorized to scan the targets. Without it the command refuses. |
| `--ports` | curated set | Comma-separated TCP ports to probe. |
| `--timeout` | `2s` | Per-connection dial/read timeout. |
| `--concurrency` | `64` | Max concurrent connections. |
| `--max-hosts` | `256` | Hard cap on expanded host count (anti-mass-scan guard; a CIDR that exceeds it is refused). |
| `--bind` | `0.0.0.0` | Bind address for the generated listeners. |
| `--archetype` | "" | `sensor.archetype` to stamp on the output (for identity coherence). |
| `--name` | "" | `sensor.name` for the output. |
| `--read-timeout` | `30s` | `read_timeout` for the generated listeners. |
| `--no-banners` | off | Skip banner / TLS-cert grabbing (faster, less faithful classification). |
| `-o <path>` | `-` (stdout) | Output file path. |

**Authorization.** `generate-decoys` actively connects to the targets. Only run
it against networks you own or are explicitly authorized to assess; the `--yes`
flag is a deliberate confirmation of that. The output is a starting point —
review the binds, severities, and archetype, and wire your sinks/UI, before
deploying.

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
# tarpit-honeypot 1.4.0 (commit a1b2c3d, built 2026-06-01T18:30:00Z)

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

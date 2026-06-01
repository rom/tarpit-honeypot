# CLI Reference

The binary is a single static executable. Invoke it as `tarpit-honeypot <subcommand> [flags]`. See [`docs/usage.md`](usage.md) for higher-level scenarios and [`docs/config.md`](config.md) for the YAML schema each `-c` flag points at. For the fleet-specific commands see [`docs/fleet.md`](fleet.md); for the IOC / threat-intel exports see [`docs/ioc.md`](ioc.md) and [`docs/threat-intel-exports.md`](threat-intel-exports.md).

```
tarpit-honeypot run            -c <config> [--dry-run] [common flags]
tarpit-honeypot validate-config -c <config> [--diff <other.yaml>]
tarpit-honeypot show-config    -c <config>
tarpit-honeypot test-alert     -c <config> [--severity high] [--note "..."]
tarpit-honeypot list-events    -c <config> [--since 24h] [--source <ip>] [--rule <id>] [--fleet] [--limit N]
tarpit-honeypot gen-token      --type=dns|url|hex|ssrf [--label LBL] [--bits N] [--domain D]
tarpit-honeypot export-pcap    -c <config> --event <id> [-o file|-]
tarpit-honeypot list-honeynets -c <config>
tarpit-honeypot list-devices   -c <config> [--json] [--stats|--conflicts|--rogues|--class C|--vendor S|--search Q|--stale D|--active D]
tarpit-honeypot list-paths     -c <config> [--format table|json|tsv] [--category config|enrichment|database|state]
tarpit-honeypot list-archetypes [--json] [<name>]
tarpit-honeypot list-handlers  [--proto tcp|udp]
tarpit-honeypot list-archeservices [<role>]
tarpit-honeypot list-cves      [--service <handler>] [--json]
tarpit-honeypot list-techniques [--kind rule|handler|anomaly] [--json]
tarpit-honeypot list-fleet-rules [--json]
tarpit-honeypot export-iocs    -c <config> [--since 168h] [--format stix|csv|txt|json]
tarpit-honeypot identify       [--ua S] [--path S] [--ssh S] [--ja3 S] [--payload S] [--handler H]
tarpit-honeypot jarm           [--timeout D] [--sni NAME] <host:port>
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

Privileged setup happens **before** `drop_user`/`drop_group` takes effect:

1. Bind low-numbered listener ports (needs `CAP_NET_BIND_SERVICE` post-drop)
2. Open data_dir (root-writable in most deployments)
3. Open ARP / ICMP / LLDP responder sockets (needs `CAP_NET_RAW` post-drop)
4. Open TUN device (needs `CAP_NET_ADMIN` post-drop)

The systemd unit pre-grants the necessary `AmbientCapabilities` so the drop is safe.

On **macOS**, the AF_PACKET/TUN steps are no-ops (Linux-only — see [`docs/usage.md` §14](usage.md#14-platform-support)). Privileged port binding works as on any BSD-derived system: bind as root, then `setuid` to the configured `drop_user` (uses `syscall.Setuid`, which on darwin also drops the saved-uid so a later `setuid(0)` regain attempt fails). launchd's `<SoftResourceLimits>` and `<UserName>` keys can replace `AmbientCapabilities`.

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

Generate an unguessable canary token. Five shapes for the common bait surfaces; default 64 bits of entropy.

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
| `--type` | `dns` | `dns` / `url` / `hex` / `ssrf` / `doc`. |
| `--label` | "" | Optional human-readable suffix (DNS-safe chars only). |
| `--bits` | `64` | Multiple of 8 between 32 and 256. |
| `--domain` | `canary.example.com` | For `--type=dns` / `ssrf` / `doc`, the base domain. |
| `-o` | "" | For `--type=doc`, the output file (default `canary-<token>.docx`). |

Paste a `dns`/`url` token into a `dns_canaries:` or `url_canaries:` block and the sensor fires the moment the token gets touched anywhere on the network. A `--type=ssrf` token is a full callback URL to plant in an SSRF parameter, webhook field, or XXE entity; point it at an `ssrf_canary` listener, which records the out-of-band fetch (token + the fetching system's `User-Agent` / `X-Forwarded-For` / `Via`) and flags `ssrf-callback` / `ssrf-server-side-fetch`.

A `--type=doc` token is a **decoy Word document** (`.docx`): a real, valid Office Open XML file whose `settings.xml` carries an *external* `attachedTemplate` relationship pointing at the callback URL. Word resolves that relationship on open, issuing an outbound GET the `ssrf_canary` (or any HTTP) listener records — so dropping the file on a share named like real sensitive data turns "someone opened the honeydoc" into an alert with the opener's IP and headers. The visible document text is innocuous bait; the beacon is in the relationship, not the content.

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

## `list-techniques`

Print the sensor's static MITRE ATT&CK coverage: every rule / handler /
anomaly marker mapped to its ATT&CK techniques + tactics, annotated with
the D3FEND countermeasures the router stamps alongside. Use it to audit
detection coverage or to build ATT&CK-navigator layers.

```
tarpit-honeypot list-techniques
tarpit-honeypot list-techniques --kind anomaly
tarpit-honeypot list-techniques --json
```

| Flag | Default | Meaning |
|---|---|---|
| `--kind rule\|handler\|anomaly` | all | Limit to one mapping class. |
| `--json` | off | Emit the coverage map as JSON. |

---

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
# tarpit-honeypot 2.2.0 (commit a1b2c3d, built 2026-06-01T18:30:00Z)

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

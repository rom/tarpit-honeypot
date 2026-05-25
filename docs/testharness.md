# Test Harness

`tarpit-testharness` is a local QA / reliability harness that *exercises* the
sensor — it is a separate tool, not part of the `tarpit-honeypot` binary. It
drives either the complete tool over the network (a managed instance it spawns,
or an already-running external one) or individual protocol-handler modules
in-process, across categorized, individually-selectable test cases: unit checks,
dumb + smart fuzzing, protocol emulation/compatibility, deliberate
mis-implementation, port/host/ping/ARP sweeps, client-fingerprint triggers, and
fail-safe **resilience** (abuse/overload) + **containment** (do-no-harm) checks.

It runs fully automated (auto input + restarts), quiet in the background, or with
per-case progress; is bounded by rounds and/or wall-clock time; retries
(restarting the target) on failures/crashes; writes reports
(text/json/junit/md/csv/rtf/pdf); and records every run + result in a SQLite
database keyed by tool version + time.

For the sensor itself see [`usage.md`](usage.md), [`cli.md`](cli.md), and
[`config.md`](config.md). This document covers only the harness.

---

## Build

The harness is a second command in this repo and is not built by `make build`
(which builds only the sensor). Build it directly:

```bash
go build -o bin/tarpit-testharness ./cmd/tarpit-testharness
```

The harness has its own unit tests (an in-process fake target, the module
backend against real handlers, report + DB round-trips); `make test` (or
`go test ./internal/testharness/`) runs them.

---

## At a glance

```
tarpit-testharness list    -c harness.yaml
tarpit-testharness run     -c harness.yaml --progress
tarpit-testharness run     --target 127.0.0.1 --endpoint ssh=tcp:2222:ssh --case 'fuzz-*'
tarpit-testharness history -db harness-results.db
```

The repo ships a ready-to-run pair: [`configs/harness.example.yaml`](../configs/harness.example.yaml)
(the harness config — spawns the sensor and verifies detection) and
[`configs/harness-target.yaml`](../configs/harness-target.yaml) (the small
loopback sensor it drives). After `make build` + building the harness:

```bash
bin/tarpit-testharness run -c configs/harness.example.yaml --progress
```

Quickstart against a handler in-process (no sensor process, no privileges):

```bash
# Drive the http + ssh handlers directly; show every case as it finishes.
tarpit-testharness run --mode module \
  --endpoint http=tcp:0:http --endpoint ssh=tcp:0:ssh \
  --category unit,emulate,misimpl,fuzz-dumb --progress
```

Quickstart against a running sensor on the wire, recording detection:

```bash
tarpit-testharness run \
  --target 127.0.0.1 \
  --endpoint ssh=tcp:2222:ssh --endpoint http=tcp:8000:http \
  --verify-url http://127.0.0.1:8088 \
  --report junit=harness.xml --report text \
  --db harness-results.db --progress
```

Exit code is **0** when there are no findings, **1** when there are (for CI
gating), **2** on a setup error.

---

## Backends

The target is selected by `mode` and whether a spawn `binary` is set:

| Backend | `mode` | How it is reached | Lifecycle the harness manages |
|---|---|---|---|
| **Module** | `module` | Each handler is instantiated in-process and driven over an in-memory pipe — no sensor process, no sockets. | None (no process). `tcp` handlers only. |
| **Managed network** | `network` + `spawn.binary` set | The harness spawns the sensor binary, dials `host:port`, and can kill + respawn it on a crash. | Spawn, readiness-wait, kill/respawn on retry, stop at the end. |
| **External network** | `network`, no `spawn.binary` | Dials an already-running sensor at `host:port`. | Optional `restart_cmd` on retry; otherwise just re-tried in place. |

Notes:

- **Module mode** is the fastest, most isolated way to fuzz a handler and to
  check emulation/compatibility; it needs no privileges. Scans and
  fingerprinting are skipped (they need the wire).
- **Readiness:** a managed target is waited on until a TCP endpoint answers (or
  `spawn.health_url` returns < 500); an external target is waited on **only**
  when `spawn.health_url` is set — otherwise the harness trusts the operator
  that it is up, so that probing a deliberately-closed port is not mistaken for
  the whole target being down.

---

## Subcommands

All three accept the common selection flags:

| Flag | Meaning |
|---|---|
| `-c`, `-config <path>` | Harness YAML config. |
| `-mode network\|module` | Backend override. |
| `-target <host>` | Target host (network mode). |
| `-endpoint label=proto:port[:handler]` | Add/override an endpoint. Repeatable; CSV ok. `port` may be `0` in module mode. |
| `-case <id\|glob\|category>` | Select cases. Repeatable; CSV ok. |
| `-category <name>` | Category allow-list. Repeatable; CSV ok. |

### `list`

Print the cases a config/selection expands to, without running anything.

```bash
tarpit-testharness list --endpoint ssh=tcp:22:ssh --endpoint http=tcp:80:http
tarpit-testharness list -c harness.yaml --case 'fuzz-*'
```

### `run`

Run the selected cases. In addition to the common flags:

| Flag | Default | Meaning |
|---|---|---|
| `-binary <path>` | — | Sensor binary to spawn + manage as the target (→ managed network). |
| `-spawn-config <path>` | — | Config passed to the spawned sensor's `run`. |
| `-health-url <url>` | — | Readiness probe URL for the spawned/external target. |
| `-restart-cmd <sh>` | — | Shell command to restart an **external** target after a crash. |
| `-rounds N` | `1` | Number of full passes over the selected cases. |
| `-duration D` | `0` | Wall-clock bound (e.g. `30m`); the run stops cleanly when exceeded. `0` = run to completion. |
| `-retries N` | `1` | Per-case retries on fail/crash (`-1` = take the config value). |
| `-timeout D` | `3s` | Per-exchange I/O timeout. |
| `-concurrency N` | `1` | Cases to run in parallel (`1` = deterministic ordering). |
| `-fuzz-iter N` | `64` | Inputs per fuzz case. |
| `-seed N` | recorded | Fuzz seed (reproducible; recorded in the report + DB). |
| `-sweep-cidr <cidr>` | — | CIDR for host/ping/ARP sweeps (sweeps skip without it). |
| `-verify-url <url>` | — | Target web API base URL for detection verification. |
| `-verify-token <tok>` | — | API auth token (prefer the config/env; see Security). |
| `-quiet` | off | No output (run fully in the background). |
| `-progress` | off | Print a line per case as it completes. |
| `-report fmt[=path]` | text→stdout | Report to write; repeatable. `fmt` ∈ `text\|json\|junit\|md\|csv\|rtf\|pdf`; path `-`/empty = stdout. |
| `-db <path>` | — | SQLite results database to append this run to. |

Output modes: **quiet** prints nothing; **progress** prints every case; the
default prints only findings (problems) as they happen, then the report.

### `history`

Show recent runs recorded in a results DB.

```bash
tarpit-testharness history -db harness-results.db -n 20
```

| Flag | Default | Meaning |
|---|---|---|
| `-db <path>` | (required) | Results SQLite database. |
| `-n N` | `20` | Number of recent runs to show. |

---

## Test categories

Every case has a stable, unique id so it can be recalled and selected exactly.
Ids are deterministic from the config (endpoint labels + category), so a run is
reproducible and diff-able across builds.

| Category | Id pattern | Backends | What it checks |
|---|---|---|---|
| `unit` | `unit/port-open/<label>`, `unit/banner/<label>` | all | The endpoint is reachable and answers with a plausibly-shaped banner. |
| `emulate` | `emulate/<label>` | all | Speak the real protocol; is the response **compatible** (catches a broken emulation / setup). Known protocols only. |
| `misimpl` | `misimpl/<label>/<name>` | all | Deliberately mis-frame the protocol; does the honeypot **catch** it (records the expected anomaly). Verified via the API. |
| `fuzz-dumb` | `fuzz-dumb/<label>` | all | Protocol-**unaware** random input; the signal is a liveness re-check after every input (crash/hang detection). |
| `fuzz-smart` | `fuzz-smart/<label>` | all | Protocol-**aware** malformed input (oversized fields, bad lengths, illegal framing) mutated around known-bad shapes. Known protocols only. |
| `scan` | `scan/portscan-seq`, `scan/portscan-rand`, `scan/host-sweep`, `scan/ping-sweep`, `scan/arp-sweep` | network | Sequential + randomized TCP port scans; TCP host sweep, ICMP ping sweep, ARP sweep across `sweep_cidr`. |
| `fingerprint` | `fingerprint/http-<tool>`, `fingerprint/ssh-scanner`, `fingerprint/nmap-sV` | network | Emit traffic mimicking a known scanner/tool and confirm the client-classification layer detects it. |
| `reliability` | `reliability/soak/<label>` | all | 50 rapid connect/close cycles; the endpoint must stay responsive (no fd leak / accept-loop wedge), ≥ 90 % healthy, with liveness re-checked along the way. |
| `resilience` | `resilience/oversize/<label>`, `resilience/half-open/<label>`, `resilience/flood/<label>`, `resilience/slowloris/<label>` | all | **Fail-safe under abuse** — the sensor must not become the victim: a 2 MiB unterminated input (bounded buffers / no OOM), 40 abrupt half-open connects, a 64-way concurrent connection flood, and a slow-drip session that must not starve other clients — staying alive and responsive throughout. |
| `containment` | `containment/no-egress`, `containment/path-traversal/<label>` | all | **Do-no-harm** — feed the sensor an attacker-chosen target address and confirm it makes **no outbound connection** (SSRF / open-relay / reflector safety, via a canary listener); ask file-surface protocols (http/ftp) for `../../etc/passwd` and confirm no real host-file content is disclosed. |
| `integrity` | `integrity/capture/<label>`, `integrity/no-drop-under-load/<label>` | network (needs `verify.url`) | **Evidence integrity** — send a unique marker and confirm the sensor recorded it faithfully (capture fidelity); send a 20-connection burst of distinct markers and confirm **all** are recorded (no dropped events under load). Skips cleanly without the API. http/https/ftp/smtp_recv/telnet/imap/pop3. |

The `fingerprint` HTTP cases cover nmap, nessus, openvas, nikto, nuclei, sqlmap,
masscan, metasploit, zgrab, and wpscan (by User-Agent). If the real `nmap`
binary is on `PATH`, an extra `fingerprint/nmap-sV` case runs an actual `-sV`
service scan against the configured ports.

`misimpl`, `scan`, `fingerprint`, and `integrity` need the sensor's API
(`verify.url`) to confirm detection / capture; without it they **skip** cleanly
(scans report "completed"), and `misimpl`/fuzz still verify the target did not
crash.

### Protocol knowledge

`unit/port-open`, `unit/banner`, `fuzz-dumb`, and `reliability/soak` run for
**every** endpoint. The protocol-aware categories run only for handlers the
harness has a spec for:

| Handler | server-first | `emulate` | `fuzz-smart` shapes | `misimpl` anomalies checked |
|---|---|---|---|---|
| `http` | no | yes | oversized-uri, huge-content-length, many-headers, te-cl-smuggle | `http-method-unknown`, `http-request-line-non-printable` |
| `https` | no | yes | — | — |
| `ssh` | yes | yes | overlong-id, non-printable-id | `ssh-id-not-ssh`, `ssh-id-non-printable` |
| `ftp` | yes | yes | overlong-user, binary-command, traversal-arg | `ftp-upload-attempt`, `ftp-download-attempt` |
| `smtp_recv` | yes | yes | overlong-helo, binary-command, rcpt-flood | — |
| `telnet` | yes | yes | iac-do-storm, overlong-line, binary-creds | `telnet-credential-non-printable` |
| `redis` | no | yes | giant-multibulk, giant-bulklen, inline-overlong | — |
| `sip_tcp` | no | yes | no-headers, giant-cseq | `sip-invite-attempt` |
| `modbus` | no | yes | bad-length, bad-function | `modbus-write-attempt` |
| `rlogin` | no | yes | overlong-user, no-nulls | `rlogin-attempt` |
| `rsh` | no | yes | overlong-user, no-nulls | `rsh-command` |
| `rexec` | no | yes | overlong-pass, no-nulls | `rexec-command` |
| `tftp` | no | yes | bad-opcode, truncated, overlong-filename | `tftp-write-attempt`, `tftp-config-read` |
| `syslog_tcp` | no | yes¹ | oversized-msg, binary-msg, octet-count-overflow | — |
| `syslog_udp` | no | yes¹ | oversized-msg, binary-msg, empty-pri | — |
| `imap` | yes | yes | overlong-tag, huge-literal, binary-command | — |
| `pop3` | yes | yes | overlong-user, binary-command | — |
| `mysql` | yes | yes | oversized-login, bad-length | — |
| `postgres` | no | yes | oversized-startup, bad-length | — |
| `vnc` | yes | yes | bad-version, short-version, binary-version | — |
| `memcached` | no | yes | oversized-get, huge-set, binary | — |
| `mqtt` | no | yes | oversize-remlen, bad-proto-name, truncated | — |
| `ldap` | no | yes | bad-ber-length, truncated-bind, overlong-dn | — |

¹ `syslog_tcp` / `syslog_udp` are **accept-only**: they record what they are sent
and never reply, so `unit/banner` and `emulate` treat an empty response as
healthy (a non-reply is the correct behavior, not a missing banner).

`tftp` and `syslog_udp` are UDP handlers (configure the endpoint with
`proto: udp`); the rest are TCP. As UDP, they run only in **network** mode —
module mode is tcp-only.

An endpoint with an unknown handler still gets `unit`, `fuzz-dumb`, and
`reliability` coverage (port-open, a non-empty-banner check, and random-input
crash hunting).

---

## Selecting cases

`--case` and `--category` narrow what runs (and what `list` shows). They
combine: a case must pass the category allow-list **and** match a selector.
A selector matches when it is:

- an **exact** case id — `--case unit/port-open/ssh`
- a **glob** (`path.Match`) over the id — `--case 'emulate/*'`, `--case 'misimpl/ssh/*'`
- a slash-free glob over the **category** — `--case 'fuzz-*'` selects `fuzz-dumb` + `fuzz-smart`
- an **id prefix** — `--case unit/port-open/` (trailing slash) or `--case scan`
- a bare **category** name — `--case fuzz-dumb` or `--category fuzz-dumb`

```bash
# Only the SSH cases, any category:
tarpit-testharness list -c harness.yaml --case '*/ssh' --case 'unit/*/ssh'

# Everything except scans/fingerprints — fuzz + emulate + unit + misimpl:
tarpit-testharness run -c harness.yaml --category unit,emulate,misimpl,fuzz-dumb,fuzz-smart
```

---

## Config file

Pass a YAML file with `-c`; every field is overridable on the command line
(CLI wins). A representative config:

```yaml
mode: network                 # network | module
host: 127.0.0.1               # external target address (network mode)

# Spawn + manage the sensor as the target (omit `binary` to use an external one).
spawn:
  binary: ./bin/tarpit-honeypot
  config: ./configs/harness-target.yaml
  args: ["--log-level", "warn"]
  ready_timeout: 10s
  health_url: http://127.0.0.1:8088/healthz   # optional readiness probe
restart_cmd: ""               # external target: shell cmd to restart after a crash

endpoints:
  - { label: ssh,  proto: tcp, port: 2222, handler: ssh }
  - { label: http, proto: tcp, port: 8000, handler: http }
  - { label: modbus, proto: tcp, port: 5020, handler: modbus }

# Scope + budget.
categories: []                # empty = all; e.g. [unit, emulate, fuzz-smart]
cases: []                     # empty = all; ids / globs / prefixes
rounds: 1                     # full passes over the selected cases
duration: 0                   # wall-clock bound, e.g. 30m (0 = run to completion)
concurrency: 1                # cases in parallel (1 = deterministic)

# Resilience.
retries: 1                    # per-case retries on fail/crash
retries_by_case:              # per-case overrides
  fuzz-smart/http: 3
timeout: 3s                   # per-exchange I/O timeout

# Fuzzing.
fuzz_iterations: 64
seed: 0                       # 0 => the built-in default seed (still reproducible)
scan_ports: []               # empty => endpoint ports + a common set
sweep_cidr: 192.168.56.0/28   # for host/ping/ARP sweeps

# Detection verification (optional): point at the sensor's read-only API.
verify:
  url: http://127.0.0.1:8088
  token: ""                   # prefer an env var; see Security

# Output.
quiet: false
progress: false
reports:
  - { format: text,  path: "-" }       # "-" or "" = stdout
  - { format: junit, path: harness.xml }
  - { format: md,    path: harness.md }
  - { format: csv,   path: harness.csv } # one row per result, for spreadsheets
  - { format: pdf,   path: harness.pdf } # self-contained printable report
db: harness-results.db        # append every run here
```

Durations (`duration`, `timeout`, `spawn.ready_timeout`) accept either a Go
duration string (`30m`, `3s`, `500ms`) or a bare number of seconds — so the
natural `duration: 0` is valid (it means "no bound").

### `Config` fields

| Field | Default | Meaning |
|---|---|---|
| `mode` | `network` | Backend: `network` (dial the tool) or `module` (in-process handlers). |
| `host` | `127.0.0.1` | External target address (network mode). |
| `spawn` | — | Manage the sensor process as the target (see below). |
| `restart_cmd` | — | Shell command to restart an **external** target after a crash. |
| `endpoints` | — | Services under test (see below). |
| `rounds` | `1` | Full passes over the selected cases. |
| `duration` | `0` | Wall-clock bound; stop cleanly when exceeded (`0` = no bound). |
| `retries` | `1` | Global per-case retries on a bad outcome. |
| `retries_by_case` | — | Map of case id → retry count (overrides `retries`). |
| `timeout` | `3s` | Per-exchange I/O timeout (a case may use several exchanges). |
| `concurrency` | `1` | Cases run in parallel. |
| `categories` | all | Category allow-list. |
| `cases` | all | Case selectors (ids / globs / prefixes / categories). |
| `fuzz_iterations` | `64` | Inputs per fuzz case. |
| `seed` | default | Fuzz seed; `0` uses the built-in default. Recorded in reports + DB. |
| `scan_ports` | derived | Ports the scan cases probe; empty = endpoint ports + a common set (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080). |
| `sweep_cidr` | — | CIDR for host/ping/ARP sweeps; sweeps skip without it. |
| `verify` | — | Read-only API for detection verification (see below). |
| `quiet` / `progress` | off | Output mode. |
| `reports` | text→stdout | Reports to write. |
| `db` | — | SQLite results database to append to. |

### `endpoints[]`

| Field | Meaning |
|---|---|
| `label` | Stable name used in case ids (e.g. `ssh` → `fuzz-dumb/ssh`). Must be unique. |
| `proto` | `tcp` or `udp`. Module mode supports `tcp` handlers only. |
| `port` | Port (network mode; required there). Ignored in module mode. |
| `handler` | Handler name. Required in module mode; informational in network mode but used to pick the protocol spec for emulate/smart/misimpl. |

### `spawn`

| Field | Default | Meaning |
|---|---|---|
| `binary` | — | Path to the sensor binary. Set ⇒ managed target. |
| `config` | — | `-c` config passed to the spawned `run`. |
| `args` | — | Extra args appended to `run`. |
| `ready_timeout` | `10s` | How long to wait for the target to become ready. |
| `health_url` | — | Optional readiness probe URL (ready when it returns < 500). |

### `verify`

| Field | Meaning |
|---|---|
| `url` | Sensor web API base, e.g. `http://127.0.0.1:8088`. Enables detection checks. |
| `token` | Bearer token if the UI requires auth. |

### `reports[]`

| Field | Meaning |
|---|---|
| `format` | `text`, `json`, `junit`, `md`, `csv`, `rtf`, or `pdf`. |
| `path` | Output file; `-` or empty = stdout. |

---

## Retries and target restart

A case that ends `fail`, `crash`, or `error` is retried up to its retry count
(`retries_by_case[id]` if present, else `retries`). Between retries the harness
restarts the target: a managed target is killed + respawned; an external target
runs `restart_cmd` (if set); module mode is a no-op. After a non-scan case ends
badly the harness re-checks liveness — if the target is unresponsive the result
is reclassified `crash` so the report is honest about *why* it failed.

A per-case timeout (derived from `timeout` and `fuzz_iterations`, at least two
minutes) caps any single case so a hung target cannot stall the whole run.

---

## Rounds, time bound, and concurrency

`rounds` repeats the whole selected set (useful for soak / flake-hunting).
`duration` stops the run cleanly at a wall-clock deadline mid-round; the report
notes it was time-bounded. `concurrency` > 1 runs cases in parallel; keep it at
`1` for deterministic ordering when you want reproducible logs.

---

## Reproducible fuzzing

Both fuzzers are deterministic: each case derives its RNG from `seed` X:OR'd
with a hash of the case id, so the same `seed` reproduces the exact same inputs
for a given case, independent of selection or concurrency. The effective seed is
printed at start and recorded in every report and DB row. A crash report names
the input index and seed so you can replay it with `--seed`.

---

## Detection verification (the API)

When `verify.url` is set the harness queries the sensor's read-only events API
(`GET <url>/api/events?since=10m&limit=5000`, `Authorization: Bearer <token>`
when a token is given) and matches recent events by `rule_id` prefix, exact
anomaly marker, or attributed tool. This turns "I sent a scanner signature" into
"the honeypot **identified** it" (pass) or "did **not**" (fail). If the API is
unreachable the case **skips** (checked=false) rather than failing — so a
missing API never produces false findings.

---

## What a run records about the target (before / during / after)

Beyond each case's pass/fail, every run captures context about the program under
test so a report is self-describing and reproducible. It appears in an
**Environment & target** section of the text/markdown/RTF/PDF reports and as an
`info` object in the JSON report.

- **Before** — provenance + environment: harness host (OS/arch/CPUs/Go
  version/hostname), a one-line config summary (mode, endpoint count, categories,
  rounds, concurrency, fuzz iterations, timeout, seed), the spawned sensor
  binary's **SHA-256 + size** (managed mode), and a **baseline snapshot** of every
  endpoint (reachable?, byte count, and a hash of the identity banner).
- **During** — a resource envelope sampled ~4×/s for the length of the run:
  **RSS** (read from the sensor's `/proc/<pid>` when managed, else the harness
  process — which hosts the handlers in module mode) and **goroutine count**,
  each as start / peak / end. A peak well above the end is normal load; an *end*
  that stays far above the *start* is the leak signal.
- **After** — a **final snapshot** of every endpoint compared to the baseline
  (`stable` / `DRIFTED` / `NOW UNREACHABLE`), and how the run ended (completed /
  time-bounded / interrupted, with a warning if a managed sensor had exited).

This is the "additional info collected from the program under test" that makes a
fail-safe harness auditable. Drift uses the *banner line* (not the whole reply),
so per-connection nonces (e.g. the SSH KEXINIT cookie) are not mistaken for a
changed decoy.

**Harness self-trust.** Before touching the target, the runner runs synthetic
positive / negative / error / panic controls through the same execution path
real cases use and verifies each is classified correctly — if the harness can no
longer tell a pass from a fail it **aborts** rather than risk reporting a false
all-green ("nothing ran, so nothing failed"). It also confirms case selection is
deterministic. After the run it checks the **accounting invariant** — every
dispatched `(case, round)` produced exactly one recorded result. Both are shown
in the report's Environment block (`self-check passed; accounting N/N results
recorded`) and a mismatch is surfaced loudly.

---

## Reports

`--report fmt[=path]` is repeatable; the same run can emit several formats at
once. With no `--report` and not `--quiet`, a text summary goes to stdout.

| Format | Use |
|---|---|
| `text` | Human summary: header (tool version, target, seed, duration, rounds), per-category tally, then the findings list. |
| `json` | Full structured result (every case, status, attempts, duration) for tooling. |
| `junit` | JUnit XML for CI — `fail`/`crash` → `<failure>`, `error` → `<error>`, `skip` → `<skipped>`. |
| `md` | Markdown summary + findings table for a PR/issue. |
| `csv` | One row per `(case, round)` result (`case_id, category, endpoint, round, attempt, status, duration_ms, started, detail`) for spreadsheets / pivots. |
| `rtf` | Rich-text summary that opens directly in Word / Pages / WordPad. |
| `pdf` | Self-contained, paginated PDF (no external tooling) for archiving or sharing a printable report. |

The same run can emit all of them at once — list one `--report` per format
(CLI) or one entry per `reports[]` item (config).

### Where reports are stored

Each report goes exactly where its `path` says:

- **A file path** (e.g. `--report pdf=./var/harness.pdf` or `path: ./var/harness.pdf`)
  writes/overwrites that file. Relative paths resolve against the **current
  working directory** of the `tarpit-testharness` process; the directory must
  already exist. The example configs write under `./var/`.
- **`-` or empty** writes to **stdout** (handy for `text`/`json`/`md`; pipe it
  on). Binary-ish formats (`pdf`, `rtf`) are best given a real file path.
- **No `--report` at all** (and not `--quiet`) prints a single `text` summary to
  **stdout** — nothing is written to disk.

The machine-readable run history is separate from these report files: it is the
SQLite **results database** at `--db <path>` / `db:` (see below), which is
appended to — not overwritten — on every run.

---

## Results database

`--db <path>` appends each run to a SQLite database (auto-created) so QA can
track which tool version was tested when, against what, with what outcome —
the spec's "keep a database tracking which version of tools/units tested at what
time." Two tables: `runs` (started/finished, `tool_version`, target, seed,
rounds, per-status counts, time-bounded) and `results` (one row per case ×
round: id, category, endpoint, round, attempts, status, detail/error, duration).
`history` summarizes the most recent runs:

```
RUN   STARTED              TOOL                    TOTAL  PASS  FAIL  CRASH
2     2026-05-24 16:41:09  2.0.0 (a1b2c3d)            32    28     0      0
1     2026-05-24 16:28:35  2.0.0 (a1b2c3d)            10     6     0      0
```

For richer analysis, query the DB directly (e.g. fail rate of a case across
builds) with any SQLite client.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings (all cases passed/skipped). |
| `1` | At least one finding (`fail`/`crash`/`error`) — for CI gating. |
| `2` | Setup error (bad config, target would not start, report/DB write failed). |

---

## Cookbook

```bash
# 1. Pre-commit smoke test of a handler, fully in-process, no privileges:
tarpit-testharness run --mode module \
  --endpoint http=tcp:0:http --category unit,emulate,fuzz-smart

# 2. Spawn + manage a sensor build, full sweep, JUnit for CI, record to DB:
tarpit-testharness run \
  --binary ./bin/tarpit-honeypot --spawn-config ./configs/harness-target.yaml \
  --health-url http://127.0.0.1:8088/healthz \
  --endpoint ssh=tcp:2222:ssh --endpoint http=tcp:8000:http \
  --verify-url http://127.0.0.1:8088 \
  --report junit=harness.xml --db harness-results.db --quiet
echo "exit=$?"   # 0 clean, 1 findings, 2 setup error

# 3. Soak an external sensor for 30 minutes, restart it on a crash:
tarpit-testharness run -c harness.yaml \
  --category reliability --rounds 1000 --duration 30m \
  --restart-cmd 'systemctl restart tarpit-honeypot'

# 4. Reproduce a fuzz crash with the seed from a previous report:
tarpit-testharness run -c harness.yaml --case fuzz-dumb/http --seed 8024599 --progress

# 5. Review trend across builds:
tarpit-testharness history -db harness-results.db -n 50
```

---

## Requirements and caveats

- **Privileges / external tools.** TCP port scans and the TCP host sweep use
  ordinary `connect()` and need nothing special. The **ICMP ping sweep** shells
  out to the system `ping`, and the **ARP sweep** to `arping` (raw L2 /
  `CAP_NET_RAW`); both **skip cleanly** when the tool is missing or unprivileged.
  The optional real-`nmap` fingerprint case runs only if `nmap` is on `PATH`.
- **Module mode is `tcp`-only** and covers per-endpoint categories (`unit`,
  `emulate`, `misimpl`, `fuzz-dumb`, `fuzz-smart`, `reliability`); `scan` and
  `fingerprint` need the wire and are not generated.
- **Sweeps need `sweep_cidr`**; without it they skip. Only sweep ranges you are
  authorized to touch.
- **Security.** Prefer supplying `verify.token` via the environment / config
  rather than a shell argument (process args are world-readable). The harness is
  authorized QA tooling — point it only at honeypots you operate.

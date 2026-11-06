# Test-coverage policy

CI enforces a **per-package statement-coverage floor of 80%** via
[`scripts/check-coverage.sh`](../scripts/check-coverage.sh) (the `coverage` job
in `.github/workflows/ci.yml`). Run it locally the same way CI does:

```bash
bash scripts/check-coverage.sh          # full suite with -cover, then the gate
FLOOR=85 bash scripts/check-coverage.sh  # try a higher floor
```

## How the gate works

Every package must hit **80%** or the build fails. Two explicit, auditable
escape hatches keep that enforceable on a codebase that isn't uniformly there
yet:

- **EXCLUDE** — packages with nothing meaningful to unit-test in CI: the two
  command `main`s (`cmd/tarpit-honeypot`, `cmd/tarpit-testharness`, exercised
  end-to-end) and `internal/store/pgstore` (the PostgreSQL backend, which needs
  a live database). These are skipped with the reason printed.
- **GRANDFATHER** — packages below the floor *today*, each pinned a little under
  its current level (headroom for run-to-run variance in the integration-driven
  packages). The gate passes now, **blocks any regression** below the pinned
  level, and enforces the full 80% on every other package. The list is tracked
  debt to burn down: raise a package's tests past 80%, then delete its line from
  the `GRANDFATHER` map in the script, and the gate holds it to the full floor.
  The gate prints a reminder when a grandfathered package has quietly climbed
  past 80% so it can be promoted.

Never raise a grandfathered number to make a regression pass — fix the tests.

## Burn-down list (packages below the 80% floor)

Sorted worst-first. Networking / root / hardware / live-infra packages are
hardest and are lower priority; the pure-Go logic packages are the best next
targets. The closest wins are the packages already in the high-70s.

| Package | Pin | Notes |
|---|---|---|
| `internal/privdrop` | 3 | setuid/capability drop — needs root; test the arg/parse paths |
| `internal/canary` | 4 | file/URL/DNS canary tripwires — core feature, very under-tested |
| `internal/tunnet` | 17 | userspace TUN networking |
| `internal/sandbox` | 29 | landlock/seccomp — platform-gated |
| `internal/retention` | 29 | DB prune/rotate scheduling |
| `internal/listener` | 32 | TCP/UDP accept loops — needs sockets |
| `internal/honeynet` | 32 | virtual-host topology |
| `internal/sink` | 33 | egress sinks — needs httptest coverage of each type |
| `internal/sniffer` | 34 | AF_PACKET L2 capture — needs CAP_NET_RAW |
| `internal/identity` | 34 | deployment identity derivation — pure Go, good target |
| `internal/cli` | 35 | subcommand surface — good target (table-driven) |
| `internal/config` | 44 | YAML load + validation — good target |
| `internal/dnscanary` | 49 | DNS canary responder |
| `internal/intel` | 63 | fleet intel feed |
| `internal/sensor` | 64 | the orchestrator; large, wires everything (now ~66%, up from ~33%) |
| `internal/archetype` | 68 | device/OS archetypes — close |
| `internal/artifactscan` | 68 | YARA-ish artifact scan — close |
| `internal/detect` | 69 | declarative detection rules |
| `internal/event` | 70 | event model helpers |
| `internal/fakefiles` | 70 | synthetic filesystem content |
| `internal/shell` | 71 | emulated-shell loot |
| `internal/ui` | 71 | web UI handlers — integration-heavy |
| `internal/listener/handler` | 75 | protocol handlers — integration-heavy |

Recently promoted to the full 80% floor (removed from `GRANDFATHER`):
`internal/format` (98.1%), `internal/misp` (97.4%), `internal/feeds` (94.8%),
`internal/egress` (88.1%), `internal/p0f` (87.0%), `internal/store` (80.7%).

Of what remains, `internal/listener/handler` is the closest near-floor target;
the pure-Go logic packages (`identity`, `cli`, `config`, `event`, `archetype`,
`artifactscan`, `detect`, `shell`) are the best next wins, while the
root/hardware/live-infra packages (`privdrop`, `sniffer`, `tunnet`, `sandbox`,
`listener`) are hardest and lower priority.

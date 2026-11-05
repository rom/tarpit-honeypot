# Test-coverage policy

CI enforces a **per-package statement-coverage floor of 70%** via
[`scripts/check-coverage.sh`](../scripts/check-coverage.sh) (the `coverage` job
in `.github/workflows/ci.yml`). Run it locally the same way CI does:

```bash
bash scripts/check-coverage.sh          # full suite with -cover, then the gate
FLOOR=75 bash scripts/check-coverage.sh  # try a higher floor
```

## How the gate works

Every package must hit **70%** or the build fails. Two explicit, auditable
escape hatches keep that enforceable on a codebase that isn't uniformly there
yet:

- **EXCLUDE** — packages with nothing meaningful to unit-test in CI: the two
  command `main`s (`cmd/tarpit-honeypot`, `cmd/tarpit-testharness`, exercised
  end-to-end) and `internal/store/pgstore` (the PostgreSQL backend, which needs
  a live database). These are skipped with the reason printed.
- **GRANDFATHER** — packages below the floor *today*, each pinned to its current
  level. The gate passes now, **blocks any regression** below the pinned level,
  and enforces the full 70% on every other package. The list is tracked debt to
  burn down: raise a package's tests past 70%, then delete its line from the
  `GRANDFATHER` map in the script, and the gate holds it to the full floor. The
  gate prints a reminder when a grandfathered package has quietly climbed past
  70% so it can be promoted.

Never raise a grandfathered number to make a regression pass — fix the tests.

## Burn-down list (packages below the 70% floor)

As of the gate's introduction, sorted worst-first. Networking / root /
hardware / live-infra packages are hardest and are lower priority; the pure-Go
logic packages are the best next targets.

| Package | Coverage | Notes |
|---|---|---|
| `internal/privdrop` | ~4% | setuid/capability drop — needs root; test the arg/parse paths |
| `internal/canary` | ~5% | file/URL/DNS canary tripwires — core feature, very under-tested |
| `internal/tunnet` | ~17% | userspace TUN networking |
| `internal/sandbox` | ~29% | landlock/seccomp — platform-gated |
| `internal/retention` | ~30% | DB prune/rotate scheduling |
| `internal/sensor` | ~31% | the orchestrator; large, wires everything |
| `internal/listener` | ~32% | TCP/UDP accept loops — needs sockets |
| `internal/honeynet` | ~33% | virtual-host topology |
| `internal/sink` | ~34% | egress sinks — needs httptest coverage of each type |
| `internal/sniffer` | ~34% | AF_PACKET L2 capture — needs CAP_NET_RAW |
| `internal/identity` | ~34% | deployment identity derivation — pure Go, good next target |
| `internal/cli` | ~35% | subcommand surface — good next target (table-driven) |
| `internal/config` | ~45% | YAML load + validation — good next target |
| `internal/dnscanary` | ~49% | DNS canary responder |
| `internal/intel` | ~63% | fleet intel feed |
| `internal/artifactscan` | ~69% | YARA-ish artifact scan — close |
| `internal/archetype` | ~69% | device/OS archetypes — close |

The closest wins (`internal/archetype`, `internal/artifactscan`, and the pure-Go
`internal/identity` / `internal/config` / `internal/cli`) are the recommended
first targets.

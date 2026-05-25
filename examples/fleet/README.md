# Fleet topology examples

A worked multi-tier fleet, smallest to largest. Each node is the same binary in
a different role; a node can play several roles at once.

```
   leaf-sensor ─┐
   leaf-sensor ─┤ forward (full)      ┌─ rollup ─┐
   leaf-sensor ─┴──────────────►  site-aggregator ──────────►  global-hub
        ▲  intel feed (down)          │  (ingest +            │  (ingest +
        └─────────────────────────────┘   fleet + IOC +        │   fleet + IOC +
                                           intel serve +        │   MISP + STIX/
                                           trust + UI)          │   TAXII + SIEM)
```

| File | Role | Key features |
|------|------|--------------|
| `leaf-sensor.yaml` | Tier 1 — edge decoy | listeners, `egress.enforce`, `forward:` (full), `intel_feed:` subscribe |
| `site-aggregator.yaml` | Tier 2 — site collector | `ingest:` + `trust:`, `fleet:` + `serve_intel`, `ioc:`, `forward: rollup` up, UI |
| `global-hub.yaml` | Tier 3 — global | `ingest:`, wide `fleet:`, `ioc:`, `misp:` push, STIX/TAXII serve, CEF→SIEM |

## Run

Each node reads its secrets from the environment (never the file), then:

```
tarpit-honeypot validate-config -c examples/fleet/<file>.yaml
tarpit-honeypot run -c examples/fleet/<file>.yaml
```

- Tokens: a leaf's `TARPIT_FWD_TOKEN` must equal the aggregator's
  `TARPIT_INGEST_TOKEN`; the aggregator's `TARPIT_FWD_TOKEN` must equal the hub's
  `TARPIT_INGEST_TOKEN`.
- The downward intel feed + STIX/TAXII are served on the same authenticated
  ingest endpoint (`/intel`, `/intel/stix`, `/taxii2/`).
- `tarpit-honeypot list-fleet-rules` prints the cross-sensor detector catalog;
  `tarpit-honeypot export-iocs` dumps the IOC store (STIX/CSV/txt/JSON).

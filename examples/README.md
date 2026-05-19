# Examples

Four reference deployments that exercise different parts of the tool.
Each YAML is a **complete, valid config** — copy, edit, validate:

```
tarpit-honeypot validate-config -c examples/<file>.yaml
```

| File | Scenario |
|---|---|
| [`edge-corp-network.yaml`](edge-corp-network.yaml) | Corporate edge — IT honeypots + AD-style honeynet, SIEM via syslog/CEF, web UI on loopback, retention. |
| [`raspberry-pi-zero.yaml`](raspberry-pi-zero.yaml) | Minimal embedded sensor: tripwire-only listeners, no UI, no SQLite, jsonlog + webhook only. |
| [`ot-substation.yaml`](ot-substation.yaml) | OT / ICS focus — Modbus / S7 / IEC-104 / BACnet, port-scan correlator tuned tight, SNMP-trap to NMS. |
| [`siem-integration.yaml`](siem-integration.yaml) | Output-format showcase: same events to JSON, CEF (ArcSight), LEEF (QRadar), OCSF (Snowflake) sinks. |

The base [`configs/tarpit-honeypot.example.yaml`](../configs/tarpit-honeypot.example.yaml) is the "everything turned on" reference; the examples here pick subsets for specific deployment shapes.

## Verifying any example

```
./bin/tarpit-honeypot validate-config -c examples/edge-corp-network.yaml
# config OK: ...

./bin/tarpit-honeypot show-config    -c examples/edge-corp-network.yaml | less
# the post-defaults effective config (secrets stay as env-var names)

./bin/tarpit-honeypot run --dry-run  -c examples/edge-corp-network.yaml
# config valid, sensor constructed, listeners not bound
```

## Combining via conf.d

The base file can stay generic and per-deployment overrides live in `conf.d/`:

```
/etc/tarpit-honeypot/
├── config.yaml                          # examples/edge-corp-network.yaml
└── conf.d/
    ├── 01-site-name.yaml                # sensor.name + sensor.deployment_id
    ├── 50-secrets-environment.yaml      # env var references for this site
    └── 90-emergency-silence.yaml        # temporarily raise min_severity
```

`conf.d/*.yaml` are deep-merged over the base in lexical order at load time.

# Examples

Reference deployments that exercise different parts of the tool.
Each YAML is a **complete, valid config** — copy, edit, validate:

```
tarpit-honeypot validate-config -c examples/<path>.yaml
```

For an extensive walkthrough of every example (what it models, how to adapt
it, how to combine them), see [`EXAMPLES.md`](EXAMPLES.md).

### IT — office, DMZ & data center

| Path | Scenario |
|---|---|
| [`office-network.yaml`](office-network.yaml) | Office LAN: server room + per-floor printers + ~20 workstations (large honeynet). |
| [`enterprise-dmz.yaml`](enterprise-dmz.yaml) | Internet DMZ of a few larger corporations (bank / SaaS / manufacturer — 3 honeynets). |
| [`smb-dmz.yaml`](smb-dmz.yaml) | Internet DMZ of a few small businesses (NAS / cameras / RDP / router exposed — 4 honeynets). |
| [`datacenter-server-farm.yaml`](datacenter-server-farm.yaml) | Multi-tier server farm, ~35 hosts across two honeynets (the large-honeynet reference). |
| [`university-classroom.yaml`](university-classroom.yaml) | University CS teaching lab: ~30 student/instructor machines + lab infra (large honeynet). |

### OT / Purdue model + edge

| Path | Scenario |
|---|---|
| [`it-ot-dmz/manufacturing-idmz.yaml`](it-ot-dmz/manufacturing-idmz.yaml) | Full IT/OT DMZ (level 3.5): jump hosts, patch/AV, historian, OPC-UA/MQTT broker, FW mgmt. |
| [`ot-dmz/dmz-historian-fileserver-jumphosts.yaml`](ot-dmz/dmz-historian-fileserver-jumphosts.yaml) | Simpler IDMZ: replica historian, file transfer, RDP/SSH jump hosts. |
| [`ot-cell/single-plc.yaml`](ot-cell/single-plc.yaml) | Simple single PLC (Siemens S7-1500) on its real control ports. |
| [`ot-client-network/operator-and-engineering-ws.yaml`](ot-client-network/operator-and-engineering-ws.yaml) | Operator HMI workstations + one engineering workstation. |
| [`ot-server-network/historian-appservers-ad-fileserver.yaml`](ot-server-network/historian-appservers-ad-fileserver.yaml) | Historian (SQL), app servers, OT-AD DC, file server. |
| [`edge/mikrotik-router.yaml`](edge/mikrotik-router.yaml) | MikroTik RouterOS edge-router decoy. |
| [`edge/teltonika-rut240.yaml`](edge/teltonika-rut240.yaml) | Teltonika RUT240 industrial LTE-router decoy. |

### Broad reference deployments

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

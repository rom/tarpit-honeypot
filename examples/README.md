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
| [`devops-stack.yaml`](devops-stack.yaml) | Cloud-native tooling: git/CI/containers/queues/caches/search role bundles + unauth Grafana/Prometheus/Jupyter/Consul/CouchDB/ClickHouse Lua decoys. |
| [`data-platform.yaml`](data-platform.yaml) | Big-data/secrets/logging: Cassandra/Kafka/ZooKeeper/NATS/NFS roles + Vault/etcd/Kibana/Solr/MinIO/RabbitMQ Lua decoys. |
| [`app-platform.yaml`](app-platform.yaml) | App/build/container tier: tomcatserver (AJP13) + erlangcluster (epmd) + k8s/registry/objectstore roles + Jenkins/GitLab/SonarQube/Keycloak/Traefik Lua decoys. |
| [`mobile-iot-fleet.yaml`](mobile-iot-fleet.yaml) | Android/IoT fleet: exposed ADB (5555) + androidadb role + Raspberry Pi/OpenWrt/Huawei honeynet. |
| [`cloud-virtualization.yaml`](cloud-virtualization.yaml) | Virtualization mgmt plane: ESXi/Proxmox/TrueNAS + macOS + Juniper/PAN/F5/SonicWall appliances. |
| [`legacy-unix.yaml`](legacy-unix.yaml) | Solaris / AIX / Gentoo big-iron + NFS/portmapper honeynet (TTL 255). |
| [`telecom-edge.yaml`](telecom-edge.yaml) | ISP/carrier edge: Arista/VyOS/OpenWrt gear + VPN-gateway/RADIUS/NTP roles. |
| [`network-aaa-edge.yaml`](network-aaa-edge.yaml) | Network control plane: TACACS+/RADIUS (aaaserver) + SQL Browser (sqlserver) + Huawei/Zyxel/DrayTek/NetScaler/Sophos honeynet. |
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
| [`ot-safety-dcs.yaml`](ot-safety-dcs.yaml) | OT safety + DCS — Triconex/HIMA SIS + Yokogawa/Emerson DCS + Ignition/WinCC/CODESYS decoys; plc_program_download / ics_mode_change / ot_kill_chain. |
| [`ot-power-grid.yaml`](ot-power-grid.yaml) | OT power grid — SEL relays (IEC 61850 MMS / DNP3 / IEC-104) + SMA/GE + relay/historian/inverter web decoys. |
| [`ot-discrete-mfg.yaml`](ot-discrete-mfg.yaml) | OT discrete mfg / fab — fins_tcp / secs_gem / pcom / wdbrpc + Omron/Rockwell/Unitronics/VxWorks roles + HMI decoys. |
| [`datacenter-oob.yaml`](datacenter-oob.yaml) | Out-of-band / lights-out plane — Supermicro/Lenovo/Cisco-UCS/ILOM/Fujitsu BMCs + console/KVM roles + BMC web decoys (oob_mgmt_access). |
| [`remote-access-gateway.yaml`](remote-access-gateway.yaml) | Remote-access exposure — RDP/VNC + Radmin/DameWare/pcAnywhere/PCoIP/ARD + Guacamole/ScreenConnect (remote_tool_sweep). |
| [`legacy-rservices-mainframe.yaml`](legacy-rservices-mainframe.yaml) | Legacy cleartext access — rexec/rsh + TN3270 mainframe + console/PDU mgmt (remote_exec_command / oob_mgmt_access). |
| [`voip-pbx.yaml`](voip-pbx.yaml) | VoIP PBX — Asterisk/FreePBX SIP/AMI/IAX2 + pbxserver/voicemail roles + FreePBX/FusionPBX/VICIdial decoys (toll_fraud / pbx_control). |
| [`enterprise-telephony.yaml`](enterprise-telephony.yaml) | Enterprise UC — Cisco/Avaya/Mitel SCCP/H.323/SIP + callmanager/unifiedcomms roles + phone honeynet (voip_enum). |
| [`voip-edge-sbc.yaml`](voip-edge-sbc.yaml) | VoIP carrier edge — Ribbon/AudioCodes SBC/gateways + IP phones + sbc/voipgateway/ipphone roles. |
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

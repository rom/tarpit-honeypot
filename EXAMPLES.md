# Example configurations

This document walks through every shipped example config — what it models,
why it's shaped that way, and how to adapt it. Every file is a **complete,
valid config**: validate before you run.

```sh
tarpit-honeypot validate-config -c examples/<path>.yaml   # parse + check
tarpit-honeypot show-config     -c examples/<path>.yaml   # effective config
tarpit-honeypot run --dry-run   -c examples/<path>.yaml   # build, don't bind
```

The examples live in categorized subdirectories under [`examples/`](examples/);
a few broad reference deployments remain at the top level. The base
[`configs/tarpit-honeypot.example.yaml`](configs/tarpit-honeypot.example.yaml)
is the "everything turned on" reference.

| Category | File | Scenario |
|---|---|---|
| OT cell | [`examples/ot-cell/single-plc.yaml`](examples/ot-cell/single-plc.yaml) | One Siemens S7-1500-class PLC on its real control ports. |
| OT client net | [`examples/ot-client-network/operator-and-engineering-ws.yaml`](examples/ot-client-network/operator-and-engineering-ws.yaml) | Operator HMI workstations + one engineering workstation. |
| OT server net | [`examples/ot-server-network/historian-appservers-ad-fileserver.yaml`](examples/ot-server-network/historian-appservers-ad-fileserver.yaml) | Historian (SQL), app servers, OT-AD DC, file server. |
| OT DMZ | [`examples/ot-dmz/dmz-historian-fileserver-jumphosts.yaml`](examples/ot-dmz/dmz-historian-fileserver-jumphosts.yaml) | IDMZ: replica historian, file transfer, RDP/SSH jump hosts. |
| Edge | [`examples/edge/mikrotik-router.yaml`](examples/edge/mikrotik-router.yaml) | MikroTik RouterOS edge router decoy. |
| Edge | [`examples/edge/teltonika-rut240.yaml`](examples/edge/teltonika-rut240.yaml) | Teltonika RUT240 industrial LTE router decoy. |
| IT edge | [`examples/edge-corp-network.yaml`](examples/edge-corp-network.yaml) | Corporate edge: IT honeypots + AD honeynet + SIEM. |
| Minimal | [`examples/raspberry-pi-zero.yaml`](examples/raspberry-pi-zero.yaml) | Tripwire-only embedded sensor (no UI/SQLite). |
| OT (flat) | [`examples/ot-substation.yaml`](examples/ot-substation.yaml) | Flat ICS segment: Modbus/S7/IEC-104/BACnet. |
| SIEM | [`examples/siem-integration.yaml`](examples/siem-integration.yaml) | Same events to JSON/CEF/LEEF/OCSF sinks. |

---

## The Purdue model, in four configs

The four OT examples line up with the levels of a segmented OT network, so
you can deploy a decoy in each zone:

```
  Enterprise (IT)
        │
  ┌─────┴─────────────────────────────┐  examples/ot-dmz/  (level 3.5, IDMZ)
  │ replica historian · file transfer · RDP/SSH jump hosts
  └─────┬─────────────────────────────┘
  ┌─────┴─────────────────────────────┐  examples/ot-server-network/  (level 3)
  │ historian · app servers · OT-AD · file server
  └─────┬─────────────────────────────┘
  ┌─────┴─────────────────────────────┐  examples/ot-client-network/  (level 2)
  │ operator workstations · engineering workstation
  └─────┬─────────────────────────────┘
  ┌─────┴─────────────────────────────┐  examples/ot-cell/  (levels 0–1)
  │ PLCs / RTUs / field devices
  └───────────────────────────────────┘
```

Common thread: OT networks have almost no scan baseline, so every example
tunes the correlators tight (`port_scan.distinct_ports` of 2–4) and treats
external touches as incidents. Adjust `allowlist` to your known-good
management subnets so legitimate engineering traffic doesn't alert.

---

## OT cell — single PLC

[`examples/ot-cell/single-plc.yaml`](examples/ot-cell/single-plc.yaml)

The smallest useful OT decoy. The sensor *is* a Siemens S7-1500-class PLC
(`archetype: siemens-s7-1500`) exposed on its real ports: S7comm-Plus
(102), Modbus (502), the device web server (80), SNMP (161), and a dropped
PROFINET-RT port (34964). A real PLC only talks to its engineering
workstation and SCADA, so the `port_scan` correlator trips at 2 distinct
ports and brute force at 3 attempts. Put the engineering workstation's IP
in `allowlist`.

**Adapt:** change the archetype to `siemens-s7-1200` or drop in the
relevant ICS handlers for a different vendor (`dnp3`, `iec104`, `ge_srtp`,
`codesys`, `ethernetip`). Set `sensor.interfaces: [<iface>]` to bind to the
cell-facing NIC.

## OT client network — operator + engineering workstations

[`examples/ot-client-network/operator-and-engineering-ws.yaml`](examples/ot-client-network/operator-and-engineering-ws.yaml)

A honeynet of four operator HMI workstations (`windows-10`/`windows-11`,
RDP + SMB) and one engineering workstation (`windows-server-2019`, RDP +
SMB + WinRM + SSH — the box that programs the controllers and is the crown
jewel). The honeynet's ARP + ICMP responders make the virtual hosts answer
`arp-scan` and ping; each virtual IP+port dispatches to its own handler
instance with a deployment-unique identity. Lateral RDP/SMB between
workstations is exactly what you want to catch.

**Adapt:** add/remove operator hosts under `honeynets[].hosts`; the
top-level `listeners` set just needs to cover the union of ports the hosts
use. Point `allowlist` at the SCADA server tier north of the clients.

## OT server network — historian, app servers, OT-AD, file server

[`examples/ot-server-network/historian-appservers-ad-fileserver.yaml`](examples/ot-server-network/historian-appservers-ad-fileserver.yaml)

The level-3 server tier: an OT-side Active Directory DC
(`archetype: active-directory` — Kerberos/LDAP/SMB/DCE-RPC/WinRM/RDP/DNS),
a process historian (`mssql` on 1433 + web), two SCADA/batch application
servers, and a file server (`smb` + `ftp`). `vuln_emulation: true` because
OT servers are notoriously unpatched — banner-aware handlers advertise the
archetype's unpatched versions so a version scanner records exploitable
boxes (the services never become actually exploitable). Events `>=high`
forward to a CEF syslog SIEM.

**Adapt:** the historian is the highest-value target — keep its
`severity: critical`. Swap the DC archetype aliases (`domain-controller`,
`windows-server-2019-dc`) freely. The `allowlist: [192.0.2.0/24]` treats
intra-tier traffic as expected and alerts on outsiders; tighten or remove
it per your segmentation.

## OT DMZ (IDMZ) — historian replica, file transfer, jump hosts

[`examples/ot-dmz/dmz-historian-fileserver-jumphosts.yaml`](examples/ot-dmz/dmz-historian-fileserver-jumphosts.yaml)

The brokered level-3.5 zone between IT and OT. Models the canonical IDMZ
hosts: two RDP/SSH **jump servers** (the only sanctioned path into OT and
the attacker's favourite target), a forward/replica **historian** readable
from the enterprise, and a **file-transfer** server (patches in, reports
out). `session_recording: true` captures asciinema casts of what attackers
do on the jump hosts (the SSH jump uses `ssh_interactive`, and the file
server uses `ftp_files` to serve bait files). Retrieve the recordings + the
per-connection pcaps from the web UI (`/download?source=<ip>`).

**Adapt:** this is the most exposed zone — keep brute-force thresholds low.
Add more jump hosts under `honeynets[].hosts`. Forward to your enterprise
SIEM, not the OT one.

## Edge devices — MikroTik & Teltonika

[`examples/edge/mikrotik-router.yaml`](examples/edge/mikrotik-router.yaml) ·
[`examples/edge/teltonika-rut240.yaml`](examples/edge/teltonika-rut240.yaml)

Internet-/remote-site-facing edge hardware, which is relentlessly scanned
and botnet-recruited. The MikroTik decoy presents the full RouterOS
fingerprint (`SSH-2.0-ROSSSH`, webfig, Winbox 8291 + API 8728, MikroTik
SNMP OID) and routes SSH/Telnet to the RouterOS CLI emulator so login
attempts and `/system`/`/export` commands are captured. The Teltonika
decoy presents RutOS (Dropbear SSH, lighttpd, Teltonika SNMP). Both enable
tighter brute-force thresholds appropriate to the constant edge noise.

**Adapt:** these are single-archetype sensors (no honeynet) — the simplest
shape. Add `sensor.interfaces: [<wan-iface>]` to pin to the WAN NIC.

---

## Top-level reference deployments

- **[`examples/edge-corp-network.yaml`](examples/edge-corp-network.yaml)** —
  corporate edge: IT honeypots (SSH/HTTP/RDP/SMB), an AD-style honeynet,
  syslog/CEF to a SIEM, loopback web UI, retention tuned for IT.
- **[`examples/raspberry-pi-zero.yaml`](examples/raspberry-pi-zero.yaml)** —
  minimal embedded sensor: tripwire-only listeners, no UI, no SQLite,
  jsonlog + webhook only. For an ARMv6 Pi Zero or other tiny node.
- **[`examples/ot-substation.yaml`](examples/ot-substation.yaml)** — a flat
  ICS segment (Modbus/S7/IEC-104/EtherNet-IP/OPC-UA/BACnet) with the
  port-scan correlator tuned tight and an SNMP-trap channel to an NMS.
- **[`examples/siem-integration.yaml`](examples/siem-integration.yaml)** —
  output-format showcase: the same events to JSON, CEF (ArcSight), LEEF
  (QRadar), and OCSF (Snowflake) sinks.

---

## Combining and adapting examples

**Multiple files (combine).** Pass `-c` more than once and the files are
combined — every listener / honeynet / host across all files is used, while
scalar config (`sensor.*`, `ui`, …) takes the last file's value:

```sh
tarpit-honeypot run \
  -c examples/ot-server-network/historian-appservers-ad-fileserver.yaml \
  -c examples/ot-dmz/dmz-historian-fileserver-jumphosts.yaml
```

(Mind overlapping listener ports if you combine configs that both bind the
same port — validation rejects duplicates.)

**conf.d overrides (one config).** Keep a base file generic and put
per-site overrides in a sibling `conf.d/`; they deep-merge over the base in
lexical order (lists are replaced, not appended):

```
/etc/tarpit-honeypot/
├── config.yaml                  # one of the examples
└── conf.d/
    ├── 01-site.yaml             # sensor.name / deployment_id / interfaces
    ├── 50-secrets.yaml          # *_env references for this site
    └── 90-silence.yaml          # temporarily raise min_severity
```

**Network interface.** Set `sensor.interfaces: [eth0]` (or
`-i eth0` / `--interface eth0`, repeatable) to choose the NIC the sensor
uses: it pins wildcard listener binds to that interface's IP and is the
default interface for the AF_PACKET layer (sniffer + ARP/ICMP/LLDP/PROFINET
responders).

**`--set` / env.** One-off overrides without editing files:

```sh
tarpit-honeypot run -c examples/ot-cell/single-plc.yaml \
  --set sensor.name=plc-cellB --set ui.enabled=false
TARPIT_SENSOR_NAME=plc-cellB tarpit-honeypot run -c examples/ot-cell/single-plc.yaml
```

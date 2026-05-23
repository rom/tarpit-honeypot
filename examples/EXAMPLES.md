# Example configurations

This document walks through every shipped example config — what it models,
why it's shaped that way, and how to adapt it. Every file is a **complete,
valid config**: validate before you run. (Commands are written to be run
from the repository root.)

```sh
tarpit-honeypot validate-config -c examples/<path>.yaml   # parse + check
tarpit-honeypot show-config     -c examples/<path>.yaml   # effective config
tarpit-honeypot run --dry-run   -c examples/<path>.yaml   # build, don't bind
```

The examples live here in [`examples/`](.) (a short index is in
[`README.md`](README.md)); the base
[`../configs/tarpit-honeypot.example.yaml`](../configs/tarpit-honeypot.example.yaml)
is the "everything turned on" reference.

| Category | File | Scenario |
|---|---|---|
| Office IT | [`office-network.yaml`](office-network.yaml) | Office LAN: server room + per-floor printers + ~20 workstations (large honeynet). |
| Internet DMZ | [`enterprise-dmz.yaml`](enterprise-dmz.yaml) | A few larger corporations' public edge (3 honeynets: bank / SaaS / manufacturer). |
| Internet DMZ | [`smb-dmz.yaml`](smb-dmz.yaml) | A few small businesses' edge (4 honeynets: NAS/cameras/RDP/router exposed). |
| Data center | [`datacenter-server-farm.yaml`](datacenter-server-farm.yaml) | Multi-tier server farm — ~35 hosts across two honeynets (the large-honeynet reference). |
| DevOps | [`devops-stack.yaml`](devops-stack.yaml) | Cloud-native tooling: git/CI/containers/queues/caches/search role bundles + unauth dashboards (Grafana/Prometheus/Jupyter/Consul/CouchDB/ClickHouse). |
| Data platform | [`data-platform.yaml`](data-platform.yaml) | Big-data/secrets/logging: Cassandra/Kafka/ZooKeeper/NATS/NFS roles + Vault/etcd/Kibana/Solr/MinIO/RabbitMQ Lua decoys. |
| Cloud infra | [`cloud-virtualization.yaml`](cloud-virtualization.yaml) | Virtualization mgmt plane: ESXi/Proxmox/TrueNAS + macOS + Juniper/PAN/F5/SonicWall appliances. |
| Legacy Unix | [`legacy-unix.yaml`](legacy-unix.yaml) | Solaris / AIX / Gentoo big-iron + NFS/portmapper (TTL 255, telnet/finger/rpcbind). |
| Telecom edge | [`telecom-edge.yaml`](telecom-edge.yaml) | ISP/carrier edge: Arista/VyOS/OpenWrt gear + VPN-gateway/RADIUS/NTP roles (IKE/PPTP/BGP). |
| Education | [`university-classroom.yaml`](university-classroom.yaml) | University CS teaching lab: ~30 student/instructor machines + lab infra. |
| IT/OT DMZ | [`it-ot-dmz/manufacturing-idmz.yaml`](it-ot-dmz/manufacturing-idmz.yaml) | Full IDMZ (Purdue 3.5): jump hosts, patch/AV, historian, OPC-UA/MQTT broker, FW mgmt. |
| OT DMZ | [`ot-dmz/dmz-historian-fileserver-jumphosts.yaml`](ot-dmz/dmz-historian-fileserver-jumphosts.yaml) | Simpler IDMZ: replica historian, file transfer, RDP/SSH jump hosts. |
| OT cell | [`ot-cell/single-plc.yaml`](ot-cell/single-plc.yaml) | One Siemens S7-1500-class PLC on its real control ports. |
| OT client net | [`ot-client-network/operator-and-engineering-ws.yaml`](ot-client-network/operator-and-engineering-ws.yaml) | Operator HMI workstations + one engineering workstation. |
| OT server net | [`ot-server-network/historian-appservers-ad-fileserver.yaml`](ot-server-network/historian-appservers-ad-fileserver.yaml) | Historian (SQL), app servers, OT-AD DC, file server. |
| Edge | [`edge/mikrotik-router.yaml`](edge/mikrotik-router.yaml) | MikroTik RouterOS edge router decoy. |
| Edge | [`edge/teltonika-rut240.yaml`](edge/teltonika-rut240.yaml) | Teltonika RUT240 industrial LTE router decoy. |
| IT edge | [`edge-corp-network.yaml`](edge-corp-network.yaml) | Corporate edge: IT honeypots + AD honeynet + SIEM. |
| Minimal | [`raspberry-pi-zero.yaml`](raspberry-pi-zero.yaml) | Tripwire-only embedded sensor (no UI/SQLite). |
| OT (flat) | [`ot-substation.yaml`](ot-substation.yaml) | Flat ICS segment: Modbus/S7/IEC-104/BACnet. |
| SIEM | [`siem-integration.yaml`](siem-integration.yaml) | Same events to JSON/CEF/LEEF/OCSF sinks. |

---

## Honeynet sizes — single, multi, and large

These examples deliberately span the honeynet shapes:

- **Single-archetype, no honeynet** — the sensor *is* one device
  ([`edge/mikrotik-router.yaml`](edge/mikrotik-router.yaml),
  [`ot-cell/single-plc.yaml`](ot-cell/single-plc.yaml)). Simplest to deploy.
- **One small honeynet** — a handful of virtual hosts
  ([`edge-corp-network.yaml`](edge-corp-network.yaml),
  [`ot-dmz/...`](ot-dmz/dmz-historian-fileserver-jumphosts.yaml)).
- **Several honeynets in one sensor** — model *a few* organisations or
  network segments side by side, each its own CIDR/domain
  ([`enterprise-dmz.yaml`](enterprise-dmz.yaml) — 3 corporate edges;
  [`smb-dmz.yaml`](smb-dmz.yaml) — 4 small businesses;
  [`datacenter-server-farm.yaml`](datacenter-server-farm.yaml) — app + data tiers).
- **Large honeynets** — many virtual hosts in one network
  ([`office-network.yaml`](office-network.yaml) ~20 workstations + infra;
  [`university-classroom.yaml`](university-classroom.yaml) ~30 lab machines;
  [`datacenter-server-farm.yaml`](datacenter-server-farm.yaml) ~35 servers).

The pattern is always the same: the top-level `listeners` set is the
**union of the service ports** the virtual hosts expose; the honeynet then
dispatches each virtual IP+port to its own handler instance with a
deployment-unique identity (so every workstation gets its own SMB key,
every printer its own serial, every web server its own TLS cert). Add or
remove hosts under `honeynets[].hosts` freely — only add a new top-level
listener when a host introduces a port not already covered.

To actually receive traffic for the virtual IPs, route the honeynet CIDR to
the sensor: per-IP `ip addr add`, a bridge/NAT rule, or the Linux **TUN
adapter** (`honeynets[].tun.enabled`), whose embedded userspace TCP stack
completes fingerprint-shaped handshakes for each host's ports without a
socket per IP (see [`../docs/tcp-stack.md`](../docs/tcp-stack.md)).

---

## Office & enterprise IT

### Office LAN — workstations, printers, server room

[`office-network.yaml`](office-network.yaml)

A medium business's internal network as one large honeynet: a server room
(AD DC, file/intranet/ERP/backup servers, a VoIP PBX), four per-floor
multi-function printers (HP / Brother / Xerox / Lexmark, each a coherent
PJL/IPP/LPD/SNMP device), and ~20 employee workstations — Windows
desktops/laptops on RDP+SMB, IT staff with WinRM, and a few Linux/Mac dev
boxes on SSH/VNC. A real office scans almost nothing internally, so the
correlators trip early and `lateral_movement` / `host_sweep` treat
workstation-to-workstation RDP/SMB and subnet sweeps as incidents.

**Adapt:** put your real helpdesk / patch-management subnet in `allowlist`
so admin sweeps stay quiet; scale the workstation block to your headcount;
swap printer archetypes to your fleet (`tarpit-honeypot list-archetypes`).

### Internet DMZ — a few larger corporations

[`enterprise-dmz.yaml`](enterprise-dmz.yaml)

Three sizable organisations' internet edge, each its own honeynet on its own
public /24: a **bank**, a **SaaS company**, and a **manufacturer**. The
public surface is web/app servers, mail (SMTP/IMAP/POP3), authoritative
DNS, an SSH/SFTP bastion, and the SSL-VPN / remote-access appliances
attackers hammer (FortiGate, Citrix ADC, Pulse Secure). `vuln_emulation:
true` makes version scanners record juicy, "unpatched" builds — the sensor
then RECOGNISES the matching CVE exploit attempts (it's never actually
exploitable). URL canaries plant secrets no legitimate visitor knows. The
edge is scanned constantly, so the signal is in the
exploit-chain / dirbust / UA-rotation correlators, not raw port volume.

**Adapt:** add or remove corporate honeynets; the appliance hosts use the
`fortinet` / `citrix_gateway` / `pulse` *handlers* (no matching archetype
needed). Forward `>=high` to your SIEM.

### Internet DMZ — a few small businesses

[`smb-dmz.yaml`](smb-dmz.yaml)

Small businesses rarely have a real DMZ — their edge is whatever the ISP
router forwards. Four small shops (a law firm, a dental clinic, an
e-commerce shop, an accounting firm), each a small honeynet, expose the
surface SMBs typically *and accidentally* publish: a website + mail, plus
the classic mistakes — a **NAS** (Synology/QNAP) reachable from outside, an
**IP camera** (Hikvision/Axis), **RDP** left open, and the **router's** own
admin UI (MikroTik/pfSense). That misconfigured surface is exactly what
mass scanners and ransomware crews hunt. Alerts go to a chat webhook.

**Adapt:** point the webhook at your Slack/Teams/chatops endpoint (set
`TARPIT_WEBHOOK_SECRET`); add shops as more `/28` honeynets.

### Data-center server farm — the large-honeynet reference

[`datacenter-server-farm.yaml`](datacenter-server-farm.yaml)

A deliberately BIG estate (~35 virtual servers across two honeynets) for
testing at scale and for dense decoy deployments. An **application tier**
(load balancers, web/app servers, Redis/memcached caches, Docker API hosts)
and a **data + management tier** (MySQL/Postgres/MSSQL, Elasticsearch /
MongoDB, NAS, ESXi hypervisors, iDRAC/iLO lights-out, a bastion). A real
farm has a tight, known management plane, so cross-tier scans, data-store
access from outside the app tier, and bastion brute force are the tells —
`lateral_movement` / `data_access` / `exfil` / `service_sweep` are tuned for
that. Watch the `/topology` map render the farm and the devices tab fill in.

**Adapt:** the densest example — duplicate the host rows to grow it further;
keep the management plane in `allowlist`.

### DevOps / cloud-native tooling

[`devops-stack.yaml`](devops-stack.yaml)

The internal tooling tier attackers pivot to after a foothold: source
control, CI, container orchestration (Docker API / Kubernetes), message
queues (Kafka/ZooKeeper), caches, search, and Java app servers (RMI/JDWP) —
expressed as **`archeservice` role bundles** — alongside the
unauthenticated web dashboards and data stores that are so often left open,
served by **Lua scripts** (Grafana, Prometheus, Jupyter, Consul, CouchDB,
ClickHouse). Exercises the developer/data-infra handlers and the Lua app
decoys; URL canaries plant a `prod.tfstate` and a CI secrets file.

**Adapt:** the role bundles bind dedicated loopback IPs so their shared
ports (22/80/443) don't collide — point them at routable IPs for a real
deployment, or fold them into a honeynet's `hosts`.

### Big-data / secrets / logging platform

[`data-platform.yaml`](data-platform.yaml)

The data-and-secrets tier — the crown jewels after a foothold. Role bundles
stand up a **Cassandra + Kafka + ZooKeeper** big-data stack, **NATS**
messaging, an **NFS** server (SunRPC portmapper), an **ELK** logging stack
and a **secret store**, while Lua decoys serve the unauthenticated web data
stores attackers hunt: **Vault, etcd, Kibana, Solr, MinIO/S3, RabbitMQ**.
Exercises the `cassandra` / `nats` / `rpcbind` handlers and the round-two
Lua app decoys, with the `cve_campaign` + `data_access` correlators on.

### Legacy Unix / big-iron

[`legacy-unix.yaml`](legacy-unix.yaml)

The forgotten corner: **Solaris**, **AIX** and **Gentoo** servers plus the
NFS/portmapper surface fronting old fileshares — rarely patched, still
running telnet/finger/rpcbind, fingerprinting with the classic **TTL 255**.
Showcases the Solaris/AIX/Gentoo archetypes and the SunRPC `rpcbind` handler.

### Telecom / ISP edge

[`telecom-edge.yaml`](telecom-edge.yaml)

A carrier edge: **Arista EOS** core switches, **VyOS** edge routers and
**OpenWrt** CPE, plus the subscriber-facing **VPN gateway** (IKE/PPTP/
OpenVPN), **RADIUS** and **NTP** infrastructure as role bundles — mass-
scanned for default creds and VPN CVEs. Exercises the round-two network
archetypes and the `pptp` handler, with `default_cred_sweep` on.

### Cloud / virtualization management plane

[`cloud-virtualization.yaml`](cloud-virtualization.yaml)

A honeynet of the hypervisor / storage / appliance personas a private cloud
runs: VMware **ESXi** hosts, **Proxmox** nodes, a **TrueNAS** box, a
**macOS** build agent, and the **Juniper / Palo Alto / F5 / SonicWall /
Netgear** edge appliances — each fingerprinting as itself via the cloud
archetypes. The management plane is tightly scoped, so brute force on the
hypervisor/appliance UIs and any scan are high-signal.

**Adapt:** keep your orchestration/backup plane in `allowlist`; swap
appliance archetypes to your fleet.

---

## Education

### University teaching lab / classroom

[`university-classroom.yaml`](university-classroom.yaml)

A CS teaching lab as one large honeynet: an instructor station, a course/lab
server, a coursework NAS, a lab printer, ~24 student workstations split
between a Windows lab (RDP/SMB) and a Linux lab (SSH), plus a few
Raspberry-Pi networking-lab nodes. Student subnets are *noisy* (people learn
nmap here), so this is a good place to TUNE: keep the workstation surface
realistic but trip on what isn't coursework — credential brute force,
lateral movement, and a compromised box sweeping the lab or beaconing out.

**Adapt:** put the instructor/admin VLAN in `allowlist`; if your
assignments include scanning, raise `port_scan` / `host_sweep` thresholds
(or disable them and rely on `brute_force` / `beacon` / `lateral_movement`).

---

## The Purdue model, in OT configs

The OT examples line up with the levels of a segmented OT network, so you
can deploy a decoy in each zone:

```
  Enterprise (IT)
        │
  ┌─────┴───────────────────────────┐  it-ot-dmz/  ·  ot-dmz/   (level 3.5, IDMZ)
  │ jump hosts · patch/AV · historian · OPC-UA/MQTT broker · FW mgmt
  └─────┬───────────────────────────┘
  ┌─────┴───────────────────────────┐  ot-server-network/       (level 3)
  │ historian · app servers · OT-AD · file server
  └─────┬───────────────────────────┘
  ┌─────┴───────────────────────────┐  ot-client-network/       (level 2)
  │ operator workstations · engineering workstation
  └─────┬───────────────────────────┘
  ┌─────┴───────────────────────────┐  ot-cell/                 (levels 0–1)
  │ PLCs / RTUs / field devices
  └─────────────────────────────────┘
```

Common thread: OT networks have almost no scan baseline, so every example
tunes the correlators tight (`port_scan.distinct_ports` of 2–4) and treats
external touches as incidents. Adjust `allowlist` to your known-good
management subnets so legitimate engineering traffic doesn't alert.

### IT/OT DMZ (IDMZ) — two depths

[`it-ot-dmz/manufacturing-idmz.yaml`](it-ot-dmz/manufacturing-idmz.yaml) ·
[`ot-dmz/dmz-historian-fileserver-jumphosts.yaml`](ot-dmz/dmz-historian-fileserver-jumphosts.yaml)

The brokered level-3.5 conduit between enterprise IT and the plant floor —
where, under ISA-99 / IEC-62443, *every* sanctioned IT↔OT flow is supposed
to terminate. The **simpler** `ot-dmz/` config models the canonical core:
RDP/SSH jump hosts, a replica historian, and a file-transfer server. The
**full** `it-ot-dmz/manufacturing-idmz.yaml` adds the rest of a mature
IDMZ — patch/WSUS + AV-update staging, an OPC-UA aggregator + MQTT broker
(the live process-data conduit that makes this an *OT* DMZ rather than a
plain IT one), a reverse proxy publishing HMI dashboards, a vendor
remote-access broker, and the boundary firewall's own management UI. The
IDMZ is the attacker's stepping stone toward the process, so brute force on
the broker hosts and any scan are high-signal; `session_recording` captures
what they do on the interactive hosts.

**Adapt:** this is the most exposed OT-adjacent zone — keep brute-force
thresholds low and forward to the **enterprise** SIEM (not the OT one).

### OT cell — single PLC

[`ot-cell/single-plc.yaml`](ot-cell/single-plc.yaml)

The smallest useful OT decoy. The sensor *is* a Siemens S7-1500-class PLC
(`archetype: siemens-s7-1500`) on its real ports: S7comm-Plus (102), Modbus
(502), the device web server (80), SNMP (161), and a dropped PROFINET-RT
port (34964). A real PLC only talks to its engineering workstation and
SCADA, so `port_scan` trips at 2 ports and brute force at 3 attempts. Put
the engineering workstation's IP in `allowlist`.

**Adapt:** change the archetype to `siemens-s7-1200` or drop in another
vendor's ICS handlers (`dnp3`, `iec104`, `ge_srtp`, `codesys`,
`ethernetip`). Set `sensor.interfaces: [<iface>]` to bind the cell NIC.

### OT client network — operator + engineering workstations

[`ot-client-network/operator-and-engineering-ws.yaml`](ot-client-network/operator-and-engineering-ws.yaml)

A honeynet of four operator HMI workstations (`windows-10`/`windows-11`,
RDP + SMB) and one engineering workstation (`windows-server-2019`, RDP + SMB
+ WinRM + SSH — the box that programs the controllers and is the crown
jewel). The ARP + ICMP responders make the virtual hosts answer `arp-scan`
and ping. Lateral RDP/SMB between workstations is exactly what to catch.

**Adapt:** add/remove operator hosts under `honeynets[].hosts`; point
`allowlist` at the SCADA server tier north of the clients.

### OT server network — historian, app servers, OT-AD, file server

[`ot-server-network/historian-appservers-ad-fileserver.yaml`](ot-server-network/historian-appservers-ad-fileserver.yaml)

The level-3 server tier: an OT-side Active Directory DC
(`archetype: active-directory`), a process historian (`mssql` + web), two
SCADA/batch app servers, and a file server (`smb` + `ftp`).
`vuln_emulation: true` because OT servers are notoriously unpatched. Events
`>=high` forward to a CEF syslog SIEM.

**Adapt:** the historian is the highest-value target — keep its
`severity: critical`. The `allowlist` treats intra-tier traffic as expected;
tighten or remove it per your segmentation.

### Edge devices — MikroTik & Teltonika

[`edge/mikrotik-router.yaml`](edge/mikrotik-router.yaml) ·
[`edge/teltonika-rut240.yaml`](edge/teltonika-rut240.yaml)

Internet-/remote-site-facing edge hardware, relentlessly scanned and
botnet-recruited. The MikroTik decoy presents the full RouterOS fingerprint
(`SSH-2.0-ROSSSH`, webfig, Winbox 8291 + API 8728, MikroTik SNMP OID) and
routes SSH/Telnet to the RouterOS CLI emulator. The Teltonika decoy presents
RutOS (Dropbear SSH, lighttpd, Teltonika SNMP). Both tighten brute-force
thresholds for the constant edge noise.

**Adapt:** these are single-archetype sensors (no honeynet) — the simplest
shape. Add `sensor.interfaces: [<wan-iface>]` to pin to the WAN NIC.

---

## Other reference deployments

- **[`edge-corp-network.yaml`](edge-corp-network.yaml)** — corporate edge:
  IT honeypots (SSH/HTTP/RDP/SMB), an AD-style honeynet, syslog/CEF to a
  SIEM, loopback web UI, retention tuned for IT.
- **[`raspberry-pi-zero.yaml`](raspberry-pi-zero.yaml)** — minimal embedded
  sensor: tripwire-only listeners, no UI, no SQLite, jsonlog + webhook only.
  For an ARMv6 Pi Zero or other tiny node.
- **[`ot-substation.yaml`](ot-substation.yaml)** — a flat ICS segment
  (Modbus/S7/IEC-104/EtherNet-IP/OPC-UA/BACnet) with the port-scan
  correlator tuned tight and an SNMP-trap channel to an NMS.
- **[`siem-integration.yaml`](siem-integration.yaml)** — output-format
  showcase: the same events to JSON, CEF (ArcSight), LEEF (QRadar), and OCSF
  (Snowflake) sinks.

---

## Combining and adapting examples

**Multiple files (combine).** Pass `-c` more than once and the files are
combined — every listener / honeynet / host across all files is used, while
scalar config (`sensor.*`, `ui`, …) takes the last file's value:

```sh
tarpit-honeypot run \
  -c examples/ot-server-network/historian-appservers-ad-fileserver.yaml \
  -c examples/it-ot-dmz/manufacturing-idmz.yaml
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

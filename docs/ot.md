# ICS / OT decoys

`tarpit-honeypot` ships a broad **industrial control system (ICS) / operational
technology (OT)** decoy suite: low-interaction emulators for the field-bus,
SCADA, building-automation and safety protocols an attacker probes when they
land on (or scan toward) an OT segment. Every interaction is captured,
classified, and mapped to **MITRE ATT&CK for ICS**, and almost every protocol
now distinguishes **reconnaissance** from **control manipulation** so a SOC sees
*what the attacker is trying to do*, not just *that an ICS port was touched*.

This document describes, in depth:

1. [Design & threat model](#1-design--threat-model)
2. [Supported protocols](#2-supported-protocols) (TCP, UDP, L2)
3. [Emulated commands & the attacker-intent map](#3-emulated-commands--attacker-intent)
4. [The deception model](#4-the-deception-model)
5. [ATT&CK for ICS mapping](#5-attck-for-ics-mapping)
6. [CVE / CWE coverage for OT](#6-cve--cwe-coverage-for-ot)
7. [Configuration & customization](#7-configuration--customization)
8. [Limitations & faults](#8-limitations--faults)

> The protocol handlers themselves are the source of truth. Run
> `tarpit-honeypot list-handlers` for the live list, and see
> [`attribution.md`](attribution.md) for the full anomaly→ATT&CK/D3FEND table
> (the OT markers below are a curated subset).

---

## 1. Design & threat model

The OT suite is **low-interaction by design**. The goals, in priority order:

1. **Detect.** Any byte that reaches an ICS port is a high-signal event — there
   is almost no benign reason for an external party to speak Modbus or S7comm to
   your sensor. Every handler captures the request and raises an anomaly.
2. **Classify.** Where the protocol carries a command, the handler decodes it
   and decides whether it is **recon** (read a register, enumerate the data
   model, read the CPU model) or **control** (write a register, change RUN/STOP
   mode, download logic, reset the device). Each maps to an ATT&CK-for-ICS
   technique and gets a human-readable `intent` string.
3. **Deceive — safely.** The handler answers *just enough* to look like a live
   device so a scanner classifies the host and an attacker keeps interacting
   (yielding more TTPs). Reads return believable process data; writes and
   mode-changes are **acknowledged as if they succeeded** — but **nothing is
   ever applied**, because there is no real device behind the decoy.

Two hard safety rules constrain the suite:

- **No real control.** A decoy has no process image, no I/O, no PLC program. A
  "successful" write is a fabricated ACK. The sensor cannot be used to pivot
  into a real process.
- **Reflection-safety.** Several OT protocols run over UDP and are spoofable.
  Handlers that would otherwise be usable as a DDoS reflection/amplification
  vector either **never reply** (capture-only) or reply with a **bounded,
  globally rate-limited** datagram no larger than the request. See each
  protocol's note in §2.

`intent` is a plain-language summary stamped on the event meta, e.g.:

```
intent = "S7comm Write Var — writing PLC memory (control manipulation)"
intent = "DNP3 COLD_RESTART — restarting the outstation (denial of control)"
intent = "OPC-UA OpenSecureChannel (SecurityPolicy#None) — unauthenticated/cleartext session attempt"
```

---

## 2. Supported protocols

OT handlers run in a listener's **`banner`** mode (the listener's protocol
handler answers the connection). They can also be wrapped by a **`tarpit`**
listener with `tarpit.emulate: true`, which runs the OT handler first (real
capture + reply) and *then* tarpits the same connection.

Handlers are classed by fidelity:

- **Deep** — decodes the protocol's command/function structure and classifies
  recon vs control.
- **Fingerprint** — completes the handshake / answers the identification probe
  with a believable per-deployment identity, captures the request, and flags
  the probe (no per-command classification).

### TCP

| Handler | Port(s) | Vendor / standard | Fidelity | Emulated |
|---|---|---|---|---|
| `modbus` | 502 | Modbus/TCP (MBAP) | Deep | Read coils/registers, write coils/registers, FC 0x08 diagnostics, Report Server ID, FC 0x2B/MEI Read-Device-ID (→ Schneider Modicon M340) |
| `modbus_security` / `modbuss` | 802 | Modbus/TCP Security (TLS + client-cert role) | Deep | TLS termination (JA3/JA4/JA3S), client-cert subject + Modbus role (OID 1.3.6.1.4.1.50316.802.1) capture, then the full `modbus` command set over the encrypted channel |
| `s7` | 102 | Siemens S7comm (TPKT/COTP) | Deep | COTP CR→CC, Setup Communication, SZL read (S7-300 identity), Read/Write Var, PLC control/STOP, block up/download |
| `s7comm_plus` | 102 | Siemens S7-1200/1500 | Fingerprint | COTP CR→CC, classifies first PDU (`0x72` plus vs `0x32` classic) |
| `iec104` | 2404 | IEC 60870-5-104 | Deep | STARTDT/STOPDT/TESTFR, I/S/U-frame parsing, General/Counter Interrogation, single/double commands, set-point commands, reset-process |
| `dnp3` | 20000 | DNP3 / IEEE 1815 | Deep | Data-link LINK_STATUS/ACK + application layer (READ, WRITE, SELECT/OPERATE/DIRECT_OPERATE, COLD/WARM_RESTART, STOP_APPL, enable/disable unsolicited) |
| `ethernetip` | 44818 | EtherNet/IP + CIP (Rockwell) | Deep | RegisterSession, ListIdentity (1756-L73 ControlLogix), SendRRData/SendUnitData CIP (Get/Set/Read_Tag/Write_Tag/Reset/Start/Stop/Forward_Open) |
| `opcua` | 4840 | OPC-UA TCP | Deep | HEL→ACK (endpoint URL + buffers), OpenSecureChannel SecurityPolicyUri capture (`#None` flagged) |
| `mms` | 102 | IEC 61850 MMS (ISO-on-TCP) | Deep | COTP CR→CC, ACSE/MMS association (AARE accept), confirmed-service detection (getNameList / identify / read / write) |
| `melsec` | 1025 / 5006 / 5007 | Mitsubishi MELSEC MC (3E) | Deep | Batch/Random read+write, Remote RUN/STOP/PAUSE/Latch-Clear, Remote Reset, Read-CPU-Model (`Q03UDVCPU`) |
| `ads` | 48898 | Beckhoff ADS/AMS (TwinCAT) | Deep | Read, Write, ReadWrite, WriteControl (run-state), ReadDeviceInfo/ReadState (TwinCAT identity) |
| `fins_tcp` | 9600 | Omron FINS/TCP | Deep | Node-address handshake, Memory-Area read/write, RUN/STOP, Program-Area download, CPU-data read |
| `roc_plus` | 4000 | Emerson ROC Plus (flow-computer RTU) | Deep | Login, parameter read (config/measurement), parameter write |
| `pcom` | 20256 | Unitronics PCOM (Vision PLC) | Deep | Identification, value writes (SB/SW/SA/…), RUN/STOP, logic download |
| `secs_gem` | 5000 | SEMI HSMS / SECS-GEM | Deep | Select/Linktest, S7F3 process-program send, S2F41 host command |
| `crimson` | 789 | Red Lion Crimson (HMI) | Fingerprint | Framed request → "G3" identity |
| `ge_srtp` | 18245 | GE/Emerson PACSystems / Series 90 | Fingerprint | 56-byte request → success response |
| `codesys` | 1217 | CODESYS V3 (WAGO/Beckhoff/Schneider/ABB) | Fingerprint | Channel-open ack |
| `hartip` | 5094 | HART-IP (field-instrument gateway) | Fingerprint | 8-byte header → response (session-initiate / token-passing) |
| `pcworx` | 1962 | Phoenix Contact PCWorx (ILC PLC) | Fingerprint | Identification frame (`ILC 330 ETH` + firmware) |
| `atg` | 10001 | Veeder-Root TLS-350 tank gauge | Fingerprint | `^A I20100/I20200/I20300` → per-deployment tank report |
| `fox` | 1911 | Niagara / Tridium Fox (BAS) | Fingerprint | per-deployment "fox hello" (station/host/versions) |

### UDP

UDP handlers are **reflection-safe** (see §1). "Capture-only" = never replies;
"bounded ack" = one rate-limited datagram ≤ request size.

| Handler | Port | Vendor / standard | Fidelity | Reply | Emulated |
|---|---|---|---|---|---|
| `bacnet` | 47808 | BACnet/IP (building automation) | Deep | unicast | Who-Is/Who-Has → I-Am, ReadProperty (point enum), WriteProperty (SimpleACK), DeviceCommunicationControl, ReinitializeDevice, AtomicWriteFile |
| `fins` | 9600 | Omron FINS/UDP | Deep | rate-limited | CPU/status/cycle/clock read, Memory-Area read/write, RUN/STOP, Program-Area access |
| `knx` | 3671 | KNXnet/IP (building automation) | Fingerprint | unicast | SEARCH/DESCRIPTION responses (MDT KNX IP Router); CONNECT refused `0x24` |
| `profinet` | 34964 | PROFINET-IO (DCE-RPC) | Deep | **capture-only** | CM opnum (Connect/Release/IODRead/IODWrite/IODControl/ReadImplicit) |
| `tristation` | 1502 | Triconex TriStation/TSAA (SIS) | Fingerprint | bounded ack | msg types; program-download/control flagged safety-controller manipulation (TRITON/TRISIS) |
| `bsap` | 1234 | Bristol/Emerson BSAP-IP RTU | Fingerprint | bounded ack | addressing/node decode |
| `ge_egd` | 18246 | GE Ethernet Global Data | Fingerprint | **capture-only** | PDU type + producer id |
| `lontalk` | 1628 | Echelon LonTalk / LonWorks-IP (CEA-852) | Fingerprint | **capture-only** | data-packet header |
| `wdbrpc` | 17185 | VxWorks WDB target agent (URGENT/11) | Fingerprint | bounded ack | probe + connect |

### L2 (sniffer / responder)

| Component | EtherType / frame | Mode | Emulated |
|---|---|---|---|
| GOOSE detection | IEC 61850 GOOSE (`0x88B8`) | sniffer (detect) | flags `sniffer:goose` (substation multicast observed) |
| PROFINET-DCP responder | PROFINET (`0x8892`) | L2 responder (Linux, CAP_NET_RAW) | answers DCP **Identify** per virtual station (cell enumeration); detects DCP **Set** — NameOfStation/IP reassignment or Control/factory-reset — raises `honeynet:profinet_dcp_set` and ACKs the Set as if it applied |

---

## 3. Emulated commands & attacker-intent

Each deep handler decodes the protocol's command/operation and stamps an
`intent`. The table below is the operation→classification map; "marker" is the
anomaly raised (see §5 for the ATT&CK technique it maps to).

### Recon (read / enumerate / fingerprint)

| Protocol | Operation | Marker |
|---|---|---|
| Modbus | Read Coils/Discrete/Holding/Input (FC 1–4) | *(captured; reply only)* |
| Modbus | Read Device Identification (FC 0x2B/MEI), Report Server ID (FC 0x11) | *(intent: PLC fingerprinting)* |
| S7comm | Read Var | `ics-process-data-access` |
| S7comm | SZL read (module/CPU identification) | `ics-field-device-probe` |
| IEC-104 | General / Counter Interrogation | `ics-process-data-access` |
| DNP3 | READ | `ics-process-data-access` |
| EtherNet/IP CIP | Get_Attribute(s), Read_Tag | `ics-process-data-access` |
| EtherNet/IP CIP | Forward_Open / ListIdentity | `ics-field-device-probe` |
| MMS | getNameList / identify / getVariableAccessAttributes | `ics-field-device-probe` |
| MMS | read | `ics-process-data-access` |
| MELSEC | Batch/Random Read | `ics-process-data-access` |
| MELSEC | Read CPU Model | `ics-field-device-probe` |
| ADS | Read | `ics-process-data-access` |
| ADS | ReadDeviceInfo / ReadState | `ics-field-device-probe` |
| FINS | Memory-Area Read | `ics-process-data-access` |
| FINS | CPU-data / status / cycle-time read | `ics-field-device-probe` |
| BACnet | ReadProperty | `bacnet-property-read` |
| BACnet | Who-Is / Who-Has | `bacnet-device-discovery` |
| PROFINET-IO | IODRead / ReadImplicit | `ics-process-data-access` |
| PROFINET-DCP | Identify | `honeynet:profinet_dcp_identify` |
| ROC Plus | parameter read | *(intent: config/measurement theft)* |

### Control (write / mode change / program / reset)

| Protocol | Operation | Marker |
|---|---|---|
| Modbus | Write Coil/Register (FC 5/6/0F/10/16/17) | `modbus-write-attempt` |
| Modbus | Diagnostics restart / force-listen-only (FC 0x08) | `ics-modbus-diagnostic` |
| S7comm | Write Var | `ics-plc-write` |
| S7comm | PLC STOP / control | `ics-plc-mode-change` |
| S7comm | block up/download | `ics-plc-program-access` |
| IEC-104 | single / double command | `ics-iec104-command` |
| IEC-104 | set-point command | `ics-plc-write` |
| IEC-104 | reset-process | `ics-device-restart` |
| DNP3 | WRITE | `ics-plc-write` |
| DNP3 | SELECT / OPERATE / DIRECT_OPERATE | `ics-dnp3-control` |
| DNP3 | COLD/WARM_RESTART, STOP_APPL | `ics-device-restart` |
| EtherNet/IP CIP | Set_Attribute(s) / Write_Tag | `ics-plc-write` |
| EtherNet/IP CIP | Reset / Stop | `ics-device-restart` |
| EtherNet/IP CIP | Start | `ics-plc-mode-change` |
| MMS | write | `ics-plc-write` |
| MELSEC | Batch/Random Write | `ics-plc-write` |
| MELSEC | Remote RUN/STOP/PAUSE/Latch-Clear | `ics-plc-mode-change` |
| MELSEC | Remote Reset | `ics-device-restart` |
| ADS | Write / ReadWrite | `ics-plc-write` |
| ADS | WriteControl (run-state) | `ics-plc-mode-change` |
| FINS | Memory-Area Write | `ics-plc-write` |
| FINS | RUN / STOP | `ics-plc-mode-change` (`fins-run-mode-change` over TCP) |
| FINS | Program-Area download | `ics-plc-program-access` / `fins-program-download` |
| BACnet | WriteProperty | `bacnet-write-attempt` |
| BACnet | DeviceCommunicationControl | `bacnet-device-comm-control` |
| BACnet | ReinitializeDevice | `bacnet-reinitialize-device` |
| BACnet | AtomicWriteFile | `bacnet-file-write-attempt` |
| PROFINET-IO | IODWrite | `profinet-iod-write` |
| PROFINET-IO | IODControl | `profinet-iod-control` |
| PROFINET-DCP | Set (NameOfStation/IP/factory-reset) | `honeynet:profinet_dcp_set` |
| ROC Plus | login | `ics-roc-plus-login` |
| ROC Plus | parameter write | `ics-plc-write` |
| PCOM | value write / RUN-STOP / logic download | `pcom-write-attempt` / `pcom-mode-change` / `pcom-program-download` |
| SECS-GEM | S7F3 process-program send / S2F41 host command | `secs-program-send` / `secs-remote-command` |
| TriStation | program-download / control-program | `ics-safety-controller-manipulation` |
| KNX | bus write | `knx-bus-write` |
| ATG | command | `ics-atg-command` |
| VxWorks WDB | connect (debug/RCE) | `wdbrpc-connect` |

---

## 4. The deception model

A scanner or attacker who reaches a decoy should see a plausible live device for
as long as possible. The handlers achieve this without any real control surface:

- **Believable identities.** Read-device / identification probes return
  realistic, per-deployment-stable strings — Siemens `6ES7 315-2EH14-0AB0`
  (S7comm SZL), Rockwell `1756-L73/B LOGIX5573` (EtherNet/IP), Mitsubishi
  `Q03UDVCPU` (MELSEC), Beckhoff `TwinCAT` (ADS), Schneider `BMX P34 2020`
  (Modbus device-ID), Phoenix Contact `ILC 330 ETH` (PCWorx), and so on. Where a
  field is deployment-specific (serial numbers, station MACs, the ATG tank
  report), it is derived from `sensor.deployment_id` so it is consistent within
  a sensor but differs across deployments.
- **Believable reads.** Register/memory reads return small, plausible
  process-value patterns rather than zeros (less suspicious to an analyst
  dumping a memory area).
- **"Successful" writes.** Writes, mode-changes, and resets are answered with
  the protocol's success/ACK shape so the attacker believes the action landed —
  while the handler flags it as control manipulation. Nothing is applied.
- **Session continuity.** The deeper handlers run a short post-handshake session
  (S7comm Setup→SZL→read/write; Modbus multi-PDU; IEC-104 STARTDT→interrogation;
  MQTT CONNECT→SUBSCRIBE) so a tool that proceeds past the banner keeps
  revealing intent.

Combine an OT handler listener with an **`archetype`** (e.g.
`schneider-modicon-m580`, a Moxa switch, a Siemens coupler) so the surrounding
banners, SNMP MIB, MAC OUI and TLS posture match the pretended device, and with
the **PROFINET-DCP responder** so an L2 discovery scan sees a populated cell.

---

## 5. ATT&CK for ICS mapping

OT events are mapped to the **MITRE ATT&CK for ICS** matrix (the `T08xx` ID
space) rather than the Enterprise matrix. Mapping happens at two levels:

- **Handler tags** — every event from an OT listener carries its handler's base
  technique(s), e.g. `modbus` → `T0814`/`T0888`, `dnp3` → `T0814`/`T0888`.
- **Anomaly markers** — the per-operation markers from §3 add a precise
  technique. Unmapped `ics-*` markers fall back to `T0888` (discovery).

D3FEND countermeasures are derived from each technique (see
[`attribution.md`](attribution.md) §2).

### ICS techniques used

| Technique | Name | Tactic |
|---|---|---|
| **T0801** | Monitor Process State | collection |
| **T0814** | Denial of Service | impact |
| **T0816** | Device Restart/Shutdown | impact |
| **T0830** | Adversary-in-the-Middle | collection |
| **T0831** | Manipulation of Control | impact |
| **T0836** | Modify Parameter | impact |
| **T0843** | Program Download | lateral-movement |
| **T0846** | Remote System Discovery | discovery |
| **T0855** | Unauthorized Command Message | impact |
| **T0858** | Change Operating Mode | impact |
| **T0866** | Exploitation of Remote Services | lateral-movement |
| **T0880** | Loss of Safety | impact |
| **T0888** | Remote System Information Discovery | discovery |

### Marker → technique (curated)

| Marker | Technique(s) |
|---|---|
| `ics-field-device-probe`, `ics-device-enumeration`, `ics-data-bus-discovery` | T0888 / T0846 |
| `ics-process-data-access`, `bacnet-property-read` | T0801 |
| `ics-plc-write`, `modbus-write-attempt`, `bacnet-write-attempt`, `profinet-iod-write`, `honeynet:profinet_dcp_set` | T0836 + T0831 |
| `ics-plc-mode-change`, `fins-run-mode-change`, `pcom-mode-change` | T0858 |
| `ics-device-restart`, `bacnet-reinitialize-device` | T0816 |
| `ics-modbus-diagnostic`, `bacnet-device-comm-control` | T0814 |
| `ics-dnp3-control`, `ics-iec104-command`, `secs-remote-command`, `profinet-iod-control` | T0855 |
| `ics-plc-program-access`, `fins-program-download`, `secs-program-send`, `pcom-program-download` | T0843 |
| `ics-safety-controller-manipulation` | T0831 + T0880 |
| `wdbrpc-connect` | T0866 |
| `honeynet:profinet_dcp_identify`, `bacnet-device-discovery` | T0846 |
| `sniffer:goose` | T0888 |

---

## 6. CVE / CWE coverage for OT

The OT suite is primarily **behaviour-based detection + deception**: it raises
ATT&CK-for-ICS events from *what the attacker does* (a write, a STOP, a program
download), not from matching a vulnerability signature. That is the right model
for ICS, where the "attack" is usually an unauthenticated-but-protocol-legal
control command, not an exploit string.

CVE/CWE attribution still applies where it is observable:

- The sensor's **CVE catalog** (with **CWE**, **CVSS**, **CPE**, **EPSS**, and
  ATT&CK on each record — see [`attribution.md`](attribution.md) §3) carries the
  IT and ICS-adjacent CVEs whose exploit *signature* appears on the wire; a
  match raises a `cve:<id>` event regardless of `vuln_emulation`.
- The **YARA artifact engine** ([`yara.md`](yara.md)) includes a deep
  IoT/IIoT/OT/building-automation rule focus (ICS protocol & tooling
  fingerprints, ICS-malware families, BAS product references) for any artifact
  an attacker drops.
- Industrial **archetypes** can advertise known-vulnerable firmware/version
  strings when `sensor.vuln_emulation: true`, so a version scanner records an
  unpatched PLC/switch — the service never becomes actually exploitable.

There are no OT-protocol *exploit* emulations (no buffer-overflow payloads, no
firmware RCE); the decoys answer protocol-legally and capture intent.

---

## 7. Configuration & customization

### Expose an OT service directly

```yaml
listeners:
  - { id: plc-modbus, proto: tcp, bind: 0.0.0.0:502,   handler: modbus,  mode: banner, severity: high, capture: true }
  - { id: plc-s7,     proto: tcp, bind: 0.0.0.0:102,   handler: s7,      mode: banner, severity: high, capture: true }
  - { id: rtu-dnp3,   proto: tcp, bind: 0.0.0.0:20000, handler: dnp3,    mode: banner, severity: high, capture: true }
  - { id: bms-bacnet, proto: udp, bind: 0.0.0.0:47808, handler: bacnet,  mode: banner, severity: high, capture: true }
  - { id: pn-io,      proto: udp, bind: 0.0.0.0:34964, handler: profinet, mode: banner, severity: high, capture: true }
```

### Role bundles (`archeservices:`)

Declare an OT *role* and it expands into the right ports + handlers. Built-in
OT-relevant roles:

| Role | Services |
|---|---|
| `scadaserver` | Modbus 502, S7comm 102, DNP3 20000, HMI HTTP 80, SNMP 161 |
| `substation` | IEC 61850 MMS 102, DNP3 20000, IEC-104 2404, SNMP 161 |
| `buildingautomation` | BACnet 47808, Niagara Fox 1911, OPC-UA 4840, BMS HTTP 80 |
| `rockwellplc` | EtherNet/IP 44818 + 2222, PLC HTTP 80, SNMP 161 |
| `omronplc` | FINS/TCP + FINS/UDP 9600 |
| `emersonrtu` | ROC Plus 4000, Modbus 502, RTU HTTP 80, SNMP 161 |
| `bristolrtu` | BSAP-IP 1234, Modbus 502, RTU HTTP 80, SNMP 161 |
| `gecontroller` | GE EGD 18246, Modbus 502, PLC HTTP 80, SNMP 161 |
| `redlionhmi` | Crimson 789, Modbus 502, HMI HTTP/HTTPS |
| `lonworksgateway` | LonWorks/IP 1628, gateway HTTP/HTTPS, SNMP 161 |
| `safetyplc` | Modbus 502, SIS HTTP 80, Triconex TriStation/TSAA 1502 |

```yaml
archeservices:
  - { role: substation, archetype: "siemens", bind: 0.0.0.0 }
```

### Industrial archetypes

Pin a decoy's identity to a real product with `archetype:` — banners, SNMP
sysDescr/ifTable, MAC OUI, CLI prompt and TLS posture follow. The catalog spans
Siemens, Moxa, Schneider Modicon, Allen-Bradley/Rockwell, Omron, Westermo,
Hirschmann, Phoenix Contact, Advantech, Cisco Industrial Ethernet, and more (see
[`archetypes.md`](archetypes.md)). The `siemens`/`moxa` families also drive the
PROFINET-DCP responder's per-station identity.

### PROFINET-DCP responder

```yaml
honeynets:
  - id: ot-cell
    profinet_responder: { enabled: true, interface: eth0 }   # Linux + CAP_NET_RAW
    hosts:
      - { ip: 10.20.0.10, hostname: plc1, archetype: siemens, services: [ {port: 102, handler: s7} ] }
```

Industrial hosts (and archetypes carrying a SCALANCE-class PROFINET device tree)
become DCP stations; an `Identify` scan enumerates the cell, and a `Set`
(rename / IP reassign / factory-reset) is detected and ACK'd.

### Other knobs

- **`interaction.mode`** (`low` / `medium_experimental`) gates how far
  interactive emulators go.
- **`sensor.vuln_emulation`** lets industrial archetypes advertise
  known-vulnerable versions (banner only — never actually exploitable).
- **`listener.read_timeout`** bounds how long a session waits for the next PDU.
- **`sensor.deployment_id`** seeds the per-deployment identity strings (serials,
  station MACs, tank reports).
- **`tarpit.emulate: true`** on a `tarpit` listener runs the OT handler first,
  then tarpits the connection.
- Ready-to-run scenarios: `configs/tarpit-honeypot.example-ADVANCED-OT.yaml`,
  `configs/tarpit-honeypot.example-SMALL-OT.yaml`, and the `examples/ot-*.yaml`
  scenarios (`ot-substation`, `ot-power-grid`, `ot-discrete-mfg`,
  `ot-safety-dcs`) + the `examples/it-ot-dmz` IDMZ.

### Ready-made example configs

`configs/tarpit-honeypot.example-ADVANCED-OT.yaml` builds a Purdue-model OT
estate; `configs/tarpit-honeypot.example-SMALL-OT.yaml`, the `examples/ot-*.yaml`
scenarios, and the `examples/it-ot-dmz` IDMZ are lighter starting points.
Validate any config with `tarpit-honeypot validate-config -c <file>`.

---

## 8. Limitations & faults

Be clear-eyed about what these decoys are and are not:

- **Low-interaction.** No handler implements a full protocol stack or a real
  device model. A determined adversary who drives a *complete* engineering
  workflow (e.g. a full TIA Portal online session, a complete CIP connected
  messaging exchange, a multi-fragment DNP3 application transaction with
  confirmations) will eventually see responses that don't fully cohere. The
  decoys are tuned to satisfy scanners (nmap NSE, PLCScan, Shodan-class probes)
  and the opening moves of an attacker, not a full HMI/engineering tool.
- **Fingerprint-grade handlers** (`s7comm_plus`, `ge_srtp`, `codesys`, `hartip`,
  `pcworx`, `crimson`, `fox`, `atg`, `knx`, `tristation`, `bsap`, `ge_egd`,
  `lontalk`, `wdbrpc`) capture + flag the probe and return a believable
  identity, but do **not** decode per-command control vs recon.
- **No cryptographic sessions.** OPC-UA stops after capturing the
  OpenSecureChannel SecurityPolicyUri — it does not run the OPN/CreateSession
  crypto handshake (so a security-policy *other* than `#None` won't proceed).
  S7comm-Plus's integrity-protected session is not emulated. TLS-wrapped OT
  variants are out of scope unless fronted by `tls_intercept`.
- **MMS service detection is heuristic.** The post-association confirmed-request
  service is found by a bounded scan of the BER for the confirmed-request tag +
  invokeID; it recognizes the common services (getNameList/identify/read/write)
  but is not a full ASN.1/BER decoder and may miss exotic or deeply-nested
  encodings.
- **UDP reflection trade-off.** To stay reflection-safe, several UDP handlers are
  capture-only (`profinet`, `ge_egd`, `lontalk`) or reply only under a global
  rate limiter with a bounded datagram (`fins`, `tristation`, `bsap`, `wdbrpc`).
  Under that limiter a scanner may occasionally see no reply (`rate_limited` is
  recorded), which is a deliberate safety choice over perfect fidelity.
- **PROFINET-DCP is Linux-only.** The L2 responder needs `AF_PACKET` +
  `CAP_NET_RAW`; on other platforms it returns a clean diagnostic and stays off.
  GOOSE detection is likewise sniffer-based (Linux).
- **"Successful" writes are fiction.** A write/mode-change/reset ACK is
  fabricated. This is intentional (no real control surface) but means a decoy
  cannot reproduce *downstream* process effects an attacker might check for.
- **Shared port 102.** S7comm (`s7` / `s7comm_plus`) and IEC 61850 MMS (`mms`)
  all live on TCP 102; pick the one that matches the device you are pretending
  to be (a Siemens PLC vs a substation IED), since a single listener serves one
  handler.
- **No control-logic emulation.** There is no ladder/FBD/ST program, no tag
  database, and no I/O simulation; tag/symbol browsing beyond the canned
  identity is not served.

For the authoritative, always-current view of what a build implements, use
`tarpit-honeypot list-handlers` and the in-product **docs** tab (`/docs/ot`).

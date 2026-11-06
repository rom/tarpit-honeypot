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
| `s7comm_plus` | 102 | Siemens S7-1200/1500 | Deep | COTP CR→CC, parses the S7comm-Plus PDU: version→firmware family, opcode, function (Explore / Get-SetMultiVariables / CreateObject / Invoke) |
| `iec104` | 2404 | IEC 60870-5-104 | Deep | STARTDT/STOPDT/TESTFR, I/S/U-frame parsing, General/Counter Interrogation, single/double commands, set-point commands, reset-process |
| `dnp3` | 20000 | DNP3 / IEEE 1815 | Deep | Data-link LINK_STATUS/ACK + application layer (READ, WRITE, SELECT/OPERATE/DIRECT_OPERATE, COLD/WARM_RESTART, STOP_APPL, enable/disable unsolicited) |
| `ethernetip` | 44818 | EtherNet/IP + CIP (Rockwell) | Deep | RegisterSession, ListIdentity (1756-L73 ControlLogix), SendRRData/SendUnitData CIP (Get/Set/Read_Tag/Write_Tag/Reset/Start/Stop/Forward_Open) |
| `opcua` | 4840 | OPC-UA TCP | Deep | HEL→ACK (endpoint URL + buffers), OpenSecureChannel SecurityPolicyUri capture (`#None` flagged) |
| `dcerpc` (OPC-DA) | 135 | OPC-DA / OPC Classic over DCOM (MSRPC) | Deep | DCE/RPC bind + endpoint-mapper parse; flags OPCEnum / IOPCServer interface binds (`ics-opc-da-probe`), advertises believable OPC-DA server ProgIDs, and services IOPCServer GetStatus/AddGroup/Read/Write with OPCSERVERSTATUS stubs |
| `mms` | 102 | IEC 61850 MMS (ISO-on-TCP) | Deep | COTP CR→CC, ACSE/MMS association (AARE accept), confirmed-service detection (getNameList / identify / read / write); **ICCP/TASE.2** profile detection (TASE.2 version OID + Bilateral_Table / Transfer_Set / VCC objects) with Transfer-Set, Bilateral-Table, and Block-5 Device-control classification |
| `iccp_secure` | 3782 | Secure ICCP / TASE.2 over TLS (IEC 62351) | Deep | TLS termination (JA3/JA4/JA3S) then the full `mms`/ICCP stack over the encrypted channel |
| `melsec` | 1025 / 5006 / 5007 | Mitsubishi MELSEC MC (3E) | Deep | Batch/Random read+write, Remote RUN/STOP/PAUSE/Latch-Clear, Remote Reset, Read-CPU-Model (`Q03UDVCPU`) |
| `ads` | 48898 | Beckhoff ADS/AMS (TwinCAT) | Deep | Read, Write, ReadWrite, WriteControl (run-state), ReadDeviceInfo/ReadState (TwinCAT identity) |
| `fins_tcp` | 9600 | Omron FINS/TCP | Deep | Node-address handshake, Memory-Area read/write, RUN/STOP, Program-Area download, CPU-data read |
| `roc_plus` | 4000 | Emerson ROC Plus (flow-computer RTU) | Deep | Login, parameter read (config/measurement), parameter write |
| `pcom` | 20256 | Unitronics PCOM (Vision PLC) | Deep | Identification, value writes (SB/SW/SA/…), RUN/STOP, logic download |
| `secs_gem` | 5000 | SEMI HSMS / SECS-GEM | Deep | Select/Linktest, S7F3 process-program send, S2F41 host command |
| `crimson` | 789 | Red Lion Crimson (HMI) | Fingerprint | Framed request → "G3" identity |
| `ge_srtp` | 18245 | GE/Emerson PACSystems / Series 90 | Fingerprint | 56-byte request → success response |
| `codesys` | 1217 | CODESYS V3 (WAGO/Beckhoff/Schneider/ABB) | Deep | Component/service classification (CmpUserMgr login, CmpFileTransfer, CmpApp download/online-change, start/stop, CmpDevice) + CVE-2022-31806/31802 |
| `hartip` | 5094 | HART-IP (field-instrument gateway) | Fingerprint | 8-byte header → response (session-initiate / token-passing) |
| `pcworx` | 1962 | Phoenix Contact PCWorx (ILC PLC) | Deep | Identification + session classification (run-state / program / write / read / login) + CVE-2016-8367 |
| `proconos` | 20547 | ProConOS / eCLR soft-PLC runtime (PCWorx/MULTIPROG) | Deep | Opcode classification: START/STOP mode-change, unauthenticated logic DOWNLOAD (ICS-ALERT-13-016 class) + CVE-2022-31800/31801 (OT:ICEFALL) |
| `c37118` | 4712 | IEEE C37.118.2 synchrophasor (PMU/PDC) | Deep | Frame parse (DATA/HEADER/CFG/COMMAND), COMMAND classification (turn-on/off transmission, send-CFG-2/HEADER), believable CFG-2 reply |
| `focas` | 8193 | FANUC FOCAS (CNC / machine tool) | Fingerprint | Request capture → `FANUC Series 30i` sysinfo reply |
| `osdp` | — | SIA OSDP / IEC 60839-11-5 (access control) over IP | Deep | Command classification (osdp_OUT door-strike, osdp_COMSET channel hijack, osdp_KEYSET/CHLNG secure-channel), osdp_ACK/PDID reply |
| `atg` | 10001 | Veeder-Root TLS-350 tank gauge | Fingerprint | `^A I20100/I20200/I20300` → per-deployment tank report |
| `fox` | 1911 | Niagara / Tridium Fox (BAS) | Fingerprint | per-deployment "fox hello" (station/host/versions) |

### UDP

UDP handlers are **reflection-safe** (see §1). "Capture-only" = never replies;
"bounded ack" = one rate-limited datagram ≤ request size.

| Handler | Port | Vendor / standard | Fidelity | Reply | Emulated |
|---|---|---|---|---|---|
| `bacnet` | 47808 | BACnet/IP (building automation) | Deep | unicast | Who-Is/Who-Has → I-Am, ReadProperty (point enum), WriteProperty (SimpleACK), DeviceCommunicationControl, ReinitializeDevice, AtomicWriteFile |
| `bacnet_sc` / `bacnet_scs` | 47808 (WS+TLS) | BACnet Secure Connect (ASHRAE 135-2020 Annex AB) | Deep | WS binary | WebSocket upgrade + `hub.bsc.bacnet.org` / `dc.bsc.bacnet.org` subprotocol; BVLC-SC framing; Connect-Request (node VMAC + device UUID) → Connect-Accept; Heartbeat-Request → Heartbeat-ACK; encapsulated WriteProperty flagged. `bacnet_scs` = TLS-fronted |
| `mqtt` (Sparkplug B) | 1883 / 8883 | Eclipse Sparkplug B (IIoT over MQTT) | Deep | CONNACK/SUBACK | `spBv1.0/` namespace on Will/SUBSCRIBE/PUBLISH topics parsed into group/msg-type/edge-node/device; NCMD/DCMD (edge-node/device commands) flagged as control writes |
| `fins` | 9600 | Omron FINS/UDP | Deep | rate-limited | CPU/status/cycle/clock read, Memory-Area read/write, RUN/STOP, Program-Area access; cleartext UM password + logic download flagged CVE-2022-31204/31207 (OT:ICEFALL) |
| `knx` | 3671 | KNXnet/IP (building automation) | Fingerprint | unicast | SEARCH/DESCRIPTION responses (MDT KNX IP Router); CONNECT refused `0x24` |
| `profinet` | 34964 | PROFINET-IO (DCE-RPC) | Deep | **capture-only** | CM opnum (Connect/Release/IODRead/IODWrite/IODControl/ReadImplicit) |
| `tristation` | 1502 | Triconex TriStation/TSAA (SIS) | Fingerprint | bounded ack | msg types; program-download/control flagged safety-controller manipulation (TRITON/TRISIS, CVE-2018-8872) |
| `bsap` | 1234 | Bristol/Emerson BSAP-IP RTU | Fingerprint | bounded ack | addressing/node decode |
| `ge_egd` | 18246 | GE Ethernet Global Data | Fingerprint | **capture-only** | PDU type + producer id |
| `lontalk` | 1628 | Echelon LonTalk / LonWorks-IP (CEA-852) | Fingerprint | **capture-only** | data-packet header |
| `wdbrpc` | 17185 | VxWorks WDB target agent (URGENT/11) | Deep | bounded ack | WDBPROG parse: memory-access / context-call (RCE) / connect + CVE-2010-2965; oversized → URGENT/11 (CVE-2019-12256) |
| `ads_discovery` | 48899 | Beckhoff TwinCAT AMS/UDP discovery + route | Deep | bounded ack | Identify/Discovery (`ics-ads-discovery`), AddRoute (`ics-ads-route-add`, captures route/host/user) |
| `modbus_udp` | 502 | Modbus over UDP | Fingerprint | **capture-only** | MBAP + PDU decode; write-class function codes flagged (coexists with `modbus`/TCP) |
| `enip_udp` | 44818 | EtherNet/IP CIP discovery (UDP) | Fingerprint | **capture-only** | ListIdentity / encapsulation-command capture |
| `cip_io` | 2222 | EtherNet/IP Class-1 cyclic I/O | Fingerprint | **capture-only** | CIP I/O (forward-open data) connection-id / sequence decode |
| `dnp3_udp` | 20000 | DNP3 over UDP (utility SCADA) | Fingerprint | **capture-only** | data-link/application function decode (coexists with `dnp3`/TCP) |
| `hartip_udp` | 5094 | HART-IP over UDP | Fingerprint | **capture-only** | HART-IP header (message type / session) capture |
| `pcom_udp` | 20256 | Unitronics PCOM over UDP | Fingerprint | **capture-only** | PCOM/ASCII + binary command capture |
| `slmp` | 5007 | Mitsubishi SLMP / MELSEC over UDP | Fingerprint | **capture-only** | SLMP command/sub-command; Write / Remote-RUN-STOP flagged |
| `powerlink` | 3819 | Ethernet POWERLINK | Fingerprint | **capture-only** | message-type decode (SoC/PReq/PRes/ASnd) |
| `ethercat` | 34980 | EtherCAT-over-UDP (EtherType 0x88A4) | Deep | bounded ack | command-datagram decode; slave register/PDO **read** = recon, **write** = control manipulation, broadcast (BRD) read = segment enumeration; echoes the frame with the **Working Counter incremented** + read data filled (same size, no amplification). EtherCAT is normally L2-only, so a master datagram over IP is itself anomalous targeted recon → `ethercat-probe` |
| `ff_hse` | 1089 | FOUNDATION Fieldbus HSE | Fingerprint | **capture-only** | HSE message-header capture |
| `saia_sbus` | 5050 | Saia Ether-S-Bus PCD controllers | Fingerprint | **capture-only** | S-Bus telegram decode |
| `opcua_pubsub` | 4840 | OPC-UA PubSub over UDP | Fingerprint | **capture-only** | UADP network-message header (publisher id / dataset) |
| `dds_rtps` | 7400 | DDS / RTPS (OMG Data Distribution Service) | Fingerprint | **capture-only** | RTPS submessage / vendor-id capture |
| `synchrophasor` | 4713 | IEEE C37.118 synchrophasor / PMU stream (UDP) | Fingerprint | **capture-only** | frame-type / id-code decode |
| `c1222` | 1153 | ANSI C12.22 smart-meter / AMI | Fingerprint | **capture-only** | ACSE/EPSEM message capture |
| `siprotec_en100` | 50000 | Siemens SIPROTEC 4 / Compact EN100 module | Deep | **capture-only** | crafted-datagram relay-DoS detection (CVE-2015-5374, INDUSTROYER `siprotec-en100-dos`) |

### L2 (sniffer / responder)

| Component | EtherType / frame | Mode | Emulated |
|---|---|---|---|
| GOOSE detection + attack analysis | IEC 61850 GOOSE (`0x88B8`) | sniffer (detect) | benign multicast → `sniffer:goose`; **stateful per-`gocbRef` analysis** flags **spoofing** (2nd publisher → `sniffer:goose_spoof`), **replay** (`stNum` regression → `sniffer:goose_replay`), **storm** (state-change flood → `sniffer:goose_storm`), **simulation** (simulate/`test` bit → `sniffer:goose_simulation`) → T0856/T0831/T0814 |
| PROFINET-DCP responder | PROFINET (`0x8892`) | L2 responder (Linux, CAP_NET_RAW) | answers DCP **Identify** per virtual station (cell enumeration); detects DCP **Set** — NameOfStation/IP reassignment or Control/factory-reset — raises `honeynet:profinet_dcp_set` and ACKs the Set as if it applied |

---

## 2a. Per-protocol implementation detail

This is the honest, function-level account of *what subset* each protocol
implements and *how it behaves on the wire*. Behavior legend:

- **Interactive reply** — completes the protocol handshake and answers each
  request with a believable, protocol-legal response (TCP). Nothing is ever
  actually actuated; "successful" writes/mode-changes are fabricated ACKs.
- **Bounded reply (rate-limited)** — UDP handler that answers, but behind a
  global reflection limiter with a size-bounded datagram (records
  `rate_limited` when it declines, so a spoofed-source flood can't amplify).
- **Capture-only (passive)** — records + classifies the request and sends
  **nothing** (the reflection-safe choice for spoofable UDP / L2).

Every handler stamps `intent` + ATT&CK-for-ICS markers regardless of whether it
replies. Any listener can be wrapped/replaced with a **`lua`** or **`scripted`**
handler to customize the exact bytes returned (see [`lua.md`](lua.md)) — the Lua
script sees the request payload and returns the response, so you can pin a
vendor-specific identity or add a function code the built-in handler treats
generically.

### Modbus/TCP (`modbus`, 502) — Interactive reply, deep

Full MBAP framing + per-PDU dispatch. Implemented function codes:

| FC | Name | Behavior |
|---|---|---|
| `0x01`/`0x02` | Read Coils / Discrete Inputs | answers with believable bit values |
| `0x03`/`0x04` | Read Holding / Input Registers | answers with believable register values |
| `0x05` | Write Single Coil | echoes (write attempt → `ics-modbus-write`) |
| `0x06` | Write Single Register | echoes (write attempt) |
| `0x0F` | Write Multiple Coils | ACKs (write attempt) |
| `0x10` | Write Multiple Registers | ACKs (write attempt) |
| `0x16` | Mask Write Register | echoes (write attempt) |
| `0x17` | Read/Write Multiple Registers | answers + write attempt |
| `0x07` | Read Exception Status | answers (Metasploit `modbus_detect` tell) |
| `0x08` | Diagnostics | request/echo loopback (`ics-modbus-diagnostic`) |
| `0x0B`/`0x0C` | Get Comm Event Counter / Log | answers |
| `0x11` | Report Server ID | answers with the deviceID identity |
| `0x14`/`0x15` | Read / Write File Record | read returns a believable record (config exfil); write captured |
| `0x18` | Read FIFO Queue | answers |
| `0x2B`/MEI `0x0E` | Read Device Identification | vendor/product/version strings (the asset-scanner deception, → Schneider Modicon by default) |
| `0x28`/`0x29`/`0x2A` | Schneider program/firmware transfer | captured as program access |
| `0x5A` | **UMAS** (Schneider) | sub-function parsed (reservation, read/write memory, run/stop, program) → `modbus-umas*` |
| 65–72, 100–110 | reserved / vendor-defined | captured, generic ack |

Unknown/unsupported FCs return a Modbus **exception** (the real-server reply).
**Modbus/TCP Security** (`modbus_security`/`modbuss`, 802) is the same command
set after TLS termination (JA3/JA4/JA3S + client-cert subject + the Modbus role
OID `1.3.6.1.4.1.50316.802.1`).

### Other deep TCP control protocols (Interactive reply)

- **S7comm** (`s7`, 102) — COTP CR→CC, Setup Communication, SZL read (S7-300
  identity), Read/Write Var, PLC STOP/control, block up/download. **S7comm-Plus**
  (`s7comm_plus`, 102) parses the S7-1200/1500 PDU (version→firmware, opcode,
  Explore/Get-Set-MultiVar/CreateObject/Invoke). The integrity-protected session
  is *not* emulated.
- **IEC 60870-5-104** (`iec104`, 2404) — STARTDT/STOPDT/TESTFR, I/S/U-frame
  parsing, General/Counter Interrogation, single/double + set-point commands,
  reset-process.
- **DNP3** (`dnp3`, 20000) — data-link LINK_STATUS/ACK (correct CRC) **plus**
  application layer (de-blocked): READ, WRITE, SELECT/OPERATE/DIRECT_OPERATE(_NR),
  COLD/WARM_RESTART, STOP_APPL, ENABLE/DISABLE_UNSOLICITED.
- **EtherNet/IP + CIP** (`ethernetip`, 44818) — RegisterSession, ListIdentity,
  SendRRData/SendUnitData CIP (Get/Set/Read_Tag/Write_Tag/Reset/Start/Stop/
  Forward_Open). Full DCOM-style connected messaging not completed.
- **IEC 61850 MMS** (`mms`, 102) — COTP + ACSE/MMS association, confirmed-service
  detection (getNameList/identify/read/write); **ICCP/TASE.2** profile detection
  + Transfer-Set / Bilateral-Table / Block-5 device-control classification.
  Heuristic BER scan, not a full ASN.1 decoder. **Secure ICCP** (`iccp_secure`,
  3782) is the same over TLS.
- **OPC-DA / OPC Classic** (`dcerpc`, 135) — the DCOM / MSRPC transport behind
  OPC Classic. Parses the DCE/RPC bind + endpoint-mapper, flags an OPCEnum /
  IOPCServer interface bind as an OPC-DA discovery probe (`ics-opc-da-probe`),
  advertises believable OPC-DA server ProgIDs, and returns structurally-valid
  IOPCServer GetStatus/AddGroup/Read/Write stubs (OPCSERVERSTATUS). OPC-UA
  (`opcua`, 4840) is the transport-independent successor; both ship in the
  ALL-OT example.
- **MELSEC** (`melsec`), **ADS/AMS** (`ads`/`ads_discovery`), **FINS**
  (`fins_tcp`/`fins`), **ROC Plus** (`roc_plus`), **PCOM** (`pcom`), **SECS/GEM**
  (`secs_gem`), **CODESYS V3** (`codesys`), **PCWorx** (`pcworx`), **KNXnet/IP**
  (`knx`) — each decodes its session/service layer and classifies recon vs
  control vs program-access (see the table in §2 for the exact verbs).
- **IEEE C37.118.2** (`c37118`, 4712) — frame parse + COMMAND classification
  (turn-on/off transmission, send CFG/HEADER); answers a CRC-checked CFG-2.
- **OSDP** (`osdp`) — access-control frame parse; classifies osdp_OUT (door
  strike), osdp_COMSET, osdp_KEYSET/CHLNG/SCRYPT; replies osdp_ACK/PDID.
- **ProConOS** (`proconos`, 20547) — opcode classification (START/STOP, logic
  DOWNLOAD); short ack — now carrying the **ICEFALL** advisory CVEs (see §6).

### Write-then-read-back coherence (engagement depth)

A careful ICS client — and an attacker validating that a controller write
actually *landed* — writes a value, then reads the same address back and
checks it changed. A handler that acks every write but always reads back the
same canned value fails that check and reveals itself as a decoy. The deep
control handlers now keep a **per-connection overlay** so a value written
earlier in the session reads back verbatim:

| Handler | Write verb → later read returns it |
|---|---|
| `modbus` | Write Single/Multiple Coils & Registers (`0x05`/`0x06`/`0x0F`/`0x10`/`0x16`) → subsequent Read Coils / Read Holding Registers of the same address |
| `s7` | Write Var → Read Var of the same area/DB/offset |
| `ethernetip` (CIP) | Write_Tag of a symbolic tag → Read_Tag of that tag (stores the CIP type + value, replayed exactly) |
| `dnp3` | OPERATE a binary output (CROB) / analog output (AOB) → READ of the matching status group (binary-output-status / analog-output-status) |
| `opcua` | Write of a node's Value (after CreateSession → ActivateSession) → Read of the same NodeId |

The overlay is **bounded and per-connection** — no cross-session or
cross-source state, nothing is ever actuated, and an address/object the parser
doesn't model falls back to the handler's stable synthetic value (never a
malformed frame). This raises engagement depth without adding amplification or
shared mutable state. (See `*_state.go` / `opcua_session.go` and the
`*_stateful_test.go` round-trips.)

### Fingerprint-grade TCP (Interactive reply, identity-only)

`ge_srtp`, `hartip`, `crimson`, `fox`, `atg`, `focas`, `osisoft_pi` — complete
the opening exchange and return a believable **identity** (model / firmware /
version) so a scanner records a live device, and flag the probe, but do **not**
decode per-command control vs recon.

**Process historians** (`osisoft_pi` 5450, `proficy_historian` 14000,
`canary_historian` 9990, `aspen_ip21` 10014) — the proprietary binary data ports
of the big process historians (OSIsoft/AVEVA PI, GE Proficy, Canary Labs,
AspenTech InfoPlus.21). Their wire protocols are closed and undocumented, so
these are fingerprint-grade only: they capture the client's opening message,
classify its framing (length-prefixed BE/LE vs raw stream), scavenge the
cleartext app/user/version strings these SDK handshakes leak, greet with a
minimal product identification a scanner greps, and surface the connection as
**historian / process-data access** (an IT→OT pivot and exfil target). No tag /
point database is served and the proprietary record formats are never
fabricated.

### UDP

- **Bounded reply (rate-limited):** `bacnet` (Who-Is→I-Am, ReadProperty,
  WriteProperty, DeviceCommunicationControl, ReinitializeDevice,
  AtomicWriteFile), `fins` (UDP), `tristation` (TriStation/TSAA — program-
  download/control flagged safety-controller manipulation, the TRITON/TRISIS
  vector), `bsap`, `wdbrpc` (WDB memory/context-call + URGENT/11), `ethercat`
  (EtherCAT-over-UDP — WKC-incremented echo, read=recon / write=control).
- **Capture-only (passive):** `profinet` (DCE-RPC CM opnums), `ge_egd`
  (producer id), `lontalk` (data-packet header), `knx` discovery — record +
  classify, never reply (reflection-safe).

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
| BACnet/SC | Connect-Request (node join) | `ics-bacnet-sc-connect` / `ics-field-device-probe` |
| BACnet/SC | Advertisement-Solicitation | `ics-bacnet-sc-discovery` |
| Sparkplug B | NBIRTH / DBIRTH | `ics-sparkplug-birth` |
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
| BACnet/SC | encapsulated WriteProperty | `ics-plc-write` |
| Sparkplug B | NCMD / DCMD (edge-node/device command) | `ics-sparkplug-command` / `ics-plc-write` |
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
| `ics-dnp3-control`, `ics-iec104-command`, `secs-remote-command`, `profinet-iod-control`, `ics-pmu-command`, `ics-actuator-command` | T0855 |
| `ics-iccp-association`, `ics-iccp-bilateral-table` | T0888 / T0846 |
| `ics-iccp-transfer-set` | T0855 + T0856 |
| `ics-iccp-control` (Block-5 device control) | T0855 + T0831 |
| `ics-comms-reconfigure` (osdp_COMSET) | T0855 + T0856 |
| `ics-key-install` (osdp_KEYSET) | T0859 |
| `ics-secure-channel-setup` (osdp_CHLNG/SCRYPT) | T0830 |
| `ics-plc-program-access`, `fins-program-download`, `secs-program-send`, `pcom-program-download` | T0843 |
| `ics-safety-controller-manipulation` | T0831 + T0880 |
| `wdbrpc-connect` | T0866 |
| `honeynet:profinet_dcp_identify`, `bacnet-device-discovery` | T0846 |
| `sniffer:goose_spoof`, `sniffer:goose_replay` | T0856 + T0831 |
| `sniffer:goose_storm` | T0814 + T0831 |
| `sniffer:goose_simulation` | T0856 |
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
- **Named-campaign attribution.** Several control actions now carry the CVE of
  the campaign that abused them, emitted by the handler's own classifier (not a
  payload signature, so they show `Det = —` in the catalog but still fire a
  `cve:<id>` from the handler):
  - **TRITON / TRISIS** — Schneider Triconex SIS memory write (`tristation` →
    **CVE-2018-8872**, T0843), the safety-controller manipulation vector.
  - **OT:ICEFALL** — Phoenix Contact ProConOS unauthenticated logic up/download
    (`proconos` → **CVE-2022-31800 / CVE-2022-31801**) and Omron SYSMAC FINS
    cleartext UM-protection password + unauthenticated logic download (`fins` →
    **CVE-2022-31204 / CVE-2022-31207**).
  - Attributed the same way: **CODESYS V3** (CVE-2022-31806 / 31802), **PCWorx**
    (CVE-2016-8367), **VxWorks URGENT/11** (`wdbrpc` → CVE-2010-2965 /
    CVE-2019-12256), and **SIPROTEC EN100 / INDUSTROYER** (`siprotec_en100` →
    CVE-2015-5374).

  The behaviour marker still fires on its own (a STOP / program-download is
  flagged regardless), but pinning the advisory hands an analyst the campaign
  name for free. Full per-CVE detail (CWE/CPE/EPSS/ATT&CK) is in
  [`attribution.md`](attribution.md) §3.

- **Refrigeration / cold-chain (`danfoss_aksm`).** The Danfoss **AK-SM 8xxA
  "StoreView"** supermarket-refrigeration system manager is an HTTP/`xml.cgi`
  web interface rather than a binary control protocol, so it lives alongside the
  remote-access/management personas (not the control-protocol table above) — but
  it is squarely OT: the controller family behind the October 2026 French
  supermarket "FROMAGEGATE" incident, where attackers forced defrost cycles and
  spoiled food in hundreds of stores. The handler fingerprints the device and
  **recognizes — detection only** — the Claroty Team82 / Danfoss-advisory flaws:
  the date-derived **code-of-the-day authentication bypass** (CVE-2025-41450,
  DSA-2025-03-01), the **alarm-to-mail OS command injection** via SMTP config
  item `0x1be1` (CVE-2025-41451, DSA-2025-08-01), the **nginx `headers.conf`
  config injection / `sm_app` crash DoS** via `action=load_nginx_headers`
  (CVE-2025-41452, DSA-2025-08-01), the AK-SM 800A `xml.cgi` **path traversal**
  (CVE-2023-25914, DSA-2023-08-01), and **debug/engineering-interface access**
  (Danfoss iC7 CVE-2026-15203, DSA-2026-08-01 — "debug and engineering
  interfaces with improper access control by default"). The redacted
  code-of-the-day algorithm is **not** reproduced; the handler matches only the
  documented request *shape* (extra auth attributes / a short date-derived
  numeric code) and never grants a real session or executes anything. See the
  `danfoss_aksm` row in the [README handler table](../README.md) for the full
  marker list.

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
| `beckhoffplc` | ADS/AMS 48898, TwinCAT AMS/UDP discovery 48899, Modbus 502, CX web 80 |
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
- Ready-to-run scenarios: `configs/tarpit-honeypot.example-ALL-OT.yaml` (a flat
  single-sensor decoy with **every** OT/ICS protocol in §2 enabled),
  `configs/tarpit-honeypot.example-ADVANCED-OT.yaml`,
  `configs/tarpit-honeypot.example-SMALL-OT.yaml`, and the `examples/ot-*.yaml`
  scenarios (`ot-substation`, `ot-power-grid`, `ot-discrete-mfg`,
  `ot-safety-dcs`) + the `examples/it-ot-dmz` IDMZ.

### Ready-made example configs

`configs/tarpit-honeypot.example-ALL-OT.yaml` is a flat, single-sensor decoy
that turns on every OT/ICS protocol listed in §2 (one listener per protocol on
its standard port, plus a small honeynet so the three TCP-102 protocols — S7comm,
S7comm-Plus, and IEC-61850 MMS — each get their own virtual IP);
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
- **Fingerprint-grade handlers** (`ge_srtp`, `hartip`, `crimson`, `fox`, `atg`, `focas`, `tristation`, `bsap`,
  `ge_egd`, `lontalk`) capture + flag the probe and return a believable
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
- **Shared port 102.** S7comm (`s7` / `s7comm_plus`), IEC 61850 MMS (`mms`),
  and ICCP/TASE.2 (also `mms` — it rides the same MMS stack, and the handler
  detects the TASE.2 profile at runtime) all live on TCP 102; pick the handler
  that matches the device you are pretending to be (a Siemens PLC vs a
  substation IED / control-center ICCP node), since a single listener serves
  one handler. Secure ICCP (`iccp_secure`) is MMS-over-TLS on TCP 3782.
- **ICCP/TASE.2 detection is heuristic.** The profile is inferred from the
  TASE.2 version OID and the TASE.2 object-name vocabulary appearing in the
  BER, not a full TASE.2 server — Block-1/2/5 operations are classified by
  object name, and no bilateral table or transfer-set engine is emulated.
- **No control-logic emulation.** There is no ladder/FBD/ST program, no tag
  database, and no I/O simulation; tag/symbol browsing beyond the canned
  identity is not served.

For the authoritative, always-current view of what a build implements, use
`tarpit-honeypot list-handlers` and the in-product **docs** tab (`/docs/ot`).

---

## 9. OT scanner & tool fingerprinting

The sensor attributes the *tool* behind a probe, not just the protocol. Two
layers cover the OT discovery / exploitation ecosystem:

- **HTTP/User-Agent layer** (`internal/toolfp`): the OT asset-discovery and
  monitoring platforms reach out over HTTP for enrichment, updates, and active
  queries with product-tagged User-Agents — **Claroty** (CTD/xDome),
  **Nozomi** Guardian, **Tenable.ot** (Indegy), **Forescout** SilentDefense,
  **Dragos**, **Otorio**, **ScadaFence** — and the internet-wide research
  crawlers (**Rapid7 Project Sonar**, Censys, Shodan, Shadowserver). The
  ICS exploitation toolkits (**ISF**, `smod`, `plcscan`, `s7scan`, `modscan`)
  are classified too. The OT discovery platforms register as vuln-scanners;
  ISF as an exploitation framework.
- **Binary-probe layer** (`internal/scananalysis`): the recon tools that drive
  a *control protocol* never carry a User-Agent, so they are fingerprinted by
  the documented bytes they send — nmap's ICS NSE scripts
  (`modbus-discover` Read-Device-ID / Report-Server-ID, `s7-info` COTP CR,
  `enip-info` ListIdentity, `bacnet-info`, `dnp3`, `pcworx-info`, `fox-info`),
  Metasploit's scada modules (e.g. Read-Exception-Status liveness), and the
  plcscan/s7scan family. These surface in the `scananalysis:profile` event's
  `nse_scripts` / `tool` fields. Attribution stays conservative: a probe shape
  shared by many tools names the *script* but not a vendor.

> **Passive monitors are invisible at the connection layer.** A purely passive
> OT sensor (the default mode for Claroty/Nozomi/Dragos) never initiates a
> connection, so a connection-level honeypot only ever sees these products when
> their *active-query* features or management/update clients reach out.

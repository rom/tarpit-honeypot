# Archetype catalog

`tarpit-honeypot` ships **164** OS / device *archetypes*. An archetype is a
coherent identity — the banners, SNMP MIB-2 identity, MAC vendor OUI, TLS
posture, ICMP TTL, default service map, web-UI body, and advertised
CVEs — that a real instance of a given operating system or device would
present on the wire. Pin one with `sensor.archetype`, `listener.archetype`,
or a honeynet host's `archetype`, and every fingerprint-bearing handler
answers consistently, so a scanner (nmap, Shodan, Censys, PRET, snmpwalk)
cannot catch the sensor on an internal inconsistency.

See [`README.md`](../README.md#os--device-archetypes) for precedence rules
and [`config.md`](config.md) for the schema. List the catalog at runtime
with `tarpit-honeypot list-archetypes` (add a name for the full
fingerprint, or `--json` for machine output).

## How vulnerabilities are emulated

Archetypes advertise CVEs in two ways, and **the honeypot is never actually
exploitable** either way:

- **Advisory** — the service advertises a version / patch-level that a real
  unpatched device would, so a version scanner records the box as
  vulnerable. The exploit, if attempted, is *detected and logged* (a
  high-severity `cve:<id>` event) but never executed. Enable the vulnerable
  banners with `vuln_emulation: true`.
- **Detectable** — the matching handler additionally recognizes the live
  exploit attempt's signature (see [`cli.md`](cli.md) → `list-cves`, the
  `DET` column) and raises the `cve:<id>` event on the spot.

Every archetype below lists the CVEs it advertises. Run
`tarpit-honeypot list-cves` for the full catalog with CVSS + detectability.

## Consistency & anachronism audit

An archetype is only useful if it has no *internal* anachronism — a feature
that could not coexist with the version it claims. The catalog is audited for
these; findings and fixes:

- **SSH algorithm timeline (fixed).** The server KEXINIT now advertises only
  the algorithms that existed in the OpenSSH release named in the banner. The
  generator buckets by the real feature timeline: `< 5.7` → no elliptic curve
  at all; `5.7–6.4` → NIST-curve ECDH/ECDSA but **no** Curve25519 / Ed25519 /
  chacha20 (those first shipped in **6.5**, Jan 2014); `6.5–7.x` → legacy set
  with 25519 + chacha20 + CBC/3DES; `≥ 8.0` → modern. This removes the classic
  *"OpenSSH 5.3 (2009) offering an Ed25519 host key"* tell (the CentOS 5 /
  CentOS 6 / HPE OnBoard Administrator archetypes were affected). A regression
  test (`TestSSHNoAlgorithmAnachronisms`) pins the mapping.
- **TLS posture vs OS era (fixed).** Old OSes no longer negotiate TLS they
  could not speak: **CentOS 5** (OpenSSL 0.9.8) is capped at TLS 1.0 with the
  legacy cipher suites, **CentOS 6** (OpenSSL 1.0.1) at TLS 1.2; the Windows
  7 / 8 / Server 2008 archetypes already pinned TLS 1.1 / 1.2 / 1.0
  respectively. A modern OS that advertised only SSLv3/TLS 1.0 would be an
  equal-and-opposite tell, so the modern archetypes keep the TLS 1.2+ default.
- **Verified-correct (no change).** Some apparent mismatches are historically
  accurate and were left alone: **Windows Server 2019** genuinely shipped
  *OpenSSH for Windows 7.7* (Win10 1809 lineage); **CentOS 5** really did ship
  OpenSSH 4.3 / Apache 2.2.3 / vsftpd 2.0.5 / MySQL 5.0.95; HPE OnBoard
  Administrator firmware legitimately runs a very old OpenSSH. Daemon versions
  are taken from each distro's package archive at the relevant point release.
- **IIS ↔ Windows mapping.** Windows Server 2016/2019/2022 → IIS 10.0; 2012 →
  8.0/8.5; 2008 R2 → 7.5 — verified consistent with each `httpServer`.

## Catalog at a glance

The full catalog (every archetype, complete and current) is below; `tarpit-honeypot list-archetypes` prints it at runtime and `list-archetypes <name>` shows one archetype's full fingerprint. The deep-dive sections that follow describe representative archetypes per family.

| Archetype | Name (`sensor.archetype`) | Family | Services |
|---|---|---|---|
| 3CX Phone System | `3cx` | 3cx | 4 |
| ABB AC500 PLC (PM573) | `abb-ac500` | abb | 6 |
| ABB RTU560 (substation RTU) | `abb-rtu560` | abb | 4 |
| ABB S500 remote I/O (CI502 PROFINET) | `abb-s500-io` | abb | 3 |
| Active Directory (Windows Server 2019 DC) | `active-directory` | windows | 13 |
| Advantech EKI-5528 (managed switch) | `advantech-eki-5528` | advantech | 4 |
| Allen-Bradley ControlLogix (Rockwell) | `rockwell-controllogix` | ics | 4 |
| AlmaLinux 9 | `almalinux-9` | rhel | 1 |
| Alpine Linux 3.20 | `alpine-3.20` | alpine | 3 |
| Amazon Linux 2023 | `amazon-linux-2023` | amazonlinux | 3 |
| APC Network Management Card (rPDU) | `apc-nmc` | apc | 4 |
| Arch Linux | `arch-linux` | arch | 1 |
| Arista EOS switch | `arista-eos` | arista | 4 |
| Asterisk PBX (VoIP) | `asterisk-voip` | voip | 3 |
| AudioCodes Mediant gateway | `audiocodes` | audiocodes | 4 |
| Avaya Aura Communication Manager | `avaya-aura` | avaya | 4 |
| Axis network camera | `axis-camera` | axis | 2 |
| B&R X20 (PLC) | `br-x20` | br | 4 |
| Bachmann M1 (controller) | `bachmann-m1` | bachmann | 4 |
| Beckhoff CX9020 (TwinCAT) | `beckhoff-cx` | beckhoff | 4 |
| Brother HL-L8260CDW (printer) | `brother-printer` | printer | 6 |
| Canon imageRUNNER ADVANCE (MFP) | `canon-imagerunner` | printer | 6 |
| CentOS 5 | `centos-5` | rhel | 0 |
| CentOS 6 | `centos-6` | rhel | 0 |
| CentOS 7 | `centos-7` | rhel | 0 |
| CentOS 8 | `centos-8` | rhel | 0 |
| CentOS Stream 10 | `centos-stream-10` | rhel | 0 |
| Check Point Gaia firewall | `checkpoint-gaia` | checkpoint | 2 |
| Cisco Catalyst 2960 (IOS 15) | `cisco-catalyst-2960` | cisco | 5 |
| Cisco Catalyst 9300 (IOS-XE 17) | `cisco-catalyst-9300` | cisco | 5 |
| Cisco Catalyst IE-3400 (IOS-XE 17) | `cisco-ie-3400` | cisco | 6 |
| Cisco Industrial Ethernet 2000 (IOS 15) | `cisco-ie-2000` | cisco | 6 |
| Cisco IR1101 (industrial router, IOS-XE) | `cisco-ir1101` | cisco | 6 |
| Cisco UCS CIMC | `cisco-ucs-cimc` | ciscoucs | 4 |
| Cisco Unified CM (CUCM) | `cisco-cucm` | ciscocucm | 4 |
| Citrix NetScaler ADC | `citrix-netscaler` | citrix | 2 |
| Debian 10 (buster) | `debian-10` | debian | 0 |
| Debian 11 (bullseye) | `debian-11` | debian | 0 |
| Debian 12 (bookworm) | `debian-12` | debian | 0 |
| Debian 13 (trixie) | `debian-13` | debian | 0 |
| Debian 9 (stretch) | `debian-9` | debian | 0 |
| Dell iDRAC 9 (lights-out) | `dell-idrac` | dell | 2 |
| DrayTek Vigor router | `draytek-vigor` | draytek | 2 |
| Emerson DeltaV (DCS controller) | `emerson-deltav` | emerson | 4 |
| Epson WorkForce Pro (MFP) | `epson-workforce` | printer | 6 |
| F5 BIG-IP (TMOS) | `f5-bigip` | f5 | 2 |
| Fedora 40 | `fedora-40` | fedora | 3 |
| Fortinet FortiGate (FortiOS) | `fortigate` | fortios | 4 |
| FreeBSD 13 | `freebsd-13` | bsd | 2 |
| FreeBSD 14 | `freebsd-14` | bsd | 1 |
| FreePBX (Sangoma) | `freepbx` | freepbx | 5 |
| FreeSWITCH | `freeswitch` | freeswitch | 4 |
| Fujitsu iRMC | `fujitsu-irmc` | fujitsu | 3 |
| GE PACSystems RX3i (PLC) | `ge-pacsystems` | ge | 4 |
| Gentoo Linux | `gentoo` | gentoo | 3 |
| Grandstream UCM (VoIP PBX) | `grandstream-ucm` | grandstream | 2 |
| Hikvision IP camera | `hikvision-camera` | hikvision | 3 |
| HIMA HIMax (safety PLC) | `hima-himax` | hima | 2 |
| Hirschmann EAGLE20 (industrial firewall) | `hirschmann-eagle20` | hirschmann | 3 |
| Hirschmann RS20 (Classic managed switch) | `hirschmann-rs20` | hirschmann | 4 |
| Hirschmann RSP35 (HiOS managed switch) | `hirschmann-rsp35` | hirschmann | 5 |
| Honeywell ControlEdge 900 (PLC/RTU) | `honeywell-controledge` | honeywell | 5 |
| Honeywell Experion C300 (DCS controller) | `honeywell-experion` | honeywell | 3 |
| HP LaserJet (network printer) | `hp-printer` | printer | 6 |
| HPE iLO 5 (lights-out) | `hpe-ilo` | hp | 2 |
| HPE Onboard Administrator | `hpe-oa` | hpeoa | 3 |
| Huawei VRP (router/switch) | `huawei-vrp` | huawei | 3 |
| IBM AIX 7.2 | `aix-7` | aix | 3 |
| Juniper SRX (JunOS) | `juniper-srx` | juniper | 4 |
| Konica Minolta bizhub C284e (MFP) | `konica-minolta-bizhub` | printer | 6 |
| Kyocera ECOSYS M3550idn (MFP) | `kyocera-ecosys` | printer | 6 |
| Lantronix SLC console server | `lantronix-slc` | lantronix | 4 |
| Lenovo XClarity Controller (XCC) | `lenovo-xcc` | lenovo | 3 |
| Lexmark MX622 (MFP) | `lexmark-printer` | printer | 6 |
| macOS Sonoma 14 | `macos-sonoma` | macos | 4 |
| MikroTik RouterOS (RB750Gr3, 6.49.10) | `mikrotik-routeros` | mikrotik | 7 |
| Mitel MiVoice Business | `mitel-mivoice` | mitel | 3 |
| Mitsubishi MELSEC iQ-R (R04CPU) | `mitsubishi-melsec-iq-r` | mitsubishi | 3 |
| Moxa AWK-3131A (industrial wireless AP) | `moxa-awk-3131a` | moxa | 5 |
| Moxa EDS-208 | `moxa-eds-208` | moxa | 3 |
| Moxa EDS-405A (managed switch) | `moxa-eds-405a` | moxa | 4 |
| Moxa EDS-G516E (gigabit managed switch) | `moxa-eds-g516e` | moxa | 5 |
| Moxa MGate MB3180 (Modbus gateway) | `moxa-mgate-mb3180` | moxa | 4 |
| Moxa NPort 5210 | `moxa-nport-5210` | moxa | 5 |
| Moxa NPort 5650-8 (serial device server) | `moxa-nport-5650` | moxa | 6 |
| Netgear Nighthawk router | `netgear-nighthawk` | netgear | 3 |
| Omron NX1P2 (Sysmac) | `omron-nx1p2` | omron | 4 |
| Omron PLC (FINS) | `omron-plc` | ics | 3 |
| OpenBSD 7.5 | `openbsd-7.5` | bsd | 2 |
| OpenBSD 7.6 | `openbsd-7.6` | bsd | 1 |
| Opengear console server | `opengear-cm` | opengear | 4 |
| OpenWrt router | `openwrt` | openwrt | 3 |
| OPNsense firewall | `opnsense` | opnsense | 2 |
| Oracle Linux 8 | `oracle-linux-8` | rhel | 1 |
| Oracle Linux 9 | `oracle-linux-9` | rhel | 1 |
| Oracle Solaris 11 | `solaris-11` | solaris | 4 |
| Oracle/Sun ILOM | `oracle-ilom` | ilom | 3 |
| Palo Alto PAN-OS firewall | `paloalto-panos` | paloalto | 2 |
| pfSense (Netgate firewall) | `pfsense` | pfsense | 4 |
| Phoenix Contact FL MGUARD (security router) | `phoenix-fl-mguard` | phoenix | 3 |
| Phoenix Contact FL SWITCH 2008 | `phoenix-fl-switch-2008` | phoenix | 3 |
| Poly/Polycom VVX phone | `polycom-vvx` | polycom | 3 |
| Proxmox VE 8 (Debian) | `proxmox-ve` | proxmox | 3 |
| QNAP Turbo NAS (QTS) | `qnap-qts` | qnap | 5 |
| Raritan Dominion KX (KVM) | `raritan-kx` | raritan | 4 |
| Raspberry Pi OS (Debian) | `raspberry-pi-os` | raspbian | 2 |
| Red Hat Enterprise Linux 10 | `rhel-10` | rhel | 0 |
| Red Hat Enterprise Linux 8 | `rhel-8` | rhel | 0 |
| Red Hat Enterprise Linux 9 | `rhel-9` | rhel | 0 |
| Ribbon SBC (session border controller) | `ribbon-sbc` | ribbon | 4 |
| Ricoh IM C3000 (MFP) | `ricoh-mfp` | printer | 6 |
| Rockwell MicroLogix 1400 (PLC) | `rockwell-micrologix` | rockwell | 4 |
| Rocky Linux 9 | `rocky-9` | rhel | 1 |
| Schneider Modicon M340 PLC | `schneider-modicon` | ics | 4 |
| Schneider Modicon M580 (BME P58) | `schneider-modicon-m580` | schneider | 5 |
| Schneider Triconex Tricon (SIS) | `triconex-tricon` | triconex | 3 |
| SEL-751 (protection relay) | `sel-751` | sel | 4 |
| Sharp MX-3071 (MFP) | `sharp-mfp` | printer | 6 |
| Siemens PN/PN Coupler | `siemens-pn-pn-coupler` | siemens | 3 |
| Siemens S7-1200 PLC | `siemens-s7-1200` | siemens | 3 |
| Siemens S7-1500 PLC | `siemens-s7-1500` | siemens | 5 |
| Siemens SCALANCE S615 | `siemens-scalance-s615` | siemens | 4 |
| Siemens SCALANCE SC-600 | `siemens-scalance-sc-600` | siemens | 3 |
| Siemens SCALANCE XB-208 | `siemens-scalance-xb-208` | siemens | 5 |
| SMA Sunny (solar inverter) | `sma-inverter` | sma | 4 |
| SonicWall TZ (SonicOS) | `sonicwall-tz` | sonicwall | 2 |
| Sophos XG firewall | `sophos-xg` | sophos | 2 |
| Supermicro BMC (IPMI/Redfish) | `supermicro-bmc` | supermicro | 4 |
| Synology DiskStation (DSM) | `synology-dsm` | synology | 5 |
| Teltonika RUT240 (RutOS, LTE router) | `teltonika-rut240` | teltonika | 4 |
| Teltonika RUT955 (industrial router, GPS) | `teltonika-rut955` | teltonika | 5 |
| Teltonika RUT956 (industrial router) | `teltonika-rut956` | teltonika | 5 |
| Teltonika RUTX11 (LTE Cat6 router) | `teltonika-rutx11` | teltonika | 4 |
| Teltonika TRB140 (LTE gateway) | `teltonika-trb140` | teltonika | 4 |
| TrueNAS CORE (FreeBSD) | `truenas-core` | truenas | 4 |
| Ubiquiti EdgeRouter (EdgeOS) | `ubiquiti-edgerouter` | ubiquiti | 3 |
| Ubuntu 24.04 LTS | `ubuntu-24.04` | ubuntu | 0 |
| Ubuntu 26.04 LTS | `ubuntu-26.04` | ubuntu | 0 |
| VMware ESXi 8.0 | `vmware-esxi` | esxi | 3 |
| VMware vCenter Server Appliance | `vmware-vcenter` | vmware | 2 |
| VyOS router | `vyos` | vyos | 3 |
| WAGO 750-8212 PFC200 | `wago-750-pfc` | wago | 7 |
| Westermo Ibex (industrial wireless) | `westermo-ibex` | westermo | 4 |
| Westermo Lynx (WeOS managed switch) | `westermo-lynx` | westermo | 5 |
| Westermo Merlin-4400 (cellular router) | `westermo-merlin-4400` | westermo | 4 |
| Westermo RedFox (rugged managed switch) | `westermo-redfox` | westermo | 5 |
| Westermo Viper (EN50155 rail switch) | `westermo-viper` | westermo | 4 |
| Windows 10 | `windows-10` | windows | 5 |
| Windows 11 | `windows-11` | windows | 5 |
| Windows 7 | `windows-7` | windows | 4 |
| Windows 8 | `windows-8` | windows | 3 |
| Windows Server 2008 | `windows-server-2008` | windows | 6 |
| Windows Server 2012 | `windows-server-2012` | windows | 6 |
| Windows Server 2012 R2 | `windows-server-2012-r2` | windows | 6 |
| Windows Server 2016 | `windows-server-2016` | windows | 6 |
| Windows Server 2019 | `windows-server-2019` | windows | 7 |
| Windows Server 2022 | `windows-server-2022` | windows | 7 |
| Xerox VersaLink C405 (MFP) | `xerox-versalink` | printer | 6 |
| Yealink IP phone | `yealink-phone` | yealink | 3 |
| Yokogawa CENTUM VP (DCS) | `yokogawa-centum` | yokogawa | 4 |
| Zebra ZT411 (label printer) | `zebra-printer` | printer | 3 |
| Zyxel USG FLEX firewall | `zyxel-usg` | zyxel | 2 |

## Linux distributions

### AlmaLinux 9 — `almalinux-9`

**Family:** rhel · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **SSH:** `SSH-2.0-OpenSSH_8.7`
- **HTTP Server:** `Apache/2.4.62 (AlmaLinux)`
- **SNMP sysDescr:** Linux alma9 5.14.0-427.31.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Mon Aug 12 x86_64
- **Services:** :22 `ssh`
- **CVEs advertised:** —

### Arch Linux — `arch-linux`

**Family:** arch · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **SSH:** `SSH-2.0-OpenSSH_9.9`
- **HTTP Server:** `nginx/1.27.3`
- **SNMP sysDescr:** Linux arch 6.10.10-arch1-1 #1 SMP PREEMPT_DYNAMIC x86_64
- **Services:** :22 `ssh`
- **CVEs advertised:** —

### CentOS 5 — `centos-5`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_4.3`
- **HTTP Server:** `Apache/2.2.3 (CentOS)`
- **Services:** —
- **CVEs advertised:** —

### CentOS 6 — `centos-6`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_5.3`
- **HTTP Server:** `Apache/2.2.15 (CentOS)`
- **Services:** —
- **CVEs advertised:** —

### CentOS 7 — `centos-7`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_7.4`
- **HTTP Server:** `Apache/2.4.6 (CentOS)`
- **Services:** —
- **CVEs advertised:** —

### CentOS 8 — `centos-8`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_8.0`
- **HTTP Server:** `Apache/2.4.37 (centos)`
- **Services:** —
- **CVEs advertised:** —

### CentOS Stream 10 — `centos-stream-10`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_9.9`
- **HTTP Server:** `Apache/2.4.62 (CentOS Stream)`
- **Services:** —
- **CVEs advertised:** —

### Debian 10 (buster) — `debian-10`

**Family:** debian · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4`
- **HTTP Server:** `Apache/2.4.38 (Debian)`
- **Services:** —
- **CVEs advertised:** —

### Debian 11 (bullseye) — `debian-11`

**Family:** debian · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3`
- **HTTP Server:** `Apache/2.4.62 (Debian)`
- **Services:** —
- **CVEs advertised:** —

### Debian 12 (bookworm) — `debian-12`

**Family:** debian · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`
- **HTTP Server:** `Apache/2.4.62 (Debian)`
- **Patch level:** Debian 12 (no 2024 security rollup)
- **Services:** —
- **CVEs advertised:** CVE-2021-41773, CVE-2018-15473

### Debian 13 (trixie) — `debian-13`

**Family:** debian · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_9.9p1 Debian-4`
- **HTTP Server:** `Apache/2.4.62 (Debian)`
- **Services:** —
- **CVEs advertised:** —

### Debian 9 (stretch) — `debian-9`

**Family:** debian · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7`
- **HTTP Server:** `Apache/2.4.25 (Debian)`
- **Services:** —
- **CVEs advertised:** —

### Oracle Linux 8 — `oracle-linux-8`

**Family:** rhel · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.111.1.1`

- **SSH:** `SSH-2.0-OpenSSH_8.0`
- **HTTP Server:** `Apache/2.4.37 (Oracle Linux Server)`
- **SNMP sysDescr:** Linux oracle8 4.18.0-553.16.1.el8_10.x86_64 #1 SMP Mon Aug 19 x86_64
- **Services:** :22 `ssh`
- **CVEs advertised:** —

### Oracle Linux 9 — `oracle-linux-9`

**Family:** rhel · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.111.1.1`

- **SSH:** `SSH-2.0-OpenSSH_8.7`
- **HTTP Server:** `Apache/2.4.62 (Oracle Linux Server)`
- **SNMP sysDescr:** Linux oracle9 5.14.0-427.31.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Aug 13 x86_64
- **Services:** :22 `ssh`
- **CVEs advertised:** —

### Red Hat Enterprise Linux 10 — `rhel-10`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_9.9`
- **HTTP Server:** `Apache/2.4.62 (Red Hat Enterprise Linux)`
- **Services:** —
- **CVEs advertised:** —

### Red Hat Enterprise Linux 8 — `rhel-8`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_8.0`
- **HTTP Server:** `Apache/2.4.37 (Red Hat Enterprise Linux)`
- **Services:** —
- **CVEs advertised:** —

### Red Hat Enterprise Linux 9 — `rhel-9`

**Family:** rhel · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_8.7`
- **HTTP Server:** `Apache/2.4.62 (Red Hat Enterprise Linux)`
- **Services:** —
- **CVEs advertised:** —

### Rocky Linux 9 — `rocky-9`

**Family:** rhel · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **SSH:** `SSH-2.0-OpenSSH_8.7`
- **HTTP Server:** `Apache/2.4.62 (Rocky Linux)`
- **SNMP sysDescr:** Linux rocky9 5.14.0-427.31.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Aug 13 x86_64
- **Services:** :22 `ssh`
- **CVEs advertised:** —

### Ubuntu 24.04 LTS — `ubuntu-24.04`

**Family:** ubuntu · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`
- **HTTP Server:** `Apache/2.4.58 (Ubuntu)`
- **Services:** —
- **CVEs advertised:** —

### Ubuntu 26.04 LTS — `ubuntu-26.04`

**Family:** ubuntu · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_10.0p1 Ubuntu-1`
- **HTTP Server:** `Apache/2.4.62 (Ubuntu)`
- **Services:** —
- **CVEs advertised:** —


## BSD

### FreeBSD 13 — `freebsd-13`

**Family:** bsd · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.2238.1.0`

- **SSH:** `SSH-2.0-OpenSSH_8.8 FreeBSD-20211221`
- **HTTP Server:** `Apache/2.4.62 (FreeBSD)`
- **SNMP sysDescr:** FreeBSD host.example.com 13.3-RELEASE FreeBSD 13.3-RELEASE GENERIC amd64
- **Services:** :22 `ssh`, :25 `smtp_recv`
- **CVEs advertised:** —

### FreeBSD 14 — `freebsd-14`

**Family:** bsd · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.2238.1.0`

- **SSH:** `SSH-2.0-OpenSSH_9.5 FreeBSD-20231004`
- **HTTP Server:** `Apache/2.4.62 (FreeBSD)`
- **SNMP sysDescr:** FreeBSD host.example.com 14.1-RELEASE FreeBSD 14.1-RELEASE GENERIC amd64
- **Services:** :22 `ssh`
- **CVEs advertised:** —

### OpenBSD 7.5 — `openbsd-7.5`

**Family:** bsd · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.30155.1.1`

- **SSH:** `SSH-2.0-OpenSSH_9.7`
- **HTTP Server:** `OpenBSD httpd`
- **SNMP sysDescr:** OpenBSD obsd.example.com 7.5 GENERIC#10 amd64
- **Services:** :22 `ssh`, :25 `smtp_recv`
- **CVEs advertised:** —

### OpenBSD 7.6 — `openbsd-7.6`

**Family:** bsd · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.30155.1.1`

- **SSH:** `SSH-2.0-OpenSSH_9.8`
- **HTTP Server:** `OpenBSD httpd`
- **SNMP sysDescr:** OpenBSD obsd.example.com 7.6 GENERIC#10 amd64
- **Services:** :22 `ssh`
- **CVEs advertised:** —


## Windows & Active Directory

### Active Directory (Windows Server 2019 DC) — `active-directory`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **HTTP Server:** `Microsoft-IIS/10.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)
- **Patch level:** Windows Server 2019 RTM (build 17763.107, pre-2020-08 rollup)
- **Services:** :53 `dns`, :88 `kerberos`, :135 `dcerpc`, :139 `raw`, :389 `ldap`, :445 `smb`, :464 `raw`, :636 `https`, :3268 `ldap`, :3269 `https`, :3389 `rdp`, :5985 `winrm`, :9389 `raw`
- **CVEs advertised:** CVE-2020-1472, CVE-2021-34527, CVE-2021-26855, CVE-2021-42278

### Windows 10 — `windows-10`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.1`

- **SSH:** `SSH-2.0-OpenSSH_for_Windows_8.1`
- **HTTP Server:** `Microsoft-IIS/10.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 19045 Multiprocessor Free)
- **Services:** :22 `ssh`, :135 `dcerpc`, :445 `smb`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —

### Windows 11 — `windows-11`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.1`

- **SSH:** `SSH-2.0-OpenSSH_for_Windows_9.5`
- **HTTP Server:** `Microsoft-IIS/10.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 22631 Multiprocessor Free)
- **Services:** :22 `ssh`, :135 `dcerpc`, :445 `smb`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —

### Windows 7 — `windows-7`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.1`

- **HTTP Server:** `Microsoft-IIS/7.5`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 Model 60 Stepping 3 AT/AT COMPATIBLE - Software: Windows Version 6.1 (Build 7601 Multiprocessor Free)
- **Services:** :135 `dcerpc`, :139 `raw`, :445 `smb`, :3389 `rdp`
- **CVEs advertised:** —

### Windows 8 — `windows-8`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.1`

- **HTTP Server:** `Microsoft-IIS/8.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 6.2 (Build 9200 Multiprocessor Free)
- **Services:** :135 `dcerpc`, :445 `smb`, :3389 `rdp`
- **CVEs advertised:** —

### Windows Server 2008 — `windows-server-2008`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **HTTP Server:** `Microsoft-IIS/7.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 6.0 (Build 6002 Multiprocessor Free)
- **Services:** :135 `dcerpc`, :139 `raw`, :445 `smb`, :389 `ldap`, :88 `kerberos`, :3389 `rdp`
- **CVEs advertised:** —

### Windows Server 2012 — `windows-server-2012`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **HTTP Server:** `Microsoft-IIS/8.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 6.2 (Build 9200 Multiprocessor Free)
- **Services:** :135 `dcerpc`, :445 `smb`, :389 `ldap`, :88 `kerberos`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —

### Windows Server 2012 R2 — `windows-server-2012-r2`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **HTTP Server:** `Microsoft-IIS/8.5`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 6.3 (Build 9600 Multiprocessor Free)
- **Services:** :135 `dcerpc`, :445 `smb`, :389 `ldap`, :88 `kerberos`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —

### Windows Server 2016 — `windows-server-2016`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **HTTP Server:** `Microsoft-IIS/10.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 14393 Multiprocessor Free)
- **Services:** :135 `dcerpc`, :445 `smb`, :389 `ldap`, :88 `kerberos`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —

### Windows Server 2019 — `windows-server-2019`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **SSH:** `SSH-2.0-OpenSSH_for_Windows_7.7`
- **HTTP Server:** `Microsoft-IIS/10.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 17763 Multiprocessor Free)
- **Services:** :22 `ssh`, :135 `dcerpc`, :445 `smb`, :389 `ldap`, :88 `kerberos`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —

### Windows Server 2022 — `windows-server-2022`

**Family:** windows · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.311.1.1.3.1.2`

- **SSH:** `SSH-2.0-OpenSSH_for_Windows_8.6`
- **HTTP Server:** `Microsoft-IIS/10.0`
- **SNMP sysDescr:** Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 20348 Multiprocessor Free)
- **Services:** :22 `ssh`, :135 `dcerpc`, :445 `smb`, :389 `ldap`, :88 `kerberos`, :3389 `rdp`, :5985 `winrm`
- **CVEs advertised:** —


## Network infrastructure

### Cisco Catalyst 2960 (IOS 15) — `cisco-catalyst-2960`

**Family:** cisco · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.9.1.716`

- **SSH:** `SSH-2.0-Cisco-1.25`
- **HTTP Server:** `cisco-IOS`
- **SNMP sysDescr:** Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
- **Patch level:** 15.0(2)SE11
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** CVE-2018-0171

### Cisco Catalyst 9300 (IOS-XE 17) — `cisco-catalyst-9300`

**Family:** cisco · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.9.1.2494`

- **SSH:** `SSH-2.0-Cisco-1.25`
- **HTTP Server:** `cisco-IOS`
- **SNMP sysDescr:** Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc1)
- **Patch level:** 15.0(2)SE11
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** CVE-2018-0171

### Cisco Catalyst IE-3400 (IOS-XE 17) — `cisco-ie-3400`

**Family:** cisco · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.9.1.2920`

- **SSH:** `SSH-2.0-Cisco-1.25`
- **HTTP Server:** `cisco-IOS`
- **SNMP sysDescr:** Cisco IOS Software [Cupertino], IE3400 Switch Software (IE3400-UNIVERSALK9-M), Version 17.9.4, RELEASE SOFTWARE (fc1)
- **Patch level:** IOS 15.2(7)E3
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`, :4840 `opcua`
- **CVEs advertised:** —

### Cisco IR1101 (industrial router, IOS-XE) — `cisco-ir1101`

**Family:** cisco · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.9.1.2601`

- **SSH:** `SSH-2.0-Cisco-1.25`
- **HTTP Server:** `cisco-IOS`
- **SNMP sysDescr:** Cisco IOS Software [Cupertino], ir1101 Software (ir1101-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc1)
- **Patch level:** IOS 15.2(7)E3
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`, :4840 `opcua`
- **CVEs advertised:** —

### Cisco Industrial Ethernet 2000 (IOS 15) — `cisco-ie-2000`

**Family:** cisco · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.9.1.1409`

- **SSH:** `SSH-2.0-Cisco-1.25`
- **HTTP Server:** `cisco-IOS`
- **SNMP sysDescr:** Cisco IOS Software, IE2000 Software (IE2000-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)
- **Patch level:** IOS 15.2(7)E3
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`, :4840 `opcua`
- **CVEs advertised:** —

### MikroTik RouterOS (RB750Gr3, 6.49.10) — `mikrotik-routeros`

**Family:** mikrotik · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.14988.1`

- **SSH:** `SSH-2.0-ROSSSH`
- **SNMP sysDescr:** RouterOS RB750Gr3
- **Services:** :22 `ssh`, :23 `telnet`, :21 `ftp`, :80 `http`, :8291 `raw`, :8728 `raw`, :161 `snmp`
- **CVEs advertised:** —

### Ubiquiti EdgeRouter (EdgeOS) — `ubiquiti-edgerouter`

**Family:** ubiquiti · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.41112`

- **SSH:** `SSH-2.0-OpenSSH_7.4 Debian`
- **HTTP Server:** `lighttpd`
- **SNMP sysDescr:** EdgeOS v2.0.9 ER-X
- **Services:** :443 `https`, :22 `ssh`, :161 `snmp`
- **CVEs advertised:** —


## Security & storage appliances

### Fortinet FortiGate (FortiOS) — `fortigate`

**Family:** fortios · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.12356.101.1.6001`

- **SSH:** `SSH-2.0-OpenSSH_7.4`
- **HTTP Server:** `xxxxxxxx-xxxxx`
- **SNMP sysDescr:** FortiGate-60F
- **Patch level:** FortiOS 6.0.4
- **Services:** :443 `https`, :22 `ssh`, :10443 `https`, :161 `snmp`
- **CVEs advertised:** CVE-2018-13379

### QNAP Turbo NAS (QTS) — `qnap-qts`

**Family:** qnap · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.24681.1`

- **SSH:** `SSH-2.0-OpenSSH_8.4`
- **HTTP Server:** `http server`
- **SNMP sysDescr:** QNAP TS-453D QTS 5.0
- **Services:** :8080 `http`, :443 `https`, :445 `smb`, :22 `ssh`, :21 `ftp`
- **CVEs advertised:** —

### Synology DiskStation (DSM) — `synology-dsm`

**Family:** synology · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.6574.1`

- **SSH:** `SSH-2.0-OpenSSH_8.2p1`
- **HTTP Server:** `nginx`
- **SNMP sysDescr:** Synology DS920+ DSM 7.2
- **Services:** :5000 `http`, :5001 `https`, :445 `smb`, :22 `ssh`, :21 `ftp`
- **CVEs advertised:** —

### pfSense (Netgate firewall) — `pfsense`

**Family:** pfsense · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.12325.1.1.2.1.1`

- **SSH:** `SSH-2.0-OpenSSH_8.8 FreeBSD-20211221`
- **HTTP Server:** `nginx`
- **SNMP sysDescr:** pfSense fw01.local FreeBSD 14.0-RELEASE-p6 amd64
- **Services:** :443 `https`, :80 `http`, :22 `ssh`, :161 `snmp`
- **CVEs advertised:** —


## IP cameras & VoIP

### Asterisk PBX (VoIP) — `asterisk-voip`

**Family:** voip · **TTL:** 64

- **SSH:** `SSH-2.0-OpenSSH_8.9p1 Ubuntu`
- **HTTP Server:** `Asterisk/18.10.0`
- **SNMP sysDescr:** Asterisk PBX 18.10.0 on Linux
- **Services:** :5060 `sip`, :80 `http`, :22 `ssh`
- **CVEs advertised:** —

### Axis network camera — `axis-camera`

**Family:** axis · **TTL:** 64

- **HTTP Server:** `Apache/2.4.53`
- **SNMP sysDescr:** AXIS M3045-V Network Camera
- **Services:** :80 `http`, :554 `rtsp`
- **CVEs advertised:** —

### Hikvision IP camera — `hikvision-camera`

**Family:** hikvision · **TTL:** 64

- **HTTP Server:** `App-webs/`
- **SNMP sysDescr:** Hikvision DS-2CD2042WD-I
- **Patch level:** V5.4.0
- **Services:** :80 `http`, :554 `rtsp`, :8000 `raw`
- **CVEs advertised:** CVE-2017-7921


## Printers & multi-function devices

### Brother HL-L8260CDW (printer) — `brother-printer`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.2435.2.3.9.1`

- **HTTP Server:** `debut/1.20`
- **SNMP sysDescr:** Brother HL-L8260CDW series
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### Canon imageRUNNER ADVANCE (MFP) — `canon-imagerunner`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.1602.4.7`

- **HTTP Server:** `Canon HTTP Server`
- **SNMP sysDescr:** Canon iR-ADV C5550i /P
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### Epson WorkForce Pro (MFP) — `epson-workforce`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.1248.1.2.2.1.1`

- **HTTP Server:** `EPSON-HTTP/1.0`
- **SNMP sysDescr:** EPSON WF-C5790 Series
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### HP LaserJet (network printer) — `hp-printer`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.11.2.3.9.1`

- **HTTP Server:** `HP HTTP Server; HP LaserJet`
- **SNMP sysDescr:** HP LaserJet MFP M428fdw
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### Konica Minolta bizhub C284e (MFP) — `konica-minolta-bizhub`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.18334.1.1.1.1.1`

- **HTTP Server:** `KM-MFP-Http/1.0`
- **SNMP sysDescr:** KONICA MINOLTA bizhub C284e
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### Kyocera ECOSYS M3550idn (MFP) — `kyocera-ecosys`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.1347.43`

- **HTTP Server:** `KM-httpd/1.0`
- **SNMP sysDescr:** Kyocera ECOSYS M3550idn
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** CVE-2022-1026

### Lexmark MX622 (MFP) — `lexmark-printer`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.641.6`

- **HTTP Server:** `Lexmark_Web_Server`
- **SNMP sysDescr:** Lexmark MX622
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** CVE-2023-26067

### Ricoh IM C3000 (MFP) — `ricoh-mfp`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.367.1.1`

- **HTTP Server:** `Web-Server/3.0`
- **SNMP sysDescr:** RICOH IM C3000
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### Sharp MX-3071 (MFP) — `sharp-mfp`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.2385.1.1`

- **HTTP Server:** `Boa/0.94.13`
- **SNMP sysDescr:** SHARP MX-3071
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** —

### Xerox VersaLink C405 (MFP) — `xerox-versalink`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.253.8.62.1.25.1`

- **HTTP Server:** `Xerox_MicroServer/Xerox(R)`
- **SNMP sysDescr:** Xerox VersaLink C405; SS 73.61.21; UI 1.5.2
- **Services:** :80 `http`, :443 `https`, :9100 `pjl`, :631 `ipp`, :515 `lpd`, :161 `snmp`
- **CVEs advertised:** CVE-2024-12510

### Zebra ZT411 (label printer) — `zebra-printer`

**Family:** printer · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.10642.1`

- **HTTP Server:** `ZebraNet`
- **SNMP sysDescr:** ZTC ZT411-203dpi, V93.21.06Z
- **Services:** :80 `http`, :9100 `pjl`, :161 `snmp`
- **CVEs advertised:** —


## Industrial / OT (PLCs, RTUs, switches, routers)

### ABB AC500 PLC (PM573) — `abb-ac500`

**Family:** abb · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **HTTP Server:** `ABB`
- **SNMP sysDescr:** ABB AC500 PM573-ETH PLC
- **Services:** :80 `http`, :443 `https`, :1217 `codesys`, :502 `modbus`, :44818 `ethernetip`, :161 `snmp`
- **CVEs advertised:** —

### ABB RTU560 (substation RTU) — `abb-rtu560`

**Family:** abb · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **HTTP Server:** `ABB`
- **SNMP sysDescr:** ABB RTU560 telecontrol unit
- **Services:** :80 `http`, :161 `snmp`, :2404 `iec104`, :102 `mms`
- **CVEs advertised:** —

### ABB S500 remote I/O (CI502 PROFINET) — `abb-s500-io`

**Family:** abb · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **HTTP Server:** `ABB`
- **SNMP sysDescr:** ABB S500 CI502-PNIO PROFINET I/O adapter
- **Services:** :80 `http`, :161 `snmp`, :34964 `raw`
- **CVEs advertised:** —

### Advantech EKI-5528 (managed switch) — `advantech-eki-5528`

**Family:** advantech · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.10297.202.5528`

- **HTTP Server:** `Boa/0.94.14rc21`
- **SNMP sysDescr:** Advantech EKI-5528 8FE Managed Ethernet Switch
- **Services:** :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Allen-Bradley ControlLogix (Rockwell) — `rockwell-controllogix`

**Family:** ics · **TTL:** 64

- **HTTP Server:** `Allen-Bradley`
- **SNMP sysDescr:** 1756-L75 ControlLogix 5575
- **Services:** :44818 `ethernetip`, :2222 `raw`, :80 `http`, :161 `snmp`
- **CVEs advertised:** —

### Beckhoff CX9020 (TwinCAT) — `beckhoff-cx`

**Family:** beckhoff · **TTL:** 128 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **HTTP Server:** `TwinCAT`
- **SNMP sysDescr:** Beckhoff CX9020 TwinCAT 3 Embedded PC
- **Services:** :80 `http`, :161 `snmp`, :48898 `ads`, :502 `modbus`
- **CVEs advertised:** —

### Hirschmann EAGLE20 (industrial firewall) — `hirschmann-eagle20`

**Family:** hirschmann · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.248.14.3`

- **SSH:** `SSH-2.0-OpenSSH_7.4`
- **HTTP Server:** `Hirschmann WebInterface`
- **SNMP sysDescr:** Hirschmann EAGLE One, SW: EAGLE-05.3.00
- **Services:** :22 `ssh`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Hirschmann RS20 (Classic managed switch) — `hirschmann-rs20`

**Family:** hirschmann · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.248.14.1`

- **HTTP Server:** `Hirschmann WebInterface`
- **SNMP sysDescr:** Hirschmann RS20-0800M2M2SDAEHC, SW: L2E-09.0.00
- **Services:** :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Hirschmann RSP35 (HiOS managed switch) — `hirschmann-rsp35`

**Family:** hirschmann · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.248.14.2`

- **SSH:** `SSH-2.0-OpenSSH_7.4`
- **HTTP Server:** `Hirschmann WebInterface`
- **SNMP sysDescr:** Hirschmann RSP35, HiOS-2A-08.5.00
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Honeywell ControlEdge 900 (PLC/RTU) — `honeywell-controledge`

**Family:** honeywell · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **HTTP Server:** `ControlEdge`
- **SNMP sysDescr:** Honeywell ControlEdge 900 Controller
- **Services:** :80 `http`, :443 `https`, :502 `modbus`, :2404 `iec104`, :161 `snmp`
- **CVEs advertised:** —

### Honeywell Experion C300 (DCS controller) — `honeywell-experion`

**Family:** honeywell · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.8072.3.2.10`

- **HTTP Server:** `Experion`
- **SNMP sysDescr:** Honeywell Experion PKS C300 Process Controller
- **Services:** :80 `http`, :161 `snmp`, :502 `modbus`
- **CVEs advertised:** —

### Moxa AWK-3131A (industrial wireless AP) — `moxa-awk-3131a`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.15.1`

- **SSH:** `SSH-2.0-MoxaSSH_1.0`
- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa AirWorks AWK-3131A
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Moxa EDS-208 — `moxa-eds-208`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.7.1`

- **SSH:** `SSH-2.0-MoxaCLI_1.0`
- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa EtherDevice Switch EDS-208
- **Services:** :23 `telnet`, :80 `http`, :161 `snmp`
- **CVEs advertised:** —

### Moxa EDS-405A (managed switch) — `moxa-eds-405a`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.7.6`

- **SSH:** `SSH-2.0-MoxaCLI_1.0`
- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa EtherDevice Switch EDS-405A
- **Services:** :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Moxa EDS-G516E (gigabit managed switch) — `moxa-eds-g516e`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.7.20`

- **SSH:** `SSH-2.0-MoxaCLI_1.0`
- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa EtherDevice Switch EDS-G516E-4GSFP
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Moxa MGate MB3180 (Modbus gateway) — `moxa-mgate-mb3180`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.10.3`

- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa MGate MB3180 V2.3
- **Services:** :23 `telnet`, :80 `http`, :161 `snmp`, :502 `modbus`
- **CVEs advertised:** —

### Moxa NPort 5210 — `moxa-nport-5210`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.5.5`

- **SSH:** `SSH-2.0-MoxaSSH_1.0`
- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa NPort 5210 V2.7
- **Services:** :23 `telnet`, :80 `http`, :161 `snmp`, :4001 `raw`, :4002 `raw`
- **CVEs advertised:** —

### Moxa NPort 5650-8 (serial device server) — `moxa-nport-5650`

**Family:** moxa · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.8691.5.8`

- **SSH:** `SSH-2.0-MoxaSSH_1.0`
- **HTTP Server:** `Moxa-HTTPd`
- **SNMP sysDescr:** Moxa NPort 5650-8 V3.8
- **Services:** :23 `telnet`, :80 `http`, :161 `snmp`, :4001 `raw`, :4002 `raw`, :4008 `raw`
- **CVEs advertised:** —

### Omron PLC (FINS) — `omron-plc`

**Family:** ics · **TTL:** 64

- **HTTP Server:** `OMRON`
- **SNMP sysDescr:** OMRON CJ2M-CPU
- **Services:** :9600 `fins`, :44818 `ethernetip`, :80 `http`
- **CVEs advertised:** —

### Phoenix Contact FL MGUARD (security router) — `phoenix-fl-mguard`

**Family:** phoenix · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.4346.11.2`

- **SSH:** `SSH-2.0-OpenSSH_7.9 mGuard`
- **HTTP Server:** `mGuard`
- **SNMP sysDescr:** Phoenix Contact FL MGUARD RS4000, mGuard 8.8.0
- **Services:** :22 `ssh`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Phoenix Contact FL SWITCH 2008 — `phoenix-fl-switch-2008`

**Family:** phoenix · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.4346.11.1`

- **HTTP Server:** `Allegro-Software-RomPager/4.51`
- **SNMP sysDescr:** Phoenix Contact FL SWITCH 2008, FW 1.40
- **Services:** :23 `telnet`, :80 `http`, :161 `snmp`
- **CVEs advertised:** —

### Schneider Modicon M340 PLC — `schneider-modicon`

**Family:** ics · **TTL:** 64

- **HTTP Server:** `Schneider-WEB/V`
- **SNMP sysDescr:** BMX P34 2020 Modicon M340
- **Services:** :502 `modbus`, :44818 `ethernetip`, :80 `http`, :161 `snmp`
- **CVEs advertised:** —

### Siemens PN/PN Coupler — `siemens-pn-pn-coupler`

**Family:** siemens · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.4196.1.1.5.2.60`

- **HTTP Server:** `Siemens Web Server`
- **SNMP sysDescr:** Siemens, SIMATIC NET, PN/PN Coupler, 6ES7158-3AD10-0XA0
- **Services:** :80 `http`, :161 `snmp`, :34964 `raw`
- **CVEs advertised:** —

### Siemens S7-1200 PLC — `siemens-s7-1200`

**Family:** siemens · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.4196.1.1.5.2.22`

- **HTTP Server:** `Siemens Web Server`
- **SNMP sysDescr:** Siemens, SIMATIC S7, CPU-1200, 6ES7 212-1AE40-0XB0, HW: 4, FW: V4.5.1
- **Services:** :80 `http`, :102 `s7`, :161 `snmp`
- **CVEs advertised:** —

### Siemens S7-1500 PLC — `siemens-s7-1500`

**Family:** siemens · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.4196.1.1.5.2.23`

- **HTTP Server:** `Siemens Web Server`
- **SNMP sysDescr:** Siemens, SIMATIC S7, CPU-1500, 6ES7 516-3AN02-0AB0, HW: 6, FW: V2.9.4
- **Services:** :80 `http`, :443 `https`, :102 `s7`, :161 `snmp`, :4840 `opcua`
- **CVEs advertised:** —

### Siemens SCALANCE S615 — `siemens-scalance-s615`

**Family:** siemens · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.4196.1.1.5.2.42`

- **SSH:** `SSH-2.0-SCALANCE_S615_v07.02`
- **HTTP Server:** `Siemens Web Server`
- **SNMP sysDescr:** Siemens, SIMATIC NET, SCALANCE S615, 6GK5615-0AA00-2AA2, HW: 2, FW: V07.02.00
- **Services:** :22 `ssh`, :443 `https`, :161 `snmp`, :500 `raw`
- **CVEs advertised:** —

### Siemens SCALANCE SC-600 — `siemens-scalance-sc-600`

**Family:** siemens · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.4196.1.1.5.2.55`

- **SSH:** `SSH-2.0-SCALANCE_SC600_v02.03`
- **HTTP Server:** `Siemens Web Server`
- **SNMP sysDescr:** Siemens, SIMATIC NET, SCALANCE SC636-2C, 6GK5636-2GS00-2AC2, HW: 1, FW: V02.03.02
- **Services:** :22 `ssh`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Siemens SCALANCE XB-208 — `siemens-scalance-xb-208`

**Family:** siemens · **TTL:** 255 · **SNMP OID:** `.1.3.6.1.4.1.4196.1.1.5.2.30`

- **SSH:** `SSH-2.0-SCALANCE_X-200_v06.01.01`
- **HTTP Server:** `Siemens Web Server`
- **SNMP sysDescr:** Siemens, SIMATIC NET, SCALANCE XB-208, 6GK5208-0BA00-2AB2, HW: 4, FW: V06.01.01
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Teltonika RUT240 (RutOS, LTE router) — `teltonika-rut240`

**Family:** teltonika · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.48690`

- **SSH:** `SSH-2.0-dropbear`
- **HTTP Server:** `lighttpd/1.4.59`
- **SNMP sysDescr:** Teltonika RUT240 RutOS
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Teltonika RUT955 (industrial router, GPS) — `teltonika-rut955`

**Family:** teltonika · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.48690`

- **SSH:** `SSH-2.0-dropbear`
- **HTTP Server:** `lighttpd/1.4.59`
- **SNMP sysDescr:** Teltonika RUT955 RutOS
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`, :502 `modbus`
- **CVEs advertised:** —

### Teltonika RUT956 (industrial router) — `teltonika-rut956`

**Family:** teltonika · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.48690`

- **SSH:** `SSH-2.0-dropbear`
- **HTTP Server:** `nginx`
- **SNMP sysDescr:** Teltonika RUT956 RutOS
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`, :502 `modbus`
- **CVEs advertised:** —

### Teltonika RUTX11 (LTE Cat6 router) — `teltonika-rutx11`

**Family:** teltonika · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.48690`

- **SSH:** `SSH-2.0-dropbear`
- **HTTP Server:** `nginx`
- **SNMP sysDescr:** Teltonika RUTX11 RutOS
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Teltonika TRB140 (LTE gateway) — `teltonika-trb140`

**Family:** teltonika · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.48690`

- **SSH:** `SSH-2.0-dropbear`
- **HTTP Server:** `lighttpd/1.4.59`
- **SNMP sysDescr:** Teltonika TRB140 RutOS
- **Services:** :22 `ssh`, :80 `http`, :161 `snmp`, :502 `modbus`
- **CVEs advertised:** —

### WAGO 750-8212 PFC200 — `wago-750-pfc`

**Family:** wago · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.13576.10.1`

- **SSH:** `SSH-2.0-OpenSSH_8.4 WAGO`
- **HTTP Server:** `lighttpd`
- **SNMP sysDescr:** WAGO 750-8212 PFC200 CS 2ETH RS
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :502 `modbus`, :1217 `codesys`, :2455 `raw`, :161 `snmp`
- **CVEs advertised:** —

### Westermo Ibex (industrial wireless) — `westermo-ibex`

**Family:** westermo · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.16177.1.7.1`

- **SSH:** `SSH-2.0-OpenSSH_7.4 WeOS`
- **HTTP Server:** `GoAhead-Webs`
- **SNMP sysDescr:** Westermo Ibex-RT-310 WeOS v4.32.4
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Westermo Lynx (WeOS managed switch) — `westermo-lynx`

**Family:** westermo · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.16177.1.5.1`

- **SSH:** `SSH-2.0-OpenSSH_7.4 WeOS`
- **HTTP Server:** `GoAhead-Webs`
- **SNMP sysDescr:** Westermo Lynx L108-F2G WeOS v4.32.4
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Westermo Merlin-4400 (cellular router) — `westermo-merlin-4400`

**Family:** westermo · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.16177.1.6.1`

- **SSH:** `SSH-2.0-OpenSSH_8.4 WeOS`
- **HTTP Server:** `lighttpd`
- **SNMP sysDescr:** Westermo Merlin-4400 LTE router
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Westermo RedFox (rugged managed switch) — `westermo-redfox`

**Family:** westermo · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.16177.1.5.2`

- **SSH:** `SSH-2.0-OpenSSH_7.4 WeOS`
- **HTTP Server:** `GoAhead-Webs`
- **SNMP sysDescr:** Westermo RedFox RFI-219-F4G WeOS v4.32.4
- **Services:** :22 `ssh`, :23 `telnet`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —

### Westermo Viper (EN50155 rail switch) — `westermo-viper`

**Family:** westermo · **TTL:** 64 · **SNMP OID:** `.1.3.6.1.4.1.16177.1.5.3`

- **SSH:** `SSH-2.0-OpenSSH_7.4 WeOS`
- **HTTP Server:** `GoAhead-Webs`
- **SNMP sysDescr:** Westermo Viper-212-T3G WeOS v4.32.4
- **Services:** :22 `ssh`, :80 `http`, :443 `https`, :161 `snmp`
- **CVEs advertised:** —


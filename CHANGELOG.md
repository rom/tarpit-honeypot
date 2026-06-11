# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
semantic versioning loosely (this is single-binary infrastructure, not a
library, so the public-API contract is the YAML schema + CLI surface
documented in `docs/`).

## [Unreleased]

### Added

- **Configurable BGP Autonomous System (`sensor.bgp_as`).** The `bgp` decoy can
  now present a believable router identity: when `sensor.bgp_as` is set, it
  answers a peer's OPEN with its own OPEN advertising that AS (My Autonomous
  System; ASNs > 65535 are sent as AS_TRANS with the real value in the 4-octet-
  ASN capability, RFC 6793) before declining with a NOTIFICATION (Cease). With
  no AS configured it replies NOTIFICATION only, as before. The AS is carried on
  the deployment identity, so every BGP responder (top-level listener and
  honeynet `{handler: bgp}` services) shares it. `install.sh` gained a
  `--bgp-as` flag / `TARPIT_BGP_AS` env and prompts for the AS when a deployed
  config runs the BGP service but `sensor.bgp_as` is unset, saving it to the
  config. The captured event records `bgp_local_as`.

- **TR-069 (CWMP), TR-369 (USP) and UPnP device-management handlers.** Three new
  TCP handlers cover the CPE / IoT remote-management attack surface end to end —
  attack **intent**, protocol **fingerprint**, **decoy** response, **CVE/CWE**,
  and **ATT&CK**:
  - `tr069` (CWMP connection-request, classically TCP 7547): serves a RomPager
    Digest 401 / CWMP `InformResponse` decoy; fingerprints the SOAP action +
    CWMP method + the spoofed device identity (`cwmp_oui`/`cwmp_serial`);
    recognizes the **Misfortune Cookie** (CVE-2014-9222, CWE-787), the **TR-064
    SetNTPServers RCE** reachable on 7547 (CVE-2016-10372, CWE-78 — the 2016
    Deutsche Telekom / Mirai outage), firmware-push (`Download`) and disruptive
    RPCs (reboot / factory-reset).
  - `upnp` (UPnP IGD SOAP control + GENA eventing): serves a believable
    `rootDesc.xml` / SOAP action response; flags **UPnProxy** `AddPortMapping`
    NAT injection (CWE-441), **CallStranger** SUBSCRIBE-callback SSRF
    (CVE-2020-12695, CWE-918), NAT-table enumeration, and Realtek/Huawei SOAP
    command injection (CVE-2014-8361 / CVE-2017-17215, CWE-78).
  - `tr369` (USP agent): completes the `v1.usp` WebSocket handshake (or
    recognizes a raw USP **Record** protobuf), scavenges the controller/agent
    endpoint IDs (`proto::`/`os::`) + USP version, and flags an unauthenticated /
    cleartext USP MTP (CWE-319 / CWE-306).

  The existing `ssdp` (UPnP discovery) handler now also stamps an `intent` and
  flags the **libupnp** SSDP overflow (CVE-2012-5958, CWE-120) on an over-long
  header. New CVEs are added to the catalog with their CWEs; the handlers attach
  a `cwe` meta annotation for the protocol-misuse cases that have no single CVE;
  ATT&CK handler + anomaly tags map the abuse (T1190/T1133 base, plus T1059
  exec, T1542/T1105 firmware push, T1529 reboot, T1090 UPnProxy, T1048
  CallStranger exfil, …), with a D3FEND defense for each.

- **Deeper attacker-profile dossier (`/profiles/{ip}`).** The per-source dossier
  now aggregates, over *all* of an actor's events: its **intent** (the per-event
  "what the attacker was doing" labels, deduped) shown up top; a consolidated
  **attacks, misuse & manipulation** catalog that gathers the CVEs (vulnerabilities
  / exploit attempts), the web-application attack classes, and the protocol
  misuse / manipulation markers (non-webapp anomalies) into one place — folding in
  the previously scattered standalone CVE / web-attack / anomalies sections; every
  distinct **URL requested** (request targets, separate from harvested C2 URLs);
  the **HTTP headers seen** (name → sampled values + per-header request count);
  the **files downloaded / exfiltrated** over a transfer protocol (FTP `RETR`
  honeyfiles, SCP source transfers, SFTP paths, TFTP read requests) or a DNS zone
  transfer; and the **honeytokens served / stolen** (planted decoy secrets /
  canary accounts the source pulled or replayed). **Protocol intelligence** now
  goes beyond TLS with a **per-protocol summary**: every protocol the source spoke,
  with the versions observed and the negotiated/selected parameters (KEX, ALPN,
  SNMP MIB profile, VNC/RDP security type, …). All new fields are also in the
  `/api/profiles/{ip}` JSON.

- **Process-historian binary protocol depth.** GE Proficy Historian (14000),
  Canary Labs Historian / Sender (9990), and AspenTech InfoPlus.21 (10014) — the
  proprietary binary data ports that were previously captured raw — now have
  fingerprint-grade handlers (`proficy_historian`, `canary_historian`,
  `aspen_ip21`), and the AVEVA PI archetype's port 5450 is wired to the existing
  `osisoft_pi` handler. Each captures the client's opening message, classifies
  its framing (length-prefixed big-/little-endian vs raw stream), scavenges the
  cleartext app/user/version strings these SDK handshakes leak, greets with a
  minimal product identification, and surfaces the connection as historian /
  process-data access (IT→OT pivot / exfil). The closed wire protocols are not
  fabricated — no tag/point database is served.

- **Connection-oriented QUIC session handler (HTTP/3).** The `quic` handler is
  now the first consumer of the `udp_session` primitive: on a listener with
  `udp_session: true` it (1) reassembles a TLS ClientHello split across multiple
  QUIC Initial datagrams — common with post-quantum key shares / ECH / long
  extension sets, where the stateless single-datagram path saw only a fragment —
  and (2) validates the source address by emitting a real QUIC **Retry** (RFC
  9000 §17.2.5 with the RFC 9001 §5.8 Retry Integrity Tag, verified against the
  RFC 9001 A.4 vector); a retried Initial that echoes the token is flagged
  `quic-address-validated` (it cannot be a spoofed source). The Retry is smaller
  than the ≥1200-byte Initial it answers (never an amplifier) and is gated by the
  reply policy. Recovering 1-RTT HTTP/3 application data (a live TLS 1.3
  handshake) remains out of scope.

- **Per-virtual-host LDAP rootDSE identity.** Each honeynet DC now presents its
  own `dnsHostName` / `serverName` / `dsServiceName` / `ldapServiceName` derived
  from the virtual host's name, so hosts sharing an AD archetype no longer look
  identical to recon tools. The stand-alone listener keeps the canonical `dc01`.

- **LDAP rootDSE advertises the AD functional level.** The `ldap` / `ldaps` /
  `cldap` handlers now return `domainFunctionality` / `forestFunctionality` /
  `domainControllerFunctionality` (msDS-Behavior-Version) from the domain-
  controller archetype's pinned level — 4 / 5 / 7 for the 2008R2 / 2012 / 2016
  AD DCs (default 7) — plus `supportedCapabilities` LDAP_CAP_* OIDs that grow
  with the level, `isGlobalCatalogReady`, `serverName`, SASL mechanisms, and the
  DomainDnsZones/ForestDnsZones naming contexts. AD-recon tools (e.g. BloodHound,
  ldapsearch) now read a coherent level off the rootDSE.

### Fixed

- **HTTP/HTTPS form-login credential capture now handles app-specific field
  names + any path.** `parseLoginForm` previously matched only a handful of
  generic field names (`username`/`user`/… + `password`/`pass`/…), so a real
  Hydra brute force against phpMyAdmin (`pma_username` / `pma_password`),
  Tomcat (`j_username` / `j_password`), WordPress (`log` / `pwd`), or any
  `*_username` / `*_password` app silently captured only the cookie — not the
  credentials. The parser now recognizes the common app field names plus a
  substring fallback (any field containing `user`/`login` resp. `pass`/`pwd`,
  with `user_agent` excluded), and the capture runs for **any** POST form body
  rather than only the known login routes (the fake 401 login-retry page stays
  route-gated). It now also parses **JSON** request bodies (`application/json`,
  any `*+json`, or a body that starts with `{` even when mislabeled) — the
  modern API-login shape `{"username":...,"password":...}` and nested variants
  like `{"auth":{"user":...,"pass":...}}`. Captured `http_login_user` /
  `http_login_pass` flow to the captures page + attacker profile and flag
  `http-login-attempt` (T1110.001).

## [2.21.0] - 2026-06-09

### Added

- **Active Directory DC archetypes pinned to a forest/domain functional level.**
  `windows-2008r2-ad` (FFL 4), `windows-2012-ad` (FFL 5), `windows-2016-ad`
  (FFL 7) — the full DC protocol mix (DNS/Kerberos/LDAP/LDAPS/GC/SMB/DCE-RPC/
  WinRM/ADWS) with era-accurate OS build, IIS version and CVEs (EternalBlue /
  ZeroLogon / PrintNightmare / noPac as appropriate). The level (msDS-Behavior-
  Version) is carried in the display name + an `adfl:<n>` quirk.

- **Process-historian / industrial-data-platform archetypes (12).**
  `kepware-opcua` (OPC UA / KEPServerEX), `aveva-pi` (OSIsoft/AVEVA PI Data
  Archive, PI-SRV01, /piwebapi + 5450/5457), `aveva-pi-af` (PI AF, PI-AF01),
  `wonderware-historian` (AVEVA/Wonderware, HISTORIAN01), `aspentech-ip21`
  (InfoPlus.21, IP21-SERVER), `ge-proficy-historian` (PROFICY-HIST01,
  /ProficyHistorian), `emerson-historian` (Ovation/DeltaV, PHD-HIST01),
  `canary-historian` (CANARY-HIST01, /CanaryData), `dataparc` (PARCVIEW01,
  /PARCview), `ignition-gateway` (Ignition, 8088/8043/62541 OPC UA),
  `influxdb` (8086/8088), `timescaledb` (5432). Each carries product-accurate
  ports, hostnames, banners and a landing page linking the real web/API base
  paths + a sample point/tag.

- **Archetypes: `guacamole-server`, `keycloak-server`, `rdp-server`.** Apache
  Guacamole remote-desktop gateway (Tomcat web + guacd/4822), Keycloak IAM/SSO
  (8080/8443 admin console), and a legacy Windows RDP/RDS host (Server 2008 R2,
  3389 + RD Web, advertising BlueKeep CVE-2019-0708).
- **Archetype service audit + fixes.** A new integrity test
  (`TestArchetypeServicesResolve`) verifies every archetype's defaultServices
  name a *registered* handler with valid, non-duplicate ports — all 241 pass.
  A companion coherence check found and closed 7 service/identity gaps
  (Synology/QNAP model FTP feature sets, Schneider M340 FTP banner, Raritan KX
  SSH banner, Opengear telnet login prompt).

- **Operator detection rules (detection-as-code).** A new `detection.rules_dir`
  points the sensor at a directory of Sigma-style YAML rules
  (`internal/detect`) matched against every event with no recompile (re-read on
  SIGHUP). A match adds the rule's `tags` as anomaly markers (flowing into
  search / attack tables / exports / ATT&CK chips) and may raise the event
  severity. Conditions AND across fields / OR within a value list, with
  `contains|prefix|suffix|re|gt|lt|exists` modifiers over event fields +
  `meta.<dotted.path>`. `validate-config` loads + validates them; docs in
  `detection-rules.md` + an example rule set in `configs/rules/`.

- **Connection-oriented UDP listener (`udp_session`).** A new opt-in UDP path
  that demultiplexes datagrams per source into multi-datagram `handler.UDPSession`s
  (Read next datagram / Write reply) handed to handlers implementing
  `handler.UDPSessionHandler` — the missing primitive for QUIC/DTLS/TFTP-style
  exchanges. Bounded session table (falls back to the stateless path when full),
  one event per session. Stateless UDP handlers and TCP are unaffected.

- **`replay` subcommand — record-and-replay regression harness.** Re-runs a
  recorded request back through its protocol handler offline (no socket,
  nothing executed): `--event <id>` replays the bytes the sensor captured for
  an event and reports whether the recomputed anomalies drifted from what was
  stored (detection-regression signal); `--handler <name>` + `--file`/stdin
  feeds arbitrary bytes to any TCP/UDP handler. Prints anomalies / CVE hits /
  meta as JSON.

- **CI + signed-release / SBOM supply chain.** `.github/workflows/ci.yml`
  (gofmt, vet, build, test, `-race`, fuzz smoke over every `FuzzXxx`,
  `govulncheck`) and `.github/workflows/release.yml` + `.goreleaser.yaml`:
  tagged `v*` releases produce cross-compiled archives, `checksums.txt`, a
  CycloneDX SBOM per artifact (syft), and keyless cosign signatures (Sigstore
  OIDC). New Makefile targets `sbom`, `checksums`, `govulncheck`,
  `release-artifacts` for the same locally.

- **CVE decoys extended to the remaining network gear.** Aruba ArubaOS-Switch
  (CVE-2020-7115), OpenWrt (CVE-2020-7982), pfSense (CVE-2022-31814), Teltonika
  RUTOS routers (CVE-2023-32347, all RUT/TRB models) and Cisco UCS CIMC
  (CVE-2024-20356) now advertise a CVE; 5 new catalog records added. (Arista,
  Nokia SR OS, VyOS, OPNsense and the already-patched base MikroTik builds are
  intentionally left without one — no high-confidence/applicable CVE.)

- **SOHO router / UDM / NAS archetypes.** `dlink-router` (DIR-882), `tplink-router`
  (Archer AX21), `asus-router` (RT-AX88U / ASUSWRT), `mikrotik-hap-ax3`,
  `ubiquiti-udm` (Dream Machine), and the NAS models `synology-ds220plus`,
  `synology-ds920plus`, `qnap-ts251plus`, `qnap-ts873a`. (SonicWall, FortiGate
  60F, Juniper MX480, Cisco NCS5500, TrueNAS CORE already shipped.)
- **CVE / exploit decoys across the comms & network-gear archetypes.** 32 router /
  switch / firewall / VPN archetypes now advertise a vendor-accurate `patchLevel`
  + `cveVulns` so a version scanner sees an exploitable box and the follow-up
  exploit attempt is recognised: Cisco IOS Smart Install (CVE-2018-0171) / IOS-XE
  web-UI (CVE-2023-20198) / IOS-XR Redis (CVE-2022-20821), Juniper J-Web
  (CVE-2023-36845), Citrix Bleed (CVE-2023-4966 + CVE-2019-19781), PAN-OS
  GlobalProtect (CVE-2024-3400), F5 (CVE-2022-1388 + CVE-2020-5902), FortiOS
  (CVE-2018-13379), Check Point (CVE-2024-24919), Sophos (CVE-2022-1040),
  SonicWall (CVE-2024-40766), Zyxel (CVE-2022-30525), DrayTek (CVE-2020-8515),
  Huawei (CVE-2017-17215), MikroTik (CVE-2023-30799 / CVE-2018-14847), Netgear,
  Ubiquiti EdgeRouter (CVE-2021-22909), D-Link, TP-Link, ASUS (CVE-2024-3080).
  Six new CVE catalog records added (Cisco IOS-XR, MikroTik, SonicWall, Sophos,
  Ubiquiti, ASUS).

- **Service-provider / data-center router & switch archetypes.** `juniper-mx480`,
  `juniper-mx960` (MX routers), `juniper-ex4300`, `juniper-qfx5120` (Junos
  switches), `arista-7280r`, `cisco-ncs5500`, `cisco-asr9000` (Cisco IOS XR),
  `nokia-7750-sr1` (new `nokia` family, SR OS), and Ubiquiti UniFi
  `ubiquiti-unifi-switch` / `ubiquiti-unifi-ap` — each with vendor-accurate SSH /
  J-Web / SNMP identity, product sysObjectID, and CPE.
- **Catalog table completeness.** `docs/archetypes.md`'s quick-reference table is
  now regenerated from the live catalog, so all 221 archetypes appear (it had
  drifted, missing ~23 existing entries such as `ubuntu-20.04`, `debian-8`,
  `arista-7050`, `cisco-2811`, the M340 / RX3i / ControlLogix ICS variants, …).
- **18 more OS / NAS / printer / ICS archetype variants.** OS: `freebsd-11`,
  `openbsd-7.4`, `openbsd-7.7`, `netbsd-9`, `netbsd-10` (NetBSD is new to the
  catalog), `debian-7`, `centos-stream-9`, `rhel-7`, `ubuntu-22.04`, plus a new
  **SUSE** family — `sles-12`, `sles-15`, `opensuse-leap-15`. Storage:
  `truenas-scale`, `netgear-readynas`, `asustor-nas`. Printers/MFP:
  `oki-printer`, `toshiba-estudio`. ICS: `abb-ac450` (ABB Advant Controller
  450). Each has era-accurate banners / SNMP identity / TLS posture; the SUSE
  family gets a `suse` kernel-version mapping. Catalog table + per-archetype
  detail sections in `docs/archetypes.md` updated.
- **More IP-camera archetype variants.** Beyond the base `axis-camera` /
  `hikvision-camera` / `bosch-camera`, added fixed-dome / PTZ / NVR variants:
  `axis-p3245` (P3245-LVE dome), `axis-q6075` (Q6075 PTZ), `hikvision-ptz`
  (DS-2DE, CVE-2021-36260), `hikvision-nvr` (DS-7608NI, CVE-2021-36260),
  `bosch-flexidome` (FLEXIDOME IP 5000i), `bosch-autodome` (AUTODOME PTZ) — each
  with its own model banner / SNMP sysDescr / services (+ https on the Axis
  variants), so the web/RTSP/SNMP/ONVIF identities stay coherent per model.
- **`bosch-camera` archetype.** A Bosch IP-camera device identity (family
  `bosch`, lighttpd web UI / "BOSCH" title + digest realm, SNMP "Bosch DINION IP
  starlight 7000", Bosch Security Systems MAC OUI, services http/rtsp + RCP+ on
  tcp/1756, ONVIF quirk) — joining the existing `axis-camera` and
  `hikvision-camera`.

### Fixed

- **Analytics pages degrade instead of 500 on a slow store.** When an aggregate
  page query (e.g. `/remote`, `/dns`, `/web`, `/databases`) exceeds its time
  budget — a large/busy event store or an index still (re)building — the page
  now serves a friendly, auto-refreshing 503 "this view is taking longer than
  usual" page (with a shorter-range hint) instead of a bare "internal server
  error" 500.

## [2.20.0] - 2026-06-08

### Added

- **`list-events` target/handler/port filters + `validate-config` TLS check.**
  `list-events` gains `--target <ip>` (filter by which of the host's server IPs
  was hit — the multi-IP pivot), `--handler`, and `--port`; the store `Filter`
  gains a `DstIP` clause. `validate-config` now prints the TLS-cert ↔
  deployment-domain coherence warnings (same as the startup log / config page)
  so a mismatch is caught before deploy.
- **Statistics page multi-IP breakdown.** On a host serving more than one IP,
  `/stats` now leads with "targeted server IPs" + the busiest one, and adds a
  "Targeted server IPs (this host)" top-N table — so a multi-address sensor
  shows which of its own addresses are under attack.

- **Attacker interactions view (`/interactions`).** A new page showing what
  attackers actually *did* once engaged: commands typed into the emulated
  SSH/Telnet shells (`shell_commands`), exec requests, fake-web-shell commands
  (`webshell_cmd`), keystrokes, and recorded session casts (linked for
  download). Top-commands table + by-service/top-command charts + per-session
  command transcripts, newest first. The "work" view, distinct from the
  recon/attack tables.
- **Remote-access / mail / NTP analytics views.** Three new DNS-style pages
  (`/remote`, `/mail`, `/ntp`) driven by one generic service-view builder +
  template: event volume over time, services hit, top usernames/commands/
  senders, banners, top attackers, attacks/CVEs, the attacker-intent table, and
  a per-event activity log with an intent column. Categories: remote =
  ssh/telnet/rdp/vnc/…, mail = all SMTP/POP3/IMAP variants, ntp. Nav-gated +
  togglable like the existing service pages.
- **Attacker-intent on the web + database views — and in every export.** The
  intent table near the top is now populated and an intent column appears in the
  per-request / activity listings. The http handler labels intent itself, and a
  listener-level deriver (`deriveEventIntent`) now sets an authoritative
  `meta["intent"]` for every event a handler didn't already label — remote
  (shell session / login / probe), mail (relay / login / address harvesting),
  database (auth / command / probe), and the CVE-exploit case — so the intent
  appears in search and in all SIEM exports (JSON / CEF / LEEF / OCSF), not just
  the UI pages.
- **Cross-target timeline on the source profile.** When a source reached more
  than one of the host's server IPs, the profile shows the targets in first-seen
  order with timing-offset bars, per-target ports + services + hit counts, and a
  ⚠ list of ports hit on more than one target (same-service fleet sweep).

- **Cross-target correlation (`correlate:cross_target`).** On a host serving
  several decoy IPs, this detector fires when one source reaches multiple target
  IPs within a window and records the dimensions an analyst asks for: the
  targets in first-seen **order**, the **timing** (first-touch offset per
  target), the **ports per target**, and the **ports hit on more than one
  target** (`shared_ports` — a scripted same-service sweep across the fleet).
  Opt-in (`correlate.cross_target`), ATT&CK-mapped (T1018/T1046/T1595), enabled
  in the FULL example; the event persists like any other so it shows in the
  source profile + event views.

- **SNMP trap / inform receiver (`snmptrap`, udp/162) + Cisco SNMP RCE
  detection.** A passive receiver parses SNMPv1 and v2c traps *and* informs
  (and notes v3) with a tolerant BER walker that never feeds attacker bytes into
  a real SNMP stack: it captures version / community (v3 user) / enterprise OID
  / generic+specific trap / varbind OIDs, acknowledges informs (PDU flipped to
  GetResponse, no amplification) when the reply policy allows, and flags
  malformed ASN.1, oversized packets, oversized/truncated PDUs, non-standard
  SNMP versions, randomized/off-tree enterprise OIDs and varbind floods. The
  same inspector runs on the udp/161 agent, so the **Cisco IOS / IOS XE SNMP RCE
  class** (`CVE-2017-6736`, `CVE-2025-20352`, and advisory `CVE-2025-20312` /
  `CVE-2024-20373` / `CVE-2025-68615`) is attributed on its shared overflow
  primitive — an over-long / malformed OID or a PDU whose declared length runs
  past the packet — and surfaced as `cisco-snmp-rce-attempt` + `cve:<id>`.

- **Multiple honeypots on one host, one per server IP (systemd template).** A
  new `tarpit-honeypot@.service` template runs independent, fully-isolated
  instances — each with its own config (`/etc/tarpit-honeypot/instances/NAME
  .yaml`), data dir (`/var/lib/tarpit-honeypot/NAME` → own SQLite DB,
  `.deployment-id` and certificates), syslog identity and UI port.
  `scripts/add-instance.sh --name NAME --listen-ip IP` provisions one (derives +
  patches the per-IP config, creates/labels the dirs for SELinux, auto-assigns a
  loopback UI port, and enables the unit). `install.sh` lays down the template
  and the rsyslog routing now matches every `tarpit-honeypot*` instance tag.

- **Multi-IP binding (`sensor.listen_addresses`).** A wildcard listener
  (`[::]`/`0.0.0.0`) already answers on every host IP; now you can also pin all
  listeners to a specific set of IPs. One logical listener owns several sockets
  — the same SSH/HTTP/… decoy on N server IPs feeding one handler — and the
  destination IP is still recorded per connection (`dst_ip`). Set one IP to
  dedicate an instance to a single address (the per-IP multi-honeypot model).
  Also fixed `sensor.interfaces`, which bound only the *first* interface IP; it
  now binds every usable IP on the named interfaces (matching its documented
  intent). A failed bind (an IP not on the host) warns and is skipped instead of
  taking the whole listener down.

- **`install.sh` sets the deployment identity, not just the TLS name.** It now
  prompts for (and accepts `--hostname` / `--domain`, or `TARPIT_HOSTNAME` /
  `TARPIT_DOMAIN`) the sensor's host label (`sensor.name`) and DNS domain
  (`sensor.domain`) — the suffix every banner-aware decoy uses (DNS zone, SMTP
  HELO, Kerberos realm, LDAP base, …). Previously it asked only for the TLS
  certificate name, so services kept advertising the generic
  `*.example.internal` default while the cert said something else. The TLS name
  (`--tls-domain`) now **defaults to `<hostname>.<domain>`**, so the certificate
  stays coherent with the deployment domain out of the box. The install summary
  prints the resolved `host` / `domain` / TLS name.

### Fixed

- **.deb / .rpm now produce a working install.** Beyond the wrong service
  account (fixed above), the packages contradicted the systemd unit they ship:
  the bundled config kept the repo-local relative `data_dir: ./var` (the unit
  makes `/var/lib/tarpit-honeypot` writable, so the daemon wrote to the wrong
  place), neither package created `/var/log/tarpit-honeypot` (in the unit's
  `ReadWritePaths`, so startup failed on the missing path), and the RPM laid the
  binary in `/usr/bin` while the unit's `ExecStart` pointed at
  `/usr/local/bin`. The packages now rewrite the installed config's `data_dir`
  to `/var/lib/tarpit-honeypot`, create + own `/var/log/tarpit-honeypot`
  (`honey:honeypot`), and the RPM repoints `ExecStart` to `%{_bindir}`.

- **Consistent service account (`honey`:`honeypot`) everywhere; .deb/.rpm now
  create the right one.** The Debian postinst and RPM spec created a `tarpit`
  user/group while shipping a systemd unit that runs `User=honey
  Group=honeypot` — so a packaged install couldn't start. They now create
  `honey` (primary group `honeypot`) and own the data dir `honey:honeypot`. The
  docs (README, usage, hardening, FAQ, INTEGRATIONS) that still showed
  `useradd … tarpit` / `User=tarpit` / `drop_user: tarpit` were corrected to
  match `scripts/install.sh` and the unit.

- **`install.sh` confirms the data dir at the end.** It prints whether the
  config's `data_dir` matches the dir `--data` made writable and, under
  SELinux, whether that dir carries the `tarpit_honeypot_var_lib_t` label — so a
  mismatch (the cause of "unable to open database file (14) … not writable") is
  obvious at install time, not after a failed start.

- **`install.sh --data DIR` now actually moves the data directory.** It created
  the dir and pointed the systemd unit's `ReadWritePaths` at it, but left
  `sensor.data_dir` in the deployed config unchanged — so the daemon kept
  writing to the old path, which `ProtectSystem=strict` now made read-only,
  and SQLite died with "unable to open database file (14) … not writable".
  `install.sh` now patches `sensor.data_dir` to `--data` (keeping config + unit
  in lockstep) and, under SELinux, adds a file-context equivalence so a custom
  data dir inherits the `tarpit_honeypot_var_lib_t` labels the policy expects.

- **SELinux: `syslog` channel failed under confinement ("Unix syslog delivery
  error").** The `syslog` output channel dials the local syslog socket
  (`/dev/log`) to emit events to the system logger; the confined domain wasn't
  allowed to, so the sink build failed and the daemon exited at startup. The
  policy now includes `logging_send_syslog_msg(tarpit_honeypot_t)`.

- **SELinux: `disk I/O error (5386)` under confinement (missing `map`).** Once
  the `init_t → tarpit_honeypot_t` domain transition actually fired (i.e. when
  started via systemd, not by hand), the confined daemon could no longer open
  its DB: WAL mode memory-maps the `events.db-shm` wal-index, and on RHEL 8/9
  `mmap` is a *separate* `map` permission not covered by the read/write/manage
  sets the policy granted — so the mmap was denied and SQLite returned
  `SQLITE_IOERR_SHMMAP` (5386), even though the same files opened fine when run
  unconfined. The SELinux policy now grants `map` on the data files
  (`tarpit_honeypot_var_lib_t`, for the WAL `-shm`) and the config files
  (`tarpit_honeypot_etc_t`, for the memory-mapped GeoIP/ASN `.mmdb` databases).
  Rebuild + reinstall the module (re-run `scripts/install.sh`) to apply.

- **Full-disk crash loop / cryptic `disk I/O error (5386)`.** When the data
  filesystem fills, SQLite can no longer grow the WAL/`-shm` (extended error
  `SQLITE_IOERR_SHMMAP` = 5386), `events.db` stops growing, and — because index
  creation lived in the mandatory schema exec — the daemon failed at `Open` and
  crash-looped, so it could never prune back under its cap to recover. Now:
  secondary indexes are built **non-fatally after** the tables/migrations
  (`ensureIndexes`), so a failed index build only makes a page full-scan instead
  of blocking startup; `Open` and the open-error diagnostics detect a
  full/near-full filesystem and say so (instead of a bare `(5386)`); and the
  retention prune fires as a **safety net when free disk is low even under the
  configured `sensor.disk.sqlite_mb` cap** (a cap larger than the partition is
  the usual root cause), truncating the WAL afterward. Note: a prune frees rows
  but does not shrink `events.db` itself (SQLite reuses the pages) — reclaiming
  file space still needs a `VACUUM`.

### Added

- **TLS ↔ deployment-domain coherence check.** The sensor now verifies that the
  TLS certificate identity it presents (`sensor.tls_domain`, falling back to
  `sensor.domain`, plus any per-listener `https.hosts`/`https.cn` overrides) is
  coherent with the deployment domain the rest of the deception advertises
  (DNS zone, SMTP HELO, Kerberos realm, NTLM target). A divergence — e.g. a cert
  for `acme.test` on a `corp.example.com` deployment — is a fingerprinting tell;
  it's now surfaced on the UI **config page** (a `⚠ mismatch` badge + the
  specific discrepancies) and logged once at startup
  (`config.TLSCoherenceWarnings`).

### Changed

- **Web-UI pages scale to 100k+ events.** The **captures**, **credentials**, and
  **DNS/web/database** pages returned `internal server error` once the event
  table reached ~160k rows: each pulled 20k–50k full rows (payload blob +
  per-row banner subquery) and filtered/aggregated in Go inside a short
  deadline. Now they query `NoPayload` (these pages aggregate over event meta,
  never the raw bytes), the service pages push their category filter into SQL
  (`store.Filter.Handlers` IN-clause), and a new composite index
  `idx_events_handler_time(handler, time DESC)` lets those queries
  range-filter + order straight from the index. The index ships in the schema
  DDL (`CREATE INDEX IF NOT EXISTS`), so it also lands on existing databases on
  next open.
- **Sensor logs no longer pollute `/var/log/messages`.** An installer rsyslog
  drop-in (`packaging/rsyslog/30-tarpit-honeypot.conf`) routes the sensor's own
  output — operational startup/warning logs *and* the CEF event stream, both
  tagged `tarpit-honeypot` — to a dedicated
  `/var/log/tarpit-honeypot/tarpit-honeypot.log` and `stop`s it from falling
  through to `/var/log/messages`. `scripts/install.sh` installs the drop-in +
  a logrotate policy, provisions the log file with ownership the local syslog
  daemon can write (handling Debian's priv-dropped `syslog` user), and the
  SELinux policy grants `syslogd_t` access to `tarpit_honeypot_log_t`. The
  systemd unit pins `SyslogIdentifier=tarpit-honeypot`.

- **Cross-protocol extraction audit.** Surfaced more high-value client intel
  several handlers received but discarded: HTTP **UA client hints** (Sec-CH-UA
  family → client OS / version / CPU arch / device / browser), the proxy chain
  (`forwarded_for`) and locale (`accept_language`); the **IMAP `ID`** client
  name/version (`imap_client_id`); **Postgres** `application_name` + database
  from the startup params; the **STUN `SOFTWARE`** attribute (`stun_software`);
  the **SNMPv3** USM `msgUserName` (`snmp_v3_user`); and the **Redis** client
  name (`CLIENT SETNAME`/`SETINFO` → `redis_client_name`).
- **LDAP/CLDAP/LDAPS rootDSE** `defaultNamingContext` derived from the
  deployment domain (e.g. `corp.example.com` → `DC=corp,DC=example,DC=com`),
  with the CLDAP reply gated by the amplifier policy + a reflection limiter.

- **Reply-policy modes** (`sensor.reply_policy`) — one deployment-wide lever,
  enforced centrally for every TCP + UDP service: `full` (default), `non-ot`
  (mute OT-class handlers), `fingerprint` / `fingerprint-non-ot` (reply only
  enough to fingerprint / capture creds — no deep sessions or call-outs), and
  `mute` (receive-only — every outgoing byte and call-out dropped). Plus
  `sensor.no_amplifier_replies` (suppress NTP mode 6/7 + reflector replies with
  a special warning).
- **Fake web ↔ decoy MySQL** — a fake-web listener auto-stands-up a MySQL on the
  same host (`:3306`), and the DB credentials it leaks in `.env` (user
  `intranet_app`, db `intranet`, the per-deployment password) now actually
  authenticate against that MySQL (`mysql-honeytoken-auth`), which then captures
  the attacker's post-auth SQL.
- **Web second-stage sample retrieval** finished + made policy-safe
  (`sensor.web_sample_retrieval`, opt-in/off): egress-gated download, YARA scan,
  never executed, persisted to the captures page; suppressed under mute /
  fingerprint modes. New **`captured`** counter on the summary dashboard.
- **`sensor.db_reply_delay`** — configurable multi-second answer delay on the
  SQL handlers (MySQL/Postgres/MSSQL) so a heavy decoy DB feels real.
- **Config page** now shows the deployment domain / TLS-cert domain / honeynet
  domains, the active reply policy + amplifier/DB-delay modes, and the fake-web
  state (portal name + sample-retrieval on/off).
- The fake-web **portal name** is set via `listener.webapp_brand.name` and drives
  both the displayed page and the leaked `.env` `APP_NAME`.
- **NTS-KE** (`nts`, TCP 4460) — Network Time Security Key Establishment over
  TLS (RFC 8915, ALPN ntske/1): JA3/JA4/JA3S + offered next-protocols/AEAD
  capture, believable NTPv4 + AES-SIV-CMAC-256 + cookies response.
- **NTP mode-6/mode-7 now answered** (bounded + rate-limited): `ntpq -c rv`
  (READVAR system variables), `ntpq -c peers` (READSTAT), `ntpdc -c monlist`
  (one-entry response, never the ~556x amplifier).
- **Deployment DNS domain** (`sensor.domain`) — the SMTP banner host, DNS
  hostname.bind/id.server and the telnet \h escape are all consistent; the cert
  identity falls back to it when sensor.tls_domain is unset.
- **Deep TDS LOGIN7 extraction** (MSSQL) — hostname, user, de-obfuscated
  password, app, target server, client driver/library, language, database,
  client PID + MAC. **NTLM client OS version** added to the shared
  SMB/RDP/WinRM capture.

### Fixed

- **Telnet /etc/issue escapes** — the login banner substitutes \r (kernel
  release), \m (machine), \n/\h (nodename), \l (tty), \o (domain) instead of
  printing a literal "Kernel \r on an \m".

### Added (continued)

- **OSIsoft/AVEVA PI** (`osisoft_pi`, TCP 5450) — fingerprint-grade PI Data
  Archive / PI Network Manager responder; flags historian access (IT→OT pivot,
  T0811/T0801).
- **Web vulnerability detection.** Nine new 2024–25 web/appliance CVEs
  (CyberPanel, SimpleHelp, Apache OFBiz/mod_rewrite, MOVEit SFTP, Cisco Smart
  Licensing, ProjectSend, Cleo, BeyondTrust, Notepad++) plus three new web
  attack-class detectors: **CRLF injection**, **LDAP injection**, **XPath
  injection** (base HTTP handler + vulnweb emulation).
- **Kerberos misuse + legacy variants.** Detection of **Kerberos 4 / KTH-KRB**
  (the legacy v4 wire format), **AS-REP roasting** (AS-REQ without pre-auth),
  **PKINIT / Shadow Credentials**, **S4U2Self** constrained-delegation abuse,
  and the **Bronze Bit** (PA-PAC-OPTIONS) path — over both TCP and UDP.
- **Scanner vendor/affiliation reference.** `toolfp.Vendor()` maps tool
  identifiers to the org/project behind them (Nozomi Networks, Claroty,
  Tenable.ot, Dragos, Rapid7 Project Sonar, Censys, ISF, …); surfaced as
  `tool_vendor(s)` on HTTP events + the scananalysis profile, and in the new
  statistics page.
- **Web UI `/stats` statistics page** — numeric headline metrics + top-N tables
  across severity, protocol, service, geography, ASN, ATT&CK, CVE, tools
  (vendor-annotated) and sources; companion to the visual `/charts` page.
- **OPC vendor identity is archetype-driven** — the OPC-DA (DCOM) GetStatus
  vendor string follows the archetype; new **MatrikonOPC** and **Kepware
  KEPServerEX** Windows archetypes pin it.
- **Legacy OS / network-gear archetypes** (era-correct, no anachronisms):
  Ubuntu 14.04/16.04/18.04/20.04, Debian 8, FreeBSD 12, Solaris 10, MikroTik
  RouterOS 7 + 6.40 (Winbox CVE-2018-14847), Cisco 2811 ISR (IOS 12.4).
- **Deployment-wide TLS certificate identity** — `sensor.tls_domain` /
  `sensor.tls_org` give every TLS decoy one consistent cert (the admin's
  name/domain) instead of the per-service `localhost` default; `install.sh`
  prompts for and wires them.

### Fixed

- **SSH algorithm anachronisms.** The server KEXINIT now tracks the real
  OpenSSH feature timeline — a pre-6.5 banner no longer offers Ed25519 /
  Curve25519 / chacha20, and pre-5.7 offers no elliptic curve at all (the
  "OpenSSH 5.3 advertising an Ed25519 host key" tell). CentOS 5/6 TLS posture
  pinned to their OpenSSL era.
- **PostgreSQL fingerprint fidelity** — full `ErrorResponse` field set
  (S/V/C/M/F/L/R) so port 5432 is identified as PostgreSQL, not a generic / H2
  service; an invalid startup now gets a FATAL `0A000` instead of a silent close.
- **SMB timestamps** — SMB1/SMB2 NEGOTIATE now stamp a real SystemTime (was
  zero) and a plausible deployment-stable ServerStartTime (boot/uptime).

### Earlier in this cycle

- **More OT protocols + ICCP/TASE.2.** Four new control-system handlers and a
  deep inter-control-center implementation:
  - **IEEE C37.118.2 synchrophasor** (`c37118`, TCP 4712) — parses the frame
    header + FRAMESIZE, classifies COMMAND frames (turn-on/off transmission,
    send CFG/HEADER) and answers with a CRC-checked CFG-2; turn-off against a
    PMU flags `ics-pmu-command` (blinds wide-area monitoring).
  - **SIA OSDP / IEC 60839-11-5** (`osdp`) over IP — access-control reader/panel
    framing; classifies osdp_OUT (door-strike actuation), osdp_COMSET (channel
    hijack), osdp_KEYSET/CHLNG/SCRYPT (secure-channel key install/negotiation);
    replies osdp_ACK / osdp_PDID with the right checksum or CRC.
  - **FANUC FOCAS** (`focas`, TCP 8193) — CNC fingerprint → Series 30i sysinfo.
  - **ProConOS / eCLR** (`proconos`, TCP 20547) — the soft-PLC runtime PCWorx /
    MULTIPROG download logic to; classifies START/STOP and unauthenticated
    logic DOWNLOAD (ICS-ALERT-13-016 class).
  - **ICCP / TASE.2** detection on the `mms` handler — recognizes the TASE.2
    profile (version OID + Bilateral_Table / Transfer_Set / VCC objects) and
    classifies Transfer-Set, Bilateral-Table, and Block-5 Device-control
    operations. **Secure ICCP** (`iccp_secure`, TCP 3782) wraps it in TLS
    (JA3/JA4/JA3S) per IEC 62351.
- **OT scanner & tool fingerprinting.** `toolfp` adds User-Agent signatures for
  the OT asset-discovery/monitoring platforms (Claroty, Nozomi, Tenable.ot,
  Forescout, Dragos, Otorio, ScadaFence), Rapid7 Project Sonar, and the ICS
  exploitation toolkits (ISF, smod, plcscan, s7scan, modscan). `scananalysis`
  fingerprints the binary-protocol recon probes that carry no UA — nmap's ICS
  NSE scripts (modbus-discover / s7-info / enip-info / bacnet / pcworx / fox),
  Metasploit's scada modules — surfacing them in `scananalysis:profile`.
- **Deeper VNC/RFB.** Client fingerprinting from the RFB version (Apple Remote
  Desktop 003.889, UltraVNC), the RFB 3.8 auth-failure reason string, selected
  security-type naming with None-auth probe detection (`vnc-none-auth-probe`),
  and a SetEncodings client fingerprint (`vnc_encodings`). VNC anomalies now
  carry explicit ATT&CK/D3FEND mappings.
- **Deep ICS protocol implementations.** Five fingerprint-grade handlers now
  decode their session/service layer and classify recon vs control:
  - **CODESYS V3** (1217) — classifies the targeted component/service from the
    in-clear tokens (CmpUserMgr login, CmpFileTransfer / CmpApp download &
    online-change, start/stop/reset, CmpDevice info, CmpTraceMgr) and attributes
    the CODESYS no-default-auth (**CVE-2022-31806**) + gateway auth-bypass
    (**CVE-2022-31802**). Embedded across WAGO/Beckhoff/Schneider/ABB/Festo.
  - **S7comm-Plus** (102) — parses the S7-1200/1500 PDU: version→firmware family,
    opcode, and function (Explore, Get/SetMultiVariables, CreateObject/Invoke) →
    explore/read/write/program-access markers.
  - **KNXnet/IP** (3671) — parses the cEMI/APCI layer of TUNNELLING_REQUEST +
    ROUTING_INDICATION: GroupValue read/write (bus drive), A_Memory_Write,
    A_Restart, individual-address/property/key programming, with the KNX
    individual+group addresses; flags CONNECT and DEVICE_CONFIGURATION.
  - **Phoenix Contact PCWorx** (1962) — richer ILC identification + a bounded
    session classifying run-state / program-transfer / variable write-read /
    login, attributing the ILC unauthenticated-access **CVE-2016-8367**.
  - **VxWorks WDB target agent** (UDP 17185) — parses the ONC-RPC/WDB header
    (WDBPROG 0x55555555), classifies memory access / context-create+function-call
    (RCE) / connect, attributes the exposed-WDB-agent backdoor (**CVE-2010-2965**)
    and detects oversized **URGENT/11** IPnet requests (**CVE-2019-12256/-12255**).
- **Deeper Modbus + Modbus/TCP Security.** Both the plaintext (502) and TLS
  (802) Modbus handlers now share a much deeper analysis layer:
  - **More function codes** — Read Exception Status (0x07), Get Comm Event
    Counter/Log (0x0B/0x0C), Read FIFO Queue (0x18), Read/Write File Record
    (0x14/0x15), CANopen General Reference (MEI 0x0D), program/firmware transfer
    (0x28/0x29/0x2A), and the **Schneider UMAS** engineering channel (FC 0x5A,
    with sub-function naming: read/write memory & variables, START/STOP, take/
    release reservation).
  - **Register-reference + vendor-tag enrichment** — every coil/register
    operation is stamped with its Modicon reference (0/1/3/4xxxx), register
    class, and a Schneider/IEC `%M`/`%MW`/`%IW` **tag hint**.
  - **Vendor extensions & backdoors** — vendor/reserved function codes
    (65-72, 100-110) flagged as proprietary/backdoor channels
    (`modbus-vendor-function`); UMAS flagged `modbus-umas` with the Schneider
    Modicon auth-bypass CVE (**CVE-2018-7842**); program/firmware transfer →
    `modbus-program-download`; diagnostic counter-clear → `modbus-diagnostic-clear`
    (anti-forensics); **config/system register-area** access flagged.
  - **Enumeration / fingerprinting** — session-level unit-id sweep
    (`modbus-uid-enumeration`, T0846), function-code scan (`modbus-fc-scan`,
    T0888), and broadcast (unit 0) write (`modbus-broadcast-write`).
  - New ATT&CK-for-ICS mappings for all markers; CVE-2018-7842 added to the
    catalog (advisory-only, CWE-287/294).
- **15 more PHP vulnerability emulations** in the fake web app: phpMyAdmin LFI
  (**CVE-2018-12613**) + setup RCE (**CVE-2009-1151**), Drupalgeddon2
  (**CVE-2018-7600**), Laravel Ignition RCE (**CVE-2021-3129**), ThinkPHP 5.x
  RCE (**CVE-2018-20062**), PHP-FPM status leak, Composer manifest leak,
  exposed `php-cgi`, Adminer, WordPress REST/`?author=` **user enumeration** +
  `xmlrpc.php` `system.multicall` brute / pingback SSRF, webshell-filename
  probes, PHP **superglobal pollution**, **type-juggling / magic-hash** auth
  bypass, **RFI** (`allow_url_include`), and **code-eval** sinks
  (`preg_replace /e`, `assert`, `create_function`). New `webapp:*` markers
  (mapped via the `webapp:`→T1190 fallback) + 4 new catalog CVEs
  (CVE-2018-12613, CVE-2009-1151, CVE-2018-20062, CVE-2019-11043) with
  CWE/CVSS/CPE/EPSS.

- **8 more OS/device archetypes (ICS/OT + networking)** — Schneider Modicon
  M340, Allen-Bradley ControlLogix 1756-L73, GE PACSystems RX3i, WAGO PFC200
  (CODESYS Linux PLC); and Juniper SRX340 (Junos), Arista 7050SX (EOS), Palo
  Alto PA-220 (PAN-OS), Aruba 2930F (ArubaOS-Switch). Each ships the device
  fingerprint surface (MAC OUI, SNMP sysDescr/sysObjectID, CPE, default
  services) so a scan keys on the right vendor/product. The existing Beckhoff
  CX9020 archetype now also advertises the TwinCAT AMS/UDP discovery port.
- **More PHP vulnerability emulation in the fake web app.** The vulnerable-webapp
  decoy now emulates the major PHP-specific attack surfaces: **PHP stream
  wrappers** in LFI — `php://filter` source disclosure (returns believable
  base64-encoded "config.php"), `php://input`/`data:`/`expect:` wrapper RCE,
  `phar://` deserialization, and `/proc/self/environ` + `/var/log` log-poisoning
  targets; **php-cgi argument injection** (`?-d+allow_url_include…` →
  **CVE-2012-1823**, and the Windows soft-hyphen `%AD` best-fit →
  **CVE-2024-4577**); the **PHPUnit `eval-stdin.php` RCE** (**CVE-2017-9841**,
  echoes plausible command output); and generic **PHP source-backup disclosure**
  (`*.php.bak` / `.php~` / `.phps`). New `webapp:php-*` markers (mapped via the
  `webapp:` → T1190 fallback) plus the three enriched CVE hits.
- **Beckhoff TwinCAT — AMS/UDP discovery + route (UDP 48899).** A new
  `ads_discovery` handler emulates the TwinCAT AMS/UDP service the "Add Route"
  dialog / TcAmsRemoteMgr broadcasts use: it parses the AMS/UDP header, captures
  the sender AmsNetId, flags **discovery** (`ics-ads-discovery`, T0846) with a
  bounded rate-limited identity reply, and flags **AddRoute**
  (`ics-ads-route-add`, T0866) — an attacker adding a trusted engineering route
  / control-system foothold — capturing the embedded route/host/user strings.
  The existing ADS/TCP (48898) handler now also names the target **AMS port**
  (`ams_target_port`: system-service/router 10000, TC2/TC3 PLC runtimes, …) and
  flags system-service access. New `beckhoffplc` role bundle.
- **GOOSE attack analysis (IEC 61850).** The L2 GOOSE sniffer now keeps
  per-control-block (`gocbRef`) state and detects manipulation, not just
  presence: **spoofing** (a second publisher / different src MAC for an existing
  control block → `sniffer:goose_spoof`, critical), **replay** (an `stNum`
  regression → `sniffer:goose_replay`, critical), **storm** (rapid `stNum`
  state-change flood → `sniffer:goose_storm`), and **simulation** (the header
  simulate bit / `test` flag → `sniffer:goose_simulation`) — mapped to ATT&CK
  for ICS **T0856** (Spoof Reporting Message) + T0831 / T0814 (new T0856
  technique + D3FEND). The parser now also extracts `test`, `confRev`, and the
  simulate bit; benign streams still emit the rate-limited `sniffer:goose`.
- **Modbus/TCP Security (Modbus-over-TLS) handler** (`modbus_security` /
  `modbuss`, port 802). Terminates TLS (requesting the client's role
  certificate), computes JA3/JA4/JA3S, captures the client-cert subject + the
  **Modbus role** (X.509 extension OID `1.3.6.1.4.1.50316.802.1`), flags the
  secure session (and a missing client cert), then runs the normal Modbus PDU
  handler over the encrypted channel — so reads/writes/diagnostics are
  classified exactly as on plaintext 502. Added to the `scadaserver` role.
- **HTTP evasion / obfuscation detection.** The base HTTP handler now flags the
  encoding tricks attackers use to slip payloads past signature filters —
  **double/triple percent-encoding** (`..%252f`), **overlong-UTF-8** and
  **`%u`-style Unicode** dot-dot, **null-byte** truncation, **backslash /
  mixed-slash** path obfuscation, and **SQL-comment splitting** (`UNION/**/SELECT`)
  — as `evasion:*` markers (→ ATT&CK **T1027**, defense-evasion). It also
  **percent-decodes the request through successive layers and re-runs** the
  path + attack-class checks, so a single- or double-encoded traversal / Log4Shell
  / SSTI payload is still caught and additionally tagged `evasion:encoded-payload`.
- **HTTP active-enumeration detection.** Flags verb/method enumeration
  (`OPTIONS`/`TRACE`/`TRACK`/`PROPFIND`/`DEBUG`/`SEARCH` → `http-method-enumeration`,
  T1595) and account enumeration (a username-style parameter on a login/auth
  endpoint → `http-account-enumeration`, T1087). Complements the existing
  protocol enumeration signals (SMTP `VRFY`/`EXPN`, LDAP, SNMP walk, mDNS, NBD).

## [2.13.0] — 2026-06-06

### Added

- **Combined traffic graphs + attacks-by-service donut.** On `/charts`, incoming
  and outgoing throughput (kb/s↔Mb/s) now share one graph and packet-rate
  shares another (two series each). A new **"Attacks by service (%)"** donut
  (attacks = events with an anomaly / CVE / high severity, grouped by handler)
  appears on both the summary "visual overview" and the `/charts` Overview.
- **IBM MQ (WebSphere MQ) decoy** on TCP 1414 (`ibmmq` / `mq` / `websphere_mq`):
  parses the MQ channel TSH segment, names the control opcode, extracts the
  SVRCONN channel + queue-manager from Initial Data, and labels the MQCSP
  security flow (AMQP + MQTT already existed; IBM MQ did not).
- **Infrastructure tool fingerprinting** — extended DNS (`IdentifyDNS`/fpdns:
  +20 OOB-callback / tunnel / rebind / open-resolver / AD-recon signatures) and
  new `IdentifyNTP` (ntpdc / ntpq / monlist-scanner / legacy) + `IdentifySNMP`
  (default-community brute) fingerprinters, wired into the ntp / snmp handlers.
- **More CVEs** (CWE+CVSS+EPSS+ATT&CK each): OMIGOD (signature-detected),
  HTTP.sys ×2, noPac, KeyTrap DNSSEC DoS, ntpd crypto-NAK — plus the DNS/SNMP/NTP
  exploit-detection + intent analysis added earlier. (CWE and CVSS are already
  present on 100% of catalog records; D3FEND flows from each record's ATT&CK
  technique via the mitre map.)

- **Deeper DNS / SNMP / NTP attacker-intent analysis + new CVEs & ATT&CK.** Each
  of these handlers now stamps an `intent` meta summary of what the attacker is
  actually doing, and recognizes more exploit/abuse vectors:
  - **DNS** — a **SIG** query (qtype 24) is flagged as a **SIGRed (CVE-2020-1350)**
    probe and a **TKEY** query (qtype 249) as the **ISC BIND assertion-failure DoS
    (CVE-2015-5477)** vector; the `intent` label distinguishes tunneling /
    exfil / amplification / zone-transfer / AD-discovery / cache-poison / DoS.
  - **SNMP** — detects **CISCO-CONFIG-COPY-MIB** access (`snmp-config-exfil`,
    running-config exfil/overwrite), flags **default-community** use as a weak
    credential, and labels SET / GetBulk-amplification / walk intent.
  - **NTP** — refines mode-7 classification (monlist vs other private queries)
    and ties the **monlist** vector to **CVE-2013-5211** (DRDoS amplification).
  - New CVE-catalog records (CVE-2013-5211, CVE-2014-9295, CVE-2016-7434,
    CVE-2016-9311, CVE-2015-5477, CVE-2008-1447, CVE-2002-0013) and new
    ATT&CK mappings (`snmp-config-exfil`→T1602.001, `snmp-getbulk-amplification`
    /`ntp-mode7-private`→T1498.002, `snmp-default-community`→T1078.001,
    `dns-sig-query`→T1190, `dns-tkey-query`→T1499, …); added CWE-617.

- **NetNTLMv1 capture (SMB + RDP).** The NTLMSSP AUTHENTICATE parser now
  distinguishes the two NetNTLM dialects by the NT-response length and emits the
  correct hashcat hash: **NetNTLMv2** (variable-length response → mode **5600**,
  unchanged) and **NetNTLMv1** (24-byte response → mode **5500**, in a new
  `meta.ntlmv1_hash`), including the **NTLM2 session-response / ESS** variant
  (LM = client challenge + zero-padding; the effective challenge is
  `MD5(serverChallenge‖clientChallenge)[:8]`, flagged `meta.ntlm_ess`). Flagged
  `*-ntlmv1-capture`. Previously a v1 (or ESS-v1) response was mis-emitted as a
  malformed v2 line and the LM field was ignored; now both v1 and v2 are captured
  correctly and surface on `/captures` as hash credentials.

- **20 more emulated HTTP vulnerabilities.** The deceptive web app now serves
  convincing loot for 20 additional probe paths: exposed VCS metadata
  (`/.git/HEAD`, `/.svn/entries`, `/.hg`, `/.bzr`), auth/config files
  (`/.htpasswd`, `/.htaccess`, `/web.config`, `/WEB-INF/web.xml`), leaked
  credentials (`/.aws/credentials`, `/.ssh/id_rsa`, `/docker-compose.yml`,
  `/.dockercfg`, `/.npmrc`, `/.netrc`, `/.env.local|.production|.dev|.example`),
  and exposed management/observability endpoints (`/server-status`,
  `/server-info`, `/actuator/*`, `/jolokia`, `/solr/admin`, `/debug/pprof`,
  `/metrics`, `/telescope`, `/_profiler`, `/manager/html`). File leaks flag
  `webapp:secret-file-probe`; endpoint exposures flag dedicated anomalies
  (`apache-status-exposed`, `spring-actuator-exposed`, `jolokia-exposed`,
  `solr-admin-exposed`, `pprof-exposed`, `metrics-exposed`,
  `laravel-telescope-exposed`, `symfony-profiler-exposed`, `tomcat-manager-probe`,
  `apache-info-exposed`), each mapped to ATT&CK reconnaissance/access techniques.

- **Deeper BGP / SunRPC(NFS) / MQTT protocol analysis + new CVEs & ATT&CK.**
  - **BGP** — OPEN now decodes the protocol version, 4-octet ASN capability
    (`bgp_peer_as4`) and multiprotocol capability; **UPDATE** parses NLRI and
    flags **route-injection** (prefix hijack, `bgp-route-injection`→T1557) and
    **route-withdrawal** (`bgp-route-withdrawal`→T1498), with per-message
    `intent` labels. New CVEs **CVE-2023-38802** and **CVE-2022-40302** (FRR
    BGP).
  - **SunRPC / rpcbind** — names the queried RPC program (`rpc_program_name`),
    parses **GETPORT** targets, and flags **NFS-stack enumeration**
    (`rpcbind-nfs-enum`→T1135) when nfs / mountd / nlockmgr / statd / nfs_acl is
    looked up — NFS reconnaissance is captured at the portmapper entry point.
    New CVE **CVE-2017-8779** (rpcbomb).
  - **MQTT** — stamps attacker-`intent` for broker login / anonymous probe and
    for **wildcard subscribe** (`#`/`+`/`$SYS` topic harvesting / exfil).

- **Dedicated NFS (2049) handler.** New `nfs` handler that captures the
  mount/traversal/read attempt itself (the `rpcbind` handler captures the
  enumeration that precedes it). It parses the record-marked RPC call, names
  the program / version / procedure, and for **NFSv4 COMPOUND** decodes the
  operation list (`nfs_ops`: PUTROOTFH / GETFH / LOOKUP / READDIR / READ / …).
  It captures the **AUTH_UNIX** uid/gid/hostname the client claims — a **uid 0**
  is flagged `nfs-root-access` (no_root_squash bypass, →T1078.003). It flags
  export traversal (`nfs-export-enum`→T1135), file reads (`nfs-file-read`→T1039)
  and client negotiation (`nfs-client-setup`), and answers like a live-but-
  locked-down NFSv4 root: `PUTROOTFH`/`PUTFH`/`GETFH` succeed (handing back a
  root filehandle so the scanner keeps probing) while any traversal/read gets
  `NFS4ERR_ACCESS` — no real data leaves. NFSv3 data procedures get a plausible
  `NFS3ERR_ACCES` reply. Wired into the `nfsserver` archetype role and the
  `legacy-unix` example. New ATT&CK technique **T1039** (Data from Network
  Shared Drive) with its D3FEND mapping.

- **Deeper OT / building-automation protocol analysis (S7comm, DNP3, Modbus,
  BACnet) + attacker-intent + ATT&CK-for-ICS.** Each handler now stamps an
  `intent` summary and recognizes the dangerous control/recon operations:
  - **S7comm (102)** — previously stopped after the COTP handshake; now runs
    the S7comm session: negotiates **Setup Communication**, answers **SZL
    reads** with a believable S7-300 module/firmware identity (the CPU
    fingerprint nmap's `s7-info` / plcscan parse, `ics-field-device-probe`),
    and classifies **Read Var** (`ics-process-data-access`), **Write Var**
    (`ics-plc-write`), **PLC STOP/control** (`ics-plc-mode-change`) and
    **block up/download** (`ics-plc-program-access`).
  - **DNP3 (20000)** — previously only the data-link layer; now de-blocks the
    user data and parses the **application function**: READ
    (`ics-process-data-access`), WRITE (`ics-plc-write`), SELECT/OPERATE/
    DIRECT_OPERATE (`ics-dnp3-control`), and COLD/WARM_RESTART / STOP_APPL
    (`ics-device-restart`).
  - **Modbus (502)** — adds per-operation `intent` and handles **FC 0x08
    Diagnostics**, flagging Restart-Communications / Force-Listen-Only as
    control/DoS (`ics-modbus-diagnostic`).
  - **BACnet (47808)** — adds `intent` and flags **ReadProperty** point
    enumeration (`bacnet-property-read`), **Who-Is/Who-Has** discovery
    (`bacnet-device-discovery`), and maps the previously-unmapped
    DeviceCommunicationControl / ReinitializeDevice / AtomicWriteFile markers.
  - New ATT&CK-for-ICS technique **T0816** (Device Restart/Shutdown) with its
    D3FEND mapping; new `ics-device-restart` + BACnet anomaly mappings.

- **Deeper IEC-104 / EtherNet/IP / OPC-UA / MMS analysis + attacker-intent.**
  - **IEC-104 (2404)** — flags **General/Counter Interrogation** as process-
    image enumeration (`ics-process-data-access`), **single/double commands**
    as control-point actuation (`ics-iec104-command`→T0855), **set-point
    commands** as setpoint changes (`ics-plc-write`), and **reset-process** as
    a device reset (`ics-device-restart`); answers set-point/reset confirmations.
  - **EtherNet/IP (44818)** — now services **SendRRData/SendUnitData**: parses
    the embedded **CIP** request, names the service (`cip_service`), and flags
    Get/Read (`ics-process-data-access`), Set/Write (`ics-plc-write`),
    Reset/Stop (`ics-device-restart`), Start (`ics-plc-mode-change`) and
    Forward_Open (`ics-field-device-probe`), answering a believable CIP success.
  - **OPC-UA (4840)** — after the Hello/ACK, reads the **OpenSecureChannel** and
    records the requested **SecurityPolicyUri**; a `#None` policy (the classic
    exposed-server misconfig) is flagged `ics-opcua-insecure-policy`.
  - **MMS / IEC-61850 (102)** — after the association completes, parses the
    first MMS confirmed-request and names the service (`mms_service`): getNameList/
    identify = data-model enumeration (`ics-field-device-probe`), read
    (`ics-process-data-access`), write (`ics-plc-write`).

- **Attacker-intent + control/recon classification for the remaining ICS
  decoys.** Adds an `intent` summary to every remaining OT handler and, where
  the protocol carries a command, distinguishes recon reads from control
  writes / mode changes / resets:
  - **MELSEC (MC 3E)** — names the command (`command_name`) and flags Batch/
    Random Read (`ics-process-data-access`), Batch/Random Write (`ics-plc-write`),
    Remote RUN/STOP/PAUSE (`ics-plc-mode-change`), Remote Reset
    (`ics-device-restart`), Read-CPU-Model (`ics-field-device-probe`).
  - **Beckhoff ADS/AMS** — flags Read (`ics-process-data-access`), Write/ReadWrite
    (`ics-plc-write`), WriteControl run-state change (`ics-plc-mode-change`),
    ReadDeviceInfo/ReadState (`ics-field-device-probe`).
  - **Omron FINS** (UDP + FINS/TCP) — adds Memory-Area Read recon
    (`ics-process-data-access`) and CPU-data fingerprint (`ics-field-device-probe`)
    alongside the existing write / mode-change / program-download flags.
  - **Emerson ROC Plus** — classifies parameter read (config/measurement theft),
    parameter write (`ics-plc-write`), and login (`ics-roc-plus-login`).
  - **CODESYS, GE-SRTP, HART-IP, PCWorx, Red Lion Crimson, Triconex TriStation,
    GE-EGD, BSAP-IP, LonTalk** — intent labels (the TriStation program-download
    path keeps its `ics-safety-controller-manipulation` flag).

- **Deeper PROFINET analysis (DCE-RPC + DCP).**
  - **PROFINET-IO (UDP 34964)** — now names the CM operation
    (`profinet_operation`: Connect / Release / IODRead / IODWrite / IODControl /
    ReadImplicit) and adds `intent` + read classification
    (`ics-process-data-access` for IODRead/ReadImplicit) alongside the existing
    IODWrite / IODControl flags.
  - **PROFINET-DCP responder (L2, sniffer side)** — previously answered only
    **Identify** requests. It now also recognizes **DCP Set** (FrameID 0xFEFD):
    a NameOfStation / IPParameter reassignment or a Control/factory-reset, which
    is configuration manipulation of the cell, not recon. Set requests raise a
    new high-severity `honeynet:profinet_dcp_set` event (→T0836/T0831) carrying
    the targeted option, and the addressed virtual station ACKs the Set (L2
    unicast) so it appears to land. The Identify probe meta now also carries
    `service: identify`.

## [2.12.0] — 2026-06-06

### Added

- **Web-UI page toggles + service-activity tint config.** New `ui.pages` map
  enables/disables individual secondary console pages by slug (`charts`,
  `credentials`, `dns`, `web`, `databases`, `tunnels`, `fleet`, `iocs`,
  `campaigns`, `correlation`, `attack`, `map`, `captures`, `fingerprints`,
  `devices`, `topology`, `alerting`, `errors`, `docs`) — a disabled page is
  hidden from the nav and its route returns 404; the core pages (summary /
  events / search / timeline / profiles / health / config) can't be disabled.
  New `ui.service_activity` (default on) toggles the summary's service-card
  activity highlight. An unknown `ui.pages` slug is rejected at config validation.
- **NTP decoy in `example-CENTOS-SERVER-EXTENDED`.** Adds an `ntp` listener
  (UDP 123) and honeynet host service — a believable time server that recognizes
  the MONLIST / mode-6 / mode-7 amplification-abuse vectors.
- **Per-protocol analytics pages: DNS, web, and databases.** Three new pages
  appear in the nav (and respond) only when the running config exposes a relevant
  listener:
  - **`/dns`** — queries/hour, query types/commands, top queries (qname) + top
    registrable domains, top replies, the bounded query log, and the
    attacks/misuses/manipulations table (tunnelling / amplification / zone
    transfer / DGA …) with CVE→CWE.
  - **`/web`** — requests/hour, top URLs, top HTTP headers, top replies (HTTP
    status), **top-10 attacks** + **top-10 attackers**, every unique URL and file
    accessed, and the web-attack-class / CVE / CWE table.
  - **`/databases`** — events/hour, by-engine split, top queries/commands, top
    databases, top replies (version banners), top-10 attacks + attackers, and the
    injection/abuse / CVE / CWE table — across mysql/postgres/mssql/mongodb/redis/….
- **Credential captures by service.** The `/credentials` page gains a pie + bar
  comparing how many captured logins came from each service (ssh / ftp / telnet /
  …), so the credential-attack load per protocol is visible at a glance.
- **Summary service-activity highlight.** Each service card on the summary's
  listener board is now tinted (and shows its event count) when that service saw
  any access or attempt in the window.
- **RDP now harvests offline-crackable NetNTLMv2 hashes.** The `rdp` handler
  previously stopped after the TLS handshake and only read one CredSSP message
  (so a standards-compliant NLA client — which sends NTLM **type 1** first —
  leaked nothing crackable). It now drives the CredSSP/NLA exchange one round
  further: it issues the NTLMSSP **CHALLENGE** (type 2, wrapped in SPNEGO + a
  CredSSP `TSRequest`), reads the client's **AUTHENTICATE** (type 3), and emits
  the hashcat-mode-5600 **NetNTLMv2** hash (`ntlmv2_hash`) plus the
  username/domain/workstation — reaching parity with the SMB/WinRM capture, and
  surfacing on `/captures` as a hash credential. The credential is never
  validated (capture only); it still also records the pre-auth `mstshash`
  username, JA3/JA3S, and BlueKeep probes. Flagged `rdp-ntlmv2-capture`.

- **`example-CENTOS-SERVER-EXTENDED` config.** A superset of the CentOS
  all-in-one decoy with a much wider service surface — adds **Telnet (23)**,
  **SNMP v2c (UDP 161)**, **SMB/CIFS (445)**, **MSSQL (1433 + UDP 1434 browser)**,
  **MySQL/MariaDB (3306)**, **PostgreSQL (5432)**, **Redis (6379)**, **MongoDB
  (27017)**, **RDP (3389 TCP+UDP)**, and **IMAPS/POP3S (993/995)**, all backed by
  the existing protocol emulators. Its virtual host carries an `ipv6:` address
  and answers + captures **ping and ping6**.
- **ICMP / ICMPv6 echo capture, and a full IPv6 responder.** The honeynet ICMP
  responder now emits a captured-traffic event (`honeynet:icmp_echo`, proto
  `icmp`) for every echo / timestamp / address-mask probe (previously it only
  replied and debug-logged), and gained a complete **ICMPv6** path: virtual
  hosts with an `ipv6:` address answer **ping6** (echo) and the **Neighbor
  Discovery** (solicitation → advertisement) that makes the v6 address reachable.
  New `honeynet.hosts[].ipv6` and `icmp_responder.severity` config fields.
- **Web API-recon decoys.** The fake web app now serves believable **`/api`**
  (REST discovery root), **`/openapi.json` + `/swagger`** (OpenAPI 3 spec +
  Swagger UI), and **`/graphql` + `/graphiql`** (GraphQL endpoint; an
  introspection POST returns a fake schema and is flagged). Each probe is flagged
  (`webapp:api-probe` / `webapp:api-spec-probe` / `webapp:graphql-introspection`).
- **Secret-file probes now name the file.** A `webapp:secret-file-probe` / LFI
  attempt records the specific path it tried to read (`meta.probed_file` — `/.env`,
  `/config.php.bak`, `/.git/config`, or an LFI traversal target), and the
  attacker profile gains a **"sensitive files probed"** section listing them — so
  the anomaly reveals *which* files were targeted, not just that a probe happened.
- **Clickable IPv6 badges + a source address-family search filter.** The `IPv6`
  chip next to v6 addresses is now a link to the search filtered to all
  IPv6-source events, backed by a new `family=ipv4|ipv6` search filter (also a
  dropdown on the search form).

- **Network-traffic charts on `/charts`.** A new **Network traffic** section
  plots four time series over the selected range: **incoming** and **outgoing**
  throughput (auto-scaled network bit-rate, **kb/s ↔ Mb/s**) and **incoming** and
  **outgoing** packet rate (**packets/s**). These are driven by new per-connection
  counters every listener now stamps onto each event — `bytes_in` / `bytes_out`
  (full, uncapped volume, via a lock-free counting wrapper applied to every
  accepted TCP connection independent of pcap capture) and `pkts_in` / `pkts_out`
  (application-layer read/write segments, a close proxy for on-wire packets since
  the sensor captures from inside the app goroutine, not a raw socket). UDP is
  counted per datagram. Rates are each bucket's summed volume ÷ the bucket width;
  idle buckets read zero.
- **Configurable upload retention + captures for every upload path.** A new
  `sensor.payloads.max_upload_kb` (default 1 MiB; CLI
  `--set sensor.payloads.max_upload_kb=<KiB>`) caps how much of an uploaded file
  is captured, so operators can keep full samples. Files obtained **any** way —
  FTP uploads, web/multipart uploads, a raw request body after the HTTP headers,
  or a binary embedded mid-stream / base64-encoded in a URL or header — are now
  extracted (`payload-embedded`), checksummed, classified + YARA-scanned, and
  persisted to `<data_dir>/payloads/`, so they all appear on the **captures**
  page (previously only files whose magic sat at offset 0 were harvested).
- **FTP upload capture → checksums + classification + YARA.** Both FTP handlers
  now treat a STOR/STOU/APPE as a malware/webshell drop: the uploaded file is
  read (bounded), **MD5/SHA1/SHA256** checksummed into the event meta, flagged by
  type and drop-context (`ftp-elf-upload` / `ftp-pe-upload` / `ftp-macho-upload`
  / `ftp-archive-upload` / `ftp-script-upload`, `ftp-executable-upload`,
  `ftp-keymaterial-upload`, `ftp-script-dropper-upload`, `ftp-webshell-upload`,
  and `ftp-anon-writable-drop` for /pub /incoming /upload /tmp …), and **surfaced
  as the connection payload** so the sensor's payload pipeline runs full
  file-type classification + the built-in YARA engine + persistence over the
  captured file. The `ftp_files` handler also now **accepts anonymous uploads**
  (was download-only) and advertises the full vsftpd FEAT set.
- **FTP scanner/client fingerprinting** (`toolfp.IdentifyFTP`) — identifies the
  client/scanner from the anonymous credential it presents (nmap `IEUser@`,
  Firefox/Chrome/wget/lftp/ncftp default passwords; self-identifying zgrab /
  masscan / nuclei / hydra / medusa / ncrack / censys / shodan). Wired into both
  FTP handlers (`tools` meta + `tool:<name>` anomaly).
- **More YARA classification rules / file-type coverage:** a `Private_Key_Material`
  rule (PEM / OpenSSH / PuTTY private keys + authorized public keys), a classic
  `WEBSHELL_ASP_Classic` rule, and **archive-contains-executable** detection in
  the static analyzer (a zip/jar/apk member that is a PE/ELF/Mach-O by magic *or*
  by dangerous extension → `payload-archive-exe` anomaly + report trait). ELF/PE
  uploads, shell-dropper scripts, packed/UPX binaries, Mirai/Gafgyt, XMRig and
  reverse-shell one-liners are already covered by the existing built-in pack and
  now fire on FTP uploads too via the payload pipeline.
- **HTTP/2 frame-DoS detection** in the h2c handler (`internal/listener/handler/http2.go`),
  each surfaced as a `cve:<id>` event + descriptive anomaly:
  - **CVE-2026-49975 "HTTP/2 Bomb"** (`http2-bomb`) — thousands of near-empty
    HPACK headers (header-field-count amplification; the count nginx's fix caps
    at 1000), plus the zero-window Slowloris hold (`http2-zero-window-hold`,
    detected from `SETTINGS_INITIAL_WINDOW_SIZE=0`).
  - **CVE-2016-6581 HPACK Bomb** (`http2-hpack-bomb`) — a tiny header block that
    decodes to a huge byte size (decoded:wire amplification ≥ 64×, ≥ 1 MiB).
  - **CVE-2016-8740** (`http2-continuation-unbounded`) — an unbounded header
    block accumulated across CONTINUATION frames (≥ 16 KiB on one stream).
  - **CVE-2016-1546** (`http2-worker-starvation`) — many half-open request
    streams (≥ 32) holding worker threads/buffers.
  - **CVE-2025-53020** (`http2-memory-exhaustion`) — aggregate HPACK-decoded
    memory across the connection exceeding 4 MiB (Apache mod_http2 family).

  The HPACK decode was also hardened: it now streams via a bounded emit callback
  (retaining only the first 256 fields, capping single strings) so the honeypot
  *measures* a decompression bomb without being bombed by it — the previous
  `DecodeFull` over a 1 MiB-capped block could itself blow up. New catalog
  records (CWE-400/409/770, T1499/impact) and `CWE-409` (data amplification)
  added.
- **Credential analytics page (`/credentials`).** A dedicated view over every
  captured login attempt: top usernames / passwords tried, password-length and
  composition (digits-only / lowercase / has-symbol / mixed) distributions, the
  per-account heatmap, a per-source **spray-vs-brute** classification (password
  spray / brute force / credential stuffing / repeated / probe, from the
  user×password fan-out), and a **credential-reuse** table surfacing secrets
  seen from two or more distinct sources (shared wordlists, or one actor
  rotating IPs). Linked from the top nav.
- **New chart-page analytics.** The `/charts` page gains: a **destination-port ×
  hour-of-day heatmap** and a **dest-port leaderboard**; **CVE analytics** —
  exploit-attempt leaderboard, disclosure-year (n-day age) histogram,
  **EPSS-weighted exposure** ranking (attempts × EPSS), and the **CWE** weakness
  classes targeted; **per-entity trend sparklines** (one line per top ASN /
  country over time); a **force-directed actor-clustering graph** (sources link
  to their shared ASN / TLS-SSH-fingerprint hubs, so one actor rotating IPs forms
  a visible cluster — backed by a new Fruchterman-Reingold `force` renderer in
  `charts.js`); and a **coverage-gap report** (destination ports that were probed
  but that no configured listener answers — a ranked "what should we emulate
  next" list).
- **IPv6 address badge.** Listings and detail views now tag genuinely-IPv6
  source/host addresses with a small `IPv6` chip (profiles list + header,
  events, captures, threat map, storyline, tunnels, devices, credential spray
  table, ARP-conflict and pcap tables). IPv4 and IPv4-mapped addresses are not
  badged.

### Changed

- **`--help` lists subcommands alphabetically.** The top-level usage now prints
  the subcommand table sorted by name (the dispatch order is grouped by purpose),
  so commands are easy to scan.
- **More clickable UI labels.** On the **threat map** page the *events* /
  *countries* / *ASNs* counter boxes are now links (events → the event log;
  countries / ASNs → their on-page breakdown). In an attacker profile the
  *tools / scanners*, *ATT&CK tactics*, *web-attack classes*, *domains / SNIs
  requested*, *harvested URLs*, *protocol intelligence* (TLS versions / SSH KEX /
  QUIC SNI+ALPN), and the *origin & infrastructure* **network** row (cloud
  provider + net-class) link to that source's filtered events. On the **tunnels
  & covert transport** page the *kind* labels (by-type bars + the by-source and
  recent chips) link to the events that produced each detection.

## [2.11.0] — 2026-06-05

### Fixed

- **Profile page "internal error" / `unable to open database file (14)`.** The
  per-source profile query (`WHERE src_ip = ? AND time >= ? ORDER BY time DESC`)
  filtered on one index and sorted on another, so SQLite materialised the sort
  in an on-disk temp file; under a locked-down runtime (systemd
  `PrivateTmp`/`ProtectSystem`, or a non-writable/missing `TMPDIR`) that open
  failed with `SQLITE_CANTOPEN(14)`. The store now opens with
  `temp_store=MEMORY` (transient sort/GROUP-BY B-trees stay in RAM, fixing this
  class of error for every query) and adds a composite `(src_ip, time DESC)`
  index so the profile query is index-ordered with no sort at all. The index is
  created automatically on the next start for existing databases.

### Added

- **+100 more IoT / IIoT / OT / building-automation YARA rules** (`artifactscan`
  pack now **469 rules**). A second domain-focused set: more IoT botnet/malware
  families (AESDDoS/Dofloo, Ddostf, BillGates, LuaBot, Remaiten, Wifatch,
  BCMUPnP_Hunter, Mirai Owari/Sora/Wicked, FreakOut, …) and router/camera
  exploit-CGI patterns (Linksys JNAP, MikroTik Winbox, ASUS infosvr, Huawei HG,
  ZTE, Foscam/Axis/Vivotek/GeoVision/Sony cameras, Tenda/TOTOLINK/DrayTek/Netgear
  SOAP); more OT/ICS protocol & tooling fingerprints (PCWorx, Crimson v3,
  ProConOS, EtherCAT, POWERLINK, SERCOS, Emerson ROC, ICCP/TASE.2, DLMS/COSEM,
  ANSI C12, TwinCAT ADS, WAGO, PLCnext, B&R, Kepware/Matrikon OPC, ICSSploit,
  Nmap ICS NSE, Redpoint, GRASSMARLIN, plcinject, Snap7); more ICS malware
  (GreyEnergy, Exaramel, KillDisk, AcidRain/AcidPour, LookBack, LockerGoga,
  Cring, MegaCortex); more building-automation product references (Siemens
  APOGEE, Carrier i-Vu, Trane Tracer, Trend IQ, Sauter, Iconics, ABB Cylon,
  Priva, LOYTEC, WattStopper, Philips Hue, Calimero, Niagara N4, Schneider
  SmartX); and adjacent domains — smart meter (DLMS/ANSI C12, Termineter),
  automotive (CAN-utils, UDS/CaringCaribou, J1939), medical (DICOM, HL7, FHIR),
  maritime (NMEA/AIS), rail (RaSTA/Genisys), and discovery (SSDP, WS-Discovery,
  mDNS, LoRaWAN, MQTT Sparkplug B).
- **+30 CWE weakness-class names** (128 total) — memory-safety, crypto,
  certificate, auth, concurrency and logging classes common in IoT/embedded/OT
  firmware (out-of-bounds read, hard-coded password, weak/missing encryption,
  TOCTOU, request smuggling, insufficient session expiration, …).
- **YARA engine documentation** — new [`docs/yara.md`](docs/yara.md) (also under
  the in-product **docs** tab): when rules run, the built-in pack, per-rule
  severity, the supported rule subset + module surface, loading your own `.yar`
  rules, known-malware hash sets, and the `analyze` CLI. The FAQ gains a
  top-of-page index and an *Artifact analysis (YARA)* + *IPv6* section.

### Changed

- **Attacker-profile labels are clickable.** In `/profiles/<ip>` the
  recent-events rule column (e.g. `webapp:secret-file-probe`, `cve:CVE-…`) links
  to that source's filtered events, CVE rules also link to the CVE reference, and
  anomaly tags link to the source-scoped search.
- **CentOS example serves IPv6.** `configs/tarpit-honeypot.example-CENTOS-SERVER.yaml`
  binds the IPv6 wildcard `"[::]:<port>"`, so on a dual-stack host every service
  is reachable over both IPv6 and IPv4 on one socket (was IPv4-only `0.0.0.0`).
- **Version → 2.11.0.**

- **+100 IoT / IIoT / OT / building-automation YARA rules** (`artifactscan` pack
  now ~369 rules). New domain coverage: IoT botnet families (Hajime, Hide-N-Seek,
  dark_nexus, Torii, Persirai, Reaper, BrickerBot, VPNFilter, Cyclops Blink,
  QSnatch, Moobot, EnemyBot, Zerobot, RapperBot, Mukashi, Echobot, Fbot,
  Matryosh, Condi, Kaiji, BotenaGo, Chalubo, Katana, Pink); multi-arch IoT
  loader/dropper and device-exploit patterns (busybox/tftp loaders, HNAP, UPnP
  SOAP, TR-064, Realtek SDK, GoAhead/JAWS cameras, Netgear/D-Link, GPON, Dahua,
  Hikvision, Mirai default-credential tables); OT/ICS protocol & tooling
  fingerprints (Modbus, S7comm, DNP3, EtherNet/IP, BACnet, PROFINET, IEC-61850
  MMS, IEC-104, OPC UA/DA, Niagara Fox, CODESYS, Omron FINS, Mitsubishi MELSOFT,
  GE-SRTP, HART-IP, KNX, LonWorks, M-Bus, plcscan/s7scan/smod); OT/ICS malware
  (Industroyer/CrashOverride, Industroyer2, TRITON/TRISIS, Havex, BlackEnergy,
  EKANS, PIPEDREAM/INCONTROLLER, IRONGATE, Fuxnet, CosmicEnergy, FrostyGoop,
  Conficker); building-automation product references (Tridium Niagara, JCI
  Metasys, Siemens Desigo, Honeywell EBI, Schneider EcoStruxure, Automated Logic
  WebCTRL, Delta Controls, Distech, Reliable Controls, KNX/ETS, Crestron, AMX,
  Lutron, DALI); and smart-home/firmware artifacts (MQTT/CoAP, Zigbee/Z-Wave/BLE
  tooling, RTSP/ONVIF cameras, UART/JTAG, SquashFS/U-Boot/binwalk, SCADA/HMI
  products). Severities follow the existing tiering (malware/botnet families
  critical; protocol/product references and recon tagged medium/high).

- **+100 more built-in YARA rules** (`artifactscan` pack now ~269 rules). Adds
  nation-state/APT implants (SUNBURST, Stuxnet, Flame, Winnti, ShadowPad,
  X-Agent, Zebrocy, Lazarus Bankshot, Kimsuky BabyShark, Carbanak, Equation),
  more Linux/Unix malware & rootkits (Mirai-Satori, Mozi, Tsunami/Kaiten,
  Bashlite/Gafgyt, BPFDoor, Symbiote, RotaJakiro, Reptile, Drovorub, Sysrv,
  Outlaw, LD_PRELOAD hiders), macOS malware (Shlayer, XCSSET, KeRanger, AMOS,
  Bundlore, CoinTicker, Macma, Silver Sparrow), Android families (Cerberus,
  Anubis, Joker, FluBot, SpyNote, GodFather), phishing kits & exfil channels
  (16Shop, Evilginx, Modlishka, Office365 kits, Telegram-bot / Discord-webhook
  exfil), LOLBin & reverse-shell script patterns (curl|bash, /dev/tcp,
  Python/Perl/PHP/Ruby shells, rundll32/wmic-XSL/cmstp/MSBuild/InstallUtil),
  more exploit-traffic (Shellshock, Spring4Shell, Log4Shell, Struts OGNL, JNDI,
  NoSQLi, CRLF, gopher/dict SSRF, PHP dynamic-eval, Ghostcat, GraphQL
  introspection, JS heap-spray), packers/protectors (Enigma, PECompact, Petite,
  MEW, FSG, NsPack, MoleBox, Obsidium, .NET Reactor, ConfuserEx, SmartAssembly,
  PyArmor), behavioral traits & pe-module rules (process hollowing, UAC bypass,
  LSASS dump, AMSI patch, anti-VM, token impersonation, raw keylogger,
  QueueUserAPC injection, CryptoAPI ransom set, anti-debug imports), and banking
  trojans / clippers (Ursnif, Zeus/Zbot, SpyEye, Citadel, Tinba, crypto
  clipper). Severities follow the existing tiering (families critical;
  recon/heuristic/packer rules tagged down).

- **+100 more built-in YARA rules** (`artifactscan` pack now ~169 rules). New
  coverage: ransomware families (LockBit, Conti, REvil, BlackCat, Hive, Ryuk,
  WannaCry, Phobos, Dharma, STOP/Djvu, Maze, Cl0p, Black Basta, Akira, Royal),
  RATs/backdoors (Gh0st, PlugX, Orcus, NetWire, Adwind, BitRAT, XWorm, Pupy,
  AveMaria, Houdini, Crimson, ZeroAccess, …), stealers/loaders (Vidar, Raccoon,
  Azorult, Xloader, Rhadamanthys, Lumma, StealC, Amadey, SmokeLoader, GuLoader,
  BazarLoader, IcedID, Qakbot, Dridex, Ramnit), document/script droppers (VBA
  auto-exec, VBS/HTA/JScript, Office DDE, RTF Equation Editor, XLL), more
  webshells (Godzilla, AspxSpy, Caidao, reGeorg, Tunna, p0wny, …), offensive/
  recon/cracking tooling (Responder, Impacket, CrackMapExec, Nmap, masscan,
  sqlmap, Hydra, hashcat, John, Gobuster, ffuf, PowerCat, socat, plink, AdFind,
  Seatbelt), persistence/defense-evasion patterns (schtasks, Run-key, WMI
  subscription, Startup folder, Defender/firewall disable, event-log clear,
  shadow-copy delete, ETW patch, timestomp), exploit-traffic patterns (SQLi,
  XSS, path traversal, PHP LFI wrappers, command injection, cloud-metadata SSRF,
  XXE, SSTI, Java deserialization), and more miners/Linux malware (CoinHive,
  Kinsing). Each rule carries an appropriate severity (trait/recon rules tagged
  down to high/medium; named-threat families stay critical).

- **Detection-content expansion: +50 YARA rules, +30 CVEs, +30 CWEs, +30 service
  emulators.** The built-in `artifactscan` pack gains 50 rules covering RATs
  (njRAT, AsyncRAT, Quasar, Remcos, NanoCore, DarkComet), stealers (RedLine,
  AgentTesla, Lokibot), C2/offensive tooling (Sliver, Havoc, Brute Ratel,
  Covenant, Empire, Mimikatz, Rubeus, SharpHound, PsExec, Chisel/ngrok/frp
  tunnels), webshells (China Chopper, WSO, b374k, Behinder, AntSword, Weevely),
  packers (VMProtect/Themida/ASPack), LOLBIN/PowerShell abuse, coin miners,
  Linux malware (XorDDoS, Diamorphine), and `pe`-module behavioral rules
  (keylogger hooks, service persistence) — each tagged with an appropriate
  severity. The CVE catalog gains 30 web/appliance exploit signatures (Spring
  Cloud Gateway/Config, Lucee, Apache OFBiz, Jira SSRF/SSTI/file-read,
  ManageEngine, Solr, Citrix, GitLab ExifTool, PHP-CGI, SnakeYAML, …) with
  CWE/CPE/EPSS cross-references, the CWE dictionary grows by 30 weakness classes,
  and 30 new Lua service emulators ship under `configs/scripts/` (Gophish, EMQX,
  Wazuh, MISP, TheHive, Nessus, GLPI, Jellyfin, Home Assistant, TrueNAS, …).
- **YARA module support + bigger built-in rule pack** — the CGO-free rule
  engine (`internal/artifactscan`) now evaluates a practical slice of the YARA
  module surface: `filesize`, the integer readers `uint8/16/32(be)` and
  `int8/16/32`, arithmetic/comparison/bitwise operators, and the `pe`, `elf`,
  `math`, and `hash` modules (`pe.imports`, `pe.entry_point`, `pe.is_dll`,
  `pe.number_of_sections`, `elf.type`, `elf.number_of_sections`, `math.entropy`,
  `math.in_range`, `hash.md5/sha1/sha256`). Module facts are sourced from the
  std-lib `debug/pe` · `debug/elf` parsers and computed once per artifact. This
  unlocks the large fraction of community `.yar` rules that were previously
  skipped as "unsupported construct". The built-in pack gains Cobalt Strike,
  Meterpreter, XMRig, JSP/ASP.NET webshell, Mirai/Gafgyt, cron-persistence,
  sandbox-evasion, and PE process-injection / dynamic-API-resolution rules. The
  `analyze` CLI now prints each matched rule's description.
- **Per-rule YARA severity tiering** — a captured artifact's `malware:capture`
  severity is now driven by the matched rule's declared severity (rule meta
  `severity = "low|medium|high|critical"`, or a numeric `score`) instead of
  every YARA hit forcing Critical. Rules that declare neither still default to
  critical (unchanged for the high-confidence built-ins), while generic
  trait/heuristic rules tag down — the built-in packer / sandbox-evasion rules
  are now `medium` and the credential-theft / XOR-stub / dynamic-API-resolution
  loader rules `high`, so they sit at the High baseline rather than over-firing
  Critical. A known-malware hash match remains Critical regardless.

- **Native ATT&CK matrix** on the `/attack` page — a tactic column per observed
  tactic (kill-chain order), each a stack of technique cells shaded by event
  volume and linking to the per-technique drill-down. Server-rendered from the
  existing ATT&CK aggregation.
- **Activity punchcard** on the `/attack` page — a 7×24 UTC weekday × hour-of-day
  heatmap (14-day window) of event volume, revealing the operators' working
  hours and timezone.
- **In-browser session replay** — `/replay?name=<cast>` / `?event=<id>` plays
  back recorded interactive SSH/Telnet shells: the asciinema v2 cast is parsed
  server-side and rendered in a terminal with play / pause / seek / speed (ANSI
  stripped, `\r`/`\b`/`\t`/`\n` handled). Linked from the captures session list
  and event detail. Replaces the static replay list with a real timed player.
- **Enrichment installer auto-mapping** — `install-enrichment.sh` now places the
  new datasets (cloud-provider ranges, fingerprint DBs, malware-hash set, p0f.fp)
  automatically; `list-paths` enumerates them so the air-gapped install flow
  maps each bundle file to its configured destination.

- **Enriched attacker profile page** — the `/profiles/<ip>` dossier now surfaces
  data already attached to events but previously hidden: an **origin &
  infrastructure** card (reverse DNS, geo, ASN/org, net-class, cloud provider,
  known scanner, passive OS fingerprint, MAC vendor) and a **protocol
  intelligence** section (TLS versions, negotiated SSH KEX + weak-primitive
  flag, HTTP/2-3, QUIC SNI/ALPN), plus OPC-DA/ICS items probed and per-
  fingerprint client/tool attribution.
- **Cloud-provider CIDR tagging** (`sensor.cloud_ranges`) — sources inside a
  provider's published IP ranges (AWS/GCP/Azure/Cloudflare/DigitalOcean) get an
  authoritative `cloud_provider` tag, more precise than the asn_org heuristic.
- **Passive OS fingerprinting** (`internal/p0f`) — builds a p0f-v3 signature
  from a TCP SYN and matches it against a DB (embedded curated set + optional
  `sensor.sniffer.p0f_db` p0f.fp) to stamp `os_fingerprint` / `p0f_signature`,
  refining the coarse TTL `os_guess`.
- **Known-scanner attribution: +28 operators** — ProjectDiscovery, GreyNoise,
  FOFA/Knownsec, ZoomEye, QiAnXin Hunter, Netlas, FullHunt, Spur, IPinfo,
  RiskIQ, Tenable, Qualys, Detectify, Cyble, IntelX, Greenbone, Deutsche
  Telekom, Ahrefs, SEMrush, and more.
- **Known-malware hash attribution** (`sensor.payloads.malware_hashes`) — the
  `artifactscan` engine matches a captured artifact's SHA-256 against an
  abuse.ch (ThreatFox/MalwareBazaar) hash set, flagging `known_malware` +
  `malware_family` and elevating to Critical. New `analyze --hashes` flag.
- **Fingerprint → client/tool DB** (`sensor.fingerprint_db`) — JA3/JA4/JA4H/
  HASSH corpora (FoxIO JA4DB, community JA3) map a fingerprint to the client /
  library / malware behind it (`<kind>_client` on events, shown on the profile).
- **`fetch-enrichment.sh` extended** — now also downloads cloud-provider IP
  ranges, abuse.ch ThreatFox/MalwareBazaar hashes (normalized to
  `sha256[,family]`) + URLhaus, and the FoxIO JA4DB (→ per-kind
  `fingerprint,label` files), and the suggested config wires them all.

- **QUIC 1-RTT packet-protection layer** (`internal/listener/handler/quic_1rtt.go`)
  — a verified, self-contained building block toward live HTTP/3 request
  capture: RFC 9001 §5.1 key derivation (`quic key`/`iv`/`hp` for AES-128/256-GCM)
  and short-header (1-RTT) header-protection removal + AEAD decrypt/encrypt
  (§5.3–5.4) with packet-number decoding (RFC 9000 A.3). The key schedule is
  tested against the **RFC 9001 Appendix A.1 vector** and the protection logic
  via encrypt/decrypt round-trips. It is **not wired into a live flow**:
  decrypting 1-RTT needs a completed QUIC handshake, which needs a new
  connection-oriented QUIC listener (the UDP framework dispatches single
  datagrams with no per-connection state) plus QPACK — documented as the known
  ceiling in `docs/design.md` §15.
- **HTTP/2 (h2c) capture with real HPACK + multiplexed-stream reconstruction**
  — the `http` handler now detects the HTTP/2 cleartext (prior-knowledge)
  preface and switches to a real HTTP/2 path: it answers SETTINGS, decodes
  **HPACK** against a connection-scoped dynamic table (via
  `golang.org/x/net/http2/hpack`), and reassembles each stream's HEADERS +
  CONTINUATION + DATA frames into a full request — capturing the real
  `:method` / `:path` / `:authority` / headers across **multiplexed streams**
  (`http2_requests`), not just a scanned literal. The first request is promoted
  to the usual flat meta (`request_line` / `http_method` / `http_uri` / `host`)
  and drives tool fingerprinting. Detects HTTP/2-specific abuse:
  **Rapid Reset** (`http2-rapid-reset`, CVE-2023-44487) and **CONTINUATION
  flood** (`http2-continuation-flood`, CVE-2024-27316). Strips HEADERS
  padding/priority, answers PING/SETTINGS, replies a minimal 200 per stream,
  then GOAWAY. Capture only.
- **SMB2 + NTLMSSP NetNTLMv2 capture** — the `smb` handler no longer rejects
  SMB2; it now negotiates SMB 2.0.2 for real and drives the **NTLMSSP
  SESSION_SETUP** exchange to completion (NEGOTIATE response with a SPNEGO blob
  offering NTLM → NTLMSSP CHALLENGE with a fresh server challenge + AV_PAIR
  target info → AUTHENTICATE), capturing the client's **NetNTLMv2** as the
  offline-crackable hashcat-mode-5600 string (`ntlmv2_hash`,
  `user::domain:challenge:ntproofstr:blob`) plus `ntlm_user` / `ntlm_domain` /
  `ntlm_workstation`, and flagging `smb-ntlmv2-capture`. The logon always fails
  — capture only, never grants access. This is how modern clients and
  credential-capture tooling (impacket, CrackMapExec, coerced Windows auth)
  authenticate. `smb-ntlmv2-capture` is removed from
  `list-unavailable-capabilities`.
- **QUIC / HTTP-3 ClientHello deep parsing** — the `quic` handler already
  decrypts the Initial flight; it now parses the recovered TLS ClientHello for
  the request-shaping fields: the **SNI** host (`quic_sni`), the **ALPN** list
  (`quic_alpn`) with **HTTP/3 detection** (`h3` / `h3-NN` → `http3: true` +
  `quic-http3` anomaly), and the advertised **QUIC transport-parameter IDs**
  (`quic_transport_params`). `list-unavailable-capabilities` now reports
  `http3-quic-request-capture` as experimental rather than unavailable. The
  1-RTT HTTP/3 request body (the `:method`/`:path`) stays encrypted — capturing
  it requires completing a full QUIC+TLS 1.3 server handshake, which remains
  out of scope (decoy-only stack); the handler still never replies.
- **OPC-DA (DCOM/MSRPC) call marshaling** — the `dcerpc` handler now services
  the OPC-DA call sequence past the bind, not just the bind itself. A new
  little-endian **NDR codec** (alignment, uint16/32/64, conformant+varying
  UTF-16 strings, unique pointers) parses post-bind Request PDUs, decodes the
  NDR-marshaled arguments (the **OPC item IDs / group names** an attacker reads
  or writes — captured in `opc_strings`, flagged `ics-opc-da-item-access`),
  and marshals believable NDR responses: a full running `OPCSERVERSTATUS` for
  `IOPCServer::GetStatus`, a server-group handle for `AddGroup`, `S_OK` stubs
  for `AddItems`/`Read`, and DCE/RPC faults for unknown opnums. Each call is
  recorded in `dcerpc_calls` and flagged `ics-opc-da-call`. Added the
  `IOPCSyncIO` interface to the recognized set. Full DCOM activation
  (IOXIDResolver/ISystemActivator OXID resolution) remains out of scope — see
  `docs/design.md` §15.
- **Turnkey fleet collector mode** — new `tarpit-honeypot collector`
  subcommand runs the node as a pure aggregator: it force-enables the
  authenticated ingest endpoint (defaulting bind `:8443` and token env
  `TARPIT_INGEST_TOKEN` when unset), force-enables the cross-sensor fleet
  correlator, serves the downward intel feed + STIX/TAXII export, and **binds
  no honeypot listeners** (a collector impersonates nothing — `--keep-listeners`
  runs a combined sensor+collector instead). It reuses the exact `run` engine
  (storage, web UI, channels, sandbox, privilege drop) via a shared
  `runWithConfig`, differing only in the aggregator-shaped config. `--bind`
  overrides the ingest address; `--dry-run` validates without binding. Point
  child sensors' `forward.url` at the collector's ingest bind.
- **Static analysis + YARA-style scanning of captured artifacts**
  (`internal/artifactscan`, enabled with `sensor.payloads.analyze: true`).
  A new **CGO-free** engine (no libyara) runs on every harvested
  malware/payload artifact: executable **format / section / import parsing**
  via the Go standard library (`debug/elf`, `debug/pe`, `debug/macho`,
  `archive/zip`), **Shannon-entropy + packer heuristics** (UPX + high-entropy
  section/whole-file), **ASCII/UTF-16 string + IOC extraction** (URLs, IPv4,
  domains, emails, .onion, bitcoin), **suspicious-trait** flags from imports
  (VirtualAlloc / CreateRemoteThread / ptrace / …) and strings, and a
  **YARA-subset rule engine** with text / hex-wildcard / regex strings and
  `any`/`all`/`N of` + boolean conditions. Ships a built-in rule set
  (packers, droppers, encoded PowerShell, PHP webshells, ransomware notes,
  reverse shells, credential theft, XOR-decoder stubs) and loads operator
  `.yar` files from `sensor.payloads.yara_rules` (a file or directory; rules
  using unsupported constructs are skipped, not fatal). Findings are attached
  to the event (`payload_analysis`) and the `malware:capture` event, raise
  `yara:<rule>` / `payload-packed` anomalies, and elevate severity on a
  content match. New `tarpit-honeypot analyze [--rules PATH] [--json] <file>`
  subcommand runs the same engine offline on a sample.
- **Extended SSH key-exchange capture** (`interaction.ssh_kex_depth:
  extended_experimental`, requires `interaction.mode: medium_experimental`).
  Beyond the client KEXINIT/HASSH, the `ssh` handler now parses the full
  client KEXINIT (all ten algorithm name-lists + the `first_kex_packet_follows`
  guess flag), computes the **negotiated KEX** against the server's advertised
  set, and reads the client's **first key-exchange message** — the ephemeral
  public value from `SSH_MSG_KEXDH_INIT` / `SSH_MSG_KEX_ECDH_INIT` (recorded as
  a length + SHA-256), or the requested group bounds from
  `SSH_MSG_KEX_DH_GEX_REQUEST`. Weak/legacy primitives (group1-sha1, CBC,
  arcfour, DES, hmac-md5) raise `ssh-kex-weak-primitive`. New event meta:
  `ssh_kex_client`, `ssh_kex_hostkeys`, `ssh_kex_ciphers_c2s/s2c`,
  `ssh_kex_macs_c2s/s2c`, `ssh_kex_compression_c2s`, `ssh_kex_negotiated`,
  `ssh_kex_first_follows`, `ssh_kex_msg`, `ssh_kex_client_pubkey_sha256`,
  `ssh_kex_client_pubkey_bytes`, `ssh_kex_gex_min/n/max`. Capture-only — no
  shared secret is computed and the exchange is never carried through, so the
  sensor stays a low-interaction emulator. `list-unavailable-capabilities`
  now reports `ssh-kex-extended` as a real experimental capability.
- **DNS detection depth (UDP + TCP): +30 detections** for DNS
  vulnerabilities / leakage / recon / poisoning / DoS — header/opcode/section
  abuse (`dns-response-as-query`, `dns-inverse-query`, `dns-notify-opcode`,
  `dns-dynamic-update`, `dns-multi-question`, `dns-prestuffed-answers`,
  `dns-additional-stuffing`, `dns-nonstandard-class`), recon/leakage
  (`dns-chaos-class`, `dns-dnssec-recon`, `dns-nsec-walk`, `dns-svcb-probe`,
  `dns-caa-probe`, `dns-mail-policy-probe`, `dns-srv-ad-discovery`,
  `dns-ptr-reverse-sweep`, `dns-internal-tld-leak`), MITM bait
  (`dns-wpad-probe`, `dns-isatap-probe`), OOB/rebind callbacks
  (`dns-oob-interaction`, `dns-rebind-lookup`), tunnelling
  (`dns-cname-tunnel`, `dns-null-record`, `dns-long-encoded-label`,
  `dns-many-labels`) and DoS/amplification (`dns-random-subdomain`,
  `dns-repeated-label`, `dns-edns-large-udpsize`, `dns-edns-version-nonzero`,
  `dns-dnssec-amplification`), all ATT&CK/D3FEND-mapped.
- **DNS tool fingerprinting**: `IdentifyDNS` recognizes 20 DNS recon/tunnel/
  OOB-interaction tools & services from the QNAME (BIND version probes,
  interactsh/Burp Collaborator/dnslog/ceye OAST callbacks, nip.io/sslip.io
  DNS-rebinding, dnscat2/dns2tcp/tcp-over-dns tunnels) — wired into both DNS
  handlers.
- **SSH: +30 CVE detections** (498 catalogued total) — CVE-2008-0166 Debian
  weak keys, the OpenSSH roaming pair (CVE-2016-0777/0778), user-enumeration,
  scp client flaws, ssh-agent PKCS#11 RCEs (incl. CVE-2023-38408), libssh auth
  bypass (CVE-2018-10933), ProxyCommand injection, the 2025 pre-auth DoS, and
  classic pre-auth RCEs.
- **CVE-2016-0777 detection**: a vulnerable OpenSSH client (roaming default-on,
  5.4–7.1) is flagged from its banner in both SSH handlers
  (`ssh-roaming-vulnerable-client`); the interactive handler additionally offers
  the `roaming@openssh.com` trap and records the client's reaction. Full
  private-key extraction needs the roaming resume protocol (not expressible
  through crypto/ssh) — the sensor captures the vuln signal + offered client
  public keys instead.
- **SSH brute-force tools in "top tools"**: the credential-capturing interactive
  SSH handler now runs the client-banner tool fingerprint (was HTTP + banner-grab
  SSH only), so hydra/medusa/ncrack/patator-class testers reach the chart.
- **+110 attack-tool fingerprints** (900+ total): **+50 HTTP** (credential
  brute-force / stuffing / password-spray — OpenBullet, SilverBullet, SentryMBA,
  legba, CredMaster, Spray365, MSOLSpray, …; banking-trojan loaders — Emotet,
  TrickBot, Qakbot, IcedID, …; web/API vuln scanners; recon), **+40 SSH** client/
  stack banners (libraries, enterprise/MFT SSH, PAM/zero-trust bastions, network-
  device stacks, brute/recon tools), **+20 DNS** QNAME signatures.
- **`export-creds`**: `--sort time|source|user|secret|service|kind` and
  `--reverse` to sort the extracted credentials from the command line (`--dedup`
  already removes duplicates).
- **Captures page**: summary counters by **type** and by **service** at the top
  of the credentials section, and clickable type/service labels — click to
  filter the table in place (`/captures?kind=…` / `?service=…`).

- **+100 attack-tool fingerprints** (780+ total): C2/RAT/loader families
  (Nighthawk, Nuages, Remcos, DCRat, VenomRAT, XWorm, NetWire, NanoCore, Orcus,
  AgentTesla, FormBook, SmokeLoader, …), web/CMS/API/mobile vuln scanners
  (moodlescan, scant3r, 403fuzzer, headerpwn, smugglefuzz, param-miner,
  spring4shell-scan, shiro-scan, APKLeaks, MobSF, …), AD/Windows
  post-exploitation (atexec/dcomexec/rpcdump/samrdump, PowerView, BOFHound,
  ADCSPwn, the Potato family, SharpSCCM/SCCMHunter, …), cloud/k8s/IaC auditors
  (Checkov, tfsec, KICS, Trivy, Grype, kube-bench, …), and OSINT/recon (nrich,
  mosint, CrossLinked, SubDomainizer, …).
- **+20 SSH attack-tool/stack fingerprints** (from the SSH-2.0 client banner):
  the engines under Python/Ruby/Java offensive frameworks (AsyncSSH,
  Ruby Net::SSH used by Metasploit's ssh_login, SSHJ, Ganymed), embedded/IoT
  stacks (dropbear, TinySSH, wolfSSH, Apache MINA SSHD, cryptlib), SSH-specific
  offensive tools (sshamble, ssh-mitm), and clients abused in intrusions
  (Xshell — ShadowPad supply-chain compromise).

## [2.10.0] — 2026-06-04

### Added — risk in CENTOS, CVE-2026-41089 + SIPROTEC EN100 + vsftpd-glob DoS, export-creds

- **Version bumped to 2.10.0**, releasing the accumulated work below.
- **`export-creds` subcommand**: export captured credentials (login user/pass
  pairs, SSH `auth_attempts` incl. public keys, tokens, API keys, SNMP
  communities, cookies, Kerberos tickets, honeytokens) with a `--kind` filter
  and `--format json | xml | yaml | csv | txt`.
- **Captures page**: removed the 300-row cap on displayed credentials — it now
  shows every unique credential in the scan window.
- **CVE-2026-41089**: the CLDAP (UDP/389) handler flags a Netlogon request with
  an oversized (130+ byte) username — the LSASS stack-overflow shape
  (NetpLogonPutUnicodeString byte/WCHAR confusion) — as `cve:CVE-2026-41089` /
  `cldap-netlogon-overflow`.
- **Siemens SIPROTEC 4 / SIPROTEC Compact EN100**: new capture-only UDP/50000
  handler (`siprotec_en100`) recognizing the CVE-2015-5374 DoS datagram
  (`11 49 … 28 9E`); never replies (no amplification).
- **vsftpd 2.3.2 recursive-glob DoS** (Metasploit `dos/ftp/vsftpd_232`): the
  `ftp` / `ftp_files` handlers flag an over-long, glob-metacharacter-stuffed
  command argument as `ftp-glob-dos`.
- **POP3 STLS** is now flagged (`pop3-starttls`, with a `starttls_rejected` meta
  when no cert is configured); it already upgraded the channel when a cert is
  available.
- **Risk scoring enabled** in the CENTOS example config (decaying per-source
  threat score → `risk:elevated/high/critical`; active blocking left off).

### Added — SSH/SFTP/SCP, Cobalt Strike detection, banner interning, CPEs, +20 Lua, +50 sigs

- **SSH credentials on the captures page**: extractCreds now walks the SSH
  `auth_attempts` list, so SSH passwords + pubkey attempts show alongside every
  other captured credential (not just in the raw event meta).
- **Cobalt Strike detection**: the default checksum8 beacon-staging URI is
  recognized (tool=cobaltstrike, category=c2, anomaly `cobaltstrike-stager`),
  plus geacon / crossc2 / redwarden / starkiller / nimbo-c2 fingerprints.
- **More behavioral beaconing**: the beacon correlator now also catches
  sleep-with-jitter beacons (Cobalt Strike / Sliver) — tight-band intervals over
  ≥8 contacts even when the stddev jitter exceeds `max_jitter_pct`. Enabled in
  the CENTOS example.
- **+50 attack-tool fingerprints** (680+ total): C2 / AD / cloud / OSINT / recon
  / DoS, incl. the Cobalt Strike beacons above.
- **+20 Lua personas** (200 total): Mattermost, Rocket.Chat, Zeppelin, salt-api,
  DolphinScheduler, APISIX, Moodle, Odoo, Ghost, code-server, Uptime Kuma,
  Netdata, mongo-express, Teleport, Vaultwarden, ISPConfig, Plesk, Omada,
  Redash, Hasura.
- **CPE 2.3 identifiers** on every archetype (`Profile.CPE()`, explicit override
  or derived from family + name) and service role (`archeservice.CPE()`);
  surfaced in list-archetypes / list-archeservices.
- **Storage: banner interning** — repeated static banners are stored once in a
  `banners` table and referenced by `banner_id` instead of a full copy per event
  (backward-compatible read path).
- **install.sh**: relocates a host sshd off tcp/22 to 10022 (SELinux + firewall +
  socket-activation aware) so the SSH decoy can own 22, with loud operator
  notice + client-side reconnect instructions.

### Added — explicit FTPS, +50 tool sigs (630+), events-page fixes (version 2.9.0)

- **Explicit FTPS** (RFC 4217) in the `ftp` emulator: it previously refused
  `AUTH TLS`/`AUTH SSL` with 530; it now advertises AUTH TLS/SSL + PBSZ + PROT in
  FEAT, replies 234 and upgrades the control channel to TLS (and the PROT P data
  channel), capturing USER/PASS + commands over the encrypted session. Plaintext
  pipelined before the handshake is flagged as a STARTTLS-style injection probe.
  Falls back to a 502 refusal when no cert manager (data_dir) is configured.
- **+50 attack-tool fingerprints** (630+ total): web injection/LFI/XXE/SQLi
  scanners, .NET secret cracking, k8s/container escape, cloud (AWS/Azure/M365)
  audit+attack, AD/LDAP/SMB + coercion, OSINT/username/phone recon, phishing,
  and C2 (slackor, toxssin, trevorc2).
- **Events-page fixes**: the `scanner:<name>` reputation badge linked to an
  empty page (known_scanner is IP-level, not in meta.tools) — added a
  `/events?scanner=` filter matching both attribution paths. Top source
  countries now show the code first then the flag; the top-graph rows put the
  percentage in brackets next to the count (no more big gap).

### Added — web-deception trio, events-page fixes, +50 tool sigs, +61 CVEs (2025/2026) (version 2.9.0)

- **Web deception** (`listener.web_deception`, on by default) on http/https: a
  decoy `robots.txt` (bait `Disallow` paths → `robots-honeypot-access`),
  `/.well-known/security.txt` (RFC 9116 honeytoken contacts), and `sitemap.xml`
  of many fake pages served **slowly** (a bounded per-page byte-trickle tarpit)
  → `sitemap-honeypot-access`. The security.txt contact names (local-part + full
  address) become **cross-protocol honeytoken accounts**: a login with one over
  web / ftp / imap / pop3 / smtp raises `honeytoken:account-login` (T1078).
- **Events page fixes / polish**: fixed the "Rows: All still shows only 100"
  bug (the Rows control now re-queries the server via `?limit=`, lifting the cap
  to 50000); well-known service names (pop3 / http / smtp-submission) link to
  that port's events; D3FEND ids link to their MITRE D3FEND page; the
  `geo_country` field renders with its flag. (Source reputation badges were
  already shown.)
- **+50 attack-tool fingerprints** (580+ total): web injection/XSS/redirect/cache
  scanners, JWT tooling, AD/Kerberos (ldapdomaindump, pingcastle, bloodyad,
  targetedkerberoast, …), cloud/bucket enum, subdomain-takeover + DNS recon, and
  C2 (HardHatC2, AdaptixC2).
- **+31 real 2025 CVEs** (Cisco ISE/IOS-XE, PAN-OS, FortiVoice/FortiWeb, Citrix
  NetScaler incl. CitrixBleed 2, SAP NetWeaver, CrushFTP/Wing FTP, SharePoint
  ToolShell, Langflow, Commvault, Roundcube, Wazuh, Ivanti EPMM, SonicWall, …),
  several payload-detectable. **+30 CVE-2026 forward-looking placeholders** —
  advisory-only (no signatures, so they never tag live traffic); the exact IDs
  are unverified and should be confirmed against NVD.

### Verified

- **The SNMP MIB is fully walkable**: the handler implements GetNext
  (lexicographic successor) and GetBulk over an OID-sorted MIB built from the
  archetype + topology, Null-terminating at end-of-MIB so `snmpwalk` /
  `snmpbulkwalk` traverse it completely (v3 excluded by design), with a
  per-source walk rate-limit / tarpit.

### Added — search regex + time filters, clickable pivots, summary attacks/vulns; +155 tool sigs, +25 Cisco/ASA/Moxa CVEs; DB rotate/prune (version 2.9.0)

- **Search overhaul** (`/search`): the **source IP / dest IP / rule / handler /
  full-text** fields are now case-insensitive **regular expressions**, so a
  partial value (`10.0.`) matches an incomplete IP and `^192\.168\.` anchors it;
  alternation and any RE2 pattern work, and a malformed pattern is reported
  inline instead of erroring. **Absolute time filtering** — `after` / `before` /
  `on` (UTC date or date-time) alongside the relative `since`. The **full-text**
  now walks nested meta recursively, so it matches the **request line**, **HTTP
  header names + values**, and any similar capture in addition to the rule,
  banner, and decoded payload.
- **Clickable pivots across the console**: reputation badges (`scanner:<name>`,
  `blacklist`, `tor`, `bogon`, `intel` / `fleet-intel`), transport labels
  (`tcp` / `udp` / `icmp`) and handler names now link to the matching events
  (`/events?tool=…`, `?flag=…`, `?proto=…`, `?handler=…`). A new `flag=` events
  filter backs the reputation badges.
- **Summary "top attacks" + "top vulnerabilities"**: two new ranked dashboard
  lists — most-seen ATT&CK techniques (→ the technique drill-down) and
  most-probed CVEs (→ a search for that CVE's events) — kept distinct because a
  technique spans many CVEs and a CVE can be reached by several techniques.
- **Static docs reader**: the in-product `/docs` pages no longer carry a
  `<meta refresh>` (reading is never interrupted), and `lua` + `attack-tools`
  now appear in the curated docs index.
- **+155 attack-tool fingerprints** (530+ total): AD / Impacket post-exploitation
  (secretsdump, wmiexec, BloodHound, Rubeus, Certipy, mitm6, …), Java-deser
  (ysoserial, marshalsec), web / CMS / TLS / IKE exploit scanners (jexboss,
  weblogicscan, lfimap, graphql-cop, sqlninja, jSQL, yawast, sslscan, …),
  cloud / k8s recon (Pacu, ScoutSuite, Prowler, kube-hunter), pivot / tunnel
  (Stowaway, reGeorg, pivotnacci), DNS/HTTP C2 + webshells (dnscat2, godoh,
  CALDERA, Weevely, Manjusaka), OSINT / recon frameworks (autorecon, reconftw,
  maigret, sherlock, ghunt), GraphQL tooling, MITM tooling (mitmproxy,
  bettercap), and internet-search-engine clients (fofa, ZoomEye, Netlas).
- **+25 Cisco / Cisco ASA / Moxa device CVEs** (406 total) with CWE/CPE/EPSS —
  ASA WebVPN / ASDM / SNMP / SIP (EXTRABACON, the `+CSCOU+/+CSCOE+` traversals,
  ArcaneDoor), IOS / IOS-XE / Small-Business-router / HyperFlex, and Moxa NPort /
  OnCell / switch / MXview. The ASA WebVPN traversal and RV320 command injection
  are payload-detectable; the rest are advisory (cataloged + ATT&CK-tagged).
- **`rotate-db` + `prune-db` subcommands** for the event-store lifecycle:
  `rotate-db` writes a gzip-compressed, consistent `VACUUM INTO` snapshot of
  `events.db` to an archive and can `--reset --yes` to empty + VACUUM the live
  store (log rotation); `prune-db` drops the oldest events by `--keep-days` /
  `--keep-rows` / `--max-mb` and VACUUMs to reclaim disk (dry-run unless `--yes`).

### Added — DNS decoys, SMTPS, +75 CVE / +25 Lua / +25 tools; /events log fix (version 2.9.0)

- **DNS deception** (new `listener.dns_responder`): `version_bind` answers
  CHAOS-class `version.bind` / `version.server` / `hostname.bind` queries with a
  configurable (default old, exploitable-looking BIND) banner; `fake_zone`
  answers an AXFR/IXFR zone transfer with a fabricated juicy zone (NS/MX + ~55
  service hostnames + AD SRV + TXT "secrets" incl. operator `extra_txt`) instead
  of refusing — a high-signal trap, TCP-only so never a UDP amplifier. Zone-
  transfer attempts were already flagged (`dns-zone-transfer`).
- **SMTPS 465** is documented + wired in the CENTOS example; the full decrypted
  in-tunnel plaintext (commands + DATA/BDAT body) is captured for 25 / 587 / 465.
- **+75 HTTP/HTTPS CVE emulations** (381 total): Mirai-class router/IoT CGI
  endpoints (GPON, Huawei, Realtek, Netgear, D-Link, ZyXEL, TOTOLINK, Tenda,
  …), Java/enterprise (Struts S2-048, Liferay, ColdFusion BlazeDS, Solr, Flink,
  Airflow, Ivanti, SharePoint, Magento CosmicSting, …), CMS/plugins, webmail.
- **+25 Lua personas** (180 scripts): ESXi, NSX, FortiManager, Check Point GAiA,
  Sophos, Cisco ISE, Ruckus, WhatsUp Gold, GoAnywhere, CrushFTP, Serv-U, Horde,
  SquirrelMail, Magento, Drupal, TYPO3, MediaWiki, Redmine, Centreon, Rundeck,
  AWX, NetBox, phpIPAM, Dolibarr, cPanel.
- **+25 attack-tool signatures**: sn1per, afrog, fscan, kscan, yakit, goby,
  vscan, w13scan, xray, pocsuite, dismap, spiderfoot, gowitness, aquatone,
  eyewitness, dirstalk, metabigor + the ProjectDiscovery suite (asnmap/cdncheck/
  tlsx/uncover/notify/proxify/chaos-client/dnsgen).
- **New docs**: `docs/lua.md` (the Lua persona guide) and `docs/attack-tools.md`
  (the tools the sensor fingerprints); FAQ + attribution + config updated.

### Fixed

- The web UI no longer logs `WARN ui: request failed … context canceled` (or
  writes a 500) when the auto-refreshing dashboard cancels an in-flight `/events`
  request — that's normal client behaviour. Genuine timeouts still warn.

### Added — reputation badges + flags, in-tunnel SMTP capture, +20 UDP / +25 Lua / +75 CVE / +55 tools

- **Reputation on every listed IP/domain**: a `sourceBadges` helper renders
  inline badges (blacklist / threat-intel / external + fleet intel / Tor /
  known-scanner / bogon) on the events list, event detail and attacker profile.
  New `enrich.KnownScanner` attributes an IP to a scanning operator (Censys /
  Shodan / BinaryEdge / Shadowserver / Rapid7-Sonar / Stretchoid / Project
  Magellan-360 / …) from its ASN-org + rDNS — IP-level, so a scan is flagged
  even with no self-identifying User-Agent.
- **Country flags**: a `countryFlag` helper shows the emoji flag beside every
  2-letter country code (threat map, correlation graph, per-source ASN rows,
  summary top-countries bars).
- **465/TCP + in-tunnel SMTP capture**: 465 (smtps) was already supported via
  implicit-TLS; the full decrypted plaintext inside the tunnel — commands **and**
  the DATA/BDAT message body — is now captured into the payload for 25 / 587 / 465.
- **+20 UDP handlers (112 total)**: gtp_c/gtp_u (mobile core), vxlan/geneve
  (overlays), wccp, radius_acct, dhcpv6, ripng, babel, bfd, ldp, teredo,
  ike_natt, mndp, aruba_papi, artnet + sacn (DMX/E1.31 lighting), collectd,
  plex_gdm, c1222 (smart-meter/AMI). All capture-only.
- **+25 Lua personas (155 total)**: WSO2, Apache OFBiz/NiFi/Druid/Ambari,
  Argo CD, Kong, ownCloud, Seafile, Synology DSM, pfSense, OPNsense, UniFi,
  Juniper J-Web, Nagios XI, LibreNMS, PRTG, Graylog, Bitbucket, Artifactory,
  Nomad, OpenShift, MLflow, Ray (ShadowRay), Strapi, Joomla admin.
- **+75 HTTP/HTTPS CVE emulations (306 total)** and **+55 attack-tool/scanner/
  C2 fingerprints** (see toolfp). CVE scanning is now wired into the smtp_recv
  and ftp handlers too, so mail/FTP exploit attempts are detected end-to-end.

### Added — +40 web/http/smtp/ftp CVE emulations (231 total)

- **40 new exploit-attempt CVE emulations** across web servers, app servers and
  frameworks (http/https), mail (smtp) and FTP — each carries a high-signal
  request signature so a live attempt becomes a `cve:<id>` event with its CWE +
  ATT&CK technique. Highlights: Tomcat PUT-JSP / session-deser, WebLogic JNDI,
  JBoss JMX/Seam, ActiveMQ Fileserver, Struts2 REST XStream, Spring Cloud
  Function / Spring Data SpEL, Confluence Widget SSTI, Apache Druid, Jenkins
  Stapler/Script-Security, Kibana Timelion, Drupalgeddon (SQLi + RCE), Joomla
  object-injection + config-disclosure, vBulletin, Text4Shell, IIS WebDAV,
  MS15-034 HTTP.sys, SSRS deser, Grafana traversal, D-Link/Realtek IoT,
  Cacti/Webmin/Metabase/vRealize/Crowd/PHP-imap; OpenSMTPD + Exim RCE; ProFTPD
  mod_copy / mod_site_misc, vsftpd 2.3.4 backdoor, wu-ftpd SITE EXEC.
- **Wired CVE scanning into the smtp_recv and ftp handlers** (they didn't run
  the catalog before) so mail/FTP exploit attempts are detected end-to-end, not
  just on http. Added CWE-91 / CWE-134 names. Catalog: **231 CVEs**.

### Added — search overhaul, total credential capture, +25 UDP / +10 protocols / +10 Lua

- **Search actually works now + many more filters.** The full-text box only
  matched rule_id / banner / meta_json (and parsed severity case-sensitively),
  so searching for an IP, handler, tactic, anomaly, or anything in the payload
  returned nothing. Full-text now matches **every visible field plus the decoded
  payload bytes** and flattened meta, the SQL store search also covers
  src/dst IP, handler, proto, sensor and the ATT&CK columns, and severity is
  case-insensitive. New search filters: dest IP, anomaly/technique tag, network
  fingerprint (ja3/ja4/ja4h/hassh…), ASN, has-CVE and has-credential.
- **Every captured credential is now stored + shown.** `extractCreds` was
  matching ~40 hand-listed keys, leaving ~100 credential meta keys (protocol
  hashes, LDAP binds, JWTs, session tokens, and every vendor `*_auth` blob from
  the Lua personas) invisible on the captures page. It now combines curated
  pairing, generic `<prefix>_user`/`_pass` pairing, and a classifier over the
  meta keys (tokens, JWTs, hashes, tickets, communities, cookies, challenges,
  API keys, session keys, `*_auth`) that decodes Basic/Bearer values — so new
  handlers/scripts are surfaced automatically.
- **+25 UDP handlers (92 UDP total)**, all reflection-safe (capture-only):
  - *Infrastructure*: slp (CVE-2023-29552), xdmcp, db_lsp, kerberos_udp,
    lantronix_disc, pcanywhere_stat, gamespy, db2_disc, bt_dht, rdp_udp.
  - *IoT*: matter, wiz, yeelight, dahua_disc, hikvision_sadp (IP cameras).
  - *IIoT*: powerlink, slmp (Mitsubishi), cip_io, ff_hse, ads_udp (Beckhoff).
  - *OT/building*: pcom_udp (Unitronics — 2023 water-utility PLCs),
    synchrophasor (IEEE C37.118 PMU), loxone, amx_netlinx, vantage.
- **Deeper decoding for 10 more existing protocols**: coap (resource-discovery
  amplification), knx (tunnelling bus write), fins (Omron write / mode change),
  radius (EAP / access attempts), cldap (netlogon amplification + bind), isakmp
  (Aggressive Mode PSK harvest), nbns (WPAD/ISATAP poisoning), profinet
  (IODWrite / IODControl), stun (classic-STUN amplification), mssql_browser
  (broadcast amplification + requested instance).
- **+10 Lua personas (129 shipped scripts)**: paloalto-globalprotect
  (CVE-2024-3400), f5-bigip (CVE-2020-5902 / CVE-2022-1388), cisco-iosxe
  (CVE-2023-20198), apache-struts (CVE-2017-5638), spring-actuator (Spring4Shell),
  php-cgi (CVE-2024-4577), qnap-qts (CVE-2022-27593), openfire (CVE-2023-32315),
  telerik-ui (CVE-2019-18935), cisco-asa-webvpn (CVE-2020-3452).

### Added — protocol-coverage expansion: IoT/IIoT/OT UDP, full HTTP capture, clickable summary

- **25 new UDP protocol handlers** (131 TCP + **67 UDP** total), all
  reflection-safe (capture-only; several decode known amplification vectors
  without ever replying):
  - *Infrastructure*: `wsdiscovery` (3702), `memcached_udp` (11211), `natpmp`
    (5351), `ubiquiti` (10001), `wireguard` (51820), `openvpn_udp` (1194),
    `l2tp` (1701), `rip` (520), `steam` A2S (27015), `sentinel_hasp` (1947).
  - *IoT*: `mqtt_sn` (1884), `tplink_kasa` (9999 — decrypts the autokey-XOR
    JSON), `tuya` (6667), `miio` (54321), `lwm2m` (5683/5684).
  - *IIoT*: `modbus_udp` (502), `enip_udp` (44818 — CIP ListIdentity),
    `opcua_pubsub` (4840 — UADP), `dds_rtps` (7400+ — ROS 2 / OMG DDS),
    `hartip_udp` (5094).
  - *OT / building automation*: `crestron` (41794), `pjlink` (4352), `cbus`
    (20023 — Clipsal), `dnp3_udp` (20000), `saia_sbus` (5050).
- **Deeper decoding for 10 existing protocols**: ntp (mode-6/7 request codes),
  tftp (firmware-push + path traversal), ipmi (RMCP+ / Cipher-Zero auth bypass),
  ssdp (ssdp:all amplification), snmp (GETBULK amplification + default
  community), bacnet (DeviceCommunicationControl / ReinitializeDevice /
  AtomicWriteFile), mdns (service-type recon), sip (digest-user capture +
  OPTIONS sweeps), dns (ANY amplification), dhcp (DHCPINFORM / PXE boot).
- **10 new Lua service personas** (**119** shipped scripts): tomcat-manager,
  vcenter (CVE-2021-21972 / Log4Shell), fortios-vpn (CVE-2018-13379),
  citrix-netscaler (CVE-2019-19781 / CVE-2023-3519), exchange-owa
  (ProxyLogon/ProxyShell), coldfusion (CVE-2023-26360), activemq, ivanti-ics
  (CVE-2024-21887), dlink-hnap, zyxel-firewall (CVE-2022-30525), solarwinds-orion.
- **Full HTTP/HTTPS request capture**: the method, full URI + decoded query
  parameters, every request header, parsed cookies, the Authorization header +
  any bearer token, the Referer, and any JavaScript in the request (captured,
  never executed). The event detail page gained a dedicated *HTTP request*
  section; cookies + tokens surface on the captures page.
- **Clickable summary**: every line item on the summary page — ATT&CK tactic,
  handler, top source country, top source ASN, top tool/scanner — now links to
  the filtered event list (`?tactic=` / `?handler=` / `?country=` / `?asn=` /
  `?tool=`), so you can pivot from any aggregate to the attacks behind it.

### Added — web-console overhaul + mail emulation + operability (version 2.8.0)

Version bumped to **2.8.0**. A large pass focused on the operator console, mail
credential/CVE emulation, captures, and live-deploy ergonomics.

- **Mail (POP3 / IMAP, plaintext + implicit-TLS pop3s/imaps)**: credential
  harvesting (USER/PASS, APOP, SASL PLAIN/LOGIN) over plaintext and TLS;
  vulnerability + CVE emulation and protocol-misimplementation detection —
  STARTTLS/STLS plaintext command injection (CVE-2011-1430), POP3 `PASS`
  overflow (CVE-2003-0264), IMAP pre-auth literal/NUL out-of-bounds
  (CVE-2019-11500). DNS now also serves over **TCP**.
- **+5 CVEs** (181 total): ProxyNotShell SSRF (CVE-2022-41040), GitLab
  account-takeover (CVE-2023-7028), ManageEngine SAML RCE (CVE-2022-47966),
  Struts2 upload traversal (CVE-2023-50164), PAN-OS priv-esc (CVE-2024-9474).
- **+3 Lua personas**: `squid` (open HTTP proxy abuse), `stomp`
  (ActiveMQ/RabbitMQ creds), `tor-control` (Tor ControlPort password). New Go
  **`svn`** (svnserve, 3690) protocol handler.
- **Captures**: surface standalone secrets (bearer/Vault/SSRF tokens, SNMP
  communities, Kerberos pre-auth tickets, cookies, honeytokens), not just
  user/pass, in `/captures`, the profile, and the per-event detail. pcap files
  are named `<eventID>_<srcIP>_<dstPort>.pcap` and the table shows time / source
  IP / dst port.
- **Web UI**: summary gets clickable transport/severity counters, an
  events-per-hour x-axis, equal-sized "visual overview" charts with
  percentages, a **24h/7d/14d/31d/3mo/6mo** range selector, clickable port cards
  (→ `/events?port=`) and clickable trend bars (→ that window's events); the
  **GeoIP map** has a built-in world vector and bubbles link to
  `/events?country=`; the same range selector is on `/charts`; the ATT&CK page
  links techniques to the in-honeypot drill-down; external links prompt before
  leaving; the campaign kill-chain sankey no longer overlaps; click-to-zoom
  scales the chart; **refresh is now flicker-free and skips when nothing
  changed** (`/api/heartbeat`).
- **Config / docs pages**: "this deployment" moved to `/config` with sensor
  uptime + oldest-DB-entry; the infrastructure canvas is clickable; the docs
  page gained build-generated reference catalogs (JA*/HASSH, handlers, ATT&CK
  techniques, CVEs, CWEs, CPE/CVSS/EPSS).
- **Fake web app** runs over real HTTPS (optional per-listener `https.cert_file`
  / `key_file`) with professional styling, and is now **brandable**
  (`listener.webapp_brand`: custom name / accent colour / logo mark / intro
  text; colour validated against CSS injection).
- **More coverage**: +8 CVEs (**189** total — Cleo unauth RCE, Ivanti EPM SQLi,
  OFBiz/ColdFusion, Veeam, FortiSwitch, …); **+15 Lua personas** (108 total —
  Webmin, Cacti, Proxmox, OpenWRT LuCI, Pi-hole, WebLogic, JBoss, Jira,
  Confluence, SharePoint, Nextcloud, Hikvision, MikroTik, SonicWall, TeamCity,
  plus the earlier squid/stomp/tor-control); **+3 protocol handlers** —
  `svn` (svnserve, TCP 3690), `nbd` (Network Block Device, TCP 10809), and
  `statsd` (UDP 8125, capture-only / reflection-safe).
- **More OT/ICS**: new protocol handlers `tristation` (Triconex TriStation/TSAA,
  UDP 1502 — the TRITON/TRISIS safety-controller protocol), `roc_plus` (Emerson
  ROC Plus, TCP 4000), `crimson` (Red Lion Crimson, TCP 789), `ge_egd` (GE
  Ethernet Global Data, UDP 18246 — capture-only), `bsap` (Bristol/Emerson
  BSAP-IP, UDP 1234 — bounded/rate-limited ack) and `lontalk` (Echelon
  LonWorks-IP CEA-852, UDP 1628 — capture-only); new OT archetypes (Emerson
  ROC800 RTU, Red Lion Graphite HMI, Emerson Bristol ControlWave RTU, Echelon
  LonWorks i.LON Gateway); and new archeservice role bundles (`rockwellplc`,
  `emersonrtu`, `redlionhmi`, `bristolrtu`, `gecontroller`, `lonworksgateway`) —
  and `safetyplc` now uses the real `tristation` handler on 1502 instead of
  `raw`. Every new UDP handler is reflection-safe (capture-only or a reply
  bounded ≤ the request and globally rate-limited).
- **Hardening / fixes**: SELinux confinement fixes — the binary was mislabeled
  `bin_t`, and `NoNewPrivileges=yes` was silently blocking the
  init_t→tarpit_honeypot_t domain transition, so the daemon ran unconfined;
  fixed with `init_nnp_daemon_domain` in the policy + an explicit
  `SELinuxContext=` on the unit. The policy now m4-`ifdef`-guards that
  interface so it still builds on older selinux-policy, `install.sh`
  auto-drops `NoNewPrivileges` from the generated unit when the interface is
  absent (so the transition still fires), and a new read-only
  `scripts/selinux-verify.sh` walks the whole chain — enforcing mode → module
  loaded → binary label → the *running* process domain → recent AVC denials —
  and prints the exact fix for the first failure. Plus setuid/setgid identity
  pinning with an ownership guard, a `.deployment-id` "permission denied"
  startup fix with actionable errors, and more actionable store/DB-open errors.

### Added — detection-depth pass III: cloud/AI CVEs, Lua ATT&CK mapping, more correlators/scripts (version 2.7.0)

Version bumped to **2.7.0**. A third pass, this time also lifting ATT&CK/D3FEND
coverage across the whole Lua-script layer.

- **+12 CVEs** (171 total): cloud/AI infra (Ivanti CSA, Aviatrix, Ray
  "ShadowRay") + CMS/web (ChatGPT SSRF, Next.js middleware bypass, Craft CMS,
  WordPress File-Upload / Really-Simple-Security) + advisory FortiOS bypass,
  HTTP/2 Rapid Reset, Blast-RADIUS. New CWE-328.
- **Lua → ATT&CK/D3FEND mapping**: a `lua:` AnomalyTag family classifies the
  80+ dynamic service scripts' flags (rce/login/token/traversal/ssrf/enum/…)
  so every script now contributes ATT&CK coverage, storyline input, and D3FEND
  stamping. Added T1592.
- **+2 correlators**: `dns_tunnel` (DNS C2/exfil) and `recon_to_exploit`
  (scan-then-exploit, two-stage).
- **storyline**: `dns-tunneling` playbook.
- **profiles**: surface the storyline playbooks attributed to a source.
- **+1 IOC type**: `tool` (identified scanner/attack tool, for attribution).
- **+6 Lua scripts** (90 total): WordPress, Roundcube, Splunk, pgAdmin,
  ManageEngine, Zimbra.

### Added — detection-depth pass II: more CVEs/IOCs/anomalies/correlators/playbooks/scripts (version 2.6.0)

Version bumped to **2.6.0**. A second breadth/depth pass across the same
subsystems, leaning into the IoT-botnet + web-app attack surface and the
signals added in 2.5.0.

- **+17 CVEs** (159 total): IoT/DVR/camera/NAS command-injection (D-Link,
  TBK, AVTECH, Zyxel — Mirai-class) plus recent enterprise pre-auth RCE
  (HugeGraph, CrushFTP, LiteSpeed, Telerik, Grafana DuckDB, Confluence,
  FortiClient EMS, Splunk, Solr, Tomcat partial-PUT) and advisory Erlang/OTP
  SSH + Zimbra. New CWE-44.
- **+3 IOC types**: `ssh-key` (offered SSH public-key fingerprints, now
  surfaced at the top level + emitted), `ssh-client` (SSH client version), and
  `email` (SMTP envelope sender).
- **Web-attack-class detection** on every `http`/`https` listener: `webapp:ssti`
  / `xxe` / `rfi_ssrf` / `deserialize` / `nosqli` / `graphql-introspection` /
  `jwt-none` — scanned over the whole request, near-zero-FP, ATT&CK/D3FEND
  mapped.
- **+3 correlators**: `web_attack_probe` (distinct web-attack classes),
  `ssh_key_spray` (distinct offered SSH keys), `spam_relay` (open-relay /
  recipient-enumeration probing).
- **+3 storyline playbooks**: `web-vuln-fuzzing`, `data-exfiltration`,
  `dos-amplification`; web-attack-class tracking broadens
  `web-exploit-to-shell`.
- **Richer profiles**: SSH public keys offered, SMTP senders, and web-attack
  classes, with a new "web application attack" assessment band.
- **+6 Lua scripts** (84 total): Metabase, Superset, Node-RED, ThinkPHP,
  GeoServer, Rancher — each flagging its service-specific RCE/abuse primitive.

### Added — detection-depth pass: CVEs, IOCs, profiles, D3FEND, storyline, correlators, Lua (version 2.5.0)

Version bumped to **2.5.0**. A breadth-and-depth pass across the detection /
attribution subsystems, prioritizing coverage for the handlers added in 2.4.0.

- **+21 CVEs** (142 total): recent CISA-KEV / mass-exploited entries for
  handlers we model — Confluence SSTI, Check Point / PAN-OS / Ivanti EPMM /
  SolarWinds Serv-U / GeoServer / WhatsUp Gold / OFBiz / SAP NetWeaver, the
  WordPress RCE/SQLi wave, Zyxel + TP-Link command injection, and advisory-only
  Terrapin / FortiOS / Ivanti handshake exploits. New CWE names.
- **Wider IOC extraction**: `ja4h`, `ja4t`, `user-agent`, and requested TLS
  `sni` (as a domain) are now turned into typed indicators (ja4h emitted; the
  rest store-tracked).
- **Richer attacker profiles**: captured malware artifacts, harvested
  C2/dropper URLs, requested domains/SNIs, JA4T, and a confirmed-compromise
  banner + assessment when a source replays a planted honeytoken.
- **D3FEND expansion**: 32 previously-unmapped ATT&CK techniques now carry
  countermeasures; a D3FEND id→name catalog + `list-techniques --defenses`
  legend; eight new countermeasure ids.
- **Protocol anomalies**: `tls_intercept` now runs the decrypted client→backend
  stream through CVE / suspicious-URI / credential detection
  (`tls-decrypted-exploit` / `-credentials`); `dtls` raises `dtls-probe` /
  `dtls-malformed`.
- **Storyline**: new milestones (honeytoken reuse, web shells, tunnelled
  exploits) and named **playbooks** (ransomware, ot-kill-chain,
  cloud-credential-takeover, web-exploit-to-shell, edge-appliance-exploitation,
  …) stamped on the storyline event and surfaced on `/attack`.
- **+3 correlators**: `tls_mitm_capture`, `fp_rotation` (distinct-fingerprint
  rotation), `container_takeover`.
- **+6 Lua scripts** (78 total): phpMyAdmin, Adminer, Gitea, Ollama, Zabbix
  agent, Apache RocketMQ — each flagging its service-specific abuse primitive.

### Added — active capture, threat-intel ingestion, TLS MITM, campaign/journey + threat-map UI, decoy generation (version 2.4.0)

Version bumped to **2.4.0**. A feature set closing the gap to full
honeynet/deception platforms: active artifact capture, inbound threat-intel,
TLS interception, attacker-journey + threat-map dashboards, honey-token reuse
detection, and a network-aware decoy generator. All outbound paths route
through the egress allowlist and fail closed.

- **MITRE ATT&CK Navigator export.** `export-navigator` CLI (static coverage or
  `--observed` event-scored heatmap) + a `/attack/navigator` web endpoint —
  drop the JSON into the upstream Navigator for a coverage/observed heatmap.
- **Active malware/artifact fetch** (opt-in `payloads.fetch_urls`). The passive
  capture store already kept what attackers uploaded; the sensor can now pull
  attacker-referenced droppers (size-capped, http(s)-only, redirect-capped) and
  classify them — fetched through the egress allowlist, fail-closed.
- **Inbound threat-intel feeds** (`threat_feeds:`). Periodically pulls operator
  IP feeds (line or JSON / AbuseIPDB shapes) through the egress allowlist and
  tags matching sources `external_intel` / `threat_intel_hit`; keeps the last
  good snapshot if a refresh fails.
- **TLS interception** (`handler: tls_intercept`). Terminates TLS with a
  believable cert (JA3/JA4 + JA3S like `https`), then either hands the
  cleartext to an inner handler (a TLS front for any emulated service) or
  decrypt-and-forwards to a real backend through the egress allowlist (optional
  re-encrypt), capturing the plaintext session (64 KB cap). Opt-in and
  egress-scoped; never an open proxy. ATT&CK T1557 + T1040.
- **Honey-token reuse detection.** Tokens the sensor serves (honeytokens,
  bearer/vault tokens) are tracked; when one is replayed back as a credential
  the loop closes with a critical `canary:token_used` event (T1078).
- **Campaigns & attacker journey** (`/campaign`). A kill-chain journey sankey
  (tactic→tactic transitions across all sources) plus campaign clustering that
  links distinct source IPs into one operation via shared network fingerprints
  (JA3/JA4/JA4H/JA3S/HASSH), with a campaign↔fingerprint↔handler linkage graph.
- **Threat map / geo dashboard** (`/map`). A live GeoIP attack map over
  country / ASN / network-class breakdowns and threat-intel counters (known-bad
  sources, Tor exits, feed matches) plus a recent high-severity attack ticker —
  auto-refreshing, usable as a wall display.
- **Dynamic decoy generation** (`generate-decoys`). Benignly connect-scans the
  operator's own network (host / host:port / CIDR), classifies each open port
  (port + banner + TLS cert CN), and emits a matching listener config so the
  honeypot blends into its environment. TCP connect scan only (no exploit
  traffic, no stealth scanning); bounded by an explicit target list, a host
  cap, and a required `--yes` authorization flag. Generated configs pass
  `validate-config`.

### Fixed — IPv6 parity across handlers + capture (version 2.3.1)

Version bumped to **2.3.1**. A systematic audit confirmed an IPv6 attacker now
gets the same deceptions, fingerprinting, detection, correlation, and ATT&CK
attribution as IPv4. Genuine gaps fixed; protocol-correct IPv4-only behavior
left as-is with clarifying comments.

- **LLMNR** now answers AAAA (type 28) poisoning queries with our IPv6 address,
  not just A — an IPv6 `wpad` probe gets a poison reply instead of silence. The
  buggy `LastIndex(":")` local-address parse (which mangled `[::1]:port`) is
  replaced by a typed `localIPOf` helper shared with NBNS.
- **STUN** returns an IPv6 XOR-MAPPED-ADDRESS (family 0x02, address XORed with
  cookie+transaction-id per RFC 5389) instead of silently dropping IPv6 clients
  — relevant for WebRTC/VoIP over v6.
- **pcap capture** writes IPv6 sessions with a real IPv6 packet header carrying
  the actual addresses (+ v6 pseudo-header checksum) instead of flattening them
  to `0.0.0.0`.
- **FTP** PASV can't encode IPv6 (RFC 2428), so an IPv6 control connection now
  gets `522 use EPSV` (real-server behavior) instead of a broken `127.0.0.1` in
  the 227 reply; EPSV (229) already works for both families.
- Confirmed correct-as-is (IPv4-only by specification, with clarifying
  comments): `nbns` (NetBIOS-over-TCP/IP), `knx` (KNXnet/IP HPAI route-back
  `0.0.0.0`), PROFINET-DCP, the SNMP `ipNetToMediaTable` (IPv4 ARP table), and
  the ARP responder.
- Confirmed already address-family-agnostic: listener binding, source
  extraction, the `dns` handler (A + AAAA + `fakeIPv6`), correlation, enrichment
  (GeoIP/ASN/RDNS), the filter allowlist, the risk scorer, the blocklist
  (`blocked4`/`blocked6` sets), MITRE attribution, and CEF/LEEF/OCSF/STIX/JSON
  output. Adds tests for `localIPOf`, LLMNR AAAA + wrong-family guard, STUN
  IPv6, pcap IPv6 address preservation, and the FTP v4/v6 PASV branch; documents
  the parity status in `docs/config.md`.

### Added — fingerprint suite, active response, encrypted transports (version 2.3.0)

Version bumped to **2.3.0**. This release rounds out the JA4+ fingerprint
family, adds an active-response firewall backstop and a decoy-document canary,
and brings encrypted-transport fingerprinting (DTLS, QUIC/HTTP-3) plus
flow-export collectors.

**Fingerprints — JA4SSH / JA4L / JA4X + live JARM**
- `fingerprint.JA4SSH` (SSH record-length cadence), `JA4L` (latency/locality —
  RTT + TTL), and `JA4X` (X.509 cert structure) join the JA4+ family. JA4L is
  emitted live as `ja4l` on `honeynet:tcp_connect` events; JA4X as `ja4x` by the
  https handler over the cert it presents; JA4SSH is a tested library primitive
  (the SSH handlers don't expose raw record lengths to wire it live).
- New `jarm` CLI command actively probes a TLS server (ten varied ClientHellos)
  and prints its JARM fingerprint — point it at the sensor's own https listener
  to confirm its TLS posture matches the impersonated product.

**Active inbound response (opt-in)**
- New `risk.block` (`internal/blocklist`): when a source crosses a configured
  risk level, the sensor adds it to an nftables drop set for a bounded TTL, then
  lets the kernel expire it — the honeypot analogue of fail2ban, driven by the
  risk score. OFF by default (blocking ends the engagement); TTL-bounded so a
  crash can't leave a host firewalled forever; loopback / link-local /
  `never_block` CIDRs always exempt; Linux + nft + CAP_NET_ADMIN.

**Decoy-document canary**
- `gen-token --type=doc` writes a real `.docx` whose external `attachedTemplate`
  relationship beacons the callback URL when the file is opened in Word — drop
  it on a share named like sensitive data and "someone opened the honeydoc"
  becomes an alert (captured by the `ssrf_canary` listener) with the opener's IP.

**Encrypted-transport handlers**
- New `dtls` UDP handler: parses the cleartext DTLS ClientHello, computes
  JA3/JA4 over it + `dtls_version`, replies with a HelloVerifyRequest, and only
  answers a genuine ClientHello (no reflection surface).
- New `quic` UDP handler: decrypts the QUIC Initial packet (key schedule
  verified byte-for-byte against the RFC 9001 Appendix A test vectors),
  reassembles the TLS ClientHello from its CRYPTO frames, and computes JA3/JA4 +
  `quic_version`. Capture-only — gives QUIC/HTTP-3 scans the same fingerprinting
  the TLS handlers give HTTPS, without a QUIC transport.

**Routing / flow-export collectors**
- New `netflow` (NetFlow v5/v9 + IPFIX) and `sflow` (sFlow v5) UDP collector
  decoys capture the exporting network's flow records / agent identity — routing
  reconnaissance complementing the existing `bgp` handler. The `routerserver`
  archeservice role now exposes them alongside BGP/SNMP/SSH.

### Added — cloud-native attack surface + protocol breadth (version 2.2.0)

Version bumped to **2.2.0**. This release widens the honeypot toward the
cloud-native / container attack surface, modern application transports, the
full JA4+ TLS/TCP fingerprint suite, an out-of-band SSRF canary, deeper
post-login TTP detection, and IPv6 reconnaissance parity.

**Cloud-native + container handlers**
- New `cloud_metadata` handler emulates the instance metadata service (IMDS)
  for AWS, GCP and Azure from one listener (they share 169.254.169.254 with
  different paths/headers). Serves synthetic instance identity and honeytoken
  IAM / OAuth credentials and flags `cloud-credential-theft` on the IAM
  `security-credentials`, GCP service-account `token`, and Azure `oauth2/token`
  paths — the post-SSRF credential-theft TTP (T1552.005).
- New `etcd` handler emulates the etcd KV store API (v2 `/v2/keys`, v3
  `/v3/kv/range|put|deleterange`, `/version`, `/health`, `/metrics`, member
  list) with believable Kubernetes cluster state including a base64
  `/registry/secrets/...` key; flags `etcd-secret-read` / `etcd-range-read` /
  `etcd-write` (T1552.007 / T1213 / T1565.001).
- New `kubernetes_api` handler emulates kube-apiserver (6443/8080/10250):
  answers `/version`, `/api`, `/apis`, `/healthz` discovery; captures the
  `Authorization: Bearer` service-account token (`bearer_token`); flags
  `k8s-secret-enum` / `k8s-pod-create` / `k8s-pod-exec`; 403s anonymous
  protected requests as `system:anonymous`.
- New `vault` handler emulates the HashiCorp Vault API (8200): answers
  `/v1/sys/health` + `seal-status` like an unsealed Vault; captures
  `X-Vault-Token` (`vault_token`); flags `vault-secret-read` /
  `vault-mount-enum` / `vault-policy-access` / `vault-seal-control`; tokenless
  secret reads get 403 (T1555 / T1528).

**Modern application transports**
- New `websocket` handler completes the RFC 6455 opening handshake (computing
  `Sec-WebSocket-Accept`), then unmasks and captures client frames, flagging
  `ws-credential-material` and `ws-command-payload` on hostile first messages;
  non-upgrade probes get a `426`.
- New `grpc` handler recognizes the HTTP/2 connection preface, replies with a
  believable SETTINGS + ACK, reads the following frames and extracts the
  `/package.Service/Method` path from HEADERS (no HPACK decode required),
  flagging `grpc-reflection-probe`.

**TLS/TCP fingerprint suite (JA4+)**
- `fingerprint.JA4S` — server-side TLS fingerprint from the ServerHello
  (modern JA3S successor), emitted alongside `ja3s` as `ja4s` by the https
  handler.
- `fingerprint.JA4T` — TCP-layer fingerprint (window, option-kind layout, MSS,
  window-scale) computed from the client SYN in the userspace honeynet stack
  and attached to `honeynet:tcp_connect` events as `ja4t`.
- `fingerprint.JARM` — server fingerprint library primitive for confirming a
  sensor's TLS posture matches the product it impersonates.

**SNI virtual hosting**
- `https.vhosts` lets one HTTPS listener front several personas. The TLS
  `GetCertificate` callback matches the client SNI (exact or `*.domain`
  wildcard) and presents that vhost's own deployment-derived certificate (own
  CN / Org / key type), recording the matched name in the `tls_vhost` event
  field.

**SSRF out-of-band callback canary**
- New `ssrf_canary` handler — the inverse of the URL/DNS canaries. Plant a
  token URL (`gen-token --type=ssrf`) in an SSRF parameter, webhook field, or
  XXE entity; when a coerced system fetches it the callback is recorded with
  the token + `User-Agent` / `X-Forwarded-For` / `Via`. Flags `ssrf-callback`
  always, and `ssrf-server-side-fetch` when the UA is an HTTP client library
  rather than a browser. Returns a 1×1 GIF so the exploit chain proceeds.
- `gen-token --type=ssrf` emits a ready-to-plant callback URL.

**Tarpit strategies (9 new)**
- The per-listener tarpit grew from 3 to 12 strategies: `jitter`, `backoff`,
  `ssh_banner` (endlessh-style), `http_headers`, `http_chunked`, `echo`,
  `babble`, plus the aggressive opt-in `zipbomb` (gzip decompression bomb) and
  `zero_window` (LaBrea TCP receive-window clamp). Each has its own config
  sub-struct, defaults, and validation; the two aggressive modes are clearly
  documented as retaliatory and are never selected by default.

**Post-login shell — 7 more ATT&CK-mapped TTPs**
- The emulated shell's command classifier gains `shell-container-escape`
  (T1611), `shell-cloud-cred-theft` (T1552.005), `shell-local-exploit` (T1068),
  `shell-data-staged` (T1560.001), `shell-exfil-channel` (T1048),
  `shell-decode-pipe-exec` (T1140), and `shell-destruction` (T1485/T1486).

**Correlation rules**
- New `correlate:cloud_cred_theft` (counts cloud credential-theft markers from
  one source) and `correlate:ssrf_callback` (counts distinct SSRF tokens called
  back by one source), both windowed, severity-configurable, and ATT&CK-tagged.

**IPv6 honeynet parity**
- The honeynet TUN responder now gives IPv6 TCP reconnaissance the same
  SYN-layer visibility as IPv4: an IPv6 SYN to an open port of an IPv6 virtual
  host is answered with a SYN-ACK and surfaced as a `honeynet:tcp_connect`
  event (closed ports get a RST). The stateful data phase remains IPv4-only by
  design. `tcpstack.Event` gained `SrcIP6`/`DstIP6`/`IsV6` so v6 addresses are
  carried honestly.

**Listeners / service bundles**
- New `kubernetes` archeservice role (apiserver + kubelet + etcd client/peer).
  The `containerhost` role's 6443/10250 ports now use the dedicated
  `kubernetes_api` handler and it gains etcd on 2379; `secretstore` now uses the
  dedicated `vault` handler. A new catalog-wide test expands and validates every
  role against the handler whitelist.

**MITRE / docs**
- All new handlers, anomaly markers, and correlation rules are mapped in the
  MITRE technique + tactic tables (new technique descriptions for T1555, T1528,
  T1609, T1611, T1068, T1560.001). README, `docs/config.md`, and the handler
  reference tables document every addition.

### Added — in-product documentation + new guides (version 2.1.0)
- The web UI **docs** tab now renders the full documentation in-product: the
  Markdown guides are embedded in the binary (`docs` package), `/docs` lists a
  documentation library, and `/docs/<name>` serves each guide via a compact,
  dependency-free Markdown→HTML renderer (headings with slug ids, fenced code,
  lists, blockquotes, GFM tables, inline code/bold/italic/links) under the
  strict CSP; internal `.md` links are rewritten to `/docs/<name>` and unknown
  names 404.
- New guides: `docs/fleet.md` (roles, topologies, the 27 `fleet:*` detectors,
  broad-vs-targeted, downward intel, tuning, troubleshooting), `docs/ioc.md`
  (the IOC store, `ioc:<type>` events, exports), `docs/threat-intel-exports.md`
  (STIX 2.1 / TAXII 2.1 / MISP, the downward feed, CEF/LEEF/OCSF sinks),
  `docs/FAQ.md`, and `docs/webui.md` (the web-UI walkthrough).
- Refreshed the man page, `docs/cli.md`, `docs/README.md`, `docs/usage.md`
  (new Fleet and IOC sections), `docs/internals.md` (the fleet/ingest/intel data
  flow, persisted ATT&CK/D3FEND columns, the package map), and the root README
  for the fleet / IOC / threat-intel features. Version bumped to **2.1.0**.

### Added — IOC retention (tied to retention_days)
- The hourly retention runner now also prunes stale indicators from the `iocs`
  table — those not seen for `sensor.disk.retention_days` (last-seen basis, the
  same age cap as the event store), reported as `ioc_rows` in the prune log. An
  indicator kept fresh by continued sightings survives. Unit-tested.

### Added — worked fleet topology example configs
- `examples/fleet/` — a tiered, validated reference deployment: `leaf-sensor.yaml`
  (edge decoy that forwards full + subscribes to the intel feed under
  `egress.enforce`), `site-aggregator.yaml` (ingest + trust + fleet + IOC +
  serve-intel, rolling up to the hub), and `global-hub.yaml` (wide fleet windows
  + IOC + MISP push + STIX/TAXII + CEF→SIEM), with a `README.md` topology
  diagram. Listed in `examples/EXAMPLES.md`; all three pass `validate-config`.

### Changed — web UI brought up to date with the fleet / IOC / mitre features
- **Event detail** (`/events/<id>`) now shows an ATT&CK / D3FEND section
  (technique chips link to the technique view, with hover descriptions; tactics +
  D3FEND defenses listed) — from the persisted columns, recomputed for
  pre-migration events.
- **Config canvas** (`/config`, `/api/config/canvas`) gained a "Fleet /
  aggregation" group surfacing the new subsystems with live state: fleet
  correlation (+ detector count), fleet forwarding (full/rollup target mix),
  ingest endpoint, trust scoring, intel feed serving + subscribing, MISP push,
  and the IOC store.
- The template function map is now a single shared `tmplFuncs` (used by the
  server and all view tests) so they can't drift; added a `techDesc` helper
  (mitre.Describe).

### Added — indicator-of-compromise (IOC) store, events, and web-UI tab
- New `internal/ioc` distils the indicators every event already carries — source
  IPs, ja3/ja4/hassh fingerprints, ASNs, DNS names, CVE ids, captured-payload
  SHA-256s, harvested C2 URLs, credentials, MACs — into a de-duplicated IOC
  store (new `iocs` sqlite table: type+value → first/last seen, count, max
  severity, last rule/source), with `Store.UpsertIOC` / `QueryIOCs` /
  `IOCSummary`.
- The first sighting of a **high-value** indicator (sha256 / url / domain /
  ja3 / ja4 / hassh / cve / credential by default) emits an `ioc:<type>` event —
  stored locally **and forwarded** to aggregators like any event; a forwarded
  `ioc:*` re-yields its indicator so a parent harvests child IOCs even in rollup
  mode. Configurable under `ioc:` (`emit_types`); on by default with a store.
- New web-UI **iocs** tab (`/iocs` + `/api/iocs`): per-type breakdown bar chart
  (each bar filters by type) and the indicator list (value, count, first/last
  seen, severity, last rule) — each row links to the events that exhibited it.
  Linked from the nav + `/docs`.
- Verified end-to-end: an ingest batch populated the IOC store and emitted
  `ioc:credential/cve/ja3/sha256/url` (bare IPs tracked, not emitted); the tab
  and `/api/iocs` render them. Unit-tested (extractor incl. forwarded-ioc
  propagation; store upsert/query/summary).

### Added — persist ATT&CK / D3FEND in the event store
- The event store now persists `mitre_techniques` / `mitre_tactics` /
  `mitre_defenses` (schema + additive migration), so `/api/events`, the event
  log, and the IOC/event views carry the same ATT&CK + D3FEND attribution the
  streaming sinks already get. Verified: a stored `cve:*` event now reports
  `T1190` + its D3FEND set via `/api/events`.

### Added — ATT&CK / D3FEND / CVE cross-reference coverage for the new features
- **Fleet detectors mapped to ATT&CK + D3FEND** — all 27 `fleet:*` detectors
  (and `egress:denied`) now resolve to ATT&CK technique(s)/tactic(s) and the
  D3FEND countermeasures, so they flow to the SIEM sinks (CEF/LEEF/OCSF/webhook/
  syslog/MQTT), the UI `/attack` view, and `list-techniques`. Breadth/recon
  patterns → T1595, shared-fingerprint/botnet → T1583.005, payload → T1105,
  credential → T1110.x, CVE waves → T1190, C2 → T1071, egress-denied → T1090/
  T1071, etc. The volume-only `fleet:rollup` / `fleet:sensor-untrusted` stay
  unmapped (no attacker technique).
- **Filled mapping gaps** — added the missing `T1583` (Acquire Infrastructure)
  description and the `T1583` + `T1090` (Proxy) D3FEND entries that earlier rules
  already referenced.
- **CVE catalog → 100% CPE** — added representative `linux_kernel` CPEs for the 4
  OS-network-stack DoS CVEs (Teardrop / LAND / TCP-RST / sockstress) that had
  none; the catalog is now 100% CWE / CPE / EPSS covered.
- **`fleet:cve-wave` / `fleet:cve-emergence` carry CVE risk meta** — the
  triggering CVE's CVSS / EPSS / CWE / CPE are propagated onto the fleet finding,
  so a wave/emergence is triageable without pivoting to the underlying event.

### Added — CLI surface for the fleet / IOC features
- **`list-fleet-rules`** — prints the cross-sensor (`fleet:*`) detector catalog
  (rule, what it detects, the `fleet.*` config keys that tune it); `--json`. A
  new `fleet.Catalog()` is the single source of truth (guard-tested for no dupes
  / `fleet:` prefix).
- **`export-iocs`** — derives the fleet's IOCs from the stored `fleet:*` findings
  and prints them as STIX 2.1 / CSV / txt (blocklist) / JSON, for piping into a
  TIP / SIEM. The offline counterpart to the live `/intel` + `/intel/stix`
  endpoints; reads the local event store (`--since`, `--format`).
- **`list-events --fleet`** — tail only the `fleet:*` findings from the CLI.
  All documented in `docs/cli.md`; unit-tested.

### Added — web UI: dedicated fleet panel
- New `/fleet` page (and `/api/fleet` JSON) surfacing the cross-sensor
  `fleet:*` findings: a **per-detector breakdown bar chart** where each bar
  links to that detector's filtered event log (`/events?rule=fleet:<name>`), a
  **findings-over-time bar chart** (bucketed across the window), and a findings
  list with a compact, per-detector summary (primary identity + breadth counts +
  broad/targeted scope) linking to each full event. Server-rendered CSS bars (no
  JS, CSP-safe). `since` filter; linked from the nav and `/docs`. Verified live
  (charts + per-detector links render and resolve; non-fleet events excluded).
  Unit-tested (handler render, the detector-link href, and summary/number
  formatting).

### Added — two more fleet correlators (credential-spray / asn-org)
- **`fleet:credential-spray-fleet`** — one username tried with >=
  `cred_spray_passwords` (5) distinct passwords across >= `cred_spray_sensors`
  (2) sensors: a distributed brute-force of a single account.
- **`fleet:asn-org-campaign`** — one AS-org spanning >= `asn_org_asns` (2)
  distinct ASNs across >= `asn_org_sensors` (5) sensors: a provider-wide campaign
  that ASN-number keying misses (requires >= 2 ASNs so it never duplicates
  asn-multi-sensor). Unit-tested.

### Added — three more fleet correlators (tactic / persistence / port axes)
- **`fleet:tactic-convergence`** — one MITRE ATT&CK technique exercised by >=
  `tactic_sources` (8) distinct sources across >= `tactic_sensors` (3) sensors:
  a coordinated push on a TTP, abstracted above the specific CVE/tool.
- **`fleet:recidivist-network`** — an ASN active in >= `recidivist_windows` (3)
  distinct `recidivist_bucket`s (default 24h = "days") over the long horizon: a
  network that keeps coming back, a persistence signal (not breadth). Keyed on
  ASN so memory stays bounded.
- **`fleet:port-campaign`** — one destination port probed by >=
  `port_campaign_sources` (5) sources across >= `port_campaign_sensors` (3)
  sensors, a service-targeted campaign (e.g. a new botnet on tcp/23). The
  ubiquitous always-scanned ports are excluded (`port_campaign_exclude`, default
  22/80/443) so the signal isn't drowned by routine scanning. Unit-tested per
  detector (incl. the ubiquitous-port exclusion).

### Added — four more fleet correlators (new signal axes)
- **`fleet:threat-intel-surge`** — >= `threat_surge_sources` (10) distinct
  enrichment-flagged sources (threat-intel list member / Tor exit) across >=
  `threat_surge_sensors` (3) sensors: known-bad infrastructure converging on the
  fleet (the fleet-wide complement to the in-sensor threat_intel_burst).
- **`fleet:tool-campaign`** — one identified attack tool (meta `tools`) on >=
  `tool_sensors` (3) sensors from >= `tool_sources` (3) sources: a tool /
  exploit-kit sweeping the fleet, linked by tool name across differing IPs/stacks.
- **`fleet:c2-shared`** — one harvested C2/dropper URL (meta `harvested_urls`)
  on >= `c2_sensors` (2) sensors: shared command-and-control infrastructure
  (critical; never background noise).
- **`fleet:user-agent-shared`** — one HTTP User-Agent on >= `ua_sensors` (3)
  sensors from >= `ua_sources` (5) sources: a shared HTTP scanner/tool family —
  the HTTP-layer analogue of fingerprint-shared (catches tools with no/varying
  TLS fingerprint). New signal axes: enrichment flags, tooling, C2 URLs, UAs.
  Unit-tested per detector.

### Added — interactive-shell host realism (post-login)
- The emulated POSIX shell (ssh_interactive / telnet) now presents a believable,
  internally-consistent host state derived deterministically from the archetype,
  instead of the same hardcoded values on every honeypot (which fingerprinted
  the decoy). New `internal/shell/hoststate.go`.
- `uptime` / `w` / `who` / `last` show a stable, per-host login user, source,
  boot time, and load average (uptime advances with the clock); `date` is
  current; the values differ across hosts but stay consistent across commands
  and reconnects.
- `ifconfig` / `ip addr` / `ip link` / `ip route` / `route` / `arp` render the
  archetype's interfaces with a per-host IP, gateway, and MAC (MAC OUI from the
  archetype), all agreeing with each other. New `ip` subcommands + `route` /
  `arp` / `last`.
- `ps` is built from the archetype's default services — base procs (systemd,
  kthreadd, journald, sshd) plus the role daemons a host of that role runs
  (nginx / mysqld / postgres / redis / postfix / vsftpd / dockerd / ...), the
  login shell, and ps itself.
- `history` is a believable root command history. Two hosts now look like two
  different machines; one host stays self-consistent. Unit-tested (realism,
  per-host distinctness + stability, service→daemon mapping).

### Added — IOC export: STIX 2.1 / TAXII 2.1 / MISP push
- The fleet's observed indicators (the intel store) are now exportable to
  standard threat-intel tooling. New `internal/stix` and `internal/misp`.
- **STIX 2.1** — `GET /intel/stix` serves a bundle of Indicator SDOs (IPs →
  `ipv4-addr`/`ipv6-addr`, ASNs → `autonomous-system`, ja3/ja4/hassh → an
  `x-tarpit-fingerprint` custom pattern). Indicator IDs are deterministic
  (UUIDv5 of the pattern) so downstreams dedup cleanly.
- **TAXII 2.1** — a minimal read-only API (`/taxii2/` discovery, api-root,
  collections, and the `fleet-iocs` collection's `objects/` envelope) so a TAXII
  client can discover and pull the collection.
- **MISP push** — a `misp:` delta pusher ships not-yet-sent indicators as a
  periodic MISP event (ip-src / AS / ja3-fingerprint-md5 / hassh-md5
  attributes), egress-allowlisted, with retry-on-failure rollback of the
  sent-set. All served on the existing bearer-gated endpoint where a node serves
  intel. Verified live (valid STIX bundle + TAXII envelopes); unit tests cover
  STIX patterns / deterministic ids / TAXII auth and the MISP delta + mapping.

### Added — four more fleet correlators
- **`fleet:honeytoken-spread`** (the one detector from the design not yet built)
  — the same canary token tripped on >= `honeytoken_sensors` (2) sensors: a
  planted token has leaked and is propagating across the fleet (critical).
- **`fleet:cve-emergence`** — a brand-new CVE, novel within `first_seen_horizon`,
  reaching >= `cve_emergence_sensors` (2) sensors: an n-day going live fleet-wide
  (distinct from `cve-wave`, which fires for any CVE crossing breadth).
- **`fleet:cross-protocol-actor`** — one source touching >= `cross_proto_handlers`
  (4) distinct services across >= `cross_proto_sensors` (2) sensors: fleet-wide
  service enumeration by a single actor (the cross-sensor analogue of the
  in-sensor service-sweep).
- **`fleet:fingerprint-asn-spread`** — one fingerprint operated from >= `fp_asns`
  (3) distinct ASNs across >= `fp_asn_sensors` (2) sensors: a toolkit run from
  many networks (complements fingerprint-shared's source axis and
  geo-distributed-actor's country axis with the network-of-origin axis).
- All configurable under `fleet:`, reusing the windowed actor model + once-per-
  window firing + loop guard; CVE-emergence reuses the long-horizon novelty
  memory. Unit-tested per detector (incl. the novel-vs-established CVE split).

### Added — fleet aggregation: sensor trust scoring + store scale-out (phase 4)
- **Sensor trust scoring + admission control** (`ingest.trust`, new
  `internal/trust`). The aggregator scores each child sensor's stream health
  with per-sensor windowed counters (accepted / deduped / dropped / malformed),
  derives a 0..1 trust score, and emits a high-severity `fleet:sensor-untrusted`
  event when a node's score falls. A **malformed** event (missing `sensor_id` /
  `id`, out-of-range severity, or a timestamp implausibly far in the future) is
  dropped and penalised hard — the strongest "this stream is fabricated" signal.
  On by default wherever `ingest:` is enabled.
- `quarantine_below` refuses a low-trust node's events (before the dedup set /
  bus) until its window rolls; `rate_per_sec` caps per-sensor injection rate
  (token bucket) so one flooding/compromised node can't overwhelm the store.
- **Store scale-out** — `store.InsertBatch` commits many events in one
  transaction, and the SQLite sink now batches writes (flush by size/age, and on
  Close) — the throughput path for a busy aggregator. Durable across shutdown
  (the sensor drains the router, then closes the sink — which flushes — before
  closing the store). Docs spell out horizontal scale: rollup to a higher tier,
  per-sensor rate caps, retention bounds, and external-SIEM `channels`.
- Verified end-to-end against a live aggregator: well-formed events stored via
  the batching sink; a stream of malformed events was dropped and raised
  `fleet:sensor-untrusted`; and a quarantined sensor's subsequent well-formed
  event was refused. Unit tests cover the scorer (healthy / malformed-alert /
  quarantine / window-roll / rate-limit), the ingest integration, and
  `store.InsertBatch`.

### Added — fleet aggregation: multi-level rollups + downward intel feedback (phase 3)
- **Multi-level rollups** — a `forward:` target can now ship `mode: rollup`
  instead of `full`: one `fleet:rollup` event per `rollup_interval` (default 60s)
  carrying per-window top source-IP / ASN / fingerprint / rule counters, a
  severity histogram, and the distinct-source count. Keeps upward volume sane at
  L2/L3 while preserving the correlation keys; a node can mix `full` (to a site
  SOC) and `rollup` (to a global hub). The accumulator is capped to bound memory.
- **Downward intel feedback** — new `internal/intel`. An aggregator derives
  indicators (hot source IPs, ASNs, ja3/ja4/hassh fingerprints) from its own
  `fleet:*` findings and serves them as a small JSON feed at GET `<ingest>/intel`
  (same bearer token; on by default where fleet correlation + `ingest:` are both
  enabled, `fleet.serve_intel`/`intel_ttl`/`intel_max` to tune/opt-out).
- Any node subscribes via `intel_feed:` (url + token_env + poll): it polls the
  feed through the egress allowlist and hands the indicators to its enricher,
  which tags matching events with `fleet_intel` **and** sets `threat_intel_hit`
  — so the existing tarpit / severity / risk / `threat_intel_burst` machinery
  acts on fleet-derived knowledge with no extra wiring. Events flow up; intel
  flows down, improving every sensor.
- Verified end-to-end against live nodes: an aggregator derived
  `source-multi-sensor` → served the source IP at `/intel` (bearer-gated, 401
  without a token); a leaf node subscribed, polled, and applied the indicator to
  its enricher overlay. Unit tests cover the rollup wire shape, the intel
  store/TTL/cap/handler-auth, `Feed.Maps`, and the enricher overlay tagging.

### Added — fleet aggregation: temporal / novelty / linking correlators (phase 2c)
- **`fleet:scan-trajectory`** — one source hitting sensors' destination IPs in
  (numeric) address order over time: the merged view reconstructs the scan's
  direction, rate (median stride), and the **next target** it's about to reach.
  Fires at >= `trajectory_hits` (8) destinations across >= `trajectory_sensors`
  (3) sensors with >= `trajectory_monotonic` (0.8) of time-ordered steps moving
  one way.
- **`fleet:synchronized-burst`** — >= `burst_sensors` (3) sensors each seeing >=
  `burst_min_events` (20) within `burst_window` (5m), regardless of source
  overlap: a fleet-level changepoint marking the moment a new campaign / exploit
  goes live. One alert per window (cooldown).
- **`fleet:first-fleet-contact`** — a brand-new ASN or fingerprint, unseen
  anywhere in the fleet within `first_seen_horizon` (7d), that immediately
  reaches >= `first_contact_sensors` (3) sensors: new infrastructure spinning up.
  Keyed on ASN / fingerprint (not raw IP) so the novelty memory stays bounded.
- **`fleet:identity-pivot`** — one actor behind rotating IPs, linked by a
  composite identity (a fingerprint or credential **plus** a second attribute,
  so it's stronger than a single shared fingerprint); fires at >= `pivot_sources`
  (5) distinct IPs across >= `pivot_sensors` (3) sensors.
- **`fleet:geo-distributed-actor`** — one fingerprint/credential appearing from
  >= `geo_countries` (3) countries across >= `geo_sensors` (2) sensors:
  fleet-scale impossible travel (distributed proxy / botnet). Needs GeoIP country
  enrichment on the aggregator.
- **`fleet:target-profile-match`** — >= `profile_sources` (3) distinct sources
  independently running the same >= `profile_cves` (2)-CVE playbook across >=
  `profile_sensors` (2) sensors: a shared toolkit / runbook even without a shared
  fingerprint.
- All thresholds configurable under `fleet:`; new state (per-source address-walk
  tracking, short burst buckets on the per-sensor counters, a long-horizon
  novelty memory, composite-identity / geo / CVE-playbook actor maps) is
  window-pruned (novelty by the longer horizon). Detectors live in a new
  `advanced.go`. Verified end-to-end against a live aggregator: one ingest batch
  produced all six new `fleet:*` events with correct meta — including
  `scan-trajectory` predicting `next_target` and `geo-distributed-actor`
  aggregating three countries.

### Added — fleet aggregation: five more cross-sensor correlators (phase 2b)
- **`fleet:payload-campaign`** — the same malware/shellcode artifact (by
  SHA-256, parsed from `payload_artifacts`) landing on >= `payload_sensors` (2)
  sensors: one sample on separate honeypots is one distribution campaign. Never
  background noise.
- **`fleet:credential-campaign`** — the same `username:password` tried on >=
  `cred_sensors` (2) sensors: a shared stuffing list, or — the high-value case —
  a **honeytoken credential** planted on one node now used against others.
- **`fleet:cve-wave`** — the same CVE exploit on >= `cve_sensors` (3) sensors:
  a worm / mass-exploitation wave.
- **`fleet:subnet-coordinated`** — >= `subnet_sources` (3) distinct IPs from one
  source `/24` (or `/64`) collectively covering >= `subnet_sensors` (3) sensors:
  the one-IP-per-target botnet that slips under every per-sensor threshold (and
  under `source-multi-sensor`, which needs a single IP).
- **`fleet:outlier-sensor`** — a sensor whose high-severity volume crosses
  `outlier_min_events` (100) AND exceeds `outlier_factor` (4) x the peer median
  (with >= `outlier_min_peers` (3) peers to compare): that node was specifically
  found / targeted. Volume-relative, so robust to nodes running different handler
  mixes; purely aggregator-only (needs peer baselines).
- **Broad-vs-targeted classifier** — the breadth/wave detectors
  (`source-/asn-multi-sensor`, `cve-wave`) now stamp a `coverage` ratio
  (`sensors_hit / active_sensors`) and a `scope`: a hit spanning >=
  `broad_coverage` (0.8) of the fleet is `broad` internet background (downgraded
  to medium), a specific subset is `targeted` (high). Cuts the
  Censys/Shodan-scanning noise that would otherwise dominate the breadth alerts.
- All thresholds are configurable under `fleet:` with sensible defaults; the new
  detectors reuse the windowed actor model + once-per-window firing + loop guard.
  Verified end-to-end against a live aggregator: a single ingest batch produced
  all five new `fleet:*` events with correct meta (hash, credential, CVE+scope,
  `/24`, and the node-level outlier with its peer median).

### Added — fleet aggregation: cross-sensor correlation (`fleet:`) — phase 2
- The aggregator now runs a **cross-sensor correlator** over the merged
  local + ingested stream, surfacing the attacker-identity patterns no single
  sensor can see. On by default wherever `ingest:` is enabled; `fleet.enabled`
  forces it on/off. New `internal/fleet` package.
- Three detectors, each emitting a high-severity event the first time an
  identity crosses its breadth threshold within `window` (once per window):
  - `fleet:source-multi-sensor` — one **source IP** on >= `source_sensors` (3)
    distinct sensors (a single attacker sweeping the fleet).
  - `fleet:asn-multi-sensor` — one **ASN** on >= `asn_sensors` (5) sensors
    (coordinated / distributed from one network; needs GeoIP-ASN enrichment).
  - `fleet:fingerprint-shared` — one **ja3/ja4/hassh** on >= `fp_sensors` (3)
    sensors AND >= `fp_sources` (5) distinct sources (shared toolkit / botnet:
    the IPs differ but the client stack is identical).
- Each alert carries the triggering source, the breadth counts, the (capped,
  sorted) `sensors` / `sources` lists, and the `window`. The detectors run after
  enrichment (so the ASN tag is present) and after the in-sensor correlators;
  `fleet:*` output is never re-correlated (loop guard). Alerts flow through the
  normal pipeline (store / UI / routes / risk scoring / onward `forward:`).
  Verified end-to-end: two `sensor_id`s sharing a source IP through one
  aggregator's `ingest:` produced `fleet:source-multi-sensor` in the store/API
  with `sensor_count: 2` and the contributing sensor list.

### Added — fleet aggregation: `ingest:` endpoint (phase 1c)
- A node can now be an **aggregator**: an authenticated HTTP `ingest:` endpoint
  (bearer token, optional HMAC, optional TLS) accepts batches forwarded by child
  sensors and feeds them into the same pipeline as local events, so the store /
  UI / correlators see the whole fleet. Composes with `listeners:` + `forward:`
  (a node can be sensor + mid-tier aggregator + upstream forwarder = multi-level).
- Admitted events are **deduped** by `sensor_id:id` and **loop-guarded** (an
  event whose hop chain already includes this node, or that exceeds `max_hops`,
  is dropped), so a fan-out / multi-path topology can't double-count.
- The event store now persists the originating **`sensor_id`** (a migration adds
  the column + index to existing DBs) — stable origin attribution even when
  sensors share a hostname. New `internal/ingest` package.
  Verified end-to-end: sensor A → aggregator B; B's API shows A's events tagged
  with A's sensor_id, distinct from B's own.

### Added — fleet forwarding (`forward:`) — phase 1 of central aggregation
- A sensor can now ship its events to one or more parent **aggregator** nodes
  for fleet-wide correlation. `forward:` lists targets; multiple targets fan out
  (HA, or a site SOC + a global hub), each with its own batching queue + retry.
- Events ship as NDJSON over HTTPS **through the egress allowlist** (each
  `forward.url` is allowlisted automatically, so forwarding works under
  `egress.enforce`), bearer-token + optional HMAC authenticated.
- Every event now carries the originating `sensor_id` (stable deployment id) and
  a `hops` chain stamped per node — the fleet dedup key (`sensor_id:id`) and a
  loop/provenance guard. The forwarder stamps `hops` on a copy, never mutating
  the shared event the sinks see; a full queue sheds load with a counter.
- New `internal/forward` package (Forwarder + fan-out Group + shared NDJSON codec
  + HMAC sign/verify, reused by the future aggregator ingest endpoint).
  Verified end-to-end: a sensor forwarded its listener / CVE / lifecycle events
  to a parent with `sensor_id` + `hops` and the auth/batch headers.

### Added — egress containment (outbound allowlist)
- New `sensor.egress` block: when enabled, the sensor's outbound telemetry is
  permitted to **exactly** its configured channel destinations (webhook / syslog
  / smtp / sns / discord / twilio — i.e. central forwarding + IOC export) plus
  `egress.allow` (a collector / feed not modeled as a channel), and **every
  other outbound connection is refused and recorded** as a high-severity
  `egress:denied` event — so the decoy can't be used as an SSRF pivot, open
  relay, reflector, or exfil channel while its own telemetry keeps flowing.
- New `internal/egress` package is the single outbound chokepoint (allowlist +
  guarded DialContext + HTTPClient); the dialing sinks route through it. Off by
  default (egress unrestricted) so there's no behavior change until enabled; the
  allowlist updates additively on config reload.
- `egress.enforce` adds an OS-level **nftables** backstop (Linux; needs `nft` +
  CAP_NET_ADMIN, installed at startup before privilege drop / sandbox) that drops
  the sensor's outbound packets to anything off the allowlist — scoped to the
  sensor's uid via `meta skuid` (the rest of the host is untouched), permitting
  established connections, loopback, and DNS to the system resolvers. This is the
  hard backstop that catches even a raw `net.Dial` or a library (e.g. the MQTT
  paho client) that dials outside the in-process guard.

### Changed — handlers: deeper Kerberos + VNC interaction
- **Kerberos** now records the requested **enctypes**, then drives a second
  round: after `KDC_ERR_PREAUTH_REQUIRED` it reads the client's pre-auth retry
  and captures the offline-crackable encrypted timestamp
  (`preauth_enc_timestamp_hex`, `kerberos-preauth-bruteforce`) before answering
  `KDC_ERR_PREAUTH_FAILED`.
- **VNC**: with `accept_creds: any|defaults` on the listener, the handler now
  **accepts** the auth and runs a post-auth RFB session — sends a ServerInit and
  captures the client's **keystrokes** (KeyEvents) and **clipboard**
  (ClientCutText) as `keystrokes` / `clipboard` (`vnc-session` /
  `vnc-clipboard-capture`). Default (`none`) still rejects, and the
  `(challenge, DES-response)` pair is captured for offline cracking either way.

### Added — testharness: self-trust controls + evidence-integrity category
- The runner now **self-checks** before each run: synthetic positive / negative
  / error / panic controls go through the real execution path and must classify
  correctly, and case selection must be deterministic — otherwise the run aborts
  rather than risk a false all-green. After the run it asserts the **accounting
  invariant** (every dispatched case recorded exactly one result). Both appear
  in the report's Environment block and the JSON `info` (self_check / expected /
  recorded).
- New **`integrity`** category (needs `verify.url`): `integrity/capture/<label>`
  sends a unique marker and confirms the sensor recorded it faithfully;
  `integrity/no-drop-under-load/<label>` sends a 20-connection burst and confirms
  all are recorded (no dropped events under load). Covers http/https/ftp/
  smtp_recv/telnet/imap/pop3; skips cleanly without the API.

### Changed — handlers: protocol depth (RDP TLS/NLA, Oracle version, MQTT CONNACK)
- **RDP** now completes the TLS handshake after selecting `PROTOCOL_SSL`
  (previously it advertised SSL then left the client's handshake unanswered).
  It records JA3/JA3S and best-effort harvests the CredSSP/NLA **NTLMSSP**
  domain/user + offline-crackable NetNTLM response (`rdp-ntlm-auth`).
- **Oracle TNS** version banner + VSNNUM are now derived per deployment from a
  believable 11g–21c spread, instead of a hardcoded `19.0.0.0.0` (a fingerprint
  tell across sensors).
- **MQTT** CONNACK is version-aware: v3.1/3.1.1 get a 2-byte reply, v5 the
  3-byte (properties-length) reply, and an unsupported protocol level is
  rejected with `0x01` (`mqtt-unsupported-protocol-level`) — previously every
  client got an identical v3 "accepted".

### Added — handlers: in-protocol STARTTLS (SMTP / IMAP / POP3)
- **SMTP** (25) now advertises `STARTTLS` in EHLO and performs a real TLS
  upgrade on the command (was a `454` refusal); **IMAP** (143) advertises +
  upgrades on `STARTTLS` (replacing the first-batch honest-refusal once a cert
  store is available); **POP3** (110) advertises + upgrades on `STLS` (was an
  `-ERR`). After the upgrade the command loop continues over TLS and keeps
  capturing credentials. Advertised only when a cert manager is wired and the
  connection isn't already TLS, so the implicit-TLS variants don't offer a
  pointless nested STARTTLS, and a TLS-less deployment never advertises it.
- A fresh reader is created over the upgraded connection so any plaintext a
  client pipelines after the STARTTLS command is dropped, not executed
  (STARTTLS-injection defense).

### Added — handlers: implicit-TLS services + PostgreSQL SSL
- New implicit-TLS handlers **`smtps`** (465), **`imaps`** (993), **`pop3s`**
  (995), **`ldaps`** (636), **`mqtts`** (8883), and **`ftps`** (990): a generic
  TLS wrapper performs the handshake (self-signed cert from `<data_dir>/tls`,
  shared with `https`; JA3/JA4 + JA3S computed) and runs the underlying protocol
  over the encrypted channel. Previously TLS was served only by `https`.
- **PostgreSQL** now honours an `SSLRequest` with a real TLS upgrade (answers
  `S` then handshakes) instead of always refusing with `N`, so a libpq client
  with `sslmode=require` proceeds and its cleartext password is captured.
- A shared `certManager` backs all of the above, reusing the https handler's
  on-disk cert format, per-service subject/key spread, and rotation window.

### Changed — handlers: fail-safe line caps, honest IMAP STARTTLS, wider credential capture
- Text-protocol handlers (**imap**, **pop3**, **smtp_recv**, **elasticsearch**,
  **gopher**) now read command/header lines through a bounded reader
  (`readLineCapped`, 8 KiB) instead of `bufio.ReadString('\n')`, so a
  newline-less flood can no longer drive an unbounded allocation inside the read
  deadline window.
- **IMAP STARTTLS** no longer answers `OK` and then leaves the client's TLS
  ClientHello to be read as plaintext (a broken-handshake fingerprint). It now
  refuses honestly (`NO [PRIVACYREQUIRED] STARTTLS not available`), consistent
  with the unadvertised capability and with the existing SMTP/FTP behaviour.
- Broader credential / auth capture: **mqtt** runs CONNECT username+password
  through the default-credential corpus (`mqtt-credential-attempt`); **winrm**
  runs captured HTTP **Basic** creds through it too; **vnc** now records the
  auth *challenge* alongside the response (the pair is needed to crack offline)
  and flags `vnc-auth-attempt`; **kerberos** extracts the principal/realm
  (the sprayed username) and flags `kerberos-principal-probe`.

### Added — testharness: resilience + containment categories, run-info, more report formats & protocol specs
- Two new fail-safe/fool-proof categories: **resilience** (oversize input,
  half-open churn, connection flood, slow-drip starvation — the sensor must not
  become the victim) and **containment** (no-egress canary + path-traversal —
  do-no-harm). Both run in module and network modes.
- Reports can now be emitted as **csv**, **rtf**, and **pdf** in addition to
  text/json/junit/md (the PDF is hand-rolled — no new dependency).
- Every run now records **before/during/after** context (host + Go env, config
  summary, spawned-binary sha256, a sampled RSS/goroutine envelope, and
  baseline-vs-final endpoint snapshots that flag drift / went-dark), surfaced in
  the reports and the JSON `info` object.
- Deep protocol specs (emulate/fuzz-smart/misimpl) added for **imap**, **pop3**,
  **mysql**, **postgres**, **vnc**, **memcached**, **mqtt**, and **ldap**.

### Added — web UI: traffic counters + richer health page
- The **summary** page opens with an at-a-glance counters strip — event
  volume by transport (TCP / UDP / ICMP) + high/critical from the store —
  plus a raw **L2 frame** row (received / ARP / IPv4 / IPv6 / TCP / UDP /
  ICMP) when the AF_PACKET sniffer is running. The sniffer now counts frames
  per protocol (`tarpit_sniffer_frames_total{proto=...}`); `store.Summary`
  gained a `ByProto` breakdown.
- The **health** page adds build version/commit, a 24h by-transport
  breakdown, per-name panic counts, and the sniffer's L2 frame counters.
- The enrichment keys (`oui_file`, `geoip`, `tor`, `net_class`,
  `threat_intel`) are now shown in the example configs (run-safe: empty/
  disabled by default).

### Added — file-path visibility + enrichment install/update workflow
- New **`list-paths`** subcommand prints every filesystem path the config
  references — config file(s), enrichment inputs, GeoIP/event databases, and
  data-dir state — classified by category with read/write + present/MISSING
  (`--json` / `--format tsv` / `--category` for tooling).
- The web UI **`/config`** page gains a **"files in use"** table (category,
  key, access, path, present/MISSING) from the same source.
- `scripts/fetch-enrichment.sh` now **packages** its output: a `SHA256SUMS`
  manifest, a single `<dir>.tar.gz` (+ `.sha256`) for easy transfer, and a
  `suggested-config.yaml` — the "download step".
- New **`scripts/install-enrichment.sh`** (the "install/update step", for
  cron/systemd on the sensor): verifies the bundle checksums, asks the live
  config where each file belongs via `list-paths --format tsv`, atomically
  installs each downloaded file into its configured destination, and signals
  the running sensor (SIGHUP) to re-read.
- SIGHUP now **re-reads the enrichment databases** (GeoIP / threat-intel /
  Tor / OUI) unconditionally — even when the config text is unchanged — by
  hot-swapping the enricher (`Sensor.ReloadEnrichment`), so refreshed feeds
  apply without a restart.

### Added — MAC-vendor enrichment + an enrichment-database fetcher
- Events carrying a MAC (DHCP `client_mac`, ARP `sender_mac`, …) are now
  decorated with `mac_vendor`. `devices.LoadOUIFile` loads the full IEEE
  OUI registry (`oui.csv`) — configured via `sensor.oui_file` — and it
  upgrades vendor resolution everywhere (event enrichment + the learned-
  device inventory); a small built-in OUI table is the fallback. Surfaced
  as a "MAC vendor (OUI)" collector on the config canvas.
- New standalone operator tool **`scripts/fetch-enrichment.sh`**: run it on
  an internet-connected machine to download the enrichment databases — Tor
  exit list, IP-reputation feeds (blocklist.de, abuse.ch, Spamhaus DROP,
  FireHOL), GeoIP/ASN (DB-IP lite by default, MaxMind GeoLite2 with a
  license key), and the IEEE OUI database — into a directory you can
  transfer to an air-gapped/restricted-egress sensor. It prints a
  ready-to-paste config snippet wiring every file.

### Added — web UI: case-insensitive search, credential source, clickable ATT&CK
- Full-text search is now explicitly case-insensitive (LOWER on both sides).
- The attacker-profile **"credentials tried"** table shows the
  service/protocol each credential was captured on.
- ATT&CK technique chips are **clickable** → `/attack/technique?id=<TID>`, a
  drill-down with a plain-English description (`mitre.Describe`) plus the
  tactics, source IPs, and rules behind that technique.

### Added — detection breadth
- **+5 in-sensor correlators**: `lateral_movement`, `ot_recon`,
  `data_access`, `malware_campaign`, `webshell` (all opt-in).
- **HTTP protocol-misuse**: request-smuggling (TE+CL ambiguity) and
  CONNECT open-proxy detection.
- **+ATT&CK coverage**: a technique-description map; tags for the new
  correlators / `attack:*` events; and ~30 previously-untagged
  protocol-misuse markers (redis drop chain, docker deploy, NTP
  amplification, postgres replication, SIP/RTSP/WinRM auth, …).

### Added — protocol handlers + fake-web variants
- **+6 handlers**: rsync (873), gopher (70), SOCKS4/5 (1080), BGP (179)
  over TCP; IKE/ISAKMP (500) and NetBIOS-DGRAM (138) over UDP.
- **webapp variants**: `webapp_variant` selects a decoy persona —
  `wordpress`, `phpmyadmin`, or `jenkins` — over the shared attack-class
  detection + credential capture.

### Added — device identity
- **+7 archeservice role bundles**: proxyserver, vpnserver,
  monitoringserver, backupserver, iotgateway, scadaserver, routerserver.
- **+3 PLC archetypes**: Schneider Modicon M580, Omron NX1P2, Mitsubishi
  MELSEC iQ-R (with their OT CVEs advertised under vuln_emulation).
- **+CLI command emulation**: a FortiOS (FortiGate) command family, and a
  vendor-aware PLC console for non-Siemens PLCs.

### Added — Windows builds
- `make cross` now also builds `windows/amd64` and `windows/arm64`. The
  raw-L2 deception layers stay Linux-only (no-op elsewhere); the protocol
  emulators, correlators, web UI, and file canaries run on Windows. Fixed
  a 32-bit integer overflow that also blocked the arm cross builds.

### Added — fuzzing & DoS detection + classification
- New always-on `internal/fuzzdos` detector with two halves:
  - **Per-payload fuzzing classifier** — scores each request's byte
    structure (Shannon entropy, printable ratio, single-byte runs, null
    floods, format-string specifiers, gross oversize) and labels the
    technique: `buffer-overflow`, `format-string`, `null-flood`,
    `oversize`, `high-entropy`, or `binary-garbage`. Binary protocols
    aren't entropy-judged (they look that way normally). A positive
    verdict stamps a `fuzzing-<technique>` anomaly + `fuzz_technique` /
    `payload_entropy` meta on the event, so the `protocol_violation`
    correlator and SIEM inherit it.
  - **Per-source DoS / campaign classifier** — labels the denial-of-service
    type (`slowloris` / `connection-flood` / `app-flood` / `volumetric` /
    `malformed-flood`) and a sustained fuzzing campaign (dominant
    technique), emitting `attack:dos` / `attack:fuzzing` with a confidence
    score. Complements the AF_PACKET sniffer's wire-level flood detection.
  - **Slowloris signal**: the TCP listener stamps a `slow-request` anomaly
    + `conn_duration_ms` on a banner connection the client held open for
    ~the full read window while sending only a tiny/partial request; the
    tracker aggregates these into the `slowloris` DoS classification.
- ATT&CK mappings added for `attack:dos` (T1499) / `attack:fuzzing`
  (T1595.002) and for the 10 opt-in correlators added earlier (they were
  previously untagged). Surfaced as a "Fuzzing/DoS classifier" detection
  card on the config canvas.

### Added — collectors: enrichment + canvas visibility
- **3 new enrichment collectors** in the event-decoration pipeline
  (`sensor:` config, enrichment-only — they tag, never block):
  - `threat_intel` — tag source IPs found on operator-supplied IP/CIDR
    reputation lists (each labeled); events get `threat_intel` (matched
    labels) + `threat_intel_hit`.
  - `tor` — flag sources in a Tor exit-node list with `tor_exit=true`.
  - `net_class` — built-in, database-free classification of public
    sources: `bogon` (reserved/martian ranges) or `hosting` (datacenter /
    cloud AS-org, from the GeoIP-ASN org).
- The web UI **config canvas** now surfaces the real-but-previously-hidden
  background subsystems: **Scan analysis** and **Client fingerprinting**
  (detection), **PCAP capture** (forensics), and the three new enrichment
  collectors. The **Correlation engine** detector count now includes the
  10 opt-in correlators added earlier.

### Added — CVE catalog: +20 OT/ICS advisories
- The CVE catalog grows by **20 OT/ICS control-protocol records** mapped to
  the industrial handlers the honeypot emulates: Schneider Modicon UMAS/Modbus
  (CVE-2021-22779, CVE-2018-7852), Siemens S7-1500 (CVE-2016-2200) and
  S7CommPlus MITM (CVE-2019-10929), CODESYS V2/V3 runtime + gateway
  (CVE-2022-31806, CVE-2020-10245, CVE-2022-31802), OPC UA .NET
  (CVE-2021-27432), KNX (CVE-2023-4346), Siemens SIPROTEC EN100 / IEC-104
  (CVE-2015-5374), GE PACSystems SRTP (CVE-2019-13524, CVE-2018-8867), Omron
  FINS (CVE-2020-6986), Mitsubishi MELSEC iQ-R (CVE-2021-20591), TMW IEC-61850
  MMS (CVE-2022-38138), TMW DNP3 (CVE-2013-2783), Tridium Niagara Fox
  (CVE-2017-16744), Phoenix Contact PCWorx (CVE-2016-8367), FieldComm HART-IP
  (CVE-2020-16209), and Veeder-Root ATG (CVE-2025-58428). Advisory-only
  (binary control protocols have no safe substring signature), each with
  CWE / CPE 2.3 / EPSS cross-references and an ATT&CK mapping; surfaced by the
  matching handler under `vuln_emulation` and via `Lookup`.

### Added — scan analysis: tool fingerprinting + scan geometry
- `scananalysis` gains **scanner/exploitation-tool fingerprinting**
  (masscan, zgrab/zmap, nuclei, nikto, sqlmap, gobuster/dirbuster, ffuf,
  wpscan, nessus, qualys, acunetix, nmap-nse) from self-identifying
  User-Agents, plus more nmap service probes (RTSP, SIP, TLS ClientHello,
  Java-RMI) and vuln-scan NSE signatures (`/.env`, `/manager/html`,
  `/actuator`, `/wp-login.php`, HNAP).
- The per-source `Tracker` now reports **scan geometry**: `ScanShape`
  (vertical / horizontal / block from host×port breadth), `PortOrder`
  (sequential vs random), `DistinctHosts`, a fingerprinted `Tool`/`Tools`,
  a `Stealthy` flag (-T0/-T1 cadence), a `VulnScan` flag, and a 0–100
  `Confidence` score. The sensor's `scananalysis:profile` event carries all
  of these in its meta.

### Added — correlators: 10 new detectors
- The in-sensor correlation engine adds **10 opt-in detectors** (all
  default-off, configured under `correlate:`): `host_sweep` (horizontal
  scan across honeynet hosts), `service_sweep` (cross-protocol recon),
  `ua_rotation` (User-Agent cycling), `exploit_chain` (multiple distinct
  CVEs from one source), `ics_control` (repeated OT write/control commands),
  `canary_trip` (multiple distinct canary tokens), `fingerprint_reuse`
  (one JA3/JA4/HASSH across many source IPs), `protocol_violation`
  (fuzzing — many distinct anomaly markers), `exfil` (cumulative inbound
  bytes), and `session_flood` (connection flood). Each emits a
  `correlate:<name>` aggregate event with windowed, memory-bounded state.

### Added — device inventory: 11 query/analysis methods
- The learned-device `Registry` gains query/analysis methods powering richer
  rogue-device review: `Get`, `FindByIP`, `Count`, `Stats` (totals + by
  source/class), `ByClass`, `ByVendor`, `Rogues`, `Active`, `Stale`,
  `Search`, and `Conflicts` (one IP bound to multiple MACs — a persistent
  ARP-spoof / impersonation signal).
- Surfaced to operators in two places:
  - **`list-devices`** gains `--stats`, `--conflicts`, `--rogues`,
    `--class`, `--vendor`, `--search`, `--stale`, and `--active` (all
    honoring `--json`).
  - The web UI **`/devices`** tab now opens with a summary panel (total /
    allow-listed / rogue, by-source and by-class breakdown) and a
    highlighted **IP/MAC-conflict** warning; JSON at
    `/api/devices/summary`.

### Added — CVE catalog: +40 detections
- The in-source CVE catalog grows by **40 records** (now covering the
  edge-device / enterprise-app pre-auth chains attackers mass-scan):
  - **26 exploit-signature records** (recognized live by `MatchPayload` →
    `cve:<id>` events): Ivanti EPMM/Sentry/Connect-Secure, ConnectWise
    ScreenConnect, Confluence broken-access-control, Jenkins CLI, JetBrains
    TeamCity, VMware vCenter/Workspace ONE, Oracle WebLogic/Access Manager,
    F5 TMUI SSRF, Cisco ASA WebVPN, WSO2, Fortra GoAnywhere, Apache Struts2
    S2-057, JBoss invoker, Alibaba Nacos, CWP, Citrix NetScaler RCE, Zimbra,
    PaperCut, and Elasticsearch Groovy/MVEL scripting RCE (the last two now
    matched on the `elasticsearch` handler).
  - **14 advisory-only records** (banner / patch-level + ATT&CK mapping):
    CitrixBleed, the FortiOS SSL-VPN chain + FortiManager FortiJump, SambaCry,
    SIGRed, regreSSHion, ESXiArgs, and the Windows RPC/NTLM relay flaws.
  - Each new record carries CWE / CPE 2.3 / EPSS cross-references.

### Added — protocol handlers: 20 richer service decoys
- Twenty banner-mode handlers now answer more of their protocol's real
  command surface so a scanner that goes past the first banner keeps getting
  believable replies (still no real exploitability, no UDP amplification):
  - **redis** answers `INFO` / `CONFIG GET` / `CLIENT` / `HELLO` / `COMMAND`
    / `DBSIZE` / `SCAN` / `ACL` / `LOLWUT` (was `-ERR`); **memcached** emits a
    full `stats` block + `stats settings|items|slabs`; **mongodb** answers
    `buildInfo` / `listDatabases` / `ping` and an auth-required error for
    data-access commands; **elasticsearch** serves cluster/indices/nodes JSON
    and matches the Groovy/MVEL RCE payloads.
  - **imap** / **pop3** / **smtp_recv** gained SASL `AUTHENTICATE`
    (PLAIN/LOGIN/CRAM-MD5) credential capture, fuller `CAPABILITY`/`CAPA`,
    `STARTTLS`/`STLS`, and SMTP `CHUNKING`/`BDAT`.
  - **rtsp** / **sip** are now method-aware (OPTIONS→200 Public/Allow,
    DESCRIBE/REGISTER/INVITE→401 Digest to harvest creds, sipvicious
    detection); **mqtt** runs a post-CONNACK session (SUBSCRIBE/PUBLISH/PING
    + wildcard-harvest flag); **coap** flags write-method probes.
  - **telnet** does proper IAC option negotiation (clean credential capture +
    TERMINAL-TYPE); **vnc** adds the RFB 3.3 handshake; **ntp** flags
    mode-6/7 amplification recon (still never replies); **xmpp** decodes SASL
    PLAIN creds; **dockerapi** lists containers/images/networks and flags
    container-takeover POSTs; **mysql**/**postgres** flag SSL/auth-plugin and
    replication/cancel; **oracle_tns** answers the `COMMAND=version` probe;
    **winrm** drives NTLM type1→type2→type3 to harvest the AD domain/user.
  - Per-deployment version pools added for redis / memcached / mongodb /
    elasticsearch (no banner clustering across sensors).

### Added — web UI: config infrastructure canvas
- The **`/config`** page now opens with an **infrastructure canvas**: a
  port-card grid (port · service · handler · mode, badged tls/pcap/archetype,
  coloured by drop/banner/tarpit) showing exactly which ports/services are
  listening, plus **collector pills** grouped by category (passive capture,
  network responders, enrichment, detection, forensics, output) marking each
  background subsystem active vs available-but-off. JSON at
  `/api/config/canvas`; the full effective YAML still follows below.

### Changed — web UI: packaged JavaScript + relaxed-but-tight CSP
- The UI now ships a small **packaged JS layer** (`internal/ui/static/app.js`,
  embedded in the binary via `go:embed`, served same-origin from `/static/`
  — never a CDN). The CSP moves from blocking all scripts to
  `script-src 'self'` (no inline, no `eval`, no third-party) plus
  `connect-src 'self'` / `form-action 'self'`.
- The JS is **progressive enhancement** (every view still works with JS off):
  a pausable, visibility-aware live-refresh bar (no-JS fallback remains the
  `<meta refresh>`), client-side table sort + row filter, and an interactive
  SVG **node-link correlation graph** on `/correlation`. No third-party
  framework blob is vendored into the security binary; the static pipeline +
  `script-src 'self'` make dropping one in (pinned + checksummed) a one-file
  change if desired.

### Added — web UI: infrastructure-map activity overlay
- `/topology` is now an **infrastructure map**: each honeynet host shows live
  attack activity (last 24h) overlaid — event count, distinct attacker count,
  max severity, last-seen — with a per-network rollup, so the operator sees
  which decoys / fake-AD / OT / cloud traps are under attack at a glance.

### Added — web UI: correlation, tunnels, advanced search
- New **`/correlation`** view: per-source pivot chains (IP → fingerprints →
  User-Agents → ASN/country → domains → tools → credentials → malware →
  sessions) as linked chips — a no-JS render of the pivot graph.
- New **`/tunnels`** view: covert-transport detections (DNS/ICMP tunnels,
  encrypted DNS, DGA, sniffer encapsulation, QUIC, unknown-protocol) by type
  / source / recency. Honest by design — labelled detections, not live
  tunnels (the sensor doesn't carry SSH/SOCKS/k8s/service-mesh pivots).
- New **`/search`** view: structured columns to SQL + behavioral post-filters
  (ATT&CK tactic / country / tool / has-payload / has-session) over meta.

### Added — web UI: attack timeline + richer summary
- New **`/timeline`** view: per-source chronological event sequences (top
  sources by volume), each showing the attacker's progression with severity
  colouring + the ATT&CK tactics touched — distinct from the flat `/events`
  firehose.
- The **summary** page gained charts for ATT&CK tactic, handler, source
  country, source ASN, and identified tool/scanner (from a bounded scan of
  recent events; the SQL summary only covers severity/rule/source).

### Added — web UI: ATT&CK mapping + sensor health dashboards
- New **`/attack`** view: a kill-chain-ordered tactic timeline (techniques
  nested per tactic), a top-technique heatmap, and the recent
  `storyline:multi_stage` kill-chain progressions — techniques recomputed
  per stored event from rule + handler + anomaly markers (the same mapping
  the router stamps live). JSON at `/api/attack`.
- New **`/health`** view: uptime, Go runtime (memory / goroutines / GC),
  recovered panics, event-DB size + data_dir disk %, events/24h, and
  per-sink dropped / failed / retried counters. The stats provider now also
  exposes `tarpit_disk_used_percent`.

### Added — more example configs + refreshed existing ones
- New ready-to-run example configs in `configs/`: `example-MINIMAL`
  (smallest useful deployment), `example-AD-ENTERPRISE` (Windows / Active
  Directory decoy exercising the Kerberos / LDAP / MSRPC detections),
  `example-DATASTORES-WEB` (web app + Redis / memcached / MongoDB /
  Elasticsearch + the path-enumeration correlator), and
  `example-LOW-INTERACTION-STRICT` (interaction guardrails pinned to their
  floor). All validate with `validate-config`.
- Refreshed the existing examples for this cycle's features: the new
  correlators (`path_enumeration` / `dns_enumeration` / `beacon`), the
  `interaction:` block, the new handlers (pop3 / imap / memcached / mongodb /
  elasticsearch / mdns / auto), and the SNMP `mib_profile` / `walk_*` knobs
  (FULL uses `medium_experimental` + the `full` MIB profile; the OT examples
  pin `mode: low`).

### Added — SNMP: walkable MIB, profiles, topology table, walk rate-limit/tarpit
- The `snmp` handler now answers from an **ordered, walkable MIB** with proper
  lexicographic GetNext + bounded GetBulk, so real `snmpwalk` / `snmpbulkwalk`
  actually traverse the tree (the old handler "cheated" GetNext, stalling a
  walk). Exposes the system group, `ifNumber` + full `ifTable`, the ip group,
  and the **`ipNetToMediaTable` (ARP table) synthesized from the honeynet
  topology** — so a walk enumerates the artificial L2/L3 inventory.
- **`listener.snmp.mib_profile`** (`minimal` | `host` | `network` | `full`)
  selects the exposed subtrees.
- **`listener.snmp.walk_rate_per_min`** + **`walk_tarpit`** rate-limit / tarpit
  per-source SNMP walks, flagging `snmp-walk-rate-exceeded` (T1046).

### Added — interaction-depth guardrails (`interaction:`) + CLI
- New `interaction:` config block makes "this signal is infeasible in
  low-interaction mode" an explicit guardrail instead of a docs footnote:
  `mode` (`low` default | `medium_experimental`), `http2_probe_capture`
  (`disabled` | `headers_only`), `ssh_kex_depth` (`kexinit_only` |
  `extended_experimental`), `browser_traps` (locked `off`). The
  `*_experimental` values only unlock in `medium_experimental`; setting one
  in `low` mode is a config **error**, not a silent downgrade.
- New CLI: `--interaction-mode low|medium_experimental` (overrides
  `interaction.mode` for run/validate/show-config through the normal
  override path), and `list-unavailable-capabilities` which prints the
  disabled / locked / infeasible high-interaction feature matrix for the
  active config (`--json` supported).

### Fixed — remaining ATT&CK gaps + example-config coverage
- Mapped the last 15 emitted-but-unattributed anomaly markers so **every
  marker the sensor emits now carries an ATT&CK technique**: web-shell
  access / command (`webshell-access-attempt`, `webshell-command` →
  T1505.003 / T1059), login attempts (`http-login-attempt`,
  `mssql-login-attempt` → T1110.001), bare service probes + malformed
  protocol banners (`*-probe`, `ssh-id-*`, `http-method-unknown`,
  `http-request-line-non-printable`, `telnet-credential-non-printable` →
  T1595), and `pjl-command` / `dhcp-client-observed` (T1083 / T1046).
  ATT&CK catalog is now **242 mappings** (31 rule + 92 handler + 119 anomaly).
- The example config (`configs/tarpit-honeypot.example.yaml`) now exercises
  the handlers added this cycle: `pop3`, `imap`, `memcached`, `mongodb`,
  `elasticsearch`, `mdns`, and the generic `auto` catch-all.

### Fixed — ATT&CK attribution gaps (audit follow-up)
- The **24 `shell-*` interactive-shell TTP markers** (reverse shells,
  credential dumping, persistence, AD recon, defense evasion, coin miners,
  …) had **no ATT&CK mapping** — the marquee post-login detections were
  emitting with empty `mitre_techniques`. Each now carries its own technique
  (T1059 / T1003 / T1053.003 / T1548.x / T1562.x / T1496 / …), plus a
  `shell-` prefix fallback (→ T1059) so future markers are never unattributed.
- `ssh_interactive` had no handler-tag and fell back to **T1190**
  (exploit-public-facing-app); it now maps like `ssh` → T1110.001 + T1078.
- Mapped three more emitted-but-unattributed markers: `bacnet-write-attempt`
  (T0836/T0831, the BACnet analogue of `modbus-write-attempt`),
  `udp-amplifier-probe` (T1498.002), and `honeyfile-download` (T1005).
- The `mailserver` archeservice role now also stands up **POP3 + IMAP**, and
  `dbserver` adds **memcached / MongoDB / Elasticsearch**, so those roles
  expose the handlers added this cycle. (ATT&CK catalog is now 227 mappings:
  31 rule + 92 handler + 104 anomaly.)

### Fixed
- The web UI **fingerprints** page (and the fingerprint detail/API filter) no
  longer 500s. Events stored without meta have `meta_json = ''`, and SQLite's
  `json_extract('', …)` raises "malformed JSON", which failed the whole index
  query whenever any empty-meta event existed. The fingerprint queries now
  guard `json_extract` with `json_valid(meta_json)` (via CASE, so it can't be
  reordered around the guard). Fixes existing databases with no migration.

### Added — IPv6 packet capture (scans / tunnels / fragmentation over IPv6)
- The sniffer now binds a third AF_PACKET socket for IPv6 (alongside IPv4
  and the L2 path), so the scan, encapsulation, fragmentation, and ICMP-
  tunnel detectors see **both IP versions**. New coverage: **DS-Lite**
  (IPv4-in-IPv6), **GRE-over-IPv6**, IPv6-in-IPv6, **ICMPv6** echo tunnels,
  and IPv6 SYN/NULL/FIN/Xmas/ACK/Maimon/UDP scans + IPv6 fragmentation.
  `parseIPv6` walks the extension-header chain (hop-by-hop / routing /
  fragment / dest-opts / AH) with full bounds-checking and is exercised by
  the frame fuzzer.

### Added — covert / tunnelling transport detection
- `sniffer:icmp_tunnel` — an ICMP echo carrying a large, high-entropy data
  payload (ptunnel / icmpsh / Loki); stock pings don't trip it. T1095/T1572.
- `sniffer:encapsulation` now sub-types IPv6-in-IPv4 (IP proto 41) into
  **6in4 / 6to4 / ISATAP** from the inner IPv6 addresses (2002::/16,
  …:5efe interface id).
- The `auto` catch-all fingerprints **QUIC** long-header packets, so a
  covert QUIC channel on an unmodelled port is labelled (`protocol_guess:
  quic`) rather than dropped.
- `docs/attribution.md` gained a covert-transport coverage & limits note:
  what's caught (DNS/ICMP tunnels, the encap family, QUIC, fragmentation,
  custom malware framing via the catch-all) and what isn't without IPv6
  capture (DS-Lite, GRE-over-IPv6) or in general (steganographic transport).

### Added — scripted-protocol framework: stages, match modes, capture
- The `scripted` handler gained **stateful sessions**: a rule can require a
  `stage` and transition with `set_stage`, so operators can model multi-step
  protocols (e.g. an `auth` stage gating a `command` stage) in YAML.
- New **match modes**: `suffix`, and the case-insensitive `iprefix` /
  `icontains` (alongside the existing prefix/contains/regex/hex_prefix/any).
- **Credential capture**: a `regex` rule with `capture: user` / `capture:
  pass` records the first capture group into `auth_user` / `auth_pass`,
  feeding the attacker profile + default-credential matching — so a custom
  auth protocol harvests credentials without writing Lua.

### Added — deeper FTP interaction (post-auth session capture)
- The FTP handler no longer stops at the login: it captures the first
  credential (still 530), then accepts a retry (230) and drives a logged-in
  session, recording every command in `ftp_commands` and flagging intent —
  `ftp-upload-attempt` (malware/webshell drop, T1105), `ftp-download-attempt`
  (T1020), `ftp-site-command` (SITE EXEC RCE, T1059), `ftp-bounce-scan`
  (a PORT pointing at a third party, T1090/T1046, with the target in meta),
  `ftp-delete-attempt`, and `ftp-listing`. No data connection is ever opened
  and the filesystem is never touched.

### Added — generic `auto` catch-all handler (TCP + UDP)
- New `auto` handler for protocols the sensor doesn't explicitly model: it
  captures the client's opening message, guesses the protocol from the
  leading bytes (`protocol_guess`: tls / ssh / http / socks4|5 / text /
  binary / length-prefixed), records the byte count, and raises an
  `unknown-protocol` anomaly (ATT&CK T1046) so a probe on any unmodelled
  port is still attributable. On TCP it can send an operator-set `banner`
  as a server-first nudge; on UDP it never replies (a UDP reply to a
  spoofable source would be a reflection/amplification primitive).

### Added — correlator: C2 beacon detection
- New `correlate:beacon` detector — regularly-spaced call-home contact from
  one source. After `min_hits` samples (default 6) in the window it measures
  inter-arrival jitter (stddev/mean); a jitter `<= max_jitter_pct`
  (default 20%) over a mean interval `>= 1s` is flagged as C2 beaconing.
  Sub-second bursts and irregular timing are excluded. Config
  `correlate.beacon`; ATT&CK T1071.

### Added — correlator: path-enumeration + DNS-enumeration
- New `correlate:path_enumeration` detector — one source requesting many
  distinct HTTP URL paths within a window (content discovery / dirbusting /
  forced browsing that per-request UA fingerprinting misses when the UA is
  spoofed). Config `correlate.path_enumeration` (default 50 paths / 60s);
  ATT&CK T1595.003 / T1083.
- New `correlate:dns_enumeration` detector — one source querying many
  distinct DNS names within a window (subdomain brute force / NXDOMAIN flood
  / DGA churn). Config `correlate.dns_enumeration` (default 50 names / 60s);
  ATT&CK T1590.002 / T1568.002. Both per-source sets are window-aged + capped.

### Added — DNS DGA detection
- The DNS handler + canary flag `dns-dga-suspected` on A/AAAA lookups for
  algorithmically-generated domains (long, vowel-poor / digit-heavy /
  long-consonant-run labels — the shape of malware DGA C2 rendezvous,
  ATT&CK T1568.002). Conservative (>= 12-char all-alphanumeric labels) to
  avoid false-positives on real domains; only address lookups, since
  tunnelling uses TXT/NULL.

### Added — SMB / Windows MSRPC abuse detection
- The **DCERPC** handler now flags a bind to a sensitive MSRPC interface as
  AD enumeration / lateral movement: `dcerpc-samr-enum` (account
  enumeration), `dcerpc-lsarpc-enum` (SID/policy enumeration — BloodHound,
  T1482), `dcerpc-srvsvc-enum` (share enumeration, T1135),
  `dcerpc-svcctl-access` (remote service control — PsExec, T1021.002 /
  T1543.003), `dcerpc-winreg-access` (remote registry — SAM/LSA hive read,
  T1003.002), `dcerpc-dcsync` (DRSUAPI replication — DCSync, T1003.006),
  and `dcerpc-netlogon-access` (Netlogon — ZeroLogon surface, T1210). Added
  the drsuapi + netlogon interface UUIDs.

### Added — Active Directory / Kerberos abuse detection
- The **Kerberos** handler flags a TGS-REQ (`kerberos-tgs-request` —
  Kerberoasting service-ticket request) and an RC4-HMAC etype in the
  request (`kerberos-rc4-requested` — the offline-crack downgrade
  Kerberoasting / AS-REP roasting use). ATT&CK T1558.003.
- The **LDAP** handler now processes a full message sequence: it accepts an
  anonymous bind (resultCode 0) to elicit the follow-up search, then flags
  AD reconnaissance — `ldap-spn-enumeration` (Kerberoasting recon,
  T1558.003 / T1087.002), `ldap-asrep-roast-recon` (the DONT_REQ_PREAUTH
  `userAccountControl:…:=4194304` filter, T1558.004), and `ldap-enumeration`
  (broad objectClass / sAMAccountName / objectCategory queries, T1087.002).
  Credentialed binds are still captured + rejected.

### Added — HTTP behavioral detection
- The HTTP handler now flags **malformed headers** (`http-malformed-header`:
  a header line with no `name:` colon, or control bytes embedded in a
  header — a smuggling / non-HTTP-client tell), **duplicate Host**
  (`http-duplicate-host`: request-smuggling / cache-poisoning, T1190), and
  an **impossible browser stack** (`http-impossible-browser`: a `Mozilla/5.0`
  User-Agent that omits the Accept-* header set every real browser sends —
  UA spoofing / masquerade, T1036).

### Added — new protocol handlers: MongoDB, Elasticsearch
- **MongoDB** (TCP 27017) speaks the wire protocol: parses the OP_MSG /
  OP_QUERY header, answers the hello/isMaster handshake with a hand-built
  BSON document, captures the command (OP_MSG) or collection (OP_QUERY),
  and flags data-access commands (`mongodb-data-access`: find / aggregate /
  listDatabases / …). T1213 / T1110.001.
- **Elasticsearch** (TCP 9200) returns a believable cluster banner on `/`
  and flags recon (`elasticsearch-recon`: `_cat`, `_cluster/health`,
  `_nodes`) and data access (`elasticsearch-data-access`: `_search`,
  `_all`). T1213 / T1046.

### Added — new protocol handlers: POP3, IMAP, memcached
- **POP3** (TCP 110) and **IMAP** (TCP 143) mail handlers greet, walk the
  login (USER/PASS, APOP, LOGIN incl. quoted args, AUTHENTICATE), capture
  the credentials (→ attacker-profile creds + default-credential matching),
  and reject the auth. ATT&CK T1110.001 / T1114.
- **memcached** (TCP 11211) text-protocol handler answers version/stats/
  get/set believably and flags abuse (`memcached-stats-probe`,
  `memcached-write-attempt`, `memcached-flush`). TCP-only by design — it
  never reflects, so it can't be abused as a UDP amplifier. T1213 / T1046.

### Added — encrypted-DNS detection (DoH / DoT / DNSCrypt) + mDNS handler
- The HTTP handler flags **DNS-over-HTTPS** (`dns-over-https`): the RFC 8484
  `/dns-query` path or the `application/dns-message` media type.
- The TLS handler flags **DNS-over-TLS** (`dns-over-tls`): a connection on
  port 853 or an ALPN of `dot`.
- The DNS handler + canary flag **DNSCrypt** (`dnscrypt-probe`): the
  `<v>.dnscrypt-cert.<provider>` certificate lookup.
- All three map to ATT&CK T1572 / T1071.004 (DNS tunnelled inside an
  encrypted channel to evade plaintext DNS monitoring).
- New **mDNS handler** (UDP 5353, RFC 6762): observes multicast-DNS / DNS-SD
  queries, flags `mdns-service-enumeration` for the `_services._dns-sd._udp`
  discovery sweep (T1046), and answers `.local` A queries to draw a
  follow-up connection. (LLMNR / NBNS / CLDAP already had handlers; plain
  DNS tunnelling / exfil / amplifier probes were already detected.)

### Added — sniffer L2/tunnelling detection (encapsulation + spanning-tree)
- The packet-capture layer now flags **tunnelling / overlay traffic**
  (`sniffer:encapsulation`): GRE, IP-in-IP, 6in4, EtherIP, L2TPv3 by IP
  protocol, and VXLAN, GENEVE, L2TP, Teredo, GRE-in-UDP by UDP port —
  anomalous on a flat segment (ATT&CK T1572 / T1095, protocol tunnelling).
- It also recognizes **spanning-tree BPDUs** (`sniffer:stp_bpdu` —
  STP/RSTP/MSTP/PVST+) on the main capture socket; a root-bridge /
  topology-manipulation tell (AiTM, T1557), low severity + rate-limited.
  Both are gated by the existing `tcp_scan` capability (need CAP_NET_RAW).

### Added — nmap Maimon (`-sM`) + UDP (`-sU`) scan detection + coverage docs
- The packet-capture layer now classifies the nmap Maimon scan
  (`sniffer:tcp_maimon_scan` — bare FIN+ACK to a port, volume-gated so a
  normal connection teardown can't trip it) and the UDP port scan
  (`sniffer:udp_scan` — one source spraying many distinct UDP ports),
  both mapped to ATT&CK T1046 / T1595.001. (`-sW` Window scan was already
  caught — it shares the ACK probe on the wire with `-sA`.)
- `docs/attribution.md` gained a **coverage & limitations** matrix mapping
  every requested client-fingerprint signal to its status (covered via
  JA3/JA4/JA4H/HASSH/TTL, partial, or infeasible-for-a-passive-no-JS-sensor
  with the reason), plus the new confidence-scoring, C2/headless
  categories, and fingerprint-reputation/cross-sensor views.

### Added — Fingerprint reputation + cross-sensor correlation (web UI)
- New **fingerprints** tab (`/fingerprints`, `/api/fingerprints`): an index
  of every JA3 / JA4 / JA4H / JA3S / HASSH / HASSH-server fingerprint seen
  in the last 30 days, ranked by event volume with distinct-IP and
  distinct-sensor counts and first/last-seen.
- Per-fingerprint **reputation report** (`/fingerprints/<kind>/<value>`,
  `/api/fingerprints/<kind>/<value>`): first/last seen, distinct source
  IPs, and CSS bar-chart breakdowns (no JavaScript) over sensors (fleet
  correlation), top source IPs, countries, ASNs, protocols, destination
  ports (service-named), attack types (rules), tools/scanners, and captured
  malware-artifact kinds. Attacker-profile fingerprints now link to it.
- `store` gained a `Fingerprints` index query (one GROUP BY pass per kind,
  UNION'd) and a fingerprint `Filter` (`FPKind`/`FPValue`) on `Query`. The
  kind is validated against a fixed allowlist mapped to JSON paths, so only
  the fingerprint value is ever bound as a SQL parameter (an unknown kind
  matches nothing) — `json_extract` over `meta_json`.

### Added — Fingerprint / tool-identification confidence scoring
- `toolfp` now scores every identification with a `Confidence` (0-100,
  banded high/medium/low by `ConfidenceLabel`): a self-identifying
  User-Agent tool string or an in-clear SSH client banner or a JA3 hash
  match scores **high**; a tool inferred from a tool-specific request path
  (UA spoofed/absent) or automation from a missing/non-browser UA scores
  **medium**; automation inferred from a weak heuristic (browser UA but no
  Accept-* headers) scores **low**. The http/ssh handlers promote it to
  `tool_confidence` / `tool_confidence_label` event meta; the attacker
  profile surfaces the peak confidence, and `identify` prints it.

### Added — Web UI: service names, attacker-profile synthesis, sortable rules
- Event tables and the event-detail view now annotate destination ports
  with their well-known service name (`:22 ssh`, `:502 modbus`,
  `:9100 jetdirect/pjl`, …) via a new `internal/portsvc` lookup covering
  common IANA ports plus the ICS/OT and printer ports the honeypot emulates.
- Attacker profiles gained a synthesized **assessment**: a higher-level
  `Classification` (C2 / red-team framework, exploitation attempt,
  vulnerability scan, credential brute-force, reconnaissance / scanning,
  automated client, manual / unclassified) plus a one-line `Summary`
  (event count, time span, ports/services touched, peak severity, tools,
  credentials, CVEs). The profile also surfaces the reporting sensor(s).
- The "triggered rules" table on a profile is now sortable by rule name or
  count via `?rsort=rule|count&rorder=asc|desc` (server-side, so it works
  under the no-JavaScript CSP), with clickable column headers and a
  direction arrow.

### Added — C2 / red-team / headless-browser tool detection
- toolfp now recognizes C2 / red-team frameworks (Cobalt Strike, Mythic,
  Empire, Covenant, Sliver, Havoc, Brute Ratel, Metasploit, Core Impact)
  and headless-browser automation (Selenium, Puppeteer, Playwright, headless
  Chrome, PhantomJS), and classifies every identified tool into a coarse
  `Category` (`c2` / `vuln-scanner` / `headless` / `tool`). The http handler
  raises a `c2-framework` (ATT&CK T1071.001 / T1219) or `headless-browser`
  (T1595) anomaly accordingly. (SYN/connect port scanners like naabu /
  rustscan / nmap are caught by the packet-capture + scan-analysis layers.)

### Added — CLI: flags in any position + `reset-db`
- Global/subcommand flags may now appear **before or after** the
  subcommand: `tarpit-honeypot -c cfg.yaml run` and
  `tarpit-honeypot run -c cfg.yaml` are equivalent (the dispatcher locates
  the subcommand token, skipping flags and their values).
- New `reset-db` subcommand empties the local databases under `data_dir`:
  the event store by default, or `--devices` / `--captures` / `--payloads`
  / `--sessions` / `--state` / `--all`. Dry-runs unless `--yes`; identity
  (`.deployment-id`) and TLS certs are always preserved; `--data-dir`
  operates without loading a config.

### Docs — clarify that example-FULL/LARGE remap ports
- `example-FULL` (and `example-LARGE`) bind every service on high ports
  (20000+/10000+) so they run without root/port conflicts — so scanning the
  standard ports (22/80/443) hits nothing and only `sensor:*` lifecycle
  events appear, which surprised operators. Added a prominent header note
  ("scan the bound ports, not 22/80/443" + how to get the id→port map) and
  a troubleshooting entry; `example.yaml` binds real service ports for
  scan-and-watch demos. (No pipeline bug — events are recorded when a bound
  port is hit; the startup log already prints each `bind=`.)

### Fixed — web UI now auto-updates (live view during a scan)
- The web UI is server-rendered and its strict CSP forbids JavaScript, so
  it never refreshed on its own — during a port scan the page sat static
  until you reloaded (the footer literally said "refresh for latest"). It
  now emits an HTML `<meta http-equiv="refresh">` every
  `ui.refresh_seconds` (default **10s**, `0` disables) so the dashboard /
  events views update live. (The event→store→UI data path itself was fine;
  the gap was purely the missing auto-refresh.)

### Added — per-channel `enabled` toggle
- Channels accept `enabled: false` to stay **defined but off** — not built,
  not type-validated, so an outbound sink that needs external infra (an
  MQTT broker, a webhook secret, a SIEM collector) can ship in a config and
  stay dormant until turned on. `run` no longer aborts when a disabled
  broker/endpoint is unreachable. The bundled `example-FULL` and
  `example-ADVANCED-OT` configs now ship their MQTT / webhook /
  remote-syslog channels disabled, so every example runs standalone out of
  the box.

### Added — CWE / CPE / EPSS cross-references + attribution doc
- The CVE catalog records now carry **CWE** (weakness class), **CPE 2.3**
  (affected product) and **EPSS** (exploit-probability snapshot) alongside
  CVSS + the ATT&CK mapping. `cve:<id>` events stamp `cwe`/`cpe`/`epss` into
  meta; `list-cves` shows EPSS in the table and CWE/CPE/EPSS in `--json`.
- New [`docs/attribution.md`](docs/attribution.md) — an in-depth reference
  for every standards mapping the sensor stamps (ATT&CK, D3FEND, CVE, CWE,
  CPE, EPSS), the four scanner-detection layers (tool fingerprinting, nmap
  profiling, packet-capture scan detection, correlator aggregates), and the
  client classifiers (automation heuristic + JA3/JA4/JA3S/HASSH/JA4H). Linked
  from the docs index and the main README.

### Added — archeservice role bundles
- New `archeservices:` config section: declare a service *role* —
  `webserver`, `ftpserver`, `sshserver`, `printserver`, `fileserver`,
  `ldapserver`, `adserver`, `mailserver`, `dbserver`, `dnsserver`,
  `snmpserver`, `voipserver`, `remoteaccess` — and it expands at load time
  into the right listeners (correct ports + handlers). Combined with an
  `archetype:` it answers with that OS/device's software, banners, versions
  and TLS posture (e.g. `webserver` + `debian 12` → Apache; +
  `windows server 2019` → IIS; `printserver` + `hp-printer` → coherent
  PJL/IPP/LPD/SNMP). New `list-archeservices` subcommand + `internal/archeservice`.

### Added — vulnerability-scanner detection
- toolfp now classifies identified tools and sets `Verdict.Scanner` for
  vulnerability scanners (Nessus/Tenable, OpenVAS/Greenbone, Qualys,
  Nexpose/InsightVM/Rapid7, Acunetix, Nikto, Nuclei, sqlmap, …). The http
  handler raises a `vulnerability-scanner` anomaly (ATT&CK T1595.002 /
  T1190); the `tool:` prefix maps to active-scanning recon.

### Added — example configs + tests
- `configs/tarpit-honeypot.example-LARGE.yaml` (every handler enabled + all
  archeservice roles + all subsystems) and
  `configs/tarpit-honeypot.example-archeservices.yaml`.
- Unit / regression / coherence / compatibility tests: archeservice
  expansion + validation, every role's handlers are real, scanner
  detection, plus catalog coherence — every archetype that pins an HTTP
  Server header actually serves it, every printer's IPP reply carries its
  identity, and every archetype name resolves at runtime.

### Fixed
- `correlate.icmp_sweep` (and `dns.amplifier_detection`) could pass
  `validate-config` but crash `run` with `unknown severity ""` — they were
  enabled-but-not-defaulted and the correlator / dnscanary parse severity at
  construction time. Now defaulted in `applyDefaults`, validated in
  `Validate`, and `dnscanary.New` defaults defensively. (Surfaced by the
  example-LARGE config.)
- `archetype.Lookup` now resolves a profile's canonical Name and pretty
  DisplayName (not just registry-key variants), so a config naming an
  archetype the way `list-archetypes` prints it resolves identically at
  runtime instead of silently running with no archetype.

### Security — DoS / robustness hardening (audit findings batch)
- **DCE/RPC concurrent-map crash**: the endpoint-mapper interface set was a
  shared package var assigned into per-event meta; the listener sanitizes
  meta in place, so concurrent connections mutated the same maps → `fatal:
  concurrent map writes`. Now built fresh per request.
- **DNS post-dispatch map mutation**: dnscanary added honeynet A-resolution
  metadata to the event *after* sending it to async sinks, racing the
  sink's encode. Metadata is now complete before dispatch.
- **UDP reflection/amplification**: the coap / knx / ssdp / fins handlers
  could be used as spoofed-source reflectors. Added a global token-bucket
  reply rate-limiter plus stricter request validation (KNX declared-length
  + HPAI, SSDP requires MAN+ST); the sensor can no longer reflect
  meaningful bandwidth at a forged victim.
- **Unbounded reads**: the ssh and redfish handlers used `ReadString`
  (buffers a newline-less stream up to the deadline); both now read bounded
  lines. The PJL handler gained an absolute session deadline (anti-slowloris).
- **HTTPS cert-regeneration DoS**: rotation keyed on the (deliberately
  backdated) cert NotBefore, so any `tls_rotate.days` shorter than the
  backdate regenerated a key/cert on every connection. Rotation now keys on
  real creation time (cache timestamp / file mtime).
- **Unbounded per-source maps**: hard caps + sweeps added to the event
  dedup cache, the sniffer fragment rate-limiter, and the DNS amplifier
  tracker (all keyed by spoofable source IPs).
- **Goroutine/fd exhaustion**: the TCP accept-cap path no longer spawns a
  blocking goroutine per refused connection (synchronous close +
  non-blocking emit); a recovered handler panic now closes the conn + ends
  the capture session via deferred cleanup; the DNS canary bounds in-flight
  handler goroutines with a semaphore.
- **JA4 quadratic sort**: the cipher/extension sort over an
  attacker-controlled ClientHello was O(n²); now O(n log n).

## [v2.0.0] — 2026-05-21

Major release. Headline additions since v1.5: a full printer / multi-function
device deception + detection suite (PJL, IPP/CUPS, LPD handlers; PRET-aware
PJL with decoy filesystem; 11 printer/MFD archetypes); five offline CLI
inspection subcommands; passive OS fingerprinting; per-deployment webapp
honeytokens; SNMP-SET / DNS-zone-transfer / TFTP protocol-misuse detection;
and the catalog grown to 99 OS/device archetypes. See the entries below.

### Changed
- Default build version is now `2.0.0` (compiled-in fallback; release builds
  still derive it from `git describe`).

### Fixed
- Deterministic archetype catalog: the Active Directory, MikroTik and Cisco
  Catalyst archetypes registered several aliases with *different*
  `Profile.Name`s but one `DisplayName`, so `All()` / `Names()` /
  `list-archetypes` picked a nondeterministic canonical name. Each now uses
  one canonical name per device. `list-archetypes <canonical-name>` also
  resolves now (the `Find` resolver gained a Name fallback).
- Catalog integrity: added the CVEs the AD DC archetype advertised but the
  catalog was missing — ZeroLogon (CVE-2020-1472), PrintNightmare
  (CVE-2021-34527), noPac (CVE-2021-42278).

### Added — documentation & tests
- New [`docs/archetypes.md`](docs/archetypes.md): the full 99-archetype
  catalog with each device's services/protocols and emulated CVEs.
- New cross-package integrity tests: archetype name/DisplayName round-trip,
  archetype default-service handlers are all real, advertised CVEs all exist
  in the catalog, the CVE catalog is sorted/dup-free, and the MITRE coverage
  map is well-formed.
- A man page (`docs/tarpit-honeypot.1`).

### Added — 10 printer/MFD archetypes + richer emulation & detection
- **10 new printer/MFD archetypes** (ship total 99): Brother, Canon
  imageRUNNER, Epson WorkForce, Xerox VersaLink, Lexmark, Ricoh, Konica
  Minolta bizhub, Kyocera ECOSYS, Sharp, and a Zebra ZT411 label printer.
  Each carries the vendor EWS Server header + title, SNMP enterprise OID +
  sysDescr, MAC OUI, a believable web status page (toner/drum levels, page
  count), and the full MFD service set (9100/631/515/161/80/443; Zebra is
  9100/80/161). Xerox/Lexmark/Kyocera advertise a real (advisory) device CVE.
- **IPP emulation is archetype-aware** — the IPP reply now takes its
  printer-name / make-and-model from the bound archetype (so IPP, SNMP and
  the web UI agree) and advertises a fuller, more believable attribute set
  (printer-uuid, dns-sd-name, document-format-supported, media-default,
  toner `marker-levels`, queued-job-count, color-supported).
- **PJL filesystem deception** — FSDIRLIST / FSUPLOAD / FSQUERY now return a
  believable fake directory tree + file contents so PRET's `ls`/`get`/`fuzz`
  keep walking the decoy filesystem (nothing real behind it).
- **More PJL/printer attack detection** — PJL `ENTER LANGUAGE=` language
  switch (`printer-language-switch`), service-mode access
  (`printer-servicemode`), firmware upgrade (`printer-firmware-upload`), and
  **ZPL** (Zebra) + PCL job recognition (`printer-zpl-job` /
  `printer-zpl-config` / `printer-pcl-job`). New ATT&CK/D3FEND rows
  (T1601, T1212).

### Added — broad printer / MFD attack detection (PJL · IPP/CUPS · LPD)
- **PJL handler (9100) rewritten as an interactive responder** — the channel
  PRET drives. Answers many more `@PJL INFO` recon categories (VARIABLES,
  FILESYS, MEMORY, PAGECOUNT, USTATUS, …) believably and flags a broad set
  of abuse: panel defacement (`printer-rdymsg-set` / `printer-message-injection`),
  filesystem access + the destructive `FSINIT` format (`printer-filesystem-access`
  / `printer-filesystem-format`), path traversal (`printer-path-traversal`),
  config + password writes (`printer-config-set` / `printer-password-set`),
  credential reads (`printer-credential-access`), PJL job passwords
  (`printer-auth-attempt`, captured), NVRAM + device-management commands, and
  embedded **PostScript** abuse in the job stream — `serverdict`/`exitserver`
  persistence, file ops, `set*params`, raw `%disk%`/`%os%` device access.
  Nothing prints; no real filesystem/NVRAM is touched.
- **IPP handler (631) gains CUPS attack detection** — names the IPP operation,
  flags printer-admin / job-injection / server-fetch ops (`printer-ipp-admin-op`),
  the foomatic-rip RCE primitive (`printer-cups-rce` + a live `cve:CVE-2024-47177`),
  and command-injection metacharacters in printer/device attributes
  (`printer-ipp-cmd-injection`). Catalog gains the Sept-2024 CUPS chain
  (CVE-2024-47177 detectable; 47076/47175/47176 advisory).
- **New `lpd` handler (LPD, TCP 515)** — acknowledges the command so a client
  sends its control file, captures the queue + control metadata, and flags
  shell-metacharacter injection (`printer-lpd-injection`), overlong fields
  (`printer-lpd-overflow`), and path traversal. Wired into the `hp-printer`
  archetype (now advertises 9100/631/515/161/80/443) + the FULL example.
- All printer markers carry ATT&CK + D3FEND mappings (T1485/T1491/T1098/
  T1552/T1005/T1059/T1190 + a `printer-` discovery prefix fallback).

### Changed — webapp decoy secrets are now per-deployment honeytokens
- The fake-vulnerable webapp's `/.env` and config-backup loot no longer use
  static strings (`Tr4pP3d-D3c0y-2024` / `decoy-not-a-real-secret`) — those
  were a literal fingerprint that let a scanner grep-match every
  tarpit-honeypot. Secrets (DB password, Laravel `APP_KEY`, an `AKIA…` AWS
  access key + secret, app `SECRET_KEY`) are now derived deterministically
  from the deployment identity: unique per sensor, stable per sensor. The
  served DB password is stamped on the event meta as `honeytoken`, turning
  the decoy into a trackable canary a SOC can watch for in real auth logs.

### Added — passive OS fingerprint (TTL) device learning
- The AF_PACKET scan-detector now reads the source IPv4 **TTL** and stamps
  `ip_ttl` + an `os_guess` (linux/unix · windows · network/embedded) with an
  estimated `ttl_hops` onto its scan / fragment events. The device registry
  learns `os_guess` as a per-device attribute (visible in `list-devices
  --json`, `/api/devices`, and the devices web-UI tab), so the inventory
  gains an OS family for hosts seen only on the wire. Best-effort, passive.

### Added — protocol-misuse detection on SNMP / DNS / TFTP
- **`snmp-set-attempt`**: the SNMP handler now flags an SNMP `SetRequest`
  (a config *write* — flip an interface, rewrite an ACL, trigger a config
  copy-to-TFTP) and captures the target OIDs + intended values. The write
  is never applied (we don't even reply). High-signal across every
  SNMP-advertising archetype (switch / PLC / printer / camera). ATT&CK
  T1565.001 / T0836.
- **`dns-zone-transfer`**: the DNS handler flags AXFR/IXFR (qtype 251/252)
  zone-transfer requests — bulk host enumeration against a misconfigured
  authoritative server / DC. ATT&CK T1590.002 / T1018.
- **`tftp-write-attempt`** + **`tftp-config-read`**: the TFTP handler flags
  WRQ uploads (firmware/config push) and RRQ of device-config / firmware
  filenames (`running-config`, `*.cfg`, `*.bin`, Cisco `network-confg`, …).
  ATT&CK T1105 / T1602.001. New D3FEND rows: T1565, T1590, T1602.

### Added — five read-only inspection subcommands (offline catalog/triage)
- **`list-archetypes`** [`<name>`]: dump the device/OS archetype catalog, or
  one archetype's full fingerprint (banners, SNMP identity, ICMP TTL,
  advertised CVEs, default services). `--json` for machine output.
- **`list-handlers`** [`--proto tcp|udp`]: the protocol handlers valid in a
  listener's `handler:` field, sourced from the same whitelist the config
  validator enforces (the maps were lifted to package scope so the two can
  never drift).
- **`list-cves`** [`--service`]: the CVE catalog, marking which records are
  recognized as live exploit attempts vs advisory-only.
- **`list-techniques`** [`--kind`]: the static MITRE ATT&CK → D3FEND coverage
  map (rule / handler / anomaly), for coverage audits + navigator layers.
- **`identify`**: run the offline fingerprint engine over a supplied
  User-Agent / path / SSH client id / JA3 / payload and print the verdict
  (tool, automation flag, CVE matches) — a log-triage / detection-tuning aid.
- Shell completions (bash/zsh/fish) + `help` topic docs updated for all of
  the above (and the previously-undocumented `list-devices`). New exported
  accessors: `archetype.All`/`Find`, `cve.All`/`Record.Detectable`,
  `mitre.Coverage`, `config.TCPHandlerNames`/`UDPHandlerNames`.

### Added — PJL (printer) + Beckhoff ADS handlers (archetype protocol gaps)
- **`pjl`** (TCP 9100): HP JetDirect PJL responder — answers `@PJL INFO`
  queries with a printer identity, captures jobs/commands, flags ready-
  message defacement + filesystem access. Wired into the `hp-printer`
  archetype (was a `raw` placeholder).
- **`ads`** (TCP 48898): Beckhoff ADS/AMS responder — parses the AMS header,
  answers Read-Device-Info with a TwinCAT identity, flags `ics-ads-probe`.
  Wired into the `beckhoff-cx` archetype (was `raw`). Both ATT&CK-tagged.

### Added — device classification + larger CVE catalog
- **Device classification**: each learned device now gets an inferred
  `class` attribute (scanner / ics-endpoint / network-device / web-host /
  host) from the services + ports it touched, sharpening over time
  (`devices.classify`).
- **CVE catalog ~30 → ~40**: added Confluence 22518, Cisco IOS-XE 20198,
  PHP-CGI 4577, TeamCity 42793, ManageEngine 40539, Ivanti 21887, and ICS
  advisory records for Siemens S7 (CVE-2020-15782) and Rockwell Logix
  (CVE-2023-3595 / 2021-22681 / 2022-1161).

### Added — 8 more OT/ICS device archetypes (ship total 89)
- **ABB**: AC500 PLC (CODESYS), S500 remote I/O (CI502 PROFINET), RTU560
  substation RTU (IEC 104 + 61850 MMS).
- **Honeywell**: ControlEdge 900 PLC/RTU, Experion C300 DCS controller.
- **Siemens PN/PN Coupler** (PROFINET-to-PROFINET).
- **WAGO 750-8212 PFC200** (CODESYS Linux PLC) and **Beckhoff CX9020**
  (TwinCAT, ADS/AMS) — each with vendor MAC OUI + realistic service map.

### Added — IEC 61850 MMS handler + GOOSE detection
- **`mms`** (TCP 102): IEC 61850 MMS responder for substation IEDs — completes
  the COTP CR→CC handshake, captures the ACSE/MMS Initiate (association)
  request, replies with a believable AARE accept, flags `ics-mms-probe`.
  Distinct from S7comm on the same port. ATT&CK T0888/T0814.
- **`sniffer.goose`**: passive IEC 61850 **GOOSE** detection on a dedicated
  AF_PACKET socket (ethertype 0x88B8) — parses APPID + gocbRef/goID/stNum/
  sqNum and emits `sniffer:goose` (rate-limited per source MAC). ATT&CK
  T0888. New `internal/sniffer` GOOSE parser + config `sniffer.goose`.

### Added — more toolfp client/scanner signatures
- PowerShell web cmdlets (Invoke-WebRequest/RestMethod, pwsh), more recon
  (SecurityTrails, driftnet, alphastrike), and param-discovery tooling
  (arjun, paramspider, kiterunner, x8, httprobe).

### Added — broader ATT&CK / D3FEND / CVE attribution
- **Anomaly-level ATT&CK attribution**: the router now unions the techniques
  implied by an event's anomaly markers into the rule_id/handler base tag
  (`mitre.Augment`), so finer detections get precise IDs even on a generic
  handler event — `webapp:sqli`/`lfi`/`rfi_ssrf`/`log4shell`/`xxe` → T1190,
  `webapp:xss`/`cmdi`/`ssti` → T1059(.007), `modbus-write-attempt` → ICS
  T0836/T0831, `default-credential-attempt` → T1078.001,
  `smtp-open-relay-probe` → T1071.003, `uri-*` → T1595.003/T1083, `ics-*`
  → T0888.
- **ATT&CK for all the new handlers**: atg/fox/hartip/pcworx (T0888),
  redfish/vmware_authd/rlogin/nx/x11 (auth + lateral-movement), mssql/
  oracle_tns/ftp_files, teamviewer/anydesk (T1219), openvpn/citrix_ica
  (T1133), and the vendor management-web UIs (T1190). New `device:changed`
  → T1557.002.
- **D3FEND** entries for the new techniques (T1059, T1056, T1219, T1133,
  T0836, T0831).
- **CVE catalog grown ~18 → ~30**: added WebLogic (CVE-2017-10271 /
  2020-14882), Telerik (2019-18935), Laravel Ignition (2021-3129),
  Confluence OGNL (2021-26084), Tomcat PUT (2017-12615), Apache 2.4.50
  (2021-42013), MOVEit (2023-34362), Follina (2022-30190), vSphere
  (2021-21972), D-Link NAS (2024-3273), GPON (2018-10561), Hikvision
  (2017-7921), FortiOS auth-bypass (2022-40684), plus advisory-only records
  (OpenSSH user-enum 2018-15473, Cisco Smart Install 2018-0171) so
  archetype-advertised CVEs carry a technique.

### Added — device:changed rebind detection + more snooped attributes
- **`device:changed`** event: a known device's IP/MAC/hostname rebinding
  (ARP-spoof / impersonation / re-IP) is now detected and alerted
  (`devices.ObserveResult.Changed`), distinct from `device:new`.
- More snooped device attributes from event meta: SMTP HELO, DHCP vendor
  class, OS hint, realm/domain, and the last service touched.

### Added — per-language HTTP client / framework detection (toolfp)
- Detect wget/curl plus the common HTTP client libraries across python,
  perl, go, java/jvm, c/c++, .NET, and rust, plus more recon tooling.

### Added — richer device learning + a devices web-UI tab
- **More learning sources**: broadcast/multicast discovery (SSDP / LLMNR /
  NBNS / mDNS / CLDAP / CoAP senders) now register as `broadcast` devices,
  alongside the existing DHCP / ARP / connection learning.
- **Knowledge accrues over time**: each `devices.Device` now accumulates the
  sensor ports + services it touched and free-form attributes other
  listeners contribute (JA3/JA4/HASSH, SSH client, User-Agent, identified
  tools, automation) — extracted from event meta in the sensor bus.
- **Devices web-UI tab** (`/devices`, replacing/expanding `hosts`): shows
  the learned services/ports + attributes per device, filterable; source
  IPs link to their attacker profile. JSON at `/api/devices`.
- **Opt-in device delete / whitelist actions** in the UI: gated behind a new
  `ui.allow_device_actions` flag AND the UI auth token (the only write
  endpoint; off by default, so the read-only invariant holds unless
  explicitly enabled). Whitelisting persists via `Device.Allowed` in
  `devices.json`. New `Registry.Delete` / `Registry.Allow`.

### Added — more tool / scanner identification
- Another ~40 toolfp signatures: recon engines (Rapid7, Tenable, Detectify,
  Netcraft, Cortex Xpanse, modat), scanners/fuzzers (rustscan, naabu,
  testssl, sslyze, dalfox, gospider), HTTP clients (httpie, Postman, deno,
  bun), more named-CVE probe paths, and SSH clients (twisted-conch, erlang).

### Added — 23 more industrial-device archetypes (ship total 81)
- **More Moxa**: EDS-405A, EDS-G516E (gigabit, MRP), NPort 5650-8, AWK-3131A
  wireless AP, MGate MB3180 Modbus gateway.
- **Westermo (WeOS)**: Lynx, RedFox, Viper (EN50155 rail), Merlin-4400
  cellular router, Ibex wireless.
- **More Teltonika**: RUT955 (GPS), RUTX11, RUT956, TRB140.
- **More industrial switch vendors**: Hirschmann RS20 / RSP35 (HiOS) /
  EAGLE20 firewall, Phoenix Contact FL SWITCH 2008 / FL MGUARD, Advantech
  EKI-5528 — each with the correct vendor MAC OUI + SNMP enterprise OID.
- **Cisco industrial**: Industrial Ethernet 2000 (IOS), Catalyst IE-3400
  (IOS-XE), IR1101 industrial router.
  All carry realistic banners, SNMP identity, MAC OUI, ICMP TTL, and
  default-service maps; guarded by `TestIndustrialArchetypeFields`.

### Added — web UI dashboard charts, full-text search, payload hex view
- **Dashboard** (summary page): an events-per-hour trend sparkline plus
  severity / top-rule / top-source CSS bar charts (no JavaScript — bars are
  styled divs, CSP-safe). Backed by `store.EventsPerHour`.
- **Full-text search** on the events tab (`?q=`): a substring match over
  rule_id / banner_sent / captured meta (`store.Filter.Text`), preserved
  across column sorts.
- **Payload hex view**: event detail now renders an offset/hex/ASCII dump
  of the captured payload (base64 still available behind a details toggle).

### Added — 5 more remote-access / out-of-band management protocols
- **`vmware_authd`** (TCP 902): VMware Authentication Daemon banner +
  FTP-style USER/PASS capture (ESXi / Workstation management agent).
- **`redfish`** (TCP 443/8000): BMC Redfish REST API — serves the
  unauthenticated service root, demands Basic auth below it, captures
  credentials (iLO / iDRAC / XCC / Supermicro OOB).
- **`x11`** (TCP 6000): X11 display server — parses the setup request,
  captures the auth-protocol name, returns a Failed setup; flags an exposed
  X server (keylog/screen-capture risk).
- **`rlogin`** (TCP 513): BSD rlogin — captures the NUL-separated client/
  server user + termtype and the password prompt.
- **`nx`** (TCP 4000): NoMachine NX server banner + client-hello capture.
  All registered, validated, fuzzed, and tested.

### Added — web UI "attacker profiles" tab
- New **`/profiles`** tab + **`/profiles/<ip>`** detail (and `/api/profiles`,
  `/api/profiles/<ip>`): a per-source-IP threat-actor dossier compiled from
  every event the source produced and built up over time —
  first/last seen, a severity-weighted **threat score** + level, identified
  **tools/scanners**, **JA3/JA4/HASSH** fingerprints, **credentials tried**,
  **ATT&CK** techniques/tactics, **CVE** exploit attempts, anomalies, and
  the services/ports targeted, plus recent events. The list (cheap GROUP BY
  via `store.SourceAggregates`) ranks actors by threat; the detail view
  (`ui.buildProfile`) scans that actor's events. Summary top-sources now
  link to the profile.

### Added — 4 more OT/ICS protocols
- **`atg`** (Veeder-Root TLS-350, TCP 10001): the "internet-exposed gas
  pump" target — answers `^A I20100/I20200/I20300` with a believable
  per-deployment tank report, captures the command. Report-only.
- **`fox`** (Niagara / Tridium Fox, TCP 1911): Shodan's `fox` probe —
  emits a per-deployment "fox hello" (station name / host id / app+VM+OS
  versions / brand), captures the follow-up.
- **`hartip`** (HART-IP, TCP 5094): parses the 8-byte header, captures the
  message type, replies with a valid response header.
- **`pcworx`** (Phoenix Contact PCWorx, TCP 1962): captures the
  connect/identify probe, returns a model + firmware identification frame.
  All four added to the end-to-end handler fuzz harness.

### Added — much broader tool / scanner identification
- Expanded `internal/toolfp` from ~25 to ~80 User-Agent + request-path
  signatures: recon engines (Shodan, BinaryEdge, LeakIX, Onyphe,
  Shadowserver, Stretchoid, ProjectDiscovery, …), web vuln scanners
  (Acunetix/Nessus/OpenVAS/Qualys/Netsparker/AppScan/Arachni/Wapiti/
  WhatWeb/OWASP-ZAP/Burp/commix/XSStrike), fuzzers (ffuf/dirsearch/
  katana/httpx/wfuzz), brute-forcers (medusa/ncrack/patator), frameworks +
  webshell managers (Cobalt Strike/AntSword/Behinder/Godzilla), and many
  HTTP libraries. Path signatures now flag named-CVE probes (Log4Shell,
  PHPUnit, FortiOS, WebLogic, Citrix/Pulse/Exchange/Confluence).
- New `IdentifySSH`: classifies the clear-text SSH client banner
  (libssh/hydra, libssh2, paramiko, Go, PuTTY, zgrab, JSch, phpseclib, …),
  wired into the `ssh` handler → `meta.tools` + `tool:<name>`.

### Added — outbound channels: syslog/TLS, Discord, MQTT/TLS options
- **syslog `network: tcp` / `network: tls`** now use an RFC 5424 message
  with RFC 6587 octet-counting framing (the framing RFC 5425 mandates for
  syslog over TLS), with reconnect-on-failure (`internal/sink/syslog_stream.go`).
  TLS verifies against the system roots unless `ca_cert_file` /
  `tls_insecure` / `tls_server_name` are set. Cross-platform (the stream
  sink builds on Windows too; only local/udp/unix need the unix stdlib).
- **`discord` channel**: posts a severity-colored embed to a Discord
  incoming-webhook `url` (or `url_env`). Embeds suppress @mentions and meta
  is sanitized, so a captured payload can't ping a channel.
- **MQTT TLS options**: `tls://` brokers now honor `ca_cert_file` /
  `tls_insecure` / `tls_server_name`.
- New shared channel fields: `url_env`, `tls_insecure`, `ca_cert_file`,
  `tls_server_name`.

### Added — full fake-vulnerable web application (`webapp: true`)
- Setting `webapp: true` on an `http`/`https` listener serves a believable
  multi-page PHP/MySQL-flavored app (`internal/listener/handler/vulnweb.go`):
  login, search, product, file download, a JSON API, and the juicy paths
  scanners probe (`/.env`, `/.git/config`, `/config.php.bak`, `/robots.txt`,
  `/phpinfo.php`, `/admin`). Every request is classified for the web-attack
  families — SQLi, XSS, LFI, RFI/SSRF, command injection, SSTI, Log4Shell,
  XXE, insecure deserialization — and flagged as `webapp:<class>`; nothing
  is ever executed. Active deception: LFI toward `/etc/passwd` and `/.env`
  return fake "loot" (decoy creds) to draw the attacker deeper, and a SQLi
  login/parameter gets a fake MySQL syntax error. Reflected input is always
  HTML-escaped, so the honeypot is never itself a real reflected-XSS vector.
  Works over plain HTTP and TLS (the https handler shares the code path).

### Added — Lua `time` API + 6 new dynamic interaction scripts
- New sandboxed `time` API (`time.now`/`time.ms`/`time.utc`/`time.uptime`)
  so Lua scripts can emit live timestamps, TTLs, and uptime counters.
- Eleven new shipped scripts in `configs/scripts/` demonstrating counters,
  timestamps, uptime, and rotating banners: `redis-mini` (dynamic INFO with
  live uptime + per-source client counter), `memcached-stats` (live `stats`
  + cmd_get counter), `smtp-greeting` (RFC822-dated 220 banner),
  `telnet-switch` (per-source command counter + live uptime),
  `pop3` (live APOP timestamp challenge), `finger` (recon capture),
  `http-status` (live JSON health page + request counter), `irc` (botnet-C2
  NICK/USER/PASS/JOIN capture), `whois`, `ident` (stable per-source user),
  and `rsync` (module-enumeration capture).

### Added/Changed — richer existing-protocol support
- **SSH server `KEXINIT` + HASSH-server** (`ssh_kex.go`): the `ssh` handler
  now pipelines its own `SSH_MSG_KEXINIT` right after the banner, exactly as
  real OpenSSH does. The advertised algorithm set is derived from the
  version banner (modern OpenSSH / legacy / Dropbear) so the **server
  HASSH** is realistic and version-consistent — previously "banner then
  silence" was a honeypot tell. Recorded as `hassh_server`; the bogus
  "Protocol mismatch." trailer was dropped.
- **Modbus write detection + fuller function set**: write function codes
  (5/6/0F/10/15/16/17) now raise the `modbus-write-attempt` anomaly
  (control-process manipulation, ATT&CK for ICS T0836/T0831). Added
  believable responses for FC 0x16 (Mask Write Register) and 0x17
  (Read/Write Multiple Registers) so the Modicon persona supports its real
  function set.

### Added — declarative fake-protocol handler (`scripted`)
- **`handler: scripted`** (`internal/listener/handler/scripted.go`): stand up
  a believable custom TCP service entirely in YAML — no Lua. The `scripted:`
  block defines an optional on-connect `greeting` and top-down `rules` that
  match each client message by `prefix` / `contains` / `regex` (RE2, no
  catastrophic backtracking) / `hex_prefix` / `any`, then write a `respond`
  (text with `\r \n \t \0 \xHH \\` escapes, or `respond_hex` for binary),
  with optional per-rule `anomaly` flag and connection `close`. A `default`
  reply covers misses. Bounded `max_rounds` (≤64) + 64 KB per-reply cap +
  16 KB transcript cap; TCP-only so it can never be a spoofed-source
  amplifier. The spec is fully validated at config-load (`ScriptedProto`)
  and recompiled at handler build. FULL example: a fake memcached text
  service (`tcp-scripted-memcached`). Added to the end-to-end handler fuzz
  harness.

### Added — 12 appliance archetypes + richer per-archetype service params
- **12 new archetypes** (`internal/archetype/appliances.go`), bringing the
  ship total to **58**: pfSense + FortiGate firewalls, Synology + QNAP NAS,
  Hikvision + Axis IP cameras, Ubiquiti EdgeRouter, Allen-Bradley
  ControlLogix / Schneider Modicon / Omron PLCs, an HP LaserJet, and an
  Asterisk/FreePBX VoIP box. Each carries the vendor `Server` banner, SSH
  banner, SNMP identity, MAC OUI, ICMP TTL, and default-service map a
  scanner keys on; FortiGate + Hikvision present their signature CVEs
  (CVE-2018-13379 / CVE-2017-7921) as advisory unpatched markers.
- **Richer per-archetype service fingerprints** (consumed by handlers):
  - `httpHeaders` — extra HTTP response headers (vendor `Set-Cookie`,
    custom `WWW-Authenticate` realm, `X-Powered-By`, …) injected by the
    `http`/`https` handler.
  - `ftpFeatures` — the FTP `FEAT` set; the `ftp` handler now answers
    `FEAT`/`SYST` in a bounded command loop (vsFTPd default; Synology/QNAP
    expose MLST/MLSD).
  - `smtpExtensions` — ESMTP keywords in the multiline `EHLO` reply
    (Postfix-style default). Also fixed a consistency tell: `EHLO` echoed a
    hardcoded `mail.example.com` regardless of the greeting host.

### Added — operational alarms (lifecycle / health / first-seen / digest)
- `sensor:started` / `sensor:stopped` lifecycle events; `sensor:health`
  (data_dir disk usage past `disk_warn_percent` with hysteresis, and sink
  drop counts) — both always on. Opt-in `source:first_seen` (a source's
  first >= medium event, deduped + capped) and `sensor:digest` (periodic
  summary: totals by severity, top rules, top risk sources). Config under
  `sensor.alerts`.

### Added — per-source risk scoring
- **`risk:`** (`internal/risk`): a decaying per-source threat score. Every
  event adds severity- and category-weighted points to its source (CVE /
  malware / storyline weigh heaviest); the score halves over `half_life`
  of silence. Crossing a threshold emits `risk:elevated` / `risk:high` /
  `risk:critical` (once per escalation, with `score` + `trigger_rule` in
  meta), and the top scorers are exposed for the web UI. Concurrency-safe,
  bounded, GC'd.

### Added — end-to-end handler fuzzing (+ 2 parser bugs fixed)
- `FuzzTCPHandlers` / `FuzzUDPHandlers` drive every registered protocol
  handler's `Handle()` end-to-end with arbitrary bytes via an in-memory
  conn/packet-conn (selector byte multiplexes the ~50 TCP + 24 UDP
  handlers). Added `FuzzJA3S` for the new ServerHello parser. ~3M+ execs
  across the suite found two off-by-one slice panics, now fixed with the
  crashers committed as regression seeds:
  - **nbns** (UDP 137): `parseNBNSQuery` guarded `len < 12` but indexed
    `msg[12]` — a 12-byte datagram panicked the handler.
  - **mqtt** `readMQTTString`: no negative/overflow guard on the offset →
    `slice bounds out of range [:-N]`.
  (Both were recovered per-packet in production, but are now hard-fixed.)

### Fixed — security audit, round 2 (concurrency + secret hygiene)
- **Reload data race**: `Reload()` hot-swapped `cfg`/`router`/`correlator`/
  `sinks` with no lock while the bus loop, save ticker, shutdown, and the
  public accessors read them. All four are now guarded by an `RWMutex`
  (swap takes the write lock; readers snapshot under the read lock).
  Added a `-race` regression test; `go test -race ./...` is clean.
- **VNC / SMB challenges** are now fresh per-connection `crypto/rand`
  nonces (what a real server sends) instead of a deployment-static value
  — a static challenge was itself a fingerprint and enabled
  precomputed/replay attacks on the captured response.
- **SNMP-trap community**: added `community_env` so the trap write
  credential can come from an env var instead of inline YAML (kept out of
  `show-config`). Documented that remote `syslog` is cleartext.
- **capture prune race**: the pcap-pruner now serializes on the manager
  mutex so concurrent session-ends can't over-delete / double-count.
- **privdrop**: clear root's supplementary groups even when dropping uid
  without a resolved target gid. **UI**: 500s return a generic message and
  log the detail (no DB-path disclosure). Removed dead `crypto/rand` call
  in `identity.SerialNumber`.

### Added — detection coverage: password spraying + credential reuse
- **`correlate:password_spray`** (`correlate.password_spray`): one source
  trying many DISTINCT usernames within a window — the breadth signal,
  complementing brute_force's depth. ATT&CK T1110.003.
- **`correlate:credential_reuse`** (`correlate.credential_reuse`): the same
  credential pair attempted from many DISTINCT source IPs — a shared
  credential list / botnet (credential stuffing). ATT&CK T1110.004. The
  emitted event reports the username + source count but never the password.
- Both reuse the existing credential extraction across handlers (HTTP/SSH/
  FTP/LDAP/DB/...), are windowed + deduped like the other correlators, and
  cap their per-key sets to bound memory.

### Added — categorized example configs + EXAMPLES.md
- New example configs under categorized `examples/` subdirectories mapped to
  the OT Purdue model: `ot-cell/single-plc.yaml`,
  `ot-client-network/operator-and-engineering-ws.yaml`,
  `ot-server-network/historian-appservers-ad-fileserver.yaml`,
  `ot-dmz/dmz-historian-fileserver-jumphosts.yaml`, plus
  `edge/mikrotik-router.yaml` and `edge/teltonika-rut240.yaml` showcasing
  the new archetypes. Each is a complete, validated config.
- **`EXAMPLES.md`**: an extensive walkthrough of every example — what it
  models, the Purdue-level mapping, per-file adaptation notes, and how to
  combine configs (`-c` × N), use `conf.d/`, pick an interface (`-i`), and
  `--set`/env overrides.

### Added — web UI pcap / session retrieval
- The web UI can now download recorded artifacts: `/pcap/<event-id>` serves
  the per-connection capture, `/session/<event-id>` serves the asciinema
  session cast, and `/download?source=<ip>&rule=&since=&what=pcap|session|all`
  streams a ZIP of every matching event's pcaps + casts — so "all attacks
  from 198.51.100.42" is one click. The event-detail page links its pcap +
  session and an "all from this IP" bundle; the events list links a
  filter-scoped bundle. Paths are validated (hex event ids, basename-only
  cast names) against traversal; routes go through the existing UI auth.

### Added — interface selection + multiple config files
- **`sensor.interfaces`** (+ `-i`/`--interface` CLI, repeatable): name the
  network interface(s) the sensor uses. It supplies the default interface
  for the AF_PACKET layer (sniffer + honeynet ARP/ICMP/LLDP/PROFINET
  responders) when those sections don't set their own, and pins
  wildcard-bound listeners (`0.0.0.0`/`::`) to the first interface's
  primary IP. `-i` overrides the config list.
- **Multiple `-c` config files**: `run`, `validate-config`, and
  `show-config` accept `-c` repeatedly and COMBINE the files — top-level
  lists (listeners, honeynets, channels, ...) are appended so every host
  across all files is used, while scalar config takes the later file's
  value (`config.LoadManyWithOverrides`). A single `-c` is unchanged;
  per-file `conf.d/` keeps its override (replace-lists) semantics.

### Added — OPC-DA emulation (dcerpc / OPCEnum)
- The `dcerpc` handler now recognizes the OPC-DA (classic, DCOM) interface
  family — OPCEnum, IOPCServerList(2), IOPCServer/Browse/ItemMgt — plus the
  common Windows MSRPC interfaces, labelling each bind with
  `dcerpc_interface`. A bind to an OPC interface flags `ics-opc-da-probe`
  and advertises believable OPC-DA server ProgIDs (`opc_servers`). The
  endpoint mapper now always advertises OPCEnum (`epm_interfaces`) so a
  scanner walking port 135 records an OPC-DA server present. (Full DCOM
  IOPCServer call marshaling remains out of scope.)

### Added — fake web shells + new device archetypes
- **Fake web shells** (`internal/listener/handler/webshell.go`): the HTTP
  handler now recognizes web-shell activity — known shell filenames
  (c99/r57/wso/b374k/China-Chopper-style) and command parameters
  (`?cmd=`, POST `cmd=`, ...) — and always captures + flags it
  (`webshell-access-attempt`, `webshell-command`, `webshell_cmd` meta).
  When `vuln_emulation` is on it actively serves a believable fake shell
  whose command output comes from the canned shell emulator
  (`shell.OneShot`, archetype-aware) — never executed. TTP markers from
  the command (wget/reverse-shell/shadow-read) are flagged too.
- **New archetypes**: Cisco Catalyst switch (2960 + Catalyst-9300), MikroTik
  RouterOS, Teltonika RUT240 — see the archetype table in the README.

### Added — PROFINET-DCP responder (L2 ICS discovery)
- **`honeynets[].profinet_responder`** (`internal/honeynet`): answers
  PROFINET Discovery and Configuration Protocol (DCP) **Identify** requests
  on the raw L2 segment (EtherType 0x8892) for virtual industrial hosts, so
  a PROFINET scan (Siemens PRONETA / TIA Portal / nmap) enumerates a
  populated cell — NameOfStation, DeviceVendor, Device ID, Device Role, and
  IP parameters per station. Stations come from each host's archetype
  PROFINET device tree (SCALANCE-class) or the host itself for industrial
  archetypes. Because a DCP Identify is itself strong ICS reconnaissance,
  every request raises `honeynet:profinet_dcp_identify` (ATT&CK **T0846**,
  ICS Remote System Discovery). Linux + CAP_NET_RAW; identify-all and
  name-filtered requests both handled. (OPC-DA over DCOM/MSRPC remains out
  of scope.)

### Added — TCP/IP stack personality (TUN responder)
- The honeynet TUN adapter (`internal/tunnet`) now stamps each virtual
  host's synthesized **ICMP echo replies and closed-port RSTs** with the
  initial IP TTL of that host's archetype (64 Linux / 128 Windows / 255
  OT), derived automatically from the host's `archetype:`/`os:`. Replies
  previously echoed the prober's TTL, which both leaked the honeypot and
  produced an inconsistent OS guess; now `nmap -O` + traceroute
  hop-distance line up with the claimed OS. Open-port SYN-ACKs still come
  from the host kernel stack (a full userspace TCP/IP stack is out of
  scope). V4 response builders extracted as pure, unit-tested functions.

### Added — packet-capture scan-detection layer
- **`sniffer.tcp_scan`** (`internal/sniffer`): a second AF_PACKET socket
  (inbound IPv4) classifies TCP segments by flags and detects scans that
  never establish a session — **NULL/FIN/Xmas** stealth probes (flagged at
  a low distinct-port threshold), **SYN/ACK** scans (flagged by volume),
  and fragmented probes. New events `sniffer:tcp_{syn,null,fin,xmas,ack}_scan`
  and `sniffer:ip_fragmented`, ATT&CK-tagged T1046 / T1595.001. Opt-in,
  needs CAP_NET_RAW; the ARP path is unchanged. (Decoy-scan detection is
  out of scope; ICMP sweeps remain handled by `correlate:icmp_sweep`.)

### Added — server-side TLS fingerprint (JA3S)
- **JA3S** (`internal/fingerprint`): the HTTPS handler now captures the
  ServerHello it sends and emits the server-side TLS fingerprint in event
  meta (`ja3s`, `ja3s_raw`), complementing the existing client-side JA3 /
  JA4. The `(ja3, ja3s)` pair is the tuple TLS threat-intel feeds key on.
  (Active multi-probe JARM — the Shodan/Censys-style server fingerprint —
  is a larger separate item and is not implemented here.)

### Added — more ICS/OT protocols
- New handlers: **DNP3** (TCP 20000, link-status responder with valid DNP3
  CRC), **S7comm-Plus** (TCP 102, S7-1200/1500 over TPKT/COTP, classifies
  S7comm-Plus vs classic S7comm), **GE-SRTP** (TCP 18245, GE/Emerson
  PACSystems), **CODESYS** (TCP 1217 V3 gateway). **BACnet WriteProperty**
  is now acknowledged (SimpleACK) and flagged (`bacnet-write-attempt`).
  ATT&CK-tagged (T0814/T0888). (PROFINET-DCP (L2) and OPC-DA still pending.)

### Added — Lua dynamic responses + session recording + durable correlator
- **Lua dynamic-response engine** (`handler: lua`, `internal/luaengine`):
  operator scripts drive a service in a sandboxed pure-Go gopher-lua VM
  (no io/os, context deadline + read/write/sleep budgets). Per-service
  scripts, per-session + per-source `host` state, `personality()`
  (stable hostname/version/firmware per source), deterministic `rng`
  (seeded from deployment_id), `sleep` timers, dynamic banners, and
  `log`/`flag`/`meta`. Example `configs/scripts/iot-login.lua`.
- **Attacker session recording** (`sensor.session_recording`,
  `internal/sessionrec`): interactive `telnet` / `ssh_interactive`
  sessions saved as replayable asciinema v2 casts under
  `<data_dir>/sessions/`; cast filename recorded in event meta.
- **Persistent correlator state**: port-scan / brute-force / slow-scan /
  icmp-sweep state checkpoints to `<data_dir>/correlate-state.json`
  (60s + on shutdown), restores on startup, and carries across hot
  reload — so long-window detection survives a restart.

### Added — topology-coherent DNS + web UI sorting/filtering/errors view
- **DNS resolver answers in correspondence with the topology**: a query
  matching a virtual host's FQDN (or reverse address) returns that host's
  real virtual IP; SRV (`_ldap`/`_kerberos`/`_gc`/… incl. AD `_msdcs`)
  resolves to the virtual host offering the service with its real port;
  HINFO is derived from the host's archetype; NS/MX/SOA point at the
  domain's resolver/mail/authoritative server. Added PTR, HINFO, LOC,
  SOA, SRV record types. Names outside the topology keep the deterministic
  fabricated answer.
- **Web UI**: sortable event columns (time / severity / rule / source /
  handler, click to sort, click again to reverse) + a severity filter;
  a substring/status filter on the hosts view; a new **/errors** view
  surfacing operational/health events. The sensor now emits
  `sensor:listener_stopped`, `sensor:listener_error`, and
  `sensor:canary_stopped` events that feed it.

### Fixed — code-quality review pass
- **seccomp now covers all threads**: the filter is installed with
  `SECCOMP_FILTER_FLAG_TSYNC`, so it confines every OS thread of the Go
  runtime (previously only the calling thread); added a cross-thread
  regression test + an 8-bit BPF jump-offset guard.
- **Landlock scope documented honestly**: it confines the calling thread +
  threads created afterward (no TSYNC equivalent); docs now point to
  AppArmor/SELinux/systemd for full-process FS confinement.
- **Unbounded memory fixed**: the correlator (scan/brute/slow/sweep/story/
  emitted) and the scananalysis Tracker now evict idle per-source state, so
  the maps don't grow without bound under many distinct source IPs.
- **D3FEND defenses centralized** in `router.Dispatch`, so synthesized
  events (device:new, malware:capture, scananalysis:profile, test-alert)
  also carry `mitre_defenses`.
- **CVE catalog made honest**: removed records that can't be substring-
  detected (Heartbleed, SMBGhost); wired EternalBlue/BlueKeep into the
  smb/rdp handlers (their ASCII signatures genuinely appear); fixed the
  conflated EternalBlue signature + misleading comments; signatures are
  lowercased once at init.
- **DNS fake A records never land in reserved space**: first octet is now
  drawn from a curated public set (no RFC1918/loopback/link-local/CGNAT).
- **Payload harvesting**: tightened the shellcode heuristic (>=32 bytes,
  >=0.45 non-printable, >=3 opcode sigs) to avoid false positives on binary
  protocol frames; magic-confirmed binaries stay Critical, heuristic hits
  drop to High; now also harvests URLs/droppers from interactive-shell
  command lines; payload is base64-decoded once and shared; artifact bytes
  are only copied when persistence is enabled.
- Removed the dead `cve.Record.Affects` field; fixed `cmd ver` output
  (`extractWinVersion`); single-pass `extractURLs`.

### Added — kernel self-confinement + docs
- **seccomp + Landlock self-confinement** (`internal/sandbox`,
  `sensor.sandbox`): pure-Go, CGO-free, Linux-only, applied after privilege
  drop. seccomp-bpf denylist blocks execve/ptrace/module-load/mount/kexec/…
  (a parser 0-day can't spawn a shell); Landlock makes the filesystem
  read-only except `data_dir`. Best-effort; no-op on non-Linux.
- **AppArmor profile** (`packaging/apparmor/`) and **SELinux policy module**
  (`packaging/selinux/`) enforcing the same intent from the host LSM.
- **Docs**: moved `design.md` → `docs/design.md` and rewrote it to cover the
  full current implementation; added `docs/hardening.md` (layered
  confinement guide); documented `sensor.sandbox` in `config.md` + the FULL
  example.

### Added — CVE emulation, command emulation, malware capture, D3FEND, AD/Cisco
- **CVE catalog + emulation** (`internal/cve`): curated high-signal exploit
  signatures (Log4Shell, Shellshock, Spring4Shell, ProxyLogon/Shell,
  FortiOS/Pulse/Citrix traversals, Apache 2.4.49, EternalBlue/SMBGhost,
  BlueKeep, …). http/https/appliance handlers recognize exploit attempts and
  emit CVSS-scaled `cve:<id>` events. `sensor.vuln_emulation` (per-listener
  overridable) makes banner-aware handlers advertise a known-vulnerable
  version / fake patch level. The service is never actually exploitable.
- **ATT&CK + D3FEND mappings**: `cve:<id>` rule mapping; MITRE **D3FEND**
  defensive countermeasures stamped on every event (`mitre_defenses`).
- **Active Directory + Cisco archetypes**: a Windows Server 2019 DC (Kerberos/
  LDAP/SMB/DNS/WinRM/DCERPC/Global-Catalog + PowerShell shell + pre-2021 patch
  level) and a Cisco IOS switch. Archetypes gain vulnerable-banner / patch-
  level fields.
- **Command emulation**: PowerShell (incl. AD cmdlets), Windows cmd.exe, Cisco
  IOS, and the Siemens S7 PLC console, routed by archetype family; the shell
  anomaly scanner gains Windows/PowerShell TTP markers (download cradle,
  encoded command, credential dumping, AD recon, Defender/AMSI tamper,
  registry/schtask/service persistence).
- **Malware capture / shellcode extraction / payload harvesting**
  (`internal/payload`): classifies captured bytes (ELF/PE/Mach-O/archive/script
  + x86 shellcode heuristics), decodes base64-wrapped droppers, harvests
  ingress URLs, and persists artifacts to `<data_dir>/payloads/` with size
  caps (`sensor.payloads`). Emits `malware:capture` (T1105+T1027).
- **Storyline correlator** now tracks CVE exploits / captured malware /
  fingerprinted tools, flags `objective_reached` (impact/exfil), scales
  severity to Critical, and carries D3FEND defenses.
- **Web UI**: new **hosts** tab (known/seen/allow-listed IPv4/IPv6/MAC) and
  **alerting** tab (syslog/email/webhook/SMS/SNMP forwarding + routes).

### Added — scan analysis + small services + DNS resolver + tarpit emulation + UI tabs
- **Scan analysis / nmap fingerprinting** (`internal/scananalysis`,
  `scananalysis:profile` event): stateless per-payload classification
  (nmap service-probe strings, NSE-script signatures, version probes,
  bare connect scans) plus a stateful per-source `Tracker` that
  estimates the nmap timing template (`-T0` paranoid .. `-T5` insane)
  from inter-connection cadence and flags aggressive (`-A`), OS-probe
  (`-O`), and version (`-sV`) scans once a source crosses the
  confidence threshold. Half-open SYN / FIN / NULL / Xmas / ACK scans,
  raw fragmentation, and decoy floods (`-D`) are honestly scoped as
  needing the AF_PACKET sniffer. Tagged `T1595` + `T1046`.
- **Small services** (RFC 862-868 / 1340), TCP **and** UDP: `echo`,
  `discard`, `daytime`, `qotd`, `chargen`, `time`. `chargen`/`echo`
  reply with a single bounded datagram and never amplify — the UDP
  `chargen` probe is flagged `udp-amplifier-probe`. (Reflection-safe by
  construction.)
- **Resolving DNS handler** (`dns`, UDP/53): answers
  `A`/`AAAA`/`MX`/`TXT`/`NS`/`CNAME` with fabricated,
  deterministic-per-deployment records (same name → same fake IP,
  avoiding RFC1918/loopback) so a resolver enumeration sees a live,
  populated server. Every query runs through the tunneling/exfil
  detection heuristics. Distinct from the NXDOMAIN-by-default DNS
  canary listener.
- **Emulate-then-tarpit** (`tarpit.emulate: true`): runs the listener's
  protocol `handler:` first (real banner + captured request), then
  applies the tarpit strategy on the same connection — turning any
  emulator into a tarpit. Captured banner/request lands in
  `tarpit_start` (`tarpit_emulated_handler` in meta).
- **Web UI: topology + docs tabs**. `/topology` (+ `/api/topology`)
  renders the honeynet networks / hosts / services the sensor presents;
  `/docs` is a built-in reference that reflects the running deployment.
- Handler count: **76** (1 generic + 52 TCP + 23 UDP).

### Added — protocol breadth + archetype consistency + fingerprinting
- **15 new protocol emulators**: `mssql` (TDS PRELOGIN), `oracle_tns`
  (TNS connect/refuse), `teamviewer`, `anydesk`, `openvpn`,
  `citrix_ica`, and the management-web personas `intel_amt`, `ilo`,
  `idrac`, `esxi`, `fortinet`, `pulse`, `citrix_gateway`, `horizon`,
  `moxa_mgmt`. VNC handler now varies its RFB version (3.3 / 3.7 / 3.8
  / 4.1 / Apple ARD) per deployment. (63 handlers total.)
- **11 Windows archetypes** (7/8/10/11, Server 2008/2012/2012R2/2016/
  2019/2022) with version-matched IIS Server header + default page,
  Microsoft SNMP sysObjectID, TTL 128, and era-correct **TLS posture**
  (Server 2008 caps TLS 1.0 + legacy CBC ciphers, 2012/R2 TLS 1.2).
  3 new Siemens archetypes (SCALANCE S615 / SC-600; XB-208 enriched).
- **Archetype consistency**: new Profile fields for TLS posture
  (min/max version + weak-cipher flag, applied by the https handler),
  per-host **ICMP TTL personality** (255 OT / 128 Windows / 64
  Linux-BSD, stamped by the ICMP responder), and switch/OT topology
  (MRP rings, PROFINET device tree, VLANs, HMIs).
- **Switch web-UI topology exposure**: SCALANCE archetypes serve their
  MRP / PROFINET / VLAN / HMI / LLDP inventory from the http handler's
  device-info paths (`/topology`, `/status`, `/vlan`, …).
- **Tool fingerprinting + human-vs-automation** (`internal/toolfp`):
  UA + path signatures for nmap / masscan / sqlmap / nikto / hydra /
  nuclei / metasploit / gobuster / zgrab / censys / curl / wget /
  python / Mirai + router-exploit probes, plus a browser-vs-script
  verdict. Surfaced as `meta.tools` / `meta.automation` +
  `tool:<name>` / `automation-client` anomalies.
- **Abnormal-payload detection**: ICMP (`internal/icmp.Anomalies` —
  oversize / non-filler-entropy payload, fragmentation abuse,
  overlapping-fragment evasion) and DNS (tunneling fingerprint —
  overlong qname / label, high-entropy encoded label, NULL/TXT
  tunneling qtypes, oversize query).
- **Web UI config tab** (`/config` + `/api/config`) — view the
  effective config (secrets shown as `*_env` names).
- **Default credentials + fake files + `ftp_files` handler**, **device
  intelligence** (DHCP discovery + learned-device registry +
  `device:new` alerts + `list-devices`), **ICMP message library** +
  `correlate:icmp_sweep`, and **cross-handler default-credential
  detection** (redis dangerous commands, smtp open-relay / VRFY-EXPN).
- Example configs: refreshed `tarpit-honeypot.example.yaml` + new
  `-FULL`, `-SMALL-OT`, `-ADVANCED-OT` sibling configs.

### Added — deception depth + network intelligence
- **Default-credential corpus** (`internal/creds`) — curated vendor
  defaults (router/camera/BMC/database/ICS/generic). Every
  auth-capturing handler (ftp, ftp_files, telnet, smtp_recv, redis,
  postgres) now flags `default-credential-attempt` (+ device
  category) when a captured pair is a known default.
- **Fake-file registry** (`internal/fakefiles`) — deterministic decoy
  tree per deployment with bait files (id_rsa, credentials.txt,
  config.bak, database_dump.sql, ...).
- **`ftp_files` handler** (TCP/21) — medium-interaction FTP: anonymous
  / accept_creds login, full PASV browse + RETR, flags
  `honeyfile-download` on bait retrieval. Listener `accept_creds`:
  none | defaults | any.
- **Apache / nginx web emulation** — http handler serves the real
  "It works!" / "Welcome to nginx!" index + version-appropriate
  flavored 404 (Apache `<address>...Server at host Port N</address>`
  footer / nginx centered page) matching the Server header.
- **Expanded `deployment_id` surfaces** — ApacheVersion(+modules),
  NginxVersion, FTPBannerVariant, DNSServerVersion, NTPRefID,
  ETagSeed, SMTPGreetingProduct, SSHCookie.
- **Per-service X.509 certs** — distinct self-signed cert per listener
  (subject CN/O/OU, ecdsa|rsa key type, per-service validity jitter,
  independent serials) so each TLS service is a unique endpoint.
- **Device intelligence** — `internal/devices` learned-host registry
  (IP/MAC/hostname/vendor-OUI/source), persisted to devices.json.
  New `dhcp` handler (UDP/67, passive) captures client MAC / hostname
  / vendor-class / option-55 DHCP fingerprint. Sensor feeds every
  observed host into the registry and raises `device:new` for
  non-allow-listed / never-seen hosts. New `list-devices` subcommand
  (table or `--json` baseline). config.Devices block.
- **ICMP message library** (`internal/icmp`) — portable builders for
  ICMPv4 Echo/Dest-Unreachable(0/1/3/4/13)/Redirect/Time-Exceeded/
  Param-Problem/Timestamp/Address-Mask and ICMPv6 Echo/Neighbor-
  Advert/Router-Advert. Honeynet ICMP responder now answers echo +
  timestamp + address-mask.
- **ICMP sweep correlator** (`correlate:icmp_sweep`) — one source
  touching N distinct destination IPs via ICMP in a window.
- **More protocol anomalies** — redis dangerous commands
  (config-set / replication-takeover / module-load / flush /
  script-exec), smtp open-relay probe + VRFY/EXPN user enumeration,
  telnet non-printable credentials, dhcp-client-observed.

### Security — panic-trigger + UDP reflection fixes
- **High**: `modbus` handler — MBAP `length=1` allocated a zero-byte
  PDU buffer; the subsequent function-code dereference panicked. The
  goroutine recover-guard contained the damage but the handler died
  on every connection attempt. Tightened the length check to `>= 2`.
- **High**: `s7` handler — a COTP CR body of exactly 6 bytes (TPKT
  length=10) sliced `body[7:]` and panicked. Tightened the guard to
  `len(body) >= 7` before slicing the parameters.
- **High**: `radius` handler — attacker-controlled `length` field
  used to drive `payload[20:length]` which panicked when `length < 20`
  (low > high) or `length > len(payload)`. Added a bounds check.
- **High**: `ssdp` + `sip` UDP handlers — attacker-supplied headers
  (ST, Via, From, To, Call-ID, CSeq) were reflected verbatim into the
  response. CRLF in any of them gave an off-path attacker a one-shot
  UDP reflection/amplification primitive against a third party. Every
  echoed value now goes through `safe.SanitizeHeader`.
- **Medium**: `rtsp` handler — `CSeq` echoed without sanitization
  (TCP-only so no UDP spoofing, but a downstream proxy / cache could
  still be confused). Now `safe.SanitizeHeader(cseq)`.
- **Medium**: `ssh_interactive` — `xssh.DiscardRequests` and the
  session-channel request loop were raw `go func()` goroutines. A
  panic in crypto/ssh request parsing — possible with a malformed
  payload from a hostile client — would propagate to
  `runtime.fatalpanic` and kill the sensor process. Both now run
  inside `safego.Run` with the standard recovery + counter.
- **Medium**: Central output sanitization gap — `metaToString` (which
  calls `safe.SanitizeForLog`) only ran for CEF/LEEF. JSON / OCSF
  marshalled raw `ev.Meta` directly; control characters survived as
  JSON-escapes (``) but downstream consumers that decoded and
  rendered to a terminal reconstituted the original ANSI/escape
  bytes. `safe.SanitizeMetaStrings` now runs at the listener
  boundary (`tcp.go` + `udp.go`) so every string-typed value is
  scrubbed once, recursively, before any formatter sees it.
- **Low**: `ssh_interactive` host-key write error was silently
  swallowed (`_ = os.WriteFile(...)`); on a read-only filesystem the
  promised "stable host key fingerprint across restarts" property
  broke without warning. Now logs at warn level + continues with the
  in-memory key.
- **Low**: `https` TLS handshake used `context.Background()` instead
  of the caller's `ctx`. Slow-handshake drip couldn't be interrupted
  at sensor shutdown — only when `ReadDeadline` fired. Now uses the
  caller's context.

### Added — protocol depth improvements
- **`iec104`** is now a multi-frame session: it loops over the
  connection, handles STARTDT_ACT / STOPDT_ACT / TESTFR_ACT with the
  matching CONfirm reply, and responds to General Interrogation
  requests (ASDU type 100, COT=6) with the full sequence a real RTU
  emits — activation-confirmation, three M_ME_NB_1 measurement
  frames at IOAs 0x4001–0x4003, then activation-termination. Also
  handles Clock-Sync, Read-Command, Single-Command, and Double-
  Command requests. Every received frame's `asdu_type`, `cot`,
  `common_addr`, and `ioa` land in `meta.frames`.
- **`fins`** extended from one to seven Omron command pairs:
  CPU_UNIT_DATA_READ, CPU_UNIT_STATUS_READ (with RUN/MONITOR mode
  + zero-error fields), MEMORY_AREA_READ (with believable PV-like
  data, decoded `mem_area_name`: DM/CIO/WR/HR/AR/EM), CYCLE_TIME_READ,
  CLOCK_READ, plus generic ACK for everything else. Meta carries
  `mem_addr` and `mem_count` for memory reads.
- **`modbus`** extended:
  - Multi-PDU session loop (was one-shot).
  - **FC 0x2B / 0x0E (Read Device Identification)** — what nmap's
    modbus-discover uses for vendor fingerprinting. Now advertises
    Schneider Electric BMX P34 2020 / Modicon M340 with the full
    objects-table (vendor, product code, revision, vendor URL,
    product name, model name, user app name, conformity class).
  - **FC 0x05 / 0x06 / 0x0F / 0x10 (Write Single/Multiple
    Coils/Registers)** — captures the values the attacker tried to
    write into `meta.written_values`. ICS-relevant TTP capture.
  - Read-register replies (FC 3/4) now return the requested quantity
    of registers (was always 1) with believable process-value
    patterns.
  - Per-PDU `function_name` symbolic decode in meta.

### Documentation
- `README.md` "Protocol handlers in detail" rewritten as three tables
  (TCP IT, TCP ICS, UDP) covering all 46 handlers with archetype +
  identity columns. Each row reflects the actual implementation:
  multi-frame loops, captured fields, reply shape, vendor IDs
  advertised, fingerprints computed.
- Brief feature list updated to "46 built-in protocol handlers" with
  the correct counts per category.

### Added — macOS first-class support
- `darwin/amd64` and `darwin/arm64` build targets in `make cross`.
- Real `privdrop` implementation on darwin (`internal/privdrop/
  privdrop_darwin.go`): `setgid`/`setuid` with the same "refuse uid
  0" guard as the Linux path. On darwin `setuid` also drops the
  saved-uid so a later `setuid(0)` regain attempt fails — same
  posture as Linux's `setresuid`.
- Platform-aware error messages on every Linux-only subsystem (ARP /
  ICMP / LLDP responders, AF_PACKET sniffer, fanotify OPEN events,
  Linux TUN). Each now mentions the runtime GOOS and the documented
  macOS workaround (`ifconfig <iface> alias <ip>` for L2/L3 presence,
  fsnotify for non-OPEN file canaries).
- Comprehensive platform-support matrix in `docs/usage.md` §12 and
  `README.md`. New launchd plist example in `docs/INTEGRATIONS.md`.

### Documentation
- `README.md` rewritten: 37 handlers (was 28), 29 archetypes,
  ATT&CK / storyline / anomaly / hardening / engagement sections,
  full platform support matrix, status blocks for v1.6–v1.10.
- `docs/usage.md` extended with three new top-level sections:
  Archetypes (§9), Interactive engagement (§10), ATT&CK / storyline /
  anomaly (§11), Platform support (§12). Troubleshooting table
  refreshed with macOS-specific entries.
- `docs/cli.md` adds Common flags table, config-layering description,
  `init` / `completion` / `help` subcommand sections, `--version` /
  `-V` flag forms, macOS privileged-setup notes.
- `docs/config.md` documents `ssh_interactive` vs `ssh`, adds
  `honeynets[].lldp_responder` block, updates handler lists.
- `docs/INTEGRATIONS.md` adds §3a (ATT&CK/storyline/anomaly SIEM
  rules), industrial-OT honeynet recipe, launchd deployment pattern,
  macOS `ifconfig alias` workaround note.
- `internal/cli/help.go` archetypes topic enumerates every
  fingerprint surface the archetype controls.

### Added — v1.10 attacker engagement
- **Interactive CLI shell** (`internal/shell`) — post-login command-
  line emulation. After a fake "Login incorrect" first attempt, the
  attacker is dropped into the archetype's shell where every command
  they type is captured and scanned against a 14-marker ATT&CK-
  aligned TTP catalog (reverse shells, persistence, recon, defense
  evasion, log-cleaning, crypto-miners, encoded payloads, etc.).
  Wired into:
  - `telnet` handler (after fake login).
  - New `ssh_interactive` handler running a full
    `golang.org/x/crypto/ssh` server: persists an ed25519 host key
    under `<data_dir>/tls/`, captures every password / pubkey
    attempt (incl. SHA-256 key fingerprints), accepts the 3rd
    credential and drops into shell.Run on the session channel.
  Bounded at MaxCommands=32, MaxBytesPerCommand=8KiB,
  IdleTimeout=60s, SessionTimeout=5min.
- **LLDP / CDP active responder** — each honeynet host now appears
  in `lldpctl` / Cisco `show cdp neighbors` output on the L2 segment,
  advertising the archetype-shaped MAC, hostname, system description,
  and family-tuned LLDP capabilities (bridge/router for switches +
  PLCs, station-only for hosts). Linux-only (AF_PACKET + CAP_NET_RAW).
  Config:
  ```yaml
  honeynets:
    - id: factory
      lldp_responder:
        enabled: true
        interface: eth1
        interval_s: 30
        include_cdp: true
  ```
- **Multi-page web UI + credential capture** — the http handler now
  routes on path + method:
  - `GET /` (and any archetype index): serves the archetype's HTML.
  - `GET /login`, `/admin`, `/Portal/Login.html`,
    `/cgi-bin/luci`, `/wp-login.php`, `/manager/html`, etc.: serves
    a login form.
  - `POST /login` (any of the above): parses the urlencoded body
    (accepts `username`/`user`/`login`/`name`/`uname`/`u` and
    `password`/`pass`/`passwd`/`pwd`/`p` aliases) and emits an
    `http-login-attempt` anomaly with the captured credentials.

### Added — v1.9 deception+detection upgrades
- **14 new archetypes** for full-fleet deception coverage:
  FreeBSD 13/14, OpenBSD 7.5/7.6, Arch Linux, Rocky Linux 9,
  AlmaLinux 9, Oracle Linux 8/9, Moxa EDS-208, Moxa NPort 5210,
  Siemens SCALANCE XB-208, Siemens S7-1200 PLC, Siemens S7-1500 PLC.
  Each carries the full fingerprint surface needed to fool a scanner:
  vendor MAC OUI, SNMP sysDescr/sysObjectID/interface table, default
  service list, web-UI HTML body, SSH/Telnet CLI prompt, LLDP
  neighbors, and per-archetype protocol quirks.
- **MITRE ATT&CK tagging** — every event the sensor emits is
  decorated with `mitre_techniques` (e.g. ["T1110.001","T1078"]) and
  `mitre_tactics` (e.g. ["credential-access","initial-access"]) via
  the new `internal/mitre` package. Mapping is rule_id + handler-aware
  so listener:ssh-bait gets brute-force / valid-accounts technique
  IDs, while listener:http-bait gets exploit-public-facing-app.
- **Storyline correlator** (`storyline:multi_stage`) — fires when a
  single source IP touches 3+ distinct ATT&CK tactics inside a
  30-minute window. The event meta carries the kill-chain-ordered
  stage list and a "->"-joined chain summary
  ("discovery -> credential-access -> lateral-movement"), so the SOC
  sees one timeline instead of dozens of independent listener hits.
- **Protocol anomaly detection** — handlers flag deviations from
  expected protocol shape into a first-class `event.anomalies` array
  that SIEM rules can match on directly. SSH flags non-printable /
  non-SSH / overlong identification strings; HTTP flags unknown
  methods + suspicious URIs (path traversal, Log4Shell JNDI,
  WordPress probes, secret-file probes, .git leakage, mgmt-endpoint
  scans).
- **Defensive hardening** — new `internal/safe` package centralizes
  hostile-input handling: bounds-checked slice/string/alloc helpers
  with a 32 KiB universal cap, plus SanitizeForLog /
  SanitizeUTF8ForLog / SanitizeHeader / SanitizeEmailSubject for
  output paths. CEF/LEEF/OCSF formatters now escape every control
  byte (not just CRLF), and the SMTP sink runs the Subject + every
  header through the sanitizer so a stolen credential or scanner
  banner can't inject extra MIME headers.

### Added — v1.8
- **Archetypes** — set `sensor.archetype: "debian 12"` (or
  `listener.archetype`, or per-honeynet-host `archetype`) and every
  banner-aware handler (SSH / HTTP(S) / FTP / Telnet / SMTP / MySQL)
  reports values consistent with a stock install of that OS, so a
  scanner can't catch the sensor by spotting a version-vs-distro
  mismatch. 15 ship archetypes: `centos 5`, `centos 6`, `centos 7`,
  `centos 8`, `CentOS Stream 10`, `debian 9`–`debian 13`, `Red Hat
  Enterprise Linux 8`–`10`, `Ubuntu 24.04 LTS`, `Ubuntu 26.04 LTS`.
  Override precedence: honeynet-host > listener > sensor > "no
  archetype". `tarpit-honeypot help archetypes` lists them all.
- **5 new protocol handlers**:
  - `coap` (UDP/5683) — RFC 7252 IoT discovery, parses option TLVs,
    replies with `/.well-known/core` link-format.
  - `knx` (UDP/3671) — KNXnet/IP building automation. Answers
    SEARCH_REQUEST and DESCRIPTION_REQUEST as an MDT KNX IP Router.
  - `xmpp` (TCP/5222) — XMPP client stream, advertises PLAIN +
    SCRAM-SHA-1, captures SASL AUTH attempts.
  - `amqp` (TCP/5672) — RabbitMQ-shaped Connection.Start, captures
    PLAIN credentials in Connection.StartOk, replies NOT_ALLOWED.
  - `ipp` (TCP/631) — IPP/CUPS printer. Answers Get-Printer-Attributes
    with a fake Brother HL-L8260CDW.
- `make cover` / `make race` / `make fuzz` targets
- Fuzz tests for the TLS ClientHello (JA3/JA4), SSH KEXINIT (HASSH),
  HTTP request line (JA4H), LDAP BER decoder, MQTT varint/string
  parsers, and DNS query parser. Failing inputs persist under
  `testdata/fuzz/` as regression cases.
- `internal/safego` package — `Run` / `RunWithEvent` goroutine wrappers
  with a `recover()` guard. Panics log + increment counter + emit a
  `sensor:panic:<name>` event into the bus.
- Panic recovery wired into the TCP and UDP listener handler paths and
  the sensor's bus loop.
- `/metrics` now exposes `tarpit_build_info`, `tarpit_uptime_seconds`,
  `tarpit_panic_recoveries_total`, `tarpit_panic_recoveries_by_name_total`.
- Global `--version` / `-V` flag; per-subcommand `-h` / `--help`.
- Logging flags shared across subcommands: `--log-level`,
  `--log-format=text|json`, `--log-file`, `--quiet`, `--verbose`.
- `--set key.path=value` overrides on `run` and `show-config`.
- `TARPIT_*` environment-variable overrides (`TARPIT_SENSOR_NAME=foo`,
  double-underscore escapes a real `_`).
- `conf.d/*.yaml` deep-merge over the base file in lexical order.
- `run --dry-run` validates the config and constructs the sensor
  without binding any listeners.
- New subcommand `init` writes a defaulted YAML skeleton.
- New subcommand `completion bash|zsh|fish` prints shell completions.

### Fixed
- LDAP `stripBERHeader` short-form bounds check now happens before the
  slice (caught by `FuzzLDAPParseMessage` immediately on first run).

## [v1.5] — 2026-05-19

### Added
- Linux TUN-based honeynet adapter (L3 responder for ICMP + TCP RST;
  no full TCP termination).
- IPv6 listener binds and honeynet host IPs throughout.
- SNMP / LDAP / DCE-RPC handlers expose honeynet topology in event
  meta (`honeynet_neighbors`, `honeynet_computer_accounts`,
  `honeynet_endpoints`).
- `docs/` directory: `usage.md`, `config.md`, `cli.md`, `README.md`.

## [v1.4] — 2026-05-19

### Added
- Source-IP enrichment: MaxMind GeoLite2 (city + ASN) and bounded
  synchronous reverse-DNS with LRU cache.
- Per-channel output `format:` field — `json` (default), `cef`
  (ArcSight), `leef` (QRadar), `ocsf` (cloud SIEMs).

## [v1.3] — 2026-05-19

### Added
- Linux AF_PACKET ICMP echo responder per honeynet (matches the
  v1.2 ARP responder model; reuses the per-host MAC).
- Prometheus-format `/metrics` endpoint on the web UI: per-channel
  retry / failure / drop counters, honeynet topology gauges, SQLite
  store size.

## [v1.2] — 2026-05-19

### Added
- Linux AF_PACKET ARP responder per honeynet — virtual hosts
  advertise stable deployment-derived MACs.
- Per-honeynet route matching: routes can filter on `honeynet`,
  `honeynet_os`, `rule_id` in addition to severity.

## [v1.1] — 2026-05-19

### Added
- Honeynets: configurable artificial networks with virtual hosts and
  services. Per-host derived identity (banner / version / serial /
  challenge). DNS canary listener forward-resolves honeynet hostnames.
- `list-honeynets` subcommand.

## [v1.0] — 2026-05-19

### Added
- Counter-fingerprinting: `sensor.deployment_id` seeds all
  fixed-string handler responses; per-reply jitter; TLS cert rotation;
  HTTP JA4H fingerprinting; banner variant pools.
- Brute-force credential extraction in the correlator.
- Slow-scan correlator (24h-default window with per-port aging).
- DNS amplifier-probe detection (ANY queries + per-window rate).
- `sensor.disk.retention_days` time-based pruner.
- Graceful drain on shutdown via `sensor.shutdown.drain_timeout`.
- `export-pcap` subcommand.

## [v0.9] — 2026-05-19

### Added
- CLI ergonomics: `gen-token`, `show-config`, `validate-config --diff`.
- Dockerfile (scratch base, ~14MB).
- Listener hot-reload (per-listener restart on SIGHUP).
- Per-listener `max_concurrent` accept cap.
- Outbound sink retry queue with exponential backoff.
- Diff-on-reload audit log + `sensor:reload` event.
- TLS / HTTP / SSH client fingerprinting: JA3, JA4, HASSH.
- 11 new protocol handlers: VNC, SMTP receive, RDP, WinRM, DCE-RPC,
  LDAP, Kerberos, Postgres, MySQL, Redis, IPMI.

## [v0.8] — 2026-05-19

### Added
- SMB1 / SMB2 handler.
- Comprehensive README.

## [v0.7] — 2026-05-19

### Added
- OPC-UA, EtherNet/IP, BACnet, TFTP handlers.
- linux/armv7 + linux/armv6 cross-build targets.

## [v0.6] — 2026-05-19

### Added
- UDP handler architecture.
- SNMP + NTP UDP handlers (NTP mode-7 explicitly silenced — no
  amplifier path).
- Twilio SMS, AWS SNS (hand-rolled Sigv4), SNMPv2c trap channels.

## [v0.5] — 2026-05-19

### Added
- URL canary tokens via HTTP/HTTPS handlers.
- DNS canary listener.
- Linux fanotify-based file open detection.
- AF_PACKET sniffer (ARP scan + unsolicited reply detection).

## [v0.4] — 2026-05-19

### Added
- ICS handlers: Modbus, S7comm, IEC-104, MQTT.
- Per-event pcap capture (synthesized libpcap; no raw sockets).

## [v0.3] — 2026-05-19

### Added
- SQLite event index (pure-Go).
- Read-only loopback web UI (`/`, `/events`, `/events/<id>`, `/api/*`,
  `/healthz`).
- Privilege drop (Linux setresuid/setresgid).
- SIGHUP hot reload for channels / routes / allowlist / dedup /
  correlator.

## [v0.2] — 2026-05-19

### Added
- Tarpit modes: `sticky`, `trickle`, `keepalive`.
- Built-in protocol handlers: SSH, HTTP, HTTPS (self-signed), Telnet,
  FTP.
- Filesystem honeyfile watcher via fsnotify.
- Port-scan + brute-force correlators.
- Per-sink worker queues with bounded drop.

## [v0.1] — 2026-05-19

### Added
- Tripwire MVP: TCP/UDP listeners (drop + banner modes), YAML config,
  stdout + jsonlog + webhook + SMTP + syslog sinks, dedup +
  rate-limit + allowlist + min-severity gating, systemd unit, Linux
  amd64/arm64 static cross-build.

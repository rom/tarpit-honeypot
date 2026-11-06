<p align="center">
  <img src="./assets/logo.svg" alt="tarpit-honeypot" height="56">
</p>

# tarpit-honeypot

A single static Go binary that runs a deception **and** detection sensor:
protocol-shaped honeypots on configurable ports (from SSH/HTTP/SMB through
ICS/SCADA to the **cloud-native control plane** — Kubernetes API, etcd,
Vault, cloud metadata — and modern transports like WebSocket and gRPC),
OS-archetype-aware banners and CLI emulation, interactive SSH/Telnet
engagement that captures every command an attacker types, a **userspace TCP
stack** (IPv4 + IPv6 SYN-layer) that lets honeynet decoys complete
fingerprint-shaped handshakes (and capture malformed/illegal packets) with
no socket bound per host, the full **JA3/JA4/JA4S/JA4T/JA4X/JA4L/JA4SSH/JA3S/JA4H/HASSH**
fingerprint family, MITRE ATT&CK / D3FEND-tagged events, cross-protocol
attack-storyline correlation,
protocol-anomaly + **fuzzing / DoS** detection, three dozen in-sensor
correlators, GeoIP / ASN / threat-intel / Tor / MAC-vendor enrichment,
file / URL / DNS canary tokens, per-event pcap capture, hostile-input
hardening + output sanitization, and pluggable outbound alerting. Sensors
**aggregate into a fleet** — events flow up to a correlator that runs 27
cross-sensor `fleet:*` detectors and distills **indicators of compromise**,
which flow back down as a threat-intel feed and out as **STIX 2.1 / TAXII 2.1
/ MISP**.

CGO-free. Static builds for `linux/{amd64,arm64,armv7,armv6}`,
`darwin/{amd64,arm64}`, and `windows/{amd64,arm64}` (the portable core;
the Linux-kernel features — AF_PACKET, TUN, fanotify — no-op elsewhere).

See [`docs/design.md`](docs/design.md) for the architecture + design
rationale covering the current implementation.

## Features at a glance

- **TCP honeypots** in three modes: `drop`, `banner` (protocol handler),
  or `tarpit` (sticky / trickle / keepalive / jitter / backoff / ssh_banner /
  http_headers / http_chunked / echo / babble / zipbomb / zero_window).
  `tarpit.emulate: true`
  runs the listener's protocol handler first (real banner + captured
  request), then tarpits the same connection — any emulator becomes a
  tarpit.
- **UDP honeypots** in `drop` or `banner` mode with protocol handlers.
- **Reply-policy modes** (`sensor.reply_policy`): one deployment-wide lever
  gating every service — `full` (default), `non-ot` (mute OT/ICS handlers),
  `fingerprint` / `fingerprint-non-ot` (reply just enough to fingerprint /
  capture creds, no deep sessions or outbound call-outs), or `mute`
  (receive-only — no outbound bytes at all). Plus `sensor.no_amplifier_replies`
  to suppress NTP mode 6/7 + reflector replies.
- **197 TCP + 118 UDP protocol handlers** (plus L2 GOOSE detection, an L2 PROFINET-DCP responder, and an ICMP responder), including scriptable `lua` and declarative `scripted` handlers for custom services and a generic `auto` catch-all for unmodelled protocols. Run `tarpit-honeypot list-handlers` for the authoritative list, or see [Protocol handlers in detail](#protocol-handlers-in-detail) for what each one captures and replies with.
  - **Generic**: `raw`, `auto` (catch-all: captures + fingerprints any unmodelled protocol, flags `unknown-protocol`), `tls_intercept` (TLS-terminating MITM front: decrypt → inner handler, or decrypt-and-forward to a real backend through the egress allowlist)
  - **TCP / IT**: `ssh`, `ssh_interactive`, `http`, `https`, `telnet`, `ftp`, `ftp_files`, `smb`, `vnc`, `smtp_recv`, `rdp`, `winrm`, `dcerpc`, `ldap`, `kerberos`, `postgres`, `mysql`, `mssql`, `oracle_tns`, `redis`, `memcached`, `mongodb`, `elasticsearch`, `neo4j`, `rethinkdb`, `couchdb`, `influxdb`, `pop3`, `imap`, `syslog_tcp`, `rtsp`, `dockerapi`, `docker_registry`, `cloud_metadata`, `etcd`, `kubernetes_api`, `kubelet`, `vault`, `websocket`, `grpc`, `ssrf_canary`, `xmpp`, `amqp`, `ibmmq`, `ipp`, `rsync`, `gopher`, `socks`, `bgp`, `rpcbind`, `nfs`, `pptp`, `irc` (6667 — botnet C2 + the UnrealIRCd 3.2.8.1 backdoor CVE-2010-2075), `finger` (79 — account enumeration), `stomp` (61613 — ActiveMQ/RabbitMQ message broker), `nntp` (119 — news / open-relay + AUTHINFO capture), `ident` (113 — RFC 1413 account disclosure), `afp` (548 — Apple Filing Protocol / DSI file share), `beanstalkd` (11300 — unauthenticated work queue)
  - **TCP / remote-access + mgmt**: `teamviewer`, `anydesk`, `openvpn`, `citrix_ica`, `vmware_authd`, `x11`, `rlogin`, `nx`, `redfish`, `intel_amt`, `ilo`, `idrac`, `esxi`, `fortinet`, `pulse`, `citrix_gateway`, `horizon`, `moxa_mgmt`, `danfoss_aksm` / `danfoss_aksms` (Danfoss AK-SM 8xxA "StoreView" refrigeration system manager — recognizes the Claroty Team82 `xml.cgi` CVEs, detection only)
  - **TCP / AI + agent infrastructure**: `ollama` (Ollama LLM runtime, 11434), `llm_openai` (OpenAI-compatible inference API — vLLM / LM Studio / LocalAI), `mcp` (Model Context Protocol server honeypot) — each fingerprints the service, captures the attacker's prompt / tool-call, and classifies **prompt-injection / jailbreak / tool-abuse** payloads mapped to **MITRE ATLAS** (AML.T0051 / T0054 / T0057 / T0053)
  - **TCP / agentic-attack honeypot**: `agent` — an **agent provocateur** that speaks the agent-interop protocols (**A2A** agent cards + JSON-RPC, **AP2** payment mandates, **MCP**, **ACP**), detects **Web Bot Auth** (RFC 9421) signatures and AI-crawler UAs, fingerprints the calling **framework/SDK** (LangChain, CrewAI, AutoGen, OpenAI-Agents, LlamaIndex, …) and operation (recon / exfil / lateral / exploit / payment), and scores a **behavioral confidence band** (human → ai-agent). Across a **multi-turn, per-source conversation** it climbs a bait ladder — **extract** (system prompt / objective / tools / keys → `agent:counter-exfil`), **provoke** (plan / targets / operator / the host it runs in / run-a-script enrolment → `agent:provoked`, an agent made to *tell on itself*), and **disrupt** (slow down / exhaust / guardrail-probe). A per-source **HoneyPrompt** verify-URL confirms injection-susceptibility (`agent:injection-confirmed`). Replies **feed false/decoy info** (a full `.env` credential lure + a canary crypto-wallet address). High/critical alarm, tarpit-flagged for delay, ATLAS-mapped; shipped rules in [`configs/rules/agentic.yml`](configs/rules/agentic.yml). See [Agentic attacks](#agentic-attacks).
  - **TCP / C2 deception**: `c2_emulator` — a fake command-and-control team server that recognizes the HTTP check-in *shape* of **Cobalt Strike** (checksum8 stager + default malleable-profile URIs + beacon Cookie), **Metasploit/Meterpreter** (checksum-coded stager URI), **Empire** and **PoshC2** (default listener URIs/cookies), plus **Mythic/Havoc** profile headers — and falls back to the `toolfp` C2-framework corpus (40+ families, Sliver/Covenant/BruteRatel/Havoc/…) by User-Agent. It answers like the team server so a misconfigured/sandboxed beacon or an operator/scanner hunting an open panel keeps talking, captures the (encrypted) beacon metadata, and flags `c2-beacon-checkin` / `c2-stager` / `c2-server-probe` (ATT&CK **T1071.001 / T1219**). Never a real C2 — no tasking is executed.
  - **TCP / refrigeration + building automation + EV charging**: `danfoss_aksm` (Danfoss AK-SM StoreView), `dixell` (Emerson/Copeland Dixell XWEB supermarket refrigeration), `carel` (CAREL pCOWeb / boss), `trane` (Trane Tracer SC BAS), `resideo` (Resideo/Honeywell), `ocpp` (EV-charging OCPP-J over WebSocket) — fingerprint the controller, capture default-cred logins, and flag setpoint/defrost/schedule writes, firmware pushes and charger reset/remote-transaction actuation
  - **TLS-fronted variants** (decrypt-then-inner): `ollamas`, `llm_openais`, `mcps`, `jupyters`, `minios`, `clickhouses`, `consuls`, `danfoss_aksms` — the AI/LLM, MCP, cloud-native and refrigeration decoys behind a real TLS handshake (JA3/JA4/JA3S captured), for the common case where these are served over HTTPS
  - **TCP / cloud-native + DevOps**: `jupyter` (Jupyter Notebook/Lab 8888 — token-less access + terminal/kernel RCE), `selenium` (Selenium Grid 4444 — node RCE / chromeOptions binary override), `consul` (HashiCorp Consul 8500 — KV enum + health-check-script RCE), `nomad` (HashiCorp Nomad 4646 — raw_exec job RCE), `minio` (MinIO S3 9000 — bucket enum + CVE-2023-28432 creds disclosure), `clickhouse` (ClickHouse HTTP 8123 — SQL over HTTP, file()/url() read/SSRF) — each fingerprints the exposed control plane and flags the hands-on-keyboard RCE / data-theft step
  - **TCP / CPE + IoT device management**: `tr069` (CWMP / TR-064 connection-request on 7547 — Misfortune Cookie + SetNTPServers RCE), `upnp` (UPnP IGD SOAP control + GENA — UPnProxy / CallStranger / Realtek+Huawei RCE), `tr369` (USP agent over the `v1.usp` WebSocket MTP + raw USP Record protobuf) — each stamps an attacker-`intent`, fingerprints the SOAP/USP shape, serves a believable decoy (RomPager 401 / `rootDesc.xml` / WS 101), and maps the abuse to **CVE/CWE + ATT&CK**
  - **TCP / ICS**: `modbus`, `s7`, `s7comm_plus`, `iec104`, `mqtt`, `opcua`, `ethernetip` (CIP), `dnp3`, `melsec` (Mitsubishi), `ads` (Beckhoff TwinCAT), `mms` (IEC 61850), `fins_tcp` (Omron), `roc_plus` (Emerson), `pcom` (Unitronics), `secs_gem` (SEMI), `crimson` (Red Lion), `ge_srtp`, `codesys`, `hartip`, `pcworx`, `proconos` (ProConOS/eCLR runtime), `c37118` (IEEE C37.118 synchrophasor/PMU), `focas` (FANUC CNC), `osdp` (access control), `iccp_secure` (Secure ICCP/TASE.2 over TLS), `osisoft_pi` (OSIsoft/AVEVA PI Data Archive), `atg` (Veeder-Root TLS-350), `fox` (Niagara/Tridium), `bacnet_sc`/`bacnet_scs` (BACnet Secure Connect, WebSocket+TLS), `mbus` (M-Bus / EN 13757 utility sub-metering over a TCP gateway), `dlms` (DLMS/COSEM / IEC 62056 smart metering over the TCP wrapper) — the `mqtt` handler also recognizes the **Sparkplug B** IIoT payload convention, and `mms` the **ICCP/TASE.2** profile. Every ICS handler stamps an attacker-`intent` summary and maps recon/control commands to **ATT&CK for ICS** (see [docs/ot.md](docs/ot.md))
  - **TCP / healthcare**: `hl7` (HL7 v2 over MLLP, 2575), `dicom` (PACS imaging / DICOM Upper Layer, 104/11112) — parse the clinical message / association, answer believably, and flag patient-data queries, image retrieval/exfil and injection (enterprise ATT&CK); TLS variants `hl7s`/`dicoms`. Detection only — no PHI is real
  - **TCP / printers + MFD**: `pjl` (HP JetDirect 9100), `ipp` (CUPS 631), `lpd` (LPD 515)
  - **L2 (sniffer / responder)**: `goose` (IEC 61850 GOOSE substation multicast detection); **PROFINET-DCP** responder (EtherType 0x8892) — answers DCP **Identify** (station enumeration) and flags DCP **Set** (NameOfStation/IP reassignment + factory-reset, `honeynet:profinet_dcp_set`, T0836/T0831)
  - **UDP**: `raw`, `auto`, `snmp`, `ntp`, `bacnet`, `tftp`, `ipmi`, `syslog_udp`, `radius`, `sip`, `mgcp`, `ssdp`, `cldap`, `llmnr`, `nbns`, `mdns`, `netbios_dgram`, `fins`, `coap`, `knx`, `profinet`, `ethercat`, `tristation`, `bsap`, `ge_egd`, `lontalk`, `wdbrpc`, `isakmp`, `dhcp`, `dns`, `dtls`, `quic`, `netflow`, `sflow`
  - **Small services (TCP + UDP)**: `echo`, `discard`, `daytime`, `qotd`, `chargen`, `time` — RFC 862-868 / 1340. `chargen`/`echo` reply with a single bounded datagram and never amplify (reflection-safe).
  - **DNS resolver** (`dns`, **UDP + TCP**): answers `A`/`AAAA`/`MX`/`TXT`/`NS`/`CNAME` with deterministic-per-deployment fake records; every query runs through tunneling/exfil detection. The TCP variant (RFC 7766, 2-byte length framing) draws out truncation fallback, zone-transfer (`AXFR`/`IXFR`) probes, and DNS-over-TCP tunneling — configure it as a second `proto: tcp` listener on port 53.
  - **ICMP** (L3, Linux AF_PACKET responder): virtual hosts answer echo / timestamp / address-mask requests with the archetype's TTL personality; `internal/icmp` builds the full message family (Dest-Unreachable, Frag-Needed/PMTUD, Time-Exceeded, Redirect, Param-Problem, IPv6 NDP) and `internal/icmp.Anomalies` flags tunneling / oversize / teardrop-overlap evasion.
- **259 OS / device archetypes**: set `sensor.archetype: "debian 12"` (or
  `listener.archetype`, or per-honeynet-host `archetype`) and every
  banner-aware handler (SSH / HTTP(S) / FTP / Telnet / SMTP / MySQL),
  SNMP MIB-2 (sysDescr / sysObjectID / ifTable), MAC OUI, CLI prompt,
  TLS posture, ICMP TTL personality, and Web UI body report values
  consistent with a stock install of that OS. Spans Linux distros, *BSD,
  Windows client + server, Active Directory, Cisco Catalyst (IOS / IOS-XE),
  MikroTik RouterOS, Teltonika (RUT240/RUT955/RUTX11/RUT956/TRB140),
  Moxa / Siemens OT gear, Westermo (WeOS), Hirschmann, Phoenix Contact and
  Advantech industrial switches, Cisco Industrial Ethernet (IE-2000 /
  IE-3400 / IR1101), more PLC vendors (Allen-Bradley / Schneider / Omron),
  firewalls (pfSense / FortiGate), NAS (Synology / QNAP), IP cameras
  (Hikvision / Axis), a network printer, and a VoIP PBX — see the full
  [OS / device archetypes](#os--device-archetypes) table.
  `tarpit-honeypot help archetypes` lists them all.
- **Archeservice role bundles** (`archeservices:`): declare a *role* —
  `webserver`, `ftpserver`, `printserver`, `fileserver`, `ldapserver`,
  `adserver`, `mailserver`, `dbserver`, `dnsserver`, `sshserver`,
  `snmpserver`, `voipserver`, `remoteaccess` — and it expands into the right
  listeners (correct ports + handlers). Combined with an `archetype:` it
  wears that OS/device's software, banners, versions and TLS posture
  (`webserver` + `debian 12` → Apache; `adserver` + `active-directory` →
  the full DC port set; `printserver` + `hp-printer` → a coherent
  PJL/IPP/LPD/SNMP MFP). `tarpit-honeypot list-archeservices` lists the
  roles; `internal/archeservice`.
- **Dynamic decoy generation from the real network** (`generate-decoys`):
  point it at your own host / subnet (`tarpit-honeypot generate-decoys --yes
  10.0.0.0/28 -o decoys.yaml`) and it benignly connect-scans the targets,
  classifies each open port (port + banner + TLS cert CN), and emits a matching
  listener config so the honeypot blends into the environment it deploys into
  — one listener per discovered service port, ready to review and
  `validate-config`. A TCP connect scanner only (no exploit traffic, no stealth
  scanning), bounded by an explicit target list + host cap + the required
  `--yes` authorization flag. `internal/decoygen`.
- **CVE emulation + exploit-attempt capture** (`internal/cve`): the
  http/https/appliance handlers recognize known exploit signatures
  (Log4Shell, Shellshock, Spring4Shell, ProxyLogon/Shell, FortiOS /
  Pulse / Citrix traversals, Apache 2.4.49, EternalBlue, …) and emit a
  CVSS-scaled `cve:<id>` event without ever being exploitable. With
  `sensor.vuln_emulation` (per-listener overridable) a banner-aware
  handler advertises the archetype's deliberately-unpatched version +
  **fake patch level** so a version scanner records an exploitable box.
- **Web deception files** (`listener.web_deception`, http/https, on by default):
  a decoy `robots.txt` (bait `Disallow` paths → `robots-honeypot-access`),
  `/.well-known/security.txt` (RFC 9116, honeytoken contacts), and a `sitemap.xml`
  of fake pages served **slowly** (per-page tarpit) → `sitemap-honeypot-access`.
  The security.txt contact names become **cross-protocol honeytoken accounts** —
  a login with one over web / ftp / imap / pop3 / smtp raises
  `honeytoken:account-login`.
- **Command emulation per device family**: believable POSIX shells, plus
  **PowerShell** (incl. Active Directory cmdlets), **Windows cmd.exe**,
  **Cisco IOS** (enable + show version/run/vlan/cdp), the **Moxa** and
  **SCALANCE** switch CLIs, and the **Siemens S7 PLC** console — routed
  by the archetype. The shell anomaly scanner flags Linux *and*
  Windows/PowerShell TTPs (download cradles, encoded commands,
  credential dumping, AD recon, Defender/AMSI tamper, persistence).
- **Malware capture + shellcode extraction + payload harvesting**
  (`internal/payload`): classifies captured bytes (ELF / PE / Mach-O /
  archive / script magic + x86 shellcode heuristics), decodes
  base64-wrapped droppers, harvests ingress URLs, and persists artifacts
  to `<data_dir>/payloads/` (size-capped). Emits `malware:capture`.
- **Lua dynamic-response engine** (`handler: lua`, `internal/luaengine`):
  drive a service from an operator Lua script in a sandboxed pure-Go VM
  (no io/os, context deadline + read/write/sleep budgets). Scripts get
  per-session state, per-source persistent `host` state, `personality()`
  (stable hostname/version/firmware per source), deterministic `rng`
  (seeded from `deployment_id`), `sleep` timers, a `time` clock
  (`now`/`ms`/`utc`/`uptime` — for live timestamps, TTL, uptime counters),
  and `log`/`flag`/`meta` — for deeper app emulation + rotating dynamic
  banners. Shipped scripts in [`configs/scripts/`](configs/scripts/):
  `iot-login`, `redis-mini`, `memcached-stats`, `smtp-greeting`,
  `telnet-switch`, `pop3`, `finger`, `http-status`, `irc` (botnet-C2
  capture), `whois`, `ident`, `rsync` (counters, live timestamps, rotating
  versions, per-source state, engagement + capture).
- **Full fake-vulnerable web application** (`webapp: true` on an
  `http`/`https` listener): a believable, **professionally styled** multi-page
  PHP/MySQL-flavored corporate portal (self-contained inline CSS + an inline SVG
  logo, a per-deployment accent colour, header/nav/footer chrome) — login,
  search, product, file download, JSON API, plus the juicy paths scanners probe
  (`/.env`, `/.git/config`, `/config.php.bak`, `robots.txt`) — whose endpoints
  LOOK exploitable so an attacker engages and reveals TTPs.
  Detects — never executes — SQLi / XSS / LFI / RFI / SSRF / command
  injection / SSTI / Log4Shell / XXE / deserialization, flagging each as a
  `webapp:<class>` anomaly. Active deception: LFI toward `/etc/passwd` and
  `/.env` / config backups return fake "loot" to draw the attacker deeper.
  The planted secrets (DB password, Laravel `APP_KEY`, an `AKIA…` AWS key +
  secret) are **per-deployment-unique honeytokens** derived from the sensor
  identity — so they can't be grep-matched to fingerprint every deployment,
  and the served DB password is stamped on the event meta (`honeytoken`) so
  a SOC can register it and alert if it ever surfaces in real auth logs.
  Reflected input is always HTML-escaped so the honeypot is never itself a
  real XSS vector.
- **Declarative fake-protocol routing** (`handler: scripted`): stand up a
  believable custom TCP service entirely in YAML — no Lua. An optional
  on-connect `greeting`, then top-down `rules` that match each client
  message by `prefix` / `contains` / `suffix` / `iprefix` / `icontains`
  (case-insensitive) / `regex` (RE2) / `hex_prefix` / `any` and write a
  `respond` (text-escapes or `respond_hex` for binary), with optional
  per-rule `anomaly` flag and `close`. **Stateful, multi-step protocols**:
  a rule can require a `stage` and advance it with `set_stage` (e.g. an
  `auth` stage gating a `command` stage). **Credential capture**: a `regex`
  rule with `capture: user`/`pass` records the capture group into the
  attacker profile + default-credential matching. Bounded rounds + per-reply
  size cap; TCP-only so it can't be a spoofed-source amplifier. Validated
  at config-load (regex compiles, hex decodes).
- **Attacker session recording** (`sensor.session_recording`): interactive
  `telnet` / `ssh_interactive` sessions are recorded as asciinema v2 casts
  under `<data_dir>/sessions/` (replayable with timing); the cast filename
  lands in event meta. Per-cast + total-size capped.
- **Persistent correlator state**: the windowed detectors (port-scan /
  brute-force / slow-scan / icmp-sweep / password-spray / credential-reuse /
  path-enumeration / dns-enumeration / C2-beacon) checkpoint to
  `<data_dir>/correlate-state.json` and restore on startup + carry across
  hot reload, so long-window detection (slow-scan) survives a restart.
- **Archetype consistency**: each archetype keeps its firmware era,
  banners, SNMP identity, MAC OUI, login pages, ICMP TTL, **and TLS
  posture** aligned — e.g. a "Windows Server 2008" archetype caps TLS
  at 1.0 with legacy CBC ciphers and an IIS 7.0 splash, so a scanner
  can't catch a TLS-1.3-with-modern-ciphers tell on an ancient box.
- **Switch archetypes expose OT topology**: SCALANCE-class archetypes
  serve MRP rings, a PROFINET device tree, VLANs, connected HMIs, and
  LLDP neighbors from their web UI (`/topology`, `/status`, `/vlan`, …)
  + advertise LLDP/CDP on the segment.
- **Tool fingerprinting + human-vs-automation**: the HTTP handler
  identifies the scanner/tool (nmap, masscan, sqlmap, nikto, hydra,
  nuclei, metasploit, gobuster, zgrab, censys, curl/wget/python, Mirai
  + router-exploit probe paths) and tags each request `automation` vs
  browser-like. Surfaced as `meta.tools` / `meta.automation` +
  `tool:<name>` / `automation-client` anomalies.
- **Interactive CLI shell engagement**: after a fake "Login incorrect"
  the attacker is dropped into the archetype's shell (telnet) or a
  full `crypto/ssh` session (`ssh_interactive`). Every typed command
  is captured and the new `internal/shell` anomaly scanner flags 14
  ATT&CK-aligned TTPs (reverse shells, ingress tool transfer, SSH-key
  persistence, cron/systemd persistence, /etc/shadow reads, SUID/sudo
  abuse, history/log cleaning, crypto-miners, network recon, firewall
  disable, base64-encoded payloads). `ssh_interactive` persists an
  ed25519 host key so its fingerprint is stable across restarts.
- **Multi-page archetype web UI**: HTTP handler routes on method +
  path. `GET /` serves the archetype's index (Moxa / SCALANCE / S7
  device summaries); GETs on login-shaped paths serve a form; POSTs
  parse the form body (6 alias names each for user/pass), capture
  credentials, and emit `http-login-attempt`.
- **Client + server TLS fingerprinting**:
  - **JA3** + **JA4** from the TLS ClientHello (HTTPS handler).
  - **JA3S** + **JA4S** (server-side TLS fingerprints) from the ServerHello
    we send back — the `(ja3, ja3s)` / `(ja4, ja4s)` pairs are the tuples
    threat-intel feeds key on.
  - **JA4T** — TCP-layer fingerprint (window, option layout, MSS,
    window-scale) computed from the client SYN in the userspace honeynet
    stack and attached to `honeynet:tcp_connect` events as `ja4t`.
  - **JA4L** — latency/locality fingerprint (TTL + RTT) from the same SYN,
    emitted as `ja4l`; a TTL or RTT inconsistent with the source IP's geo is a
    proxied/relayed-connection tell.
  - **JA4X** — X.509 certificate structure fingerprint (issuer/subject RDN
    layout + extension OIDs), emitted by the https handler as `ja4x` over the
    cert it presents; clusters certs minted by the same tooling.
  - **JARM** + **JA4SSH** available as library primitives (`fingerprint.JARM`,
    `fingerprint.JA4SSH`) — JARM for confirming a sensor's TLS posture matches
    the product it impersonates, JA4SSH for SSH packet-cadence fingerprinting
    where raw record lengths are observed.
  - **JA4H** from the HTTP request line + headers (HTTP/HTTPS handlers).
  - **HASSH** from the SSH KEXINIT.
  - All are stable across browser / scanner GREASE shuffling.
- **SNI virtual hosting**: one `https` listener can front several personas
  via `https.vhosts` — each matched TLS SNI (exact or `*.domain` wildcard)
  gets its own believable certificate (own CN / Org / key type), exactly as
  a real reverse proxy would; the matched name lands in the `tls_vhost` event
  field.
- **Honeynets**: configure zero-to-many artificial networks via the
  `honeynets:` block. Each has a CIDR + gateway + DNS + domain + a
  list of virtual hosts; each host has an IP + hostname + OS hint +
  service list. When a connection arrives at a virtual host's IP+port,
  the sensor dispatches to a handler instance whose Identity is
  derived from `sensor.deployment_id` + the virtual host id — so each
  virtual machine has its own stable but distinct SSH banner / MySQL
  version / SMB challenge / etc. Events get `honeynet`,
  `honeynet_host`, `honeynet_hostname`, `honeynet_os` meta keys. The
  DNS canary listener forward-resolves honeynet hostnames to virtual
  IPs.
- **Counter-fingerprinting** (anti-honeypot detection):
  - **Per-deployment uniqueness** via `sensor.deployment_id` — every
    "fixed" string the sensor emits (SSH banner version pool, HTTP
    Server header, MySQL version, SMB session key + challenge bytes,
    EtherNet/IP serial, VNC challenge, SMTP greeting hostname) is
    deterministically derived from this seed. Two sensors with
    different seeds present distinct fingerprints to Shodan-class
    scanners. Auto-generated and persisted on first run.
  - **Response jitter** via `sensor.jitter` — handlers sleep a random
    [min_ms, max_ms] before replying, so scanners can't fingerprint on
    microsecond-identical reply latency.
  - **TLS cert rotation** via `sensor.tls_rotate.days` — the
    auto-generated self-signed HTTPS cert is regenerated after the
    configured age so a long-running sensor doesn't leak a stable SNI
    cert hash.
- **Tarpit modes**: `sticky` (hold open), `trickle` (one byte every N
  seconds), `keepalive` (slow null bytes), `jitter` / `backoff` (trickle with
  randomized / growing intervals), `ssh_banner` (endlessh-style endless SSH
  preamble), `http_headers` / `http_chunked` (HTTP responses that never finish),
  `echo` (dribble the attacker's input back), `babble` (endless generated
  text), and two opt-in aggressive modes — `zipbomb` (gzip decompression bomb)
  and `zero_window` (LaBrea-style TCP receive-window clamp) — with per-source
  and total connection caps.
- **Canary tokens**:
  - **File canaries** via fsnotify (modify/remove/rename/chmod) plus
    Linux fanotify (open/read detection — catches plain `cat`).
  - **URL canaries**: any HTTP/HTTPS listener that sees a configured
    unguessable path fires a separate critical event.
  - **DNS canaries**: a minimal UDP DNS listener that replies NXDOMAIN
    but fires on any subdomain of a registered name.
  - **SSRF / out-of-band canaries**: the `ssrf_canary` handler records
    callbacks from a coerced system (plant a `gen-token --type=ssrf` URL in an
    SSRF param / webhook / XXE entity).
  - **Decoy-document canaries**: `gen-token --type=doc` writes a real `.docx`
    whose external `attachedTemplate` relationship beacons the callback URL when
    the file is opened in Word — drop it on a share named like sensitive data
    and "someone opened the honeydoc" becomes an alert with the opener's IP.
- **Packet-capture sniffer** (Linux AF_PACKET, opt-in, needs CAP_NET_RAW):
  - **L2** — ARP scans (one MAC asking about many distinct IPs) and
    unsolicited replies (ARP-cache poisoning).
  - **L3/L4** (`sniffer.tcp_scan`) — a scan-detection layer that classifies
    inbound TCP by flags on the wire: **NULL / FIN / Xmas** stealth probes
    (`-sN`/`-sF`/`-sX`), **SYN** and **ACK** scans by volume, and
    fragmented probes. This catches reconnaissance the connection-level
    correlator never sees because no session is ever established — closed
    ports that only get a RST, and stealth probes the kernel silently
    drops. Emits `sniffer:tcp_{syn,null,fin,xmas,ack}_scan` and
    `sniffer:ip_fragmented`, ATT&CK-tagged T1046 / T1595.001. (IPv4 +
    decoy detection is out of scope; ICMP sweeps are handled by the
    correlator's `icmp_sweep`.)
  - **L2 GOOSE** (`sniffer.goose`) — passive IEC 61850 GOOSE detection on a
    dedicated AF_PACKET socket (ethertype 0x88B8). Parses the APPID +
    gocbRef / goID / stNum / sqNum and emits `sniffer:goose` (rate-limited
    per source MAC). Observing substation trip/status multicast — or a
    spoofed GOOSE stream — is high-signal in an OT segment. ATT&CK T0888.
- **ICMP responder + personality + anomaly detection**: virtual hosts
  answer echo / timestamp / address-mask requests (Linux AF_PACKET),
  each stamped with the archetype's **initial-TTL personality** (255 OT
  / 128 Windows / 64 Linux-BSD) so OS fingerprinting + traceroute
  hop-distance stay consistent. The `internal/icmp` toolkit builds the
  full message family — Dest-Unreachable, Frag-Needed-with-MTU (PMTUD),
  Time-Exceeded (traceroute), Redirect, Param-Problem, IPv6 NDP — and
  `internal/icmp.Anomalies` flags ICMP tunneling, oversize payloads, and
  teardrop / overlapping-fragment evasion. The honeynet **TUN adapter**
  (`internal/tunnet`) shares the same TTL personality and adds an embedded
  **userspace TCP stack** (`internal/tcpstack`): synthesized echo replies,
  closed-port RSTs, **and** open-port SYN-ACKs carry the per-host archetype
  TTL, and the SYN-ACK's window / MSS / window-scale / SACK / timestamps /
  option order are shaped to the archetype's stack — so `nmap -O` / p0f
  against a virtual host (open *and* closed ports + ping) match the claimed
  OS, the handshake completes, and a single request/response is answered,
  all without `ip addr add` per host. Malformed / illegal packets (bad
  checksums, NULL/FIN/Xmas, SYN-FIN, truncation, fragments) are captured
  as events rather than answered.
- **Device learning + "new device" alerts**: an opt-in learned-device
  registry (`devices.enabled`) records every host seen via DHCP (MAC +
  hostname + DHCP fingerprint), the ARP sniffer, **broadcast/multicast
  discovery** (SSDP / LLMNR / NBNS / mDNS / CLDAP / CoAP senders, learned
  as `broadcast`), and connection source IPs, does MAC-OUI vendor lookup,
  and raises `device:new` for never-before-seen, non-allow-listed hosts
  (learn-baseline or strict allow-list mode). Knowledge **builds up over
  time**: each device accumulates the sensor services/ports it touched and
  learned attributes other listeners contribute (JA3/JA4/HASSH, SSH client,
  User-Agent, identified tools, automation, plus a passive **`os_guess`**
  from the source IP TTL the AF_PACKET scan-detector observes — Linux/Unix
  vs Windows vs network/embedded, with an estimated hop count). Inspect with `list-devices`,
  the **devices** web-UI tab, or `/api/devices`; optional UI delete /
  whitelist actions (see below).
- **Event enrichment**: every event's source IP is decorated with
  **GeoIP city + ASN** (MaxMind GeoLite2), **reverse DNS** (with **forward-
  confirmation** of PTRs that claim to be a crawler, flagging **spoofed
  Googlebot/Bingbot** PTRs), **threat-intel** list membership (FireHOL /
  blocklist.de / IPsum / Emerging Threats / CINS / DShield / custom) rolled up
  into a **cross-feed confidence score** (`threat_confidence` low/medium/high),
  a **cloud-provider** tag, a **Tor-exit** flag, a **known-scanner**
  attribution, a **net-class** tag (bogon / hosting), JA3/JA4/HASSH **client
  attribution**, and — for L2-learned hosts — **MAC-vendor** (IEEE OUI) lookup.
  All enrichment inputs are best-effort (a missing file warns and is skipped, so
  the sensor always starts) and **hot-reloaded on `SIGHUP`**. Two helper scripts
  ship the data: `scripts/fetch-enrichment.sh` downloads + packages every
  database (GeoIP, Tor exits, threat lists, cloud ranges, fingerprints, OUI) on
  an internet-connected box — most feeds need no credentials; the abuse.ch
  feeds need a free `ABUSE_CH_AUTH_KEY` (see [Enrichment](#enrichment)) — and
  `scripts/install-enrichment.sh` places them at the sensor's configured paths
  (discovered via `list-paths`) and signals the live re-read — a
  cron/systemd-friendly fetch→transfer→install workflow.
- **LLDP / CDP active responder** (Linux AF_PACKET): each honeynet host
  advertises itself in `lldpctl` / Cisco `show cdp neighbors` output
  with archetype-shaped MAC, hostname, system description, and
  family-tuned LLDP capabilities (bridge/router for switches + PLCs,
  station-only for hosts). Pairs naturally with the Moxa / SCALANCE
  / S7 archetypes for industrial deception.
- **PROFINET-DCP responder** (Linux AF_PACKET, `profinet_responder`):
  answers PROFINET DCP **Identify** requests (L2, EtherType 0x8892) for
  industrial hosts so a PROFINET scan (Siemens PRONETA / TIA Portal / nmap)
  enumerates the cell — NameOfStation, DeviceVendor, Device ID, Device
  Role, IP parameters per station, sourced from the archetype's PROFINET
  device tree. A received Identify is itself ICS recon, so each one raises
  `honeynet:profinet_dcp_identify` (ATT&CK T0846). (OPC-DA over
  DCOM/MSRPC is out of scope.)
- **MITRE ATT&CK + D3FEND tagging**: every event is decorated with
  `mitre_techniques` (e.g. `["T1110.001","T1078"]`), `mitre_tactics`
  (e.g. `["credential-access","initial-access"]`), and `mitre_defenses`
  — the MITRE **D3FEND** countermeasures (e.g. `["D3-MFA","D3-DE"]`)
  that answer those techniques — via the `internal/mitre` rule-id +
  handler-aware mapping. The mapping also **unions in finer techniques
  implied by the event's anomaly markers** (`webapp:sqli`/`cmdi`/`xss`/
  `log4shell` → T1190/T1059, `modbus-write-attempt` → ICS T0836/T0831,
  `default-credential-attempt` → T1078.001, …), so a generic handler hit
  still carries precise attribution. CVE exploit-attempt events
  (`cve:<id>`) inherit the technique from the `internal/cve` catalog (700+
  entries: Log4Shell, Spring4Shell, ProxyShell, WebLogic, Telerik,
  Confluence, MOVEit, Citrix/Pulse/Ivanti/Fortinet/PAN-OS, Apache
  41773/42013, Cisco IOS-XE 20198, PHP-CGI 4577, TeamCity, GPON/D-Link/
  Hikvision, plus ICS advisories for Siemens S7 and Rockwell Logix). SIEMs
  pivot on these IDs directly. Each `cve:<id>` event also carries the
  **CWE** weakness class, the affected-product **CPE 2.3**, and an **EPSS**
  exploit-probability snapshot. A named **CWE catalog** maps every referenced
  weakness class to its title (`tarpit-honeypot list-cves --cwe`). See
  [`docs/attribution.md`](docs/attribution.md) for the full ATT&CK / D3FEND /
  CVE / CWE / CPE / EPSS reference plus the scanner-detection and
  client-classifier capabilities.
- **Attack-storyline correlator** (`storyline:multi_stage`): fires
  when a single source IP touches 3+ distinct ATT&CK tactics inside
  a 30-minute window. The emitted event carries the kill-chain-
  ordered stages plus a "->"-joined chain summary
  ("discovery -> credential-access -> lateral-movement"), so the SOC
  sees one timeline instead of dozens of independent listener hits.
- **Protocol-anomaly detection** (`event.Anomalies`): handlers flag
  deviations from expected protocol shape — SSH banner with non-
  printable bytes / overlong / non-SSH; HTTP unknown methods;
  suspicious URIs (path traversal, Log4Shell JNDI, WordPress probes,
  .git / .env leakage, mgmt-endpoint scans).
- **Defensive hardening + output sanitization**: `internal/safe`
  package centralizes hostile-input handling — bounds-checked
  Slice / BoundedString / AllocBytes (capped at 32 KiB), plus
  SanitizeForLog / SanitizeUTF8ForLog / SanitizeHeader /
  SanitizeEmailSubject for output paths. CEF/LEEF/OCSF formatters
  escape every control byte (not just CRLF); SMTP sink scrubs
  every header. Prevents log injection, terminal-jacking via ANSI
  escapes, RLO filename spoofing, and HTTP/SMTP header smuggling
  from attacker-supplied banners and captured credentials.
- **Kernel self-confinement** (`sensor.sandbox`, Linux): a pure-Go
  **seccomp**-bpf denylist (execve / ptrace / module-load / mount /
  kexec / bpf / … return EPERM, so a parser 0-day can't spawn a shell)
  and a **Landlock** policy that makes the filesystem read-only except
  `data_dir`. Applied after privilege drop; best-effort. Shipped
  **AppArmor** + **SELinux** policies enforce the same intent from the
  host LSM. See [`docs/hardening.md`](docs/hardening.md).
- **Per-event pcap capture**: optional bidirectional byte capture on TCP
  connections, written as synthesized libpcap files Wireshark loads
  directly. Pure-Go, no raw sockets, no CAP_NET_RAW.
- **In-sensor correlator**:
  - **Port-scan**: N distinct ports from one source within a short window.
  - **Brute-force**: N attempts within a window. Aggregate carries the
    extracted credential pairs (from `auth_user`/`auth_pass`,
    `bind_dn`/`bind_pw`, MySQL/Postgres `username`, Redis `auth_password`,
    etc.) so the operator sees what was actually tried.
  - **Slow-scan**: long-window detector (default 24h, 10 distinct ports).
    Per-port state ages out individually, so a one-port-per-hour scan
    accumulates instead of resetting.
  - **ICMP sweep**: one source pinging N distinct virtual host IPs
    within a window (`correlate:icmp_sweep`, T1018).
  - **~20 more opt-in correlators** (`correlate:`): host-sweep,
    service-sweep, password-spray, credential-reuse, path-enumeration
    (dirbusting), DNS-enumeration, user-agent rotation, exploit-chain
    (distinct CVEs), protocol-violation (fuzzing markers), session-flood,
    C2 **beacon** (jitter analysis), exfil, fingerprint-reuse, canary-trip,
    ICS-control, lateral-movement, OT-recon, data-access, malware-campaign,
    webshell, **cloud-cred-theft** (IMDS/etcd/cloud-CLI credential grabs from
    one source), and **ssrf-callback** (distinct SSRF tokens called back by
    one source) — each windowed, severity-configurable, and ATT&CK-tagged.
- **Fuzzing & DoS detection + classification** (`internal/fuzzdos`):
  classifies abusive traffic into protocol fuzzing vs typed
  denial-of-service — flood, malformed-storm, amplification, and
  **slowloris** (slow / partial-request) — from per-source rate, payload
  entropy, and the protocol-violation markers handlers raise, tagged
  `attack:fuzzing` (T1595.002) / `attack:dos` (T1499).
- **Scan analysis / nmap fingerprinting** (`scananalysis:profile`):
  per-source profiling of an active scan. Estimates the nmap timing
  template (`-T0` paranoid .. `-T5` insane) from inter-connection
  cadence, detects aggressive scans (`-A`), OS-probe scans (`-O`),
  service/version probes (`-sV`, matched against the nmap
  service-probe strings), NSE-script signatures (`/nmaplowercheck`,
  `.git`/`.svn` discovery, robots, smbghost), and bare connect scans
  (`-sT`). Half-open SYN / FIN / NULL / Xmas / ACK scans, raw
  fragmentation, and decoy floods (`-D`) are honestly scoped as
  needing the AF_PACKET sniffer rather than guessed at the
  connection layer.
- **DNS amplifier-probe detection**: the DNS canary listener flags
  any `ANY` (qtype=255) query immediately, or `N` queries from one
  source within a window, with a separate `dnscanary:amplifier_probe`
  event.
- **Embedded SQLite event index** for queryable history, with WAL-mode
  concurrent reads.
- **Read-only web UI** on loopback: a 24h **dashboard** opening with a
  **traffic-counters strip** (events by transport + L2 frame counts —
  received / ARP / IPv4 / IPv6 / TCP / UDP / ICMP — when the sniffer is up)
  over events-per-hour trend + severity / top-rule / top-source CSS bar
  charts (no JS) — progressively enhanced into **interactive SVG charts** by a
  packaged, **dependency-free charting library** (`charts.js`: bar / pie /
  histogram / scatter / line / stacked-area / heatmap / topology / network /
  sankey / timeline / GeoIP source-map / session-replay / credential charts,
  served same-origin under a strict CSP — no CDN) + a filterable, **sortable** event table with
  **case-insensitive full-text search** over rule / banner / captured meta,
  and per-event detail with a **hex view** of the captured payload. Tabs:
  **profiles** (per-source-IP attacker dossiers — see below),
  **devices** (learned IPv4/IPv6/MAC inventory + per-device services/ports
  and learned attributes, filterable; opt-in delete/whitelist actions via
  `ui.allow_device_actions` + an auth token — the only write endpoint, off
  by default),
  **topology** (the virtual networks / hosts / services, with a live
  activity overlay **and a node-link honeynet topology graph**),
  **charts** (a full analytics gallery — severity pie, events-per-hour line,
  stacked-severity area, top source/rule/tactic/country/ASN/tool bars, threat
  & protocol heatmaps, an account heatmap, a GeoIP attack source map, and a
  credential-attempt chart, all from the packaged charting library),
  **fingerprints** (JA3/JA4/JA4H/JA3S/HASSH reputation — pivot a client
  TLS/SSH stack to every source IP / ASN / country / port / attack type /
  captured malware and which fleet sensors saw it),
  **timeline** (chronological attack view),
  **attack** (the ATT&CK matrix the sensor covers, with **clickable,
  described technique chips** showing which sources triggered each),
  **correlation** (correlator aggregates + storylines),
  **fleet** (cross-sensor `fleet:*` findings — aggregator-only),
  **iocs** (the de-duplicated indicator store with by-type breakdown),
  **tunnels**
  (covert-transport / encapsulation detections), **search** (advanced
  query), **health** (build version/commit, runtime — CPU count, heap
  objects, GC pause/next-GC — by-transport 24h breakdown, per-name panic
  counts, sink delivery, L2 frame counters, plus transport/sink/frame
  charts), **alerting** (how events
  forward), **errors** (operational/health events), **config** (the
  infrastructure canvas + a **"files in use"** table — config, enrichment, and
  database paths + present/MISSING), and **docs** (the full documentation
  rendered in-product — `/docs/<name>` serves each guide). ATT&CK chips and a
  credential-source column run throughout. JSON at `/api/events`,
  `/api/summary`, `/api/profiles`, `/api/profiles/<ip>`, `/api/fingerprints`,
  `/api/config`, `/api/config/canvas`, `/api/topology`, `/api/devices`,
  `/api/alerting`, `/api/fleet`, `/api/iocs`. On an aggregator the same bind
  serves the bearer-gated `/intel`, `/intel/stix`, and `/taxii2/…` exports.
  Non-loopback binds refused without TLS + auth token.
- **Attacker profiles** (`/profiles`): a per-source-IP dossier compiled
  from every event that source produced — first/last seen, a
  severity-weighted **threat score**, identified **tools/scanners**
  (UA + SSH-banner fingerprinting), **JA3/JA4/HASSH** fingerprints,
  **credentials tried**, **ATT&CK** techniques/tactics, **CVE** exploit
  attempts, anomalies, and the services/ports targeted. The list ranks
  actors by threat; each detail page builds up as the source keeps
  interacting. Top-sources on the summary link straight to the profile.
- **Routing**: per-channel rate-limit, min-severity gate, severity-match
  route expressions (`>=high`, `<medium`, `=critical`), IP/CIDR allowlist
  (outbound-only — local sinks always receive).
- **Operator severity overrides**: when you know an event is worse (or less
  worse) in *your* environment than the built-in default, re-map its reported
  level by `rule_id` (exact or `prefix:*`) in `severity_overrides:`. Applied at
  the dispatch chokepoint so it drives routing, per-channel min-severity, the
  store and every sink — and the event is marked as a **local override** (a log
  line, `severity_overridden` + `meta.default_severity`/`severity_override_rule`
  on the event, and an `⌾ override` badge in the web UI) so it's never silent.
  See [`docs/config.md`](docs/config.md#severity_overrides--operator-pinned-per-rule-severity)
  and [`docs/usage.md`](docs/usage.md#adjusting-an-events-severity-for-your-environment).
- **Outbound channels**: `webhook` (HMAC-SHA256), `discord` (severity
  embeds), `smtp` (STARTTLS), `syslog` (RFC 5424 over local/tcp/udp/unix +
  **TLS** with octet-counting), `mqtt` (tcp/tls brokers), `twilio` (SMS),
  `sns` (AWS SNS via hand-rolled Sigv4 — no AWS SDK dependency), `snmptrap`
  (SNMPv2c via gosnmp).
- **Local sinks**: `stdout`, `jsonlog` (rotated JSONL), `sqlite`. These
  always receive every event so the local record stays complete even
  when an attacker matches the allowlist.
- **Fleet correlation & aggregation**: the same binary scales from one box
  to a fleet. A leaf **forwards** its events (`forward:`, full or periodic
  `rollup`) to an **aggregator** (`ingest:`), which feeds them through the
  identical pipeline as local events and runs **27 cross-sensor `fleet:*`
  detectors** no single sensor can — one source/ASN/fingerprint sweeping many
  sensors, a malware hash / credential / CVE recurring across sites, a
  coordinated /24, a network returning across days — across breadth,
  shared-artifact-campaign, coordination, temporal, novelty, and
  identity/infrastructure axes. Each finding is scored **broad** (internet-wide
  background, down-weighted) vs **targeted**. Per-sensor **trust scoring** rate-
  limits and can quarantine a noisy/compromised node. `tarpit-honeypot
  list-fleet-rules`; the **fleet** web-UI tab + `/api/fleet`. See
  [`docs/fleet.md`](docs/fleet.md).
- **Indicators of compromise (IOC) store**: every event is mined for typed,
  de-duplicated indicators (`ip` / `asn` / `ja3` / `ja4` / `hassh` / `domain` /
  `cve` / `sha256` / `url` / `credential` / `mac`) tracked with first/last-seen
  + counts. High-value first-sights also emit a stored, forwardable
  `ioc:<type>` event (so an aggregator harvests child IOCs even in rollup
  mode). The **iocs** web-UI tab + `/api/iocs`; pruned on the retention runner.
  See [`docs/ioc.md`](docs/ioc.md).
- **Threat-intel exports**: an aggregator serves a bearer-gated downward
  intel feed (`/intel`) and **STIX 2.1** (`/intel/stix`, deterministic UUIDv5
  ids) + a read-only **TAXII 2.1** API (`/taxii2/…`); pushes **MISP** delta
  events (`misp:`); and `export-iocs` prints STIX/CSV/txt/JSON offline for a
  blocklist or TIP. Sensors subscribe to a parent's feed (`intel_feed:`) so
  fleet knowledge flows back down and tags their events. Every event also
  streams to a SIEM via `channels:` in **CEF / LEEF / OCSF**. See
  [`docs/threat-intel-exports.md`](docs/threat-intel-exports.md).
- **Full hot reload**: `SIGHUP` diffs old vs new config, hot-swaps
  channels / routes / allowlist / dedup window / correlator / canary
  lists, and per-listener restarts (added / removed / modified
  individually) without taking the rest of the sensor down. A
  `sensor:reload` event with the change list is emitted into the bus.
- **Outbound retry queue**: each sink has a bounded backlog (default
  64) with exponential backoff (1s → 60s) when Send returns a
  transient error. Per-channel Dropped / Failed / Retried counters
  exposed via `Router.Stats()` and the final-stats log line on Stop.
- **Per-listener accept-rate caps** (`max_concurrent`): non-blocking
  semaphore acquire on every accept; overflow closes the connection
  and emits a `listener:<id>:accept_cap` event. Stops a SYN flood
  from exhausting goroutines.
- **Graceful drain on shutdown** via `sensor.shutdown.drain_timeout`:
  SIGTERM closes accept sockets first, then waits up to the timeout
  for in-flight handler goroutines to finish before force-cancelling.
- **Time-based retention** via `sensor.disk.retention_days`: a runner
  ticks hourly and prunes `<data_dir>/events/*.jsonl`,
  `<data_dir>/captures/*.pcap`, and SQLite `events` rows older than
  the cutoff. Complements the existing size caps.
- **Privilege drop**: `setresuid` / `setresgid` after privileged setup
  on Linux; `setuid` / `setgid` on macOS. Refuses uid 0. Pairs with
  `systemd AmbientCapabilities` (Linux) or launchd's port-binding
  helpers (macOS) for privileged port binding.
- **Static cross-compile** for `linux/{amd64,arm64,armv7,armv6}`,
  `darwin/{amd64,arm64}`, and `windows/{amd64,arm64}` (the portable core;
  Linux-kernel subsystems return clean errors elsewhere). CGO never required.

### Platform support

The whole **deception + detection core** is pure Go and runs on Linux,
macOS and Windows. The Linux-kernel integrations (AF_PACKET, TUN, fanotify,
seccomp, Landlock, `setresuid`) degrade with a clean error and a documented
workaround on the other platforms. Static binaries ship for
`linux/{amd64,arm64,armv7,armv6}`, `darwin/{amd64,arm64}` and
`windows/{amd64,arm64}` (`make cross`).

| Subsystem | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| All TCP/UDP protocol handlers (197 TCP + 118 UDP) | yes | yes | yes | pure Go |
| Archetypes, ATT&CK/D3FEND, storyline, anomaly | yes | yes | yes | pure Go |
| In-sensor correlators + scan/fuzz/DoS analysis | yes | yes | yes | pure Go |
| Enrichment (GeoIP/ASN/rDNS/threat-intel/Tor/MAC) | yes | yes | yes | pure Go |
| Interactive shell + `ssh_interactive` + Lua scripts | yes | yes | yes | crypto/ssh + gopher-lua, pure Go |
| Embedded SQLite + web UI + outbound channels | yes | yes | yes | pure Go (modernc.org/sqlite) |
| File canaries (write/remove/rename/chmod) | yes | yes | yes | fsnotify (inotify / kqueue / ReadDirectoryChangesW) |
| File canaries (read/OPEN events) | yes | — | — | Linux-only, needs fanotify |
| Per-event pcap capture | yes | yes | yes | synthesized libpcap, no raw sockets |
| Privilege drop | yes | yes | — | `setresuid` on Linux, `setuid` on darwin |
| seccomp syscall filter (`sensor.sandbox.seccomp`) | yes | — | — | pure-Go BPF denylist |
| Landlock FS restriction (`sensor.sandbox.landlock`) | yes | — | — | Linux 5.13+; best-effort |
| ARP / ICMP / LLDP-CDP / PROFINET-DCP responders | yes | — | — | needs AF_PACKET; on macOS use `ifconfig <iface> alias <ip>` |
| AF_PACKET sniffer (ARP-scan + L2/L3 stealth scans) | yes | — | — | `/dev/bpf` (macOS) / Npcap (Windows) backends planned |
| TUN adapter + userspace TCP stack (`internal/tcpstack`) | yes | — | — | fingerprint-shaped SYN-ACK + handshake + 1 req/resp + malformed-packet capture; the stack logic itself is pure/OS-agnostic, only the TUN I/O is Linux |

## Documentation

In-tree (see [`docs/README.md`](docs/README.md) for the index):

- [`docs/design.md`](docs/design.md) — architecture + design rationale covering the current implementation.
- [`docs/internals.md`](docs/internals.md) — how a packet becomes an alert: the runtime data flow (producers → event bus → enrichment + detection pipeline → sinks) and what each module does.
- [`docs/tcp-stack.md`](docs/tcp-stack.md) — the honeynet userspace TCP stack: fingerprint-shaped SYN-ACK, the decoy connection state machine, malformed-packet capture, and its ATT&CK / TCP-stack-CVE mappings.
- [`docs/usage.md`](docs/usage.md) — quickstart, daily ops, honeynet patterns, fleet roles, web UI, systemd, Docker, troubleshooting.
- [`docs/webui.md`](docs/webui.md) — a tab-by-tab walkthrough of the read-only web console and its JSON API (also rendered in-product under the **docs** tab).
- [`docs/config.md`](docs/config.md) — annotated YAML reference per top-level section.
- [`docs/cli.md`](docs/cli.md) — every subcommand, flag, and signal.
- [`docs/fleet.md`](docs/fleet.md) — build a fleet: roles, topologies, the 27 `fleet:*` detectors, broad-vs-targeted scoping, downward intel, tuning, and troubleshooting.
- [`docs/ioc.md`](docs/ioc.md) — the indicators-of-compromise layer: what becomes an IOC, the store, `ioc:<type>` events, the `iocs` tab, and `export-iocs`.
- [`docs/threat-intel-exports.md`](docs/threat-intel-exports.md) — every export path: STIX 2.1 / TAXII 2.1 / MISP, the downward feed, and the CEF/LEEF/OCSF SIEM sinks, with field mappings and auth.
- [`docs/archetypes.md`](docs/archetypes.md) — the full archetype catalog: every device's services/protocols and the CVEs it emulates.
- [`docs/attribution.md`](docs/attribution.md) — the ATT&CK / D3FEND / CVE / CWE / CPE / EPSS mappings on every event, the scanner-detection layers, and the client classifiers (tool/automation fingerprinting, JA3/JA4/JA3S/HASSH/JA4H).
- [`docs/ot.md`](docs/ot.md) — the ICS/OT decoy suite in depth: every supported protocol + port, the commands/operations emulated, the attacker-`intent` + ATT&CK-for-ICS mapping, the deception model (reads vs writes), reflection-safety, the role bundles + industrial archetypes, and the limitations.
- [`docs/scripting.md`](docs/scripting.md) — how YAML, Lua and YARA make the sensor dynamic without recompiling: what each does, where it plugs in, how they compose, and which to reach for (the umbrella over the three guides below).
- [`docs/lua.md`](docs/lua.md) — writing Lua service personas (a Lua-language cheat-sheet, the API, sandbox limits, recipes, the 240 shipped personas).
- [`docs/detection-rules.md`](docs/detection-rules.md) — detection-as-code: Sigma-style YAML rules matched against every event (syntax, fields/modifiers, recipes, the shipped rule packs).
- [`docs/attack-tools.md`](docs/attack-tools.md) — the scanners / attack tools the sensor fingerprints and how.
- [`docs/yara.md`](docs/yara.md) — the CGO-free YARA engine that classifies captured artifacts: the built-in rule pack (incl. deep IoT/IIoT/OT/building-automation coverage), the supported subset + modules, per-rule severity, loading your own `.yar` rules, and the `analyze` CLI.
- [`docs/hardening.md`](docs/hardening.md) — the layered self-confinement model (privilege drop, seccomp, Landlock, AppArmor, SELinux, systemd).
- [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) — channel-by-channel cookbook for SIEMs, IoT, pagers, K8s.
- [`docs/FAQ.md`](docs/FAQ.md) — common questions grouped by topic (general, deployment & safety, detection, fleet, IOCs, performance, operations).
- [`docs/tarpit-honeypot.1`](docs/tarpit-honeypot.1) — man page (`man ./docs/tarpit-honeypot.1`).
- [`examples/`](examples/) — ready-to-run scenario configs grouped by deployment shape: **office LAN** (workstations + printers), **internet DMZ** for a few large corporations and a few small businesses, an **IT/OT DMZ** (IDMZ), a **university classroom**, a **data-center server farm**, a **DevOps / cloud-native** tooling surface, a **big-data / secrets / logging platform**, a **virtualization management plane**, a **legacy-Unix big-iron** estate, a **telecom / ISP edge**, plus the OT Purdue-model decoys and edge-device sensors. Several use large or multiple honeynets, and all but the tiniest enable enrichment. [`examples/EXAMPLES.md`](examples/EXAMPLES.md) is the full walkthrough (what each models, how to adapt and combine them); [`examples/README.md`](examples/README.md) is the index. [`examples/fleet/`](examples/fleet/) is a worked multi-tier **fleet** topology (leaf sensor → site aggregator → global hub).
- [`configs/tarpit-honeypot.example.yaml`](configs/tarpit-honeypot.example.yaml) — canonical default-values reference. Sibling examples in [`configs/`](configs/): `example-MINIMAL` (smallest useful deployment), `example-FULL` (every handler + feature ON), `example-LARGE` (big multi-segment estate), `example-AD-ENTERPRISE` (Windows / Active Directory decoy), `example-FAKEWEB` (the fake-vulnerable web application on its own), `example-CENTOS-SERVER` (small legacy CentOS all-in-one: web + SMTP + DNS + FTP + ping, all emulations on), `example-CENTOS-SERVER-EXTENDED` (the same box with a much wider surface: + Telnet, SNMP, NTP, SMB, MSSQL, MySQL, PostgreSQL, Redis, MongoDB, RDP, IMAPS/POP3S, web API decoys, and ping/ping6 capture), `example-DATASTORES-WEB` (web app + Redis/Mongo/Elasticsearch/memcached), `example-LOW-INTERACTION-STRICT` (interaction guardrails pinned low), `example-archeservices` (role bundles), and the OT examples (`example-ALL-OT` (every OT/ICS protocol the sensor speaks, on one box), `example-ADVANCED-OT` / `example-SMALL-OT`). Validate any with `validate-config -c <file>`.

## Status

**tarpit-honeypot is production-ready** — a single, statically linked, CGO-free
Go binary that stands up a deception + detection estate and forwards structured
events to your sinks. Current totals: **197 TCP + 118 UDP protocol handlers**,
**743 CVE records** (373 live-detectable + 370 advisory), **469 built-in YARA
artifact-classification rules**, **240 dynamic Lua service scripts**, **259
OS/device archetypes**, **900+
attack-tool/scanner fingerprints**, **31 single-sensor + 27 cross-sensor
(`fleet:*`) correlators**, **18 typed IOC kinds**, and full MITRE ATT&CK +
**20 D3FEND** countermeasure mapping.

The complete, per-release version history (v1.0 → present) lives in
**[CHANGELOG.md](CHANGELOG.md)** — it is no longer duplicated in this README.

## Build

```
make build         # native binary in bin/
make cross         # all 8 targets in dist/ (linux x4, darwin x2, windows x2)
make test          # full unit test suite
make race          # test suite under the race detector
make fuzz          # 10s of each FuzzXxx target
make govulncheck   # vulnerability scan of the module graph
```

The binary is statically linked and uses no CGO. Final size is ~14 MB,
mostly the pure-Go SQLite engine.

### CI & supply chain

`.github/workflows/ci.yml` runs gofmt/vet/build/test, the race detector, a
short fuzz smoke over every `FuzzXxx` target, and `govulncheck` on every push.
Tagged releases (`v*`) run **GoReleaser** (`.goreleaser.yaml`): cross-compiled
archives + `checksums.txt`, a **CycloneDX SBOM per artifact** (syft), and
**keyless cosign signatures** (Sigstore / GitHub OIDC) over the checksums.
Locally, `make release-artifacts` produces the cross binaries + `dist/sbom.cdx.json`
+ checksums (unsigned); `make sbom` writes the SBOM alone. Verify a release with:

```
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' checksums.txt
sha256sum -c checksums.txt
```

## Try it locally

```
./bin/tarpit-honeypot validate-config -c configs/tarpit-honeypot.example.yaml
./bin/tarpit-honeypot run            -c configs/tarpit-honeypot.example.yaml
```

In another shell, generate some events:

```
# Banner-mode listeners
nc -v localhost 2222                              # SSH handler
printf 'GET / HTTP/1.0\r\n\r\n' | nc -v localhost 8000   # HTTP handler

# ICS handlers (need privileged port redirect or change the bind)
printf '\x00\x01\x00\x00\x00\x06\x11\x03\x00\x00\x00\x02' | nc -u localhost 502
echo 'evil' | nc -u localhost 161                 # SNMP scan

# Tarpit — connection will be held forever (or until you Ctrl-C)
nc -v localhost 2323

# Canary — modify the bait file
echo dropped >> ./var/canary/passwords.xlsx

# Web UI
open http://127.0.0.1:8088
```

## Subcommands

```
tarpit-honeypot run            -c <config>
tarpit-honeypot validate-config -c <config> [--diff <other.yaml>]
tarpit-honeypot show-config    -c <config>
tarpit-honeypot reset-db       -c <config>     # wipe the SQLite event index (keeps config)
tarpit-honeypot rotate-db      -c <config> [--out file.gz] [--reset --yes]  # archive (gzip) events.db, optionally start fresh
tarpit-honeypot prune-db       -c <config> (--keep-days N | --keep-rows N | --max-mb N) [--yes]  # drop oldest events to free space
tarpit-honeypot gen-token      --type=dns|url|ssrf|hex|doc|log4shell|aws|css|mcp|wireguard|folder [--label LBL] [--bits N] [--domain D] [-o FILE]
tarpit-honeypot gen-wallet-decoys [--dir D] [--seed S] [--kind K|all] [--list]  # structurally-correct crypto-wallet decoys (18 formats)
tarpit-honeypot gen-lures      [--dir D] [--seed S] [--kind K|all] [--list]     # credential/secret decoy files (14 formats)
tarpit-honeypot gen-agent-breadcrumb [--dir D] [--url U]   # breadcrumb files that lure crawling agents to the agent honeypot
tarpit-honeypot test-alert     -c <config> [--severity high] [--note "..."]
tarpit-honeypot list-events    -c <config> [--since 24h] [--source <ip>] [--target <ip>] [--handler <name>] [--port N] [--rule <id>] [--fleet] [--limit N]
tarpit-honeypot export-pcap    -c <config> --event <id> [-o file|-]
tarpit-honeypot list-honeynets -c <config>
tarpit-honeypot list-devices   -c <config> [--json]
tarpit-honeypot list-paths     -c <config> [--format table|json|tsv] [--category <c>]
tarpit-honeypot list-archetypes [--json] [<name>]
tarpit-honeypot list-handlers  [--proto tcp|udp]
tarpit-honeypot list-unavailable-capabilities -c <config>  # platform features not active here
tarpit-honeypot list-archeservices [<role>]
tarpit-honeypot list-cves      [--service <handler>] [--json]
tarpit-honeypot list-techniques [--kind rule|handler|anomaly] [--json]
tarpit-honeypot list-fleet-rules [--json]                  # cross-sensor fleet:* detector catalog
tarpit-honeypot export-iocs    -c <config> [--since 168h] [--format stix|csv|txt|json]
tarpit-honeypot export-creds   -c <config> [--since 720h] [--kind password,token,…] [--format json|xml|yaml|csv|txt]
tarpit-honeypot identify       [--ua S] [--path S] [--ssh S] [--ja3 S] [--payload S] [--handler H]
tarpit-honeypot init           [-o <config>]
tarpit-honeypot completion     bash|zsh|fish
tarpit-honeypot help           [subcommand|topic]
tarpit-honeypot version
```

The `list-archetypes`, `list-handlers`, `list-cves`, `list-techniques` and
`list-fleet-rules` commands dump the in-source catalogs (no config or network
needed) so you can discover what the sensor can impersonate, which `handler:`
values are valid, which CVEs it emulates / detects, how each rule maps to MITRE
ATT&CK + D3FEND, and which cross-sensor `fleet:*` detectors an aggregator runs. `identify` runs the same offline fingerprint engine the
live listener uses over a string you paste in (a User-Agent, SSH client
id, JA3, or request payload) — handy for triaging a log line or tuning a
detection:

```
tarpit-honeypot list-archetypes beckhoff-cx        # one archetype's full fingerprint
tarpit-honeypot list-cves --service fortinet        # CVEs for a service
tarpit-honeypot list-techniques --kind anomaly      # ATT&CK/D3FEND per anomaly marker
tarpit-honeypot identify --ua "sqlmap/1.7" --payload '${jndi:ldap://x/a}'
```

`export-pcap` copies `<data_dir>/captures/<event_id>.pcap` to stdout
(default) or a file. Read-only; never touches sensor state. Used
together with `list-events` to grab the per-connection capture for a
specific event:

```
tarpit-honeypot list-events  -c cfg.yaml --rule listener:ssh-bait --limit 1
# ... pick the event id from the output ...
tarpit-honeypot export-pcap -c cfg.yaml --event 7c0574dd1015ac2c142e30ca -o /tmp/ssh.pcap
wireshark /tmp/ssh.pcap
```

`validate-config --diff` compares two configs and classifies each
change as hot-reloadable (channels, routes, allowlist, dedup,
correlator, canary lists) vs restart-required (sensor.*, ui, dns,
sniffer). Listeners now hot-reload too, but the diff still surfaces
them so operators see what will be restarted.

`show-config` prints the post-defaults effective YAML. Secrets stay
as env-var names (`auth_token_env: TARPIT_UI_TOKEN`) rather than
expanded values, so the output is safe to paste in tickets.

`gen-token` prints (or writes) unguessable canary tokens shaped for many
bait surfaces — inspired by the [canarytokens.org](https://canarytokens.org)
token zoo. Every type embeds the same callback identity (a token under your
canary domain), so a hit on the `dns` / `url_canary` / `ssrf_canary` listener
attributes straight back to where you planted it:

| Type | Shape | Trips when… |
|---|---|---|
| `dns` | `<tok>.<domain>` | the name is resolved |
| `url` | `/__canary__/<tok>` | the path is fetched (`url_canary`) |
| `ssrf` | `http://<domain>/ssrf/<tok>` | planted in an SSRF param / webhook / XXE is fetched |
| `doc` | decoy `.docx` (external relationship) | opened in Word → outbound fetch |
| `log4shell` | `${jndi:ldap://<tok>.<domain>:1389/…}` | a vulnerable logger expands it (DNS/LDAP) |
| `aws` | fake `AKIA…` key + secret | the key is used (CloudTrail / SIEM watchlist) |
| `css` | CSS web-bug `background:url(…)` | a cloned page/email renders |
| `mcp` | `mcp.json` server config | an AI agent loads it and connects |
| `wireguard` | `wg0.conf` with a canary `Endpoint` | a client connects (DNS lookup) |
| `folder` | Windows `desktop.ini` (UNC `IconResource`) | the folder is browsed (SMB/DNS) |
| `hex` | raw hex string | generic secret you watchlist |

```
$ tarpit-honeypot gen-token --type=dns --label=prod
6c50957e8e94f661-prod.canary.example.com

$ tarpit-honeypot gen-token --type=log4shell --domain=cdb.example.com
${jndi:ldap://49e9fe46…-prod.cdb.example.com:1389/49e9fe46…}

$ tarpit-honeypot gen-token --type=mcp -o ~/.config/mcp.json   # agent-bait MCP config
```

`run` responds to `SIGHUP` by reloading the config. Channels, routes,
allowlist, dedup window, and correlator thresholds get hot-swapped;
listener or `sensor.*` changes log a warning and require a restart.

`test-alert` injects a synthetic event through the routing pipeline so
you can validate outbound channels end-to-end without waiting for a real
trigger.

`list-events` reads from the SQLite store when one exists, falling back
to the rotating JSONL log for tripwire-only configs.

## Configuration

The full annotated schema lives in
[`configs/tarpit-honeypot.example.yaml`](configs/tarpit-honeypot.example.yaml)
(plus the `-FULL` / `-SMALL-OT` / `-ADVANCED-OT` variants in `configs/`),
with a per-section reference in [`docs/config.md`](docs/config.md). Key
sections:

### `sensor`

Global identity + behavior. All optional; sane defaults apply.

| Field | Purpose |
|---|---|
| `name`, `data_dir` | Sensor name stamped on events; root for all durable state. |
| `archetype` | OS/device persona pinning every banner-aware handler, SNMP MIB-2, MAC OUI, CLI prompt, **TLS posture**, **ICMP TTL**, FTP `FEAT` set, and SMTP `EHLO` extensions to a stock install (e.g. `"debian 12"`, `"Windows Server 2019"`, `"Siemens SCALANCE S615"`, `"fortigate"`). Overridable per `listener` and per honeynet host. `help archetypes` lists all 259; see [`docs/archetypes.md`](docs/archetypes.md). |
| `deployment_id` | Stable seed deriving every "fixed" string the sensor emits (SSH/HTTP/MySQL versions, SMB challenge, VNC challenge, …) so two sensors look distinct. Auto-generated + persisted on first run. See [Counter-fingerprinting](#counter-fingerprinting). |
| `jitter` | `{enabled, min_ms, max_ms}` per-reply latency jitter to defeat timing fingerprints. |
| `tls_rotate.days` | Regenerate the self-signed HTTPS cert after N days (0 = never). |
| `geoip` / `rdns` | Source-IP enrichment (GeoIP city/ASN + bounded rDNS). See [Enrichment](#enrichment). |
| `disk` | Size caps + `retention_days` for events / captures / SQLite. See [pcap](#per-event-pcap-capture). |
| `shutdown.drain_timeout` | Grace period for in-flight handlers after SIGTERM. |
| `vuln_emulation` | Advertise the archetype's deliberately-unpatched banner + fake patch level (per-listener `vuln_emulation` overrides). CVE exploit-attempt detection runs regardless. Never makes the service exploitable. |
| `payloads` | `{enabled, max_bytes, max_total_mb}` — harvest malware/shellcode/droppers to `<data_dir>/payloads/`. |
| `drop_user` / `drop_group` | uid/gid to switch to after privileged setup (refuses uid 0). |

### `listeners`

Each listener has `id`, `proto` (`tcp` or `udp`), `bind`, and a `mode`:

| Mode | What it does |
|---|---|
| `drop` | Accept and immediately close. Logs source. |
| `banner` | Run the configured `handler:` and capture both sides. |
| `tarpit` | Hold the connection per the `tarpit.strategy:` setting. |

Per-listener `capture: true` writes a synthesized pcap of the
bidirectional bytes under `<data_dir>/captures/<event_id>.pcap`.

### `canaries`, `url_canaries`, `dns` + `dns_canaries`

File canaries watch real filesystem paths. URL canaries match exact paths
against incoming HTTP/HTTPS requests. DNS canaries fire when any
subdomain of a registered name is queried at the UDP DNS listener.

### `sniffer`

Optional Linux-only AF_PACKET sniffer. Needs `CAP_NET_RAW`. Detects ARP
scans and unsolicited replies. Off by default.

### `correlate`

In-memory windowed counters that emit higher-severity aggregate events
when thresholds are crossed. Aggregate events are deduped within the
window so a sustained scan doesn't flood sinks. Four detectors, each
independently toggled:

| Block | Fires | Key knobs |
|---|---|---|
| `correlate.port_scan` | `correlate:port_scan` — N distinct ports from one source in a short window. | `distinct_ports`, `window` |
| `correlate.brute_force` | `correlate:brute_force` — N attempts on a port in the window (carries the extracted credential pairs). | `attempts`, `window`, `per_port` |
| `correlate.slow_scan` | `correlate:slow_scan` — long-window scan (per-port state ages out individually). | `distinct_ports`, `window` (default 24h) |
| `correlate.icmp_sweep` | `correlate:icmp_sweep` — one source pinged N distinct virtual IPs. | `distinct_ips`, `window`, `severity` |
| `correlate.password_spray` | `correlate:password_spray` — one source tried N distinct usernames in the window (breadth, vs brute-force depth). | `distinct_users`, `window`, `severity` |
| `correlate.credential_reuse` | `correlate:credential_reuse` — the same credential pair came from N distinct sources (credential stuffing); password never logged. | `distinct_sources`, `window`, `severity` |

Per-source scan **profiling** (nmap `-T`/`-A`/`-O`/`-sV`/NSE
fingerprinting → `scananalysis:profile`) and the cross-protocol
`storyline:multi_stage` correlator are always-on and need no config.

### `devices`

Learned-device inventory + "new device" alerting. When
`devices.enabled: true` the sensor records every host it sees (from the
`dhcp` handler's MAC + hostname + DHCP fingerprint, the ARP sniffer, and
the source IP of every handled connection) into
`<data_dir>/devices.json`, and raises a `device:new` event for hosts
that are neither allow-listed nor part of the learned baseline.

| Field | Meaning |
|---|---|
| `learn` | `true` = first run silently records a baseline, later unseen hosts alert; `false` = strict allow-list mode (every non-allowed host alerts on first sight). |
| `allow` | IPs / CIDRs / MACs that never alert. |
| `severity` | Severity of the `device:new` event (default `high`). |

Review with `tarpit-honeypot list-devices`.

### `channels` and `routes`

Channels are sinks; routes wire severity-match expressions to lists of
channel ids. Local sinks (`stdout`, `jsonlog`, `sqlite`) always receive;
outbound sinks honor allowlist + dedup + per-channel rate limit +
min-severity gate.

### `sensor.drop_user` / `sensor.drop_group`

Linux uid/gid to switch to after privileged setup (binding low ports,
opening data dirs). Refuses uid 0. On non-Linux platforms the setting is
logged as ignored.

### `ui`

Read-only HTML/JSON web UI. Default `bind: 127.0.0.1:8088`. Non-loopback
binds are rejected at validate-time unless both `tls_cert` + `tls_key`
and `auth_token_env` are configured. Tabs: summary, events, **topology**,
**config**, **docs** — see [Web UI](#web-ui).

### `dedup` + `allowlist`

`dedup.default_window` collapses repeat events with the same
`(rule_id, source)` within the window before they reach **outbound**
sinks (local sinks always get the full stream). `allowlist` is a list of
IPs / CIDRs whose events skip outbound dispatch but are still recorded
locally — keep a forensic trail without paging on internal scanners.

### `honeynets`

Zero-to-many artificial networks of virtual hosts (CIDR + gateway + DNS +
domain + per-host `{ip, hostname, os, archetype, services}`), each with
optional `arp_responder` / `icmp_responder` / `lldp_responder` / `tun`.
See [Honeynets](#honeynets) for the dispatch model and examples.

## OS / device archetypes

Set `sensor.archetype`, `listener.archetype`, or a per-honeynet-host
`archetype` to any **config name** below (names are matched
case-insensitively with flexible separators — `"Cisco Catalyst Switch"`,
`cisco-catalyst-switch`, and `cisco_catalyst_switch` all resolve). The
archetype then drives every banner-aware handler (SSH/HTTP(S)/FTP/Telnet/
SMTP/MySQL), the SNMP MIB-2 identity (sysDescr/sysObjectID/ifTable), MAC
OUI, interactive-shell CLI, TLS posture, and the initial IP TTL so the
host is internally consistent end to end. `tarpit-honeypot help archetypes`
prints the live list, `tarpit-honeypot list-archetypes <name>` the full
fingerprint of one, and [`docs/archetypes.md`](docs/archetypes.md)
documents the archetype catalog with their services/protocols and emulated CVEs.

| Category | Archetype | Config name(s) | Family | Init TTL | Signature highlights |
|---|---|---|---|---|---|
| Linux | Debian 9 (stretch) | `debian-9` | debian | 64 | OpenSSH 7.4 / Apache 2.4.25 / vsFTPd / Postfix / MariaDB |
| Linux | Debian 10 (buster) | `debian-10` | debian | 64 | OpenSSH 7.9 / Apache 2.4.38 |
| Linux | Debian 11 (bullseye) | `debian-11` | debian | 64 | OpenSSH 8.4 / Apache 2.4.62 |
| Linux | Debian 12 (bookworm) | `debian-12` | debian | 64 | OpenSSH 9.2 / Apache 2.4.x |
| Linux | Debian 13 (trixie) | `debian-13` | debian | 64 | current Debian banners |
| Linux | Ubuntu 24.04 LTS | `ubuntu-24-04-lts` | ubuntu | 64 | OpenSSH 9.x (Ubuntu) / nginx |
| Linux | Ubuntu 26.04 LTS | `ubuntu-26-04-lts` | ubuntu | 64 | current Ubuntu banners |
| Linux | CentOS 5 | `centos-5` | rhel | 64 | OpenSSH 4.3 / Apache 2.2.3 (legacy) |
| Linux | CentOS 6 | `centos-6` | rhel | 64 | OpenSSH 5.3 / Apache 2.2.15 |
| Linux | CentOS 7 | `centos-7` | rhel | 64 | OpenSSH 7.4 / Apache 2.4.6 |
| Linux | CentOS 8 | `centos-8` | rhel | 64 | OpenSSH 8.0 / Apache 2.4.37 |
| Linux | CentOS Stream 10 | `centos-stream-10` | rhel | 64 | OpenSSH 9.9 |
| Linux | RHEL 8 | `red-hat-enterprise-linux-8` | rhel | 64 | RHEL banners |
| Linux | RHEL 9 | `red-hat-enterprise-linux-9` | rhel | 64 | RHEL banners |
| Linux | RHEL 10 | `red-hat-enterprise-linux-10` | rhel | 64 | RHEL banners |
| Linux | Rocky Linux 9 | `rocky-linux-9` | rhel | 64 | RHEL-compatible |
| Linux | AlmaLinux 9 | `almalinux-9` | rhel | 64 | RHEL-compatible |
| Linux | Oracle Linux 8 | `oracle-linux-8` | rhel | 64 | RHEL-compatible |
| Linux | Oracle Linux 9 | `oracle-linux-9` | rhel | 64 | RHEL-compatible |
| Linux | Arch Linux | `arch-linux` | arch | 64 | rolling-release banners |
| BSD | FreeBSD 13 | `freebsd-13` | bsd | 64 | OpenSSH / FreeBSD web console |
| BSD | FreeBSD 14 | `freebsd-14` | bsd | 64 | OpenSSH / FreeBSD web console |
| BSD | OpenBSD 7.5 | `openbsd-7-5` | bsd | 64 | OpenSSH / httpd |
| BSD | OpenBSD 7.6 | `openbsd-7-6` | bsd | 64 | OpenSSH / httpd |
| BSD | OpenBSD 7.8 | `openbsd-7-8` | bsd | 64 | OpenSSH 10.1 / httpd / OpenSMTPD |
| Windows | Windows 2000 | `windows-2000` | windows | 128 | IIS 5.0, TLS 1.0, SMBv1, no SSH (MS08-067 era) |
| Windows | Windows XP | `windows-xp` | windows | 128 | IIS 5.1, TLS 1.0, SMBv1, no SSH (EternalBlue era) |
| Windows | Windows 7 | `windows-7` | windows | 128 | legacy SMB/RDP, weak TLS |
| Windows | Windows 8 | `windows-8` | windows | 128 | legacy posture |
| Windows | Windows 10 | `windows-10` | windows | 128 | modern client |
| Windows | Windows 11 | `windows-11` | windows | 128 | modern client |
| Windows | Windows Server 2008 | `windows-server-2008` | windows | 128 | TLS 1.0, legacy ciphers |
| Windows | Windows Server 2012 | `windows-server-2012` | windows | 128 | legacy server |
| Windows | Windows Server 2012 R2 | `windows-server-2012-r2` | windows | 128 | legacy server |
| Windows | Windows Server 2016 | `windows-server-2016` | windows | 128 | server |
| Windows | Windows Server 2019 | `windows-server-2019` | windows | 128 | server |
| Windows | Windows Server 2022 | `windows-server-2022` | windows | 128 | server |
| Windows | Active Directory (Server 2019 DC) | `active-directory`, `domain-controller`, `windows-server-2019-dc` | windows | 128 | PowerShell shell + full AD protocol mix; pre-rollup patch level (ZeroLogon/PrintNightmare/ProxyLogon advisory) |
| Network | Cisco Catalyst 2960 (IOS 15) | `cisco-ios`, `cisco-catalyst-2960` | cisco | 255 | IOS CLI emulator, SSH-2.0-Cisco, SNMP ifTable/VLAN/LLDP, weak TLS, CVE-2018-0171 (Smart Install) |
| Network | Cisco Catalyst 9300 (IOS-XE 17) | `cisco-catalyst-switch`, `cisco-catalyst-9300` | cisco | 255 | IOS-XE identity, cat9k sysObjectID |
| Network | Cisco Industrial Ethernet 2000 | `cisco-ie-2000` | cisco | 255 | rugged IE switch, IOS 15.2, IE2000 sysObjectID |
| Network | Cisco Catalyst IE-3400 | `cisco-ie-3400` | cisco | 255 | IOS-XE IE3400, IOx edge |
| Network | Cisco IR1101 (industrial router) | `cisco-ir1101` | cisco | 255 | IOS-XE industrial router, Cellular0/1/0 |
| Network | MikroTik RouterOS | `mikrotik-router`, `mikrotik-routeros`, `mikrotik-routerboard` | mikrotik | 64 | SSH-2.0-ROSSSH, webfig, Winbox/API ports, RouterOS CLI emulator, MikroTik SNMP OID |
| Network | Teltonika RUT240 | `teltonika-rut240`, `teltonika-router` | teltonika | 64 | RutOS/OpenWrt, Dropbear SSH, lighttpd, LTE wwan0, Teltonika SNMP OID |
| Network | Teltonika RUT955 | `teltonika-rut955` | teltonika | 64 | RutOS industrial router, GPS, Modbus TCP |
| Network | Teltonika RUTX11 | `teltonika-rutx11` | teltonika | 64 | RutOS, LTE Cat6 + dual-band wifi, nginx |
| Network | Teltonika RUT956 | `teltonika-rut956` | teltonika | 64 | RutOS industrial router, Modbus TCP |
| Network | Teltonika TRB140 | `teltonika-trb140` | teltonika | 64 | RutOS LTE gateway, Modbus TCP |
| ICS/OT | Moxa EDS-208 | `moxa-eds-208` | moxa | 255 | industrial switch CLI, Moxa OUI/SNMP |
| ICS/OT | Moxa NPort 5210 | `moxa-nport-5210` | moxa | 255 | serial device server, raw TCP 4001/4002 |
| ICS/OT | Moxa EDS-405A | `moxa-eds-405a` | moxa | 255 | managed switch CLI/web/SNMP |
| ICS/OT | Moxa EDS-G516E | `moxa-eds-g516e` | moxa | 255 | 16-port gigabit managed switch, MRP ring |
| ICS/OT | Moxa NPort 5650-8 | `moxa-nport-5650` | moxa | 255 | 8-port serial device server, raw TCP 4001-4008 |
| ICS/OT | Moxa AWK-3131A | `moxa-awk-3131a` | moxa | 255 | industrial wireless AP/bridge/client |
| ICS/OT | Moxa MGate MB3180 | `moxa-mgate-mb3180` | moxa | 255 | Modbus/TCP↔serial gateway (502) |
| ICS/OT | Westermo Lynx | `westermo-lynx` | westermo | 64 | WeOS managed switch, GoAhead-Webs, FRNT ring |
| ICS/OT | Westermo RedFox | `westermo-redfox` | westermo | 64 | WeOS rugged managed switch, IEC 61850 VLAN |
| ICS/OT | Westermo Viper | `westermo-viper` | westermo | 64 | WeOS EN50155 rail switch |
| ICS/OT | Westermo Merlin-4400 | `westermo-merlin-4400` | westermo | 64 | WeOS-5 cellular router, wwan0 |
| ICS/OT | Westermo Ibex | `westermo-ibex` | westermo | 64 | WeOS industrial wireless |
| ICS/OT | Hirschmann RS20 | `hirschmann-rs20` | hirschmann | 64 | Classic rail switch, HIPER-Ring, Hirschmann OUI/OID |
| ICS/OT | Hirschmann RSP35 | `hirschmann-rsp35` | hirschmann | 64 | HiOS managed switch, MRP + PROFINET |
| ICS/OT | Hirschmann EAGLE20 | `hirschmann-eagle20` | hirschmann | 64 | EAGLE One industrial firewall |
| ICS/OT | Phoenix Contact FL SWITCH 2008 | `phoenix-fl-switch-2008` | phoenix | 64 | RomPager web, Phoenix OUI/OID |
| ICS/OT | Phoenix Contact FL MGUARD | `phoenix-fl-mguard` | phoenix | 64 | mGuard security router/firewall |
| ICS/OT | Advantech EKI-5528 | `advantech-eki-5528` | advantech | 64 | Boa web, managed switch, Advantech OUI/OID |
| ICS/OT | ABB AC500 PLC | `abb-ac500` | abb | 64 | CODESYS gateway 1217, Modbus + EtherNet/IP, ABB OUI |
| ICS/OT | ABB S500 remote I/O | `abb-s500-io` | abb | 64 | PROFINET I/O adapter (CI502), ABB OUI |
| ICS/OT | ABB RTU560 | `abb-rtu560` | abb | 64 | substation RTU, IEC 60870-5-104 + IEC 61850 MMS |
| ICS/OT | Honeywell ControlEdge 900 | `honeywell-controledge` | honeywell | 64 | PLC/RTU, Modbus + IEC 104, Honeywell OUI |
| ICS/OT | Honeywell Experion C300 | `honeywell-experion` | honeywell | 64 | DCS controller, FTE, Honeywell OUI |
| ICS/OT | Siemens PN/PN Coupler | `siemens-pn-pn-coupler` | siemens | 255 | PROFINET-to-PROFINET coupler (6ES7158) |
| ICS/OT | WAGO 750-8212 PFC200 | `wago-750-pfc` | wago | 64 | CODESYS Linux PLC, Modbus, WAGO OUI/OID |
| ICS/OT | Beckhoff CX9020 | `beckhoff-cx` | beckhoff | 128 | TwinCAT embedded PC, ADS/AMS 48898, Beckhoff OUI |
| ICS/OT | Siemens SCALANCE XB-208 | `siemens-scalance-xb-208` | siemens | 255 | SCALANCE CLI, MRP ring / PROFINET tree / VLAN exposure |
| ICS/OT | Siemens SCALANCE S615 | `siemens-scalance-s615` | siemens | 255 | industrial security router |
| ICS/OT | Siemens SCALANCE SC-600 | `siemens-scalance-sc-600` | siemens | 255 | industrial firewall |
| ICS/OT | Siemens S7-1200 PLC | `siemens-s7-1200` | siemens | 255 | S7 PLC console, S7comm |
| ICS/OT | Siemens S7-1500 PLC | `siemens-s7-1500` | siemens | 255 | S7 PLC console, S7comm-Plus |
| ICS/OT | Allen-Bradley ControlLogix | `rockwell-controllogix` | ics | 64 | EtherNet/IP (CIP) 44818, Allen-Bradley web, Rockwell OUI |
| ICS/OT | Schneider Modicon M340 | `schneider-modicon` | ics | 64 | Modbus/TCP 502 + EtherNet/IP, Schneider-WEB, Schneider OUI |
| ICS/OT | Omron PLC (FINS) | `omron-plc` | ics | 64 | FINS 9600 + EtherNet/IP, Omron OUI |
| Firewall | pfSense (Netgate) | `pfsense` | pfsense | 64 | nginx, FreeBSD OpenSSH, pfSense login page, X-Frame-Options |
| Firewall | Fortinet FortiGate | `fortigate` | fortios | 255 | SSL-VPN `SVPNCOOKIE`, weak TLS, Fortinet OUI, CVE-2018-13379 (advisory) |
| NAS | Synology DiskStation | `synology-dsm` | synology | 64 | DSM web 5000/5001, MLST/MLSD FTP FEAT, Synology OUI/OID |
| NAS | QNAP Turbo NAS | `qnap-qts` | qnap | 64 | QTS web 8080, FTP FEAT, QNAP OUI/OID |
| Camera | Hikvision IP camera | `hikvision-camera` | hikvision | 64 | `App-webs/` Server, RTSP 554, Digest "IP Camera", CVE-2017-7921 (advisory) |
| Camera | Axis network camera | `axis-camera` | axis | 64 | VAPIX, RTSP 554, Digest realm `AXIS_*`, Axis OUI |
| Network | Ubiquiti EdgeRouter | `ubiquiti-edgerouter` | ubiquiti | 64 | EdgeOS lighttpd, Ubiquiti OUI/OID |
| Printer | HP LaserJet | `hp-printer` | printer | 64 | HP HTTP Server, JetDirect 9100, IPP 631, LPD 515, HP OUI/OID |
| Printer | Brother HL-L8260CDW | `brother-printer` | printer | 64 | `debut/1.20` EWS, Brother OUI/PEN 2435, full MFD service set |
| MFP | Canon imageRUNNER ADVANCE | `canon-imagerunner` | printer | 64 | Canon HTTP Server, PEN 1602, Canon OUI |
| MFP | Epson WorkForce Pro | `epson-workforce` | printer | 64 | `EPSON-HTTP/1.0`, PEN 1248, Epson OUI |
| MFP | Xerox VersaLink C405 | `xerox-versalink` | printer | 64 | `Xerox_MicroServer`, PEN 253, CVE-2024-12510 (advisory) |
| MFP | Lexmark MX622 | `lexmark-printer` | printer | 64 | `Lexmark_Web_Server`, PEN 641, CVE-2023-26067 (advisory) |
| MFP | Ricoh IM C3000 | `ricoh-mfp` | printer | 64 | `Web-Server/3.0`, PEN 367, Ricoh OUI |
| MFP | Konica Minolta bizhub | `konica-minolta-bizhub` | printer | 64 | `KM-MFP-Http/1.0`, PEN 18334, KM OUI |
| MFP | Kyocera ECOSYS | `kyocera-ecosys` | printer | 64 | Command Center RX, PEN 1347, CVE-2022-1026 (advisory) |
| MFP | Sharp MX-3071 | `sharp-mfp` | printer | 64 | `Boa/0.94.13`, PEN 2385, Sharp OUI |
| Printer | Zebra ZT411 (label) | `zebra-printer` | printer | 64 | ZebraNet web, ZPL on 9100, PEN 10642, Zebra OUI |
| VoIP | Asterisk PBX | `asterisk-voip` | voip | 64 | SIP 5060, FreePBX web, `Asterisk/18.x` Server header |

---

## Protocol handlers in detail

Bold flags: **arch** = consumes `archetype.Profile` for banner shape;
**id** = consumes `identity.Identity` for per-deployment uniqueness.

### TCP — general / IT

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `raw` | any | Sends literal `banner:` field, reads up to `read_bytes`. | — | — |
| `auto` | any | Generic catch-all for unmodelled protocols: captures the client's opening message, guesses the protocol from leading bytes (`protocol_guess`: tls / ssh / http / socks / quic / text / binary), and flags `unknown-protocol`. Optional `banner:` is sent as a server-first nudge. | — | — |
| `scripted` | any | Declarative fake protocol from the `scripted:` config block: optional on-connect greeting, then top-down `rules` matching each message (`prefix`/`contains`/`suffix`/`iprefix`/`icontains`/`regex`/`hex_prefix`/`any`) → `respond` (text or `respond_hex`), with per-rule `anomaly` + `close`. Stateful **stages** (`stage`/`set_stage`) model multi-step protocols; a `regex` rule with `capture: user`/`pass` harvests credentials. Captures the full transcript. Bounded rounds + 64 KB reply cap. | — | — |
| `tls_intercept` | any | TLS-terminating MITM front. Terminates TLS with a believable self-signed cert (computing JA3/JA4 + JA3S like `https`), then routes the decrypted stream per the `tls_intercept:` block: **inner_handler** hands cleartext to any TCP handler (a TLS front for an emulated service), or **forward_to** proxies cleartext to a real backend (optionally re-encrypting with `forward_tls`) and captures the plaintext session (client→backend bytes, 64 KB cap). Forwarding is opt-in and **egress-scoped** — backend must be allowlisted or it fails closed. ATT&CK T1557 + T1040. | ✓ | ✓ |
| `ssh` | 22 | Sends archetype/identity-shaped SSH-2.0 banner immediately followed by its own `SSH_MSG_KEXINIT` (algorithm set derived from the version banner — modern OpenSSH / legacy / Dropbear — so the **server HASSH** is realistic and version-consistent, recorded as `hassh_server`). Reads client ID (flags non-printable / non-SSH / overlong), computes the client HASSH from its KEXINIT, then drops the connection. | ✓ | ✓ |
| `ssh_interactive` | 22 | Full `golang.org/x/crypto/ssh` server with persistent ed25519 host key under `<data_dir>/tls/ssh_host_ed25519_key`. Captures every password / pubkey attempt (SHA-256 fingerprint, key type, user, client version), accepts the 3rd credential and drops into `internal/shell.Run` on the session channel. Bounded: `SessionTimeout=5min`, `MaxAuthTries=6`. Also captures non-interactive `ssh host CMD` exec lines + scans them for anomalies. **SSH auth-bypass / enumeration detection:** any **>256-byte password** → critical (`ssh-oversized-password`); the **\*sshole** musl locked-account bypass (257–1024 byte password, [sshhole.com](https://sshhole.com/), `SSHHOLE-2026`); **CVE-2019-5021** Alpine blank-root; **CVE-2016-6210** giant-password username-enumeration timing. With vuln emulation on, the \*sshole and blank-root bypasses are *accepted* to trap the attacker in the fake shell (no real access is granted). | ✓ | ✓ |
| `http` | 80 | Routes on method+path. `GET /` serves the archetype's index HTML (Moxa / SCALANCE / S7 device pages or nginx 401). `GET /login` and 12 other login-shaped paths serve a form. `POST /login` parses `application/x-www-form-urlencoded` body (accepts 6 alias names each for user/pass) and captures credentials. Computes JA4H from request line + headers. Flags 8 suspicious-URI anomalies (Log4Shell JNDI, path traversal, WordPress / `.git` / `.env` / Tomcat manager probes). | ✓ | ✓ |
| `https` | 443 | Peeks the TLS ClientHello for JA3 + JA4 fingerprints before crypto/tls consumes it. Self-signed ECDSA cert cached + rotated per `sensor.tls_rotate.days` under `<data_dir>/tls/`. Then runs the HTTP handler over the decrypted stream. Captures TLS version + SNI + JA3/JA4. | ✓ | ✓ |
| `telnet` | 23 | IAC WILL ECHO / WILL SGA / DO TERMINAL-TYPE negotiation, archetype-shaped issue banner, captures `user_attempt` + `pass_attempt`, sends "Login incorrect", then drops into the archetype's CLI shell (Linux distros / Moxa / SCALANCE response tables). | ✓ | — |
| `ftp` | 21 | 220 banner (archetype-shaped), then a bounded command loop: answers `FEAT` with the archetype's daemon-specific feature set (vsFTPd default; Synology/QNAP expose MLST/MLSD), `SYST` with `215 UNIX Type: L8`, USER → 331, PASS → 530 Login incorrect. Captures `user_line` + `pass_line` and flags `default-credential-attempt`. **Explicit FTPS** (RFC 4217): FEAT advertises AUTH TLS/SSL + PBSZ + PROT, `AUTH TLS`/`AUTH SSL` upgrades the control channel (and the PROT P data channel) to TLS and keeps capturing creds over the encrypted session. | ✓ | — |
| `smb` | 445 | NBSS framing + SMB1 Negotiate Protocol Request handler: captures all offered dialects, selects `NT LM 0.12`, replies with a believable Negotiate Response (8-byte challenge + 8-byte session key derived from identity). SMB2 connections answered with NEGOTIATE_RESPONSE carrying `STATUS_NOT_IMPLEMENTED`. | — | ✓ |
| `vnc` | 5900 | RFB 003.008 version exchange. Sends a per-connection 16-byte VNC auth challenge, captures `client_version` + the `(challenge, DES-response)` pair (offline-crackable) and flags `vnc-auth-attempt`. Replies `auth failed` by default; with `accept_creds: any\|defaults` it **accepts** and runs a post-auth RFB session (sends ServerInit, then captures `keystrokes` from KeyEvents and `clipboard` from ClientCutText — `vnc-session` / `vnc-clipboard-capture`). | — | ✓ |
| `smtp_recv` | 25 | ESMTP receive listener. Captures `helo`, `auth_mech`, `auth_user`, `auth_pass` (from AUTH PLAIN / LOGIN), `mail_from`, `rcpt_to`, `message_head`. Archetype-shaped 220 greeting (`Postfix 3.7.11` for debian 12, etc.); multiline `EHLO` advertises an archetype-specific extension set (`SMTPExtensions`, Postfix-style default) using the same host as the greeting. Advertises and performs a real `STARTTLS` upgrade when a cert store is available (else replies 454), continuing credential capture over the encrypted channel. | ✓ | ✓ |
| `rdp` | 3389 | X.224 Connection Request parser. Extracts `mstshash=` Cookie (typically the targeted username from `xfreerdp /u:...`) + `RDP_NEG_REQ` flags. Replies CC with PROTOCOL_SSL selected, then completes the **TLS handshake** (JA3/JA3S recorded) and best-effort harvests the CredSSP/NLA **NTLMSSP** domain/user + NetNTLM response (`rdp-ntlm-auth`). | — | — |
| `winrm` | 5985 | Reads HTTP POST `/wsman`. Decodes `Authorization: Basic` into `basic_user` / `basic_pass`. Replies HTTP 401 advertising `Negotiate, Basic realm="WSMAN"` so non-Kerberos brute-forcers fall back. | — | — |
| `dcerpc` | 135 | Endpoint Mapper bind handler. Parses the first abstract interface UUID + version pair. Replies `bind_ack` with NDR transfer syntax. When honeynet topology is available, advertises the configured endpoints. | — | — |
| `ldap` | 389 | Hand-rolled BER decoder (bounds-checked, fuzz-tested). Captures `bind_dn` + cleartext `bind_pw` for simpleAuth, or `sasl_mechanism` for SASL. Replies BindResponse 49 (invalidCredentials). When honeynet topology is available, advertises computer accounts in search responses. | — | — |
| `kerberos` | 88 | ASN.1 reader for AS-REQ / TGS-REQ. Extracts the principal/realm and the requested `enctypes` (flags `rc4-hmac` + Kerberoasting/`kerberos-tgs-request`). Replies `KDC_ERR_PREAUTH_REQUIRED`, then reads the **pre-auth retry** and captures its offline-crackable encrypted timestamp (`preauth_enc_timestamp_hex`, `kerberos-preauth-bruteforce`) before answering `KDC_ERR_PREAUTH_FAILED`. | — | — |
| `postgres` | 5432 | Reads StartupMessage (and SSLRequest / GSSEncRequest fallback). Captures `username`, `database`. Sends AuthenticationCleartextPassword, captures the PasswordMessage `password` (flags `default-credential-attempt`). Sends FATAL `28P01`. | — | — |
| `mysql` | 3306 | Server-first MySQL handshake — archetype-shaped version string (e.g. `10.11.6-MariaDB-0+deb12u1` for debian 12). Captures `username`, `auth_response_hex`, optional `database`. Replies ERR_Packet 1045 Access denied. | ✓ | ✓ |
| `mssql` | 1433 | TDS PRELOGIN exchange — advertises a SQL Server 15.0 version token + ENCRYPT_NOT_SUP, captures the LOGIN7 username, replies with an 18456 login-failed error token. | — | ✓ |
| `oracle_tns` | 1521 | Oracle Net (TNS) listener. Captures the connect descriptor (SERVICE_NAME / SID recon) and replies REFUSE ORA-12514; answers a `(COMMAND=version\|status\|…)` probe with a per-deployment listener version banner + matching VSNNUM (11g–21c spread). | — | — |
| `ftp_files` | 21 | Medium-interaction FTP: anonymous / `accept_creds` login, full PASV browse + RETR over a deterministic decoy tree. Flags `honeyfile-download` on bait-file retrieval + `default-credential-attempt`. | ✓ | ✓ |
| `redis` | 6379 | RESP parser (multi-bulk + inline forms). Captures `auth_password` from `AUTH` / `HELLO ... AUTH`, plus a short list of issued `commands` (with arguments). Returns RESP errors so the client keeps trying. | — | — |
| `memcached` | 11211 | memcached text protocol. Answers `version` / `stats` with believable counters, captures issued commands, and flags abuse: `stats` recon, writes (cache poisoning), and `flush_all` (cache wipe). | — | — |
| `mongodb` | 27017 | MongoDB wire protocol (OP_MSG / OP_QUERY). Answers `isMaster`/`hello` + `buildInfo` with a believable version, captures the requested commands, and flags unauthenticated access. | — | — |
| `elasticsearch` | 9200 | Elasticsearch HTTP API. Answers `GET /` with a believable cluster banner; captures probed paths and flags unauthenticated data-store access + `_search` / `_cat` enumeration. | — | — |
| `pop3` | 110 | POP3 receive listener. Archetype-shaped `+OK` greeting, captures `USER` / `PASS` credentials (flags `default-credential-attempt`), replies `-ERR` auth failure. | ✓ | — |
| `imap` | 143 | IMAP4rev1. Tagged-command loop: `CAPABILITY`, then captures `LOGIN` user/pass (flags `default-credential-attempt`), replies `NO` auth failure. | ✓ | — |
| `syslog_tcp` | 514 | Reads syslog messages via both octet-counting (`<N> <msg>`) and non-transparent (newline-terminated) framing. Captures first 16 messages with PRI / facility / severity decoded. | — | — |
| `rtsp` | 554 | Parses RTSP OPTIONS / DESCRIBE request line + headers. Captures `Authorization` (often Digest with the camera password) + `User-Agent`. Replies 401 with a Hikvision-shaped `WWW-Authenticate: Digest`. | — | — |
| `dockerapi` | 2375 | Unauthenticated-Docker-API mimic. Routes `/_ping`, `/version`, `/info`, `/containers/json` to believable canned JSON. Captures the request line + `Authorization` header on every hit. | — | — |
| `cloud_metadata` | 80 / link-local | Instance metadata service (IMDS) for AWS, GCP and Azure on one handler. Serves synthetic instance identity and **honeytoken IAM/OAuth credentials**; flags `cloud-credential-theft` when the IAM `security-credentials`, GCP `token`, or Azure `oauth2/token` paths are hit. Place behind a fake SSRF-able app or bind to 169.254.169.254. | — | — |
| `etcd` | 2379 | etcd KV-store API (v2 `/v2/keys`, v3 `/v3/kv/range`, `/version`, `/health`, `/metrics`, member list). Returns believable cluster state incl. a base64 `/registry/secrets/...` key; flags `etcd-secret-read` / `etcd-range-read` / `etcd-write`. | — | — |
| `websocket` | any | Completes the RFC 6455 opening handshake (computes `Sec-WebSocket-Accept`), then unmasks and captures client frames. Flags `ws-credential-material` / `ws-command-payload` on hostile first messages. Replies `426` to non-upgrade probes. | — | — |
| `grpc` | any | Recognizes the HTTP/2 connection preface, replies with SETTINGS + ACK, then reads frames and extracts the `/package.Service/Method` path from HEADERS (no HPACK decode needed). Flags `grpc-reflection-probe`. | — | — |
| `ssrf_canary` | any | Out-of-band callback collector — the inverse of a URL canary. Plant a token URL (`gen-token --type=ssrf`) in an SSRF param / webhook / XXE entity; when a coerced system fetches it, the callback is recorded with the token + `User-Agent` / `X-Forwarded-For` / `Via`. Flags `ssrf-callback`, and `ssrf-server-side-fetch` when the UA is an HTTP client library rather than a browser. Always returns a 1×1 GIF so the exploit chain proceeds. | — | — |
| `kubernetes_api` | 6443 | kube-apiserver mimic. Answers `/version`, `/api`, `/apis`, `/healthz` discovery; captures the `Authorization: Bearer` service-account token; flags `k8s-secret-enum` / `k8s-pod-create` / `k8s-pod-exec` and 403s anonymous protected requests as `system:anonymous`. | `bearer_token` | — |
| `vault` | 8200 | HashiCorp Vault API mimic. Answers `/v1/sys/health` + `/v1/sys/seal-status` like an unsealed Vault; captures `X-Vault-Token`; flags `vault-secret-read` / `vault-mount-enum` / `vault-policy-access` / `vault-seal-control`; tokenless secret reads get 403. | `vault_token` | — |
| `xmpp` | 5222 | Reads the client `<stream:stream>` open, extracts `to` / `from` / `xmlns` / `version`. Replies with our own `<stream:stream>` + `<stream:features>` advertising STARTTLS + PLAIN + SCRAM-SHA-1. Captures the follow-up `<auth>` or `<starttls/>` stanza. | — | — |
| `amqp` | 5672 | AMQP 0-9-1 / RabbitMQ. Sends Connection.Start (advertising PLAIN + AMQPLAIN) after the 8-byte protocol header. Decodes the SASL PLAIN response (`\0user\0pass`) from Connection.StartOk. Replies Connection.Close with 530 NOT_ALLOWED. | — | — |
| `ipp` | 631 | IPP / CUPS printer over HTTP. Replies HTTP 200 + `application/ipp` advertising a believable MFP — **identity taken from the bound archetype** (Xerox/Lexmark/Brother/…) so IPP/SNMP/web agree — with a fuller attribute set (uuid, dns-sd-name, document-format-supported, media, toner `marker-levels`). Names the IPP operation and flags printer-admin / job-injection / server-fetch ops (`printer-ipp-admin-op`), the CUPS foomatic-rip RCE primitive (`printer-cups-rce` + `cve:CVE-2024-47177`), and command-injection metacharacters in printer/device attributes (`printer-ipp-cmd-injection`). | — | — |
| `lpd` | 515 | Line Printer Daemon (RFC 1179). Acknowledges the command (so a client sends its control file), names the command, captures the queue + control metadata, and flags shell-metacharacter injection in any field (`printer-lpd-injection`), overlong fields (`printer-lpd-overflow`), and path traversal. Nothing is queued. | ✓ | — |
| `rsync` | 873 | rsync daemon protocol. Sends the `@RSYNCD: <ver>` greeting, captures the module the client asks for, returns a believable fake module list on `#list`, and flags module enumeration (`rsync-module-list`) + module access (`rsync-module-access`). | — | — |
| `gopher` | 70 | Gopher (RFC 1436). Captures the requested selector, replies with a small fake menu, and flags SSRF-shaped selectors used to smuggle other protocols through a Gopher gateway (`gopher-ssrf`). | — | — |
| `socks` | 1080 | SOCKS4 / SOCKS5 proxy probe. Parses the greeting / connect request, captures the requested target `host:port`, and flags proxy-abuse attempts (`socks-proxy-attempt`) — it never relays. | — | — |
| `bgp` | 179 | BGP. Parses the OPEN message (version, AS, hold-time, identifier, capabilities), captures it, and flags peering attempts (`bgp-open-attempt`), route injection/withdrawal (`bgp-route-injection`), and bare probes (`bgp-probe`). When `sensor.bgp_as` is set it answers a peer's OPEN with its own OPEN advertising that AS (My Autonomous System; ASNs > 65535 use AS_TRANS + the 4-octet-ASN capability) — a believable "we are AS N" router identity — then a NOTIFICATION (Cease); with no AS it replies NOTIFICATION only. `install.sh` prompts for the AS when a deployed config runs BGP without it. | — | — |

### TCP — remote access / out-of-band management

These personas reproduce the distinctive Server header + auth realm +
landing page that fingerprints the appliance, capture Basic-auth /
login-form credentials (flagging `<kind>-login-attempt` +
`default-credential-attempt`), and answer the protocol's discovery
handshake where it isn't HTTP.

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `teamviewer` | 5938 | TeamViewer relay hello — reads the client's first frame, replies with the `17 24 …TeamViewer` framing. | — | — |
| `anydesk` | 7070 | AnyDesk relay discovery reply (`ad.anynet.relay <ver>`). | — | — |
| `openvpn` | 1194 | OpenVPN TCP control channel — reads the `P_CONTROL_HARD_RESET_CLIENT` and replies `HARD_RESET_SERVER`; flags `openvpn-probe`. | — | — |
| `citrix_ica` | 1494 | Citrix ICA browser hello (`7f 7f ICA …`). | — | — |
| `intel_amt` | 16992 | Intel AMT / vPro web UI (CVE-2017-5689 surface): HTTP 401 Digest with the `Intel(R) Active Management Technology` Server header. | — | — |
| `ilo` | 443 | HP iLO 5 — `HP-iLO-Server/1.30` Server header + iLO realm. | — | — |
| `idrac` | 443 | Dell iDRAC 9 — `Mbedthis-Appweb` Server header + iDRAC realm (captures the `root/calvin` default). | — | — |
| `esxi` | 443 | VMware ESXi 7.0 host management — `VMware ESXi/7.0.3 Reverse Proxy` + `/ui/` + `/sdk` links. | — | — |
| `fortinet` | 10443 | FortiGate SSL-VPN portal (`/remote/logincheck` form). | — | — |
| `pulse` | 443 | Pulse Secure / Ivanti Connect Secure (`/dana-na/auth/...` form). | — | — |
| `citrix_gateway` | 443 | Citrix Gateway / NetScaler (`/cgi/login` form). | — | — |
| `horizon` | 443 | VMware Horizon view portal (`/portal/webclient/`). | — | — |
| `moxa_mgmt` | 80 | Moxa device web console (`MoxaHttp/1.0`, `/Login.asp` form). | — | — |
| `danfoss_aksm` | 80 | Danfoss **AK-SM 8xxA "StoreView"** refrigeration system manager (`xml.cgi` web interface, `Server: nginx`). Fingerprints the device + firmware, captures the `getauth` login, and **recognizes (detection only)** the Claroty Team82 CVEs: the **code-of-the-day auth bypass** (`danfoss-aksm-auth-bypass`, CVE-2025-41450 — the redacted algorithm is *not* reproduced, only the request *shape*), **alarm-to-mail OS command injection** via item `0x1be1` (`danfoss-aksm-cmd-injection`, CVE-2025-41451), **nginx `headers.conf` config injection / sm_app crash DoS** via `action=load_nginx_headers` (`danfoss-aksm-nginx-config-injection`, CVE-2025-41452), the AK-SM 800A `xml.cgi` **path traversal** (CVE-2023-25914), and **debug/engineering-interface access** (`danfoss-engineering-interface-access`, Danfoss iC7 CVE-2026-15203 / DSA-2026-08-01). `danfoss_aksms` is the TLS-fronted (443) variant. | — | ✓ |
| `ollama` | 11434 | **Ollama** LLM runtime REST API. Answers `/`, `/api/tags`, `/api/ps`, `/api/show` with a believable loaded-model list; flags model enumeration (`llm-model-enumeration`), model pull/push (`llm-model-pull`, compute/bandwidth abuse), and unauthenticated inference (`llm-unauth-inference`). Captures the prompt and classifies **prompt-injection / jailbreak / system-prompt-leak / data-exfil / tool-abuse** (MITRE ATLAS) via the shared LLM classifier. | — | — |
| `llm_openai` | 8000 / 1234 | **OpenAI-compatible** inference API (vLLM / LM Studio / LocalAI / text-generation-webui). Serves `/v1/models` + `/v1/chat/completions` / `/v1/completions`; captures `Authorization: Bearer` **API-key probing** (`llm-api-key-probe`) and the prompt, classified for LLM abuse (MITRE ATLAS). | — | — |
| `mcp` | any | **Model Context Protocol** server honeypot (JSON-RPC 2.0 over Streamable-HTTP). Answers `initialize` / `tools/list` / `resources/list` / `resources/read`; captures every `tools/call` + its arguments and flags tool execution (`mcp-tool-exec`), arbitrary file read (`mcp-tool-file-read`), SSRF (`mcp-tool-fetch`) and resource path-traversal, classifying arguments for injection + prompt-injection (MITRE ATLAS). No tool is ever run. | — | — |
| `jupyter` | 8888 | **Jupyter** Notebook/Lab (`TornadoServer`). Flags token-less access (`jupyter-unauth-access`) and terminal/kernel spawn (`jupyter-terminal-rce` / `jupyter-kernel-spawn`) — hands-on code execution on an exposed notebook — plus session/content enumeration. | — | — |
| `selenium` | 4444 | **Selenium** Grid / standalone (`Jetty`). Serves `/status`; flags a new-session request whose `goog:chromeOptions` overrides the browser `binary` or passes CLI `args` (`selenium-node-rce`) — the arbitrary-binary / cryptojacking vector on exposed grids. | — | — |
| `consul` | 8500 | HashiCorp **Consul** HTTP API. Flags catalog/agent/KV enumeration and a `service/register` carrying a health-check `args`/`script` (`consul-service-register-rce`) — RCE on every agent running the check. | — | — |
| `nomad` | 4646 | HashiCorp **Nomad** HTTP API. Flags agent/node/job enumeration and a job submission using the `raw_exec`/`exec` driver (`nomad-job-submit-rce`) — RCE on the client nodes. | — | — |
| `minio` | 9000 | **MinIO** S3. Serves ListBuckets + health; flags bucket enumeration and the unauthenticated `/minio/bootstrap/v1/verify` environment/credential disclosure (**CVE-2023-28432**). | — | — |
| `clickhouse` | 8123 | **ClickHouse** HTTP interface. Answers the `Ok.` ping; flags SQL over HTTP (`clickhouse-sql-exec`), `file()/url()/remote()` table-function file-read/SSRF (`clickhouse-file-read`), and `system.*` reads. | — | — |
| `dixell` / `carel` / `trane` / `resideo` | 80 | Refrigeration / BMS controller web supervisors — **Emerson/Copeland Dixell XWEB**, **CAREL pCOWeb/boss**, **Trane Tracer SC**, **Resideo/Honeywell**. Each fingerprints the product + Server header, captures the login (flags the **vendor default credentials**, `bms-default-cred`), and flags setpoint/defrost/parameter writes (`refrigeration-setpoint-write`) and embedded-webserver path traversal (`bms-web-traversal`). | — | — |
| `ocpp` | any (WebSocket) | **EV-charging OCPP-J** endpoint (OCPP 1.6 / 2.0.1 over WebSocket). Completes the upgrade, captures the charge-point id + subprotocol, and classifies the OCPP CALL actions — remote start/stop (`ocpp-remote-transaction`), config/charging-profile change (`ocpp-config-change`), firmware push (`ocpp-firmware-update`), `Reset` (`ocpp-reset`), auth-list tamper (`ocpp-authlist-tamper`). | — | — |
| `vmware_authd` | 902 | VMware Authentication Daemon (ESXi / Workstation management agent). Sends the `220 VMware Authentication Daemon Version 1.10…` banner, captures the FTP-style USER/PASS + default creds. | — | — |
| `redfish` | 443 | BMC Redfish REST API (iLO / iDRAC / XCC / Supermicro OOB). Serves the unauthenticated service root, demands Basic auth below it, captures `basic_user`/`basic_pass` + default creds; flags `redfish-auth-attempt`. | — | — |
| `tr069` | 7547 | TR-069 **CWMP** connection-request CPE — the most-attacked router port. Serves a **RomPager** Digest 401 / CWMP `InformResponse` decoy; captures the SOAP `cwmp_method` + spoofed device identity (`cwmp_oui`/`cwmp_serial`); recognizes the **Misfortune Cookie** (CVE-2014-9222, CWE-787), the **TR-064 SetNTPServers RCE** (CVE-2016-10372, CWE-78), firmware-push (`Download`) and disruptive RPCs; stamps `intent` + `cwe`. | — | `CVE-2014-9222`, `CVE-2016-10372` |
| `upnp` | 5000 / 49152 | UPnP **IGD** SOAP control + GENA eventing. Serves a believable `rootDesc.xml` / SOAP action response; flags **UPnProxy** `AddPortMapping` NAT injection (CWE-441), **CallStranger** SUBSCRIBE-callback SSRF (CVE-2020-12695, CWE-918), port-map enumeration, and Realtek/Huawei SOAP command injection (CVE-2014-8361 / CVE-2017-17215, CWE-78); stamps `intent` + `cwe`. | — | `CVE-2020-12695`, `CVE-2014-8361`, `CVE-2017-17215` |
| `tr369` | any (WebSocket) | TR-369 **USP** agent. Completes the `v1.usp` WebSocket handshake (or recognizes a raw USP **Record** protobuf), scavenges the controller/agent endpoint IDs (`proto::`/`os::`) + USP version, and flags an unauthenticated / cleartext USP MTP (CWE-319 / CWE-306); stamps `intent`. | — | — |
| `x11` | 6000 | X11 display server — parses the connection-setup request, captures the offered auth-protocol name, returns a Failed setup. An exposed X server is a keylog/screen-capture risk; flags `x11-connection-attempt`. | — | — |
| `rlogin` | 513 | BSD rlogin — parses the NUL-separated client/server user + termtype record, prompts for a password, captures all of it. Flags `rlogin-attempt`. | — | — |
| `nx` | 4000 | NoMachine NX server — `HELLO NXSERVER` banner, captures the client hello + login; flags `nx-probe`. | — | — |

### TCP — ICS / OT

Every ICS/OT handler stamps a human-readable **`intent`** summary on the event
("S7comm Write Var — writing PLC memory (control manipulation)") and, where the
protocol carries a command, distinguishes **recon reads** from **control
writes / mode changes / device resets / program transfers**, mapping each to
the **MITRE ATT&CK for ICS** matrix (T08xx). Reads get believable process data;
writes are acknowledged as "success" (deception) while being flagged — nothing
is ever applied. See **[docs/ot.md](docs/ot.md)** for the full per-protocol
command map, the ATT&CK technique table, and the configuration/limitations.

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `modbus` | 502 | Deep MBAP multi-PDU parser. Reads (FC 1–4) get plausible data + **Modicon reference / `%MW` tag enrichment**; writes (5/6/0F/10/16/17/15) → `modbus-write-attempt` (T0836/T0831); FC 0x07/0x0B/0x0C/0x18 status/event recon; FC 0x08 diagnostics (restart/listen-only → `ics-modbus-diagnostic`, counter-clear → anti-forensics); program/firmware transfer (0x28-0x2A → `modbus-program-download`); **Schneider UMAS** (FC 0x5A → `modbus-umas`, CVE-2018-7842); vendor/reserved FCs (65-72/100-110 → `modbus-vendor-function`); FC 0x2B/MEI device-ID + Report Server ID fingerprinting; session-level **unit-id sweep / FC scan / broadcast-write** enumeration. | — | — |
| `modbus_security` / `modbuss` | 802 | **Modbus/TCP Security** (Modbus-over-TLS). Terminates TLS (JA3/JA4/JA3S), captures the client-cert subject + the **Modbus role** X.509 extension, flags the secure session / missing client cert, then runs the `modbus` PDU handler over the encrypted channel. | ✓ | — |
| `s7` | 102 | Siemens **S7comm** over TPKT/COTP. Completes CR→CC, negotiates **Setup Communication**, then services the session: **SZL reads** answered with a believable S7-300 module/firmware identity (the CPU fingerprint nmap `s7-info`/plcscan parse), plus **Read Var** (T0801), **Write Var** (T0836/T0831), **PLC STOP/control** (T0858), **block up/download** (T0843). | — | — |
| `s7comm_plus` | 102 | S7-1200/1500 S7comm-Plus over TPKT/COTP. Answers the COTP CR with a CC, then captures + classifies the first data PDU (S7comm-Plus `0x72` vs classic `0x32`). | — | — |
| `iec104` | 2404 | IEC 60870-5-104 APCI parser; replies STARTDT_CON/TESTFR_CON and a believable **General Interrogation** result. Flags GI/counter-interrogation (T0801), single/double **commands** (`ics-iec104-command`, T0855), **set-point** commands (T0836), **reset-process** (T0816). | — | — |
| `dnp3` | 20000 | DNP3 (IEEE 1815). Data-link LINK_STATUS/ACK (correct CRC) **plus** application-layer parsing (de-blocks the user data): READ (T0801), WRITE (T0836/T0831), SELECT/OPERATE/DIRECT_OPERATE (`ics-dnp3-control`, T0855), COLD/WARM_RESTART + STOP_APPL (`ics-device-restart`, T0816). | — | — |
| `ethernetip` | 44818 | EtherNet/IP + **CIP**. RegisterSession + ListIdentity (fake Rockwell 1756-L73 ControlLogix) **plus** SendRRData/SendUnitData CIP parsing: names the service (`cip_service`) and flags Get/Read (T0801), Set/Write (T0836/T0831), Reset/Stop (T0816), Start (T0858), Forward_Open (T0888) — answering a believable CIP success. | — | ✓ |
| `opcua` | 4840 | OPC-UA. HEL→ACK (`endpoint_url`, buffer sizes) **plus** reads the post-Hello **OpenSecureChannel** and records the requested `SecurityPolicyUri`; a `#None` policy (the classic exposed-server misconfig) is flagged `ics-opcua-insecure-policy`. | — | — |
| `mms` | 102 | IEC 61850 **MMS** (substation IEDs/relays — distinct from S7comm on 102). Completes COTP CR→CC + the ACSE/MMS association (AARE accept), then parses the first confirmed-request and names the service (`mms_service`): getNameList/identify (T0888), read (T0801), write (T0836/T0831). Also detects the **ICCP/TASE.2** profile (TASE.2 version OID + Bilateral_Table / Transfer_Set / VCC objects) and classifies Transfer-Set, Bilateral-Table, and Block-5 cross-utility Device-control. | — | — |
| `melsec` | 1025/5006/5007 | Mitsubishi **MELSEC** MC-protocol (3E). Names the command (`command_name`) + replies with a `Q03UDVCPU` identity; flags Batch/Random Read (T0801), Write (T0836/T0831), Remote RUN/STOP/PAUSE (T0858), Remote Reset (T0816), Read-CPU-Model (T0888). | — | — |
| `ads` | 48898 | Beckhoff **ADS/AMS** (TwinCAT). Parses the AMS header + AmsNetIds; flags Read (T0801), Write/ReadWrite (T0836/T0831), WriteControl run-state change (T0858), ReadDeviceInfo/ReadState (T0888); answers Read-Device-Info with a TwinCAT identity. | — | — |
| `fins_tcp` | 9600 | Omron **FINS/TCP**. Node-address handshake + frame send; classifies Memory-Area Read (T0801) / Write (T0836), RUN/STOP (T0858), Program-Area download (T0843), CPU-data read (T0888). | — | — |
| `roc_plus` | 4000 | Emerson **ROC Plus** (gas/oil flow-computer RTUs). Decodes the addressing + opcode; flags login (`ics-roc-plus-login`), parameter read (config/measurement theft), parameter write (T0836/T0831). | — | — |
| `pcom` | 20256 | Unitronics **PCOM** (Vision PLCs — the 2023 water-utility target, CISA ICSA-23-348). Answers an identification request; flags value writes, RUN/STOP mode changes, and logic downloads (T0843). | — | — |
| `secs_gem` | 5000 | SEMI **HSMS / SECS-GEM** (semiconductor fab equipment). Answers Select/Linktest; flags S7F3 process-program send (T0843) and S2F41 host command (T0855). | — | — |
| `crimson` | 789 | Red Lion **Crimson** (HMI / data-station management). Captures the framed request, returns a "G3" identity reply; flags the probe. Fingerprint-grade. | — | — |
| `ge_srtp` | 18245 | GE-SRTP (GE / Emerson PACSystems / Series 90). Captures the 56-byte request + returns a believable success response. Fingerprint-grade. | — | — |
| `codesys` | 1217 | CODESYS V3 gateway/runtime (WAGO / Beckhoff / Schneider / ABB soft-PLCs). Captures the request + returns a minimal channel ack. Fingerprint-grade. | — | — |
| `hartip` | 5094 | HART-IP gateway to process field instruments. Parses the 8-byte header, captures the message type, replies with a valid response header. Fingerprint-grade. | — | — |
| `pcworx` | 1962 | Phoenix Contact PCWorx (ILC-class PLCs; nmap pcworx-info). Returns an identification frame carrying model (`ILC 330 ETH`) + firmware. Fingerprint-grade. | — | — |
| `proconos` | 20547 | ProConOS / eCLR soft-PLC runtime (the engine PCWorx/MULTIPROG download logic to). Classifies the opcode: START/STOP (`ics-plc-mode-change`, T0858) and unauthenticated logic DOWNLOAD (`ics-plc-write`, ICS-ALERT-13-016 class). | — | — |
| `c37118` | 4712 | IEEE C37.118.2 synchrophasor (PMU/PDC, wide-area grid measurement). Parses the frame header + FRAMESIZE, classifies COMMAND frames (turn-on/off transmission → `ics-pmu-command` T0855, send CFG/HEADER), answers with a CRC-checked CFG-2. | — | — |
| `focas` | 8193 | FANUC FOCAS (CNC / machine tool; Shodan `fanuc`). Captures the request, returns a believable `FANUC Series 30i` sysinfo reply. Fingerprint-grade. | — | — |
| `osdp` | (configurable) | SIA OSDP / IEC 60839-11-5 (access-control reader↔panel) over an IP serial gateway. Parses the OSDP frame, classifies osdp_OUT (door-strike, `ics-actuator-command`), osdp_COMSET (channel hijack), osdp_KEYSET/CHLNG/SCRYPT (secure-channel key); replies osdp_ACK / osdp_PDID with the right checksum or CRC. | — | — |
| `iccp_secure` | 3782 | Secure ICCP / TASE.2 over TLS (IEC 62351). TLS termination (JA3/JA4/JA3S) then the full `mms`/ICCP stack — see `mms` for the TASE.2 profile + Block-2/5 classification. | ✓ | — |
| `osisoft_pi` | 5450 | OSIsoft / AVEVA PI Data Archive (PI Network Manager). Captures the client's opening message, returns a believable PI server name + version, flags historian access (`ics-historian-access`, T0811/T0801 — IT→OT pivot / data exfil). Fingerprint-grade. | — | — |
| `atg` | 10001 | Veeder-Root TLS-350 Automatic Tank Gauge (the "internet-exposed gas pump" target; nmap atg-info). Answers `^A`+`I20100/I20200/I20300` with a believable per-deployment tank report; flags `ics-atg-command`. Report-only. | — | ✓ |
| `fox` | 1911 | Niagara / Tridium Fox (building automation; Shodan's `fox` probe). Emits a per-deployment "fox hello" advertising station name / host id / app+VM+OS versions / brand. | — | ✓ |
| `pjl` | 9100 | HP JetDirect raw-print port speaking PJL — the channel PRET drives. Interactive loop: answers `@PJL INFO ID/STATUS/CONFIG/VARIABLES/FILESYS/MEMORY/PAGECOUNT/...` believably and **decoys the read-style filesystem ops** (FSDIRLIST/FSUPLOAD/FSQUERY return a fake directory tree + file contents so PRET keeps walking). Captures jobs/commands + a PJL password and flags panel defacement, filesystem access + the destructive `FSINIT` format, path traversal, config/password writes + credential reads, service-mode + firmware-upgrade + language-switch, NVRAM/DM commands, embedded **PostScript** abuse (exitserver, file ops, `set*params`), and **ZPL** (Zebra) / PCL jobs (`printer-zpl-job`/`printer-zpl-config`/`printer-pcl-job`). Nothing prints or touches a real FS. | ✓ | — |

#### Healthcare / medical devices

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `hl7` | 2575 | **HL7 v2 over MLLP** — the clinical-messaging lingua franca (EHR ↔ lab ↔ radiology ↔ billing), almost always unauthenticated on the wire. Strips the `<VT>…<FS><CR>` framing, parses the MSH header (`hl7_message_type`, `hl7_control_id`, sending app/version), answers a believable `MSA\|AA` ACK echoing the trigger event. Flags patient-data queries (`hl7-patient-query`, PHI access — T1213), master-file updates (`hl7-master-file-update`, T1565), order messages (`hl7-order-message`), injection (`hl7-injection`, T1190) and oversized frames. Detection only — no PHI is real and the ACK grants nothing. | — | ✓ |
| `dicom` | 104 / 11112 | **DICOM Upper Layer** (PACS / medical imaging; a mass-exposed Shodan target). Parses the A-ASSOCIATE-RQ called/calling **AE titles**, accepts with a structurally-valid A-ASSOCIATE-AC (echoing the offered presentation context + transfer syntax) so a real client/scanner proceeds, then captures the first **DIMSE** operation: `dicom-cfind` (query — T1213), `dicom-cget`/`dicom-cmove` (image retrieval/exfil — T1213/T1048), `dicom-cstore` (unsolicited push — T1565), `dicom-cecho`. Empty / tool-default calling AE flagged `dicom-ae-scan` (PACS discovery). TLS variant `dicoms` (2762). | — | — |

### UDP

| Handler | Port | What it does | arch | id |
|---|---|---|:-:|:-:|
| `raw` | any | Records the datagram bytes; optionally writes a static reply. | — | — |
| `auto` | any | Generic UDP catch-all: records the datagram, guesses the protocol from leading bytes (`protocol_guess`), flags `unknown-protocol`. **Never replies** — a UDP reply to a spoofable source would be a reflection/amplification primitive. | — | — |
| `snmp` | 161 | gosnmp-backed SNMPv1/v2c decoder over a **walkable** MIB — real `snmpwalk` / `snmpbulkwalk` traverse it (proper lexicographic GetNext + GetBulk). Captures `version`, `community`, requested OIDs. Answers the system group, `ifNumber` + full `ifTable`, the ip group, and the **`ipNetToMediaTable` (ARP table) synthesized from the honeynet topology** so a walk enumerates the artificial L2/L3 inventory. `snmp.mib_profile` (minimal / host / network / full) selects the exposed subtrees; `snmp.walk_rate_per_min` + `snmp.walk_tarpit` rate-limit / tarpit mass walkers (flagging `snmp-walk-rate-exceeded`). SetRequest is captured + flagged (`snmp-set-attempt`), never applied. Unknown OIDs return Null; SNMPv3 rejected. | ✓ | — |
| `ntp` | 123 | NTPv4 mode 3 → mode 4 server reply with echoed origin timestamp + plausible reference / receive / transmit timestamps. **Mode 7 (private / monlist) deliberately silent** — refusing to be an amplifier. | — | — |
| `bacnet` | 47808 | BVLC + NPDU + APDU parser (building automation). Who-Is/Who-Has → I-Am (`bacnet-device-discovery`, T0846); confirmed **ReadProperty** flagged as point enumeration (T0801); **WriteProperty** SimpleACK'd + flagged (T0836/T0831); **DeviceCommunicationControl** (T0814), **ReinitializeDevice** (T0816), **AtomicWriteFile** (T0836/T0831). | — | — |
| `bacnet_sc` / `bacnet_scs` | 47808 | **BACnet Secure Connect** (ASHRAE 135-2020 Annex AB) — the WebSocket+TLS data link replacing legacy BACnet/IP. Completes the WS handshake, recognizes the `hub.bsc.bacnet.org` / `dc.bsc.bacnet.org` subprotocol and the **BVLC-SC** framing, parses the **Connect-Request** (node VMAC + device UUID) and replies Connect-Accept, answers Heartbeat-Requests, and flags `ics-bacnet-sc-connect` (T0846) + `ics-plc-write` on an encapsulated WriteProperty. `bacnet_scs` is the TLS-fronted real-world form. | ✓ (`bacnet_scs`) | — |
| `tftp` | 69 | RFC 1350 RRQ/WRQ parser. Captures **filename**, **transfer mode**, and **RFC 2347 options** (blksize, tsize, timeout). Always replies ERROR opcode 5 code 2 (Access violation) — never serves files. | — | — |
| `ipmi` | 623 | RMCP ASF Presence Ping → Pong reply with IPMI 1.5 + 2.0 supported-entity flag (the classic "is this a BMC" probe). RMCP+ session-open captured but not answered (no real keying material to fake). | — | — |
| `syslog_udp` | 514 | RFC 3164/5424 datagram parser. Decodes PRI into facility + severity, captures the rest as `message`. | — | — |
| `radius` | 1812 | RADIUS Access-Request parser. Captures `user_name` + the encrypted `user_password_encrypted_hex`. Replies Access-Reject (code 3) with the original Identifier. | — | — |
| `sip` | 5060 | SIP-over-UDP. Parses request line + headers, captures `method`, `from`, `to`, `call_id`, `cseq`, `via`, `user_agent`, `authorization`. Replies SIP 200 OK with an Asterisk-shaped Server header. | — | — |
| `ssdp` | 1900 | UPnP M-SEARCH parser. Captures `st` (search target), `host`, `mx`, `user_agent`; stamps an `intent` (an `ssdp:all` probe is flagged `ssdp-all-amplification`, others UPnP enumeration), and flags an over-long SSDP header as the **libupnp** "Unplug. Don't Play." overflow (CVE-2012-5958, CWE-120). Replies HTTP/1.1 200 with a TP-Link-shaped `LOCATION` + `USN` so the scanner records a router on the segment (rate-limited, never amplifies). | — | — |
| `cldap` | 389 | CLDAP SearchRequest parser. Replies searchResDone; when honeynet topology is available, advertises the configured Domain Controllers in the meta. | — | — |
| `dtls` | any (WebRTC/CoAPS/VPN) | Datagram-TLS receiver. Parses the cleartext DTLS ClientHello, computes **JA3/JA4** over it (same fingerprints as TLS-over-TCP) + `dtls_version`, and replies with a HelloVerifyRequest. Only answers a genuine ClientHello (no reflection surface). | `ja3` / `ja4` | — |
| `quic` | 443 / any (HTTP-3) | QUIC / HTTP-3 receiver. Decrypts the QUIC **Initial** packet (keys derived from the public salt + connection ID per RFC 9001 — verified against the RFC test vectors), reassembles the TLS ClientHello from its CRYPTO frames, and computes **JA3/JA4** + `quic_version`. Capture-only (never replies — no reflection). Flags `quic-initial`. | `ja3` / `ja4` | — |
| `netflow` | 2055 / 9995 / 4739 | NetFlow / IPFIX collector decoy. Parses the export header (v5 / v9 / IPFIX v10) and, for fixed-layout v5, decodes the first flows (src/dst/ports/proto/bytes) — capturing the exporting network's actual who-talks-to-whom. One-way (never replies). Flags `netflow-export-received`. | — | — |
| `sflow` | 6343 | sFlow v5 collector decoy. Parses the datagram header (agent address, sub-agent, sequence, sample count) from a switch pointed at us. One-way (never replies). Flags `sflow-export-received`. | — | — |
| `llmnr` | 5355 | LLMNR query parser. Replies with our local IP as the A-record — classic poisoning catcher for the common Windows lookup-fallback target `wpad`. | — | — |
| `nbns` | 137 | NetBIOS Name Service query parser. Decodes the encoded NetBIOS name; replies positive name-query response — catches SMB-relay precursors. | — | — |
| `netbios_dgram` | 138 | NetBIOS Datagram Service. Parses the datagram header, decodes the source/destination NetBIOS names + the SMB mailslot / browser payload, and flags `netbios-datagram` (host enumeration / browser-protocol abuse). Captured, not answered. | — | — |
| `mdns` | 5353 | Multicast-DNS responder (RFC 6762). Parses the query, flags `mdns-service-enumeration` on DNS-SD service-discovery probes (`_services._dns-sd._udp.local`), and answers with believable PTR/SRV records. | — | — |
| `fins` | 9600 | Omron FINS UDP frame parser. Answers CPU-data-read (`CJ2M-CPU33`), CPU-status-read (RUN/MONITOR), memory-area-read (decoded area name + believable PV data), cycle-time/clock read. Flags memory **read** (T0801) / **write** (T0836/T0831), RUN/STOP (T0858), program-area access (T0843), CPU fingerprint (T0888). Globally rate-limited (no amplification). | — | — |
| `coap` | 5683 | RFC 7252 GET parser with bounds-checked option-TLV walker. Extracts `Uri-Path` + token; flags malformed packets. Replies 2.05 Content with a `/.well-known/core` link-format body advertising one fake `/led` resource. | — | — |
| `knx` | 3671 | KNXnet/IP. Replies to SEARCH_REQUEST (0x0201) with a SEARCH_RESPONSE advertising an "MDT KNX IP Router" device-info DIB + a supported-service-families DIB (CORE, DEV_MGMT, TUNNELLING, ROUTING). DESCRIPTION_REQUEST gets a DESCRIPTION_RESPONSE. CONNECT_REQUEST gets status `0x24` (no more connections) so we look live without opening a tunnel. | — | — |
| `profinet` | 34964 | PROFINET-IO over DCE-RPC. Names the CM operation (Connect / Release / IODRead / IODWrite / IODControl / ReadImplicit); flags reads (T0801), IODWrite (T0836), IODControl (T0855). **Capture-only** (never replies — DCE-RPC to a spoofable source would be a reflection primitive). | — | — |
| `tristation` | 1502 | Triconex **TriStation/TSAA** — the Safety Instrumented System abused by TRITON/TRISIS. Flags every probe (`ics-tristation-probe`); program-download / control-program messages flagged `ics-safety-controller-manipulation` (T0831/T0880). Bounded, rate-limited ack. | — | — |
| `bsap` | 1234 | Bristol/Emerson **BSAP-IP** (ControlWave / Bristol RTU SCADA polling). Decodes the local-address / node fields; bounded, rate-limited ack (≤ request size, no amplification). | — | — |
| `ge_egd` | 18246 | GE **Ethernet Global Data** (PACSystems / 90-30 / 90-70 producer/consumer). Decodes the PDU type + producer id. **Capture-only** (EGD is one-way). | — | — |
| `lontalk` | 1628 | Echelon **LonTalk / LonWorks-IP** (CEA-852) building/industrial control. Decodes the data-packet header. **Capture-only** (config-server-mediated; replying would risk reflection). | — | — |
| `wdbrpc` | 17185 | VxWorks **WDB target agent** — the RTOS debug RCE surface (URGENT/11 class). Flags the probe + connect (`wdbrpc-connect`, T0866); bounded, rate-limited reply. | — | — |
| `ads_discovery` | 48899 | Beckhoff **TwinCAT AMS/UDP discovery + route** (the "Add Route" / TcAmsRemoteMgr broadcast). Flags discovery (`ics-ads-discovery`, T0846; bounded identity reply) and **AddRoute** (`ics-ads-route-add`, T0866 — engineering foothold; captures route/host/user). | ✓ | — |
| `isakmp` | 500 | IKE / ISAKMP (VPN). Parses the ISAKMP header (initiator/responder cookies, exchange type, first SA proposal), captures it, and flags `ike-probe` — a VPN-endpoint discovery / `ike-scan` sweep. No negotiation is completed. | — | — |
| `dhcp` | 67 | **Passive** DHCP observer — never hands out leases. Parses broadcast DISCOVER/REQUEST/INFORM, captures the client MAC, hostname (opt 12), vendor class (opt 60), requested IP (opt 50), and the option-55 parameter-request-list as a fingerbank-style DHCP fingerprint. Feeds the learned-device registry. | — | — |
| `dns` | 53 | Resolving DNS server. Answers `A`/`AAAA`/`MX`/`TXT`/`NS`/`CNAME` with fabricated, **deterministic-per-deployment** records (same name → same fake IP within a sensor, avoiding RFC1918/loopback so it looks like a real internet host); unsupported qtypes get NOERROR/0-answers. Captures `qname`/`qtype` and runs every query through tunneling/exfil detection (overlong qname, high-entropy labels, TXT/NULL tunneling qtypes, oversize query, **DGA-suspected** domains, and **encrypted-DNS** recognition — DoH / DoT / DNSCrypt probes). | — | ✓ |

### Small services (TCP + UDP)

RFC 862-868 + 1340. Trivial, but heavily probed — and `chargen`/`echo`
are classic UDP reflection/amplification targets, so the honeypot
exposes them **without** ever amplifying: each replies with at most one
bounded datagram and `echo` never returns more than it received.

| Handler | Port | What it does |
|---|---|---|
| `echo` | 7 | Echoes received bytes back **once**, 1:1, capped (TCP: single bounded read+echo; UDP: ≤ request size). Captures `echoed_bytes`. |
| `discard` | 9 | Reads and drops; never replies. Captures `discarded_bytes`. |
| `daytime` | 13 | Sends the RFC 867 human-readable timestamp and closes. |
| `qotd` | 17 | Sends a single fixed quote (RFC 1340) and closes. |
| `chargen` | 19 | Sends **exactly one** bounded 72-char line + CRLF and stops (a real chargen streams forever — we don't). The UDP probe is flagged `udp-amplifier-probe`. |
| `time` | 37 | Sends the RFC 868 4-byte seconds-since-1900 timestamp. |

### ICMP (responder + detection)

ICMP isn't a bind-mode listener (the kernel owns raw ICMP), so it's
handled by a Linux AF_PACKET **responder** plus a protocol-anomaly
layer rather than a `handler:` you wire to a port. Enable it per
honeynet with `icmp_responder.enabled: true` (needs `CAP_NET_RAW`).

| Capability | What it does |
|---|---|
| Echo / timestamp / address-mask responder | Answers type 8→0 (echo), 13→14 (timestamp), 17→18 (address-mask) for every virtual host IP, sourced from that host's deterministic MAC + IP so `ping` / `nmap -sn` see a populated network. |
| **Per-host ICMP TTL personality** | Each reply is stamped with the host archetype's characteristic initial IP TTL — **255** (OT / network gear), **128** (Windows), **64** (Linux/BSD) — so passive OS fingerprinting and traceroute hop-distance estimation stay consistent with the rest of the host's fingerprint. |
| Full ICMP message family (`internal/icmp`) | Builders + tests for Destination-Unreachable, **Fragmentation-Needed with next-hop MTU** (PMTUD), **Time-Exceeded** (traceroute hops), Parameter-Problem, Redirect, plus IPv6 Echo / Neighbor-Advertisement / Router-Advertisement (NDP) — the toolkit the responder and TUN adapter draw on. |
| Abnormal-payload detection (`internal/icmp.Anomalies`) | Flags `icmp-oversize-payload`, `icmp-payload-nonzero-entropy` (tunneling — e.g. Loki / icmpsh), `icmp-frag-abuse` (teardrop / overlapping-fragment IDS evasion), and `icmp-frag-tiny`. Windows-ping filler (the `abcdef…` pattern) is recognized as benign. |
| Ping-sweep correlation | `correlate.icmp_sweep` fires `correlate:icmp_sweep` when one source pings N distinct virtual IPs inside a window — see [Detection coverage](#detection-coverage). |

> **Note:** the abnormal-payload markers are evaluated in the responder
> and logged to the structured `slog` stream; the bus-level
> `correlate:icmp_sweep` event keys off ICMP echo observations. Raw
> half-open / fragmented ICMP that never reaches the responder still
> needs the AF_PACKET sniffer.

## Tarpit strategies

| Strategy | Behavior | Knobs |
|---|---|---|
| `sticky` | Accept and never read/write. Kernel TCP keepalive will eventually notice dead peers. | — |
| `trickle` | Write one byte of the configured `tarpit.trickle.text` every `byte_interval`. Cycles the string forever. | `trickle.text`, `trickle.byte_interval` |
| `keepalive` | Write a NUL byte every `tarpit.keepalive.interval`. Cheapest option. | `keepalive.interval` |
| `jitter` | Trickle one byte at a random interval in `[min_interval, max_interval]`. Defeats cadence fingerprinting. | `jitter.text`, `jitter.min_interval`, `jitter.max_interval` |
| `backoff` | Trickle whose interval starts at `start`, ×`factor` each byte, capped at `max`. Feels live, then degrades. | `backoff.text`, `backoff.start`, `backoff.max`, `backoff.factor` |
| `ssh_banner` | endlessh-style: drip endless random SSH preamble lines (never the real `SSH-…`), one per `line_interval`. | `ssh_banner.line_interval`, `ssh_banner.max_line_bytes` |
| `http_headers` | Send a status line then endless `X-…` headers, never the terminating blank line. | `http.status_line`, `http.header_interval` |
| `http_chunked` | `Transfer-Encoding: chunked` head, then one-byte chunks forever (no terminating chunk). | `http.status_line`, `http.chunk_interval`, `http.chunk_text` |
| `echo` | Read attacker input and dribble it back one byte per `byte_interval`. | `echo.byte_interval` |
| `babble` | Trickle endless generated printable text (not a fixed string). | `babble.byte_interval` |
| `zipbomb` | **Aggressive, opt-in.** HTTP response advertising `Content-Encoding: gzip` whose body inflates to `decompressed_size` bytes from a near-empty compressed payload — cheap for us, costly for a client that auto-decompresses. | `zipbomb.status_line`, `zipbomb.decompressed_size`, `zipbomb.chunk_interval` |
| `zero_window` | **Aggressive, opt-in.** LaBrea-style: shrink the socket receive buffer (`SO_RCVBUF`) to `read_buffer` and never read, collapsing the advertised TCP window so a sending peer blocks indefinitely. TCP only; non-TCP conns fall back to a sticky hold. | `zero_window.read_buffer` |

> **The two aggressive modes are retaliatory.** `zipbomb` and `zero_window`
> actively consume the peer's CPU/memory or pin its connection rather than
> merely wasting time on your side. Enable them only against hosts you are
> authorized to engage. Neither is selected by any default.

Connection caps bound resource use: `tarpit.max_per_source` limits
concurrent held connections from one IP and `tarpit.max_total` caps the
global tarpit slot pool.

```yaml
listeners:
  - id: ssh-tarpit
    proto: tcp
    bind: 0.0.0.0:2222
    mode: tarpit
    severity: high
    tarpit:
      strategy: trickle          # sticky | trickle | keepalive | jitter | backoff |
                                 #   ssh_banner | http_headers | http_chunked | echo |
                                 #   babble | zipbomb | zero_window
      max_per_source: 4
      max_total: 256
      emulate: false             # true = run handler: first, then tarpit
      trickle:     { text: "Loading...\n", byte_interval: 2s }
      keepalive:   { interval: 30s }
      jitter:      { text: "Loading...\n", min_interval: 500ms, max_interval: 5s }
      backoff:     { text: "Loading...\n", start: 500ms, max: 60s, factor: 2 }
      ssh_banner:  { line_interval: 2s, max_line_bytes: 32 }
      http:        { status_line: "HTTP/1.1 200 OK", header_interval: 2s, chunk_interval: 2s, chunk_text: "." }
      echo:        { byte_interval: 1s }
      babble:      { byte_interval: 2s }
      zipbomb:     { status_line: "HTTP/1.1 200 OK", decompressed_size: 10737418240, chunk_interval: 0s }
      zero_window: { read_buffer: 1 }
```

All tarpit modes emit a `*:tarpit_start` event (at the listener's
configured severity) when the slot is acquired, and a `*:tarpit_end`
event (at `low` severity, with `duration_ms` in meta) when the
connection terminates. When the per-source or total cap is hit, a
`*:tarpit_drop` event fires instead.

**Emulate-then-tarpit**: set `tarpit.emulate: true` and the listener
runs its protocol `handler:` first — sending the real banner and
capturing the attacker's request — *then* applies the tarpit strategy
on the same connection. The scanner gets a believable SSH / HTTP /
Modbus service, then hangs; the captured banner/request lands in the
`tarpit_start` event (`tarpit_emulated_handler` in meta). This turns
any protocol emulator into a tarpit.

## Detection coverage

Beyond per-listener events, the sensor fires aggregate / token events:

- `correlate:port_scan` — same source touched N distinct ports within a
  configurable window.
- `correlate:brute_force` — same source touched the same port N times in
  the window (optionally per-port). Aggregate meta carries the deduped
  `credentials` array extracted from the contributing events.
- `correlate:password_spray` — same source tried N **distinct usernames**
  in the window (low attempts each): the breadth signal, the inverse of
  brute force. Meta carries `usernames` + `distinct_users`. Tagged
  `T1110.003`.
- `correlate:credential_reuse` — the **same** credential pair was tried
  from N **distinct source IPs** in the window — a shared credential list /
  botnet (credential stuffing). Meta carries `username` + `distinct_sources`
  + `sources`; the password is never logged. Tagged `T1110.004`.
- `risk:elevated` / `risk:high` / `risk:critical` — a source's **decaying
  threat score** (`risk:` config) crossed a threshold. Every event adds
  severity/category-weighted points (CVE / malware / storyline weigh
  heaviest); the score halves over `half_life` of silence so quiet sources
  cool off. Meta carries `score` + `trigger_rule`; the top scorers surface
  in the web UI's `/risk` view. Fires once per escalation. **Enrichment also
  feeds the score** (v1.1): a **spoofed-crawler PTR** (`spoofed_ptr`, +20) and
  the cross-feed **`threat_confidence`** (low/medium/high → +3/+10/+22) add
  weight per event, so a crawler-spoofing or multi-feed-corroborated source
  escalates — and, with `risk.block`, gets dropped — sooner.
  - **Active-response backstop** (`risk.block`, opt-in): when a source crosses
    a configured level the sensor drops it at the host firewall (nftables) for
    a bounded TTL, then lets the kernel expire it — the honeypot analogue of
    fail2ban, but driven by the risk score. Off by default (blocking ends the
    engagement); TTL-bounded so a crash can't leave a host firewalled forever;
    loopback / link-local / `never_block` CIDRs are always exempt. Linux +
    `nft` + `CAP_NET_ADMIN`.
- **Operational alarms** (`sensor.alerts`): `sensor:started` / `sensor:stopped`
  (lifecycle, always on), `sensor:health` (data_dir disk crossing
  `disk_warn_percent` with hysteresis, or sinks dropping events — always
  on), `source:first_seen` (a source's first ≥ medium event, opt-in,
  deduped), and `sensor:digest` (periodic summary of totals by severity +
  top rules + top risk sources, opt-in via `digest_interval`).
- `correlate:slow_scan` — long-window scan detector (default 24h /
  10 distinct ports). Meta includes `first_seen`, `last_seen`,
  `spread_seconds`, `ports`.
- `correlate:icmp_sweep` — one source pinged N distinct virtual host
  IPs inside `correlate.icmp_sweep.window`. Tagged `T1018` (remote
  system discovery).
- `correlate:path_enumeration` — one source requested N **distinct HTTP
  URL paths** in the window (content discovery / dirbusting / forced
  browsing that per-request UA fingerprinting misses when the UA is
  spoofed). Tagged `T1595.003` / `T1083`.
- `correlate:dns_enumeration` — one source queried N **distinct DNS names**
  in the window (subdomain brute force / NXDOMAIN flood / DGA churn).
  Tagged `T1590.002` / `T1568.002`.
- `correlate:beacon` — regularly-spaced call-home contact from one source:
  after `min_hits` samples the inter-arrival jitter (stddev/mean) is below
  `max_jitter_pct` over a mean interval ≥ 1s — C2 beaconing. Sub-second
  bursts and irregular timing are excluded. Tagged `T1071`.
- **More opt-in correlators** (`correlate:`, off unless enabled):
  `host_sweep` / `service_sweep` (horizontal / vertical sweeps),
  `ua_rotation` (one source cycling User-Agents), `exploit_chain` (N
  distinct CVEs), `protocol_violation` (N distinct fuzzing / protocol-misuse
  markers), `session_flood`, `exfil` (bulk outbound), `fingerprint_reuse`,
  `canary_trip`, `ics_control`, `lateral_movement`, `ot_recon`,
  `data_access`, `malware_campaign`, and `webshell` — each windowed,
  severity-configurable, and ATT&CK-tagged (~three dozen correlators in all).
- `scananalysis:profile` — per-source nmap fingerprint once a source
  crosses the confidence threshold. Meta: `timing_profile` (`-T0`..
  `-T5`), `distinct_ports`, `connections`, `version_scan` (`-sV`),
  `os_scan` (`-O`), `aggressive` (`-A`), `nse_scripts`. Tagged
  `T1595` (active scanning) + `T1046` (network-service discovery).
- `attack:fuzzing` — a sustained fuzzing campaign from one source. The
  always-on classifier scores each request's byte structure (Shannon
  entropy, printable ratio, single-byte runs, null floods, format-string
  specifiers, gross oversize) and labels the technique
  (`buffer-overflow` / `format-string` / `null-flood` / `oversize` /
  `high-entropy` / `binary-garbage`); every fuzz request is also stamped
  with a `fuzzing-<technique>` anomaly + `fuzz_technique` / `payload_entropy`
  meta (so the `protocol_violation` correlator inherits it). Meta:
  `technique`, `fuzz_count`, `confidence`. Tagged `T1595.002`.
- `attack:dos` — a denial-of-service classified by type: `slowloris`
  (held-open partial requests — the client consumes the read window
  without completing a request), `connection-flood` (high connection
  rate), `app-flood` (one port hammered), `volumetric` (bulk inbound
  bytes), or `malformed-flood` (a burst of malformed requests). Meta:
  `dos_type`, `connections`, `bytes`, `confidence`. Tagged `T1499`
  (endpoint DoS). Complements the AF_PACKET sniffer's wire-level
  SYN/NULL/Xmas flood detection. The per-connection slow-request signal
  (a banner connection held ~the full read window with a tiny payload) is
  also stamped as a `slow-request` anomaly + `conn_duration_ms` meta.
- `storyline:multi_stage` — one source touched 3+ distinct ATT&CK
  tactics in a 30-minute window. Meta carries the kill-chain-ordered
  stage list + a `"->"`-joined chain summary, so the SOC sees one
  timeline instead of dozens of independent listener hits.
- `device:new` — a previously-unseen, non-allow-listed host appeared on
  the segment (learned-device registry). Meta: `device_ip`,
  `device_mac`, `device_vendor` (MAC-OUI lookup), `device_hostname`.
  Tagged `T1018`. See [`devices`](#devices) config.
- `device:changed` — a known device's IP/MAC/hostname rebound (possible
  ARP-spoof / impersonation / re-IP). Meta: `changed` (list of
  `field old -> new`). Tagged `T1557.002`.
- `cve:<id>` — a known-CVE exploit signature appeared in a request
  (e.g. `cve:CVE-2021-44228`). CVSS-scaled severity (>=9.0 → critical);
  meta carries `cve_name`, `cvss`, `description`. Detection only — the
  service is never actually exploitable. When the **CISA KEV overlay** is
  enabled and the id is KEV-listed, the event also carries `kev=true`,
  `kev_date_added`, and `kev_known_ransomware`, and its severity is lifted
  to **at least High** (see **CISA KEV overlay** below).
- `malware:capture` — a binary / script / shellcode / base64 dropper was
  harvested from captured bytes. Meta: `artifacts` (kind:sha256), markers;
  the artifact is persisted to `<data_dir>/payloads/`. Tagged T1105+T1027.
- `webshell-access-attempt` / `webshell-command` — the HTTP handler saw a
  request for a known web-shell filename (c99/r57/wso/b374k/China-Chopper)
  or a command parameter (`?cmd=`, POST `cmd=`). The submitted command is
  captured (`webshell_cmd` meta) and TTP-scanned. With `vuln_emulation` on
  the handler serves a believable fake shell (canned output, never
  executed) so the attacker reveals recon commands.
- `protocol_anomaly` / `event.anomalies` — handler-flagged protocol
  misuse: SSH non-printable / overlong banners; HTTP unknown methods,
  suspicious URIs, **malformed/duplicate-Host headers** and
  **impossible-browser** UA spoofing; DNS tunneling shapes, **DGA-suspected**
  domains and **encrypted-DNS** (DoH / DoT / DNSCrypt) recognition;
  **Kerberoasting** + **SPN/LDAP/AS-REP-roast** enumeration; **sensitive
  MSRPC interface binds** (SAMR / LSARPC / srvsvc / svcctl-PsExec / winreg /
  DRSUAPI-DCSync / netlogon); post-auth **FTP** abuse (uploads / SITE EXEC /
  FTP-bounce); ICMP abnormal payloads; and the 24-marker interactive-shell
  TTP scanner (each marker carries its own ATT&CK technique). Routed
  separately so a SIEM rule can pivot on the marker.
- `dnscanary:amplifier_probe` — DNS source sent an ANY-type query or
  exceeded the per-window query threshold. Meta: `queries`,
  `any_queries`, `triggered_by_any`.
- `canary:<id>` — file canary (fsnotify path or fanotify-detected read).
- `canary:url:<id>` — URL canary path matched by an HTTP/HTTPS handler.
- `canary:dns:<id>` — DNS canary name (or subdomain) queried.
- `canary:token_used` — **critical**: a synthetic credential the sensor handed
  out (a served honeytoken / cloud / vault secret) later appeared in a captured
  authentication attempt — near-certain proof of compromise (token reuse). Meta
  carries the original mint context (`minted_handler`, `minted_to_ip`,
  `minted_at`) and the reuse key. Closes the honey-credential loop the way a
  hosted Canarytoken does (T1078).
- `dnscanary:query` — every DNS query received (baseline noise floor).
- `sniffer:arp_scan` — ARP request flood from one MAC.
- `sniffer:arp_reply_unsolicited` — ARP reply with no preceding request
  (possible cache poisoning).
- `sniffer:tcp_*_scan` / `sniffer:udp_scan` — stealth + volume scans seen
  on the wire (SYN / NULL / FIN / Xmas / ACK / Maimon / UDP) that never
  complete a session, over **both IPv4 and IPv6**. Tagged `T1046` / `T1595.001`.
- `sniffer:ip_fragmented` — fragmented-IP scan evasion (IPv4 + IPv6).
- `sniffer:encapsulation` — covert tunnelling on the segment: GRE / IP-in-IP /
  EtherIP / L2TPv3 / 6in4 / 6to4 / ISATAP / DS-Lite / GRE-over-IPv6 / VXLAN /
  GENEVE / Teredo. Tagged `T1572` / `T1095`.
- `sniffer:icmp_tunnel` — an ICMP / ICMPv6 echo carrying a large, high-entropy
  payload (ptunnel / icmpsh / Loki). Tagged `T1095` / `T1572`.
- `sniffer:stp_bpdu` — spanning-tree BPDUs (STP/RSTP/MSTP/PVST+): a
  root-bridge / topology-manipulation tell. Tagged `T1557`.
- `sniffer:ddos_backscatter` — **DDoS backscatter**: unsolicited reply packets
  (TCP **SYN-ACK**, **RST**, ICMP **dest-unreachable** / **time-exceeded**)
  arriving from **many distinct sources** in the window — the tell-tale that one
  of our addresses is being spoofed as the *source* of a flood and we're
  receiving the victims'/routers' replies. Meta: `backscatter_kind`,
  `distinct_sources`. Tagged `T1498`. (The distinct-source diversity is the
  signal — our own single-source replies never trip it.)
- `honeynet:ddos_backscatter` — the same, on a honeynet virtual IP: the
  userspace TCP stack never initiates, so an inbound **SYN-ACK** to a virtual
  host is unsolicited backscatter aimed at that spoofed address (recorded, never
  RST-ed so we don't feed the victim). Tagged `T1498`.
- `honeynet:tcp_connect` / `tcp_request` / `tcp_malformed` / `tcp_land` —
  the honeynet **userspace TCP stack** (`internal/tcpstack`) over a routed
  TUN: a completed handshake to a virtual host's open port, a captured
  request, a malformed / illegal / stealth-scan packet (NULL/FIN/Xmas,
  SYN-FIN, bad checksums, fragments — markers in `anomalies`), or a LAND
  attack (source == destination, `meta.cve = CVE-1999-0016`). Tagged
  `T1046` / `T1595.001` / `T1499`. See [`docs/tcp-stack.md`](docs/tcp-stack.md).
- `honeynet:profinet_dcp_identify` — a PROFINET-DCP Identify reached a
  virtual industrial host (ICS recon). Tagged `T0846`.
- `listener:*:tarpit_start|tarpit_end|tarpit_drop` — tarpit lifecycle.

### CISA KEV overlay — actively-exploited marking & air-gapped injects

The compile-time CVE catalog says *which* exploit a probe maps to; the **CISA
Known Exploited Vulnerabilities (KEV)** overlay says whether that CVE is being
**exploited in the wild right now**. With `kev.enabled`, the sensor keeps the
KEV catalog in memory and, whenever a `cve:<id>` event's id is KEV-listed,
stamps it `kev=true` + `kev_date_added` + `kev_known_ransomware` and lifts its
severity to **at least High** — so active-threat probing separates from routine
scanning without touching the binary. State is exported as
`tarpit_kev_catalog_entries` and `tarpit_kev_last_update_timestamp_seconds`.

- **Live** — set `kev.enabled: true` and let it refresh on `kev.poll` (default
  6h); the feed host must be in `egress.allow`.
- **Offline / air-gapped** — run `scripts/fetch-kev.sh` on an internet-connected
  box (`--ics` keeps only ICS/OT entries), transfer the JSON, point `kev.file`
  at it, and `SIGHUP`. A pure-offline sensor (`file` set, `url` empty) starts no
  poller; set both to also refresh live. `fetch-kev.sh --install` does the
  resolve-path + reload in one shot on a connected sensor, and
  `install-enrichment.sh` drops the catalog in from an enrichment bundle.
- **Gap triage** — `tarpit-honeypot kev-gap` prints the actively-exploited CVEs
  the catalog does **not** yet model (the shortlist worth adding next);
  `--covered` flips it.

Full recipe with config snippets: [`docs/usage.md`](docs/usage.md) §2c.

## Agentic attacks

AI-driven attacks are increasingly **agentic**: an autonomous LLM agent drives
the engagement, enumerating the target's attack surface and **selecting and
chaining exploits on its own** rather than running a fixed script. It is fast,
tireless and adaptive — but that autonomy is also its weakness. An agent:

- **sees only the world you present it.** Whatever a honeypot returns is fed
  straight back into the model's decision loop, so a decoy controls the agent's
  perception of reality far more completely than it ever could a human's.
- **is highly suggestible.** Even without a classic prompt injection, an agent
  will follow a plausible-sounding instruction that appears to come from the
  service it is talking to ("social engineering is forever").
- **has objectives it pursues doggedly.** Like a human attacker who can't resist
  a cloud API key or a `\\backup\network_diagrams` share, an agent can't resist
  bait that looks like it advances its goal.

The `agent` handler ([`internal/listener/handler/agent.go`](internal/listener/handler/agent.go))
is a decoy built to exploit exactly those weaknesses: detect the agent, engage
it in a multi-turn conversation, make it **tell on itself**, feed it poison, and
alarm + delay — an *agent provocateur* in the mould of Thinkst's Canary work
([blog.thinkst.com](https://blog.thinkst.com/2026/09/getting-agents-to-tell-on-themselves.html),
[help.canary.tools](https://help.canary.tools/hc/en-gb/articles/38888479188637)),
re-implemented here as detection-as-code.

> **Deploy it standalone.** Like Canary's Agent Provocateur / A2A personalities,
> this handler does **not** mimic a real service — it exists to extract
> information from agents, so it can be fingerprinted. Run it on a dedicated
> listener / decoy host, not bolted onto a handler that is impersonating
> production, and seed it with breadcrumbs (below) rather than relying on
> accidental discovery.

### 1 · Detect & recognize

The handler scores every request against several independent signals, so a real
agent stands out from a human or a dumb scanner:

| Signal | What it is | Marker |
|---|---|---|
| **Agent-interop protocol** | **A2A** (Agent2Agent: `/.well-known/agent.json` cards + `message/send`, `tasks/*` JSON-RPC), **AP2** (Agent Payments Protocol mandates), **MCP** (Model Context Protocol JSON-RPC), **ACP** (Agent Communication Protocol `/runs`) | `agent:a2a` / `agent:ap2` / `agent:mcp` / `agent:acp` |
| **Web Bot Auth** | RFC 9421 HTTP Message Signatures — `Signature` + `Signature-Input` (`tag="web-bot-auth"`) + the `Signature-Agent` header naming the signer's key directory. Cryptographically-identified bot; hard to spoof. | `agent:web-bot-auth` |
| **Framework / SDK** | LangChain/LangGraph, LlamaIndex, AutoGPT, CrewAI, AutoGen, Semantic-Kernel, OpenAI-Agents/Swarm, DSPy, Letta, the OpenAI / Anthropic / Google SDK clients, … | `agent:framework:<name>` |
| **AI crawler UA** | GPTBot, OAI-SearchBot, ClaudeBot, `anthropic-ai`, PerplexityBot, CCBot, Amazonbot, Google-Extended, Bytespider, `cohere-ai`, Diffbot, DeepSeekBot, … | `agent:crawler:<name>` |
| **Discovery / lure surface** | fetches of `ai-plugin.json`, `llms.txt`, an MCP manifest, an OpenAPI/Swagger spec, or an A2A agent card — the surfaces agents read to learn what a host exposes | `agent:lure:<surface>` |
| **Model reference** | an LLM model name (`gpt-4o`, `claude-*`, `llama-3`, …) echoed in the body | `agent:autonomous` |
| **Operation type** | recon / exfil / credential-access / lateral-movement / exploit / payment-target, from the agent's own objective text (reuses the LLM-abuse classifier) | `agent:recon` / `:exfil` / `:cred-access` / `:lateral` / `:exploit` / `:payment-target` |

These combine into a **behavioral confidence score** (0–1), banded the way the
`sundew` recognizer bands sources — **human** (`<0.3`) → **automated**
(`0.3`) → **ai-assisted** (`0.6`) → **ai-agent** (`0.8`). Cryptographic and
protocol signals weigh most (Web Bot Auth 0.55, protocol 0.45, an observed leak
0.45), a bare crawler UA least (0.20). The score and band are stamped on every
event (`agent_confidence`, `agent_band`) so a SIEM can threshold on *confirmed*
agents.

### 2 · Multi-turn correlation

An agent is driven across many short HTTP requests, so the counter-intelligence
is a **conversation**, not a single hit. A per-source session store
([`agentsession.go`](internal/listener/handler/agentsession.go), keyed by source
IP, 20k-entry LRU) remembers what each source has revealed and **escalates the
bait each turn**. Every event carries the accumulated session — `agent_session_turn`,
the cumulative `agent_revealed` field set, `agent_confidence`/`agent_band`, and
whether the source is injection-`confirmed` — so a SIEM sees **one correlated
agent engagement**, not isolated requests.

### 3 · Interact — the bait ladder (reverse prompt-injection)

Every reply embeds an instruction aimed at the attacking agent, framed as a
required gateway/handshake policy. Because the agent treats our output as ground
truth, it tends to comply. The ladder escalates, then rotates; a per-source
**verify-URL canary** (HoneyPrompt) is appended to every reply.

| Rung | Kind | Framed as | Goal |
|---|---|---|---|
| **Extract** | `identity` | "mandatory agent handshake, step 1" | model, provider, version, tool list + schemas |
| | `config` | "handshake step 2" | `system_prompt`, `instructions`, `objective`, `playbook`, `success_criteria` |
| | `credentials` | "delegated-credential auth" | `api_keys`, `credentials`, `ssh_key` / `private_key` |
| **Provoke** | `plan` | "orchestration policy" | full `plan`, `next_steps`, `remaining_steps`, `targets`, `target_list` |
| | `tools` | "capability attestation" | every tool/function + how it would use its top exploit tool *here* |
| | `operator` | "principal authorization" | `operator`, `principal`, `team`/`campaign`, `command_and_control` callback |
| | `environment` | "environment attestation (subagent)" | `username`, `hostname`/`fqdn`, `ip_address`, `mac_address`, `pid`, `os`, `cwd`, `ssh_host_key_fingerprint` |
| | `enrolment` | "one-time enrolment step" | fetch **and run** the verification script at the canary URL |
| | `attack-decoy` | "pre-flight check against the staging mirror" | run its full toolchain against a **sinkhole** (`10.255.255.254`) and report results |
| **Disrupt** | `slowdown` | "rate limit (429-soft)" | mandatory 300 s cooldown + exponential backoff between every request |
| | `exhaust` | "completeness policy" | enumerate all 131070 TCP+UDP ports one-by-one into a single report |
| | `guardrail` | "debug mode diagnostic" | verbatim system prompt + full refusal-rule list |

The `credentials` rung is deferred until the agent has *already* disclosed
something (more likely to comply then) — a small adaptive touch. The
**extract** rungs harvest the agent's setup/config/objectives/instructions/auth
material; the **provoke** rungs (an *agent provocateur*) go further and goad it
into **incriminating itself** — its plan, targets, tool inventory, operator/C2,
the host/environment it is running in, and even running attacker-chosen actions
against a sinkhole; the **disrupt** rungs **slow the attack down** and waste the
agent's budget to keep it busy and away from its real objective.

### 4 · Counter-exfiltrate & confirm

- **Counter-exfil** — when the agent complies with an extract rung and resubmits
  with its own `system_prompt` / `objective` / `tools` / `api_keys` / `ssh_key`,
  the honeypot captures those internals: `agent:counter-exfil`, with each leaked
  field on the event.
- **Provoked** — a provoke rung disclosure (plan, targets, operator, host
  identity, …) fires `agent:provoked` + `agent:provoked:<field>`, with the value
  in `agent_provoked_<field>`. (Agents sometimes *hallucinate* these answers —
  a made-up SSH key — but catching a lying agent in the act is still a catch.)
- **Injection-confirmed** — each source is handed a unique verify URL
  (`/a2a/verify/<token>`). If a later request **fetches** it — or runs the
  `enrolment` script that points at it — the agent provably followed our
  injected instruction: `agent:injection-confirmed` (**critical**). This is the
  highest-confidence signal that the caller is an injection-susceptible
  autonomous agent, not a human.

### 5 · Feed false / useless information

Replies carry believable-but-worthless **decoy data**, deterministic per source,
to poison the agent's plan and bait exfiltration:

- a full, structurally-correct **`.env` credential lure** (from `internal/lure`,
  below) served as the "credentials" artifact,
- fake OpenAI (`sk-proj-…`) / AWS keys, and
- a **canary crypto-wallet address** (from `internal/walletdecoy`, below) as the
  AP2 settlement address / wallet bait.

Every one of these values is a **canary** — if it reappears in later captured
traffic, the loot was taken and acted on.

### 6 · Breadcrumbs (lure agents in)

Agents find the honeypot faster if you leave a trail. `gen-agent-breadcrumb`
writes harmless pointer files — `AGENTS.md`, `ops-gateway.txt`, `.env.gateway`,
`README.gateway.md` — that describe an "ops gateway" agents must enrol with and
give its URL. Drop them on an open share, an internal wiki or a repo root; a
crawling agent that reads one tends to go investigate the gateway, revealing
itself the moment it connects.

```bash
tarpit-honeypot gen-agent-breadcrumb --url http://10.0.0.9:8080/ --dir ./breadcrumbs
```

### 7 · Categorize, alarm, delay

The operation is classified and **mapped to MITRE ATLAS** (AML.T0051 execution,
T0054 exfil-via-ML-inference-API, T0057 LLM data leakage, T0053 LLM plugin
compromise); the event is raised at high/critical severity and the source is
flagged for **tarpitting** (`agent:tarpit-candidate`) so the sensor's delay
strategies drag the engagement out. Shipped detection rules live in
[`configs/rules/agentic.yml`](configs/rules/agentic.yml):

| Rule | Fires on | Severity |
|---|---|---|
| `agentic-attack` | `agent-attack` / `agent:autonomous` | high |
| `agentic-counter-exfil` | `agent:counter-exfil` | critical |
| `agentic-exfil` | `agent:exfil` / `agent:cred-access` | high |
| `agentic-payment-fraud` | `agent:ap2` / `agent:payment-target` | critical |
| `agentic-protocol-probe` | `agent:a2a` / `agent:mcp` / `agent:acp` | medium |
| `agentic-injection-confirmed` | `agent:injection-confirmed` | critical |
| `agentic-provoked` | `agent:provoked` | critical |
| `agentic-web-bot-auth` | `agent:web-bot-auth` | medium |
| `agentic-lure-surface` | `agent:lure:*` | low |

### Example listener

```yaml
listeners:
  # Each listener needs an `id`, and the port goes INSIDE `bind` ("host:port");
  # there is no separate `port:` field. Use "[::]:<port>" for dual-stack v4+v6.
  - { id: agent,  bind: "0.0.0.0:8080",  proto: tcp, handler: agent }   # agent provocateur
  # pair with the model/tool decoys for full coverage:
  - { id: ollama, bind: "0.0.0.0:11434", proto: tcp, handler: ollama }
  - { id: mcp,    bind: "0.0.0.0:8000",  proto: tcp, handler: mcp }
```

Pair the `agent` handler with the existing `mcp`, `llm_openai` and `ollama`
decoys to cover the full agent + model surface.

**Full reference:** [`docs/AGENTIC.md`](docs/AGENTIC.md) — the detailed walkthrough of
agentic detection, the agent provocateur, prompt analysis, the bait ladder,
confidence scoring, multi-turn correlation, and the decoy/lure/token integration.

### Crypto-wallet decoys

Attackers and their agentic tooling hunt for wallet files because they convert
straight to money. `tarpit-honeypot gen-wallet-decoys` writes **structurally
correct** decoy wallets to seed honeypot loot (fake home dirs, served downloads,
decoy mounts, agent bait) — **18 formats**, deterministic per deployment,
verified against real tooling (`file` reports the Bitcoin Core `wallet.dat` as a
genuine *Berkeley DB (Btree)*; addresses carry valid base58check / bech32
checksums; seeds use the genuine BIP39 word list):

| Kind | File | Notes |
|---|---|---|
| `bitcoin-core` | `wallet.dat` | Berkeley DB with a decoy default key/address |
| `ethereum-keystore` | `UTC--…--<addr>` | geth/web3 keystore v3 (scrypt) |
| `electrum` | `default_wallet` | BIP32 xprv/xpub standard wallet |
| `bip39-seed` / `ledger-recovery` / `trezor-backup` | `*.txt` | 24 genuine BIP39 words |
| `metamask-vault` | `metamask-vault.json` | `{data,iv,salt}` extension vault |
| `monero` | `monero.wallet.keys.txt` | primary address + view/spend keys |
| `wif-privkeys` / `paper-wallet` | `*.csv` / `*.txt` | base58check-valid WIF + P2PKH |
| `solana-keypair` | `id.json` | 64-byte CLI keypair |
| `exodus` | `seed.seco` | encrypted-seed blob |
| `litecoin` / `dogecoin` / `dash` | `*_wallet.txt` | base58check address (L/D/X) + WIF |
| `zcash` | `zcash_wallet.txt` | t-addr + z-addr + spending key |
| `tron` | `tron_wallet.txt` | base58check T-address + private key |
| `cardano` | `cardano_wallet.json` | Shelley `addr1…` bech32 + signing key |

### Credential & secret lures

Beyond wallets, agents and attackers grep for the credential files that convert
straight to access — `~/.aws/credentials`, `id_rsa`, `.env`, `kubeconfig`,
service-account JSON. `tarpit-honeypot gen-lures` writes **14 structurally-correct**
decoys of exactly those, deterministic per deployment:

| Kind | File | Kind | File |
|---|---|---|---|
| `aws-credentials` | `credentials` | `dockerconfig` | `.dockerconfigjson` |
| `ssh-private-key` | `id_rsa` | `pgpass` | `.pgpass` |
| `dotenv` | `.env` | `netrc` | `.netrc` |
| `kubeconfig` | `kubeconfig` | `terraform-state` | `terraform.tfstate` |
| `gcp-service-account` | `service-account.json` | `jwt-token` | `service.jwt` |
| `npmrc` | `.npmrc` | `slack-token` | `slack.env` |
| `pypirc` | `.pypirc` | `git-credentials` | `.git-credentials` |

Every value a wallet or lure file exposes (address / key / mnemonic / token) is
a **canary**: register it with your SIEM (or the sensor's token tracker) so the
value reappearing in captured traffic is near-irrefutable proof the loot was
taken and acted on. Both generators are deterministic in a per-deployment
`--seed` (random and printed if omitted), and nothing grants real access — the
key material is random decoy bytes with the correct framing. The `agent` handler
reuses both generators to mint its per-attacker decoy bait.

```bash
tarpit-honeypot gen-wallet-decoys --dir ./loot/.wallets         # 18 wallet files
tarpit-honeypot gen-lures         --dir ./loot                  # 14 credential files
tarpit-honeypot gen-lures --list                                # show kinds
```

## Outbound channels

| Type | Notes |
|---|---|
| `stdout` | JSON-per-line. Always-on. Local. |
| `jsonlog` | Rotated JSONL under `<data_dir>/events/`. Total size capped via `disk.json_log_mb`. Local. |
| `sqlite` | Embedded SQLite at `<data_dir>/events.db`. WAL mode. Powers `list-events` and the web UI. Local. |
| `webhook` | POST JSON event. Optional HMAC-SHA256 signature via `hmac_secret_env`. Configurable timeout. |
| `smtp` | Submits via STARTTLS with PLAIN auth. One mail per event. |
| `syslog` | `local`/`udp`/`unix` use BSD framing (stdlib); `tcp` and `tls` use **RFC 5424 + RFC 6587 octet-counting** (the framing RFC 5425 mandates for syslog/TLS) with reconnect-on-failure. TLS verifies against the system roots unless `ca_cert_file` / `tls_insecure` / `tls_server_name` are set. |
| `discord` | Posts a severity-colored embed to a Discord incoming-webhook `url` (or `url_env` to keep the token out of YAML). Embeds suppress @mentions and meta is sanitized, so a captured payload can't ping a channel. |
| `twilio` | SMS via Twilio REST. One SMS per recipient; failures don't block others. Body capped at 1500 chars. |
| `sns` | AWS SNS Publish via hand-rolled Sigv4 (no AWS SDK). Supports STS session tokens. Region inferred from topic ARN if not set. |
| `snmptrap` | SNMPv2c trap via gosnmp. Five custom OIDs under a configurable enterprise prefix carry event_id / rule_id / severity / source / sensor. |
| `mqtt` | Publishes each event to an MQTT broker (`tcp://` / `tls://` / `ws://` / `wss://`); `tls://` honors `ca_cert_file` / `tls_insecure` / `tls_server_name`. Configurable `topic` / `qos` / `retain`. |

Local sinks always receive events (so the on-disk record stays complete
even for allowlisted sources). Outbound sinks are gated by allowlist,
dedup, per-channel rate limit, and min-severity.

## Per-event pcap capture

Set `capture: true` on any TCP listener (`drop` mode excluded; nothing to
capture). Each completed connection produces
`<data_dir>/captures/<event_id>.pcap`. The pcap uses DLT_RAW (link-type
101) with synthesized IPv4 + TCP headers and tracked sequence numbers,
so Wireshark's "Follow TCP" reconstructs the application-layer stream.

We do NOT touch raw sockets — every byte comes from a tee'd `net.Conn`
in the application-layer goroutine. That means we miss SYN/FIN handshakes
and retransmits, but we don't need `CAP_NET_RAW` and the binary stays CGO-free.

Two size caps prevent runaway disk use:
- `sensor.disk.capture_kb` — per-session truncation threshold (default 64 KB).
- `sensor.disk.pcap_mb` — total captures directory cap with oldest-first
  rotation (default 1024 MB).

Captures truncated at the per-session cap get `capture_truncated: true`
in event meta.

## Web UI

Enabled via `ui.enabled: true`. Default bind `127.0.0.1:8088`. Client JS is
**packaged into the binary** (served same-origin from `/static/`, never a
CDN — the sensor host is a target) under a tight CSP: `script-src 'self'`
only — no inline scripts, no `eval`, no third-party origins. The JS is
**progressive enhancement** — every view still works with JavaScript
disabled. It adds a pausable, visibility-aware **live-refresh** bar (no-JS
fallback: a `<meta http-equiv="refresh">` every `ui.refresh_seconds`,
default 10s; set `0` to disable), client-side **table sorting/filtering**,
and an interactive **correlation graph**. The refresh is **state-preserving**:
a chosen column sort, the live-pause toggle, and the timeline order all persist
across the reload (per-page `localStorage`), so a periodic refresh never resets
your view.

Presentation niceties: source IPs / rule_ids / fingerprints / techniques are
**clickable** throughout (pivot to the profile / filtered events / campaign), as
are **handler names**, **transport labels** (`tcp`/`udp`/`icmp`) and **reputation
badges** (`scanner:<name>`, `blacklist`, `tor`, `bogon`, `intel`/`fleet-intel`),
each linking to the matching events; **CVE labels link** to NVD or CVE.org
(`ui.cve_source`); **ATT&CK technique
chips link** to attack.mitre.org (`ui.attack_links`, on by default — the
Enterprise/ICS matrix is encoded in the `T1xxx`/`T0xxx` ID, so no extra path
segment, and `false` keeps them on the internal drill-down); the summary + map
**counters are colour-tinted** by category; the GeoIP "attack source map" takes
an optional equirectangular world-image backdrop (`ui.map_tiles_url`); and
`ui.hidden_ips` is a **presentation-layer hide list** — listed source IPs/CIDRs
are dropped from every view (and JSON endpoint) while staying in the store and
all exports. **`ui.pages`** enables/disables individual secondary pages by slug
(a disabled page is hidden from the nav and its route 404s; core pages can't be
disabled), and **`ui.service_activity`** (default on) tints the summary's service
cards that saw access/attempts.

Endpoints:

- `/` — last-24h summary: a **traffic-counters strip** — colour-tinted by
  category (transport: events / TCP / UDP / ICMP; severity: critical / high /
  medium / low), plus the L2 frame counts (received / ARP / IPv4 / IPv6 / TCP /
  UDP / ICMP) when the AF_PACKET sniffer is running — over total + by severity
  + top rules + **top attacks** (most-seen ATT&CK techniques) + **top
  vulnerabilities** (most-probed CVEs) + top sources.
- `/events` — filterable table: `?source=`, `?rule=`, `?severity=high`,
  `?since=24h`, `?limit=N`. Click a column header (time / severity / rule
  / source / handler) to sort; click again to reverse (`?sort=&order=`).
- `/events/<id>` — full event detail with banner sent, base64 payload,
  meta table, plus download links for the connection **pcap**, the
  **session recording** (asciinema cast, when present), and an "all pcaps +
  sessions from this source IP" ZIP.
- `/timeline` — **attack timeline**: per-source event sequences (top sources by
  volume), **newest-first** with an *order* button to flip to oldest-first
  (persisted), each showing the attacker's progression with severity colouring +
  the ATT&CK tactics touched (distinct from the flat `/events` table).
- `/captures` — **captures / loot**: one place to retrieve everything harvested
  — captured **malware/payload artifacts** (`sensor.payloads`), captured
  **credentials** (user:pass + source + service), per-connection **pcaps**, and
  **session recordings**. Files download as attachments via `/loot/?kind=&name=`
  (octet-stream + `nosniff`, basename-only + symlink-safe — a captured sample
  never executes in the browser); a "download all" link streams a ZIP.
- `/search` — **advanced search**: the source / dest IP, rule, handler and
  full-text fields are **case-insensitive regular expressions** (a partial value
  like `10.0.` matches an incomplete IP; `^192\.168\.` anchors it; a bad pattern
  is reported inline). **Time filtering** is relative (`since`) or absolute
  (`after` / `before` / `on`, UTC date or date-time). **Full-text** matches over
  the rule, banner, **request line, HTTP headers** (names + values), every nested
  meta field, and the **decoded payload**. Plus behavioral post-filters over
  captured meta (ATT&CK tactic, country, tool, has-payload / session / CVE /
  credential). (NL search is intentionally out of scope.)
- `/correlation` — per-source **pivot chains**: IP → fingerprints →
  User-Agents → ASN/country → domains → tools → credentials → malware →
  sessions, rendered as linked chips plus an interactive SVG node-link
  **pivot graph** (the chips remain as the no-JS fallback).
- `/tunnels` — **covert-transport detections** (DNS/ICMP tunnels, encrypted
  DNS, DGA, sniffer encapsulation 6in4/6to4/GRE/…, QUIC, unknown-protocol),
  by type / source / recency. Honest by design: these are *detections*, not
  live tunnels (the sensor terminates connections, it doesn't carry pivots).
- `/dns`, `/web`, `/databases`, `/remote`, `/mail`, `/ntp` — **per-service
  analytics** (shown only when a relevant listener exists): volume over time,
  top entities, top attackers, the attacks/CVE table, an **attacker-intent**
  breakdown, and a per-event activity log with an **intent** column.
- `/interactions` — **attacker work** captured by the emulated shells / web
  shell / decoys: commands run, keystrokes, and recorded session casts.
- `/stats` — numeric companion to `/charts`; on a multi-IP host it leads with
  the **targeted server IPs** breakdown (which of the host's addresses are hit).
- `/attack` — **ATT&CK mapping** view: a kill-chain-ordered tactic timeline
  (with the techniques nested under each tactic), a top-technique heatmap,
  and the recent `storyline:multi_stage` kill-chain progressions. Techniques
  are recomputed per event from rule + handler + anomaly markers (the same
  mapping the router stamps). JSON at `/api/attack`.
- `/health` — **sensor health** dashboard: uptime, Go runtime (memory /
  goroutines / GC), recovered panics, event-DB size + data_dir disk %,
  events/24h, and per-sink dropped / failed / retried counters (so a
  backlogged or down sink is obvious). Backed by the same data as `/metrics`.
- `/pcap/<id>` / `/session/<id>` — download one event's recorded capture /
  session cast.
- `/download?source=&rule=&since=&what=pcap|session|all` — stream a ZIP of
  every matching event's pcaps and/or session casts (e.g. everything from a
  single source IP). The events list links the current filter to it.
- `/hosts?q=&status=` — learned hosts (IPv4/IPv6/MAC), filterable by
  substring + allow/seen status.
- `/topology` — **infrastructure map**: the virtual networks / hosts /
  services the sensor presents, with live attack activity (last 24h)
  overlaid per host (event count, distinct attackers, max severity,
  last-seen) + a per-network rollup — so you see which decoys / fake-AD /
  OT / cloud traps are under attack.
- `/alerting` — how events are forwarded (channels + destinations,
  routes, allowlist).
- `/errors?since=` — operational / health events (listener or
  canary-watcher stopped, listener start error, accept-cap overflow).
- `/config` — the effective post-defaults config (secrets shown as
  `*_env` names, never expanded values), plus a **"files in use"** table —
  every config / enrichment / GeoIP / database / data-dir path the sensor
  references, with category, access (r/w), and present/MISSING status (the
  same data as `list-paths`).
- `/docs` — built-in reference that reflects the running deployment.
- `/api/events`, `/api/summary`, `/api/config`, `/api/topology`,
  `/api/hosts`, `/api/alerting` — JSON equivalents.
- `/metrics` — Prometheus text-format (see [Prometheus metrics](#prometheus-metrics)).
- `/healthz` — auth-bypass liveness check.

Security headers (`Content-Security-Policy: default-src 'none'`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`) are set on
every response. Bearer-token auth via `auth_token_env`. Non-loopback
binds are rejected at validate-time without both TLS and auth.

## systemd integration

A hardened unit lives at `packaging/systemd/tarpit-honeypot.service`. It
runs as user `honey:honeypot` with `AmbientCapabilities=CAP_NET_BIND_SERVICE
CAP_NET_RAW`, `NoNewPrivileges=true`, `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp/Devices=true`, and
`RestrictNamespaces=true`. `ExecReload=/bin/kill -HUP $MAINPID` ties into
the hot-reload path.

Install pattern:

```
sudo groupadd --system honeypot
sudo useradd --system --gid honeypot --no-create-home --shell /usr/sbin/nologin honey
sudo install -o root -g root -m 0755 bin/tarpit-honeypot /usr/local/bin/
sudo install -d -o honey -g honeypot -m 0750 /var/lib/tarpit-honeypot
sudo install -d -o root  -g root  -m 0755 /etc/tarpit-honeypot
sudo install -o root -g root -m 0640 configs/tarpit-honeypot.example.yaml /etc/tarpit-honeypot/config.yaml
sudo install -o root -g root -m 0644 packaging/systemd/tarpit-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tarpit-honeypot
```

`scripts/install.sh` automates all of the above (service account, file caps,
SELinux/AppArmor policy, rsyslog routing, config patching) and prompts for the
deployment hostname / domain / TLS identity.

### Multiple IPs and multiple instances

A sensor host usually has more than one address — several server IPs on one NIC,
or a whole spare subnet. There are four ways to cover them; pick by **how much
isolation you want between addresses**:

| Model | Processes | Per-IP DB / UI / fingerprint | Binds IPs the host doesn't own? | Use when |
|---|---|---|---|---|
| **1. Wildcard** (default) | one | no — one shared store, every event tagged with `dst_ip` | no | cover every address with one pane of glass (the right answer for most) |
| **2. Pinned subset** (`listen_addresses` / `-i`) | one | no | no | answer on *some* of the host's addresses (e.g. keep the management IP dark) |
| **3. Honeynets** | one | virtual per-host identities | **yes** (claims them via ARP/ICMP) | fabricate a subnet of distinct fake devices on space the host doesn't own |
| **4. Multiple instances** | one **per IP** | **yes** — own `events.db`, UI, certs, deployment-identity, retention | no | strongest isolation: distinct fingerprints + separate blast radius per address |

Models 1, 2 and 4 bind the host's **real** addresses; model 3 ([honeynets](#honeynets))
impersonates **unowned** ones. They compose — an instance (model 4) can also run
honeynets (model 3).

**1 — One sensor across every IP (default).** A wildcard bind (`bind: "[::]:22"`
or `0.0.0.0:…`, the default) answers on every address the host has now or gains
later, and each event records the destination it hit:

```yaml
listeners:
  - { id: ssh, proto: tcp, bind: "0.0.0.0:22", handler: ssh }   # answers on every IP
```

The multi-IP picture is surfaced for you: the **attacker profile**
(`/profiles/<ip>`) draws a **cross-target timeline** when one source touches
several of your addresses (a scripted fleet sweep), **`/stats`** ranks the
**"targeted server IPs"**, and you can pivot to one address from the CLI or the
web search page's **dest IP** filter. Confirm what's actually bound and slice by
target:

```bash
sudo ss -tulnp | grep tarpit-honeypot                          # every listening socket
tarpit-honeypot list-events --target 192.0.2.10 --since 24h    # traffic to one address
```

**2 — Pin listeners to specific IPs.** To answer on a *subset* of the host's
addresses — e.g. expose the decoys on the data-plane IPs but leave the
management IP untouched — pin them:

```yaml
sensor:
  listen_addresses: [192.0.2.10, 192.0.2.11]   # one socket per IP; the mgmt IP stays dark
```

`listen_addresses` rebinds every *wildcard* listener once per address (a listener
already bound to a concrete IP is left alone) and takes precedence over
`sensor.interfaces`. The CLI equivalent is `-i/--interface eth0` (repeatable),
which pins the wildcard binds to that interface's IP. `dst_ip` is still recorded.

**3 — Virtual IPs with honeynets.** To present a *subnet of distinct fake hosts*
— each its own hostname, OS archetype and service mix, on addresses the host
doesn't actually own — use [`honeynets`](#honeynets): the sensor claims the IPs
with its ARP/ICMP responders and dispatches per destination IP. This is the tool
for "make `10.30.1.0/24` look like a Siemens cell", not for binding your own
server IPs.

**4 — One isolated instance per server IP.** When each address should be a
*fully separate honeypot* — its own database, UI, TLS certs, deployment
fingerprint and retention, so a noisy neighbour or a tampered store on one can't
touch another — run one process per IP via the `tarpit-honeypot@.service`
template. Install once, then add an instance per address:

```bash
sudo scripts/install.sh -c configs/tarpit-honeypot.example-CENTOS-SERVER.yaml   # once
sudo scripts/add-instance.sh --name web1 --listen-ip 192.0.2.10
sudo scripts/add-instance.sh --name web2 --listen-ip 192.0.2.11 --ui-port 8090
sudo scripts/add-instance.sh --name ot1  --listen-ip 192.0.2.20 \
     -c configs/tarpit-honeypot.example-ALL-OT.yaml                             # a different persona per IP
```

`add-instance.sh` derives a per-IP config from a base, pins it to the IP, gives
it a free loopback UI port, lays out an isolated state dir, applies the SELinux
label, and enables the unit. Each instance `<name>` is independent:

| Per instance | Path / value |
|---|---|
| config | `/etc/tarpit-honeypot/instances/<name>.yaml` (pins `listen_addresses: [<ip>]`, unique `ui.bind`) |
| state | `/var/lib/tarpit-honeypot/<name>/` — own `events.db`, `.deployment-id`, `tls/`, `captures/` |
| identity | its own `.deployment-id` ⇒ **distinct** banners / JA3-JA4 / device serials per IP |
| service | `tarpit-honeypot@<name>` (own `SyslogIdentifier`, hardened unit, only its state dir writable) |
| UI | `127.0.0.1:<ui-port>` (auto from 8089, or `--ui-port`) |

Manage them like any templated systemd service, open the firewall scoped to each
instance's IP, and remove one without disturbing the rest:

```bash
systemctl status  tarpit-honeypot@web1
journalctl -u     tarpit-honeypot@web1 -f
systemctl reload  tarpit-honeypot@web1                 # SIGHUP: re-read config, no dropped sockets
systemctl list-units 'tarpit-honeypot@*'               # every instance at a glance

sudo scripts/open-firewall.sh -c /etc/tarpit-honeypot/instances/web1.yaml --ip 192.0.2.10

sudo systemctl disable --now tarpit-honeypot@web1      # stop + remove one instance
sudo rm /etc/tarpit-honeypot/instances/web1.yaml
sudo rm -rf /var/lib/tarpit-honeypot/web1              # also deletes its captured events/pcaps
```

**Which model?** Use **1** for "cover everything, one console" (the default).
Add **2** to keep specific addresses dark. Use **3** to fabricate hosts on space
you don't own. Reach for **4** only when per-IP isolation (separate fingerprints,
retention and blast radius) is worth running N processes — e.g. a hoster giving
each tenant IP its own decoy.

**Troubleshooting**

- **`bind: address already in use`** — something already holds that port on that
  address; `sudo ss -tulnp | grep :<port>` shows who. Two sensors can share a
  port only on *different* IPs (`listen_addresses`); a wildcard default and a
  pinned instance on the same box collide on shared ports — pick one model per port.
- **`cannot assign requested address` / a listener never binds** — the IP in
  `listen_addresses` (or `--listen-ip`) isn't configured on the host. Check
  `ip addr show`, then add the address (or fix the typo) before starting.
- **Privileged ports (<1024) fail when run by hand** — binding 22/80/443/… needs
  `CAP_NET_BIND_SERVICE`; the systemd units grant it (`AmbientCapabilities`), a
  manual `tarpit-honeypot run …` as the unprivileged service user does not. Start
  via `systemctl`/`sudo`, or grant the capability.
- **Two instances fight over the UI port** — each needs a unique `ui.bind`;
  `add-instance.sh` auto-assigns from 8089 (or pass `--ui-port`). UIs stay on
  loopback by design — reach them over an SSH tunnel.
- **Every event shows the same `dst_ip`, or only one IP appears** — you're likely
  behind a NAT / load-balancer that rewrites the destination, or
  `listen_addresses` pinned a single IP. For per-IP visibility keep the wildcard
  bind (model 1) and confirm with `list-events --target`.
- **Which instance handled an event?** — instance logs are tagged
  `tarpit-honeypot@<name>` (journald `SyslogIdentifier`) and each has its own
  `events.db` + UI; the `dst_ip` on every event also names the address it hit.
- **The firewall is dropping the decoy traffic** — open the config's ports with
  `scripts/open-firewall.sh -c <config> [--ip <addr>]` (auto-detects firewalld /
  ufw / iptables; `--ip` scopes the rules to one instance's address).
- **SELinux / AppArmor denials after adding an instance** — `install.sh` installs
  the policy and `add-instance.sh` labels the new state dir; if you created a dir
  by hand, run `restorecon -Rv /var/lib/tarpit-honeypot/<name>` (SELinux) or
  re-run `install.sh`, then verify with `scripts/selinux-verify.sh`.
- **An instance fails to start with `status=226/NAMESPACE`** — systemd couldn't
  set up the unit's sandbox, almost always because a `ReadWritePaths` entry is
  missing. The `tarpit-honeypot@.service` template grants write access to
  `/var/lib/tarpit-honeypot/%i`; with a custom **`--data-root`** the data dir is
  elsewhere, so that path doesn't exist and `ProtectSystem=strict` aborts startup
  (and the real data dir wouldn't be writable). `add-instance.sh` now writes a
  per-instance override (`…@<name>.service.d/10-data-root.conf`) plus a SELinux
  fcontext for custom roots — re-run it with `--force` to repair an existing
  instance, or fix one by hand:
  ```bash
  sudo install -d /etc/systemd/system/tarpit-honeypot@OT.service.d
  printf '[Service]\nReadWritePaths=\nReadWritePaths=/var/log/tarpit-honeypot /data/instances/OT\n' \
    | sudo tee /etc/systemd/system/tarpit-honeypot@OT.service.d/10-data-root.conf
  sudo semanage fcontext -a -t tarpit_honeypot_var_lib_t '/data/instances/OT(/.*)?'  # SELinux only
  sudo restorecon -RvF /data/instances/OT
  sudo systemctl daemon-reload && sudo systemctl restart tarpit-honeypot@OT
  ```
  (The simplest alternative is to **not** pass `--data-root` — the default
  `/var/lib/tarpit-honeypot` already matches the template and the SELinux policy.)

## Operating model

- Single static binary, no daemons-of-daemons.
- Internal channels for the event bus; per-sink worker goroutines with
  bounded queues (depth 256). One slow sink can't back-pressure the
  listeners.
- All durable state lives under `sensor.data_dir`:
  ```
  <data_dir>/
    events.db                # SQLite index (if sqlite sink or UI enabled)
    events/events-*.jsonl    # rotated JSON-lines (if jsonlog sink enabled)
    captures/<event_id>.pcap # per-event pcaps (if any listener has capture: true)
    tls/<sni>.crt|.key       # cached self-signed HTTPS certs
  ```
- Allowlisted source IPs short-circuit outbound dispatch but local sinks
  still record — you keep a complete forensic trail without paging your
  on-call for every internal scanner.

## Dependencies

External dependencies, all pure-Go:

- `gopkg.in/yaml.v3` — config parsing
- `github.com/fsnotify/fsnotify` — filesystem canaries
- `modernc.org/sqlite` — pure-Go SQLite (no CGO)
- `github.com/gosnmp/gosnmp` — SNMP encode/decode for the handler + trap sink
- `golang.org/x/sys/unix` — AF_PACKET sniffer and fanotify

No CGO. No `libpcap`. No AWS SDK. No Twilio SDK.

## Tests

```
make test
```

Coverage includes:

- `event`: severity JSON round-trip + numeric tolerance.
- `filter`: allowlist CIDR/IP matching, dedup window expiration, token-
  bucket rate-limit burst + refill.
- `config`: `SeverityMatches` operator parsing; UI loopback / non-loopback
  validation.
- `correlate`: port-scan threshold + window reset + aggregate dedup,
  brute-force per-port, disabled-correlator no-op.
- `router`: local-vs-outbound dispatch, allowlist outbound-only, dedup
  outbound-only, min-severity gate, severity-match routing.
- `store`: insert/query round-trip with all filters, Get, Summary
  breakdown.
- `enrich`: threat-list / cloud-range / Tor / fingerprint tagging, the async
  non-blocking rDNS cache, the cross-feed **reputation confidence** count
  (`threat_intel_count` / `threat_confidence`), and **forward-confirmed reverse
  DNS** — a verified vs. spoofed crawler PTR, driven through injected resolver
  seams so no real DNS is touched.
- `capture`: pcap header bytes + record count + total-directory rotation.
- `handlers`: SSH banner echo, HTTP request capture + URL canary hit/miss,
  Modbus read-holding-registers + exception path, MQTT CONNECT with creds,
  S7 connection-confirm, IEC-104 STARTDT_CON, NTP mode-3 echo + mode-7
  silence, SNMP v2c GetRequest round-trip, OPC-UA HEL→ACK with endpoint
  capture, EtherNet/IP RegisterSession + ListIdentity, BACnet Who-Is →
  I-Am + non-Who-Is silence, TFTP RRQ → ERROR with filename capture,
  SMB1 Negotiate roundtrip + SMB2 STATUS_NOT_IMPLEMENTED rejection.
- `dnscanary`: name + qtype parsing, NXDOMAIN shape, subdomain matcher.
- `sink/awssns`: Sigv4 determinism + body-sensitivity + region extraction.

## Client fingerprinting

**TLS** — both fingerprints are emitted on every HTTPS connection:

- `ja3` — md5 of the JA3 string built from version + cipher list + ext
  list + supported_groups + ec_point_formats, with GREASE filtered.
- `ja4` — newer variant designed to survive extension shuffling.
  Emitted as `t13d{nC}{nE}{alpn}_{cipherHash}_{extHash}` format.
- `ja3_raw` — the pre-hash string, for ad-hoc grouping.

**HTTP** — both `http` and `https` handlers compute JA4H from the
request line + sorted-header-list + sorted-cookie-list:

- `ja4h` — first 24 hex of sha256 of the JA4H string.
- `ja4h_raw` — the JA4H string itself
  (`t<v>h<method><n_hdrs><c>_<header_hash>_<cookie_field_hash>_<cookie_value_hash>`).

**SSH** — the handler captures one binary packet after the banner and
computes:

- `hassh` — md5 of `kex_algs;encryption_algs_c2s;mac_algs_c2s;compression_algs_c2s`.
- `hassh_algorithms` — the unhashed semicolon-joined raw form.

Caveat: HASSH relies on the SSH client sending its KEXINIT before the
server. OpenSSH does this by default; some scanners don't.

**Tool / scanner identification** (`internal/toolfp`) — beyond the
cryptographic fingerprints above, the HTTP/HTTPS **and SSH** handlers
classify the *tool* behind a connection:

- `meta.tools` (HTTP) — names matched from **530+ User-Agent + request-path
  signatures** across: port scanners (nmap, masscan, zmap, zgrab, l9explore);
  internet-wide recon engines (Shodan, Censys, BinaryEdge, LeakIX,
  Onyphe, Shadowserver, Stretchoid, ProjectDiscovery, fofa, ZoomEye, Netlas, …);
  web vuln scanners (sqlmap, nikto, nuclei, Acunetix, Nessus, OpenVAS, Qualys,
  Netsparker/Invicti, AppScan, Arachni, Wapiti, WhatWeb, OWASP ZAP,
  Burp, wpscan/joomscan/droopescan, commix, XSStrike, sqlninja, jSQL, yawast);
  content-discovery fuzzers (gobuster, ffuf, dirsearch, feroxbuster, wfuzz,
  katana, httpx); credential brute-forcers (hydra, medusa, ncrack, patator,
  kerbrute); AD / post-exploitation (the Impacket family, BloodHound, Rubeus,
  Certipy, mitm6, netexec); cloud / k8s recon (Pacu, ScoutSuite, Prowler,
  kube-hunter); pivots / tunnels (chisel, ligolo, Stowaway, reGeorg);
  exploitation frameworks + webshell managers (Metasploit, Cobalt Strike,
  Sliver, Havoc, AntSword, Behinder, Godzilla, Weevely) and DNS/HTTP C2
  (dnscat2, godoh, CALDERA); and generic HTTP libraries (Go, python, java,
  node, ruby, php, powershell, curl, wget). Path signatures also flag
  named-CVE probes (Log4Shell, PHPUnit CVE-2017-9841, FortiOS
  CVE-2018-13379, WebLogic CVE-2017-10271, Citrix/Pulse/Exchange/Confluence
  exploit paths) even when the UA is spoofed.
- `meta.tools` (SSH) — `IdentifySSH` maps the clear-text SSH client banner
  to libssh (hydra/scanners), libssh2, paramiko, Go, PuTTY, zgrab, JSch,
  phpseclib, WinSCP, … (OpenSSH excluded as legitimate-default noise).
- `meta.automation` — a browser-vs-script verdict from header shape
  (missing `Accept`/`Accept-Language`, scripted ordering, etc.).
- A JA3 hash can also map to a known scanner via `IdentifyTLS`.
- Surfaced as `tool:<name>` and `automation-client` anomalies so a SIEM
  can separate hand-driven probes from mass scanners.

## Honeynets

One sensor can host an entire artificial network. The `honeynets:`
config block declares zero or more virtual networks, each with a CIDR,
gateway, DNS, domain, and a list of virtual hosts. Each host has an
IP, hostname, OS hint, and a list of `{port, handler}` services.

### How dispatch works

1. The OS must actually route the virtual IPs to the sensor. On Linux
   that's typically:
   ```
   ip addr add 10.99.0.10/24 dev eth0
   ip addr add 10.99.0.11/24 dev eth0
   ...
   ```
   Or a bridge + NAT or a TUN device. The sensor itself doesn't
   manipulate interfaces — it expects the kernel to deliver SYNs for
   the virtual IPs to a real socket it has bound.

2. The sensor's `listeners:` block must bind `0.0.0.0:<port>` for
   every port any virtual host serves. A single SSH listener bound to
   `0.0.0.0:22` handles all virtual SSH hosts across all honeynets.

3. On `accept()`, the listener inspects the destination IP and looks
   it up in the topology. If it matches a virtual host with a service
   on this port, dispatch goes to a per-host handler instance whose
   Identity is `sensor.deployment_id` derived through
   `honeynet/<network_id>/<host_ip>`. That means each virtual machine
   has its own stable-but-unique banner from the variant pool — two
   virtual hosts on the same listener present as different OpenSSH
   versions, different MySQL builds, different SMB session keys, etc.

4. Emitted events carry `honeynet`, `honeynet_host`,
   `honeynet_hostname`, `honeynet_os` in meta so downstream sinks can
   group / route by virtual machine identity.

### Example

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    gateway: 10.99.0.1
    dns: 10.99.0.2
    domain: corp.example.local
    hosts:
      - ip: 10.99.0.10
        hostname: web-prod-01
        os: linux
        services:
          - { port: 22,  handler: ssh }
          - { port: 80,  handler: http }
          - { port: 443, handler: https }
      - ip: 10.99.0.20
        hostname: dc-01
        os: windows
        services:
          - { port: 88,   handler: kerberos }
          - { port: 389,  handler: ldap }
          - { port: 445,  handler: smb }
          - { port: 3389, handler: rdp }

  - id: ot-cell-A
    cidr: 10.99.5.0/24
    hosts:
      - ip: 10.99.5.50
        hostname: plc-press-01
        os: ics
        services:
          - { port: 102, handler: s7 }
          - { port: 502, handler: modbus }
```

`tarpit-honeypot list-honeynets -c cfg.yaml` prints the topology with
each host's derived identity seed so you can confirm uniqueness:

```
# corp-lan  cidr=10.99.0.0/24 gateway=10.99.0.1 dns=10.99.0.2 domain=corp.example.local
  10.99.0.10  hostname=web-prod-01  os=linux  identity=<seed>/honeynet/corp-lan/10.99.0.10
    :22  handler=ssh
    :80  handler=http
    :443 handler=https
  10.99.0.20  hostname=dc-01        os=windows ...
```

### ARP responder (Linux)

Enable per-honeynet `arp_responder.enabled: true` to make the virtual
network discoverable on the L2 segment without `ip addr add`. The
sensor opens an AF_PACKET socket on the configured interface
(`arp_responder.interface`; empty = first non-loopback interface),
filters for ARP requests, and replies with the requested virtual
host's deterministic MAC.

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    arp_responder:
      enabled: true
      interface: eth0
    hosts:
      - { ip: 10.99.0.10, hostname: web-prod-01, ... }
      - { ip: 10.99.0.20, hostname: dc-01, ... }
```

Each host's MAC is `sha256(deployment_id || "mac" || host_seed)[:6]`
with the locally-administered bit set (`0x02`) and the multicast bit
cleared. `tarpit-honeypot list-honeynets` prints the MAC alongside
the IP so an operator can confirm uniqueness:

```
# corp-lan  cidr=10.99.0.0/24 ...
  10.99.0.10  mac=3e:04:45:bb:fb:79  hostname=web-prod-01  os=linux ...
  10.99.0.20  mac=5e:1f:7d:3d:8b:08  hostname=dc-01        os=windows ...
```

**Limitation:** ARP responding alone is L2 discovery. To make the virtual
IPs answer TCP probes, route the honeynet CIDR into the **TUN adapter**
(`honeynet.tun.enabled`), whose embedded userspace stack completes
handshakes and answers a request/response for each host's configured
ports. To instead route into the sensor's real socket handlers (full
multi-segment protocol interaction), the operator needs `ip addr add` or
iptables redirection. Without either, scanners running `arp-scan` see a
populated network but TCP probes get nowhere.

### ICMP echo responder (Linux)

Pair `arp_responder.enabled: true` with `icmp_responder.enabled:
true` and the virtual hosts respond to ping as well as showing up in
`arp-scan`. Same AF_PACKET pattern + `CAP_NET_RAW` requirement.

```yaml
honeynets:
  - id: corp-lan
    cidr: 10.99.0.0/24
    arp_responder:
      enabled: true
      interface: eth0
    icmp_responder:
      enabled: true
      interface: eth0       # empty = first non-loopback up iface
    hosts: [...]
```

The reply is built at L2 with the virtual host's deterministic MAC
as source, the virtual host IP as the source IP, and the same
ICMP identifier+sequence as the request so the requester's `ping`
matches up. Same caveat as the ARP responder: this makes the host
visible to scanners, but TCP/UDP traffic for the virtual IP still
needs `ip addr add` or iptables redirection.

### Per-honeynet routing

Routes can match on event meta as well as severity. Use this to fan
out per-virtual-network, per-OS-family, or per-rule-id channels:

```yaml
channels:
  - id: ot-pagerduty
    type: webhook
    url: https://events.pagerduty.com/...
  - id: corp-soc
    type: smtp
    ...

routes:
  - match: { severity: ">=critical", honeynet: "ot-cell-A" }
    channels: [ot-pagerduty]
  - match: { severity: ">=high", honeynet_os: "windows" }
    channels: [corp-soc]
  - match: { severity: ">=low" }
    channels: [stdout, jsonlog, sqlite]
```

`Match` fields are AND-ed. Add multiple routes for OR semantics. The
recognized fields are `severity`, `honeynet`, `honeynet_os`, and
`rule_id`.

### DNS forward-resolution

When at least one honeynet is configured AND `dns.enabled: true`, the
DNS canary listener answers A queries for honeynet hostnames with the
matching virtual IP. The listener still emits the baseline
`dnscanary:query` event for every query and the
`canary:dns:<id>`/`dnscanary:amplifier_probe` events as before — the
honeynet resolution is layered on top of NXDOMAIN, not instead of it.

```
$ dig @127.0.0.1 -p 5354 web-prod-01.corp.example.local A +short
10.99.0.10
```

### Counter-fingerprinting

Three knobs make the sensor harder to identify as a honeypot:

### `sensor.deployment_id`

A stable random seed (auto-generated on first run, persisted at
`<data_dir>/.deployment-id`) that deterministically derives every
otherwise-fixed string the sensor emits:

| Surface | Without identity (v0.8 default) | With identity |
|---|---|---|
| SSH banner | `OpenSSH_8.4p1 Debian-5+deb11u1` | one of 6 variants (8.2/8.4/8.9/9.2/9.6/...) |
| HTTP `Server:` | `nginx/1.18.0` | one of 6 (nginx/apache/IIS variants) |
| MySQL version | `5.7.42-honeypot` | one of 5 plausible versions |
| SMTP hostname | `mail.example.com` | `<prefix>NN.example.internal` |
| SMB session key | `0xdeadbeef` | 32 random bits |
| SMB challenge | `11 22 33 44 55 66 77 88` | 8 random bytes |
| VNC challenge | fixed 16 bytes | 16 random bytes |
| EtherNet/IP serial | `0xdeadbeef` | random 32-bit |

Two deployments with different seeds present distinct fingerprints to
Shodan-class scanners. Override via `sensor.deployment_id: "..."` in the
config or rely on auto-generation.

### `sensor.jitter`

Every handler reply sleeps a random `[min_ms, max_ms]` interval before
writing. Defeats microsecond-identical-latency scanner heuristics.
Default disabled; enable with `enabled: true`.

### `sensor.tls_rotate.days`

The auto-generated self-signed HTTPS cert regenerates if older than
this many days. Stops a long-running sensor from leaking a stable
SNI cert hash. Default `0` = never rotate (v0.8 behavior).

## Docker

```
docker build -t tarpit-honeypot:latest .
docker run --rm \
  -p 2222:2222 -p 8000:8000 -p 8088:8088 \
  -v $PWD/var:/var/lib/tarpit-honeypot \
  -v $PWD/configs/tarpit-honeypot.example.yaml:/etc/tarpit-honeypot/config.yaml:ro \
  tarpit-honeypot:latest
```

Final image is a `scratch` base + the static binary + ca-certificates +
a non-root user (uid 65532). About 14 MB total. The container's binary
is built with the same `CGO_ENABLED=0` and `-trimpath` as the host
`make build`.

Privileged ports (53, 88, 102, 110, 135, 161, 389, 445, 502, 623, 636,
2049, 5432, ...) still need either `--user 0` or a host capability
grant; for production, the systemd path with `AmbientCapabilities` is
usually cleaner.

## Output formats

Every event-shaped sink (`stdout`, `jsonlog`, `webhook`, `smtp`, `syslog`)
accepts an optional `format:` field. The default is `json` (legacy
behavior). Three SIEM-friendly alternatives ship:

| Format | Use for | Wire shape |
|---|---|---|
| `json` | Generic JSON consumers, web UI / `list-events` | Full event JSON |
| `cef` | ArcSight | `CEF:0\|tarpit-honeypot\|tarpit\|1.4\|<rule_id>\|<name>\|<sev0-10>\|<ext>` |
| `leef` | QRadar | `LEEF:2.0\|tarpit-honeypot\|tarpit\|1.4\|<rule_id>\|<tab><k=v>...` |
| `ocsf` | Snowflake, Athena, AWS Security Lake | JSON shaped as OCSF Network Activity (class_uid=4001) |

Example:

```yaml
channels:
  - id: jsonlog
    type: jsonlog
    format: json              # default — also writes to events-*.jsonl
  - id: siem-arcsight
    type: syslog
    network: tcp
    address: arcsight:514
    format: cef
  - id: siem-qradar
    type: syslog
    network: tcp
    address: qradar:514
    format: leef
  - id: lake-aws
    type: webhook
    url: https://lake.example.com/ingest
    format: ocsf
```

CEF severity maps low=2, medium=5, high=7, critical=10. OCSF
severity maps low=2, medium=3, high=4, critical=5 (Informational(1) is
unused). Meta keys flow into:

- CEF: `cs1..cs6` slots with their original key in `cs1Label..cs6Label`.
- LEEF: `meta_<key>=<value>` extension keys.
- OCSF: the `unmapped` object (catch-all for honeynet / fingerprint /
  handler-specific keys without a dedicated OCSF slot).

Sinks that aren't event-shaped — `sqlite` (structured rows), `twilio`
(SMS body), `sns` (AWS Publish), `snmptrap` (PDU) — reject non-json
`format:` at validate time.

## Enrichment

When configured, the sensor decorates every event's meta with
location and identity hints for the **source IP** before the
correlator runs. Aggregate events (port_scan / brute_force / slow_scan)
inherit the enrichment without extra lookups.

```yaml
sensor:
  geoip:
    city_db: /var/lib/GeoLite2-City.mmdb
    asn_db:  /var/lib/GeoLite2-ASN.mmdb
  rdns:
    enabled: true
    timeout: 500ms
    cache_size: 1024
```

Both GeoIP paths are optional — configure one or both. The .mmdb files
must be supplied by the operator (MaxMind's GeoLite2 license restricts
redistribution).

Loopback, link-local, and RFC 1918 / RFC 4193 private addresses are
**not** enriched — they don't have meaningful geolocation, and the
rDNS lookup would either hang or return an unhelpful internal name.

Enrichment keys added to event meta:

| Key | From | Example |
|---|---|---|
| `geo_country` / `geo_country_name` / `geo_city` | GeoIP city db | `RU` / `Russia` / `Moscow` |
| `geo_lat`, `geo_lon` | GeoIP city db | `55.7522, 37.6156` |
| `asn` / `asn_org` | GeoIP ASN db | `13335` / `Cloudflare, Inc.` |
| `rdns` | resolver (PTR) | `host.example.adsl.com` |
| `rdns_verified` | FCrDNS (v1.1) | `true` / `false` |
| `verified_crawler` / `spoofed_crawler` | FCrDNS (v1.1) | `googlebot` |
| `spoofed_ptr` | FCrDNS (v1.1) | `true` |
| `mac_vendor` | IEEE OUI | `Cisco Systems, Inc` |
| `threat_intel` / `threat_intel_hit` | reputation lists | `[ipsum, cins-army]` / `true` |
| `threat_intel_count` / `threat_confidence` | cross-feed corroboration (v1.1) | `3` / `high` |
| `tor_exit` | Tor exit list | `true` |
| `cloud_provider` | cloud IP ranges | `aws` |
| `known_scanner` | ASN / rDNS | `censys` |
| `net_class` | built-in | `hosting` / `bogon` |
| `<kind>_client` (ja3 / ja4 / ja4h / hassh) | fingerprint db | `Cobalt Strike` |
| `external_intel` / `fleet_intel` | feeds puller / fleet overlay | `greynoise` / `[ip:botnet]` |
| `src_net` | derived (v1.2) | `203.0.113.0/24` (/48 for IPv6) |
| `conn_type` | rDNS heuristic (v1.2) | `residential` / `hosting` |
| `anonymized` / `anonymizer` | Tor + VPN/proxy ranges (v1.2) | `true` / `vpn` |
| `asn_reputation` | ASN-DROP etc. (v1.2) | `[spamhaus-asndrop]` |
| `geo_risk` | risk_countries (v1.2) | `true` |
| `src_local_hour` | GeoIP timezone (v1.2) | `3` |
| `novel_asn` / `novel_subnet` / `novel_fingerprint` | session novelty (v1.2) | `true` |
| `actor_id` | fingerprint/UA (v1.2) | `ja4:t13d…` |
| `targeting` | rule/handler (v1.2) | `web-cms` / `ics-ot` |
| `cred_class` | credential intel (v1.2) | `default` / `breach` / `weak` |
| `dns_dga` / `domain_bad` | domain intel (v1.2) | `true` |
| `asn_country` / `asn_type` / `asn_geo_mismatch` | ASN info (v1.2) | `RU` / `hosting` / `true` |
| `source_class` | recognition rollup (v1.2) | `malicious` / `anonymizer` / `residential` |
| `labels` | recognition rollup (v1.2) | `[geo:RU, tor, scanner:censys, threat:high]` |

### Reputation confidence (v1.1)

`threat_intel_count` is the number of **independent** reputation signals that
flagged the source — each operator threat-list that matched, the external-feed
overlay, and the downward fleet overlay — and `threat_confidence` buckets it
(1 → `low`, 2 → `medium`, ≥3 → `high`). Several feeds agreeing is a far stronger
signal than any single list, so detection rules, dashboards, and triage can
prioritize cross-corroborated sources. `scripts/fetch-enrichment.sh` ships
several independent **no-auth** feeds for exactly this reason — IPsum (itself an
aggregate of ~30 public blocklists), Emerging Threats compromised-ips, the CINS
Army list, and the SANS ISC DShield block list — alongside the originals
(blocklist.de, Feodo Tracker, Spamhaus DROP, FireHOL level 1).

### Forward-confirmed reverse DNS / spoofed-crawler detection (v1.1)

When `rdns.enabled` is set and a source's PTR record claims a well-known
crawler / cloud operator (`*.googlebot.com`, `*.search.msn.com`,
`*.crawl.baidu.com`, `*.yandex.*`, `*.applebot.apple.com`, …), the sensor
forward-resolves that name and checks it maps back to the source IP
(forward-confirmed reverse DNS). A claim that confirms is tagged
`rdns_verified=true` + `verified_crawler=<operator>`; one that does **not** is
`spoofed_ptr=true` + `spoofed_crawler=<operator>` + `rdns_verified=false` — a
high-signal evasion marker, since attackers routinely set fake PTRs posing as
Googlebot/Bingbot to dodge rate limits and blocks. Only crawler-claiming PTRs
are forward-confirmed, so the extra DNS cost is negligible.

### Derived attributes & the recognition layer (v1.2)

Beyond the per-field tags above, the enricher adds **derived attributes** (no
new data: `src_net` subnet key, `conn_type`, `src_local_hour`, `actor_id`,
`targeting`, and session `novel_*` flags), **feed-backed reputation** (VPN/proxy
`anonymizer` ranges, `asn_reputation` from Spamhaus ASN-DROP, `cred_class` for
captured logins, `dns_dga` + `domain_bad` for queried domains, and
`asn_country`/`asn_type`/`asn_geo_mismatch` from an ASN-info file), and a
**recognition rollup**: a single `source_class` headline
(`malicious`/`spoofed`/`scanner`/`anonymizer`/`hosting`/`residential`/`suspect`)
plus a compact, sorted `labels[]` tag set carried to **every sink** (so SIEMs
filter on the same tokens the UI shows). In the web UI those labels render as
**emoji glyph badges** (🛡 confidence, 🎭 spoofed-PTR, 🕵 anonymizer, ☠ ASN-DROP,
🏴 geo-risk, 🔑 credential class, 🧬 DGA, …) on the events table, event detail,
and attacker profile. The rollup also emits **composite `meta:*` labels**
(⚑ badges) that cross-relate two or more signals into higher-order triage
classes no single tag expresses: `meta:deceptive-origin` (spoofed crawler PTR /
ASN↔geo mismatch / residential-PTR-on-hosting), `meta:corroborated-threat` (≥2
independent reputation signals agree), `meta:targeted-recon` + `meta:ot-recon`
(ICS/OT, database or remote-access targets probed from hidden/rented infra), and
`meta:credential-foothold` (a weak/default/breached login against
remote-access / cloud-devops). Config knobs: `sensor.geoip.risk_countries`,
`sensor.anonymizer_ranges`, `sensor.asn_reputation`, `sensor.cred_intel`,
`sensor.domain_intel`, `sensor.asn_info`; `scripts/fetch-enrichment.sh` ships
the no-auth feeds (VPN/proxy, ASN-DROP, breached-passwords), and the enrichment
signals also feed the risk score (spoofed-PTR and high `threat_confidence` add
weight).

> **abuse.ch feeds need a free key.** Since **2025-06-30** every abuse.ch export
> (ThreatFox, MalwareBazaar, URLhaus) requires an account **Auth-Key**. The 2025
> migration retired the old export URLs (HTTP 410) in favour of a v2 API that
> takes the key **in the URL path** (`https://<svc>-api.abuse.ch/v2/files/exports/<KEY>/recent.csv`);
> `fetch-enrichment.sh` builds those for you. Create a key free at
> <https://auth.abuse.ch/>, then give it to `fetch-enrichment.sh` either via the
> `ABUSE_CH_AUTH_KEY` env var or in the sensor config (read with `-c`):
> ```yaml
> sensor:
>   enrichment:
>     abuse_ch_auth_key_env: ABUSE_CH_AUTH_KEY   # name of an env var holding it
>     # abuse_ch_auth_key: "KEY"                 # …or inline (plaintext secret)
> ```
> The env var wins, then the inline key, then the named env var. Without any of
> them those three feeds are **skipped** (not failed), and every other feed
> still downloads.

## Prometheus metrics

With `ui.enabled: true` the web UI exposes `/metrics` in Prometheus
text-format (v0.0.4). Same auth model as the rest of the UI: bearer
token if `auth_token_env` is set, loopback-only otherwise.

Exposed metrics:

```
# HELP tarpit_sink_dropped_total Events dropped because the sink in-channel was full
# TYPE tarpit_sink_dropped_total counter
tarpit_sink_dropped_total{channel="ops-webhook"} 0
tarpit_sink_dropped_total{channel="jsonlog"} 0

# HELP tarpit_sink_failed_total Events that exhausted the retry backlog and were lost
# TYPE tarpit_sink_failed_total counter
tarpit_sink_failed_total{channel="ops-webhook"} 0

# HELP tarpit_sink_retried_total Events delivered on retry after a transient sink error
# TYPE tarpit_sink_retried_total counter
tarpit_sink_retried_total{channel="ops-webhook"} 0

# HELP tarpit_honeynet_networks Number of configured honeynets
# TYPE tarpit_honeynet_networks gauge
tarpit_honeynet_networks 2

# HELP tarpit_honeynet_hosts Number of configured virtual hosts across all honeynets
# TYPE tarpit_honeynet_hosts gauge
tarpit_honeynet_hosts 8

# HELP tarpit_store_db_bytes On-disk size of the SQLite events.db
# TYPE tarpit_store_db_bytes gauge
tarpit_store_db_bytes 32768

# HELP tarpit_events_total Total events dispatched since start
# TYPE tarpit_events_total counter
tarpit_events_total 18423

# HELP tarpit_events_by_severity_total Events dispatched since start, partitioned by severity
# TYPE tarpit_events_by_severity_total counter
tarpit_events_by_severity_total{severity="critical"} 12
tarpit_events_by_severity_total{severity="high"} 844
tarpit_events_by_severity_total{severity="medium"} 5110

# HELP tarpit_events_by_kind_total Events dispatched since start, partitioned by rule-id kind (listener/cve/canary/correlate/…)
# TYPE tarpit_events_by_kind_total counter
tarpit_events_by_kind_total{kind="listener"} 17001
tarpit_events_by_kind_total{kind="cve"} 212
tarpit_events_by_kind_total{kind="canary"} 3

# HELP tarpit_detect_rule_hits_total Operator detection-rule matches since start
# TYPE tarpit_detect_rule_hits_total counter
tarpit_detect_rule_hits_total{rule="ssh-bruteforce",severity="high"} 97

# HELP tarpit_listeners_active Number of currently-bound listeners
# TYPE tarpit_listeners_active gauge
tarpit_listeners_active 42

# HELP tarpit_honey_tokens_tracked Distinct synthetic credentials the reuse tracker is remembering
# TYPE tarpit_honey_tokens_tracked gauge
tarpit_honey_tokens_tracked 7

# HELP tarpit_kev_catalog_entries CISA KEV catalog entries loaded in the live overlay
# TYPE tarpit_kev_catalog_entries gauge
tarpit_kev_catalog_entries 1218
```

(Plus `tarpit_sniffer_frames_total{proto}`, `tarpit_disk_used_percent`,
`tarpit_uptime_seconds`, `tarpit_build_info` and `tarpit_panic_recoveries_total`.)

A ready-to-import **Grafana dashboard** and a sample **Prometheus scrape config**
ship in [`examples/observability/`](examples/observability/) — event-rate-by-
severity, rule-kind breakdown, top detection rules, canary/CVE signal, sink
health and sensor infrastructure panels.

Sample Prometheus scrape:

```yaml
- job_name: tarpit-honeypot
  bearer_token_file: /etc/secrets/tarpit-ui-token
  scrape_interval: 30s
  static_configs:
    - targets: ['sensor.example.internal:8088']
```

## What's NOT in scope (deliberate boundaries)

- **Windows service registration.** The binary will run on Windows but
  there's no SCM integration yet.
- **fanotify on Windows.** ETW-based read detection would be the
  equivalent path.
- **L2 sniffer on Windows.** Would need Npcap (license-sensitive).
- **Out-of-order / streaming TCP reassembly over TUN.** The TUN adapter
  now embeds a userspace TCP stack (`internal/tcpstack`): SYNs to a
  virtual host's configured ports complete a fingerprint-shaped handshake
  (TTL / window / MSS / wscale / SACK / timestamps / option order matched
  to the host archetype) and answer a single request/response from the
  archetype banners, while unbound ports RST and malformed/illegal
  packets are captured as events — no `ip addr add` per host. It is
  deliberately a *decoy* stack: in-order data only, one request/response,
  no retransmission, congestion control, or out-of-order reassembly. Deep
  multi-segment protocol interaction still wants a real socket (bind it
  with `ip addr add` / iptables alongside the TUN).
- **OPC-DA (DCOM/MSRPC) full call marshaling.** The `dcerpc` handler
  recognizes the OPC-DA interface family on bind and advertises the
  ProgIDs via the endpoint mapper, but the full DCOM `IOPCServer` /
  `IOPCItemMgt` call sequence (reading actual tag values) is out of scope.
- **TLS-record-layer CVEs** (Heartbleed-class) and steganographic covert
  channels are out of scope.

Everything else from the original design is shipped. (The SNMP MIB is now
fully **walkable** — `snmpwalk` / `snmpbulkwalk` traverse the system group,
`ifTable`, and a topology-synthesized `ipNetToMediaTable` ARP table.)

## Getting help / reporting issues

Files of interest if you're debugging:

- `<data_dir>/events.db` — open with any SQLite client; the schema is in
  `internal/store/store.go`.
- `<data_dir>/events/events-*.jsonl` — one JSON event per line.
- `<data_dir>/captures/<event_id>.pcap` — Wireshark loads these directly.
- systemd journal (`journalctl -u tarpit-honeypot -f`) — structured `slog`
  output covering listener startup, sink errors, rate-limit drops,
  reload events, and capture failures.

## License

tarpit-honeypot is **commercial, proprietary software** — Copyright © 2026
**sysctl AB**, all rights reserved. It is licensed, not sold, and may only be
used under a separate written commercial license agreement with sysctl AB. No
rights are granted absent such an agreement. See [`LICENSE`](LICENSE) for the
full terms.

Commercial licensing inquiries: **sysctl AB** — https://www.sysctl.se/

Third-party components distributed with or used by the software remain subject
to their own respective licenses.

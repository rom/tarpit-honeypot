# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
semantic versioning loosely (this is single-binary infrastructure, not a
library, so the public-API contract is the YAML schema + CLI surface
documented in `docs/`).

## [Unreleased]

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

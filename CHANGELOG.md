# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
semantic versioning loosely (this is single-binary infrastructure, not a
library, so the public-API contract is the YAML schema + CLI surface
documented in `docs/`).

## [Unreleased]

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

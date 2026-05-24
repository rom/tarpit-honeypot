# Attribution, enrichment & classification

Every event `tarpit-honeypot` emits is annotated with standards-based
cross-references and classification verdicts, so a SOC can pivot,
correlate, prioritize and build navigator layers without post-processing.
This document describes, in depth:

1. [MITRE ATT&CK](#1-mitre-attck) mappings
2. [MITRE D3FEND](#2-mitre-d3fend) countermeasure mappings
3. [CVE / CWE / CPE / EPSS](#3-cve--cwe--cpe--epss) vulnerability cross-references
4. [Scanner detection](#4-scanner-detection) capabilities
5. [Client classifiers](#5-client-classifiers) (tool / automation / fingerprint)
6. [Where it lands](#6-where-it-lands-on-the-event) on the event

All of it is in-source and zero-runtime-cost (no STIX bundle, no live API
calls); the curated tables are the source of truth and are introspectable
from the CLI (`list-techniques`, `list-cves`, `identify`).

---

## 1. MITRE ATT&CK

Package `internal/mitre`. The router stamps ATT&CK metadata on every event
just before it reaches the sinks, so CEF / LEEF / OCSF / JSON / webhook /
syslog / MQTT consumers all see the same `mitre_techniques` +
`mitre_tactics`.

**Resolution order** (`mitre.Lookup(rule_id, handler)` then
`mitre.Augment(tag, anomalies)`):

| Layer | Source | Example |
|---|---|---|
| Exact rule | `exactRules` (correlator / sniffer / canary / device / malware rule ids) | `correlate:port_scan` → T1046 / discovery |
| Handler | `handlerTags` (per protocol handler, used for `listener:*` events) | `ssh` → T1110.001 + T1078 |
| Anomaly | `anomalyTags` (per fine-grained detection marker, **unioned** by `Augment`) | `modbus-write-attempt` → T0836 + T0831 |
| CVE | the exploit's `Technique`/`Tactic` from the CVE catalog | `cve:CVE-2021-44228` → T1190 |
| Prefix fallback | `uri-*`, `ics-*`, `printer-*`, `tool:*`, `automation-client`, `canary:*` | `printer-*` → T1083 / discovery |

There are **364 static mappings** (63 exact rules + 98 handler tags + 203
anomaly tags), plus the prefix fallbacks below. ICS detections use the ATT&CK
for ICS matrix (T0814 / T0830 / T0831 / T0836 / T0846 / T0888 / …) alongside
the Enterprise matrix so a SIEM expecting one ID space stays consistent.

The complete catalog follows (generated from `list-techniques --json`; the
`Augment` step *unions* the anomaly rows into the rule/handler base).

### 1a. Exact rule IDs (63) — `correlate:*`, `sniffer:*`, `honeynet:*`, `device:*`, `dnscanary:*`, `malware:capture`, …

| rule_id | ATT&CK technique(s) | Tactic(s) |
|---|---|---|
| `attack:dos` | T1499 | impact |
| `attack:fuzzing` | T1595.002 | reconnaissance |
| `correlate:amplification_probe` | T1498.002 | impact |
| `correlate:beacon` | T1071 | command-and-control |
| `correlate:brute_force` | T1110 | credential-access |
| `correlate:canary_trip` | T1083 | discovery |
| `correlate:credential_reuse` | T1110.004 | credential-access |
| `correlate:cve_campaign` | T1190 | initial-access |
| `correlate:data_access` | T1213 | collection |
| `correlate:default_cred_sweep` | T1110.001, T1078.001 | credential-access |
| `correlate:destructive_action` | T1485 | impact |
| `correlate:dns_enumeration` | T1590.002, T1568.002 | reconnaissance, command-and-control |
| `correlate:exfil` | T1048 | exfiltration |
| `correlate:exploit_chain` | T1190 | initial-access |
| `correlate:fingerprint_reuse` | T1583.005 | resource-development |
| `correlate:geo_velocity` | T1110.004 | credential-access |
| `correlate:honeytoken_spread` | T1078 | credential-access |
| `correlate:host_sweep` | T1018, T1046 | discovery |
| `correlate:icmp_sweep` | T1018 | discovery |
| `correlate:ics_control` | T0831 | impact |
| `correlate:ics_mode_change` | T0858 | impact |
| `correlate:lateral_movement` | T1021 | lateral-movement |
| `correlate:malware_campaign` | T1105 | command-and-control |
| `correlate:ot_kill_chain` | T0846, T0831 | discovery, impact |
| `correlate:ot_recon` | T0846, T0888 | discovery |
| `correlate:password_spray` | T1110.003 | credential-access |
| `correlate:path_enumeration` | T1595.003, T1083 | reconnaissance, discovery |
| `correlate:plc_program_download` | T0843 | impact |
| `correlate:port_scan` | T1046 | discovery |
| `correlate:protocol_violation` | T1595.002 | reconnaissance |
| `correlate:service_sweep` | T1046 | discovery |
| `correlate:session_flood` | T1499 | impact |
| `correlate:slow_scan` | T1046 | discovery |
| `correlate:threat_intel_burst` | T1595 | reconnaissance |
| `correlate:tool_rotation` | T1595 | reconnaissance |
| `correlate:ua_rotation` | T1595 | reconnaissance |
| `correlate:webshell` | T1505.003, T1059 | persistence, execution |
| `device:changed` | T1557.002 | credential-access |
| `device:new` | T1018 | discovery |
| `dnscanary:amplifier` | T1498.002 | impact |
| `dnscanary:hit` | T1071.004 | command-and-control |
| `honeynet:profinet_dcp_identify` | T0846 | discovery |
| `honeynet:tcp_connect` | T1046 | discovery |
| `honeynet:tcp_land` | T1499 | impact |
| `honeynet:tcp_malformed` | T1046, T1595.001 | discovery, reconnaissance |
| `honeynet:tcp_request` | T1046, T1595 | discovery, reconnaissance |
| `malware:capture` | T1105, T1027 | command-and-control, defense-evasion |
| `protocol_anomaly` | T1071 | command-and-control |
| `scananalysis:profile` | T1595, T1046 | reconnaissance, discovery |
| `sniffer:arp_reply_unsolicited` | T1557.002 | credential-access |
| `sniffer:arp_scan` | T1018 | discovery |
| `sniffer:encapsulation` | T1572, T1095 | command-and-control |
| `sniffer:goose` | T0888 | discovery |
| `sniffer:icmp_tunnel` | T1095, T1572 | command-and-control |
| `sniffer:ip_fragmented` | T1046 | discovery |
| `sniffer:stp_bpdu` | T1557 | credential-access, collection |
| `sniffer:tcp_ack_scan` | T1046, T1595.001 | discovery, reconnaissance |
| `sniffer:tcp_fin_scan` | T1046, T1595.001 | discovery, reconnaissance |
| `sniffer:tcp_maimon_scan` | T1046, T1595.001 | discovery, reconnaissance |
| `sniffer:tcp_null_scan` | T1046, T1595.001 | discovery, reconnaissance |
| `sniffer:tcp_syn_scan` | T1046, T1595.001 | discovery, reconnaissance |
| `sniffer:tcp_xmas_scan` | T1046, T1595.001 | discovery, reconnaissance |
| `sniffer:udp_scan` | T1046, T1595.001 | discovery, reconnaissance |

### 1b. Handler tags (98) — applied to every `listener:*` event by its handler

| handler | ATT&CK technique(s) | Tactic(s) |
|---|---|---|
| `ads` | T0888, T0814 | discovery, impact |
| `amqp` | T1110.001 | credential-access |
| `anydesk` | T1219 | command-and-control |
| `atg` | T0888 | discovery |
| `bacnet` | T0814 | impact |
| `bgp` | T1190, T1018 | initial-access, discovery |
| `chargen` | T1046, T1498.002 | discovery, impact |
| `citrix_gateway` | T1190 | initial-access |
| `citrix_ica` | T1133 | initial-access |
| `cldap` | T1018 | discovery |
| `coap` | T1046 | discovery |
| `codesys` | T0814 | impact |
| `daytime` | T1046 | discovery |
| `dcerpc` | T1021.003 | lateral-movement |
| `dhcp` | T1046 | discovery |
| `discard` | T1046 | discovery |
| `dnp3` | T0814, T0888 | impact, discovery |
| `dns` | T1046 | discovery |
| `dockerapi` | T1190, T1610 | initial-access, execution |
| `echo` | T1046 | discovery |
| `elasticsearch` | T1213, T1046 | collection, discovery |
| `esxi` | T1190 | initial-access |
| `ethernetip` | T0814, T0888 | impact, discovery |
| `fins` | T0814 | impact |
| `fortinet` | T1190 | initial-access |
| `fox` | T0888 | discovery |
| `ftp` | T1110.001, T1078 | credential-access, initial-access |
| `ftp_files` | T1110.001, T1078 | credential-access, initial-access |
| `ge_srtp` | T0888 | discovery |
| `gopher` | T1190 | initial-access |
| `hartip` | T0888 | discovery |
| `horizon` | T1190 | initial-access |
| `http` | T1190, T1083 | initial-access, discovery |
| `https` | T1190, T1083 | initial-access, discovery |
| `idrac` | T1190, T1078 | initial-access |
| `iec104` | T0814 | impact |
| `ilo` | T1190, T1078 | initial-access |
| `imap` | T1110.001, T1114 | credential-access, collection |
| `intel_amt` | T1190, T1078 | initial-access |
| `ipmi` | T1190 | initial-access |
| `ipp` | T1190 | initial-access |
| `isakmp` | T1133 | initial-access |
| `kerberos` | T1558 | credential-access |
| `knx` | T1046 | discovery |
| `ldap` | T1110.003, T1087.002 | credential-access, discovery |
| `llmnr` | T1557.001 | credential-access |
| `lpd` | T1190 | initial-access |
| `mdns` | T1557.001, T1046 | credential-access, discovery |
| `melsec` | T0814 | impact |
| `memcached` | T1213, T1046 | collection, discovery |
| `mms` | T0888, T0814 | discovery, impact |
| `modbus` | T0814, T0888 | impact, discovery |
| `mongodb` | T1213, T1110.001 | collection, credential-access |
| `moxa_mgmt` | T1190 | initial-access |
| `mqtt` | T1110.001, T0830 | credential-access, lateral-movement |
| `mssql` | T1110.001 | credential-access |
| `mysql` | T1110.001 | credential-access |
| `nbns` | T1557.001 | credential-access |
| `netbios_dgram` | T1018 | discovery |
| `ntp` | T1498.002 | impact |
| `nx` | T1021 | lateral-movement |
| `opcua` | T0814 | impact |
| `openvpn` | T1133 | initial-access |
| `oracle_tns` | T1110.001 | credential-access |
| `pcworx` | T0888 | discovery |
| `pjl` | T1190 | initial-access |
| `pop3` | T1110.001, T1114 | credential-access, collection |
| `postgres` | T1110.001 | credential-access |
| `pulse` | T1190 | initial-access |
| `qotd` | T1046 | discovery |
| `radius` | T1110.001 | credential-access |
| `rdp` | T1021.001, T1110.001 | lateral-movement, credential-access |
| `redfish` | T1190, T1078 | initial-access |
| `redis` | T1110.001 | credential-access |
| `rlogin` | T1110.001, T1021 | credential-access, lateral-movement |
| `rsync` | T1110.001, T1213 | credential-access, collection |
| `rtsp` | T1190 | initial-access |
| `s7` | T0814, T0888 | impact, discovery |
| `s7comm_plus` | T0814, T0888 | impact, discovery |
| `sip` | T1046 | discovery |
| `smb` | T1021.002, T1135 | lateral-movement, discovery |
| `smtp_recv` | T1110.003, T1114 | credential-access, collection |
| `snmp` | T1018, T1110.001 | discovery, credential-access |
| `socks` | T1090 | command-and-control |
| `ssdp` | T1018 | discovery |
| `ssh` | T1110.001, T1078 | credential-access, initial-access |
| `ssh_interactive` | T1110.001, T1078 | credential-access, initial-access |
| `syslog_tcp` | T1078 | initial-access |
| `syslog_udp` | T1078 | initial-access |
| `teamviewer` | T1219 | command-and-control |
| `telnet` | T1110.001, T1078 | credential-access, initial-access |
| `tftp` | T1190 | initial-access |
| `time` | T1046 | discovery |
| `vmware_authd` | T1110.001, T1078 | credential-access, initial-access |
| `vnc` | T1021.005, T1110.001 | lateral-movement, credential-access |
| `winrm` | T1021.006 | lateral-movement |
| `x11` | T1021, T1056.001 | lateral-movement, collection |
| `xmpp` | T1071.001 | command-and-control |

### 1c. Anomaly tags (203) — fine-grained markers `Augment` unions onto the base

| anomaly marker | ATT&CK technique(s) | Tactic(s) |
|---|---|---|
| `adb-auth` | T1190 | initial-access |
| `adb-connect` | T1190 | initial-access |
| `adb-shell-open` | T1059 | execution |
| `ajp-forward-request` | T1190 | initial-access |
| `ajp-probe` | T1595 | reconnaissance |
| `bacnet-write-attempt` | T0836, T0831 | impact |
| `bgp-open-attempt` | T1190 | initial-access |
| `bgp-probe` | T1595 | reconnaissance |
| `c2-framework` | T1071.001, T1219 | command-and-control |
| `cassandra-auth-attempt` | T1110.001 | credential-access |
| `cassandra-probe` | T1046 | discovery |
| `coap-write-attempt` | T1565 | impact |
| `dcerpc-dcsync` | T1003.006 | credential-access |
| `dcerpc-lsarpc-enum` | T1087.002, T1482 | discovery |
| `dcerpc-netlogon-access` | T1210 | lateral-movement |
| `dcerpc-samr-enum` | T1087.002 | discovery |
| `dcerpc-srvsvc-enum` | T1135 | discovery |
| `dcerpc-svcctl-access` | T1021.002, T1543.003 | lateral-movement, persistence |
| `dcerpc-winreg-access` | T1012, T1003.002 | discovery, credential-access |
| `default-credential-attempt` | T1078.001 | credential-access |
| `dhcp-client-observed` | T1046 | discovery |
| `dns-dga-suspected` | T1568.002 | command-and-control |
| `dns-over-https` | T1572, T1071.004 | command-and-control |
| `dns-over-tls` | T1572, T1071.004 | command-and-control |
| `dns-zone-transfer` | T1590.002, T1018 | reconnaissance, discovery |
| `dnscrypt-probe` | T1572, T1071.004 | command-and-control |
| `docker-container-create` | T1610 | execution |
| `docker-remote-control` | T1610 | execution |
| `elasticsearch-data-access` | T1213 | collection |
| `elasticsearch-recon` | T1046 | discovery |
| `elasticsearch-write-attempt` | T1565.001 | impact |
| `epmd-names` | T1018 | discovery |
| `epmd-query` | T1046 | discovery |
| `fins-program-download` | T0843 | impact |
| `fins-run-mode-change` | T0858 | impact |
| `fins-tcp-probe` | T0888 | discovery |
| `fins-tcp-write-attempt` | T0836 | impact |
| `ftp-bounce-scan` | T1090, T1046 | command-and-control, discovery |
| `ftp-delete-attempt` | T1485 | impact |
| `ftp-download-attempt` | T1020 | exfiltration |
| `ftp-listing` | T1083 | discovery |
| `ftp-site-command` | T1059 | execution |
| `ftp-upload-attempt` | T1105 | command-and-control |
| `git-push-attempt` | T1195 | initial-access |
| `git-request` | T1213 | collection |
| `gopher-request` | T1595 | reconnaissance |
| `gopher-ssrf` | T1190 | initial-access |
| `headless-browser` | T1595 | reconnaissance |
| `honeyfile-download` | T1005 | collection |
| `http-connect-proxy` | T1090 | command-and-control |
| `http-duplicate-host` | T1190 | initial-access |
| `http-impossible-browser` | T1036 | defense-evasion |
| `http-login-attempt` | T1110.001 | credential-access |
| `http-malformed-header` | T1190 | initial-access |
| `http-method-unknown` | T1595 | reconnaissance |
| `http-request-line-non-printable` | T1595 | reconnaissance |
| `http-request-smuggling` | T1190 | initial-access |
| `ike-probe` | T1595 | reconnaissance |
| `ip-bad-checksum` | T1595.001 | reconnaissance |
| `ip-bad-header-len` | T1595.001 | reconnaissance |
| `ip-fragmented` | T1046, T1595.001 | discovery, reconnaissance |
| `jdwp-handshake-attempt` | T1190 | initial-access |
| `jdwp-probe` | T1595 | reconnaissance |
| `kafka-request` | T1046 | discovery |
| `kerberos-rc4-requested` | T1558.003 | credential-access |
| `kerberos-tgs-request` | T1558.003 | credential-access |
| `ldap-asrep-roast-recon` | T1558.004, T1087.002 | credential-access, discovery |
| `ldap-enumeration` | T1087.002 | discovery |
| `ldap-spn-enumeration` | T1558.003, T1087.002 | credential-access, discovery |
| `mdns-service-enumeration` | T1046 | discovery |
| `memcached-flush` | T1485 | impact |
| `memcached-stats-probe` | T1046 | discovery |
| `memcached-write-attempt` | T1565.001 | impact |
| `modbus-write-attempt` | T0836, T0831 | impact |
| `mongodb-data-access` | T1213 | collection |
| `mssql-browser-query` | T1046 | discovery |
| `mssql-login-attempt` | T1110.001 | credential-access |
| `mysql-login-attempt` | T1110.001 | credential-access |
| `nats-connect` | T1046 | discovery |
| `nats-publish` | T1565 | impact |
| `netbios-datagram` | T1018 | discovery |
| `ntp-control-query` | T1498.002 | impact |
| `ntp-monlist-amplification` | T1498.002 | impact |
| `nx-probe` | T1595 | reconnaissance |
| `openvpn-probe` | T1595 | reconnaissance |
| `oracle-tns-probe` | T1595 | reconnaissance |
| `pcom-mode-change` | T0858 | impact |
| `pcom-probe` | T0888 | discovery |
| `pcom-program-download` | T0843 | impact |
| `pcom-write-attempt` | T0836 | impact |
| `pjl-command` | T1083 | discovery |
| `postgres-replication-connection` | T1213 | collection |
| `pptp-probe` | T1133 | initial-access |
| `printer-auth-attempt` | T1110.001 | credential-access |
| `printer-config-set` | T1565 | impact |
| `printer-credential-access` | T1552 | credential-access |
| `printer-cups-rce` | T1190 | initial-access |
| `printer-filesystem-format` | T1485 | impact |
| `printer-firmware-upload` | T1601 | defense-evasion |
| `printer-ipp-cmd-injection` | T1059 | execution |
| `printer-language-switch` | T1059 | execution |
| `printer-lpd-injection` | T1059 | execution |
| `printer-lpd-overflow` | T1190 | initial-access |
| `printer-message-injection` | T1491 | impact |
| `printer-password-set` | T1098 | persistence |
| `printer-path-traversal` | T1083 | discovery |
| `printer-postscript-exitserver` | T1059 | execution |
| `printer-postscript-fileop` | T1059, T1005 | execution, collection |
| `printer-postscript-setparams` | T1059 | execution |
| `printer-rdymsg-set` | T1491 | impact |
| `printer-servicemode` | T1078 | privilege-escalation |
| `printer-zpl-config` | T1565 | impact |
| `profinet-connect` | T0846 | discovery |
| `profinet-io-probe` | T0846 | discovery |
| `redfish-auth-attempt` | T1078 | credential-access |
| `redis-config-set` | T1059 | execution |
| `redis-flush` | T1485 | impact |
| `redis-module-load` | T1059 | execution |
| `redis-replication-takeover` | T1059, T1210 | execution, lateral-movement |
| `redis-save` | T1059 | execution |
| `redis-script-exec` | T1059 | execution |
| `rlogin-attempt` | T1021 | lateral-movement |
| `rmi-probe` | T1595 | reconnaissance |
| `rpcbind-dump` | T1135 | discovery |
| `rpcbind-getport` | T1046 | discovery |
| `rpcbind-query` | T1046 | discovery |
| `rsync-module-access` | T1213 | collection |
| `rsync-module-list` | T1083 | discovery |
| `rtsp-auth-attempt` | T1110.001 | credential-access |
| `secs-probe` | T0888 | discovery |
| `secs-program-send` | T0843 | impact |
| `secs-remote-command` | T0855 | impact |
| `shell-ad-recon` | T1087.002 | discovery |
| `shell-coin-miner` | T1496 | impact |
| `shell-credential-dump` | T1003 | credential-access |
| `shell-creds-file-access` | T1552.001 | credential-access |
| `shell-defender-tamper` | T1562.001 | defense-evasion |
| `shell-defense-evade-history` | T1070.003 | defense-evasion |
| `shell-defense-evade-logclean` | T1070.002 | defense-evasion |
| `shell-disable-fw` | T1562.004 | defense-evasion |
| `shell-download-tool` | T1105 | command-and-control |
| `shell-encoded-payload` | T1027, T1140 | defense-evasion |
| `shell-living-off-the-land` | T1218 | defense-evasion |
| `shell-network-recon` | T1016 | discovery |
| `shell-passwd-read` | T1003.008 | credential-access |
| `shell-passwd-write` | T1136.001 | persistence |
| `shell-persistence-cron` | T1053.003 | persistence |
| `shell-persistence-ssh-key` | T1098.004 | persistence |
| `shell-persistence-systemd` | T1543.002 | persistence |
| `shell-persistence-windows` | T1547 | persistence |
| `shell-priv-esc-sudo` | T1548.003 | privilege-escalation |
| `shell-priv-esc-suid` | T1548.001 | privilege-escalation |
| `shell-ps-download-exec` | T1059.001, T1105 | execution, command-and-control |
| `shell-ps-encoded` | T1059.001, T1027 | execution, defense-evasion |
| `shell-reverse-shell` | T1059 | execution |
| `shell-shadow-read` | T1003.008 | credential-access |
| `sip-invite-attempt` | T1595 | reconnaissance |
| `sip-register-probe` | T1110.001 | credential-access |
| `smtp-open-relay-probe` | T1071.003 | command-and-control |
| `smtp-user-enumeration` | T1087 | discovery |
| `snmp-set-attempt` | T1565.001, T0836 | impact |
| `snmp-walk-rate-exceeded` | T1046 | discovery |
| `socks-proxy-attempt` | T1090 | command-and-control |
| `ssh-id-non-printable` | T1595 | reconnaissance |
| `ssh-id-not-ssh` | T1595 | reconnaissance |
| `ssh-id-overlong` | T1595 | reconnaissance |
| `stun-binding` | T1016 | discovery |
| `tacacs-auth-start` | T1110.001 | credential-access |
| `tacacs-probe` | T1595 | reconnaissance |
| `tcp-bad-checksum` | T1595.001 | reconnaissance |
| `tcp-bad-dataoffset` | T1595.001 | reconnaissance |
| `tcp-data-in-syn` | T1046, T1595.001 | discovery, reconnaissance |
| `tcp-fin-scan` | T1046, T1595.001 | discovery, reconnaissance |
| `tcp-land` | T1499 | impact |
| `tcp-null` | T1046, T1595.001 | discovery, reconnaissance |
| `tcp-syn-fin` | T1046, T1595.001 | discovery, reconnaissance |
| `tcp-syn-rst` | T1046, T1595.001 | discovery, reconnaissance |
| `tcp-truncated` | T1595.001 | reconnaissance |
| `tcp-xmas` | T1046, T1595.001 | discovery, reconnaissance |
| `telnet-credential-non-printable` | T1595 | reconnaissance |
| `tftp-config-read` | T1602.001 | collection |
| `tftp-write-attempt` | T1105 | command-and-control |
| `udp-amplifier-probe` | T1498.002 | impact |
| `unknown-protocol` | T1046 | discovery |
| `vmware-authd-login` | T1110.001 | credential-access |
| `vulnerability-scanner` | T1595.002, T1190 | reconnaissance, initial-access |
| `wdbrpc-connect` | T0866 | lateral-movement |
| `wdbrpc-probe` | T0846 | discovery |
| `webapp:cmdi` | T1059 | execution |
| `webapp:deserialize` | T1190 | initial-access |
| `webapp:lfi` | T1190, T1083 | initial-access, discovery |
| `webapp:log4shell` | T1190 | initial-access |
| `webapp:rfi_ssrf` | T1190 | initial-access |
| `webapp:secret-file-probe` | T1083 | discovery |
| `webapp:sqli` | T1190 | initial-access |
| `webapp:ssti` | T1059 | execution |
| `webapp:xss` | T1059.007 | execution |
| `webapp:xxe` | T1190 | initial-access |
| `webshell-access-attempt` | T1505.003 | persistence |
| `webshell-command` | T1505.003, T1059 | persistence, execution |
| `winrm-ntlm-auth` | T1110.001 | credential-access |
| `x11-connection-attempt` | T1021 | lateral-movement |
| `zookeeper-fourletter` | T1046 | discovery |

### 1d. Prefix fallbacks

When no exact/handler/anomaly entry matches, these by-class rules apply:

| Pattern | ATT&CK | Tactic |
|---|---|---|
| `uri-*` (suspicious-URI probes) | T1595.003, T1083 | reconnaissance, discovery |
| `ics-*` | T0888 | discovery |
| `printer-*` (generic) | T1083 | discovery |
| `tool:*` (identified scanner) | T1595 | reconnaissance |
| `automation-client` | T1595 | reconnaissance |
| `tcp-*`, `ip-*` (userspace-stack packet anomalies) | T1046, T1595.001 | discovery, reconnaissance |
| `cve:<id>` | from the CVE record (else T1190) | initial-access |
| `canary:url:*` | T1083, T1190 | discovery, initial-access |
| `canary:dns:*` | T1071.004 | command-and-control |
| `canary:*` | T1083 | discovery |
| `listener:*` (unknown handler) | T1190 | initial-access |
| `storyline:*` | (none — aggregation, techniques carried in meta) | — |

**Tactic ordering.** `mitre.Tactics()` returns the 14 Enterprise tactics in
reconnaissance→impact order and `TacticRank()` scores them; the storyline
correlator uses this to detect kill-chain *progression* (a source whose
tactic rank climbs over time looks directed, not scattered).

**Inspect it:** `tarpit-honeypot list-techniques [--kind rule|handler|anomaly] [--json]`.

---

## 2. MITRE D3FEND

The same package maps each ATT&CK technique (sub-techniques inherit their
base, so `T1110.001` → `T1110`) to the D3FEND defensive countermeasures
that answer it. `mitre.DefensesFor(techniques)` populates
`mitre_defenses` on every event — "here is the attack, here is the control
that addresses it" in one record.

Because tarpit-honeypot *is* a deception system, the **decoy** branch of
D3FEND recurs throughout — it is the countermeasure the sensor itself
implements:

| ID | Countermeasure |
|---|---|
| `D3-DE` | Decoy Environment |
| `D3-DNR` | Decoy Network Resource |
| `D3-DUC` | Decoy User Credential |
| `D3-DO` | Decoy Object |

alongside detection / hardening measures a SOC pairs with it: `D3-NTA`
(Network Traffic Analysis), `D3-ITF` (Inbound Traffic Filtering), `D3-DA`
(Dynamic Analysis), `D3-DNSTA` (DNS Traffic Analysis), `D3-MFA`, `D3-DF`
(Decoy File), `D3-FH` (File Hashing), `D3-OTF` (Outbound Traffic
Filtering). The `list-techniques` D3FEND column shows the mapping per rule.

---

## 3. CVE / CWE / CPE / EPSS

Package `internal/cve` is a curated, in-source catalog (**123 records**) with
two jobs: drive vulnerable-banner / fake-patch-level emulation
(`ForService`) and recognize a live exploit attempt's signature
(`MatchPayload`). The sensor is never actually exploitable — it advertises
the version and recognizes the follow-up.

Each record carries a full cross-reference set:

| Field | Meaning |
|---|---|
| `ID` / `Name` | `CVE-2021-44228` / "Log4Shell" |
| `CVSS` | base score (drives event severity; ≥9.0 → critical) |
| `Service` | the handler the CVE applies to (`http` records also match `https`) |
| `Signatures` | high-signal exploit substrings (empty = advisory-only) |
| `Technique` / `Tactic` | ATT&CK mapping the `cve:<id>` event inherits |
| **`CWE`** | the weakness class(es), e.g. `["CWE-502","CWE-917"]` |
| **`CPE`** | affected-product CPE 2.3, e.g. `cpe:2.3:a:apache:log4j:*` |
| **`EPSS`** | Exploit-Prediction Scoring System probability (0..1) |

**CWE** answers "what *kind* of flaw" (deserialization, OS command
injection, path traversal, SSRF, …) so events cluster by weakness class
across products. **CPE** is the affected-product identifier for asset
correlation. **EPSS** is a relative exploit-likelihood prioritization hint.

> EPSS is a **curated point-in-time snapshot** (~2026-05), not a live feed —
> FIRST.org republishes EPSS daily. Treat the value as a relative-priority
> hint, and re-baseline it from the live dataset if you depend on it
> operationally. CWE and CPE are stable.

**TCP/IP-stack class (`Service: "tcp"`).** Alongside the application-layer
CVEs, the catalog carries the classic TCP/IP-stack attacks the honeynet's
userspace stack (`internal/tcpstack`, see [`tcp-stack.md`](tcp-stack.md))
is positioned to recognize: LAND (CVE-1999-0016, detected live as the
`tcp-land` anomaly and dropped), Teardrop / FragmentSmack (the
`ip-fragmented` anomaly), the TCP RST/SYN in-window and sockstress DoS
classes, SACK Panic, the Linux off-path challenge-ACK side channel, and
Ripple20 (Treck) for the OT/IoT device archetypes. These ride the packet
layer rather than an L7 handler, so they are advisory in the signature
sense (`—`) but carry full ATT&CK (mostly T1499 endpoint DoS) + CWE/EPSS.

**Full catalog (123 records — 66 live-detectable, 57 advisory-only).** `Det`
= a `cve:<id>` event fires on a matched exploit signature in a request;
advisory-only records (`—`) drive vulnerable-version emulation but have no
high-signal wire signature (ICS / auth-bypass / protocol / TCP-stack CVEs).
`Product` is the CPE 2.3 vendor:product. EPSS is the ~2026-05 snapshot.

| CVE | Name | CVSS | Service | CWE | Product (CPE) | EPSS | ATT&CK | Det |
|---|---|---|---|---|---|---|---|:-:|
| CVE-1999-0015 | Teardrop overlapping-fragment DoS | 5 | `tcp` | CWE-400 | — | 0.02 | T1499 | — |
| CVE-1999-0016 | LAND same-source/dest DoS | 5 | `tcp` | CWE-400 | — | 0.02 | T1499 | — |
| CVE-2004-0230 | TCP RST/SYN in-window DoS | 5 | `tcp` | CWE-400 | — | 0.04 | T1499 | — |
| CVE-2008-4609 | TCP sockstress state exhaustion | 7.1 | `tcp` | CWE-400 | — | 0.05 | T1499 | — |
| CVE-2013-2783 | Triangle MicroWorks DNP3 infinite loop | 7.1 | `dnp3` | CWE-835, CWE-20 | trianglemicroworks:scada_data_gateway | 0.04 | T1499 | — |
| CVE-2014-3120 | Elasticsearch MVEL RCE | 7.5 | `elasticsearch` | CWE-94 | elastic:elasticsearch | 0.85 | T1190 | yes |
| CVE-2014-6271 | Shellshock | 9.8 | `http` | CWE-78 | gnu:bash | 0.94 | T1190 | yes |
| CVE-2015-1427 | Elasticsearch Groovy RCE | 9.8 | `elasticsearch` | CWE-94 | elastic:elasticsearch | 0.90 | T1190 | yes |
| CVE-2015-5374 | Siemens SIPROTEC EN100 DoS | 7.8 | `iec104` | CWE-20, CWE-400 | siemens:en100_ethernet_module_firmware | 0.05 | T1499 | — |
| CVE-2016-10033 | PHPMailer transport RCE | 9.8 | `http` | CWE-88 | phpmailer_project:phpmailer | 0.90 | T1190 | — |
| CVE-2016-2200 | Siemens S7-1500 web DoS | 7.5 | `s7` | CWE-20 | siemens:simatic_s7-1500_cpu_firmware | 0.05 | T1499 | — |
| CVE-2016-5696 | Linux off-path TCP injection | 5.9 | `tcp` | CWE-203 | linux:linux_kernel | 0.04 | T1499 | — |
| CVE-2016-8367 | Phoenix Contact ILC missing auth | 9.8 | `pcworx` | CWE-306 | phoenixcontact:ilc_151_eth_firmware | 0.05 | T1190 | — |
| CVE-2017-0144 | EternalBlue | 8.1 | `smb` | CWE-20, CWE-787 | microsoft:windows | 0.94 | T1210 | yes |
| CVE-2017-10271 | WebLogic WLS-WSAT | 7.5 | `http` | CWE-502 | oracle:weblogic_server | 0.97 | T1190 | yes |
| CVE-2017-12149 | JBoss invoker deserialization | 9.8 | `http` | CWE-502 | redhat:jboss_enterprise_application_platform | 0.95 | T1190 | yes |
| CVE-2017-12615 | Tomcat PUT JSP | 8.1 | `http` | CWE-434 | apache:tomcat | 0.97 | T1190 | yes |
| CVE-2017-16744 | Tridium Niagara path traversal | 6.6 | `fox` | CWE-22 | tridium:niagara | 0.05 | T1190 | — |
| CVE-2017-5638 | Struts2 OGNL | 10 | `http` | CWE-1336, CWE-20 | apache:struts | 0.97 | T1190 | yes |
| CVE-2017-7494 | SambaCry | 9.8 | `smb` | CWE-94 | samba:samba | 0.80 | T1210 | — |
| CVE-2017-7921 | Hikvision auth bypass | 10 | `http` | CWE-287 | hikvision:firmware | 0.90 | T1190 | yes |
| CVE-2017-9841 | PHPUnit eval-stdin | 9.8 | `http` | CWE-94 | phpunit:phpunit | 0.97 | T1190 | yes |
| CVE-2018-0171 | Cisco Smart Install | 9.8 | `cisco` | CWE-787 | cisco:ios | 0.90 | T1190 | — |
| CVE-2018-10561 | GPON router auth bypass | 9.8 | `http` | CWE-287 | dasannetworks:gpon_firmware | 0.97 | T1190 | yes |
| CVE-2018-11776 | Struts2 namespace OGNL (S2-057) | 8.1 | `http` | CWE-1336, CWE-20 | apache:struts | 0.97 | T1190 | yes |
| CVE-2018-13379 | FortiOS path traversal | 9.8 | `fortinet` | CWE-22 | fortinet:fortios | 0.97 | T1190 | yes |
| CVE-2018-15473 | OpenSSH user enumeration | 5.3 | `ssh` | CWE-200 | openbsd:openssh | 0.55 | T1087 | — |
| CVE-2018-5391 | FragmentSmack IP-fragment DoS | 7.5 | `tcp` | CWE-400 | linux:linux_kernel | 0.05 | T1499 | — |
| CVE-2018-7600 | Drupalgeddon2 | 9.8 | `http` | CWE-20, CWE-94 | drupal:drupal | 0.97 | T1190 | yes |
| CVE-2018-7852 | Schneider Modicon Modbus DoS | 7.5 | `modbus` | CWE-20 | schneider-electric:modicon_m340_firmware | 0.03 | T1499 | — |
| CVE-2018-8867 | GE PACSystems input-validation DoS | 7.5 | `ge_srtp` | CWE-20 | ge:pacsystems_rx3i_cpe330_firmware | 0.03 | T1499 | — |
| CVE-2019-0708 | BlueKeep | 9.8 | `rdp` | CWE-416 | microsoft:windows | 0.95 | T1210 | yes |
| CVE-2019-1040 | Windows NTLM tampering (Drop the MIC) | 6.5 | `dcerpc` | CWE-345 | microsoft:windows | 0.30 | T1557 | — |
| CVE-2019-10929 | Siemens S7-1500 S7CommPlus MITM | 5.3 | `s7comm_plus` | CWE-924, CWE-300 | siemens:simatic_s7-1500_cpu_firmware | 0.02 | T1557 | — |
| CVE-2019-11477 | SACK Panic | 7.5 | `tcp` | CWE-190, CWE-400 | linux:linux_kernel | 0.06 | T1499 | — |
| CVE-2019-11510 | Pulse Secure file read | 10 | `pulse` | CWE-22 | pulsesecure:pulse_connect_secure | 0.97 | T1190 | yes |
| CVE-2019-13524 | GE PACSystems RX3i halt DoS | 7.5 | `ge_srtp` | CWE-20 | ge:pacsystems_rx3i_cpe310_firmware | 0.03 | T1499 | — |
| CVE-2019-18935 | Telerik UI deserialization | 9.8 | `http` | CWE-502 | telerik:ui_for_asp.net_ajax | 0.95 | T1190 | yes |
| CVE-2019-19781 | Citrix ADC path traversal | 9.8 | `citrix_gateway` | CWE-22 | citrix:application_delivery_controller | 0.97 | T1190 | yes |
| CVE-2019-2725 | WebLogic async deserialization | 9.8 | `http` | CWE-502 | oracle:weblogic_server | 0.96 | T1190 | yes |
| CVE-2020-10245 | CODESYS V3 web-server heap overflow | 10 | `codesys` | CWE-787, CWE-122 | codesys:codesys | 0.10 | T1190 | — |
| CVE-2020-11896 | Ripple20 Treck TCP/IP RCE | 10 | `tcp` | CWE-787 | treck:tcp_ip | 0.10 | T1190 | — |
| CVE-2020-1350 | SIGRed Windows DNS RCE | 10 | `dns` | CWE-787 | microsoft:windows_server | 0.50 | T1190 | — |
| CVE-2020-1472 | ZeroLogon | 10 | `dcerpc` | CWE-330 | microsoft:windows_server | 0.96 | T1210 | — |
| CVE-2020-14882 | WebLogic console RCE | 9.8 | `http` | CWE-22, CWE-94 | oracle:weblogic_server | 0.97 | T1190 | yes |
| CVE-2020-15782 | Siemens S7-1200/1500 memory bypass | 8.1 | `s7` | CWE-787, CWE-119 | siemens:simatic_s7-1200_firmware | 0.20 | T1190 | — |
| CVE-2020-16209 | FieldComm HART-IP hipserver overflow | 9.8 | `hartip` | CWE-787, CWE-120 | fieldcommgroup:hipserver | 0.08 | T1190 | — |
| CVE-2020-3452 | Cisco ASA/FTD WebVPN file read | 7.5 | `http` | CWE-22 | cisco:adaptive_security_appliance | 0.96 | T1190 | yes |
| CVE-2020-5902 | F5 BIG-IP TMUI | 9.8 | `http` | CWE-22, CWE-94 | f5:big-ip | 0.97 | T1190 | yes |
| CVE-2020-6986 | Omron CJ-series FINS DoS | 7.5 | `fins` | CWE-400 | omron:cj2m_cpu_firmware | 0.03 | T1499 | — |
| CVE-2021-20591 | Mitsubishi MELSEC iQ-R session DoS | 5.3 | `melsec` | CWE-300, CWE-404 | mitsubishielectric:melsec_iq-r_series | 0.02 | T1499 | — |
| CVE-2021-21972 | vSphere Client RCE | 9.8 | `http` | CWE-22, CWE-434 | vmware:vcenter_server | 0.97 | T1190 | yes |
| CVE-2021-21974 | ESXi OpenSLP heap overflow (ESXiArgs) | 8.8 | `esxi` | CWE-787 | vmware:esxi | 0.85 | T1190 | — |
| CVE-2021-21985 | vCenter vSAN H5 RCE | 9.8 | `http` | CWE-94 | vmware:vcenter_server | 0.96 | T1190 | yes |
| CVE-2021-22005 | vCenter analytics file upload | 9.8 | `http` | CWE-434 | vmware:vcenter_server | 0.97 | T1190 | yes |
| CVE-2021-22681 | Rockwell Studio 5000 key | 10 | `ethernetip` | CWE-321 | rockwellautomation:studio_5000 | 0.10 | T1190 | — |
| CVE-2021-22779 | Schneider Modicon UMAS auth bypass | 9.8 | `modbus` | CWE-287, CWE-863 | schneider-electric:modicon_m580_firmware | 0.10 | T1190 | — |
| CVE-2021-26084 | Confluence OGNL injection | 9.8 | `http` | CWE-917 | atlassian:confluence_server | 0.97 | T1190 | yes |
| CVE-2021-26855 | ProxyLogon | 9.8 | `http` | CWE-918 | microsoft:exchange_server | 0.97 | T1190 | yes |
| CVE-2021-27432 | OPC UA .NET uncontrolled recursion DoS | 7.5 | `opcua` | CWE-674 | opcfoundation:ua-.netstandard | 0.05 | T1499 | — |
| CVE-2021-29441 | Alibaba Nacos auth bypass | 9.8 | `http` | CWE-290 | alibaba:nacos | 0.90 | T1190 | yes |
| CVE-2021-3129 | Laravel Ignition RCE | 9.8 | `http` | CWE-502 | laravel:laravel | 0.96 | T1190 | yes |
| CVE-2021-34473 | ProxyShell | 9.8 | `http` | CWE-918 | microsoft:exchange_server | 0.97 | T1190 | yes |
| CVE-2021-34527 | PrintNightmare | 8.8 | `dcerpc` | CWE-269, CWE-22 | microsoft:windows | 0.94 | T1210 | — |
| CVE-2021-35587 | Oracle Access Manager deserialization | 9.8 | `http` | CWE-502 | oracle:access_manager | 0.85 | T1190 | yes |
| CVE-2021-40539 | ManageEngine ADSelfService | 9.8 | `http` | CWE-287 | zohocorp:manageengine_adselfservice_plus | 0.95 | T1190 | yes |
| CVE-2021-41773 | Apache path traversal | 9.8 | `http` | CWE-22 | apache:http_server | 0.97 | T1190 | yes |
| CVE-2021-42013 | Apache 2.4.50 traversal | 9.8 | `http` | CWE-22 | apache:http_server | 0.97 | T1190 | yes |
| CVE-2021-42278 | noPac (sAMAccountName spoofing) | 8.8 | `kerberos` | CWE-269 | microsoft:windows_server | 0.55 | T1558 | — |
| CVE-2021-44228 | Log4Shell | 10 | `http` | CWE-502, CWE-917, CWE-20 | apache:log4j | 0.94 | T1190 | yes |
| CVE-2022-1026 | Kyocera data disclosure | 7.1 | `http` | CWE-200, CWE-22 | kyocera:command_center_rx | 0.20 | T1190 | — |
| CVE-2022-1161 | Rockwell Logix hidden code | 10 | `ethernetip` | CWE-94 | rockwellautomation:logix | 0.10 | T1190 | — |
| CVE-2022-1388 | F5 iControl REST | 9.8 | `http` | CWE-306 | f5:big-ip | 0.97 | T1190 | yes |
| CVE-2022-22954 | VMware Workspace ONE SSTI | 9.8 | `http` | CWE-94, CWE-1336 | vmware:workspace_one_access | 0.97 | T1190 | yes |
| CVE-2022-22965 | Spring4Shell | 9.8 | `http` | CWE-94, CWE-20 | vmware:spring_framework | 0.97 | T1190 | yes |
| CVE-2022-26134 | Confluence OGNL | 9.8 | `http` | CWE-917 | atlassian:confluence_server | 0.97 | T1190 | yes |
| CVE-2022-26809 | Windows RPC runtime RCE | 9.8 | `dcerpc` | CWE-787 | microsoft:windows | 0.50 | T1210 | — |
| CVE-2022-27925 | Zimbra mboximport traversal | 7.2 | `http` | CWE-22 | zimbra:collaboration | 0.94 | T1190 | yes |
| CVE-2022-29464 | WSO2 arbitrary file upload RCE | 9.8 | `http` | CWE-434 | wso2:api_manager | 0.95 | T1190 | yes |
| CVE-2022-30190 | Follina MSDT | 7.8 | `http` | CWE-94 | microsoft:windows | 0.97 | T1190 | yes |
| CVE-2022-31802 | CODESYS Gateway V2 auth bypass | 9.8 | `codesys` | CWE-287 | codesys:gateway_server | 0.10 | T1190 | — |
| CVE-2022-31806 | CODESYS V2 runtime no default auth | 9.8 | `codesys` | CWE-306, CWE-1188 | codesys:control_runtime_system | 0.15 | T1190 | — |
| CVE-2022-38138 | Triangle MicroWorks 61850 MMS DoS | 7.5 | `mms` | CWE-824 | trianglemicroworks:tmw_iec_61850 | 0.03 | T1499 | — |
| CVE-2022-40684 | FortiOS auth bypass | 9.8 | `fortinet` | CWE-288 | fortinet:fortios | 0.97 | T1190 | yes |
| CVE-2022-42475 | FortiOS SSL-VPN heap overflow | 9.8 | `fortinet` | CWE-787 | fortinet:fortios | 0.90 | T1190 | — |
| CVE-2022-44877 | CWP Control Web Panel RCE | 9.8 | `http` | CWE-78 | control-webpanel:webpanel | 0.96 | T1190 | yes |
| CVE-2023-0669 | GoAnywhere MFT pre-auth RCE | 7.2 | `http` | CWE-502 | fortra:goanywhere_managed_file_transfer | 0.94 | T1190 | yes |
| CVE-2023-20198 | Cisco IOS-XE Web UI | 10 | `http` | CWE-420, CWE-269 | cisco:ios_xe | 0.94 | T1190 | yes |
| CVE-2023-22515 | Confluence broken access control | 10 | `http` | CWE-863 | atlassian:confluence_data_center | 0.94 | T1190 | yes |
| CVE-2023-22518 | Confluence setup-restore | 9.8 | `http` | CWE-863 | atlassian:confluence_data_center | 0.94 | T1190 | yes |
| CVE-2023-26067 | Lexmark privilege escalation | 8 | `http` | CWE-20 | lexmark:firmware | 0.50 | T1190 | — |
| CVE-2023-27350 | PaperCut auth bypass RCE | 9.8 | `http` | CWE-284 | papercut:papercut_mf | 0.96 | T1190 | yes |
| CVE-2023-27997 | FortiOS XORtigate | 9.8 | `fortinet` | CWE-787, CWE-122 | fortinet:fortios | 0.85 | T1190 | — |
| CVE-2023-34362 | MOVEit Transfer SQLi | 9.8 | `http` | CWE-89 | progress:moveit_transfer | 0.94 | T1190 | yes |
| CVE-2023-35078 | Ivanti EPMM API auth bypass | 9.8 | `http` | CWE-287 | ivanti:endpoint_manager_mobile | 0.96 | T1190 | yes |
| CVE-2023-3519 | Citrix NetScaler RCE | 9.8 | `citrix_gateway` | CWE-787 | citrix:netscaler_application_delivery_controller | 0.94 | T1190 | yes |
| CVE-2023-3595 | Rockwell 1756-EN2T RCE | 9.8 | `ethernetip` | CWE-787 | rockwellautomation:1756-en2t | 0.20 | T1190 | — |
| CVE-2023-38035 | Ivanti Sentry MICS auth bypass | 9.8 | `http` | CWE-306 | ivanti:sentry | 0.85 | T1190 | yes |
| CVE-2023-42793 | JetBrains TeamCity auth bypass | 9.8 | `http` | CWE-288 | jetbrains:teamcity | 0.97 | T1190 | yes |
| CVE-2023-4346 | KNX BCU-key device lockout | 7.5 | `knx` | CWE-1390, CWE-640 | knx:knx_devices | 0.02 | T1499 | — |
| CVE-2023-46604 | ActiveMQ OpenWire RCE | 10 | `http` | CWE-502 | apache:activemq | 0.97 | T1190 | yes |
| CVE-2023-46747 | F5 BIG-IP TMUI SSRF RCE | 9.8 | `http` | CWE-288 | f5:big-ip | 0.96 | T1190 | yes |
| CVE-2023-46805 | Ivanti Connect Secure auth bypass | 8.2 | `pulse` | CWE-287 | ivanti:connect_secure | 0.96 | T1190 | — |
| CVE-2023-4966 | Citrix Bleed | 9.4 | `citrix_gateway` | CWE-119, CWE-200 | citrix:netscaler_application_delivery_controller | 0.94 | T1539 | — |
| CVE-2024-0204 | GoAnywhere MFT auth bypass | 9.8 | `http` | CWE-425 | fortra:goanywhere_managed_file_transfer | 0.95 | T1190 | yes |
| CVE-2024-12510 | Xerox VersaLink pass-back | 6.7 | `http` | CWE-522 | xerox:versalink_firmware | 0.10 | T1212 | — |
| CVE-2024-1709 | ScreenConnect auth bypass | 10 | `http` | CWE-288 | connectwise:screenconnect | 0.97 | T1190 | yes |
| CVE-2024-21887 | Ivanti Connect Secure | 9.1 | `pulse` | CWE-78 | ivanti:connect_secure | 0.97 | T1190 | yes |
| CVE-2024-21893 | Ivanti Connect Secure SSRF | 8.2 | `pulse` | CWE-918 | ivanti:connect_secure | 0.96 | T1190 | yes |
| CVE-2024-23897 | Jenkins CLI arbitrary file read | 9.8 | `http` | CWE-22 | jenkins:jenkins | 0.94 | T1190 | yes |
| CVE-2024-27198 | JetBrains TeamCity auth bypass | 9.8 | `http` | CWE-288 | jetbrains:teamcity | 0.94 | T1190 | yes |
| CVE-2024-3273 | D-Link NAS RCE | 9.8 | `http` | CWE-78, CWE-77 | dlink:dns-320_firmware | 0.94 | T1190 | yes |
| CVE-2024-3400 | PAN-OS GlobalProtect | 10 | `https` | CWE-78 | paloaltonetworks:pan-os | 0.95 | T1190 | yes |
| CVE-2024-4577 | PHP-CGI argument injection | 9.8 | `http` | CWE-78, CWE-88 | php:php | 0.95 | T1190 | yes |
| CVE-2024-47076 | libcupsfilters no-validate | 8.6 | `ipp` | CWE-20 | openprinting:libcupsfilters | 0.30 | T1190 | — |
| CVE-2024-47175 | libppd PPD injection | 8.6 | `ipp` | CWE-20 | openprinting:libppd | 0.30 | T1190 | — |
| CVE-2024-47176 | cups-browsed SSRF/bind | 8.6 | `ipp` | CWE-20, CWE-918 | openprinting:cups-browsed | 0.30 | T1190 | — |
| CVE-2024-47177 | CUPS foomatic-rip RCE | 9 | `ipp` | CWE-78 | openprinting:cups-filters | 0.40 | T1190 | yes |
| CVE-2024-47575 | FortiManager FortiJump | 9.8 | `fortinet` | CWE-306 | fortinet:fortimanager | 0.90 | T1190 | — |
| CVE-2024-55591 | FortiOS auth bypass | 9.8 | `fortinet` | CWE-288 | fortinet:fortios | 0.90 | T1190 | — |
| CVE-2024-6387 | regreSSHion | 8.1 | `ssh` | CWE-364 | openbsd:openssh | 0.40 | T1190 | — |
| CVE-2025-0282 | Ivanti Connect Secure RCE | 9 | `pulse` | CWE-121 | ivanti:connect_secure | 0.85 | T1190 | — |
| CVE-2025-58428 | Veeder-Root TLS4B ATG command injection | 9.9 | `atg` | CWE-78 | veeder-root:tls4b_firmware | 0.05 | T1190 | — |

**On the wire.** When a handler recognizes an exploit signature it emits a
`cve:<id>` event whose meta carries `cve_name`, `cvss`, `cwe`, `cpe`,
`epss` and `description`, and whose ATT&CK technique comes from the record.

**Inspect it:** `tarpit-honeypot list-cves [--service <h>] [--json]` (the
table shows CVSS + EPSS + a `DET` column for live-detectable vs advisory;
`--json` adds CWE/CPE/EPSS), and `tarpit-honeypot identify --payload '<bytes>'
--handler <h>` to test a payload against the catalog.

---

## 4. Scanner detection

The sensor recognizes scanners at four independent layers; any one firing
is high-signal, and together they cover application-, host- and
network-layer scanning. Each layer is independent — a stealth SYN scan that
never reaches a handler is still caught on the wire (4c), and a tool that
spoofs its User-Agent is still caught by behaviour (4b/4d).

| Layer | Package | Sees | Needs | Misses |
|---|---|---|---|---|
| **4a** Tool fingerprinting | `internal/toolfp` | UA / path / SSH-id / JA3 of a connection that reaches a handler | one connection | a generic client with no tell |
| **4b** nmap profiling | `internal/scananalysis` | timing + flag shape across a source's connection stream | several connections | single-connect probes |
| **4c** Packet-capture | `internal/sniffer` (Linux) | raw L3/L4 — stealth/closed-port scans, tunnels (IPv4+IPv6) | `CAP_NET_RAW` | nothing on the wire (decoy/stego) |
| **4d** Correlator | `internal/correlate` | windowed per-source aggregation across all events | events in a window | a single isolated event |

### 4a. Tool fingerprinting (`internal/toolfp`)

Cheap, already-captured signals (no extra round-trips) classify the tool:

- **User-Agent / request-path signatures** (HTTP) and **SSH client-id
  signatures** map to a tool name; **JA3** hashes map to a TLS stack.
- Categories covered: **recon engines** (nmap NSE, masscan, zgrab, zmap,
  shodan, censys, binaryedge, leakix, shadowserver, …), **web
  vulnerability scanners**, **content-discovery / fuzzers** (gobuster,
  feroxbuster, ffuf, dirsearch, wfuzz, katana, …), and **credential
  brute-forcers** (hydra, medusa, ncrack, patator, …).
- **Vulnerability scanners specifically** are classed by `IsVulnScanner`
  (≈31 products): Nessus / Tenable, OpenVAS / Greenbone / GVM, Qualys,
  Nexpose / InsightVM / Rapid7, Acunetix, Netsparker / Invicti, AppScan,
  Nikto, Nuclei, Arachni, w3af, skipfish, Wapiti, OWASP ZAP, Burp, Vega,
  WPScan, sqlmap, commix, XSStrike, dalfox, jaeles, Metasploit, whatweb, …
- **C2 / red-team frameworks** (`IsC2`): Cobalt Strike, Mythic, Empire,
  Covenant, Sliver, Havoc, Brute Ratel, Core Impact, plus webshell managers
  (AntSword, Behinder, Godzilla) → `c2-framework` anomaly (T1071.001 / T1219).
- **Headless-browser automation** (`IsHeadless`): Selenium, Puppeteer,
  Playwright, headless Chrome, PhantomJS → `headless-browser` (T1595).
- Every identification gets a coarse **`Category`** (`c2` > `vuln-scanner`
  > `headless` > `tool`) and a **confidence** (`tool_confidence` 0-100,
  banded high/medium/low — a self-identifying UA / in-clear SSH banner /
  JA3 hash is *high*; a tool-specific request path or a missing/non-browser
  UA is *medium*; a weak browser-header heuristic is *low*).

When an HTTP request matches a vuln-scanner the handler raises a
`vulnerability-scanner` anomaly (ATT&CK T1595.002 / T1190); any identified
tool also raises `tool:<name>` (→ T1595 active scanning).

### 4b. nmap scan profiling (`internal/scananalysis`)

Per-source behavioral profiling of a connection stream emits
`scananalysis:profile` with the inferred nmap timing template (`-T0`..`-T5`
from inter-probe cadence), scan flags (`-A` / `-O` / `-sV`), NSE +
service-probe matches, and connect-scan shape → ATT&CK T1595 + T1046.

### 4c. Packet-capture scan detection (`internal/sniffer`, Linux AF_PACKET)

Stealth + volume TCP scans observed on the wire that never establish a
session, over **both IPv4 and IPv6** (separate AF_PACKET sockets):
`sniffer:tcp_syn_scan` (`-sS`), `tcp_null_scan` (`-sN`),
`tcp_fin_scan` (`-sF`), `tcp_xmas_scan` (`-sX`), `tcp_ack_scan`
(`-sA`; `-sW` Window scan shares the ACK probe on the wire),
`tcp_maimon_scan` (`-sM`, FIN+ACK, volume-gated), `sniffer:udp_scan`
(`-sU`, volume), plus `sniffer:ip_fragmented` (`-f`) and `sniffer:arp_scan`
→ T1046 / T1595.001. (Also feeds passive OS fingerprinting, see §5.)

The same socket also flags **covert / tunnelling transports** that have no
business on a flat honeypot segment: `sniffer:encapsulation` — GRE /
IP-in-IP / EtherIP / L2TPv3 and IPv6-in-IPv4 sub-typed into 6in4 / 6to4 /
ISATAP (by IP protocol), plus VXLAN / GENEVE / L2TP / Teredo / GRE-in-UDP
(by UDP port) → protocol tunnelling (T1572 / T1095); `sniffer:icmp_tunnel`
— a large, high-entropy ICMP echo (ptunnel / icmpsh / Loki); and
`sniffer:stp_bpdu` — spanning-tree BPDUs (STP/RSTP/MSTP/PVST+), a
root-bridge / topology-manipulation tell → AiTM (T1557). The generic
[`auto`](config.md) catch-all additionally fingerprints **QUIC** long-header
packets, so a covert QUIC channel landing on an unmodelled port is labelled
rather than dropped.

**Covert-transport coverage & limits.** Covered: DNS tunnels (§4a + the DNS
handler/canary: overlong/high-entropy qnames, NULL/TXT qtypes, DGA), ICMP
tunnels, GRE / IP-in-IP / 6in4 / 6to4 / ISATAP / EtherIP / L2TPv3 / VXLAN /
GENEVE / Teredo, QUIC, fragmented evasions (`sniffer:ip_fragmented`), and
arbitrary custom malware framing (the `auto` catch-all records + guesses it,
raising `unknown-protocol`). The L3/L4 layer captures **both IPv4 and IPv6**
(separate AF_PACKET sockets), so DS-Lite (IPv4-in-IPv6), GRE-over-IPv6,
IPv6-in-IPv6, ICMPv6 tunnels, and IPv6 scans / fragmentation are detected
too. Still out of reach: **steganographic transport** (data hidden inside
otherwise-valid traffic) can't be detected reliably in general — the
per-protocol entropy heuristics (DNS labels, ICMP payloads, payload
harvesting) catch only the blatant cases.

### 4d. Correlator aggregates (`internal/correlate`)

Windowed per-source aggregation turns many small probes into one verdict.
Each detector keys on the source IP, ages its state out per its window, and
de-duplicates emission so a sustained scan produces one alert, not a flood.
State checkpoints to `<data_dir>/correlate-state.json` so long-window
detection (slow-scan, beacon) survives a restart / hot reload. Defaults
shown are the `applyDefaults` values — all are tunable under `correlate:`
(see [`config.md`](config.md#correlate)).

| Rule | Fires when (default) | Window | Sev | ATT&CK |
|---|---|---|---|---|
| `correlate:port_scan` | 5 distinct dest ports from one source | 30s | high | T1046 |
| `correlate:slow_scan` | 10 distinct ports (per-port aged) | 24h | high | T1046 |
| `correlate:icmp_sweep` | 10 distinct dest IPs pinged | 60s | medium | T1018 |
| `correlate:brute_force` | 10 attempts to one port (creds captured) | 60s | high | T1110 |
| `correlate:password_spray` | 5 distinct usernames | 300s | high | T1110.003 |
| `correlate:credential_reuse` | same cred pair from 3 distinct source IPs | 1h | high | T1110.004 |
| `correlate:path_enumeration` | 50 distinct HTTP URL paths | 60s | high | T1595.003, T1083 |
| `correlate:dns_enumeration` | 50 distinct DNS names | 60s | medium | T1590.002, T1568.002 |
| `correlate:beacon` | ≥6 contacts, jitter ≤20%, mean interval ≥1s | 1h | high | T1071 |

Alongside these, the **storyline correlator** (`storyline:multi_stage`,
§6 / README) joins a source's events across ATT&CK *tactics* — it keys on
the tactic tags every event already carries (not on ports), so it fires for
a directed multi-stage intrusion even when no single windowed detector trips.

**Inspect it:** `tarpit-honeypot identify --ua/--path/--ssh/--ja3 …` tests a
single signal against 4a; `list-events --rule correlate:<name>` pulls the
aggregates.

---

## 5. Client classifiers

Beyond *which tool*, the sensor classifies *what kind of client* and stamps
stable fingerprints for clustering threat actors over time.

### Automation vs human (`toolfp.IdentifyHTTP`)

A layered heuristic sets `automation=true` (and the `automation-client`
anomaly, → T1595 reconnaissance) when: a tool signature matched, **or** no
`User-Agent` was sent, **or** the UA isn't browser-shaped, **or** a
browser-like UA arrived without the `Accept` / `Accept-Language` /
`Accept-Encoding` set a real browser sends. The `Verdict` carries `Tools`,
`Automation`, `Scanner`, `Category`, a `Confidence` (see §4a), and a
human-readable `Reason`.

### Cryptographic / protocol fingerprints (`internal/fingerprint`)

| Fingerprint | Computed from | Event meta |
|---|---|---|
| **JA3** | client TLS ClientHello (version, ciphers, extensions, curves, formats) | `ja3` |
| **JA4** | newer, sorted ClientHello fingerprint (cipher/extension counts + hashes) | `ja4` |
| **JA3S** | the *server* side of the TLS handshake | `ja3s` |
| **HASSH** | SSH `KEXINIT` algorithm lists (client) and server (`hassh_server`) | `hassh`, `hassh_server` |
| **JA4H** | HTTP request line + header order/values | `ja4h` |

These are deterministic per client stack, so the same scanner/library
clusters across connections even when it spoofs its User-Agent. They are
learned per source by the device registry (see
[usage.md](usage.md#archetypes)) and pair with the **passive OS guess**
(`os_guess` from the observed IPv4 TTL) for a richer actor profile.

What each encodes (so you can see which "client fingerprint" signals are
already covered): **JA3** = TLS version + cipher list + extension list +
curves + EC point formats (i.e. cipher *and* extension **ordering**);
**JA4** = TLS version + ALPN + cipher/extension *counts* + sorted hashes +
signature algorithms (ALPN, extension set, padding-extension presence);
**JA4H** = HTTP method + version + **header ordering** + cookie presence +
Accept-Language; **HASSH** = the SSH `KEXINIT` **algorithm/KEX/cipher/MAC**
ordering. SNI is captured separately (`meta.sni`).

### Fingerprint reputation + cross-sensor correlation (web UI)

The web UI **fingerprints** tab pivots from a fingerprint value to its
reputation: `/fingerprints` ranks every JA3 / JA4 / JA4H / JA3S / HASSH by
event volume (with distinct-IP and distinct-sensor counts + first/last
seen), and `/fingerprints/<kind>/<value>` is a per-fingerprint dossier —
first/last seen, distinct source IPs, and breakdowns over **sensors (fleet
correlation)**, top source IPs, **countries**, **ASNs**, protocols,
destination ports (service-named), **attack types** (rules), tools, and
**captured malware** artifact kinds. The same data is at
`/api/fingerprints[/<kind>/<value>]`. This is the cross-sensor /
fleet-correlation view: one client stack recurring across many sources,
ASNs, or sensors is a strong campaign signal.

### SSH / TLS client identification

`toolfp.IdentifySSH(client-id)` maps an SSH identification string
(`SSH-2.0-libssh2_1.9.0`, `SSH-2.0-Go`, paramiko, PuTTY, …) to a tool;
`toolfp.IdentifyTLS(ja3)` maps a JA3 to a known stack. Both feed the same
`tool:<name>` anomaly path.

**Inspect it:** `tarpit-honeypot identify --ssh SSH-2.0-libssh2_1.9.0` /
`--ja3 <md5>`.

### Coverage & limitations

What client-fingerprinting signals are observable from a **passive,
low-interaction, CGO-free, no-JavaScript** sensor that deliberately does
*not* complete handshakes it doesn't have to:

| Signal | Status | How |
|---|---|---|
| TLS cipher / extension **ordering** | ✅ | JA3 |
| TLS ALPN, extension set, padding extension | ✅ | JA4 |
| TLS SNI | ✅ | `meta.sni` |
| Server-side TLS shape | ✅ | JA3S |
| SSH KEX / cipher / MAC / compression algorithms + ordering | ✅ | HASSH |
| HTTP header **ordering** + cookies | ✅ | JA4H |
| Passive OS guess (TTL) | ✅ | `os_guess` |
| Scan timing template (`-T0`..`-T5`) | ✅ | scananalysis cadence |
| TCP/IP **window / options** (full p0f) | ◑ partial | TTL only; per-SYN options aren't joined to the flow |
| SSH **auth methods / PTY** request | ✗ infeasible | the sensor drops after `KEXINIT`; no key exchange is carried |
| HTTP/2 **SETTINGS / pseudo-header** order | ✗ infeasible | no HTTP/2 server (HTTP/1.1 bait only) |
| Browser **canvas / WebGL / fonts / timezone / navigation timing** | ✗ infeasible | requires executing JavaScript in a real attacker browser; the honeypot serves no live JS to targets (the operator UI's packaged JS is same-origin, `script-src 'self'`, and never sent to attacker-facing handlers) |
| nmap **idle / zombie scan** (`-sI`) | ✗ infeasible | by design the attacker's IP never appears on the wire — only the zombie's |

"Infeasible" here means *would require turning the honeypot into a
higher-interaction / scriptable target*, which conflicts with the threat
model (it must remain a safe target, never a reflection/amplification
primitive or a real browser). The ✅ rows already fingerprint the same
underlying tool/stack the infeasible rows would, via JA3/JA4/JA4H/HASSH.

---

## 6. Where it lands on the event

| Event field | Contents |
|---|---|
| `mitre_techniques` | ATT&CK technique ids (rule/handler/CVE/anomaly-derived) |
| `mitre_tactics` | ATT&CK tactic names |
| `mitre_defenses` | D3FEND countermeasure ids |
| `meta.cwe` / `meta.cpe` / `meta.epss` | vulnerability cross-refs (on `cve:<id>` events) |
| `meta.cvss` / `meta.cve_name` / `meta.description` | CVE detail |
| `meta.tools` / `meta.automation` / `meta.automation_reason` | tool + automation verdict |
| `meta.ja3` / `ja4` / `ja3s` / `hassh` / `hassh_server` / `ja4h` | fingerprints |
| `meta.os_guess` | passive OS family from TTL |
| `anomalies[]` | `tool:<n>`, `vulnerability-scanner`, `automation-client`, `cve:*`, protocol-misuse markers |

Every formatter (JSON / CEF / LEEF / OCSF) carries these through, so the
attribution travels with the event into the SIEM. See
[`INTEGRATIONS.md`](INTEGRATIONS.md) for SIEM field mappings and
[`design.md`](design.md) for where enrichment sits in the pipeline.

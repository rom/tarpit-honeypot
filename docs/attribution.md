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

There are **~150 static mappings** (≈23 exact rules + ≈85 handler tags + ≈42
anomaly tags), plus the prefix fallbacks. ICS detections use the ATT&CK for
ICS matrix (T0814 / T0836 / T0888 / T0846 / …) alongside the Enterprise
matrix so a SIEM expecting one ID space stays consistent.

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

Package `internal/cve` is a curated, in-source catalog (**55 records**) with
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

Worked examples:

| CVE | Name | CWE | CPE (product) | EPSS |
|---|---|---|---|---|
| CVE-2021-44228 | Log4Shell | CWE-502, CWE-917 | apache:log4j | 0.94 |
| CVE-2014-6271 | Shellshock | CWE-78 | gnu:bash | 0.94 |
| CVE-2019-19781 | Citrix ADC | CWE-22 | citrix:application_delivery_controller | 0.97 |
| CVE-2020-1472 | ZeroLogon | CWE-330 | microsoft:windows_server | 0.96 |
| CVE-2024-47177 | CUPS foomatic-rip | CWE-78 | openprinting:cups-filters | 0.40 |

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
network-layer scanning.

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
session: `sniffer:tcp_syn_scan` (`-sS`), `tcp_null_scan` (`-sN`),
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

Windowed per-source aggregation turns many small probes into one verdict:
`correlate:port_scan`, `correlate:slow_scan`, `correlate:icmp_sweep`
(discovery) and `correlate:brute_force` / `password_spray` /
`credential_reuse` (credential-access).

**Inspect it:** `tarpit-honeypot identify --ua/--path/--ssh/--ja3 …`.

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
| Browser **canvas / WebGL / fonts / timezone / navigation timing** | ✗ infeasible | requires executing JavaScript in a real browser; the honeypot serves no live JS and the UI is no-JS by design |
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

# Attack-tool & scanner identification

tarpit-honeypot fingerprints the **tool** behind a connection from signals it has
already captured — no extra round-trips — and tags the event so a SIEM can pivot
on `tool=sqlmap`, `automation=true`, or `category=c2`. The logic lives in
[`internal/toolfp`](../internal/toolfp); this page explains what it detects and
how.

## How identification works

Per connection the sensor feeds `toolfp` cheap signals and gets back a verdict:

| Signal | Source | Used for |
|---|---|---|
| **User-Agent** substring | HTTP request | the strongest tell — most tools self-identify |
| **request path** substring | HTTP request | catches tools even when the UA is spoofed/absent (e.g. `/nmaplowercheck`) |
| **SSH client banner** | SSH `SSH-2.0-…` line | libssh2 / paramiko / Go / putty / zgrab, etc. |
| **JA3 / JA4 / HASSH** | TLS / SSH handshake | cryptographic stack fingerprints (operator-extensible) |
| missing/odd browser headers | HTTP header set | the weak "this is automation, not a human" heuristic |

Matching is plain case-insensitive substring — high-signal, near-zero false
positive, and it never executes anything.

### The verdict an event carries
When a tool is identified the handler sets:

- `meta.tools` — the list of identified tool names (e.g. `["sqlmap"]`)
- anomaly `tool:<name>` — e.g. `tool:nuclei`
- `meta.tool_confidence` (0–100) + `meta.tool_confidence_label` (`high`/`medium`/`low`)
- `meta.automation` (+ anomaly `automation-client`) when the client looks scripted
- a **category** anomaly for the strongest class: `vulnerability-scanner`,
  `c2-framework`, or `headless-browser`

**Confidence** reflects *how sure we are of the identification*, not how
dangerous the tool is: `high` = the client self-identified (UA / SSH banner /
JA3 hash); `medium` = a tool-specific path matched or the UA was missing/
non-browser; `low` = automation inferred from a weak heuristic with no tool named.

## Categories

| Category | Meaning | Examples |
|---|---|---|
| **vuln-scanner** | a vulnerability / web-app scanner | Nessus, OpenVAS, Qualys, Nexpose, Acunetix, Nikto, Nuclei, sqlmap, wpscan, sn1per, afrog, xray, goby, fscan, w13scan, pocsuite, dismap, wafw00f, garak (AI/LLM), … |
| **c2** | command-and-control / RAT / red-team framework | Cobalt Strike, Metasploit/Meterpreter, Mythic, Sliver, Havoc, Brute Ratel, Empire, Covenant, Merlin, Villain, Pupy, PoshC2, Quasar, AsyncRAT, njRAT, … |
| **headless** | automation driver masquerading as a browser | headless Chrome, PhantomJS, Puppeteer, Playwright, Selenium |
| **tool** | any other identified tool (recon, fuzzers, brute-forcers, libraries, miners, tunnels, phishing kits) | everything below |

## What it recognizes (by class)

The catalog holds **300+ signatures**. The notable families:

- **Internet-wide scan / OSINT engines** (often benign-but-noisy research):
  Censys, Shodan, BinaryEdge, Shadowserver, Rapid7/Project Sonar, Stretchoid,
  InternetMeasurement/Driftnet, LeakIX, Onyphe, CriminalIP, Expanse/Palo Alto,
  NetSystemsResearch, Alphastrike, Netcraft, Modat, BitSight, ProjectDiscovery.
  *(These are also attributed at the IP level by ASN/rDNS — see the reputation
  badges in the web UI; that catches a scanner even when it sends no UA.)*
- **Port / service scanners**: nmap, masscan, zmap, zgrab/zgrab2, unicornscan,
  RustScan.
- **Web / vuln scanners**: Nuclei, Nikto, sqlmap, Acunetix, Nessus, OpenVAS,
  Qualys, Nexpose/InsightVM, Netsparker/Invicti, AppScan, Arachni, w3af,
  Skipfish, Wapiti, WhatWeb, OWASP ZAP, Burp Suite, WPScan, JoomScan,
  Droopescan, CMSeeK, Vulmap, Clusterd, Jok3r, Osmedeus, RouterSploit,
  AutoSploit, sn1per, afrog, xray, goby, fscan, kscan, w13scan, pocsuite,
  dismap, yakit, vulners, wafw00f, garak.
- **Content-discovery / fuzzers**: ffuf, feroxbuster, gobuster, dirsearch,
  dirstalk, wfuzz, Kiterunner, x8, Arjun, ParamSpider, commix, xsstrike, dalfox.
- **Recon / OSINT CLIs**: katana, httpx, subfinder, naabu, dnsx, hakrawler,
  gospider, amass, assetfinder, massdns, puredns, shuffledns, dnsrecon, fierce,
  Sublist3r, theHarvester, recon-ng, SpiderFoot, gowitness, aquatone,
  EyeWitness, metabigor, and the ProjectDiscovery suite (asnmap, cdncheck, tlsx,
  uncover, notify, proxify, chaos-client, dnsgen, interactsh).
- **Secret / repo scrapers**: git-dumper, TruffleHog, gitleaks.
- **Brute-force / cred attack**: Hydra, Medusa, Patator, Ncrack, NetExec/
  CrackMapExec.
- **C2 / RAT / red-team**: see the category table above.
- **Tunnels / pivots**: chisel, ligolo, gost, frp, rsockstun.
- **Phishing kits / proxies**: GoPhish, Evilginx, Muraena, Modlishka.
- **Crypto-miners / IoT botnet loaders**: XMRig, Kinsing, Hajime, Gafgyt,
  Tsunami.
- **HTTP client libraries** (a tell when hitting a "browser-only" surface):
  python-requests/httpx/aiohttp, Go net/http, OkHttp, axios, node-fetch,
  Guzzle, libcurl, WinHTTP, reqwest/hyper (Rust), Scrapy, HTTrack, httpie, …
- **SSH clients** (from the SSH-2.0 banner): libssh2, libssh, paramiko, Go,
  PuTTY, JSch, Russh, zgrab, and scanners that reuse them.

## Extending it

- HTTP UA / path signatures live in `uaSignatures` / `pathSignatures`
  (`internal/toolfp/toolfp.go`); SSH-banner signatures in `sshClientSignatures`;
  JA3 hashes in `ja3Signatures` (operators add their own corpus).
- A new scanner that's also a *vulnerability* scanner should be added to the
  `vulnScanners` set so it gets the `vulnerability-scanner` category; a C2/RAT to
  `c2Frameworks`.
- The authoritative, always-current list is what the running binary holds —
  the web UI's **docs** page renders it from the same tables.

## Caveats

- Self-identification can be **spoofed**: a real attacker can set
  `User-Agent: Mozilla/…`. That's why path signatures, JA3/JA4/HASSH, the
  automation heuristic, and the behavioural correlators (tool-rotation,
  fingerprint-reuse) exist alongside UA matching — and why a scanner's *IP-level*
  attribution (ASN/rDNS) is tracked independently.
- Benign research scanners (Censys/Shodan/Shadowserver/…) are identified the same
  way as hostile ones; use the reputation badges + your `allowlist` / `hidden_ips`
  to triage them.

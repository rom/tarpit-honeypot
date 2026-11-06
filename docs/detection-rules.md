# Operator detection rules (detection-as-code)

The built-in detectors (handler anomaly markers, the CVE catalog, the
correlator, ATT&CK tagging) are compiled in. **Detection rules** let an
operator add their own match logic in YAML — no recompile — matched against
*every* event the sensor produces. It is a small, Sigma-inspired,
non-Turing-complete matcher: field equality / contains / prefix / suffix /
regex / numeric / exists, ANDed across fields with OR within a field's value
list. It never executes anything (the sandboxed `lua` response handler remains
the only scripting surface), so a rules directory is safe to source-control,
review, and ship like any other detection content.

```yaml
# /etc/tarpit-honeypot/config.yaml
detection:
  rules_dir: /etc/tarpit-honeypot/rules
```

Every `*.yml` / `*.yaml` file in that directory is loaded at start and re-read
on `SIGHUP` (no restart, no dropped connections). `validate-config` loads them
too and fails on a malformed rule (bad regex, unknown modifier, missing `id`,
YAML syntax), so you catch mistakes before deploy. An unset `rules_dir`, a
missing directory, or an empty one is a clean no-op. The engine caps a
directory at **2000 rules**.

> **Quick start:** copy [`configs/rules/`](../configs/rules/) into your
> `rules_dir` — it ships an annotated [`example.yml`](../configs/rules/example.yml)
> plus seven ready-to-run packs (credential access, web exploitation, recon /
> scanners, OT/ICS control, exfil / C2, malware artifacts, appliance / Lua —
> see [§ Shipped rule packs](#shipped-rule-packs)).

> Not sure whether your idea wants a detection rule, a Lua persona, or a YARA
> rule? [`scripting.md`](scripting.md) is the map of how the three layers divide
> the work.

## Syntax at a glance

```yaml
- id: unique-rule-id            # required, unique across all files
  title: Human title            # shown in the /rules UI
  description: optional          # quote it if it contains a colon-space ": "
  severity: high                # low|medium|high|critical — only ever RAISES
  tags: [custom:foo, attack.t1190]   # added as anomaly markers (attack.* → chip)
  match:                        # ── every key ANDs; a list value ORs ──
    handler: [http, https]      #   field: v          equals (case-insensitive)
    meta.user_agent|contains: sqlmap   # field|MOD: v  → contains / prefix / suffix
    meta.http_uri|re: "(?i)\\.\\./"     #   |re   RE2 regex (case-SENSITIVE; (?i) to fold)
    dest_port|gt: "1024"         #   |gt / |lt   numeric compare
    anomaly: webapp:cmdi         #   anomaly      one of the event's markers
    meta.bearer_token|exists: true   # |exists  field present & non-empty
```

- **Fields:** `handler`, `rule_id`, `proto`, `severity`, `source_ip`,
  `dest_ip`, `dest_port`, `banner`, `sensor`, `anomaly`, `mitre`, `tactic`,
  `meta.<dotted.path>` (+ aliases — full table below).
- **Modifiers:** *(none)*=equals · `contains` · `prefix` · `suffix` · `re`
  (RE2) · `gt`/`lt` · `exists`. All case-insensitive **except `re`** — RE2, no
  look-around / backrefs, use `(?i)`.
- **Semantics:** keys AND, list values OR, exclusion is via tagging + routing
  (rules only ever *raise* severity — there is no "not" operator).

## What a match does

When a rule matches, the sensor — *in place, before correlation, risk scoring,
routing and forwarding see the event* —

- adds each of the rule's `tags` to the event as **anomaly markers** (so they
  appear in `/search?tag=…`, the attack tables, the profile dossier, and every
  export: JSON / CEF / LEEF / OCSF; an `attack.tXXXX` tag also lights up as an
  ATT&CK chip),
- adds a `detect:<id>` marker and records the id under `meta.detect_rules`,
- **raises** the event severity to the rule's `severity` (it never lowers it).

It never executes anything — this is declarative matching only. Multiple rules
can match one event; **all** of them apply and the severity ends up at the
highest any matched rule asked for. Rules are evaluated in a deterministic order
(files sorted by name, then top-to-bottom within a file), and because tags are
added in place, a later-evaluated rule's `anomaly:` condition can match a marker
an earlier rule added — so you can build a cheap two-stage rule if you want.

## Rule format

```yaml
- id: my-rule                 # required, unique
  title: Human-readable title # shown in the /rules UI
  description: optional        # quote it if it contains a colon-space ": "
  severity: high              # optional; low | medium | high | critical — only ever RAISES
  tags: [custom:foo, attack.t1190]   # added as anomaly markers on a match
  match:                      # every key is ANDed; a list value is ORed
    handler: [http, https]
    meta.user_agent|contains: "${jndi:"
    dest_port|gt: "1024"
    anomaly: webshell
```

A rule file is **either** a top-level YAML list of rules (as above) **or** a
document with a `rules:` key wrapping that list — so you can keep one rule or
many per file, and mix files freely:

```yaml
rules:
  - id: rule-a
    match: { handler: ssh }
  - id: rule-b
    match: { handler: telnet }
```

### Fields

`match` keys resolve against the in-flight event. Several have aliases (any of
the listed names works):

| Field (aliases) | Resolves to |
|---|---|
| `handler` | the protocol handler (`ssh`, `http`, `redis`, `modbus`, …) |
| `rule_id` / `rule` | the event's rule id (`listener:…`, `cve:…`, `correlate:…`) |
| `proto` | `tcp` / `udp` / `icmp` / … |
| `severity` | `low` / `medium` / `high` / `critical` (the event's current severity) |
| `source_ip` / `src_ip` / `source` | attacker IP |
| `dest_ip` / `dst_ip` / `dest` | decoy IP |
| `dest_port` / `dst_port` / `port` | decoy port (numeric string) |
| `banner` | the banner the decoy sent |
| `sensor` | the sensor id that produced the event |
| `anomaly` / `anomalies` | matches if the value is **one of** the event's anomaly markers |
| `mitre` / `technique` / `techniques` | ATT&CK techniques on the event |
| `tactic` / `tactics` | ATT&CK tactics on the event |
| `meta.<dotted.path>` | walks the event `meta` map (e.g. `meta.auth_user`, `meta.http.headers.host`) |

`meta.<path>` walks nested maps by dots; if the leaf is a list, **each element**
is a candidate (so `meta.commands|contains: "whoami"` matches when any captured
command contains it). A path that doesn't exist simply never matches — it is
not an error, so rules are safe to write against keys only some handlers set.

### Modifiers (`field|modifier`)

| `field|mod` | Matches when |
|---|---|
| `field: v` (no modifier) | candidate **equals** `v` (case-insensitive) |
| `field|contains: v` | candidate contains `v` (case-insensitive) |
| `field|prefix: v` | candidate starts with `v` (case-insensitive) |
| `field|suffix: v` | candidate ends with `v` (case-insensitive) |
| `field|re: v` | candidate matches RE2 regex `v` (**case-sensitive** — prefix `(?i)` to fold) |
| `field|gt: n` / `field|lt: n` | candidate parses as a number and is `> n` / `< n` |
| `field|exists: true` | the field is present and non-empty |

Two gotchas worth internalizing:

- **`re` is the only case-sensitive matcher.** Equality / contains / prefix /
  suffix lower-case both sides; regex does not. Use `(?i)` when you want a
  case-insensitive pattern (the shipped packs do).
- **`re` is RE2** (Go's `regexp`): linear-time, but **no back-references and no
  look-ahead/behind**. `^(?!10\.0\.)` will fail to compile. Express exclusions
  by listing the ranges you *do* want to alert on (see the OT "untrusted source"
  template), or split into two rules.

### Matching semantics

- **AND across keys**: every key in `match` must hold.
- **OR within a value list**: `handler: [http, https]` matches either; with a
  modifier, `anomaly|prefix: ["dns-tunnel", "dns-cname-tunnel"]` matches a marker
  with *either* prefix.
- `gt` / `lt` silently fail (don't match) if either side isn't numeric, so
  `dest_port|gt: "1024"` is safe even on events without a port.

## Useful event fields & meta keys

These are the most commonly populated `meta.*` keys, by area — a starting map
for writing site rules. (Run the sensor with a capture and inspect a few events,
or `--log-level debug`, to see exactly what a given handler emits.)

| Area | Keys |
|---|---|
| **Credentials** | `meta.auth_user`, `meta.auth_pass`, `meta.username`, `meta.password`, `meta.user_attempt` (telnet), `meta.basic_user` / `meta.basic_pass`, `meta.ntlm_user` / `meta.ntlm_domain` / `meta.ntlmv2_hash`, `meta.bearer_token`, `meta.authorization` |
| **HTTP** | `meta.http_uri`, `meta.http_method`, `meta.request_line`, `meta.user_agent`, `meta.http_login_user` / `meta.http_login_pass`, `meta.path` |
| **TLS / fingerprints** | `meta.ja3`, `meta.ja4`, `meta.ja3s`, `meta.tls_version`, `meta.hassh` (SSH), `meta.tools`, `meta.tool_confidence` |
| **DNS** | `meta.qname`, `meta.qtype` — plus the `dns-tunnel*` / `dns-dga*` / `dns-txt-exfil` / `dns-long-encoded-label` anomaly markers |
| **OT / ICS** | `meta.intent` (a descriptive sentence per request), `meta.op`, `meta.message_type`, `meta.cotp_type`, plus `ics-modbus-write` / `ics-plc-write` markers |
| **Honeytokens / traps** | `honeytoken:account-login`, `robots-honeypot-access`, `sitemap-honeypot-access` (anomaly markers); `meta.honeytoken` |
| **General** | `meta.intent` (set by most handlers), `meta.commands` (captured shell/protocol commands), `meta.rate_limited`, `meta.cwe` |

The single richest field is **`meta.intent`** — almost every handler stamps a
plain-language summary of what the client just did (e.g. `"S7comm PLC STOP —
halting the controller (denial of control)"`), which makes `meta.intent|re`
rules both readable and durable across protocol versions.

## Recipes

A few worked patterns; the [shipped packs](#shipped-rule-packs) contain ~40 more.

**Log4Shell JNDI string in any captured header**

```yaml
- id: log4shell-anywhere
  title: Log4Shell JNDI lookup string
  severity: critical
  tags: [custom:log4shell, attack.t1190]
  match:
    meta.user_agent|contains: "${jndi:"
```

**Privileged login on any auth-bearing service** (handler-agnostic — fires
wherever `auth_user` is captured)

```yaml
- id: privileged-login
  severity: high
  tags: [custom:privileged-login, attack.t1110]
  match:
    meta.auth_user|re: "(?i)^(root|admin|administrator|sa|oracle)$"
```

**Promote any built-in CVE hit on a web handler** (rule_id matching)

```yaml
- id: web-cve
  severity: high
  tags: [custom:web-cve]
  match:
    handler: [http, https]
    rule_id|prefix: "cve:"
```

**OT control command from an untrusted source range** (no negation operator, so
list the ranges that should never speak control to a PLC)

```yaml
- id: ot-control-from-untrusted
  severity: critical
  tags: [custom:ics-untrusted-source, attack.t0855]
  match:
    handler: [modbus, s7, dnp3, ethernetip, opcua]
    meta.intent|re: "(?i)(write|stop|download|operate|restart)"
    source_ip|prefix: ["10.20.", "192.168.50."]
```

**Quiet a noisy benign source** without dropping the event — match it and tag
it so your routing layer can de-prioritize (rules only ever *raise* severity, so
use a tag + downstream routing rather than expecting the rule to lower it):

```yaml
- id: tag-known-scanner-host
  tags: [custom:known-internal-scanner]
  match:
    source_ip: "10.0.0.50"
```

## Shipped rule packs

[`configs/rules/`](../configs/rules/) ships an annotated starter
[`example.yml`](../configs/rules/example.yml) plus nine curated packs (~55 rules)
you can deploy as-is or fork. Each is grounded in the markers the handlers
actually emit:

| File | Focus | Highlights |
|---|---|---|
| [`credential-access.yml`](../configs/rules/credential-access.yml) | credential theft / brute force | honeytoken login (critical), privileged usernames, weak/default passwords, net-NTLMv2 capture, IMDS credential-path SSRF, bearer-token capture |
| [`web-exploit.yml`](../configs/rules/web-exploit.yml) | web exploitation | Spring4Shell, path traversal, command injection, LFI, secret/VCS-file probes, web-shell upload paths, CRLF, any CVE on http/https |
| [`recon-and-scanners.yml`](../configs/rules/recon-and-scanners.yml) | enumeration / tooling | scanner User-Agents, behaviour-based tool fingerprints, unknown-protocol probes, robots/sitemap traps, SNMP default community, UDP amplification probes, a known-bad-JA3 template |
| [`ot-ics-control.yml`](../configs/rules/ot-ics-control.yml) | OT / ICS control | PLC STOP, program/logic download, Modbus & generic writes, safety-controller (TRITON) manipulation, restart/reset, fieldbus-over-IP recon, enumeration, untrusted-source template |
| [`exfil-and-c2.yml`](../configs/rules/exfil-and-c2.yml) | exfiltration / C2 | DNS tunneling / DGA / TXT-exfil / long encoded labels, SSRF callback, malware capture, DB cross-collection exfil |
| [`malware-artifacts.yml`](../configs/rules/malware-artifacts.yml) | captured artifacts | any YARA hit, C2-framework families, xz supply-chain backdoor, packed / archive-wrapped executables, cloud creds in a payload (ties into the YARA engine, [`yara.md`](yara.md)) |
| [`appliance-and-lua.yml`](../configs/rules/appliance-and-lua.yml) | appliance / persona exploitation | CVE-path hits on the fake appliances, RCE staging, Log4Shell, Cl0p/MOVEit, secret-file harvest — driven by the `lua:` flags the [Lua personas](lua.md) raise |
| [`enrichment-reputation.yml`](../configs/rules/enrichment-reputation.yml) | enrichment / reputation | spoofed-crawler PTR, high cross-feed `threat_confidence`, anonymizer (Tor/VPN/proxy), ASN-DROP / bulletproof ASN, ASN↔geo mismatch, high-risk geo, default/breached credentials, DGA + known-malicious domains, plus corroborated combos that reach critical — keys on the [enrichment labels](../README.md#enrichment) |
| [`ot-malware.yml`](../configs/rules/ot-malware.yml) | named OT-malware behavior | TTP-level recognition of FrostyGoop (Modbus register writes), Industroyer/Industroyer2 (IEC-104 control), TRITON/TRISIS (Triconex SIS), PIPEDREAM/INCONTROLLER (multi-protocol PLC manipulation), Stuxnet (S7 logic), and Havex/Dragonfly (OPC enumeration) — hedged "behavior consistent with …", built on the OT handlers' anomaly markers |

Several rules (Log4Shell, CVE promotion, OT control) deliberately overlap the
built-in detectors — they're there to show the pattern and to let you re-tag /
re-prioritize built-in hits for *your* routing. Delete or tune freely.

### Statistical baselines + multi-stage kill-chain (built-in)

Alongside the signature + pattern correlators (`correlate:*`), the sensor runs a
dependency-free **statistical baseline** detector (`internal/baseline`, always
on) that emits:

| Rule id | Fires when |
|---|---|
| `baseline:new-asn` / `baseline:new-port` / `baseline:new-country` | the first time (after a warmup learning period, default 1h) a source ASN, destination port or source country is seen — a never-before-observed entity |
| `baseline:volume-spike` | a per-minute event bucket exceeds the rolling EWMA mean + k·stddev (default k=4), above a floor — a traffic surge against the learned baseline |
| `killchain:multistage` | one source progresses through ≥N distinct ATT&CK **tactics** (default 3) within a window (default 30m) — a single consolidated "campaign" alert carrying the observed stages, deduped so it fires once per window |

These are behavioural/statistical, so they carry no CVE and complement (don't
replace) the `correlate:*` detectors. Match them in rules like any other
`rule_id` (e.g. `rule: killchain:multistage` → page; `rule: baseline:new-country`
→ enrich-and-watch).

## Operating notes

- **Validate before deploy.** `tarpit-honeypot validate-config -c your.yaml`
  loads the directory and reports each bad rule with its file and id; the run
  exits non-zero if any rule fails to compile. A bad *file* is skipped (its
  rules don't load) but never aborts the others.
- **Watch hit counts.** The operator UI's `/rules` view lists every loaded rule
  with its lifetime match count (and `meta.detect_rules` on each event shows
  which rules fired), so you can spot dead rules and noisy ones.
- **Severity only goes up.** A rule with `severity: critical` raises a matched
  event; a rule with no `severity` only tags. To *lower* priority, tag and
  handle it in routing — the engine never de-escalates.
- **Performance.** Matching is O(rules × conditions) per event, all in-memory
  string ops; a few hundred rules is negligible. The hard cap is 2000.
- **Reload semantics.** `SIGHUP` re-reads the whole directory live (no restart,
  no dropped connections), so editing, adding, or removing rule files never
  needs a bounce — validate first, then `kill -HUP`.

See [`configs/rules/example.yml`](../configs/rules/example.yml) for the annotated
starter, and [`attribution.md`](attribution.md) for how anomaly markers and
ATT&CK tags flow into exports.

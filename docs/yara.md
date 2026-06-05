# YARA artifact rules

tarpit-honeypot ships a **CGO-free, pure-Go YARA-style engine**
(`internal/artifactscan`) that statically analyses the artifacts attackers drop
on the sensor — uploaded webshells, dropped malware, raw or base64-wrapped
shellcode, archives, exploit scripts — and classifies them with a large built-in
rule pack plus any rules you add. It is **detection + classification only**:
nothing captured is ever executed or fetched (URLs found in payloads are only
recorded unless you explicitly opt into the egress-gated fetcher).

Because it is pure Go it stays inside the project's no-CGO / single-static-binary
constraint (no `libyara` dependency), at the cost of supporting the *common* YARA
rule shape rather than the entire language — see [Supported subset](#supported-rule-subset).

> Also rendered in-product under the web UI **docs** tab (`/docs/yara`).

## Contents

- [When rules run](#when-rules-run)
- [The built-in rule pack](#the-built-in-rule-pack)
- [Per-rule severity](#per-rule-severity)
- [Supported rule subset](#supported-rule-subset)
- [Module support](#module-support)
- [Loading your own rules](#loading-your-own-rules)
- [Known-malware hash sets](#known-malware-hash-sets)
- [The `analyze` CLI](#the-analyze-cli)
- [Writing a rule](#writing-a-rule)
- [How a match surfaces](#how-a-match-surfaces)

## When rules run

The engine runs when payload harvesting is enabled and the sensor extracts an
*artifact* from captured bytes — i.e. a classifiable binary / script / shellcode
/ archive blob, not every byte of every connection. Enable it with:

```yaml
sensor:
  payloads:
    enabled: true        # harvest dropped artifacts to <data_dir>/payloads/
    analyze: true         # run static analysis + the YARA engine on them
    yara_rules: /etc/tarpit-honeypot/enrichment/yara   # optional: your extra rules
    malware_hashes: /etc/tarpit-honeypot/enrichment/malware/sha256.txt  # optional
```

Each harvested artifact is parsed (ELF/PE/Mach-O/ZIP via the Go standard
library), entropy-scored, string/IOC-scraped, hashed, and rule-matched. A
positive identification enriches the triggering event and emits a
`malware:capture` event; the artifact bytes are persisted to
`<data_dir>/payloads/<sha256>.<ext>` and listed on the **captures** page.

**Uploads are scanned too.** A file pushed to the FTP handlers (STOR/STOU/APPE,
including anonymous uploads) is captured, MD5/SHA1/SHA256-checksummed into the
event, flagged by type and drop context (e.g. `ftp-elf-upload`,
`ftp-keymaterial-upload`, `ftp-anon-writable-drop` for /pub /incoming /upload),
and surfaced as the connection payload so it runs through this same classifier +
rule engine. `sensor.payloads.max_upload_kb` controls how much of an uploaded
file is retained (default 1 MiB; `--set sensor.payloads.max_upload_kb=<KiB>` on
the CLI) for full-sample capture.

Files obtained any other way are captured the same way: a file **embedded inside
another stream** — a multipart/form-data web upload, a raw PUT body after the
HTTP headers, or a base64 blob in a URL/header — is extracted from its magic
bytes wherever it sits (`payload-embedded`), so it also lands in
`<data_dir>/payloads/` and on the **captures** page. Archives are inspected for
embedded executables (`payload-archive-exe`) even when the member is renamed
(magic-byte check).

CVE *exploit-attempt* detection over request payloads is a **separate** layer
(`internal/cve`, the `cve:<id>` events) — YARA here is about the bytes attackers
leave behind, not the request that delivered them.

## The built-in rule pack

The default pack is large (hundreds of rules) and authored in the same subset
the `.yar` loader accepts, so the built-ins also exercise the parser. Coverage
includes:

- **Commodity malware**: RATs (njRAT, AsyncRAT, Quasar, Remcos, NanoCore,
  DarkComet, Gh0st, PlugX, NetWire, …), stealers/loaders (RedLine, Vidar,
  Lumma, Raccoon, AgentTesla, SmokeLoader, GuLoader, IcedID, Qakbot, …),
  bankers/clippers, and ransomware families (LockBit, Conti, REvil, BlackCat,
  WannaCry, Akira, …).
- **Offensive tooling & C2**: Cobalt Strike, Meterpreter, Sliver, Havoc, Brute
  Ratel, Covenant, Mimikatz, LaZagne, Rubeus, SharpHound, Impacket,
  CrackMapExec, sqlmap, Nmap/masscan, Chisel/ngrok/frp tunnels, …
- **Webshells**: China Chopper, WSO, b374k, Behinder, AntSword, Godzilla,
  reGeorg, Weevely, …
- **APT implants**: SUNBURST, Stuxnet, Flame, Winnti, ShadowPad, X-Agent,
  Carbanak, Equation, …
- **Packers / protectors**: UPX, VMProtect, Themida, ASPack, Enigma, ConfuserEx,
  PyArmor, … (tagged down to `medium` — packing is a trait, not proof).
- **Behavioural traits / `pe`-module rules**: process hollowing, UAC bypass,
  LSASS dump, AMSI patch, keylogger / service-persistence / injection import
  sets.
- **IoT / IIoT / OT / building automation** (a deep focus area):
  - IoT botnet families (Mirai variants, Mozi, Gafgyt/Bashlite, Hajime, Mukashi,
    Zerobot, RapperBot, AESDDoS, Tsunami/Kaiten, …) and multi-arch
    busybox/tftp loader + router/camera exploit-CGI patterns (HNAP, UPnP/TR-064,
    GPON, Dahua/Hikvision/Foscam/Axis, MikroTik, Netgear/D-Link/Tenda, …).
  - OT/ICS protocol & tooling fingerprints (Modbus, S7comm, DNP3, EtherNet/IP,
    BACnet, PROFINET, IEC-61850/104, OPC UA/DA, CODESYS, PCWorx, EtherCAT, FINS,
    MELSOFT, plcscan/s7scan/smod/ICSSploit, Nmap ICS NSE, …).
  - OT/ICS malware (Industroyer/Industroyer2, TRITON/TRISIS, Havex, BlackEnergy,
    GreyEnergy, Exaramel, PIPEDREAM/INCONTROLLER, EKANS, FrostyGoop,
    CosmicEnergy, AcidRain, LockerGoga, Cring, …).
  - Building automation product references (Tridium Niagara, JCI Metasys,
    Siemens Desigo/APOGEE, Honeywell EBI, Schneider EcoStruxure, Automated Logic
    WebCTRL, Delta/Distech/Reliable Controls, KNX, LonWorks, DALI, Crestron/AMX/
    Lutron, …).
  - Adjacent domains: smart-meter (DLMS/COSEM, ANSI C12), automotive
    (CAN-utils, UDS/CaringCaribou, J1939), medical (DICOM, HL7, FHIR), maritime
    (NMEA/AIS), rail (RaSTA/Genisys), and discovery (SSDP, WS-Discovery, mDNS,
    LoRaWAN, MQTT Sparkplug B).

Count the compiled rules at runtime: the sensor logs
`artifact static analysis enabled yara_rules=<n>` at startup, and
`tarpit-honeypot analyze` reports the engine total when it loads extra rules.

## Per-rule severity

Every rule carries a severity that controls **how far a match escalates the
`malware:capture` event**, so a generic trait rule does not page like a
confirmed-malware hit. It is read from the rule's `meta`:

```
meta:
    severity = "low" | "medium" | "high" | "critical"   # or a numeric score:
    score    = 0..100   # >=75 critical, >=50 high, >=25 medium, else low
```

A rule that declares **neither defaults to `critical`** (preserving the
historical "any hit is a confirmed detection" behaviour for the high-confidence
built-ins). The built-ins tag trait/recon/packer rules down to `high`/`medium`
so they sit at the captured-artifact baseline (High) rather than forcing
Critical. Two invariants override rule severity: a **known-malware hash match**
and a **magic-confirmed executable** are always Critical.

## Supported rule subset

Authored in `.yar` files; constructs outside the subset cause that **one rule**
to be skipped (with a collected error) rather than failing the file — so
dropping a real-world `.yar` collection in still loads whatever is expressible.

**Strings** (`strings:` section)

| Form | Example |
|---|---|
| Text | `$a = "eval(" nocase` — modifiers `nocase` `wide` `ascii` `fullword` |
| Hex | `$b = { 4D 5A ?? ?? }` — `??` byte wildcard (no jumps `[n-m]` / alternations) |
| Regex | `$c = /jndi:(ldap|rmi)/ i` — RE2 syntax, `i`/`s` flags |

**Conditions** (`condition:` section)

- `$a`, `and`, `or`, `not`, parentheses, `true`/`false`
- `N of (...)`, `any of (...)`, `all of them`, id globs (`$a*`, `them`)
- comparison (`== != < <= > >=`), arithmetic & bitwise (`+ - * \ % & | ^ << >>`),
  unary `-`/`~`, integer literals incl. `0x` hex and `KB`/`MB`/`GB` suffixes
- the modules below

**Not supported** (rule skipped): string-count `#a`, offset `@a` / `at` / `in`,
`for` loops, `entrypoint`, regex arguments to module functions, and unknown
modules.

## Module support

A practical slice of the YARA module surface, backed by the same standard-library
parsers used for static analysis (so no new dependencies):

| Module | Available |
|---|---|
| `filesize` | the artifact size in bytes |
| readers | `uint8/16/32(off)`, `uint16be/uint32be(off)`, `int8/16/32(off)` |
| `pe` | `pe.imports("dll"[, "func"])`, `pe.entry_point` (file offset), `pe.is_dll`, `pe.number_of_sections` |
| `elf` | `elf.type` (+ `elf.ET_EXEC` etc.), `elf.number_of_sections` |
| `math` | `math.entropy(off, len)`, `math.in_range(v, lo, hi)` |
| `hash` | `hash.md5/sha1/sha256(off, len)` |

Module facts are parsed once per artifact and shared across rules. As in real
YARA, any comparison/boolean use of an **undefined** module value is false — so
`pe.is_dll()` on an ELF simply doesn't match (no cross-format false positives).

```
rule PE_Process_Injection_APIs : injection {
    condition:
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}
```

## Loading your own rules

Point `sensor.payloads.yara_rules` at a `.yar` file **or a directory** of them
(every `.yar`/`.yara` under it is compiled, recursively). They are loaded *in
addition* to the built-ins. The enrichment scripts can fetch community packs
(e.g. abuse.ch YARA rules) into that directory; see `scripts/fetch-enrichment.sh`.
Reload after changing rules by restarting (or `SIGHUP` where supported).

## Known-malware hash sets

`sensor.payloads.malware_hashes` (or `analyze --hashes`) loads a SHA-256 set
(abuse.ch MalwareBazaar / ThreatFox export, `sha256[,family]` per line). A
captured artifact whose hash is in the set is flagged **known malware** (with the
family when present) and elevated to Critical regardless of any rule severity.

## The `analyze` CLI

Triage a sample offline with the exact engine the sensor uses:

```sh
tarpit-honeypot analyze suspicious.bin
tarpit-honeypot analyze --rules ./myrules --hashes ./sha256.txt sample.elf
tarpit-honeypot analyze --json sample.exe        # full structured report
```

It prints the format/arch, sha256, entropy (+ packer flag), sections, imports,
suspicious traits, extracted IOCs, and each YARA match with its tags, severity,
and description. Nothing is executed.

## Writing a rule

```
rule Acme_Dropper : dropper {
    meta:
        description = "Acme downloader cradle"
        severity    = "high"
    strings:
        $u = "Net.WebClient"
        $d = "DownloadString"
        $h = { 41 63 6D 65 }        // "Acme"
    condition:
        ($u and $d) or $h
}
```

Keep rules **high-signal**: a built-in match elevates the capture's severity, so
prefer one very-distinctive token or a 2-of/`and` combination over a single
generic word, and tag heuristic/recon rules down with `severity`.

## How a match surfaces

- The triggering event gains `yara:<rule>` anomaly markers, a
  `payload_artifacts` descriptor, and a compact `payload_analysis` report.
- A `malware:capture` event is emitted (severity per the rules / hash / magic).
- The artifact bytes are on the **captures** page and in the per-source
  artifacts ZIP; the hash becomes an IOC.
- Rule tags/severity/description show in `analyze` output and the event detail.

See also: [`attribution.md`](attribution.md) (the CVE/CWE/ATT&CK mapping layer),
[`config.md`](config.md) (`payloads` block), and [`cli.md`](cli.md) (`analyze`).

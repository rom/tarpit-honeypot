# Scripting & dynamics: YAML, Lua and YARA

`tarpit-honeypot` is a single static Go binary, but a deployment is far from
static. You shape *what it pretends to be*, *how it answers*, and *what it
decides is interesting* through three text formats — **YAML**, **Lua** and
**YARA** — none of which require recompiling the sensor. This page is the map:
what each one is, where it plugs in, and what to reach for when.

```
                         attacker bytes
                              │
            ┌─────────────────▼──────────────────┐
   YAML ───►│  listeners / handlers / archetypes  │   ← what the sensor IS
 (config)   │  (config.yaml)                      │
            └─────────────────┬──────────────────┘
                              │ a connection hits a handler
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
  built-in handler     handler: scripted      handler: lua
  (Go, compiled)        (YAML rules)          (Lua persona)   ← how it ANSWERS
        └─────────────────────┼─────────────────────┘
                              │ produces an event (+ any captured artifact)
        ┌─────────────────────┼─────────────────────┐
        ▼                                           ▼
  detection rules (YAML)                    artifact rules (YARA)   ← what it DECIDES
  match every event                         classify dropped files
                              │
                              ▼
                  store · correlate · ATT&CK · sinks
```

The short version:

| Format | Package / config | Runs… | Use it to… |
|---|---|---|---|
| **YAML** | `config.yaml`, `handler: scripted`, `detection.rules_dir` | at load (config), per-connection (scripted), per-event (rules) | declare the deployment, define simple services, and match events |
| **Lua** | `handler: lua`, `internal/luaengine` | per-connection, sandboxed VM | drive a *dynamic* service persona with real logic + state |
| **YARA** | `sensor.payloads`, `internal/artifactscan` | per-captured-artifact | classify the files / shellcode an attacker leaves behind |

All three are **detection-only**. Nothing here ever executes attacker input,
fetches a URL by default, or runs a shell — a scripted/Lua persona *emulates* a
vulnerable service, and a YARA rule *labels* bytes; neither runs them.

---

## 1. YAML — declare, define, and decide

YAML is the backbone. It does three quite different jobs.

### a) The deployment itself (`config.yaml`)

Listeners, the sensor block, honeynets, archeservice role bundles, TLS posture,
sinks, egress, retention — the whole shape of the decoy estate. Crucially, this
is where you pick **what each service pretends to be**:

- `handler:` — which protocol engine answers a port (`ssh`, `http`, `modbus`,
  `lua`, `scripted`, …).
- `archetype:` — the coherent *identity* (banners, SNMP, TLS, TTL, default
  service map) the fingerprint-bearing handlers all answer consistently with, so
  a scanner can't catch the box on an internal contradiction. See
  [`archetypes.md`](archetypes.md).
- `archeservices:` — declare a *role* (`webserver`, `adserver`, `dbserver`, …)
  and it expands into the right ports + handlers for the chosen archetype.

```yaml
listeners:
  - { id: ssh, proto: tcp, bind: 0.0.0.0:22, handler: ssh, mode: banner }
sensor:
  archetype: "debian 12"        # every handler now wears Debian 12's identity
```

Full reference: [`config.md`](config.md). Catalog of identities:
[`archetypes.md`](archetypes.md).

### b) Declarative services (`handler: scripted`)

When a fake service is just *"server says X; if the client sends Y, answer Z"* —
no branching logic, no state — you can define the whole thing in YAML with the
`scripted` handler: a greeting, ordered match/respond rules, optional stages,
and credential capture. No Lua, no Go. Reach for it for simple line protocols
and banner grabbers.

### c) Detection rules (`detection.rules_dir`)

"Detection-as-code": drop Sigma-inspired YAML rules in a directory and the
sensor matches them against **every event** it produces — adding tags / ATT&CK
chips and raising severity — with no recompile and a live `SIGHUP` reload. This
is how you encode site-specific logic ("a privileged login from outside the
engineering VLAN is critical") on top of the built-in detectors.

```yaml
- id: ot-plc-stop
  severity: critical
  tags: [custom:ics-plc-stop, attack.t0813]
  match:
    meta.intent|re: "(?i)(PLC STOP|halting the controller)"
```

Full reference + the shipped rule packs: [`detection-rules.md`](detection-rules.md).

---

## 2. Lua — dynamic service personas

When a decoy needs **logic** — parse a request, branch on the path, remember
state across an attacker's reconnects, return a believable per-source identity,
pace its replies — write it as a **Lua persona** (`handler: lua`). Each script
runs in a sandboxed, pure-Go Lua 5.1 VM, one fresh VM per connection.

**240 personas ship** under [`configs/scripts/`](../configs/scripts/) — exposed
enterprise apps, appliances, panels and ICS web UIs (phpMyAdmin, GitLab,
FortiOS, VMware, MOVEit, Hadoop YARN, Ignition, …), each of which captures the
credentials/paths an attacker sends and flags the product's signature CVE.

```yaml
listeners:
  - { id: phpmyadmin, proto: tcp, bind: 0.0.0.0:8080,
      handler: lua, script: configs/scripts/phpmyadmin.lua }
```

A persona gets a small, deterministic API — `conn:read/readline/write`,
`meta()`/`flag()`/`log()`, `personality()`, `host:get/set`, `rng`, `time`,
`sleep` — and **nothing dangerous**: no `io`/`os`/`require`, read/write/sleep
budgets, and a wall-clock deadline. Even a buggy persona can't be turned into
code execution on the sensor.

Full guide — API, the Lua-language cheat-sheet, limits, recipes:
[`lua.md`](lua.md).

**scripted vs lua:** use `scripted` (YAML) for static request/response; use
`lua` the moment you need a conditional, a counter, a captured value reflected
back, or a stable per-source persona.

---

## 3. YARA — classify captured artifacts

The first two formats shape the *conversation*. YARA is about the **files that
fall out of it**: a webshell uploaded over FTP, a dropper pasted into a fake
shell, base64 shellcode in a header, an ELF in a multipart POST. When payload
harvesting is on, the pure-Go YARA engine (`internal/artifactscan`) statically
analyses each extracted artifact and classifies it against a large built-in
pack (hundreds of rules — commodity malware, C2 frameworks, webshells, APT
implants, packers, and a deep IoT/OT focus) plus any rules you add.

```yaml
sensor:
  payloads:
    enabled: true
    analyze: true                                   # run the YARA engine
    yara_rules: /etc/tarpit-honeypot/enrichment/yara   # your extra .yar files
```

A match adds a `yara:<RuleName>` marker to the event, emits a `malware:capture`,
and (per the rule's `severity`) escalates — so your **detection rules** (§1c)
can then route on it, e.g. `anomaly|prefix: "yara:"`. That hand-off — YARA
labels the bytes, a YAML rule decides what to do about it — is the intended
composition.

Full guide — the rule subset, modules, severity, writing rules:
[`yara.md`](yara.md).

---

## Which one do I reach for?

| I want to… | Use |
|---|---|
| Stand up a decoy host / service and pin its identity | **YAML** config + `archetype` |
| Fake a simple line protocol (greeting + canned answers) | **YAML** `handler: scripted` |
| Fake an app with logic, state, or a per-source persona | **Lua** `handler: lua` |
| Alert / re-tag / raise severity on a pattern across events | **YAML** detection rules |
| Recognize the malware / webshell an attacker dropped | **YARA** artifact rules |
| Recognize an *exploit attempt in a request* | built-in CVE catalog (`internal/cve`) — not scripted; see [`attribution.md`](attribution.md) |

A real deployment uses all of them at once: YAML wires the listeners and pins a
Debian-12 archetype, a couple of Lua personas stand in for the exposed GitLab
and Fortigate, a directory of YAML detection rules raises severity on OT control
and honeytoken logins, and the YARA pack labels whatever gets uploaded.

## Validate everything before you ship it

| Format | Check |
|---|---|
| Config + detection rules | `tarpit-honeypot validate-config -c config.yaml` (loads the rules dir, fails on a bad rule) |
| Lua persona | `go test ./internal/luaengine/ -run TestShippedScriptsCompileAndRun`, or point a listener at it and probe with `curl`/`nc` |
| YARA rule | `tarpit-honeypot analyze --rules ./myrules sample.bin` |

Live-reload config + detection rules with `systemctl reload tarpit-honeypot`
(SIGHUP) — no restart, no dropped connections.

## See also

- [`config.md`](config.md) — the full configuration schema.
- [`lua.md`](lua.md) — Lua persona guide + language cheat-sheet.
- [`yara.md`](yara.md) — YARA artifact-rule guide + supported subset.
- [`detection-rules.md`](detection-rules.md) — detection-as-code reference.
- [`archetypes.md`](archetypes.md) — the OS / device identity catalog.
- [`attribution.md`](attribution.md) — CVE / CWE / ATT&CK mapping.

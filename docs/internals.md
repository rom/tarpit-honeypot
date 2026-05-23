# Internals — how a packet becomes an alert

This document traces the path data takes **inside** the sensor: where bytes
enter, how every module transforms them, and where they end up. It's the
map for anyone reading the source or extending a detection.

The design is a single fan-in pipeline. Many *producers* turn raw activity
into a uniform `*event.Event` and drop it on one in-memory **bus**; one
consumer goroutine runs every event through an ordered set of *enrichment +
detection* stages and then *dispatches* it to the configured *sinks*.
Everything is one process; the "modules" are Go packages under
[`internal/`](../internal/), not services.

```
 PRODUCERS (ingress)                      THE BUS            PIPELINE (one goroutine)            SINKS
 ─────────────────────                    ───────            ─────────────────────────          ─────
 listeners (TCP/UDP handlers) ┐                              1. enrich.Decorate                  stdout
 sniffer (AF_PACKET L2/L3)    │                              2. mitre.Lookup (ATT&CK tag)        jsonlog
 honeynet ARP/ICMP/LLDP/PNDCP │   ev *event.Event           3. first-seen                        sqlite ──► web UI
 TUN userspace TCP (tcpstack) ├──►  s.bus  ──► for ev := ─► 4. devices.Observe                   syslog/CEF/LEEF/OCSF
 file / URL / DNS canaries    │   (chan, buffered)          5. payload harvest                   webhook / discord
 device discovery (DHCP/bcast)│                              6. scananalysis.Observe              smtp / twilio / sns
 risk + operational events    ┘                             7. fuzzdos.Observe                   snmptrap / mqtt
                                                            8. correlate.Observe                      ▲
                                                            9. risk.Observe                           │
                                                           10. router.Dispatch ──► D3FEND + routing ──┘
                              side outputs:  captures/*.pcap · sessions/*.cast · payloads/* · devices.json · corr-state
```

The producers and the pipeline live in [`internal/sensor`](../internal/sensor);
`Sensor.Run` builds the bus consumer (the `for ev := range s.bus` loop) and
starts every producer.

---

## 1. The event (`internal/event`)

Every signal in the system is an `event.Event` (see
[`event.go`](../internal/event/event.go)). The fields downstream code keys
on:

| Field | Set by | Used by |
|---|---|---|
| `RuleID` | the producer (`listener:<id>`, `correlate:*`, `sniffer:*`, `honeynet:tcp_*`, `cve:<id>`, …) | ATT&CK lookup, routing, the UI |
| `Severity` | producer (low/medium/high/critical) | routing gates, risk weighting |
| `Source` / `Dest` (`Endpoint{IP,Port}`) | producer | correlators (keyed by source IP), enrichment, device learning |
| `Proto` / `Handler` | producer | handler-based ATT&CK lookup, correlators |
| `Meta map[string]any` | producer + every pipeline stage (enrichment writes geo/threat/mac; handlers write captured fields) | everything; the UI renders it |
| `Anomalies []string` | handlers (`flagAnomaly`) + fuzzdos | the protocol-violation correlator + per-marker ATT&CK augmentation |
| `MitreTechniques` / `Tactics` / `Defenses` | the pipeline (`mitre`) | sinks / SIEM pivots / the storyline correlator |
| `PayloadBase64` / `PayloadLen` | producer | payload harvest + scan-analysis (decoded once) |

A producer fills in what it knows and puts the pointer on `s.bus`
non-blockingly (`select { case s.bus <- ev: default: }` for the
high-volume producers, so a flood can never wedge the reader).

---

## 2. Producers — where events come from

| Producer | Package | What it ingests | Emits |
|---|---|---|---|
| **Listeners** | [`internal/listener`](../internal/listener) + [`/handler`](../internal/listener/handler) | a TCP/UDP connection to a bound port; the handler reads a bounded request, sends a believable reply, captures bytes | `listener:<id>` (+ handler anomalies, `cve:<id>`, `canary:url:*`) |
| **Sniffer** | [`internal/sniffer`](../internal/sniffer) | AF_PACKET frames (Linux): ARP, L2 tunnelling/BPDU, and L3/L4 stealth scans that never reach a socket — over IPv4 **and** IPv6 | `sniffer:*` |
| **Honeynet L2/L3** | [`internal/honeynet`](../internal/honeynet) | ARP / ICMP echo / LLDP-CDP / PROFINET-DCP for virtual host IPs | `honeynet:profinet_dcp_identify`, device-discovery feed |
| **TUN userspace TCP** | [`internal/tunnet`](../internal/tunnet) + [`internal/tcpstack`](../internal/tcpstack) | raw IP packets off a TUN; completes fingerprint-shaped handshakes, answers one request/response, captures malformed packets ([`tcp-stack.md`](tcp-stack.md)) | `honeynet:tcp_connect` / `tcp_request` / `tcp_malformed` / `tcp_land` |
| **Canaries** | [`internal/canary`](../internal/canary), [`internal/dnscanary`](../internal/dnscanary) | filesystem watches (fsnotify/fanotify), HTTP URL hits, DNS names | `canary:*`, `dnscanary:*` |
| **Device discovery** | [`internal/devices`](../internal/devices) (fed from DHCP/broadcast handlers + the sniffer) | passive host observations | `device:new`, `device:changed` |
| **Risk + lifecycle** | [`internal/sensor`](../internal/sensor) | the pipeline itself (scores) and process lifecycle/health | `risk:*`, `sensor:*` |

All of them converge on the single `s.bus` channel.

---

## 3. The pipeline — ordered stages

The consumer loop in `Sensor.Run` processes each event through these stages
**in this order** (the order matters: enrichment and ATT&CK tagging run
first so every later stage and the storyline correlator see the same
metadata). Each stage is wrapped so a panic on one event can't kill the
loop. Stages that *derive* new events dispatch them immediately and feed
them to the risk scorer.

1. **Enrichment** — `enrich.Decorate(ev)` ([`internal/enrich`](../internal/enrich)).
   Decorates `Meta` from the source IP: GeoIP city + ASN, reverse DNS,
   threat-intel list membership (`threat_intel_hit`), Tor-exit flag
   (`tor_exit`), net-class (`net_class`), and MAC-vendor (`mac_vendor`,
   for L2-learned hosts). Best-effort and hot-reloadable; private/loopback
   sources are skipped.
2. **ATT&CK tagging** — `mitre.Lookup(RuleID, Handler)`
   ([`internal/mitre`](../internal/mitre)) stamps `MitreTechniques` +
   `MitreTactics` (handler-refined for `listener:*`). D3FEND defenses are
   added later by the router. See [`attribution.md`](attribution.md).
3. **First-seen** — emits `source:first_seen` the first time a source
   crosses medium severity (opt-in, deduped).
4. **Device learning** — `devices.Observe` folds source/MAC/hostname +
   learned attributes (JA3/JA4, UA, os_guess from TTL) into the registry;
   emits `device:new` / `device:changed`.
5. **Payload harvest** — `payload` decodes the captured bytes (once) and
   extracts malware / shellcode / ingress URLs; persists artifacts to
   `payloads/` and emits `malware:capture`.
6. **Scan analysis** — `scananalysis.Observe`
   ([`internal/scananalysis`](../internal/scananalysis)) profiles a source's
   timing / scope / probe variety and emits `scananalysis:profile` (the
   nmap-template fingerprint) once confident.
7. **Fuzzing / DoS** — `fuzzdos.Observe` ([`internal/fuzzdos`](../internal/fuzzdos))
   scores payload structure + rate. It **stamps a `fuzzing-<technique>`
   anomaly onto `ev` in place** (so the correlator in the next stage
   inherits it) and emits `attack:fuzzing` / `attack:dos` on a campaign.
8. **Correlation** — `correlate.Observe(ev)`
   ([`internal/correlate`](../internal/correlate)) returns the original
   event plus any aggregates that fired (see §4). Derived aggregates are
   re-enriched before dispatch.
9. **Risk scoring** — `risk.Observe` ([`internal/risk`](../internal/risk))
   folds every dispatched event into a per-source decaying score and emits
   `risk:elevated|high|critical` on a threshold crossing.
10. **Routing** — `router.Dispatch` ([`internal/router`](../internal/router))
    stamps `MitreDefenses` (D3FEND), applies dedup + per-channel rate limit
    + severity/match routing + the outbound allowlist, and hands the event
    to each matching sink.

---

## 4. Detection modules in depth

The pipeline's "detection" is spread across cooperating packages, each with
a narrow job:

- **`internal/correlate`** — windowed, per-source aggregate detectors. Each
  keeps a small state map keyed by source IP (or credential / fingerprint),
  ages it out by a window, and emits a `correlate:*` event when a threshold
  is crossed. Families: scan/sweep (`port_scan`, `slow_scan`, `host_sweep`,
  `service_sweep`, `icmp_sweep`), credentials (`brute_force`,
  `password_spray`, `credential_reuse`, `geo_velocity`), web/recon
  (`path_enumeration`, `dns_enumeration`, `ua_rotation`, `exploit_chain`),
  C2/impact (`beacon`, `session_flood`, `exfil`,
  `amplification_probe`), enrichment-/campaign-driven (`threat_intel_burst`,
  `geo_velocity`, `default_cred_sweep`, `cve_campaign`), and the
  cross-protocol **`storyline`** correlator that fires `storyline:multi_stage`
  when one source touches 3+ kill-chain tactics. Adding one is a fixed recipe:
  config struct → `load.go` defaults → state map + severity field +
  `Observe` wiring + `gc` entry + `mitre` tag + test.
- **`internal/scananalysis`** — reconstructs an nmap scan profile (timing
  template, `-A`/`-O`/`-sV`, NSE/service-probe signatures, connect vs
  stealth) per source.
- **`internal/fuzzdos`** — classifies abusive traffic into fuzzing
  (entropy / format-string / null-flood / oversize) vs DoS types
  (slowloris, connection-flood, app-flood, volumetric, malformed-flood).
- **`internal/payload`** — signature + heuristic extraction of dropped
  binaries / shellcode / ingress URLs from captured bytes.
- **`internal/devices`** — the learned-device registry + MAC-OUI lookup +
  passive TTL OS-guess; the source of `device:*`.
- **`internal/mitre`** — the static rule/handler/anomaly → ATT&CK + D3FEND
  tables; also drives `list-techniques` and the storyline tactic ordering.
- **`internal/risk`** — the per-source decaying threat score.
- **`internal/cve`** — the CVE catalog; handlers call `MatchPayload` to turn
  an exploit signature in a request into a `cve:<id>` event.

Handlers themselves are the *first* line of detection: they parse a request
and call `flagAnomaly(&res, marker)`; the listener promotes those markers to
`ev.Anomalies`, where `mitre.Augment` unions each marker's technique onto
the event and the `protocol_violation` correlator counts distinct markers.

---

## 5. Sinks, persistence, and the UI

`router.Dispatch` writes each event to the matching **sinks**
([`internal/sink`](../internal/sink)): local sinks (`stdout`, `jsonlog`,
`sqlite`) always receive (so the on-disk record stays complete even for
allowlisted sources), while outbound sinks (`syslog`/CEF/LEEF/OCSF,
`webhook`, `discord`, `smtp`, `twilio`, `sns`, `snmptrap`, `mqtt`) are gated
by the allowlist + rate limit + min-severity. Each sink has a bounded retry
queue.

Side outputs are written outside the bus, by the producers:
- **`sqlite`** ([`internal/store`](../internal/store)) — the queryable event
  index that powers `list-events` and the **web UI** ([`internal/ui`](../internal/ui),
  read-only, reads the store + live snapshots).
- **captures/** — per-connection pcap (synthesized, no raw sockets).
- **sessions/** — asciinema casts of interactive shell sessions
  ([`internal/sessionrec`](../internal/sessionrec)).
- **payloads/** — harvested artifacts.
- **devices.json / correlator state** — periodically flushed so a restart
  doesn't lose the learned baseline or a 24h slow-scan window.

---

## 6. Concurrency & hot reload

- **One reader.** All detection state (correlator maps, risk, devices,
  scananalysis, fuzzdos) is mutated by the single bus-consumer goroutine,
  so most of it needs no locking; the few structures a second goroutine
  touches (devices registry saves, correlator GC) take a mutex.
- **Producers are concurrent** — each listener / responder runs its own
  goroutines and only interacts with the rest of the system by sending on
  `s.bus`.
- **Hot reload (`SIGHUP`)** swaps the router, correlator, enricher, sinks,
  routes, allowlist, dedup window and canary lists atomically; the consumer
  snapshots `curRouter()` / `curCorrelator()` / `curEnricher()` once per
  event so a reload mid-event can't tear state. Listeners are
  added/removed/restarted individually. A `sensor:reload` event records the
  diff.
- **Panic isolation** — every handler goroutine and the bus loop body run
  under a recover wrapper, so a parser bug on one connection or event is
  logged and contained, never fatal.

---

## 7. Package map

| Concern | Packages |
|---|---|
| Ingress | `listener`, `listener/handler`, `sniffer`, `honeynet`, `tunnet`, `tcpstack`, `canary`, `dnscanary` |
| Event model + bus | `event`, `sensor` |
| Enrichment | `enrich` (+ `devices` OUI) |
| Detection | `correlate`, `scananalysis`, `fuzzdos`, `payload`, `devices`, `cve`, `risk`, `mitre`, `toolfp`, `fingerprint` |
| Identity / deception | `identity`, `archetype`, `archeservice`, `shell`, `luaengine`, `fakefiles`, `sessionrec` |
| Output | `router`, `sink`, `store`, `format`, `ui` |
| Safety / lifecycle | `safe`, `safego`, `sandbox`, `privdrop`, `retention`, `config` |

See [`design.md`](design.md) for the *why* (architecture rationale and
delivered phases); this document is the *how* (runtime data flow).

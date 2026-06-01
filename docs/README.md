# Documentation

This directory has these reference documents:

| File | When to read |
|---|---|
| [`FAQ.md`](FAQ.md) | First, for quick answers. Common questions grouped by topic: general, deployment & safety, detection & events, fleet & aggregation, IOCs & threat intel, performance, operations. |
| [`usage.md`](usage.md) | First. Quickstart, daily ops, honeynet patterns, archetypes, interactive engagement, ATT&CK / storyline / anomaly, the fleet roles, web UI, systemd, launchd (macOS), Docker, platform support, troubleshooting. |
| [`webui.md`](webui.md) | A walkthrough of the read-only web console: every tab, the JSON API, and the cross-cutting concepts (the event model, ATT&CK/D3FEND attribution, the fleet view, the IOC view). Also rendered in-product under the **docs** tab. |
| [`design.md`](design.md) | The architecture + design rationale covering the current implementation: deception + detection layers, event pipeline, persistence, self-confinement, delivered phases, open risks. |
| [`internals.md`](internals.md) | How a packet becomes an alert: the runtime data flow — producers → the event bus → the ordered enrichment + detection pipeline → sinks → fleet/IOC layers — and what each module does. Read with the source. |
| [`tcp-stack.md`](tcp-stack.md) | The honeynet userspace TCP stack (`internal/tcpstack`): fingerprint-shaped SYN-ACK, the decoy connection state machine, malformed/illegal-packet capture, per-host config, and the ATT&CK / TCP-stack-CVE mappings. |
| [`config.md`](config.md) | When writing or auditing a YAML config. Section-by-section reference with defaults and rationale (includes the fleet / forward / ingest / intel-feed / IOC blocks). |
| [`cli.md`](cli.md) | When invoking the binary directly — every subcommand, every flag, every signal, every help topic. |
| [`fleet.md`](fleet.md) | Building a fleet of sensors: roles (sensor / forwarder / aggregator / correlator / intel source+subscriber), topologies, the 27 cross-sensor `fleet:*` detectors, broad-vs-targeted scoping, tuning, downward intel feedback, and troubleshooting. |
| [`ioc.md`](ioc.md) | The indicators-of-compromise layer: what becomes an IOC, the de-duplicated store, the `ioc:<type>` events (local + forwarded), the `iocs` UI tab, and the `export-iocs` CLI. |
| [`threat-intel-exports.md`](threat-intel-exports.md) | Every way intel leaves the box: STIX 2.1 / TAXII 2.1 / MISP, the downward fleet-intel feed, and the CEF/LEEF/OCSF SIEM event sinks, with field mappings and the auth model. |
| [`archetypes.md`](archetypes.md) | The full catalog of all 99 OS/device archetypes: each one's services/protocols, identity (banners, SNMP OID), and the CVEs it emulates. How vulnerability emulation works. |
| [`attribution.md`](attribution.md) | In depth: the ATT&CK / D3FEND / CVE / CWE / CPE / EPSS mappings stamped on every event, plus the scanner-detection layers and the client classifiers (tool/automation fingerprinting, JA3/JA4/JA4S/JA4T/JA3S/HASSH/JA4H). |
| [`hardening.md`](hardening.md) | The layered self-confinement model — privilege drop, seccomp, Landlock, AppArmor, SELinux, systemd. |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | When wiring the sensor into SIEMs, IoT pipelines, pagers, K8s, launchd, ATT&CK pivots. Channel-by-channel cookbook + protocol handler catalog. |
| [`testharness.md`](testharness.md) | The `tarpit-testharness` QA/reliability harness that exercises the sensor — network (managed/external) or in-process module backends; unit/fuzz/emulate/misimpl/scan/fingerprint categories; selection, retries+restart, rounds/time bounds, reports, and the results database. |
| [`tarpit-honeypot.1`](tarpit-honeypot.1) | Man page. Render with `man ./docs/tarpit-honeypot.1`; install to `/usr/share/man/man1/`. |

Every `.md` here is also rendered **in-product** under the web UI's **docs** tab
(`/docs/<name>`), so an operator can read the full documentation from the console.

The annotated example config at [`../configs/tarpit-honeypot.example.yaml`](../configs/tarpit-honeypot.example.yaml) is the canonical source of truth for default values, and [`../examples/fleet/`](../examples/fleet/) is a worked multi-tier fleet topology. The top-level [`../README.md`](../README.md) is the project overview, including platform support matrix and per-version status block.

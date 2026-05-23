# Documentation

This directory has these reference documents:

| File | When to read |
|---|---|
| [`design.md`](design.md) | The architecture + design rationale covering the current implementation: deception + detection layers, event pipeline, persistence, self-confinement, delivered phases, open risks. |
| [`tcp-stack.md`](tcp-stack.md) | The honeynet userspace TCP stack (`internal/tcpstack`): fingerprint-shaped SYN-ACK, the decoy connection state machine, malformed/illegal-packet capture, per-host config, and the ATT&CK / TCP-stack-CVE mappings. |
| [`usage.md`](usage.md) | First. Quickstart, daily ops, honeynet patterns, archetypes, interactive engagement, ATT&CK / storyline / anomaly, web UI, systemd, launchd (macOS), Docker, platform support, troubleshooting. |
| [`config.md`](config.md) | When writing or auditing a YAML config. Section-by-section reference with defaults and rationale. |
| [`cli.md`](cli.md) | When invoking the binary directly — every subcommand, every flag, every signal, every help topic. |
| [`archetypes.md`](archetypes.md) | The full catalog of all 99 OS/device archetypes: each one's services/protocols, identity (banners, SNMP OID), and the CVEs it emulates. How vulnerability emulation works. |
| [`attribution.md`](attribution.md) | In depth: the ATT&CK / D3FEND / CVE / CWE / CPE / EPSS mappings stamped on every event, plus the scanner-detection layers and the client classifiers (tool/automation fingerprinting, JA3/JA4/JA3S/HASSH/JA4H). |
| [`hardening.md`](hardening.md) | The layered self-confinement model — privilege drop, seccomp, Landlock, AppArmor, SELinux, systemd. |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | When wiring the sensor into SIEMs, IoT pipelines, pagers, K8s, launchd, ATT&CK pivots. Channel-by-channel cookbook + protocol handler catalog. |
| [`tarpit-honeypot.1`](tarpit-honeypot.1) | Man page. Render with `man ./docs/tarpit-honeypot.1`; install to `/usr/share/man/man1/`. |

The annotated example config at [`../configs/tarpit-honeypot.example.yaml`](../configs/tarpit-honeypot.example.yaml) is the canonical source of truth for default values. The top-level [`../README.md`](../README.md) is the project overview, including platform support matrix and per-version status block.

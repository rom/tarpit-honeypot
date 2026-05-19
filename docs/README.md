# Documentation

This directory has four reference documents:

| File | When to read |
|---|---|
| [`usage.md`](usage.md) | First. Quickstart, daily ops, honeynet patterns, archetypes, interactive engagement, ATT&CK / storyline / anomaly, web UI, systemd, launchd (macOS), Docker, platform support, troubleshooting. |
| [`config.md`](config.md) | When writing or auditing a YAML config. Section-by-section reference with defaults and rationale. |
| [`cli.md`](cli.md) | When invoking the binary directly — every subcommand, every flag, every signal, every help topic. |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | When wiring the sensor into SIEMs, IoT pipelines, pagers, K8s, launchd, ATT&CK pivots. Channel-by-channel cookbook + protocol handler catalog. |

The annotated example config at [`../configs/tarpit-honeypot.example.yaml`](../configs/tarpit-honeypot.example.yaml) is the canonical source of truth for default values. The top-level [`../README.md`](../README.md) is the project overview, including platform support matrix and per-version status block.

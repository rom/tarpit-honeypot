# Operator detection rules (detection-as-code)

The built-in detectors (handler anomaly markers, the CVE catalog, the
correlator, ATT&CK tagging) are compiled in. **Detection rules** let an
operator add their own match logic in YAML — no recompile — matched against
*every* event the sensor produces.

```yaml
# /etc/tarpit-honeypot/config.yaml
detection:
  rules_dir: /etc/tarpit-honeypot/rules
```

Every `*.yml` / `*.yaml` file in that directory is loaded at start and re-read
on `SIGHUP`. `validate-config` loads them too and fails on a malformed rule
(bad regex, unknown modifier, missing `id`), so you catch mistakes before
deploy.

## What a match does

When a rule matches, the sensor — *in place, before correlation, risk scoring,
routing and forwarding see the event* —

- adds each of the rule's `tags` to the event as **anomaly markers** (so they
  appear in `/search?tag=…`, the attack tables, the profile dossier, and every
  export: JSON / CEF / LEEF / OCSF; an `attack.tXXXX` tag also lights up as an
  ATT&CK chip),
- adds a `detect:<id>` marker and records the id under `meta.detect_rules`,
- **raises** the event severity to the rule's `severity` (it never lowers it).

It never executes anything — this is declarative matching only (the sandboxed
`lua` response handler remains the only scripting surface).

## Rule format

```yaml
- id: my-rule                 # required, unique
  title: Human-readable title
  description: optional
  severity: high              # optional; only ever raises the severity
  tags: [custom:foo, attack.t1190]   # added as anomaly markers on a match
  match:                      # every key is ANDed; a list value is ORed
    handler: [http, https]
    meta.user_agent|contains: "${jndi:"
    dest_port|gt: "1024"
    anomaly: webshell
```

### Fields

| Field | Resolves to |
|---|---|
| `handler` | the protocol handler (`ssh`, `http`, `redis`, …) |
| `rule_id` | the event's rule id (`listener:…`, `cve:…`, `correlate:…`) |
| `proto` | `tcp` / `udp` / `icmp` / … |
| `severity` | `low` / `medium` / `high` / `critical` |
| `source_ip`, `dest_ip`, `dest_port` | endpoints |
| `banner` | the banner the decoy sent |
| `anomaly` | matches if the value is one of the event's anomaly markers |
| `mitre` / `tactic` | ATT&CK techniques / tactics on the event |
| `meta.<dotted.path>` | walks the event `meta` map (e.g. `meta.user_attempt`, `meta.http.headers.host`) |

### Modifiers (`field|modifier`)

`contains`, `prefix`, `suffix`, `re` (RE2 regex), `gt` / `lt` (numeric),
`exists`. No modifier = case-insensitive equals. A list value matches if **any**
element matches; multiple `match` keys must **all** hold.

See [`configs/rules/example.yml`](../configs/rules/example.yml) for a starter set.

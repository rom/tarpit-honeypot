package ui

const tmpls = `
{{ define "head" }}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
{{ if gt (refreshSeconds) 0 }}<meta http-equiv="refresh" content="{{ refreshSeconds }}">{{ end }}
<title>tarpit-honeypot</title>
<style>
body { font: 14px/1.45 ui-monospace, "SF Mono", Menlo, Consolas, monospace; margin: 1.5rem; color: #111; background: #fafafa; }
h1 { font-size: 1.3rem; margin: 0 0 1rem; }
h2 { font-size: 1.05rem; margin: 1.5rem 0 .5rem; color: #444; }
nav { margin-bottom: 1rem; }
nav a { margin-right: 1rem; }
table { border-collapse: collapse; width: 100%; background: #fff; }
th, td { padding: .35rem .55rem; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
th { font-weight: 600; background: #f3f3f3; }
td.sev-low { color: #555; }
td.sev-medium { color: #b36b00; }
td.sev-high { color: #b00020; font-weight: 600; }
td.sev-critical { color: #b00020; font-weight: 700; background: #fff5f5; }
form { display: inline-block; }
input[type=text], input[type=number] { font: inherit; padding: .15rem .3rem; }
.kv { background: #fff; padding: .75rem; border: 1px solid #eee; white-space: pre-wrap; word-break: break-all; }
.note { color: #666; font-size: 12px; margin-top: .5rem; }
.net { background: #fff; border: 1px solid #e3e3e3; border-radius: 4px; padding: .6rem .8rem; margin: .6rem 0; }
.net h3 { margin: 0 0 .35rem; font-size: 1rem; }
.net .meta { color: #666; font-size: 12px; margin-bottom: .4rem; }
.host { border-left: 3px solid #ccd; padding: .15rem 0 .15rem .6rem; margin: .35rem 0; }
.host .hostline { font-weight: 600; }
.host .os { color: #777; font-weight: 400; }
.svc { display: inline-block; background: #f0f3f8; border: 1px solid #dde3ec; border-radius: 3px; padding: 0 .35rem; margin: .1rem .25rem .1rem 0; font-size: 12px; }
.docs h2 { border-bottom: 1px solid #eee; padding-bottom: .2rem; }
.docs code { background: #f0f0f0; padding: 0 .25rem; border-radius: 3px; }
.docs ul { margin: .3rem 0 .8rem 1.2rem; padding: 0; }
.docs li { margin: .12rem 0; }
.depl { background: #fff; border: 1px solid #e3e3e3; border-radius: 4px; padding: .5rem .8rem; display: inline-block; }
.threat-low { color: #555; }
.threat-elevated { color: #b36b00; font-weight: 600; }
.threat-high { color: #b00020; font-weight: 600; }
.threat-critical { color: #b00020; font-weight: 700; background: #fff5f5; }
.tag { display: inline-block; background: #eef; border: 1px solid #cce; border-radius: 3px; padding: 0 .35rem; margin: .1rem .2rem .1rem 0; font-size: 12px; }
.tag.warn { background: #fff0e6; border-color: #f0c8a0; }
.tag.bad { background: #ffe9ec; border-color: #f0a8b4; }
table.chart { width: 100%; background: transparent; }
table.chart td { border: none; padding: .12rem .4rem; }
td.blabel { width: 32%; max-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
td.bcell { width: 58%; }
td.bnum { width: 10%; text-align: right; color: #555; }
.bar { display: inline-block; height: .8rem; background: #6b8fb5; border-radius: 2px; min-width: 2px; }
.bar.sev-medium { background: #d59a3a; }
.bar.sev-high { background: #c0506a; }
.bar.sev-critical { background: #b00020; }
.spark { display: flex; align-items: flex-end; gap: 1px; height: 80px; background: #fff; border: 1px solid #eee; padding: 4px; }
.sparkbar { flex: 1 1 0; background: #6b8fb5; min-height: 1px; }
</style>
</head><body>
<nav><a href="/">summary</a> · <a href="/events">events</a> · <a href="/profiles">profiles</a> · <a href="/devices">devices</a> · <a href="/topology">topology</a> · <a href="/alerting">alerting</a> · <a href="/errors">errors</a> · <a href="/config">config</a> · <a href="/docs">docs</a></nav>
{{ end }}

{{ define "foot" }}<p class="note">read-only view · {{ if gt (refreshSeconds) 0 }}auto-refreshes every {{ refreshSeconds }}s{{ else }}refresh for latest{{ end }}</p></body></html>{{ end }}

{{ define "bars" }}<table class="chart">
{{ range . }}<tr>
  <td class="blabel">{{ if .Href }}<a href="{{ .Href }}">{{ .Label }}</a>{{ else }}{{ .Label }}{{ end }}</td>
  <td class="bcell"><span class="bar {{ .Class }}" style="width:{{ .Pct }}%">&nbsp;</span></td>
  <td class="bnum">{{ .Count }}</td>
</tr>{{ end }}
</table>{{ end }}

{{ define "index" }}{{ template "head" . }}
<h1>tarpit-honeypot — last 24 hours</h1>
<p>{{ .Sum.Total }} events since {{ fmtTime .Sum.Since }}</p>

<h2>events per hour</h2>
{{ if .Trend }}<div class="spark">{{ range .Trend }}<span class="sparkbar" style="height:{{ .Pct }}%" title="{{ .Label }}: {{ .Count }}">&nbsp;</span>{{ end }}</div>
<p class="note">last 24h, one bar per hour</p>{{ else }}<p class="note">no events yet</p>{{ end }}

<h2>by severity</h2>
{{ if .Severity }}{{ template "bars" .Severity }}{{ else }}<p class="note">none</p>{{ end }}

<h2>top rules</h2>
{{ if .Rules }}{{ template "bars" .Rules }}{{ else }}<p class="note">none</p>{{ end }}

<h2>top sources</h2>
{{ if .Sources }}{{ template "bars" .Sources }}{{ else }}<p class="note">none</p>{{ end }}
<p class="note">Source IPs link to their <a href="/profiles">attacker profile</a>.</p>
{{ template "foot" . }}{{ end }}

{{ define "events" }}{{ template "head" . }}
<h1>events</h1>
<form method="get" action="/events">
  source: <input type="text" name="source" value="{{ .Filter.SourceIP }}" size="15">
  rule: <input type="text" name="rule" value="{{ .Filter.RuleID }}" size="20">
  severity: <input type="text" name="severity" value="{{ .SeverityStr }}" placeholder="low" size="8">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="24h" size="6">
  limit: <input type="number" name="limit" value="{{ .Filter.Limit }}" min="1" max="1000" size="5">
  <br>search: <input type="text" name="q" value="{{ .QStr }}" placeholder="full-text: rule / banner / captured meta" size="40">
  <button type="submit">filter</button>
  <a href="/events">reset</a>
</form>
<p class="note">Click a column header to sort; click again to reverse.</p>
<p class="note">Download recorded artifacts for this filter (ZIP):
  <a href="/download?source={{ .Filter.SourceIP }}&amp;rule={{ .Filter.RuleID }}&amp;since={{ .SinceStr }}&amp;what=all">pcaps + sessions</a> ·
  <a href="/download?source={{ .Filter.SourceIP }}&amp;rule={{ .Filter.RuleID }}&amp;since={{ .SinceStr }}&amp;what=pcap">pcaps</a> ·
  <a href="/download?source={{ .Filter.SourceIP }}&amp;rule={{ .Filter.RuleID }}&amp;since={{ .SinceStr }}&amp;what=session">sessions</a>
</p>
<table>
  <tr>
    <th><a href="{{ .Headers.time.Href }}">time (utc){{ .Headers.time.Arrow }}</a></th>
    <th><a href="{{ .Headers.severity.Href }}">severity{{ .Headers.severity.Arrow }}</a></th>
    <th><a href="{{ .Headers.rule.Href }}">rule{{ .Headers.rule.Arrow }}</a></th>
    <th><a href="{{ .Headers.source.Href }}">source{{ .Headers.source.Arrow }}</a></th>
    <th>dest</th>
    <th><a href="{{ .Headers.handler.Href }}">handler{{ .Headers.handler.Arrow }}</a></th>
    <th></th>
  </tr>
  {{ range .Events }}
  <tr>
    <td>{{ fmtTime .Time }}</td>
    <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
    <td>{{ .RuleID }}</td>
    <td>{{ .Source.IP }}{{ if .Source.Port }}:{{ .Source.Port }}{{ end }}</td>
    <td>{{ .Dest.IP }}{{ if .Dest.Port }}:{{ .Dest.Port }}{{ end }}</td>
    <td>{{ .Handler }}</td>
    <td><a href="/events/{{ .ID }}">details</a></td>
  </tr>
  {{ end }}
</table>
{{ template "foot" . }}{{ end }}

{{ define "event" }}{{ template "head" . }}
<h1>event {{ .ID }}</h1>
<table>
  <tr><th>time</th><td>{{ fmtTime .Time }}</td></tr>
  <tr><th>sensor</th><td>{{ .Sensor }}</td></tr>
  <tr><th>rule_id</th><td>{{ .RuleID }}</td></tr>
  <tr><th>severity</th><td class="sev-{{ .Severity }}">{{ .Severity }}</td></tr>
  <tr><th>source</th><td>{{ .Source.IP }}:{{ .Source.Port }}</td></tr>
  <tr><th>dest</th><td>{{ .Dest.IP }}:{{ .Dest.Port }}</td></tr>
  <tr><th>proto</th><td>{{ .Proto }}</td></tr>
  <tr><th>handler</th><td>{{ .Handler }}</td></tr>
</table>

<h2>downloads</h2>
<ul>
  <li><a href="/pcap/{{ .ID }}">pcap</a> (per-connection capture, if recorded)</li>
  {{ if index .Meta "session_cast" }}<li><a href="/session/{{ .ID }}">session recording</a> (asciinema cast)</li>{{ end }}
  {{ if .Source.IP }}<li><a href="/download?source={{ .Source.IP }}&amp;since=720h">all pcaps + sessions from {{ .Source.IP }}</a> (ZIP, last 30d)</li>{{ end }}
</ul>

{{ if .BannerSent }}<h2>banner sent</h2><div class="kv">{{ .BannerSent }}</div>{{ end }}
{{ if .PayloadBase64 }}<h2>payload ({{ .PayloadLen }} bytes)</h2>
{{ $hex := hexdump .PayloadBase64 }}{{ if $hex }}<div class="kv">{{ $hex }}</div>{{ else }}<div class="kv">{{ .PayloadBase64 }}</div>{{ end }}
<details><summary class="note">base64</summary><div class="kv">{{ .PayloadBase64 }}</div></details>{{ end }}
{{ if .Meta }}<h2>meta</h2><table>
{{ range $k, $v := .Meta }}<tr><th>{{ $k }}</th><td>{{ $v }}</td></tr>{{ end }}
</table>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "profiles" }}{{ template "head" . }}
<h1>attacker profiles</h1>
<p class="note">One dossier per source IP, compiled from behaviour, tool / scanner
fingerprinting, credentials tried, and ATT&amp;CK technique observation — it builds up
as the source keeps interacting. Ranked by a severity-weighted threat score. JSON at
<a href="/api/profiles">/api/profiles</a>.</p>
<form method="get" action="/profiles">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="720h" size="6">
  <button type="submit">filter</button>
  <a href="/profiles">reset</a>
</form>
{{ if not .Profiles }}
<p class="note">No sources observed in the window.</p>
{{ else }}
<table>
  <tr><th>source ip</th><th>threat</th><th>max severity</th><th>events</th><th>distinct rules</th><th>first seen</th><th>last seen</th></tr>
  {{ range .Profiles }}
  <tr>
    <td><a href="/profiles/{{ .IP }}">{{ .IP }}</a></td>
    <td>{{ .Weight }}</td>
    <td class="sev-{{ .MaxSeverity }}">{{ .MaxSeverity }}</td>
    <td>{{ .Count }}</td>
    <td>{{ .DistinctRules }}</td>
    <td>{{ fmtTime .FirstSeen }}</td>
    <td>{{ fmtTime .LastSeen }}</td>
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "profile" }}{{ template "head" . }}
<h1>attacker profile — {{ .IP }}</h1>
<div class="depl">
  threat: <span class="threat-{{ .ThreatLevel }}">{{ .ThreatLevel }} ({{ .ThreatScore }})</span> ·
  max severity: <span class="sev-{{ .MaxSeverity }}">{{ .MaxSeverity }}</span> ·
  {{ .Count }} event(s){{ if .Partial }}+{{ end }} ·
  {{ if .Automation }}automation{{ else }}unflagged{{ end }}
</div>
<p class="note">first seen {{ fmtTime .FirstSeen }} · last seen {{ fmtTime .LastSeen }} ·
  <a href="/events?source={{ .IP }}&amp;since=2160h">all events</a> ·
  <a href="/download?source={{ .IP }}&amp;since=2160h&amp;what=all">artifacts (ZIP)</a> ·
  <a href="/api/profiles/{{ .IP }}">JSON</a></p>

<h2>events by severity</h2>
<table><tr><th>severity</th><th>count</th></tr>
{{ range $k, $v := .BySeverity }}<tr><td class="sev-{{ $k }}">{{ $k }}</td><td>{{ $v }}</td></tr>{{ end }}
</table>

{{ if .Tools }}<h2>tools / scanners</h2><div>{{ range .Tools }}<span class="tag bad">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .Fingerprints }}<h2>fingerprints</h2><table>
{{ range $k, $v := .Fingerprints }}<tr><th>{{ $k }}</th><td>{{ $v }}</td></tr>{{ end }}
</table>{{ end }}

{{ if .Handlers }}<h2>services targeted</h2><div>{{ range .Handlers }}<span class="tag">{{ . }}</span>{{ end }}</div>
{{ if .Ports }}<p class="note">ports: {{ join .Ports }}</p>{{ end }}{{ end }}

{{ if .Mitre }}<h2>ATT&amp;CK techniques</h2><div>{{ range .Mitre }}<span class="tag warn">{{ . }}</span>{{ end }}</div>{{ end }}
{{ if .Tactics }}<h2>ATT&amp;CK tactics</h2><div>{{ range .Tactics }}<span class="tag warn">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .CVEs }}<h2>CVE exploit attempts</h2><div>{{ range .CVEs }}<span class="tag bad">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .Anomalies }}<h2>anomalies</h2><div>{{ range .Anomalies }}<span class="tag warn">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .Credentials }}<h2>credentials tried</h2><table><tr><th>username</th><th>password</th></tr>
{{ range .Credentials }}<tr><td>{{ .User }}</td><td>{{ .Pass }}</td></tr>{{ end }}
</table>{{ end }}

{{ if .Rules }}<h2>triggered rules</h2><table><tr><th>rule</th><th>count</th></tr>
{{ range .Rules }}<tr><td><a href="/events?source={{ $.IP }}&amp;rule={{ .Name }}">{{ .Name }}</a></td><td>{{ .Count }}</td></tr>{{ end }}
</table>{{ end }}

{{ if .Sensors }}<p class="note">seen by sensor(s): {{ range .Sensors }}{{ . }} {{ end }}</p>{{ end }}

<h2>recent events</h2>
<table><tr><th>time (utc)</th><th>severity</th><th>rule</th><th>handler</th><th></th></tr>
{{ range .Recent }}<tr>
  <td>{{ fmtTime .Time }}</td>
  <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
  <td>{{ .RuleID }}</td>
  <td>{{ .Handler }}</td>
  <td><a href="/events/{{ .ID }}">details</a></td>
</tr>{{ end }}
</table>
{{ template "foot" . }}{{ end }}

{{ define "config" }}{{ template "head" . }}
<h1>effective configuration</h1>
<p class="note">Post-defaults config the sensor is running with. Secrets are shown
as their environment-variable names (<code>*_env</code>), never expanded values,
so this is safe to copy into a ticket. Raw YAML also at <a href="/api/config">/api/config</a>.</p>
<div class="kv">{{ .YAML }}</div>
{{ template "foot" . }}{{ end }}

{{ define "topology" }}{{ template "head" . }}
<h1>honeynet topology</h1>
{{ if not .Networks }}
<p class="note">No honeynet configured. Add a <code>honeynets:</code> block (virtual
networks of hosts + services the sensor answers for) to populate this view.
JSON at <a href="/api/topology">/api/topology</a>.</p>
{{ else }}
<p class="note">Virtual networks the sensor presents. Each host answers on its own
IP/MAC with the listed services. JSON at <a href="/api/topology">/api/topology</a>.</p>
{{ range .Networks }}
<div class="net">
  <h3>{{ .ID }}{{ if .CIDR }} — {{ .CIDR }}{{ end }}</h3>
  <div class="meta">
    {{ if .Domain }}domain {{ .Domain }} · {{ end }}
    {{ if .Gateway }}gw {{ .Gateway }} · {{ end }}
    {{ if .DNS }}dns {{ .DNS }} · {{ end }}
    {{ len .Hosts }} host(s)
  </div>
  {{ range .Hosts }}
  <div class="host">
    <div class="hostline">{{ .IP }}{{ if .Hostname }} · {{ .Hostname }}{{ end }}
      {{ if .OS }}<span class="os">({{ .OS }})</span>{{ end }}
      {{ if .MAC }}<span class="os">{{ .MAC }}</span>{{ end }}
    </div>
    {{ range .Services }}<span class="svc">{{ .Port }}/{{ .Handler }}</span>{{ end }}
  </div>
  {{ end }}
</div>
{{ end }}
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "devices" }}{{ template "head" . }}
<h1>known / seen devices</h1>
{{ if not .Enabled }}<p class="note">Device tracking is disabled. Set
<code>devices.enabled: true</code> to learn devices from DHCP, the ARP sniffer,
broadcast/multicast discovery, and connection source IPs.</p>{{ end }}
{{ if .Notice }}<p class="depl">{{ .Notice }}</p>{{ end }}
<form method="get" action="/devices">
  filter: <input type="text" name="q" value="{{ .Query }}" placeholder="ip / mac / hostname / vendor / service" size="28">
  status: <select name="status">
    <option value=""{{ if eq .Status "" }} selected{{ end }}>all</option>
    <option value="seen"{{ if eq .Status "seen" }} selected{{ end }}>seen</option>
    <option value="allow"{{ if eq .Status "allow" }} selected{{ end }}>allow-listed</option>
  </select>
  <button type="submit">filter</button>
  <a href="/devices">reset</a>
</form>
{{ if not .Hosts }}
<p class="note">No devices learned yet. JSON at <a href="/api/devices">/api/devices</a>.</p>
{{ else }}
<p class="note">Devices the sensor has observed (IPv4 / IPv6 / MAC), with the
services/ports they touched and learned attributes — knowledge accrues over
time. "allow" = whitelisted (won't raise <code>device:new</code>).
{{ if .ActionsEnabled }} Write actions are <b>enabled</b>.{{ else }} Actions are read-only ( set <code>ui.allow_device_actions: true</code> + an auth token to manage devices here).{{ end }}
JSON at <a href="/api/devices">/api/devices</a>.</p>
<table>
  <tr><th>ip</th><th>mac</th><th>hostname</th><th>vendor</th><th>source</th><th>status</th><th>services</th><th>ports</th><th>attrs</th><th>last seen</th><th>count</th>{{ if .ActionsEnabled }}<th>actions</th>{{ end }}</tr>
  {{ range .Hosts }}
  <tr>
    <td>{{ if .IP }}<a href="/profiles/{{ .IP }}">{{ .IP }}</a>{{ end }}</td>
    <td>{{ .MAC }}</td>
    <td>{{ .Hostname }}</td>
    <td>{{ .Vendor }}</td>
    <td>{{ .Source }}</td>
    <td>{{ if .Allowed }}allow{{ else }}seen{{ end }}</td>
    <td>{{ range .Services }}<span class="tag">{{ . }}</span>{{ end }}</td>
    <td>{{ join .Ports }}</td>
    <td>{{ range $k, $v := .Attrs }}<span class="tag">{{ $k }}={{ $v }}</span>{{ end }}</td>
    <td>{{ fmtTime .LastSeen }}</td>
    <td>{{ .Count }}</td>
    {{ if $.ActionsEnabled }}<td>
      {{ if not .Allowed }}<form method="post" action="/devices/action"><input type="hidden" name="token" value="{{ $.Token }}"><input type="hidden" name="key" value="{{ .Key }}"><input type="hidden" name="action" value="allow"><button type="submit">whitelist</button></form>{{ end }}
      <form method="post" action="/devices/action"><input type="hidden" name="token" value="{{ $.Token }}"><input type="hidden" name="key" value="{{ .Key }}"><input type="hidden" name="action" value="delete"><button type="submit">delete</button></form>
    </td>{{ end }}
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "alerting" }}{{ template "head" . }}
<h1>alerting &amp; event forwarding</h1>
<p class="note">How this sensor forwards events. Secrets show as their
<code>*_env</code> names. JSON at <a href="/api/alerting">/api/alerting</a>.</p>
<div class="depl">
  syslog: {{ if .HasSyslog }}<b>configured</b>{{ else }}off{{ end }} ·
  email: {{ if .HasEmail }}<b>configured</b>{{ else }}off{{ end }} ·
  webhook: {{ if .HasWebhook }}<b>configured</b>{{ else }}off{{ end }} ·
  sms: {{ if .HasSMS }}<b>configured</b>{{ else }}off{{ end }} ·
  snmp-trap: {{ if .HasSNMP }}<b>configured</b>{{ else }}off{{ end }}
</div>

<h2>channels</h2>
<table>
  <tr><th>id</th><th>type</th><th>destination</th><th>format</th><th>min severity</th><th>rate/min</th><th>scope</th></tr>
  {{ range .Channels }}
  <tr>
    <td>{{ .ID }}</td>
    <td>{{ .Type }}</td>
    <td>{{ .Destination }}</td>
    <td>{{ .Format }}</td>
    <td>{{ .MinSeverity }}</td>
    <td>{{ if .RateLimit }}{{ .RateLimit }}{{ end }}</td>
    <td>{{ if .Local }}local (always){{ else }}outbound{{ end }}</td>
  </tr>
  {{ end }}
</table>

<h2>routes</h2>
{{ if not .Routes }}<p class="note">No routes configured — outbound channels receive per their own gates.</p>{{ else }}
<table>
  <tr><th>match</th><th>channels</th></tr>
  {{ range .Routes }}<tr><td>{{ .Match }}</td><td>{{ range .Channels }}{{ . }} {{ end }}</td></tr>{{ end }}
</table>
{{ end }}

{{ if .Allowlist }}<h2>allowlist (outbound-suppressed sources)</h2>
<div class="kv">{{ range .Allowlist }}{{ . }}
{{ end }}</div>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "errors" }}{{ template "head" . }}
<h1>operational errors &amp; health</h1>
<p class="note">Sensor-side problems (listener stopped, listener start error,
canary watcher stopped, accept-cap overflow, recovered panics) — separated
from attacker-interaction events. JSON for all events at <a href="/api/events">/api/events</a>.</p>
<form method="get" action="/errors">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="168h" size="6">
  <button type="submit">filter</button>
  <a href="/errors">reset</a>
</form>
{{ if not .Events }}
<p class="note">No operational errors in the window. The sensor is healthy.</p>
{{ else }}
<table>
  <tr><th>time (utc)</th><th>severity</th><th>rule</th><th>detail</th></tr>
  {{ range .Events }}
  <tr>
    <td>{{ fmtTime .Time }}</td>
    <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
    <td>{{ .RuleID }}</td>
    <td><a href="/events/{{ .ID }}">details</a></td>
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "docs" }}{{ template "head" . }}
<div class="docs">
<h1>tarpit-honeypot — documentation</h1>
<p>A deception + detection sensor: it presents believable services (banners,
protocol emulators, virtual hosts), wastes attacker time (tarpits), and turns
every interaction into a structured, ATT&amp;CK-tagged event for your SIEM. It is
built to be a <em>target</em> — the UI is read-only, binds loopback by default,
and the sensor never becomes a reflection/amplification primitive.</p>

<h2>this deployment</h2>
<p class="depl">
{{ .Listeners }} listener(s) · {{ .Networks }} honeynet network(s) · {{ .Hosts }} virtual host(s)<br>
device tracking: {{ if .DevicesOn }}on{{ else }}off{{ end }} · ui bind: <code>{{ .UIBind }}</code>
</p>

<h2>tabs</h2>
<ul>
<li><a href="/">summary</a> — 24h rollup by severity, rule, and source.</li>
<li><a href="/events">events</a> — filterable event log (source, rule, severity, time).</li>
<li><a href="/profiles">profiles</a> — per-source-IP attacker dossiers (threat score, tools/scanners, fingerprints, credentials tried, ATT&amp;CK, targeted services), compiled over time.</li>
<li><a href="/devices">devices</a> — learned / seen / whitelisted devices (IPv4 / IPv6 / MAC) with the services/ports they touched + learned attributes; optional delete/whitelist actions (<code>ui.allow_device_actions</code> + auth token).</li>
<li><a href="/topology">topology</a> — the virtual networks / hosts / services the sensor presents.</li>
<li><a href="/alerting">alerting</a> — how events are forwarded (syslog / email / webhook / SMS / SNMP).</li>
<li><a href="/errors">errors</a> — operational / health events (listener or canary-watcher stopped, accept-cap overflow).</li>
<li><a href="/config">config</a> — the effective running config (secrets shown as env-var names).</li>
</ul>

<h2>detection</h2>
<ul>
<li><b>Scan analysis</b> (<code>scananalysis:profile</code>) — per-source nmap fingerprinting:
timing template (<code>-T0</code>..<code>-T5</code>) from inter-connection cadence, aggressive
(<code>-A</code>) and OS-probe (<code>-O</code>) detection, service/version-probe matching
(<code>-sV</code>), NSE-script signatures, connect-scan detection, and scan-sequencing
heuristics. SYN/FIN/NULL/Xmas/ACK scans, raw fragmentation, and decoy floods
(<code>-D</code>) require the AF_PACKET sniffer and are flagged as needing packet capture.</li>
<li><b>Protocol anomalies</b> — per-handler markers (non-printable banners, smuggled
bytes, DNS tunneling/exfil shapes, abnormal ICMP payloads, UDP amplifier probes).</li>
<li><b>Device learning</b> — learns a baseline and raises <code>device:new</code> for
never-before-seen, non-allow-listed hosts (DHCP, ARP sniffer, broadcast/multicast).</li>
<li><b>Correlation / storyline</b> — port-scan, slow-scan, brute-force, and ICMP-sweep
correlation; events carry MITRE ATT&amp;CK techniques + tactics for kill-chain pivoting.</li>
</ul>

<h2>protocol handlers</h2>
<ul>
<li><b>Auth surface</b>: ssh, ssh_interactive, telnet, ftp, ftp_files, rdp, vnc, winrm,
smb, postgres, mysql, redis, ldap, kerberos, amqp, mqtt.</li>
<li><b>Web / apps</b>: http, https (per-service certs), rtsp, ipp, dockerapi, plus vendor
gateway emulators (fortinet, pulse, citrix, esxi, idrac/ilo/amt, moxa, ...).</li>
<li><b>ICS / OT</b>: modbus, s7, iec104, opcua, ethernetip, bacnet, fins, melsec, knx.</li>
<li><b>Discovery / UDP</b>: snmp, ssdp, llmnr, nbns, cldap, sip, coap, ntp, tftp, ipmi,
radius, syslog, dhcp.</li>
<li><b>DNS</b>: <code>dns</code> answers A/AAAA/MX/TXT/NS/CNAME with fabricated, deterministic-
per-deployment records so a resolver-enumeration sees a live, populated server —
every query is run through tunneling/exfil detection.</li>
<li><b>Small services</b> (RFC 862-868, 1340): echo, discard, daytime, qotd, chargen, time —
TCP + UDP. chargen/echo are reflector favorites, so replies are strictly bounded
(one capped response) and never amplify.</li>
</ul>

<h2>tarpit modes</h2>
<ul>
<li><code>mode: tarpit</code> with <code>strategy: sticky | trickle | keepalive</code> holds the
connection open to waste scanner/worm time.</li>
<li><code>tarpit.emulate: true</code> runs the listener's protocol <code>handler:</code> first
(real banner + captured request) and <em>then</em> tarpits the same connection — any
emulator becomes a tarpit, and the captured banner/request lands in the
<code>tarpit_start</code> event.</li>
</ul>

<h2>cli</h2>
<ul>
<li><code>tarpit-honeypot run -config tarpit-honeypot.yaml</code> — start the sensor.</li>
<li><code>tarpit-honeypot validate -config ...</code> — check the config without binding.</li>
<li><code>tarpit-honeypot list-devices</code> / <code>list-honeynets</code> — inspect learned devices / topology.</li>
<li><code>tarpit-honeypot version</code> — build version. <code>SIGHUP</code> hot-reloads config.</li>
</ul>

<h2>security model</h2>
<ul>
<li>UI is read-only by default and binds loopback unless you set both TLS and a static
auth token. The only optional write action is device delete/whitelist, gated behind
<code>ui.allow_device_actions</code> + an auth token (off by default).</li>
<li>Secrets live only as <code>*_env</code> references — never expanded in config output or logs.</li>
<li>All attacker-supplied bytes are bounds-checked and sanitized before logs / SIEM / email.</li>
<li>The sensor refuses to be a reflection/amplification primitive (bounded small-service
replies, NTP mode-7 silent, no unbounded DNS answers).</li>
</ul>
</div>
{{ template "foot" . }}{{ end }}
`

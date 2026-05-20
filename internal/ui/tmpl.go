package ui

const tmpls = `
{{ define "head" }}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
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
</style>
</head><body>
<nav><a href="/">summary</a> · <a href="/events">events</a> · <a href="/topology">topology</a> · <a href="/config">config</a> · <a href="/docs">docs</a></nav>
{{ end }}

{{ define "foot" }}<p class="note">read-only view · refresh for latest</p></body></html>{{ end }}

{{ define "index" }}{{ template "head" . }}
<h1>tarpit-honeypot — last 24 hours</h1>
<p>{{ .Total }} events since {{ fmtTime .Since }}</p>

<h2>by severity</h2>
<table><tr><th>severity</th><th>count</th></tr>
{{ range $k, $v := .BySeverity }}<tr><td>{{ $k }}</td><td>{{ $v }}</td></tr>{{ end }}
</table>

<h2>top rules</h2>
<table><tr><th>rule_id</th><th>count</th></tr>
{{ range $k, $v := .ByRule }}<tr><td><a href="/events?rule={{ $k }}">{{ $k }}</a></td><td>{{ $v }}</td></tr>{{ end }}
</table>

<h2>top sources</h2>
<table><tr><th>source ip</th><th>count</th></tr>
{{ range .TopSources }}<tr><td><a href="/events?source={{ .IP }}">{{ .IP }}</a></td><td>{{ .Count }}</td></tr>{{ end }}
</table>
{{ template "foot" . }}{{ end }}

{{ define "events" }}{{ template "head" . }}
<h1>events</h1>
<form method="get" action="/events">
  source: <input type="text" name="source" value="{{ .Filter.SourceIP }}" size="15">
  rule: <input type="text" name="rule" value="{{ .Filter.RuleID }}" size="25">
  since: <input type="text" name="since" placeholder="24h" size="6">
  limit: <input type="number" name="limit" value="{{ .Filter.Limit }}" min="1" max="1000" size="5">
  <button type="submit">filter</button>
  <a href="/events">reset</a>
</form>
<table>
  <tr><th>time (utc)</th><th>severity</th><th>rule</th><th>source</th><th>dest</th><th>handler</th><th></th></tr>
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

{{ if .BannerSent }}<h2>banner sent</h2><div class="kv">{{ .BannerSent }}</div>{{ end }}
{{ if .PayloadBase64 }}<h2>payload ({{ .PayloadLen }} bytes, base64)</h2><div class="kv">{{ .PayloadBase64 }}</div>{{ end }}
{{ if .Meta }}<h2>meta</h2><table>
{{ range $k, $v := .Meta }}<tr><th>{{ $k }}</th><td>{{ $v }}</td></tr>{{ end }}
</table>{{ end }}
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
<li><a href="/topology">topology</a> — the virtual networks / hosts / services the sensor presents.</li>
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
<li>UI is read-only (no delete/config/alert endpoints) and binds loopback unless you
set both TLS and a static auth token.</li>
<li>Secrets live only as <code>*_env</code> references — never expanded in config output or logs.</li>
<li>All attacker-supplied bytes are bounds-checked and sanitized before logs / SIEM / email.</li>
<li>The sensor refuses to be a reflection/amplification primitive (bounded small-service
replies, NTP mode-7 silent, no unbounded DNS answers).</li>
</ul>
</div>
{{ template "foot" . }}{{ end }}
`

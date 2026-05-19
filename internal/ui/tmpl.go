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
</style>
</head><body>
<nav><a href="/">summary</a> · <a href="/events">events</a></nav>
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
`

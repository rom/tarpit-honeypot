package ui

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestBuildProfileForensicObservables verifies the profile surfaces the
// captured artifacts, harvested URLs, requested domains/SNIs, and the
// honeytoken-reuse compromise signal — not just high-level counts.
func TestBuildProfileForensicObservables(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "malware:capture", Severity: event.SeverityHigh,
			Handler: "http", Source: event.Endpoint{IP: "7.7.7.7"}, Dest: event.Endpoint{Port: 80},
			Meta: map[string]any{
				"payload_artifacts": []any{"elf:deadbeef -> /tmp/x"},
				"harvested_urls":    []any{"http://evil.test/bot.sh"},
				"qname":             "c2.example.org", "sni": "vpn.corp",
				"ja4t": "64240_2-4",
			},
		},
		{
			ID: "2", Time: now.Add(time.Minute), RuleID: "canary:token_used", Severity: event.SeverityCritical,
			Handler: "vault", Source: event.Endpoint{IP: "7.7.7.7"},
			Meta: map[string]any{"reused_cred_key": "vault_token"},
		},
	}
	p := buildProfile("7.7.7.7", evs)

	if !p.TokenReuse {
		t.Error("expected TokenReuse=true after canary:token_used")
	}
	if p.Classification != "confirmed compromise — honeytoken reuse" {
		t.Errorf("classification = %q; want confirmed-compromise", p.Classification)
	}
	if !hasStr(p.Artifacts, "elf:deadbeef -> /tmp/x") {
		t.Errorf("artifacts missing: %v", p.Artifacts)
	}
	if !hasStr(p.URLs, "http://evil.test/bot.sh") {
		t.Errorf("harvested URLs missing: %v", p.URLs)
	}
	if !hasStr(p.Domains, "c2.example.org") || !hasStr(p.Domains, "vpn.corp") {
		t.Errorf("domains/SNIs missing: %v", p.Domains)
	}
	if p.Fingerprints["ja4t"] == "" {
		t.Errorf("ja4t fingerprint not captured: %v", p.Fingerprints)
	}
}

// TestBuildProfileOriginAndProtoIntel verifies the dossier surfaces the
// enrichment (geo/asn/rdns/net-class/cloud/os-guess/scanner) and protocol-stack
// intelligence (TLS versions, negotiated SSH KEX, HTTP/2-3, QUIC) that the
// sensor already attaches to events but previously only lived in per-event meta.
func TestBuildProfileOriginAndProtoIntel(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "listener:https", Severity: event.SeverityMedium,
			Handler: "https", Source: event.Endpoint{IP: "203.0.113.9"}, Dest: event.Endpoint{Port: 443},
			Meta: map[string]any{
				"geo_country": "DE", "geo_country_name": "Germany", "geo_city": "Frankfurt",
				"geo_lat": 50.11, "geo_lon": 8.68,
				"asn": float64(14061), "asn_org": "DigitalOcean LLC", // float64: store JSON round-trip
				"rdns": "scanner.example.net", "net_class": "hosting",
				"cloud_provider": "DigitalOcean", "os_guess": "Linux 5.x",
				"known_scanner": "Censys", "mac_vendor": "Dell Inc.",
				"tls_version": "TLS 1.3", "ssh_kex_negotiated": "curve25519-sha256",
			},
		},
		{
			ID: "2", Time: now.Add(time.Minute), RuleID: "listener:quic", Severity: event.SeverityLow,
			Handler: "quic", Source: event.Endpoint{IP: "203.0.113.9"},
			Meta: map[string]any{
				"http3": true, "quic_sni": "edge.target.example",
				"quic_alpn": []any{"h3"}, "opc_strings": []any{"PLC1.Boiler.Pressure"},
			},
		},
	}
	p := buildProfile("203.0.113.9", evs)

	if p.Origin.Country != "DE" || p.Origin.City != "Frankfurt" {
		t.Errorf("geo not captured: %+v", p.Origin)
	}
	if p.Origin.ASN != 14061 || p.Origin.ASNOrg != "DigitalOcean LLC" {
		t.Errorf("asn not captured: %+v", p.Origin)
	}
	if p.Origin.RDNS != "scanner.example.net" || p.Origin.NetClass != "hosting" {
		t.Errorf("rdns/net_class not captured: %+v", p.Origin)
	}
	if p.Origin.CloudProvider != "DigitalOcean" || p.Origin.KnownScanner != "Censys" || p.Origin.OSGuess != "Linux 5.x" {
		t.Errorf("cloud/scanner/os not captured: %+v", p.Origin)
	}
	if !hasStr(p.Proto.TLSVersions, "TLS 1.3") || p.Proto.SSHKex != "curve25519-sha256" {
		t.Errorf("proto intel not captured: %+v", p.Proto)
	}
	if !p.Proto.HTTP3 || !hasStr(p.Proto.QUICSNI, "edge.target.example") || !hasStr(p.Proto.QUICALPN, "h3") {
		t.Errorf("quic/http3 not captured: %+v", p.Proto)
	}
	if !hasStr(p.OPCItems, "PLC1.Boiler.Pressure") {
		t.Errorf("opc items not captured: %v", p.OPCItems)
	}
	if p.Origin.Empty() || p.Proto.Empty() {
		t.Error("Empty() should be false when fields are populated")
	}
}

// TestBuildProfileNewSignals checks the SSH keys, SMTP senders, and
// web-attack-class surfacing added in the second depth pass.
func TestBuildProfileNewSignals(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "listener:ssh", Severity: event.SeverityMedium,
			Handler: "ssh", Source: event.Endpoint{IP: "8.8.8.8"}, Dest: event.Endpoint{Port: 22},
			Meta: map[string]any{"ssh_pubkey_fps": []string{"ssh-rsa:SHA256:aaa", "ssh-ed25519:SHA256:bbb"}},
		},
		{
			ID: "2", Time: now, RuleID: "listener:smtp", Severity: event.SeverityLow,
			Handler: "smtp_recv", Source: event.Endpoint{IP: "8.8.8.8"}, Dest: event.Endpoint{Port: 25},
			Meta: map[string]any{"mail_from": "<spammer@evil.test>"},
		},
		{
			ID: "3", Time: now, RuleID: "listener:http", Severity: event.SeverityHigh,
			Handler: "http", Source: event.Endpoint{IP: "8.8.8.8"}, Dest: event.Endpoint{Port: 80},
			Anomalies: []string{"webapp:ssti", "webapp:xxe", "webapp:nosqli"},
		},
	}
	p := buildProfile("8.8.8.8", evs)

	if len(p.SSHKeys) != 2 {
		t.Errorf("ssh keys = %v; want 2", p.SSHKeys)
	}
	if !hasStr(p.Emails, "spammer@evil.test") {
		t.Errorf("emails missing sender: %v", p.Emails)
	}
	if len(p.AttackClasses) != 3 {
		t.Errorf("attack classes = %v; want 3", p.AttackClasses)
	}
	// 3+ distinct web-attack classes => web application attack.
	if p.Classification != "web application attack" {
		t.Errorf("classification = %q; want web application attack", p.Classification)
	}
}

// TestBuildProfileAttackSurface verifies the dossier aggregates, over all of a
// source's events: its intent, the consolidated attack/misuse signals
// (web-attack classes + non-webapp misuse anomalies), the requested URLs, the
// HTTP headers seen, the files downloaded/exfiltrated over every transfer
// protocol, the honeytokens it pulled/replayed, and the per-protocol intel.
func TestBuildProfileAttackSurface(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "webapp:sqli", Severity: event.SeverityHigh,
			Handler: "http", Source: event.Endpoint{IP: "6.6.6.6"}, Dest: event.Endpoint{Port: 80},
			Anomalies: []string{"webapp:sqli", "http-method-unknown"},
			Meta: map[string]any{
				"intent":       "SQL injection against the login form",
				"http_uri":     "/admin/login.php?id=1",
				"http_headers": map[string]string{"user-agent": "sqlmap/1.7", "accept": "*/*"},
				"honeytoken":   "DB_PASS_s3cret",
				"tls_version":  "TLS 1.2",
			},
		},
		{
			ID: "2", Time: now.Add(time.Minute), RuleID: "listener:ftp", Severity: event.SeverityMedium,
			Handler: "ftp", Source: event.Endpoint{IP: "6.6.6.6"}, Dest: event.Endpoint{Port: 21},
			Anomalies: []string{"honeyfile-download"},
			Meta: map[string]any{
				"intent":    "FTP honeyfile download",
				"retrieved": []any{"/home/admin/id_rsa", "/etc/passwd"},
			},
		},
		{
			ID: "3", Time: now.Add(2 * time.Minute), RuleID: "listener:ssh", Severity: event.SeverityHigh,
			Handler: "ssh", Source: event.Endpoint{IP: "6.6.6.6"}, Dest: event.Endpoint{Port: 22},
			Meta: map[string]any{
				"scp_mode": "download", "scp_path": "/root/.ssh/id_rsa",
				"sftp_paths":                 []any{"/etc/shadow"},
				"ssh_kex_negotiated":         "curve25519-sha256",
				"ssh_client_openssh_version": "9.6p1",
				"honeytoken_account":         "svc-backup",
			},
		},
		{
			ID: "4", Time: now.Add(3 * time.Minute), RuleID: "listener:tftp", Severity: event.SeverityMedium,
			Handler: "tftp", Source: event.Endpoint{IP: "6.6.6.6"}, Dest: event.Endpoint{Port: 69},
			Meta: map[string]any{"opcode": "RRQ", "filename": "running-config"},
		},
		{
			ID: "5", Time: now.Add(4 * time.Minute), RuleID: "listener:dns", Severity: event.SeverityHigh,
			Handler: "dns", Source: event.Endpoint{IP: "6.6.6.6"}, Dest: event.Endpoint{Port: 53},
			Meta: map[string]any{"zone_transfer_served": true, "qname": "corp.example"},
		},
		{
			ID: "6", Time: now.Add(5 * time.Minute), RuleID: "canary:token_used", Severity: event.SeverityCritical,
			Handler: "vault", Source: event.Endpoint{IP: "6.6.6.6"},
			Meta: map[string]any{"reused_cred_key": "vault_token"},
		},
	}
	p := buildProfile("6.6.6.6", evs)

	// Intent aggregated across all events.
	for _, want := range []string{"SQL injection against the login form", "FTP honeyfile download"} {
		if !hasStr(p.Intents, want) {
			t.Errorf("intent missing %q: %v", want, p.Intents)
		}
	}
	// Consolidated attack catalog: webapp:* are attack classes; non-webapp
	// anomalies are protocol-misuse markers.
	if !hasStr(p.AttackClasses, "webapp:sqli") {
		t.Errorf("attack classes missing webapp:sqli: %v", p.AttackClasses)
	}
	if !hasStr(p.MisuseAnomalies, "http-method-unknown") {
		t.Errorf("misuse anomalies missing http-method-unknown: %v", p.MisuseAnomalies)
	}
	if hasStr(p.MisuseAnomalies, "webapp:sqli") {
		t.Errorf("misuse anomalies should exclude webapp:* classes: %v", p.MisuseAnomalies)
	}
	// Requested URLs.
	if !hasStr(p.URLsRequested, "/admin/login.php?id=1") {
		t.Errorf("requested URLs missing: %v", p.URLsRequested)
	}
	// HTTP headers seen.
	if h := findHeader(p.HTTPHeaders, "user-agent"); h == nil || !hasStr(h.Values, "sqlmap/1.7") {
		t.Errorf("http header user-agent / value not captured: %+v", p.HTTPHeaders)
	}
	// Files downloaded / exfiltrated over every transfer protocol.
	for _, want := range []FileTaken{
		{Path: "/home/admin/id_rsa", Method: "ftp"},
		{Path: "/etc/passwd", Method: "ftp"},
		{Path: "/root/.ssh/id_rsa", Method: "scp"},
		{Path: "/etc/shadow", Method: "sftp"},
		{Path: "running-config", Method: "tftp"},
		{Path: "corp.example", Method: "dns-axfr"},
	} {
		if !hasFile(p.FilesTaken, want.Path, want.Method) {
			t.Errorf("files taken missing %v: %v", want, p.FilesTaken)
		}
	}
	// Honeytokens served / replayed.
	for _, want := range []TokenTaken{
		{Token: "DB_PASS_s3cret", Kind: "honeytoken"},
		{Token: "svc-backup", Kind: "account"},
		{Token: "vault_token", Kind: "replayed"},
	} {
		if !hasToken(p.Honeytokens, want.Kind, want.Token) {
			t.Errorf("honeytokens missing %v: %v", want, p.Honeytokens)
		}
	}
	// Per-protocol intelligence (not only TLS): ssh version + negotiated KEX.
	ssh := findProto(p.Protocols, "ssh")
	if ssh == nil || !hasStr(ssh.Versions, "ssh_client_openssh_version: 9.6p1") {
		t.Errorf("ssh protocol version not captured: %+v", ssh)
	}
	if ssh == nil || !hasStr(ssh.Details, "ssh_kex_negotiated: curve25519-sha256") {
		t.Errorf("ssh negotiated KEX not captured: %+v", ssh)
	}
	if http := findProto(p.Protocols, "http"); http == nil || !hasStr(http.Versions, "tls_version: TLS 1.2") {
		t.Errorf("http protocol version not captured: %+v", http)
	}
}

func findHeader(hs []HeaderStat, name string) *HeaderStat {
	for i := range hs {
		if hs[i].Name == name {
			return &hs[i]
		}
	}
	return nil
}

func hasFile(fs []FileTaken, path, method string) bool {
	for _, f := range fs {
		if f.Path == path && f.Method == method {
			return true
		}
	}
	return false
}

func hasToken(ts []TokenTaken, kind, token string) bool {
	for _, tk := range ts {
		if tk.Kind == kind && tk.Token == token {
			return true
		}
	}
	return false
}

func findProto(ps []ProtocolUse, name string) *ProtocolUse {
	for i := range ps {
		if ps[i].Name == name {
			return &ps[i]
		}
	}
	return nil
}

// TestBuildProfilePlaybooks: storyline playbooks attributed to a source are
// collected onto its profile.
func TestBuildProfilePlaybooks(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{ID: "1", Time: now, RuleID: "storyline:multi_stage", Severity: event.SeverityCritical,
			Source: event.Endpoint{IP: "9.9.9.9"},
			Meta:   map[string]any{"playbook": "dns-tunneling"}},
		{ID: "2", Time: now, RuleID: "storyline:multi_stage", Severity: event.SeverityCritical,
			Source: event.Endpoint{IP: "9.9.9.9"},
			Meta:   map[string]any{"playbook": "cloud-credential-takeover"}},
	}
	p := buildProfile("9.9.9.9", evs)
	if !hasStr(p.Playbooks, "dns-tunneling") || !hasStr(p.Playbooks, "cloud-credential-takeover") {
		t.Errorf("playbooks not collected: %v", p.Playbooks)
	}
}

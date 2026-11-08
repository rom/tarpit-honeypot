package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestHarvestedURLsDefangAndDedup(t *testing.T) {
	if got := defangURL("http://evil.example.com/x.sh"); got != "hxxp[://]evil[.]example[.]com/x[.]sh" {
		t.Errorf("defangURL = %q", got)
	}
	now := time.Now()
	evs := []*event.Event{
		{Time: now, Source: event.Endpoint{IP: "10.0.0.9"}, Handler: "ssh_interactive",
			Meta: map[string]any{"harvested_urls": []string{"http://evil.example.com/a.sh", "http://evil.example.com/a.sh"}}},
		{Time: now.Add(-time.Minute), Source: event.Endpoint{IP: "10.0.0.9"}, Handler: "telnet",
			Meta: map[string]any{"harvested_urls": []any{"https://c2.bad/beacon"}}}, // []any (as from the store)
	}
	v := buildCapturesView("", now.Add(-time.Hour), evs, "", "")
	// Two distinct URLs; the duplicate within one source is collapsed.
	if len(v.URLs) != 2 {
		t.Fatalf("got %d harvested URLs, want 2: %+v", len(v.URLs), v.URLs)
	}
	var raws, disps []string
	for _, u := range v.URLs {
		raws = append(raws, u.URL)
		disps = append(disps, u.Display)
	}
	if !strings.Contains(strings.Join(raws, " "), "http://evil.example.com/a.sh") {
		t.Errorf("raw URL missing: %v", raws)
	}
	if strings.Contains(strings.Join(disps, " "), "http://") {
		t.Errorf("display should be defanged, got %v", disps)
	}
}

func TestHarvestedURLsRender(t *testing.T) {
	now := time.Now()
	v := capturesView{Enabled: true, Since: now.Add(-time.Hour), URLs: []harvestedURL{
		{Time: now, Source: "10.0.0.9", Handler: "ssh_interactive",
			URL: "http://evil.example.com/x.sh", Display: defangURL("http://evil.example.com/x.sh")},
	}}
	var sb strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&sb, "captures", v); err != nil {
		t.Fatalf("render captures: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		"harvested URLs", "data-malware-link",
		`data-url="http://evil.example.com/x.sh"`, // real URL preserved for the gate
		"hxxp[://]evil[.]example[.]com",           // defanged display
		"may host live malware",                   // the warning note
	} {
		if !strings.Contains(out, want) {
			t.Errorf("captures render missing %q", want)
		}
	}
	// The raw URL must NOT appear as a live href that navigates without the gate.
	if strings.Contains(out, `href="http://evil.example.com`) {
		t.Error("raw URL rendered as a live href — the warning gate would be bypassed")
	}
}

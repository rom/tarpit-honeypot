package ui

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/store"
)

// The summary service cards must carry the stable data-svc + data-hits hooks the
// live-pulse JS diffs on, plus the category badge.
func TestSummaryServiceCardHasPulseHooks(t *testing.T) {
	tmpl := uiTmpl(t)
	d := buildDashboard(store.Summary{Total: 1}, []store.HourBucket{{Hour: time.Now(), Count: 1}}, time.Hour)
	d.RangeLabel = "last 24 hours"
	d.RangeLinks = summaryRangeLinks("24h")
	d.Canvas.Listeners = []portCard{
		{Proto: "tcp", Port: 502, PortLabel: "502", Handler: "modbus", Mode: "banner", Category: "ot", Hit: true, Hits: 7},
	}
	d.Canvas.ListenerCount = 1
	d.Canvas.TCPCount = 1
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "index", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`data-svc="tcp/502"`, `data-hits="7"`, `cat-ot`} {
		if !strings.Contains(out, want) {
			t.Errorf("summary service card missing %q", want)
		}
	}
}

// The packaged JS must ship the pulse enhancer and have it registered.
func TestAppJSShipsServicePulse(t *testing.T) {
	b, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, want := range []string{"function setupServicePulse", "svc-flash", "svc-new", "setupServicePulse, setupColumnToggle, setupMalwareLinks]", "function morph", "data-chart-b64"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}

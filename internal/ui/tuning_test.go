package ui

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestUISetTuning(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}
	// Defaults applied by New.
	if s.dashTTL != defaultDashTTL || s.scanLimit != defaultUIScanLimit {
		t.Fatalf("New did not apply defaults: dashTTL=%v scanLimit=%d", s.dashTTL, s.scanLimit)
	}
	// Non-zero fields override; zero fields are a no-op.
	s.SetTuning(config.Tuning{UIDashboardTTL: 90 * time.Second, UIScanLimit: 5000})
	if s.dashTTL != 90*time.Second {
		t.Errorf("dashTTL override not applied: %v", s.dashTTL)
	}
	if s.scanLimit != 5000 {
		t.Errorf("scanLimit override not applied: %d", s.scanLimit)
	}
	if s.aggCacheTTL != defaultAggCacheTTL || s.windowEventsTTL != defaultWindowEventsTTL {
		t.Errorf("unset fields should keep defaults: agg=%v win=%v", s.aggCacheTTL, s.windowEventsTTL)
	}
}

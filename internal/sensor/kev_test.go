package sensor

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/kevsync"
)

func TestStampKEV(t *testing.T) {
	var s Sensor
	// Disabled (nil store): no stamping, no panic.
	ev := &event.Event{RuleID: "cve:CVE-2021-44228", Severity: event.SeverityLow}
	s.stampKEV(ev)
	if _, ok := ev.Meta["kev"]; ok {
		t.Fatal("stampKEV should no-op when the store is nil")
	}

	// Enabled: a KEV-listed cve event is stamped + severity lifted.
	st := kevsync.NewStore()
	st.Replace([]kevsync.Entry{
		{CVEID: "CVE-2021-44228", DateAdded: "2021-12-10", KnownRansomware: true},
	}, "v1")
	s.kevStore.Store(st)

	ev = &event.Event{RuleID: "cve:CVE-2021-44228", Severity: event.SeverityLow}
	s.stampKEV(ev)
	if ev.Meta["kev"] != true {
		t.Errorf("kev not stamped: %v", ev.Meta)
	}
	if ev.Meta["kev_date_added"] != "2021-12-10" {
		t.Errorf("kev_date_added = %v", ev.Meta["kev_date_added"])
	}
	if ev.Meta["kev_known_ransomware"] != true {
		t.Errorf("kev_known_ransomware not set: %v", ev.Meta)
	}
	if ev.Severity < event.SeverityHigh {
		t.Errorf("severity not lifted to >=High: %v", ev.Severity)
	}

	// A cve event NOT on the KEV list is left alone.
	ev = &event.Event{RuleID: "cve:CVE-2000-0001", Severity: event.SeverityMedium}
	s.stampKEV(ev)
	if _, ok := ev.Meta["kev"]; ok {
		t.Errorf("non-KEV cve wrongly stamped: %v", ev.Meta)
	}

	// A non-cve event is ignored.
	ev = &event.Event{RuleID: "listener:ssh", Severity: event.SeverityLow}
	s.stampKEV(ev)
	if ev.Meta["kev"] == true {
		t.Error("non-cve event stamped")
	}
}

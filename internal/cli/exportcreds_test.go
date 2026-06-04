package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/ui"
)

// mustExport runs export-creds with the given args and returns stdout, failing
// on error.
func mustExport(t *testing.T, args ...string) string {
	t.Helper()
	out, err := captureStdout(t, func() error { return cmdExportCreds(args) })
	if err != nil {
		t.Fatalf("export-creds %v: %v", args, err)
	}
	return out
}

func seedCredStore(t *testing.T, dir string) {
	t.Helper()
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	evs := []*event.Event{
		{ID: event.NewID(), Time: now, Sensor: "s", RuleID: "http-login-attempt", Severity: event.SeverityHigh,
			Handler: "http", Source: event.Endpoint{IP: "1.2.3.4"},
			Meta: map[string]any{"http_login_user": "admin", "http_login_pass": "hunter2"}},
		{ID: event.NewID(), Time: now, Sensor: "s", RuleID: "ssh", Severity: event.SeverityHigh,
			Handler: "ssh_interactive", Source: event.Endpoint{IP: "5.6.7.8"},
			Meta: map[string]any{"auth_attempts": []map[string]any{
				{"method": "password", "user": "root", "password": "toor"},
			}}},
		{ID: event.NewID(), Time: now, Sensor: "s", RuleID: "snmp", Severity: event.SeverityMedium,
			Handler: "snmp", Source: event.Endpoint{IP: "9.9.9.9"},
			Meta: map[string]any{"snmp_community": "public"}},
	}
	for _, ev := range evs {
		if err := st.Insert(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()
}

func TestExportCredsFormatsAndFilter(t *testing.T) {
	dir := t.TempDir()
	seedCredStore(t, dir)

	// JSON: all kinds present.
	out := mustExport(t, "--data-dir", dir, "--format", "json")
	for _, want := range []string{"admin", "hunter2", "root", "toor", "public"} {
		if !strings.Contains(out, want) {
			t.Errorf("json export missing %q:\n%s", want, out)
		}
	}

	// CSV header + a password row.
	out = mustExport(t, "--data-dir", dir, "--format", "csv")
	if !strings.Contains(out, "time,source,kind,user,secret,service") || !strings.Contains(out, "1.2.3.4") {
		t.Errorf("csv export malformed:\n%s", out)
	}

	// YAML + XML + txt smoke.
	for _, f := range []string{"yaml", "xml", "txt"} {
		o := mustExport(t, "--data-dir", dir, "--format", f)
		if !strings.Contains(o, "admin") {
			t.Errorf("%s export missing admin:\n%s", f, o)
		}
	}

	// --kind filter: only the SSH/HTTP password rows, not the SNMP community.
	out = mustExport(t, "--data-dir", dir, "--format", "json", "--kind", "password")
	if !strings.Contains(out, "admin") || strings.Contains(out, "public") {
		t.Errorf("--kind password filter wrong:\n%s", out)
	}

	// Bad format is rejected.
	if err := cmdExportCreds([]string{"--data-dir", dir, "--format", "bogus"}); err == nil {
		t.Error("bad --format should error")
	}
}

func TestSortCreds(t *testing.T) {
	mk := func(src, user, kind string, sec int) ui.Cred {
		return ui.Cred{Source: src, User: user, Kind: kind, Time: time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)}
	}
	base := []ui.Cred{mk("9.9.9.9", "bob", "token", 100), mk("1.1.1.1", "alice", "password", 300), mk("5.5.5.5", "carol", "cookie", 200)}

	// time: newest first.
	c := append([]ui.Cred(nil), base...)
	sortCreds(c, "time", false)
	if c[0].User != "alice" || c[2].User != "bob" {
		t.Errorf("time sort wrong: %v", []string{c[0].User, c[1].User, c[2].User})
	}
	// source: ascending.
	c = append([]ui.Cred(nil), base...)
	sortCreds(c, "source", false)
	if c[0].Source != "1.1.1.1" || c[2].Source != "9.9.9.9" {
		t.Errorf("source sort wrong: %v", []string{c[0].Source, c[1].Source, c[2].Source})
	}
	// user reversed: descending.
	c = append([]ui.Cred(nil), base...)
	sortCreds(c, "user", true)
	if c[0].User != "carol" || c[2].User != "alice" {
		t.Errorf("reverse user sort wrong: %v", []string{c[0].User, c[1].User, c[2].User})
	}
}

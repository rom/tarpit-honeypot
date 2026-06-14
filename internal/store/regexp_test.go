package store

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestQueryRegex covers the Filter.Regex path: the include / exclude lists for
// the text dimensions (src_ip, rule_id, proto, handler, the geo meta fields and
// the full-text) match each value as a case-insensitive RE2 pattern, while
// comma=OR (multiple includes) and the exact (non-regex) path are preserved.
func TestQueryRegex(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	since := now.Add(-time.Hour)

	e1 := mkEvent("a", "10.0.0.1", "ssh:login", event.SeverityHigh, now.Add(-1*time.Minute))
	e1.Meta = map[string]any{"asn_org": "Cloudflare Inc", "geo_country_name": "United States"}
	e2 := mkEvent("b", "10.0.0.20", "telnet:login", event.SeverityHigh, now.Add(-2*time.Minute))
	e2.Handler = "telnet"
	e3 := mkEvent("c", "192.168.1.5", "http:probe", event.SeverityLow, now.Add(-3*time.Minute))
	e3.Proto, e3.Handler = "udp", "http"
	e3.Meta = map[string]any{"asn_org": "Google LLC"}
	e4 := mkEvent("d", "2001:db8::1", "ssh:bruteforce", event.SeverityHigh, now.Add(-4*time.Minute))
	for _, e := range []*event.Event{e1, e2, e3, e4} {
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	ids := func(rows []*event.Event) map[string]bool {
		m := map[string]bool{}
		for _, r := range rows {
			m[r.ID] = true
		}
		return m
	}
	run := func(t *testing.T, f Filter, want ...string) {
		t.Helper()
		f.Since, f.Limit = since, 100
		f.Regex = true
		rows, err := s.Query(ctx, f)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		got := ids(rows)
		if len(got) != len(want) {
			t.Fatalf("got %d rows %v, want %v", len(rows), got, want)
		}
		for _, id := range want {
			if !got[id] {
				t.Fatalf("missing %q; got %v, want %v", id, got, want)
			}
		}
	}

	t.Run("src prefix", func(t *testing.T) { run(t, Filter{SourceIPs: []string{`^10\.0\.`}}, "a", "b") })
	t.Run("src anchored exact", func(t *testing.T) { run(t, Filter{SourceIPs: []string{`^10\.0\.0\.1$`}}, "a") })
	t.Run("src alternation OR list", func(t *testing.T) {
		// comma=OR: two include patterns, an event matches if it matches either.
		run(t, Filter{SourceIPs: []string{`^192\.`, `db8`}}, "c", "d")
	})
	t.Run("src exclude", func(t *testing.T) { run(t, Filter{ExcludeSourceIPs: []string{`^10\.`}}, "c", "d") })
	t.Run("rule alternation", func(t *testing.T) { run(t, Filter{RuleIDs: []string{`ssh|telnet`}}, "a", "b", "d") })
	t.Run("rule case-insensitive", func(t *testing.T) { run(t, Filter{RuleIDs: []string{`SSH:`}}, "a", "d") })
	t.Run("proto anchored", func(t *testing.T) { run(t, Filter{Protos: []string{`^udp$`}}, "c") })
	t.Run("handler", func(t *testing.T) { run(t, Filter{Handlers: []string{`^ssh$`}}, "a", "d") })
	t.Run("asn_org meta substring", func(t *testing.T) { run(t, Filter{ASNOrgs: []string{`goog`}}, "c") })
	t.Run("country_name meta", func(t *testing.T) { run(t, Filter{CountryNames: []string{`United`}}, "a") })
	t.Run("full-text regex", func(t *testing.T) { run(t, Filter{Text: `brute.*force`}, "d") })

	// Regression: regex is opt-in. The exact single-value path must NOT treat the
	// value as a regex — src_ip 10.0.0.1 must match only e1, never 10.0.0.20.
	exact, err := s.Query(ctx, Filter{SourceIP: "10.0.0.1", Since: since, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(exact) != 1 || exact[0].ID != "a" {
		t.Fatalf("exact (non-regex) src_ip over-matched: got %d rows %v, want only \"a\"", len(exact), ids(exact))
	}

	// A malformed pattern surfaces as a query error (the UI pre-validates so this
	// never reaches a user, but the store must not silently match nothing).
	if _, err := s.Query(ctx, Filter{Regex: true, SourceIPs: []string{"[unterminated"}, Since: since, Limit: 100}); err == nil {
		t.Fatal("expected an error for a malformed regex, got nil")
	}
}

// TestRegexpUDF exercises the registered REGEXP scalar directly: pattern-first
// argument order (X REGEXP Y == regexp(Y, X)), case handling, and NULL values.
func TestRegexpUDF(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cases := []struct {
		expr string
		want int
	}{
		{`SELECT '10.0.0.7' REGEXP '^10\.'`, 1},
		{`SELECT '192.168.0.1' REGEXP '^10\.'`, 0},
		{`SELECT 'SSH' REGEXP '(?i)ssh'`, 1},
		{`SELECT NULL REGEXP 'x'`, 0},
		{`SELECT 'abc' REGEXP ''`, 0}, // empty pattern never matches
	}
	for _, c := range cases {
		var got int
		if err := s.db.QueryRow(c.expr).Scan(&got); err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got != c.want {
			t.Errorf("%s = %d, want %d", c.expr, got, c.want)
		}
	}
}

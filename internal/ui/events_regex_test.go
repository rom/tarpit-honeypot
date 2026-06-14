package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestEventsRegexFilter drives the /events handler end-to-end (parse → store
// REGEXP → template) for regex mode: a pattern matches the right sources, the
// exact path is unchanged when re is off (the opt-in guarantee that keeps the
// UI's exact-match pivots precise), and a malformed pattern renders the form
// with an error banner instead of a 500.
func TestEventsRegexFilter(t *testing.T) {
	s := fleetTestServer(t) // store + templates
	ctx := context.Background()
	ins := func(id, ip string) {
		ev := &event.Event{ID: id, Time: time.Now().UTC(), RuleID: "listener:ssh",
			Severity: event.SeverityHigh, Source: event.Endpoint{IP: ip}, Proto: "tcp",
			Handler: "ssh", Meta: map[string]any{}}
		if err := s.store.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	ins("a", "10.0.0.1")
	ins("b", "10.0.0.20")
	ins("c", "192.168.1.5")

	get := func(qs url.Values) (int, string) {
		w := httptest.NewRecorder()
		s.handleEvents(w, httptest.NewRequest(http.MethodGet, "/events?"+qs.Encode(), nil))
		return w.Code, w.Body.String()
	}

	// re=1: the prefix pattern matches both 10.0.0.x sources and not the 192.168.
	code, body := get(url.Values{"re": {"1"}, "source": {`^10\.0\.`}})
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "10.0.0.1") || !strings.Contains(body, "10.0.0.20") {
		t.Error(`regex ^10\.0\. did not match the 10.0.0.x sources`)
	}
	if strings.Contains(body, "192.168.1.5") {
		t.Error(`regex ^10\.0\. leaked the 192.168 source`)
	}
	if !strings.Contains(body, `name="re" value="1" checked`) {
		t.Error("regex checkbox not echoed as checked")
	}

	// Without re, the same value is exact: 10.0.0.1 only, never 10.0.0.20 — proof
	// the regex opt-in did not change exact-match semantics.
	if _, body = get(url.Values{"source": {"10.0.0.1"}}); !strings.Contains(body, "10.0.0.1") {
		t.Error("exact source 10.0.0.1 missing")
	} else if strings.Contains(body, "10.0.0.20") {
		t.Error("exact source matched 10.0.0.20 (regex leaked into non-regex mode)")
	}

	// A malformed pattern renders the form with the error, not a 500.
	code, body = get(url.Values{"re": {"1"}, "source": {"[unterminated"}})
	if code != http.StatusOK {
		t.Fatalf("malformed regex status = %d, want 200 (form + error)", code)
	}
	if !strings.Contains(body, "source pattern") {
		t.Error("malformed regex did not surface a source-pattern error in the form")
	}
}

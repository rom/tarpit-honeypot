package ui

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/store"
)

func parseQ(t *testing.T, vals url.Values) store.Filter {
	t.Helper()
	return parseFilter(httptest.NewRequest("GET", "/events?"+vals.Encode(), nil))
}

// TestParseFilterRegexRouting checks that re=1 sends the text dimensions to the
// multi-value include/exclude lists (so the store's REGEXP path applies) and
// sets Filter.Regex, while the exact single-value fast path is used otherwise.
func TestParseFilterRegexRouting(t *testing.T) {
	// re=1: a single source value still routes to the list (not the fast field),
	// and Regex is set.
	f := parseQ(t, url.Values{"re": {"1"}, "source": {`^10\.0\.`}})
	if !f.Regex {
		t.Fatal("re=1 did not set Filter.Regex")
	}
	if f.SourceIP != "" {
		t.Errorf("regex mode used the exact SourceIP fast path: %q", f.SourceIP)
	}
	if len(f.SourceIPs) != 1 || f.SourceIPs[0] != `^10\.0\.` {
		t.Errorf("SourceIPs = %v, want [^10\\.0\\.]", f.SourceIPs)
	}

	// comma=OR and !=exclude still split per token in regex mode.
	f = parseQ(t, url.Values{"re": {"1"}, "rule": {"ssh|telnet,http"}, "proto": {"!udp"}})
	if len(f.RuleIDs) != 2 || f.RuleIDs[0] != "ssh|telnet" || f.RuleIDs[1] != "http" {
		t.Errorf("RuleIDs = %v, want [ssh|telnet http]", f.RuleIDs)
	}
	if len(f.ExcludeProtos) != 1 || f.ExcludeProtos[0] != "udp" {
		t.Errorf("ExcludeProtos = %v, want [udp]", f.ExcludeProtos)
	}

	// Without re, a single value keeps the exact fast path (regression: pivots /
	// links that don't set re must not become regexes).
	f = parseQ(t, url.Values{"source": {"10.0.0.1"}})
	if f.Regex {
		t.Error("Regex set without re=1")
	}
	if f.SourceIP != "10.0.0.1" || len(f.SourceIPs) != 0 {
		t.Errorf("non-regex single source: SourceIP=%q SourceIPs=%v, want exact fast path", f.SourceIP, f.SourceIPs)
	}
}

func TestFilterRegexError(t *testing.T) {
	// Non-regex filter is never rejected.
	if msg := filterRegexError(store.Filter{SourceIP: "["}); msg != "" {
		t.Errorf("non-regex filter reported error %q", msg)
	}
	// Valid patterns across fields pass.
	ok := store.Filter{Regex: true, SourceIPs: []string{`^10\.`}, RuleIDs: []string{"ssh|telnet"}, Text: "brute.*force"}
	if msg := filterRegexError(ok); msg != "" {
		t.Errorf("valid regex filter reported error %q", msg)
	}
	// A malformed pattern is reported with its field label.
	if msg := filterRegexError(store.Filter{Regex: true, RuleIDs: []string{"[unterminated"}}); msg == "" {
		t.Error("malformed rule pattern not reported")
	}
	if msg := filterRegexError(store.Filter{Regex: true, Text: "(unbalanced"}); msg == "" {
		t.Error("malformed search pattern not reported")
	}
}

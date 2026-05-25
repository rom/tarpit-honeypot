package stix

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/intel"
)

func TestIndicators(t *testing.T) {
	iocs := []intel.IOC{
		{Kind: "ip", Value: "203.0.113.7", Reason: "source-multi-sensor"},
		{Kind: "ip", Value: "2001:db8::1", Reason: "subnet-coordinated"},
		{Kind: "asn", Value: "AS64500", Reason: "asn-multi-sensor"},
		{Kind: "fingerprint", Value: "ja3:abc", Reason: "fingerprint-shared"},
	}
	objs := Indicators(iocs, time.Unix(1_700_000_000, 0).UTC())
	if len(objs) != 4 {
		t.Fatalf("indicators = %d; want 4", len(objs))
	}
	pats := map[string]bool{}
	for _, o := range objs {
		ind := o.(Indicator)
		if ind.Type != "indicator" || ind.PatternType != "stix" || ind.SpecVersion != "2.1" {
			t.Errorf("bad indicator scaffold: %+v", ind)
		}
		if !strings.HasPrefix(ind.ID, "indicator--") {
			t.Errorf("bad id %q", ind.ID)
		}
		pats[ind.Pattern] = true
	}
	for _, want := range []string{
		"[ipv4-addr:value = '203.0.113.7']",
		"[ipv6-addr:value = '2001:db8::1']",
		"[autonomous-system:number = 64500]",
		"[x-tarpit-fingerprint:value = 'ja3:abc']",
	} {
		if !pats[want] {
			t.Errorf("missing pattern %q (have %v)", want, pats)
		}
	}
}

func TestDeterministicID(t *testing.T) {
	a := Indicators([]intel.IOC{{Kind: "ip", Value: "1.2.3.4"}}, time.Now())[0].(Indicator)
	b := Indicators([]intel.IOC{{Kind: "ip", Value: "1.2.3.4"}}, time.Now().Add(time.Hour))[0].(Indicator)
	if a.ID != b.ID {
		t.Errorf("same IOC produced different ids: %s vs %s", a.ID, b.ID)
	}
}

func TestHandlerAuthAndTAXII(t *testing.T) {
	src := func() []intel.IOC { return []intel.IOC{{Kind: "ip", Value: "203.0.113.7", Reason: "x"}} }
	h := Handler(src, "tok")

	// Unauthorized.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/intel/stix", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no-token = %d; want 401", w.Code)
	}

	// STIX bundle.
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/intel/stix", nil)
	r.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("stix = %d; want 200", w.Code)
	}
	var b Bundle
	if err := json.NewDecoder(w.Body).Decode(&b); err != nil || b.Type != "bundle" || len(b.Objects) != 1 {
		t.Fatalf("bundle decode: type=%q objs=%d err=%v", b.Type, len(b.Objects), err)
	}

	// TAXII objects envelope.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/taxii2/api/collections/fleet-iocs/objects/", nil)
	r.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("taxii objects = %d; want 200", w.Code)
	}
	var env map[string]any
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if objs, _ := env["objects"].([]any); len(objs) != 1 {
		t.Errorf("taxii objects = %v; want 1", env["objects"])
	}

	// TAXII discovery is reachable.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/taxii2/", nil)
	r.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("taxii discovery = %d; want 200", w.Code)
	}
}

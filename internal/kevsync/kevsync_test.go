package kevsync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const sampleKEV = `{"title":"CISA KEV","catalogVersion":"2026.11.04","count":3,
 "vulnerabilities":[
  {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},
  {"cveID":"cve-2026-104935","vendorProject":"Ivanti","product":"Connect Secure","vulnerabilityName":"ICS auth bypass","dateAdded":"2026-10-20","knownRansomwareCampaignUse":"Unknown"},
  {"cveID":"CVE-2026-76418","vendorProject":"Cisco","product":"ASA/FTD","vulnerabilityName":"SSL VPN DoS","dateAdded":"2026-10-29","knownRansomwareCampaignUse":"Unknown"}
 ]}`

func TestParse(t *testing.T) {
	entries, err := Parse([]byte(sampleKEV))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	// id is upper-cased even when the feed lower-cases it.
	var found bool
	for _, e := range entries {
		if e.CVEID == "CVE-2026-104935" {
			found = true
		}
		if e.CVEID == "CVE-2021-44228" && !e.KnownRansomware {
			t.Error("Log4Shell should be flagged knownRansomware")
		}
	}
	if !found {
		t.Error("lower-cased cve id not normalized to upper-case")
	}
}

func TestStoreAndLookup(t *testing.T) {
	entries, _ := Parse([]byte(sampleKEV))
	s := NewStore()
	s.Replace(entries, "2026.11.04")
	if s.Count() != 3 {
		t.Fatalf("count=%d want 3", s.Count())
	}
	if !s.Contains("cve-2026-76418") { // case-insensitive
		t.Error("Contains should be case-insensitive")
	}
	if e, ok := s.Lookup("CVE-2021-44228"); !ok || e.Product != "Log4j2" {
		t.Errorf("lookup Log4Shell = %+v ok=%v", e, ok)
	}
	if s.Version() != "2026.11.04" {
		t.Errorf("version=%q", s.Version())
	}
	if s.UpdatedAt().IsZero() {
		t.Error("UpdatedAt should be set after Replace")
	}
	// All() sorts newest-first.
	all := s.All()
	if all[0].CVEID != "CVE-2026-76418" {
		t.Errorf("All()[0]=%s want newest CVE-2026-76418", all[0].CVEID)
	}
}

func TestGapScan(t *testing.T) {
	entries, _ := Parse([]byte(sampleKEV))
	have := []string{"CVE-2021-44228"} // only Log4Shell is modeled
	gaps := GapScan(entries, have)
	if len(gaps) != 2 {
		t.Fatalf("gaps=%d want 2", len(gaps))
	}
	for _, g := range gaps {
		if g.CVEID == "CVE-2021-44228" {
			t.Error("covered CVE wrongly reported as a gap")
		}
	}
	// newest-first
	if gaps[0].CVEID != "CVE-2026-76418" {
		t.Errorf("gaps[0]=%s want CVE-2026-76418", gaps[0].CVEID)
	}
}

func TestFetchAndPuller(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleKEV))
	}))
	defer srv.Close()

	entries, version, err := Fetch(context.Background(), srv.Client(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || version != "2026.11.04" {
		t.Fatalf("fetch: %d entries version=%q", len(entries), version)
	}

	store := NewStore()
	p := NewPuller(srv.URL, "", 0, srv.Client(), store)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 3 {
		t.Errorf("store after refresh = %d want 3", store.Count())
	}
}

func TestFetchErrorKeepsLastGood(t *testing.T) {
	store := NewStore()
	entries, _ := Parse([]byte(sampleKEV))
	store.Replace(entries, "v1")
	// Puller pointed at a dead URL: refresh fails, store retained.
	p := NewPuller("http://127.0.0.1:0/nope", "", 0, &http.Client{}, store)
	var gotErr bool
	p.SetErrorHandler(func(error) { gotErr = true })
	_ = p.Refresh(context.Background())
	if !gotErr {
		t.Error("error handler not called on failed refresh")
	}
	if store.Count() != 3 {
		t.Errorf("store should retain last good snapshot, got %d", store.Count())
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kev.json")
	if err := os.WriteFile(p, []byte(sampleKEV), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	n, ver, err := s.LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if n == 0 || s.Count() != n {
		t.Errorf("loaded %d entries; store has %d", n, s.Count())
	}
	if ver == "" {
		t.Error("catalog version not parsed")
	}
	if _, _, err := NewStore().LoadFile(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("LoadFile of a missing file should error")
	}
}

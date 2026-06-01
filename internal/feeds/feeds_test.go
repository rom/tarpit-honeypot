package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseLineIPs(t *testing.T) {
	body := []byte("# a comment\n1.2.3.4\n5.6.7.8 ; extra\n10.0.0.0/24\nnot-an-ip\n\n2001:db8::1\n")
	ips := parseLineIPs(body)
	for _, want := range []string{"1.2.3.4", "5.6.7.8", "10.0.0.0", "2001:db8::1"} {
		if _, ok := ips[want]; !ok {
			t.Errorf("expected %s parsed; got %v", want, ips)
		}
	}
	if _, ok := ips["not-an-ip"]; ok {
		t.Errorf("garbage line should be skipped")
	}
}

func TestParseJSONIPsBareArray(t *testing.T) {
	ips, err := parseJSONIPs([]byte(`["9.9.9.9","8.8.8.8","bad"]`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ips["9.9.9.9"]; !ok {
		t.Errorf("9.9.9.9 not parsed: %v", ips)
	}
	if len(ips) != 2 {
		t.Errorf("want 2 valid IPs, got %d (%v)", len(ips), ips)
	}
}

func TestParseJSONIPsAbuseIPDB(t *testing.T) {
	body := []byte(`{"data":[{"ipAddress":"203.0.113.5","score":100},{"ipAddress":"198.51.100.7"}]}`)
	ips, err := parseJSONIPs(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ips["203.0.113.5"]; !ok {
		t.Errorf("AbuseIPDB ip not parsed: %v", ips)
	}
}

func TestPullerMergesAndApplies(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1\n2.2.2.2\n"))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["2.2.2.2","3.3.3.3"]`)) // 2.2.2.2 overlaps A
	}))
	defer srvB.Close()

	var applied map[string]string
	p := NewPuller([]Feed{
		{Label: "feedA", URL: srvA.URL},
		{Label: "feedB", URL: srvB.URL, Format: "json_ips"},
	}, time.Hour, http.DefaultClient, func(m map[string]string) { applied = m })

	p.refresh(context.Background())
	if applied == nil {
		t.Fatal("apply was never called")
	}
	if applied["1.1.1.1"] != "feedA" {
		t.Errorf("1.1.1.1 label = %q, want feedA", applied["1.1.1.1"])
	}
	if applied["3.3.3.3"] != "feedB" {
		t.Errorf("3.3.3.3 label = %q, want feedB", applied["3.3.3.3"])
	}
	// An IP in both feeds carries both labels.
	if applied["2.2.2.2"] != "feedA,feedB" {
		t.Errorf("2.2.2.2 label = %q, want feedA,feedB", applied["2.2.2.2"])
	}
}

func TestPullerKeepsLastOnTotalFailure(t *testing.T) {
	// All feeds fail to fetch (a closed server → transport error). refresh must
	// NOT call apply, so the last good overlay is preserved rather than cleared.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now unreachable → Do() returns an error

	called := false
	p := NewPuller([]Feed{{Label: "x", URL: url}}, time.Hour, http.DefaultClient,
		func(m map[string]string) { called = true })
	p.refresh(context.Background())
	if called {
		t.Error("apply must not be called when every feed fails (keep last snapshot)")
	}
}

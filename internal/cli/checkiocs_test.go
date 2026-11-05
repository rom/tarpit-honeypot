package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseIOCFileFormats(t *testing.T) {
	cases := map[string]struct {
		content   string
		wantIPs   int
		wantCIDRs int
		wantBad   int
	}{
		"one per line": {
			content: "1.2.3.4\n5.6.7.8\n2001:db8::1\n", wantIPs: 3,
		},
		"comma separated": {
			content: "1.2.3.4, 5.6.7.8\n9.9.9.9,8.8.8.8, 7.7.7.7\n", wantIPs: 5,
		},
		"cidr mix": {
			content: "10.0.0.0/8\n192.168.1.0/24, 1.2.3.4\n2001:db8::/32\n", wantIPs: 1, wantCIDRs: 3,
		},
		"comments and blanks": {
			content: "# header\n\n1.2.3.4\n// note\n  \n5.6.7.8\n", wantIPs: 2,
		},
		"dedup": {
			content: "1.2.3.4\n1.2.3.4\n1.2.3.004 is bad\n", wantIPs: 1, wantBad: 1,
		},
		"json array of strings": {
			content: `["1.2.3.4", "10.0.0.0/8", "5.6.7.8"]`, wantIPs: 2, wantCIDRs: 1,
		},
		"json export-iocs objects": {
			content: `[{"Kind":"ip","Value":"1.2.3.4","Reason":"x"},{"Kind":"ip","Value":"9.9.9.9"}]`, wantIPs: 2,
		},
		"json wrapped object": {
			content: `{"indicators": ["1.2.3.4", "192.168.0.0/16"]}`, wantIPs: 1, wantCIDRs: 1,
		},
		"garbage tokens": {
			content: "not-an-ip\n300.1.2.3\n1.2.3.4\n", wantIPs: 1, wantBad: 2,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ips, cidrs, bad, err := parseIOCFile(writeTemp(t, "iocs", c.content))
			if err != nil {
				t.Fatalf("parseIOCFile: %v", err)
			}
			if len(ips) != c.wantIPs {
				t.Errorf("ips = %v (%d); want %d", ips, len(ips), c.wantIPs)
			}
			if len(cidrs) != c.wantCIDRs {
				t.Errorf("cidrs = %v (%d); want %d", cidrs, len(cidrs), c.wantCIDRs)
			}
			if len(bad) != c.wantBad {
				t.Errorf("bad = %v (%d); want %d", bad, len(bad), c.wantBad)
			}
		})
	}
}

func TestMatchIOCsAgainstStore(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	seed := func(id, ip string, sev event.Severity) {
		if e := st.Insert(ctx, &event.Event{
			ID: id, Time: now, Sensor: "s", RuleID: "listener:ssh", Severity: sev,
			Handler: "ssh", Source: event.Endpoint{IP: ip}, Dest: event.Endpoint{IP: "10.0.0.1", Port: 22}, Proto: "tcp",
		}); e != nil {
			t.Fatal(e)
		}
	}
	// Two events from an exact-match attacker, one from a CIDR-range attacker,
	// one from an IP nobody is hunting.
	seed("a1", "203.0.113.9", event.SeverityHigh)
	seed("a2", "203.0.113.9", event.SeverityCritical)
	seed("b1", "198.51.100.42", event.SeverityMedium) // inside 198.51.100.0/24
	seed("c1", "8.8.8.8", event.SeverityLow)          // not an indicator

	ips := []string{"203.0.113.9", "192.0.2.1"} // second IP never seen
	_, cidrs, _, err := parseIOCFile(writeTemp(t, "cidr", "198.51.100.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}

	hits, err := matchIOCs(ctx, st, ips, cidrs, []string{"src_ip"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]iocHit{}
	for _, h := range hits {
		byIP[h.Agg.IP] = h
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d; want 2 (203.0.113.9 exact + 198.51.100.42 via CIDR): %+v", len(hits), hits)
	}
	ex, ok := byIP["203.0.113.9"]
	if !ok || ex.ViaCIDR || ex.Agg.Count != 2 || ex.Agg.MaxSeverity != event.SeverityCritical {
		t.Errorf("exact hit wrong: %+v", ex)
	}
	cx, ok := byIP["198.51.100.42"]
	if !ok || !cx.ViaCIDR || cx.Indicator != "198.51.100.0/24" || cx.Agg.Count != 1 {
		t.Errorf("cidr hit wrong: %+v", cx)
	}
	if _, ok := byIP["8.8.8.8"]; ok {
		t.Error("8.8.8.8 is not an indicator but was reported as a hit")
	}
}

func TestCheckIOCsCommandEndToEnd(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if e := st.Insert(context.Background(), &event.Event{
		ID: "x1", Time: time.Now().UTC(), Sensor: "s", RuleID: "listener:ssh",
		Severity: event.SeverityHigh, Handler: "ssh",
		Source: event.Endpoint{IP: "203.0.113.9"}, Dest: event.Endpoint{IP: "10.0.0.1", Port: 22}, Proto: "tcp",
	}); e != nil {
		t.Fatal(e)
	}
	st.Close()

	cfgPath := writeTemp(t, "config.yaml", "sensor:\n  data_dir: "+dir+"\n")
	iocPath := writeTemp(t, "iocs.txt", "203.0.113.9\n192.0.2.0/24\n")

	out, err := captureStdout(t, func() error {
		return cmdCheckIOCs([]string{"-c", cfgPath, "--file", iocPath, "--format", "json"})
	})
	if err != nil {
		t.Fatalf("cmdCheckIOCs: %v (out=%s)", err, out)
	}
	var res struct {
		HitCount int `json:"hit_count"`
		Hits     []struct {
			IP        string `json:"ip"`
			MatchedIn string `json:"matched_in"`
			Events    int    `json:"events"`
		} `json:"hits"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out)
	}
	if res.HitCount != 1 || len(res.Hits) != 1 || res.Hits[0].IP != "203.0.113.9" ||
		res.Hits[0].Events != 1 || res.Hits[0].MatchedIn != "src" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestMatchIOCsMatchFields(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	seed := func(id, src, dst string) {
		if e := st.Insert(ctx, &event.Event{
			ID: id, Time: now, Sensor: "s", RuleID: "listener:ssh", Severity: event.SeverityHigh,
			Handler: "ssh", Source: event.Endpoint{IP: src}, Dest: event.Endpoint{IP: dst, Port: 22}, Proto: "tcp",
		}); e != nil {
			t.Fatal(e)
		}
	}
	// 1.1.1.1 only ever a source; 2.2.2.2 only ever a destination (e.g. an
	// egress/outbound event target); 3.3.3.3 appears as both.
	seed("e1", "1.1.1.1", "10.0.0.1")
	seed("e2", "9.9.9.9", "2.2.2.2")
	seed("e3", "3.3.3.3", "10.0.0.1")
	seed("e4", "9.9.9.9", "3.3.3.3")

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	run := func(cols []string) map[string]iocHit {
		hits, err := matchIOCs(ctx, st, ips, nil, cols, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]iocHit{}
		for _, h := range hits {
			m[h.Agg.IP] = h
		}
		return m
	}

	// src: only 1.1.1.1 and 3.3.3.3 (as source).
	src := run([]string{"src_ip"})
	if len(src) != 2 || src["1.1.1.1"].Fields != "src" || src["3.3.3.3"].Fields != "src" {
		t.Errorf("match=src wrong: %+v", src)
	}
	if _, ok := src["2.2.2.2"]; ok {
		t.Error("match=src should not match a destination-only IP")
	}

	// dst: only 2.2.2.2 and 3.3.3.3 (as destination).
	dst := run([]string{"dst_ip"})
	if len(dst) != 2 || dst["2.2.2.2"].Fields != "dst" || dst["3.3.3.3"].Fields != "dst" {
		t.Errorf("match=dst wrong: %+v", dst)
	}

	// any: all three; 3.3.3.3 matched in both fields with merged count (2).
	any := run([]string{"src_ip", "dst_ip"})
	if len(any) != 3 {
		t.Fatalf("match=any should match all three: %+v", any)
	}
	if any["3.3.3.3"].Fields != "src+dst" || any["3.3.3.3"].Agg.Count != 2 {
		t.Errorf("match=any 3.3.3.3 should be src+dst with 2 events: %+v", any["3.3.3.3"])
	}
	if any["1.1.1.1"].Fields != "src" || any["2.2.2.2"].Fields != "dst" {
		t.Errorf("match=any field attribution wrong: %+v", any)
	}
}

func TestAggregateIPsEmpty(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// No events + no IPs → empty map, no error. Invalid column → error.
	m, err := st.AggregateIPs(context.Background(), nil, "src_ip", time.Time{})
	if err != nil || len(m) != 0 {
		t.Fatalf("AggregateIPs(nil) = %v, %v; want empty, nil", m, err)
	}
	if _, err := st.AggregateIPs(context.Background(), []string{"1.2.3.4"}, "meta_json", time.Time{}); err == nil {
		t.Error("AggregateIPs with a non-ip column should error")
	}
}

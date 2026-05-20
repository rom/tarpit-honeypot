package scananalysis

import (
	"testing"
	"time"
)

func TestClassifyPayloadConnectScan(t *testing.T) {
	v := ClassifyPayload(nil, "http")
	if !v.ConnectScan {
		t.Error("empty payload should be a connect scan")
	}
	if v.VersionProbe {
		t.Error("bare connect must not be a version probe")
	}
}

func TestClassifyNmapServiceProbes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		probe   string
	}{
		{"GetRequest", "GET / HTTP/1.0\r\n\r\n", "GetRequest"},
		{"HTTPOptions", "OPTIONS / HTTP/1.0\r\n\r\n", "HTTPOptions"},
		{"NULL", "\r\n\r\n", "NULL"},
		{"Help", "HELP\r\n", "Help"},
		{"GenericLines", "STATS\r\n", "GenericLines"},
	}
	for _, tc := range cases {
		v := ClassifyPayload([]byte(tc.payload), "http")
		if v.NmapProbe != tc.probe {
			t.Errorf("%s: NmapProbe = %q; want %q", tc.name, v.NmapProbe, tc.probe)
		}
		if !v.VersionProbe {
			t.Errorf("%s: expected VersionProbe", tc.name)
		}
	}
}

func TestClassifyNSEScripts(t *testing.T) {
	cases := []struct {
		payload string
		script  string
	}{
		{"GET /nmaplowercheck1234 HTTP/1.1\r\n", "http-nmap-probe"},
		{"GET /.git/config HTTP/1.1\r\n", "http-vcs-discovery"},
		{"GET /robots.txt HTTP/1.1\r\n", "http-robots"},
		{"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 nmap\r\n", "nse-generic"},
	}
	for _, tc := range cases {
		v := ClassifyPayload([]byte(tc.payload), "http")
		if v.NSEScript != tc.script {
			t.Errorf("payload %q: NSEScript = %q; want %q", tc.payload, v.NSEScript, tc.script)
		}
	}
}

func TestEstimateTiming(t *testing.T) {
	d := func(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }
	cases := []struct {
		gaps []time.Duration
		want string
	}{
		{nil, "unknown"},
		{[]time.Duration{5 * time.Minute}, "-T0 paranoid"},
		{[]time.Duration{12 * time.Second}, "-T1 sneaky"},
		{[]time.Duration{d(350)}, "-T2 polite"},
		{[]time.Duration{d(50)}, "-T3 normal"},
		{[]time.Duration{d(10)}, "-T4 aggressive"},
		{[]time.Duration{d(1)}, "-T5 insane"},
	}
	for _, tc := range cases {
		if got := estimateTiming(tc.gaps); got != tc.want {
			t.Errorf("estimateTiming(%v) = %q; want %q", tc.gaps, got, tc.want)
		}
	}
}

func TestTrackerThresholdAndAggressive(t *testing.T) {
	tr := NewTracker(5 * time.Minute)
	base := time.Unix(1_700_000_000, 0)
	ports := []int{80, 443, 22, 21, 8080, 3306}
	var result *Result
	for i := 0; i < MinConnsForVerdict; i++ {
		v := PayloadVerdict{}
		switch i {
		case 0:
			v.VersionProbe = true
		case 1:
			v.NSEScript = "http-robots"
		}
		r := tr.Observe(Observation{
			SourceIP: "203.0.113.7",
			DestPort: ports[i],
			Handler:  "http",
			Time:     base.Add(time.Duration(i) * 40 * time.Millisecond),
			Verdict:  v,
		})
		if i < MinConnsForVerdict-1 && r != nil {
			t.Fatalf("emitted early at conn %d", i+1)
		}
		if r != nil {
			result = r
		}
	}
	if result == nil {
		t.Fatal("expected a Result at the threshold")
	}
	if result.Conns != MinConnsForVerdict {
		t.Errorf("Conns = %d; want %d", result.Conns, MinConnsForVerdict)
	}
	if result.DistinctPorts != len(ports) {
		t.Errorf("DistinctPorts = %d; want %d", result.DistinctPorts, len(ports))
	}
	if !result.VersionScan {
		t.Error("expected VersionScan")
	}
	if !result.Aggressive {
		t.Error("expected Aggressive (-A): version + NSE + >=4 ports")
	}
	if result.TimingProfile != "-T3 normal" {
		t.Errorf("TimingProfile = %q; want -T3 normal", result.TimingProfile)
	}
	// Once emitted, the source should not emit again.
	if again := tr.Observe(Observation{SourceIP: "203.0.113.7", DestPort: 9000, Time: base.Add(time.Second)}); again != nil {
		t.Error("source emitted a second Result; want at-most-once")
	}
}

func TestTrackerOSScanFromHint(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var result *Result
	for i := 0; i < MinConnsForVerdict; i++ {
		r := tr.Observe(Observation{
			SourceIP:    "198.51.100.5",
			DestPort:    1000 + i,
			Time:        base.Add(time.Duration(i) * 10 * time.Millisecond),
			OSProbeHint: true,
		})
		if r != nil {
			result = r
		}
	}
	if result == nil || !result.OSScan {
		t.Fatalf("expected OSScan from OS-probe hints; got %+v", result)
	}
}

func TestTrackerIgnoresEmptySource(t *testing.T) {
	tr := NewTracker(time.Minute)
	if r := tr.Observe(Observation{SourceIP: "", DestPort: 80}); r != nil {
		t.Error("empty source must be ignored")
	}
}

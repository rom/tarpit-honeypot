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

func TestClassifyMoreNmapProbes(t *testing.T) {
	cases := []struct {
		payload string
		probe   string
	}{
		{"OPTIONS / RTSP/1.0\r\n\r\n", "RTSPRequest"},
		{"OPTIONS sip:nm SIP/2.0\r\n", "SIPOptions"},
		{"\x16\x03\x01\x00\x50", "SSLSessionReq"},
		{"JRMI\x00\x02K", "JavaRMI"},
	}
	for _, tc := range cases {
		v := ClassifyPayload([]byte(tc.payload), "tcp")
		if v.NmapProbe != tc.probe {
			t.Errorf("payload %q: NmapProbe = %q; want %q", tc.payload, v.NmapProbe, tc.probe)
		}
		if !v.VersionProbe {
			t.Errorf("payload %q: expected VersionProbe", tc.payload)
		}
	}
}

func TestClassifyToolFingerprint(t *testing.T) {
	cases := []struct {
		payload  string
		tool     string
		vulnScan bool
	}{
		{"GET / HTTP/1.1\r\nUser-Agent: masscan/1.3\r\n", "masscan", false},
		{"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n", "zgrab", false},
		{"GET /x HTTP/1.1\r\nUser-Agent: Nuclei - Open-source\r\n", "nuclei", true},
		{"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n", "sqlmap", true},
		{"HEAD / HTTP/1.1\r\nUser-Agent: Mozilla/5.00 (Nikto/2.5)\r\n", "nikto", true},
	}
	for _, tc := range cases {
		v := ClassifyPayload([]byte(tc.payload), "http")
		if v.Tool != tc.tool {
			t.Errorf("payload %q: Tool = %q; want %q", tc.payload, v.Tool, tc.tool)
		}
		if v.VulnScan != tc.vulnScan {
			t.Errorf("payload %q: VulnScan = %v; want %v", tc.payload, v.VulnScan, tc.vulnScan)
		}
	}
	// A benign browser request fingerprints no tool.
	if v := ClassifyPayload([]byte("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11)\r\n"), "http"); v.Tool != "" {
		t.Errorf("benign UA fingerprinted a tool: %q", v.Tool)
	}
}

func TestClassifyNSEVulnScan(t *testing.T) {
	cases := []struct {
		payload string
		script  string
	}{
		{"GET /.env HTTP/1.1\r\n", "http-config-leak"},
		{"GET /manager/html HTTP/1.1\r\n", "http-tomcat-manager"},
		{"GET /actuator/env HTTP/1.1\r\n", "http-spring-actuator"},
		{"POST /wp-login.php HTTP/1.1\r\n", "http-wordpress"},
		{"GET /HNAP1/ HTTP/1.1\r\n", "http-hnap"},
	}
	for _, tc := range cases {
		v := ClassifyPayload([]byte(tc.payload), "http")
		if v.NSEScript != tc.script {
			t.Errorf("payload %q: NSEScript = %q; want %q", tc.payload, v.NSEScript, tc.script)
		}
		if !v.VulnScan {
			t.Errorf("payload %q: expected VulnScan", tc.payload)
		}
	}
}

func TestClassifyPortOrder(t *testing.T) {
	cases := []struct {
		seq  []int
		want string
	}{
		{[]int{1, 2, 3}, ""}, // too few
		{[]int{21, 22, 23, 80, 443}, "sequential"},
		{[]int{443, 80, 22, 21}, "sequential"}, // monotonic descending
		{[]int{443, 21, 8080, 22, 3389}, "random"},
	}
	for _, tc := range cases {
		if got := classifyPortOrder(tc.seq); got != tc.want {
			t.Errorf("classifyPortOrder(%v) = %q; want %q", tc.seq, got, tc.want)
		}
	}
}

func TestScanShape(t *testing.T) {
	cases := []struct {
		hosts, ports int
		want         string
	}{
		{1, 8, "vertical"},
		{6, 1, "horizontal"},
		{6, 8, "block"},
		{1, 1, ""},
	}
	for _, tc := range cases {
		if got := scanShape(tc.hosts, tc.ports); got != tc.want {
			t.Errorf("scanShape(%d,%d) = %q; want %q", tc.hosts, tc.ports, got, tc.want)
		}
	}
}

func TestPrimaryToolRanking(t *testing.T) {
	// A vuln scanner outranks a mass version sweeper in the same chain.
	got := primaryTool(map[string]bool{"masscan": true, "nuclei": true})
	if got != "nuclei" {
		t.Errorf("primaryTool = %q; want nuclei (vuln scanner outranks mass sweep)", got)
	}
	if got := primaryTool(nil); got != "" {
		t.Errorf("primaryTool(nil) = %q; want empty", got)
	}
}

func TestTrackerHorizontalSweepAndConfidence(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var result *Result
	// One source masscan-sweeping port 445 across many honeynet hosts.
	for i := 0; i < MinConnsForVerdict; i++ {
		r := tr.Observe(Observation{
			SourceIP: "203.0.113.50",
			DestIP:   "10.0.0." + itoa(10+i),
			DestPort: 445,
			Handler:  "smb",
			Time:     base.Add(time.Duration(i) * 5 * time.Millisecond),
			Verdict:  PayloadVerdict{Tool: "masscan", VersionProbe: true},
		})
		if r != nil {
			result = r
		}
	}
	if result == nil {
		t.Fatal("expected a Result at threshold")
	}
	if result.DistinctHosts != MinConnsForVerdict {
		t.Errorf("DistinctHosts = %d; want %d", result.DistinctHosts, MinConnsForVerdict)
	}
	if result.ScanShape != "horizontal" {
		t.Errorf("ScanShape = %q; want horizontal", result.ScanShape)
	}
	if result.Tool != "masscan" {
		t.Errorf("Tool = %q; want masscan", result.Tool)
	}
	if result.Confidence < 50 {
		t.Errorf("Confidence = %d; want a high score for a tool-fingerprinted sweep", result.Confidence)
	}
}

// itoa avoids pulling strconv into the test for a tiny positive int.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

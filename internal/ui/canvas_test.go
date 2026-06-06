package ui

import (
	"html/template"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func sampleCanvasConfig() *config.Config {
	return &config.Config{
		Listeners: []config.Listener{
			{ID: "ssh", Proto: "tcp", Bind: "0.0.0.0:22", Handler: "ssh", Mode: "banner", Archetype: "debian 12"},
			{ID: "web", Proto: "tcp", Bind: "0.0.0.0:443", Handler: "https", Mode: "tarpit", Capture: true},
			{ID: "ntp", Proto: "udp", Bind: "0.0.0.0:123", Handler: "ntp", Mode: "banner"},
		},
		Sniffer: config.Sniffer{Enabled: true, Interface: "eth0", TCPScan: config.TCPScanCfg{Enabled: true}},
		Devices: config.Devices{Enabled: true, Learn: true},
		Risk:    config.RiskScoring{Enabled: true},
		Correlate: config.Correlate{
			PortScan:   config.CorrPortScan{Enabled: true},
			BruteForce: config.CorrBruteForce{Enabled: true},
		},
		Honeynets: []config.Honeynet{
			{ID: "corp", ARP: config.ARPResponderCfg{Enabled: true}, ICMP: config.ICMPResponderCfg{Enabled: true}},
		},
		Channels: []config.Channel{
			{ID: "hook", Type: "webhook"},
			{ID: "local", Type: "sqlite"},
		},
	}
}

func TestBuildConfigCanvasListeners(t *testing.T) {
	cv := buildConfigCanvas(sampleCanvasConfig())
	if cv.ListenerCount != 3 || cv.TCPCount != 2 || cv.UDPCount != 1 {
		t.Fatalf("counts: total=%d tcp=%d udp=%d", cv.ListenerCount, cv.TCPCount, cv.UDPCount)
	}
	// TCP listeners sort before UDP, by port. First card = ssh/22.
	first := cv.Listeners[0]
	if first.Port != 22 || first.Service != "ssh" || first.Proto != "tcp" {
		t.Errorf("first card = %+v; want tcp/22/ssh", first)
	}
	// https/443 must be badged TLS and tarpit.
	var web portCard
	for _, p := range cv.Listeners {
		if p.Port == 443 {
			web = p
		}
	}
	if !web.TLS || web.Mode != "tarpit" || !web.Capture {
		t.Errorf("https card = %+v; want tls+tarpit+capture", web)
	}
	// UDP ntp sorts last.
	last := cv.Listeners[len(cv.Listeners)-1]
	if last.Proto != "udp" || last.Port != 123 {
		t.Errorf("last card = %+v; want udp/123", last)
	}
}

func TestBuildConfigCanvasCollectors(t *testing.T) {
	cv := buildConfigCanvas(sampleCanvasConfig())
	state := map[string]bool{}
	detail := map[string]string{}
	for _, c := range cv.Collectors {
		state[c.Name] = c.Active
		detail[c.Name] = c.Detail
	}
	wantActive := []string{
		"Packet sniffer (ARP/L2 scan)", "TCP stealth-scan detector",
		"Device inventory", "Risk scoring", "Correlation engine",
		"ARP responder", "ICMP echo responder", "Event forwarding",
		// always-on / config-derived collectors:
		"Scan analysis",          // always running
		"Fuzzing/DoS classifier", // always running
		"MAC vendor (OUI)",       // always available (built-in table)
		"Client fingerprinting",  // ssh + https listeners present
		"PCAP capture",           // https listener has capture: true
	}
	for _, n := range wantActive {
		if !state[n] {
			t.Errorf("collector %q should be active", n)
		}
	}
	wantOff := []string{
		"GOOSE monitor (IEC 61850)", "GeoIP enrichment", "Payload capture",
		"PROFINET DCP responder",
		// new enrichment collectors, all opt-in and unset in the sample:
		"Threat-intel tagging", "Tor-exit tagging", "Network classification",
	}
	for _, n := range wantOff {
		if state[n] {
			t.Errorf("collector %q should be inactive", n)
		}
	}
	if detail["Correlation engine"] != "2 detectors" {
		t.Errorf("correlation detail = %q; want 2 detectors", detail["Correlation engine"])
	}
	// sqlite is a local sink, not an outbound channel — only the webhook counts.
	if detail["Event forwarding"] != "1 outbound channel" {
		t.Errorf("forwarding detail = %q; want 1 outbound channel", detail["Event forwarding"])
	}
	if cv.ActiveCollector == 0 {
		t.Error("expected some active collectors")
	}
}

func TestConfigCanvasRenders(t *testing.T) {
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return 0 }, "nvd", "", true, navFuncs{has: func(string) bool { return true }, enabled: func(string) bool { return true }})).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	page := configPage{YAML: "sensor:\n  name: demo\n", Canvas: buildConfigCanvas(sampleCanvasConfig())}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "config", page); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		"infrastructure canvas", "pcard", "Packet sniffer", "Network responders",
		">22<", "ssh", "Correlation engine", `href="/api/config/canvas"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered config page missing %q", want)
		}
	}
}

func TestBuildConfigCanvasNil(t *testing.T) {
	cv := buildConfigCanvas(nil)
	if cv.ListenerCount != 0 || len(cv.Collectors) != 0 {
		t.Errorf("nil config should yield empty canvas: %+v", cv)
	}
}

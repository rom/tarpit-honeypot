package enrich

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestSubnetKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.45":    "203.0.113.0/24",
		"8.8.8.8":         "8.8.8.0/24",
		"2001:db8:1:2::5": "2001:db8:1::/48",
	}
	for in, want := range cases {
		a := netip.MustParseAddr(in)
		if got := subnetKey(a); got != want {
			t.Errorf("subnetKey(%s) = %q; want %q", in, got, want)
		}
	}
}

func TestConnType(t *testing.T) {
	cases := map[string]string{
		"host-1-2-3-4.dynamic.example.net": "residential",
		"pool-72-x.isp.example":            "residential",
		"1-2-3-4.cust.example.com":         "residential",
		"5-6-7-8.someisp.net":              "residential", // dashed-IP pattern
		"srv12.static.hoster.example":      "hosting",
		"vps-9.cloud.example":              "hosting",
		"mail.example.com":                 "", // no signal
		"":                                 "",
	}
	for in, want := range cases {
		if got := connType(in); got != want {
			t.Errorf("connType(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestActorID(t *testing.T) {
	if got := actorID(map[string]any{"ja4": "t13d_x", "ja3": "abc"}); got != "ja4:t13d_x" {
		t.Errorf("ja4 should win: %q", got)
	}
	if got := actorID(map[string]any{"hassh": "h1"}); got != "hassh:h1" {
		t.Errorf("hassh fallback: %q", got)
	}
	ua := actorID(map[string]any{"user_agent": "curl/8.0"})
	if ua == "" || ua[:3] != "ua:" || len(ua) != 3+12 {
		t.Errorf("UA hash form wrong: %q", ua)
	}
	// Same UA -> same id (stable).
	if actorID(map[string]any{"user_agent": "curl/8.0"}) != ua {
		t.Error("UA actor id must be stable")
	}
	if actorID(map[string]any{}) != "" {
		t.Error("no fingerprint/UA -> empty")
	}
}

func TestMetaASNKey(t *testing.T) {
	if got := metaASNKey(map[string]any{"asn": uint32(13335)}); got != "AS13335" {
		t.Errorf("uint32 asn: %q", got)
	}
	if got := metaASNKey(map[string]any{"asn": 7922}); got != "AS7922" {
		t.Errorf("int asn: %q", got)
	}
	if got := metaASNKey(map[string]any{}); got != "" {
		t.Errorf("absent asn: %q", got)
	}
}

func TestTargeting(t *testing.T) {
	cases := []struct{ rule, handler, want string }{
		{"webapp:wp-login-bruteforce", "http", "web-cms"},
		{"", "modbus", "ics-ot"},
		{"", "ssh", "remote-access"},
		{"", "postgres", "database"},
		{"", "kubernetes_api", "cloud-devops"},
		{"", "tr069", "iot-edge"},
		{"listener:x", "raw", ""},
	}
	for _, c := range cases {
		ev := &event.Event{RuleID: c.rule, Handler: c.handler}
		if got := targeting(ev); got != c.want {
			t.Errorf("targeting(%q,%q) = %q; want %q", c.rule, c.handler, got, c.want)
		}
	}
}

// decorateAttributes end-to-end via a constructed enricher: subnet key,
// conn-type, geo-risk, local hour, anonymized rollup, novelty, actor id.
func TestDecorateAttributes(t *testing.T) {
	e, err := New(Config{RiskCountries: []string{"ru", "KP"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("203.0.113.45")
	mk := func() *event.Event {
		return &event.Event{
			Time:   time.Date(2026, 1, 2, 15, 0, 0, 0, time.UTC),
			RuleID: "webapp:wp-scan", Handler: "http",
			Source: event.Endpoint{IP: "203.0.113.45"},
			Meta: map[string]any{
				"rdns": "1-2-3-4.dynamic.isp.ru", "geo_country": "RU",
				"geo_timezone": "UTC", "asn": uint32(64500),
				"tor_exit": true, "ja4": "t13d_fp",
			},
		}
	}

	ev := mk()
	e.decorateAttributes(ev, addr)
	checks := map[string]any{
		"src_net": "203.0.113.0/24", "conn_type": "residential",
		"geo_risk": true, "src_local_hour": 15, "anonymized": true,
		"novel_asn": true, "novel_subnet": true, "actor_id": "ja4:t13d_fp",
		"novel_fingerprint": true, "targeting": "web-cms",
	}
	for k, want := range checks {
		if ev.Meta[k] != want {
			t.Errorf("meta[%q] = %v; want %v", k, ev.Meta[k], want)
		}
	}

	// A second event from the same ASN / subnet / fingerprint is no longer novel.
	ev2 := mk()
	e.decorateAttributes(ev2, addr)
	for _, k := range []string{"novel_asn", "novel_subnet", "novel_fingerprint"} {
		if _, ok := ev2.Meta[k]; ok {
			t.Errorf("second sighting still flagged %q", k)
		}
	}
}

func TestFirstSightClearsAtCap(t *testing.T) {
	e, _ := New(Config{})
	if !e.firstSight(e.seenASN, "AS1") {
		t.Fatal("first sight should be true")
	}
	if e.firstSight(e.seenASN, "AS1") {
		t.Fatal("repeat sight should be false")
	}
	if e.firstSight(e.seenASN, "") {
		t.Error("empty key is never novel")
	}
}

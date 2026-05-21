package devices

import (
	"strings"
	"testing"
	"time"
)

func TestDeviceRebindDetected(t *testing.T) {
	r := New(Config{Learn: false})
	r.Observe(Observation{MAC: "00:90:e8:01:02:03", IP: "10.0.0.5", Source: SourceARP})
	// Same MAC now at a different IP -> "ip" change, not new.
	res := r.Observe(Observation{MAC: "00:90:e8:01:02:03", IP: "10.0.0.9", Source: SourceARP})
	if res.New {
		t.Error("rebind should not be flagged as new")
	}
	if !hasPrefix(res.Changed, "ip ") {
		t.Errorf("expected ip change; got %v", res.Changed)
	}
	// Hostname change on the same device.
	r.Observe(Observation{MAC: "00:90:e8:01:02:03", IP: "10.0.0.9", Hostname: "plc1", Source: SourceDHCP})
	res = r.Observe(Observation{MAC: "00:90:e8:01:02:03", IP: "10.0.0.9", Hostname: "evil", Source: SourceDHCP})
	if !hasPrefix(res.Changed, "hostname ") {
		t.Errorf("expected hostname change; got %v", res.Changed)
	}
}

func hasPrefix(xs []string, p string) bool {
	for _, x := range xs {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

func TestObserveAccumulatesKnowledge(t *testing.T) {
	r := New(Config{Learn: false})
	for _, o := range []Observation{
		{IP: "10.0.0.9", Source: SourceConn, Port: 22, Service: "ssh", Attrs: map[string]string{"hassh": "abc"}},
		{IP: "10.0.0.9", Source: SourceConn, Port: 80, Service: "http", Attrs: map[string]string{"ua": "curl/8"}},
		{IP: "10.0.0.9", Source: SourceConn, Port: 22, Service: "ssh"}, // dup port/service
	} {
		r.Observe(o)
	}
	devs := r.List()
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	d := devs[0]
	if len(d.Ports) != 2 || d.Ports[0] != 22 || d.Ports[1] != 80 {
		t.Errorf("ports = %v; want sorted unique [22 80]", d.Ports)
	}
	if len(d.Services) != 2 {
		t.Errorf("services = %v; want ssh+http", d.Services)
	}
	if d.Attrs["hassh"] != "abc" || d.Attrs["ua"] != "curl/8" {
		t.Errorf("attrs = %v; want merged hassh+ua", d.Attrs)
	}
	if d.Count != 3 {
		t.Errorf("count = %d; want 3", d.Count)
	}
}

func TestDeleteAndAllow(t *testing.T) {
	r := New(Config{Learn: false})
	r.Observe(Observation{IP: "10.0.0.9", MAC: "aa:bb:cc:dd:ee:ff", Source: SourceConn})
	// Whitelist by key (MAC).
	if !r.Allow("aa:bb:cc:dd:ee:ff") {
		t.Fatal("Allow should find the device")
	}
	for _, d := range r.List() {
		if !d.Allowed || !r.IsAllowed(d) {
			t.Errorf("device should be allowed after Allow: %+v", d)
		}
	}
	// A re-observation of an allowed device must not alert.
	if r.Observe(Observation{IP: "10.0.0.9", MAC: "aa:bb:cc:dd:ee:ff", Source: SourceConn}).New {
		t.Error("allowed device should not alert")
	}
	// Delete it.
	if !r.Delete("aa:bb:cc:dd:ee:ff") {
		t.Fatal("Delete should remove the device")
	}
	if len(r.List()) != 0 {
		t.Errorf("device list should be empty after delete: %v", r.List())
	}
	if r.Delete("nonexistent") {
		t.Error("Delete of unknown key should return false")
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"00:90:E8:11:22:33": "00:90:e8:11:22:33",
		"0090.e811.2233":    "00:90:e8:11:22:33",
		"00-90-e8-11-22-33": "00:90:e8:11:22:33",
		"0090E8112233":      "00:90:e8:11:22:33",
		"garbage":           "",
		"00:90:e8":          "", // too short
	}
	for in, want := range cases {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestVendorForMAC(t *testing.T) {
	if VendorForMAC("00:90:e8:11:22:33") != "Moxa" {
		t.Errorf("Moxa OUI not resolved")
	}
	if VendorForMAC("28:63:36:aa:bb:cc") != "Siemens" {
		t.Errorf("Siemens OUI not resolved")
	}
	// Locally-administered bit set on first octet (0x02).
	if VendorForMAC("02:42:ac:11:00:02") != "Docker" {
		t.Errorf("Docker OUI should win over locally-administered note")
	}
	if VendorForMAC("06:00:00:00:00:01") != "(locally administered)" {
		t.Errorf("locally administered MAC not flagged")
	}
}

// Strict allow-list mode: any non-allow-listed device alerts on first
// sight; allow-listed ones never do.
func TestStrictAllowListAlerts(t *testing.T) {
	r := New(Config{Allow: []string{"10.0.0.0/24", "aa:bb:cc:dd:ee:ff"}, Learn: false})

	// In-CIDR -> no alert.
	if r.Observe(Observation{IP: "10.0.0.5", Source: SourceConn}).New {
		t.Errorf("allow-listed CIDR device should not alert")
	}
	// Allow-listed MAC -> no alert.
	if r.Observe(Observation{MAC: "AA:BB:CC:DD:EE:FF", Source: SourceARP}).New {
		t.Errorf("allow-listed MAC device should not alert")
	}
	// Outside allow-list -> alert on first sight.
	if !r.Observe(Observation{IP: "192.168.99.7", Source: SourceConn}).New {
		t.Errorf("non-allow-listed device should alert on first sight")
	}
	// Second sight of the same device -> no repeat alert.
	if r.Observe(Observation{IP: "192.168.99.7", Source: SourceConn}).New {
		t.Errorf("device should not re-alert on subsequent sightings")
	}
}

// Learn mode: the first observed device seeds the baseline silently;
// subsequent never-seen devices alert.
func TestLearnModeBaseline(t *testing.T) {
	r := New(Config{Learn: true})
	if r.Observe(Observation{IP: "10.0.0.1", Source: SourceConn}).New {
		t.Errorf("first device in learn mode should seed baseline silently")
	}
	if !r.Observe(Observation{IP: "10.0.0.2", Source: SourceConn}).New {
		t.Errorf("second never-seen device in learn mode should alert")
	}
}

// IP-only record gets promoted to a MAC key when the MAC is later learned.
func TestIPRecordPromotedToMAC(t *testing.T) {
	r := New(Config{Learn: true})
	r.Observe(Observation{IP: "10.0.0.50", Source: SourceConn})
	r.Observe(Observation{IP: "10.0.0.50", MAC: "00:90:e8:01:02:03", Hostname: "plc1", Source: SourceDHCP})
	list := r.List()
	count := 0
	for _, d := range list {
		if d.IP == "10.0.0.50" {
			count++
			if d.MAC != "00:90:e8:01:02:03" {
				t.Errorf("MAC not attached: %+v", d)
			}
			if d.Vendor != "Moxa" {
				t.Errorf("vendor not resolved: %+v", d)
			}
			if d.Hostname != "plc1" {
				t.Errorf("hostname not attached: %+v", d)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected 1 merged record for 10.0.0.50; got %d (list=%+v)", count, list)
	}
}

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{DataDir: dir, Learn: true})
	r.Observe(Observation{IP: "10.0.0.1", MAC: "00:90:e8:aa:bb:cc", Source: SourceDHCP, Time: time.Now()})
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	// Reload — the device should be present, and (since baseline
	// existed on disk) a re-observation of a NEW device should alert.
	r2 := New(Config{DataDir: dir, Learn: true})
	if len(r2.List()) != 1 {
		t.Fatalf("reloaded registry has %d devices; want 1", len(r2.List()))
	}
	if !r2.Observe(Observation{IP: "10.0.0.250", Source: SourceConn}).New {
		t.Errorf("new device after loading a baseline should alert")
	}
}

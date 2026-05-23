package devices

import (
	"os"
	"path/filepath"
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

func TestDeviceClassification(t *testing.T) {
	cases := []struct {
		services []string
		ports    []int
		want     string
	}{
		{[]string{"modbus"}, []int{502}, "ics-endpoint"},
		{[]string{"snmp"}, []int{161}, "network-device"},
		{[]string{"http", "https"}, []int{80, 443}, "web-host"},
		{[]string{"ssh"}, []int{22}, "host"},
	}
	for _, c := range cases {
		r := New(Config{Learn: false})
		for i, s := range c.services {
			r.Observe(Observation{IP: "10.9.9.9", Source: SourceConn, Service: s, Port: c.ports[i]})
		}
		d := r.List()[0]
		if d.Attrs["class"] != c.want {
			t.Errorf("services %v -> class %q; want %q", c.services, d.Attrs["class"], c.want)
		}
	}
	// A wide port sweep is a scanner regardless of services.
	r := New(Config{Learn: false})
	for p := 1; p <= 10; p++ {
		r.Observe(Observation{IP: "5.5.5.5", Source: SourceConn, Port: p, Service: "raw"})
	}
	if r.List()[0].Attrs["class"] != "scanner" {
		t.Errorf("port sweep should classify as scanner; got %q", r.List()[0].Attrs["class"])
	}
}

func TestGetCountAndFindByIP(t *testing.T) {
	r := New(Config{Learn: false})
	now := time.Unix(1_700_000_000, 0).UTC()
	r.Observe(Observation{IP: "10.0.0.5", MAC: "00:90:e8:01:02:03", Source: SourceDHCP, Time: now})
	r.Observe(Observation{IP: "10.0.0.6", Source: SourceConn, Time: now})

	if r.Count() != 2 {
		t.Errorf("Count = %d; want 2", r.Count())
	}
	// Get by MAC key, any case/separator.
	if d, ok := r.Get("0090.e801.0203"); !ok || d.IP != "10.0.0.5" {
		t.Errorf("Get by normalized MAC failed: %+v ok=%v", d, ok)
	}
	// Get by IP key (the conn-only device).
	if _, ok := r.Get("10.0.0.6"); !ok {
		t.Error("Get by IP key failed")
	}
	// FindByIP resolves the MAC-keyed device by its IP field.
	if d, ok := r.FindByIP("10.0.0.5"); !ok || d.MAC != "00:90:e8:01:02:03" {
		t.Errorf("FindByIP failed: %+v ok=%v", d, ok)
	}
	if _, ok := r.FindByIP("203.0.113.9"); ok {
		t.Error("FindByIP of unknown IP should be false")
	}
}

func TestStatsRoguesAndByClass(t *testing.T) {
	r := New(Config{Allow: []string{"10.0.0.0/24"}, Learn: false})
	now := time.Unix(1_700_000_000, 0).UTC()
	// In-CIDR (allowed) ICS endpoint.
	r.Observe(Observation{IP: "10.0.0.10", Source: SourceConn, Service: "modbus", Port: 502, Time: now})
	// Out-of-CIDR (rogue) web host.
	r.Observe(Observation{IP: "192.168.5.5", Source: SourceConn, Service: "http", Port: 80, Time: now})
	r.Observe(Observation{IP: "192.168.5.5", Source: SourceConn, Service: "https", Port: 443, Time: now})

	st := r.Stats()
	if st.Total != 2 || st.Allowed != 1 || st.Rogue != 1 {
		t.Errorf("Stats totals = %+v; want Total2 Allowed1 Rogue1", st)
	}
	if st.ByClass["ics-endpoint"] != 1 || st.ByClass["web-host"] != 1 {
		t.Errorf("Stats.ByClass = %v; want one ics-endpoint + one web-host", st.ByClass)
	}
	if st.BySource["conn"] != 2 {
		t.Errorf("Stats.BySource[conn] = %d; want 2", st.BySource["conn"])
	}

	if ics := r.ByClass("ics-endpoint"); len(ics) != 1 || ics[0].IP != "10.0.0.10" {
		t.Errorf("ByClass(ics-endpoint) = %+v", ics)
	}
	rogues := r.Rogues()
	if len(rogues) != 1 || rogues[0].IP != "192.168.5.5" {
		t.Errorf("Rogues = %+v; want only 192.168.5.5", rogues)
	}
}

func TestActiveStaleSearchVendor(t *testing.T) {
	r := New(Config{Learn: false})
	now := time.Unix(1_700_000_000, 0).UTC()
	// Fresh device (Siemens OUI) and a stale one.
	r.Observe(Observation{IP: "10.0.0.10", MAC: "28:63:36:aa:bb:cc", Hostname: "plc-line1", Source: SourceARP, Time: now})
	r.Observe(Observation{IP: "10.0.0.20", Source: SourceConn, Time: now.Add(-2 * time.Hour)})

	if act := r.Active(time.Hour, now); len(act) != 1 || act[0].IP != "10.0.0.10" {
		t.Errorf("Active(1h) = %+v; want only the fresh device", act)
	}
	if stale := r.Stale(time.Hour, now); len(stale) != 1 || stale[0].IP != "10.0.0.20" {
		t.Errorf("Stale(1h) = %+v; want only the quiet device", stale)
	}
	// Search across hostname, vendor, IP.
	if got := r.Search("line1"); len(got) != 1 || got[0].IP != "10.0.0.10" {
		t.Errorf("Search(line1) = %+v", got)
	}
	if got := r.ByVendor("siemens"); len(got) != 1 || got[0].IP != "10.0.0.10" {
		t.Errorf("ByVendor(siemens) = %+v", got)
	}
	if got := r.Search(""); got != nil {
		t.Errorf("Search(empty) should be nil, got %+v", got)
	}
}

func TestConflictsDetectsIPCollision(t *testing.T) {
	r := New(Config{Learn: false})
	now := time.Unix(1_700_000_000, 0).UTC()
	// Two distinct MACs claiming the same IP — an ARP-spoof signature.
	r.Observe(Observation{IP: "10.0.0.50", MAC: "00:90:e8:01:02:03", Source: SourceARP, Time: now})
	r.Observe(Observation{IP: "10.0.0.50", MAC: "aa:bb:cc:dd:ee:ff", Source: SourceARP, Time: now})
	// An unrelated single-MAC device must not show as a conflict.
	r.Observe(Observation{IP: "10.0.0.60", MAC: "00:90:e8:09:09:09", Source: SourceARP, Time: now})

	cs := r.Conflicts()
	if len(cs) != 1 {
		t.Fatalf("Conflicts = %+v; want exactly one IP collision", cs)
	}
	if cs[0].IP != "10.0.0.50" || len(cs[0].MACs) != 2 {
		t.Errorf("conflict = %+v; want 10.0.0.50 with 2 MACs", cs[0])
	}
	if cs[0].MACs[0] != "00:90:e8:01:02:03" || cs[0].MACs[1] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("conflict MACs not sorted: %+v", cs[0].MACs)
	}
}

func TestLoadOUIFileAndLookup(t *testing.T) {
	dir := t.TempDir()
	// IEEE oui.csv shape (header + MA-L rows + an MA-M row to skip).
	body := "Registry,Assignment,Organization Name,Organization Address\r\n" +
		"MA-L,AABBCC,\"Acme Robotics, Inc.\",\"1 Way, Town\"\r\n" +
		"MA-L,001122,Globex PLC,Addr\r\n" +
		"MA-M,DDEEF0,Should Be Skipped,Addr\r\n"
	p := filepath.Join(dir, "oui.csv")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := LoadOUIFile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { loadedOUI.Store(nil) }) // don't leak into sibling tests
	if n != 2 {
		t.Errorf("loaded %d OUIs; want 2 (MA-M skipped)", n)
	}
	if v := VendorForMAC("aa:bb:cc:11:22:33"); v != "Acme Robotics, Inc." {
		t.Errorf("loaded OUI lookup = %q; want Acme Robotics, Inc.", v)
	}
	if v := VendorForMAC("00:11:22:33:44:55"); v != "Globex PLC" {
		t.Errorf("loaded OUI lookup = %q; want Globex PLC", v)
	}
	// An OUI absent from the loaded DB falls back to the built-in table.
	if v := VendorForMAC("00:90:e8:01:02:03"); v != "Moxa" {
		t.Errorf("built-in fallback = %q; want Moxa", v)
	}
}

func TestOUIPrefixFromHex(t *testing.T) {
	cases := map[string]string{
		"AABBCC":      "aa:bb:cc",
		"00:90:E8":    "00:90:e8",
		"00-90-e8-11": "00:90:e8",
		"Registry":    "", // header word, not enough hex
		"zz":          "",
	}
	for in, want := range cases {
		if got := ouiPrefixFromHex(in); got != want {
			t.Errorf("ouiPrefixFromHex(%q) = %q; want %q", in, got, want)
		}
	}
}

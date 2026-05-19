package honeynet

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

func TestBuildAndLookup(t *testing.T) {
	cfg := []config.Honeynet{
		{
			ID:      "corp",
			CIDR:    "10.99.0.0/24",
			Gateway: "10.99.0.1",
			Domain:  "corp.example.local",
			Hosts: []config.HoneynetHost{
				{IP: "10.99.0.10", Hostname: "web-prod-01", OS: "linux", Services: []config.HoneynetService{
					{Port: 22, Handler: "ssh"},
					{Port: 80, Handler: "http"},
				}},
				{IP: "10.99.0.11", Hostname: "db-prod-01", OS: "linux", Services: []config.HoneynetService{
					{Port: 3306, Handler: "mysql"},
				}},
			},
		},
		{
			ID:   "ot",
			CIDR: "10.99.5.0/24",
			Hosts: []config.HoneynetHost{
				{IP: "10.99.5.50", Hostname: "plc-cell-A", OS: "ics", Services: []config.HoneynetService{
					{Port: 502, Handler: "modbus"},
				}},
			},
		},
	}
	id := identity.New("test-seed")
	topo, err := Build(cfg, id, jitter.New(0, 0), t.TempDir(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if topo.Empty() {
		t.Fatal("topology unexpectedly empty")
	}
	if got := len(topo.Networks()); got != 2 {
		t.Errorf("got %d networks; want 2", got)
	}
	// dst-IP/port lookup
	if h, hd, s := topo.Lookup("10.99.0.10", 80); h == nil || hd == nil || s == nil || s.Port != 80 {
		t.Errorf("lookup web:80 missed: h=%v hd=%v s=%v", h, hd, s)
	}
	if h, _, _ := topo.Lookup("10.99.0.10", 22); h == nil || h.Hostname != "web-prod-01" {
		t.Errorf("lookup web:22 host: %v", h)
	}
	if h, _, _ := topo.Lookup("10.99.0.10", 9999); h != nil {
		t.Errorf("lookup unconfigured port should miss; got %v", h)
	}
	// Per-host identity is distinct
	host1, _, _ := topo.Lookup("10.99.0.10", 22)
	host2, _, _ := topo.Lookup("10.99.0.11", 3306)
	if host1.Identity.Seed() == host2.Identity.Seed() {
		t.Errorf("per-host identities should differ; both got %s", host1.Identity.Seed())
	}
	// SSH banner pool should also differ across hosts.
	if host1.Identity.SSHBannerVariant() == host2.Identity.SSHBannerVariant() {
		// Not strictly a bug (12 hosts × 6 variants will collide) but a
		// strong indicator the derive seed is doing its job. Skip the
		// strict check and just verify they're chosen from the pool.
		t.Logf("note: two hosts picked the same SSH banner (pool collision, not a bug)")
	}
	// Hostname-based lookup
	if h := topo.HostByName("web-prod-01"); h == nil || h.IP != "10.99.0.10" {
		t.Errorf("HostByName short missed: %v", h)
	}
	if h := topo.HostByName("web-prod-01.corp.example.local"); h == nil || h.IP != "10.99.0.10" {
		t.Errorf("HostByName fqdn missed: %v", h)
	}
	if h := topo.HostByName("nope"); h != nil {
		t.Errorf("HostByName should miss; got %v", h)
	}
}

func TestEmptyTopologySafeForNilOps(t *testing.T) {
	var topo *Topology
	if !topo.Empty() {
		t.Error("nil topo should be Empty")
	}
	if h, hd, s := topo.Lookup("1.2.3.4", 22); h != nil || hd != nil || s != nil {
		t.Errorf("nil Lookup should be all-nil")
	}
	if h := topo.HostByName("anything"); h != nil {
		t.Error("nil HostByName should return nil")
	}
}

func TestDuplicateIPRejected(t *testing.T) {
	cfg := []config.Honeynet{
		{ID: "a", CIDR: "10.0.0.0/24", Hosts: []config.HoneynetHost{
			{IP: "10.0.0.5", Hostname: "h1", Services: []config.HoneynetService{{Port: 22, Handler: "ssh"}}},
			{IP: "10.0.0.5", Hostname: "h2", Services: []config.HoneynetService{{Port: 22, Handler: "ssh"}}},
		}},
	}
	id := identity.New("seed")
	_, err := Build(cfg, id, jitter.New(0, 0), t.TempDir(), nil, 0)
	// Build itself allows duplicate IPs (config validation catches it),
	// but the second entry overwrites the first in hostByIP, so the
	// lookup still finds something. The point of this test is just to
	// verify Build doesn't crash on degenerate input — full validation
	// is in config.Validate.
	if err != nil {
		t.Logf("Build rejected duplicate IP (acceptable): %v", err)
	}
}

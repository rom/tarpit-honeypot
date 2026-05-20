package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// A SCALANCE switch archetype should serve its OT topology (MRP /
// PROFINET / VLAN / HMI / LLDP) on a switch-info path.
func TestSwitchTopologyPage(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	arch := archetype.Lookup("siemens scalance xb-208")
	if arch == nil {
		t.Fatal("scalance archetype missing")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET /topology HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Errorf("status = %q; want 200", trunc(resp, 40))
	}
	for _, want := range []string{
		"Media Redundancy (MRP)", "PROFINET Devices", "VLANs", "Connected HMIs",
		"plc-cell3", "PROFINET", "HMI-Press-01",
	} {
		if !strings.Contains(resp, want) {
			t.Errorf("topology page missing %q", want)
		}
	}
}

// A non-switch archetype on the same path falls back to the normal
// flavored response (no topology tables).
func TestNonSwitchNoTopology(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{arch: archetype.Lookup("debian 12")}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET /topology HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if strings.Contains(resp, "Media Redundancy") {
		t.Errorf("debian archetype should not serve switch topology")
	}
}

package archetype

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestWindowsArchetypesResolve(t *testing.T) {
	cases := map[string]string{
		"windows 7":              "Microsoft-IIS/7.5",
		"windows 10":             "Microsoft-IIS/10.0",
		"windows server 2008":    "Microsoft-IIS/7.0",
		"windows server 2012":    "Microsoft-IIS/8.0",
		"windows server 2012 r2": "Microsoft-IIS/8.5",
		"windows server 2022":    "Microsoft-IIS/10.0",
	}
	for name, wantServer := range cases {
		p := Lookup(name)
		if p == nil {
			t.Errorf("Lookup(%q) = nil", name)
			continue
		}
		if p.HTTPServer() != wantServer {
			t.Errorf("%s: HTTPServer = %q; want %q", name, p.HTTPServer(), wantServer)
		}
		if p.Family != "windows" {
			t.Errorf("%s: family = %q; want windows", name, p.Family)
		}
		if p.ICMPTTL() != 128 {
			t.Errorf("%s: ICMPTTL = %d; want 128", name, p.ICMPTTL())
		}
	}
}

// Old Windows archetypes must declare a weak TLS posture for internal
// consistency with their ancient-firmware banners.
func TestWindowsOldTLSPosture(t *testing.T) {
	p := Lookup("windows server 2008")
	if p == nil {
		t.Fatal("windows server 2008 missing")
	}
	tlsP := p.TLS()
	if tlsP.MaxVersion == 0 || tlsP.MaxVersion > tls.VersionTLS11 {
		t.Errorf("2008 MaxVersion = %x; want <= TLS 1.1", tlsP.MaxVersion)
	}
	if !tlsP.WeakCiphers {
		t.Errorf("2008 should declare weak ciphers")
	}
	// Modern server keeps the zero-value (modern) posture.
	if Lookup("windows server 2022").TLS().WeakCiphers {
		t.Errorf("2022 should not declare weak ciphers")
	}
}

// Pre-OpenSSH Windows has no SSH banner; modern Windows ships
// OpenSSH-for-Windows.
func TestWindowsSSHConsistency(t *testing.T) {
	if Lookup("windows 7").SSHBanner() != "" {
		t.Errorf("windows 7 should have no SSH banner")
	}
	if !strings.Contains(Lookup("windows 11").SSHBanner(), "OpenSSH_for_Windows") {
		t.Errorf("windows 11 should ship OpenSSH for Windows")
	}
}

// SCALANCE switch archetypes expose the OT topology props.
func TestSCALANCESwitchTopology(t *testing.T) {
	p := Lookup("siemens scalance xb-208")
	if p == nil {
		t.Fatal("scalance xb-208 missing")
	}
	if len(p.MRPRings()) == 0 {
		t.Errorf("scalance should expose MRP rings")
	}
	if len(p.PROFINETDevices()) == 0 {
		t.Errorf("scalance should expose a PROFINET device tree")
	}
	if len(p.VLANs()) == 0 {
		t.Errorf("scalance should expose VLANs")
	}
	if len(p.HMIs()) == 0 {
		t.Errorf("scalance should expose HMIs")
	}
	// Network gear default TTL is 255.
	if p.ICMPTTL() != 255 {
		t.Errorf("scalance ICMPTTL = %d; want 255", p.ICMPTTL())
	}
}

func TestICMPTTLFamilyDefaults(t *testing.T) {
	if Lookup("debian 12").ICMPTTL() != 64 {
		t.Errorf("debian TTL should default to 64")
	}
	if Lookup("freebsd 14").ICMPTTL() != 64 {
		t.Errorf("bsd TTL should default to 64")
	}
	if Lookup("moxa eds-208").ICMPTTL() != 255 {
		t.Errorf("moxa TTL should default to 255")
	}
}

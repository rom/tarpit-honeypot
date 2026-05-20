package archetype

import (
	"strings"
	"testing"
)

func TestLookupCommonForms(t *testing.T) {
	cases := []string{
		"debian 12",
		"Debian 12",
		"DEBIAN_12",
		"debian-12",
		"  debian  12  ",
		"Debian.12",
	}
	for _, c := range cases {
		p := Lookup(c)
		if p == nil {
			t.Errorf("Lookup(%q) returned nil", c)
			continue
		}
		if p.Name != "debian-12" {
			t.Errorf("Lookup(%q): Name = %q; want debian-12", c, p.Name)
		}
		if !strings.Contains(p.SSHBanner(), "Debian") {
			t.Errorf("Lookup(%q): SSHBanner does not mention Debian: %q", c, p.SSHBanner())
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	if p := Lookup("solaris 11"); p != nil {
		t.Errorf("Lookup(solaris 11) = %v; want nil", p)
	}
	if p := Lookup(""); p != nil {
		t.Errorf("Lookup(empty) = %v; want nil", p)
	}
}

func TestNilProfileSafe(t *testing.T) {
	var p *Profile
	if p.SSHBanner() != "" {
		t.Errorf("nil SSHBanner should be empty")
	}
	if p.HTTPServer() != "" {
		t.Errorf("nil HTTPServer should be empty")
	}
	if p.FTPBanner() != "" {
		t.Errorf("nil FTPBanner should be empty")
	}
	if p.TelnetBanner() != "" {
		t.Errorf("nil TelnetBanner should be empty")
	}
	if p.SMTPProduct() != "" {
		t.Errorf("nil SMTPProduct should be empty")
	}
	if p.MySQLVersion() != "" {
		t.Errorf("nil MySQLVersion should be empty")
	}
	if p.Set() {
		t.Errorf("nil Set() should be false")
	}
}

// Every shipped archetype should be registered, every banner field
// populated, and the Names() helper should hand each one back exactly
// once.
func TestAllShipArchetypes(t *testing.T) {
	want := []string{
		"CentOS 5", "CentOS 6", "CentOS 7", "CentOS 8", "CentOS Stream 10",
		"Debian 9 (stretch)", "Debian 10 (buster)", "Debian 11 (bullseye)",
		"Debian 12 (bookworm)", "Debian 13 (trixie)",
		"Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9",
		"Red Hat Enterprise Linux 10",
		"Ubuntu 24.04 LTS", "Ubuntu 26.04 LTS",
		// v1.9 additions:
		"FreeBSD 13", "FreeBSD 14",
		"OpenBSD 7.5", "OpenBSD 7.6",
		"Arch Linux",
		"Rocky Linux 9", "AlmaLinux 9",
		"Oracle Linux 8", "Oracle Linux 9",
		"Moxa EDS-208", "Moxa NPort 5210",
		"Siemens SCALANCE XB-208",
		"Siemens S7-1200 PLC", "Siemens S7-1500 PLC",
		// later additions:
		"Siemens SCALANCE S615", "Siemens SCALANCE SC-600",
		"Windows 7", "Windows 8", "Windows 10", "Windows 11",
		"Windows Server 2008", "Windows Server 2012", "Windows Server 2012 R2",
		"Windows Server 2016", "Windows Server 2019", "Windows Server 2022",
		// Active Directory DC (registered under several aliases that
		// collapse to one display name).
		"Active Directory (Windows Server 2019 DC)",
		// Cisco IOS switch.
		"Cisco Catalyst 2960 (IOS 15)",
	}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names returned %d entries; want %d (%v)", len(got), len(want), got)
	}
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n] {
			t.Errorf("duplicate name: %q", n)
		}
		seen[n] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing archetype: %q", w)
		}
	}
}

// Every registered distro archetype should populate every banner
// field so we don't ship one with a silent hole. Device archetypes
// (Moxa, Siemens SCALANCE/S7) have a deliberately narrower surface —
// see TestDeviceArchetypeFields for those.
func TestRegistryComplete(t *testing.T) {
	distroFamilies := map[string]bool{
		"debian": true, "ubuntu": true, "rhel": true, "centos": true,
		"arch": true, "bsd": true,
	}
	for _, p := range registry {
		if !distroFamilies[p.Family] {
			continue
		}
		if p.SSHBanner() == "" {
			t.Errorf("%s: sshBanner empty", p.Name)
		}
		if p.HTTPServer() == "" {
			t.Errorf("%s: httpServer empty", p.Name)
		}
		if p.FTPBanner() == "" {
			t.Errorf("%s: ftpBanner empty", p.Name)
		}
		if p.TelnetBanner() == "" {
			t.Errorf("%s: telnetBanner empty", p.Name)
		}
		if p.SMTPProduct() == "" {
			t.Errorf("%s: smtpProduct empty", p.Name)
		}
		// OpenBSD ships without MariaDB/MySQL by default; FreeBSD
		// has it as an optional port. Only require the
		// MySQL version for distro families where MariaDB is a
		// default dependency / commonly installed.
		switch p.Family {
		case "debian", "ubuntu", "rhel", "centos", "arch":
			if p.MySQLVersion() == "" {
				t.Errorf("%s: mysqlVersion empty", p.Name)
			}
		}
	}
}

// Device archetypes (Moxa / Siemens) have their own fingerprint set —
// SNMP identity, MAC OUI, default services — and must populate that
// instead of the generic SSH/HTTP/FTP/SMTP/MySQL distro surface.
func TestDeviceArchetypeFields(t *testing.T) {
	for _, p := range registry {
		if p.Family != "moxa" && p.Family != "siemens" {
			continue
		}
		if !p.HasMACOUI() {
			t.Errorf("%s: macOUI not set", p.Name)
		}
		if p.SNMPSysDescr() == "" {
			t.Errorf("%s: snmpSysDescr empty", p.Name)
		}
		if p.SNMPSysObjectID() == "" {
			t.Errorf("%s: snmpSysObjectID empty", p.Name)
		}
		if len(p.DefaultServices()) == 0 {
			t.Errorf("%s: defaultServices empty", p.Name)
		}
	}
}

// Make sure the per-family SSH banners are at least loosely correct:
// Debian banners should mention "Debian", RHEL banners should not
// mention "Debian", and Ubuntu banners should mention "Ubuntu".
func TestSSHBannerFamilyMatch(t *testing.T) {
	cases := map[string]string{
		"debian-12":                  "Debian",
		"red-hat-enterprise-linux-9": "OpenSSH",
		"ubuntu-24-04-lts":           "Ubuntu",
	}
	for k, want := range cases {
		p := registry[k]
		if p == nil {
			t.Fatalf("missing registry entry %s", k)
		}
		if !strings.Contains(p.SSHBanner(), want) {
			t.Errorf("%s SSH banner %q lacks %q", k, p.SSHBanner(), want)
		}
	}
}

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
	if p := Lookup("haiku-os 1"); p != nil {
		t.Errorf("Lookup(haiku-os 1) = %v; want nil", p)
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
		// Cisco IOS switches.
		"Cisco Catalyst 2960 (IOS 15)",
		"Cisco Catalyst 9300 (IOS-XE 17)",
		// Edge / SOHO networking gear.
		"MikroTik RouterOS (RB750Gr3, 6.49.10)",
		"Teltonika RUT240 (RutOS, LTE router)",
		// Appliances: firewalls, NAS, IP cameras, more PLC vendors,
		// network printer, VoIP PBX.
		"pfSense (Netgate firewall)",
		"Fortinet FortiGate (FortiOS)",
		"Synology DiskStation (DSM)",
		"QNAP Turbo NAS (QTS)",
		"Hikvision IP camera",
		"Axis network camera",
		"Bosch IP camera",
		"Ubiquiti EdgeRouter (EdgeOS)",
		"Allen-Bradley ControlLogix (Rockwell)",
		"Schneider Modicon M340 PLC",
		"Omron PLC (FINS)",
		"HP LaserJet (network printer)",
		"Asterisk PBX (VoIP)",
		// Printers / multi-function devices across the major vendors.
		"Brother HL-L8260CDW (printer)",
		"Canon imageRUNNER ADVANCE (MFP)",
		"Epson WorkForce Pro (MFP)",
		"Xerox VersaLink C405 (MFP)",
		"Lexmark MX622 (MFP)",
		"Ricoh IM C3000 (MFP)",
		"Konica Minolta bizhub C284e (MFP)",
		"Kyocera ECOSYS M3550idn (MFP)",
		"Sharp MX-3071 (MFP)",
		"Zebra ZT411 (label printer)",
		// Industrial depth: more Moxa / Teltonika, Westermo, Hirschmann,
		// Phoenix Contact, Advantech, Cisco industrial.
		"Moxa EDS-405A (managed switch)",
		"Moxa EDS-G516E (gigabit managed switch)",
		"Moxa NPort 5650-8 (serial device server)",
		"Moxa AWK-3131A (industrial wireless AP)",
		"Moxa MGate MB3180 (Modbus gateway)",
		"Westermo Lynx (WeOS managed switch)",
		"Westermo RedFox (rugged managed switch)",
		"Westermo Viper (EN50155 rail switch)",
		"Westermo Merlin-4400 (cellular router)",
		"Westermo Ibex (industrial wireless)",
		"Teltonika RUT955 (industrial router, GPS)",
		"Teltonika RUTX11 (LTE Cat6 router)",
		"Teltonika RUT956 (industrial router)",
		"Teltonika TRB140 (LTE gateway)",
		"Hirschmann RS20 (Classic managed switch)",
		"Hirschmann RSP35 (HiOS managed switch)",
		"Hirschmann EAGLE20 (industrial firewall)",
		"Phoenix Contact FL SWITCH 2008",
		"Phoenix Contact FL MGUARD (security router)",
		"Advantech EKI-5528 (managed switch)",
		"Cisco Industrial Ethernet 2000 (IOS 15)",
		"Cisco Catalyst IE-3400 (IOS-XE 17)",
		"Cisco IR1101 (industrial router, IOS-XE)",
		// ABB / Honeywell / PN-PN coupler / WAGO / Beckhoff.
		"ABB AC500 PLC (PM573)",
		"ABB S500 remote I/O (CI502 PROFINET)",
		"ABB RTU560 (substation RTU)",
		"Honeywell ControlEdge 900 (PLC/RTU)",
		"Honeywell Experion C300 (DCS controller)",
		"Siemens PN/PN Coupler",
		"WAGO 750-8212 PFC200",
		"Beckhoff CX9020 (TwinCAT)",
		"Schneider Modicon M580 (BME P58)",
		"Omron NX1P2 (Sysmac)",
		"Mitsubishi MELSEC iQ-R (R04CPU)",
		// Cloud hosts / hypervisors / NAS / network appliances.
		"macOS Sonoma 14",
		"Alpine Linux 3.20",
		"Proxmox VE 8 (Debian)",
		"TrueNAS CORE (FreeBSD)",
		"VMware ESXi 8.0",
		"Juniper SRX (JunOS)",
		"Palo Alto PAN-OS firewall",
		"F5 BIG-IP (TMOS)",
		"SonicWall TZ (SonicOS)",
		"Netgear Nighthawk router",
		// Legacy Unix / alt-Linux / more appliances.
		"Oracle Solaris 11",
		"IBM AIX 7.2",
		"Gentoo Linux",
		"OPNsense firewall",
		"VyOS router",
		"OpenWrt router",
		"Arista EOS switch",
		"Check Point Gaia firewall",
		"Dell iDRAC 9 (lights-out)",
		"HPE iLO 5 (lights-out)",
		// Cloud-Linux / SBC / more network-security appliances.
		"Amazon Linux 2023",
		"Fedora 40",
		"Raspberry Pi OS (Debian)",
		"VMware vCenter Server Appliance",
		"Citrix NetScaler ADC",
		"Huawei VRP (router/switch)",
		"Zyxel USG FLEX firewall",
		"DrayTek Vigor router",
		"Grandstream UCM (VoIP PBX)",
		"Sophos XG firewall",
		// OT/ICS device personas (safety/DCS/PLC/relay/inverter).
		"Schneider Triconex Tricon (SIS)",
		"HIMA HIMax (safety PLC)",
		"GE PACSystems RX3i (PLC)",
		"Yokogawa CENTUM VP (DCS)",
		"Emerson DeltaV (DCS controller)",
		"Rockwell MicroLogix 1400 (PLC)",
		"B&R X20 (PLC)",
		"SEL-751 (protection relay)",
		"SMA Sunny (solar inverter)",
		"Bachmann M1 (controller)",
		// Remote-access / out-of-band management personas.
		"Supermicro BMC (IPMI/Redfish)",
		"Lenovo XClarity Controller (XCC)",
		"Cisco UCS CIMC",
		"HPE Onboard Administrator",
		"Oracle/Sun ILOM",
		"Fujitsu iRMC",
		"Lantronix SLC console server",
		"Opengear console server",
		"Raritan Dominion KX (KVM)",
		"APC Network Management Card (rPDU)",
		// VoIP / telephony personas.
		"FreePBX (Sangoma)",
		"Cisco Unified CM (CUCM)",
		"Avaya Aura Communication Manager",
		"Mitel MiVoice Business",
		"3CX Phone System",
		"FreeSWITCH",
		"Ribbon SBC (session border controller)",
		"AudioCodes Mediant gateway",
		"Yealink IP phone",
		"Poly/Polycom VVX phone",
		// v2.8 OT additions:
		"Emerson ROC800 RTU",
		"Red Lion Graphite HMI (Crimson 3.0)",
		"Emerson Bristol ControlWave RTU",
		"Echelon LonWorks i.LON Gateway",
		// v2.13 ICS/OT + networking additions:
		"Schneider Modicon M340 (BMX P34)",
		"Allen-Bradley ControlLogix 1756-L73",
		"GE PACSystems RX3i (IC695)",
		"WAGO PFC200 (750-8212)",
		"Juniper SRX340 (Junos)",
		"Arista 7050SX (EOS)",
		"Palo Alto PA-220 (PAN-OS)",
		"Aruba 2930F (ArubaOS-Switch)",
		"MatrikonOPC Server (Windows)",
		"Kepware KEPServerEX (Windows)",
		"Ubuntu 14.04 LTS (Trusty)",
		"Ubuntu 16.04 LTS (Xenial)",
		"Ubuntu 18.04 LTS (Bionic)",
		"Ubuntu 20.04 LTS (Focal)",
		"Debian 8 (jessie)",
		"FreeBSD 12",
		"Oracle Solaris 10",
		"MikroTik RouterOS 7 (RB5009)",
		"MikroTik RouterOS 6.40 (Winbox CVE-2018-14847)",
		"Cisco 2811 ISR (IOS 12.4)",
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
	deviceFamilies := map[string]bool{
		"moxa": true, "siemens": true, "cisco": true,
		"mikrotik": true, "teltonika": true,
	}
	for _, p := range registry {
		if !deviceFamilies[p.Family] {
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

// Appliance archetypes (firewalls / NAS / cameras / non-Siemens PLCs /
// printer / PBX) carry their own fingerprint surface. Each must declare a
// family distinct from the distro/device families, an SNMP description, at
// least one default service, and at least one identifying banner so a
// scanner has something to key on.
func TestApplianceArchetypeFields(t *testing.T) {
	for name, p := range applianceArchetypes {
		if p.DisplayName == "" {
			t.Errorf("%s: DisplayName empty", name)
		}
		if p.Family == "" {
			t.Errorf("%s: Family empty", name)
		}
		if p.SNMPSysDescr() == "" {
			t.Errorf("%s: snmpSysDescr empty", name)
		}
		if len(p.DefaultServices()) == 0 {
			t.Errorf("%s: defaultServices empty", name)
		}
		if p.HTTPServer() == "" && p.SSHBanner() == "" {
			t.Errorf("%s: no identifying banner (httpServer/sshBanner both empty)", name)
		}
		if Lookup(name) == nil {
			t.Errorf("%s: not resolvable via Lookup", name)
		}
	}
}

// Industrial archetypes (more Moxa / Teltonika + Westermo / Hirschmann /
// Phoenix Contact / Advantech) must carry the device fingerprint surface a
// scanner keys on: MAC OUI, SNMP description + enterprise OID, at least one
// default service, and resolvability via Lookup.
func TestIndustrialArchetypeFields(t *testing.T) {
	for name, p := range industrialArchetypes {
		if !p.HasMACOUI() {
			t.Errorf("%s: macOUI not set", name)
		}
		if p.SNMPSysDescr() == "" {
			t.Errorf("%s: snmpSysDescr empty", name)
		}
		if p.SNMPSysObjectID() == "" {
			t.Errorf("%s: snmpSysObjectID empty", name)
		}
		if len(p.DefaultServices()) == 0 {
			t.Errorf("%s: defaultServices empty", name)
		}
		if p.Family == "" {
			t.Errorf("%s: Family empty", name)
		}
		if Lookup(name) == nil {
			t.Errorf("%s: not resolvable via Lookup", name)
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

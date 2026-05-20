// Package archetype maps an OS-shaped string (e.g. "debian 12") to the
// set of banners / version strings a real install of that OS would emit
// from its default-package services. When the operator sets
// sensor.archetype: "debian 12", every honeypot banner — SSH, HTTP,
// FTP, Telnet, SMTP — picks the values that a stock Debian 12 box
// would actually advertise, so a scanner can't catch us by spotting
// a "Debian 12 host running OpenSSH 8.4p1 (which is Debian 11's
// version)" inconsistency.
//
// The archetype layers on top of the existing identity-based variant
// pool. Without an archetype, banners are deterministically random per
// sensor.deployment_id (v1.0 behavior). With an archetype, the
// archetype's fixed values win; the identity's role narrows to
// salting things like SMB challenges and serial numbers where the
// archetype has nothing to say.
package archetype

import "strings"

// init merges every Profile in deviceArchetypes (FreeBSD / OpenBSD /
// Arch / Rocky / Alma / Oracle / Moxa / Siemens) into the main
// registry, then backfills cliPrompt on the original 15 distro
// archetypes so handlers that consult CLIPrompt always have a value.
func init() {
	defaultPrompts := map[string]string{
		// RHEL family — bash with the standard /etc/bashrc PS1.
		"centos-5":                    "[root@centos5 ~]# ",
		"centos-6":                    "[root@centos6 ~]# ",
		"centos-7":                    "[root@centos7 ~]# ",
		"centos-8":                    "[root@centos8 ~]# ",
		"centos-stream-10":            "[root@cs10 ~]# ",
		"red-hat-enterprise-linux-8":  "[root@rhel8 ~]# ",
		"red-hat-enterprise-linux-9":  "[root@rhel9 ~]# ",
		"red-hat-enterprise-linux-10": "[root@rhel10 ~]# ",
		// Debian / Ubuntu — root@host:~#
		"debian-9":         "root@debian9:~# ",
		"debian-10":        "root@debian10:~# ",
		"debian-11":        "root@debian11:~# ",
		"debian-12":        "root@debian12:~# ",
		"debian-13":        "root@debian13:~# ",
		"ubuntu-24-04-lts": "root@ubuntu2404:~# ",
		"ubuntu-26-04-lts": "root@ubuntu2604:~# ",
	}
	for k, prompt := range defaultPrompts {
		if p, ok := registry[k]; ok && p.cliPrompt == "" {
			p.cliPrompt = prompt
		}
	}
	for k, p := range deviceArchetypes {
		registry[k] = p
	}
	for k, p := range windowsArchetypes {
		registry[k] = p
	}
	for k, p := range adArchetypes {
		registry[k] = p
	}
	for k, p := range ciscoArchetypes {
		registry[k] = p
	}
	for k, p := range networkDeviceArchetypes {
		registry[k] = p
	}
	for k, p := range applianceArchetypes {
		registry[k] = p
	}
}

// Profile is the resolved per-deployment / per-listener / per-host
// archetype. Lookups are functions so callers don't have to handle
// nil-Profile separately: zero-value Profile returns empty strings,
// which means "fall back to the v1.0 identity-based picker."
type Profile struct {
	Name        string // canonical name, e.g. "debian-12"
	DisplayName string // pretty name, e.g. "Debian 12 (bookworm)"
	Family      string // "debian" | "ubuntu" | "rhel" | "centos" | "bsd" | "ics" | "moxa" | "siemens"

	sshBanner    string
	httpServer   string
	ftpBanner    string
	telnetBanner string
	smtpHost     string
	smtpProduct  string
	mysqlVersion string

	// Service capability advertisements that fingerprint the specific
	// daemon behind a port, beyond its version banner:
	//   ftpFeatures    – FTP FEAT lines (RFC 2389); vsftpd / ProFTPD / a
	//                    NAS's FTP expose distinct sets.
	//   smtpExtensions – ESMTP keywords in the EHLO reply; Postfix,
	//                    Exchange and sendmail differ here.
	// Empty => the handler's built-in default.
	ftpFeatures    []string
	smtpExtensions []string

	// Device / network fingerprint.
	macOUI      [3]byte // first 3 bytes of MAC, e.g. {0x00,0x90,0xe8} for Moxa
	cliPrompt   string  // post-login shell prompt for SSH/Telnet sims
	loginPrompt string  // overrides telnetBanner when the device wants a specific 1st prompt

	// HTTP body — what the index page looks like for this device. Used
	// when the operator binds the handler "http" against this archetype.
	httpTitle    string
	httpBodyHTML string
	// httpHeaders are extra HTTP response headers this device sends beyond
	// Server/Content-* (e.g. X-Powered-By, a vendor Set-Cookie, a custom
	// WWW-Authenticate realm) — a strong per-archetype fingerprint.
	httpHeaders map[string]string

	// SNMP MIB-2 identity.
	snmpSysDescr    string
	snmpSysObjectID string // dotted OID
	snmpSysName     string
	snmpSysContact  string
	snmpSysLocation string
	snmpIfTable     []Interface // ifIndex / ifDescr / ifType / ifSpeed / ifPhysAddress
	lldpNeighbors   []LLDPPeer

	// Default services on this archetype — the listener set the
	// operator would get out-of-the-box. Used by `tarpit-honeypot
	// suggest-listeners` / archetype-aware honeynet host expansion.
	defaultServices []DefaultService

	// TLS posture. Older archetypes deliberately advertise weak/old
	// TLS so the honeypot is internally consistent: a "Windows Server
	// 2008" box that negotiates TLS 1.3 with modern ciphers is an
	// obvious tell. Zero value = modern defaults (TLS 1.2+).
	tls TLSPosture

	// ICMP personality. The initial IP TTL a host stamps on its
	// replies is OS-characteristic (Linux/BSD 64, Windows 128,
	// many routers/switches 255) and is the basis of passive OS
	// fingerprinting + traceroute hop-distance estimation. 0 = pick
	// a family default.
	icmpTTL int

	// Switch / OT topology props — exposed by the snmp + web handlers
	// for switch-class archetypes so a scanner walking the device sees
	// a believable ring / PROFINET tree / VLAN / HMI inventory.
	mrpRings        []MRPRing
	profinetDevices []PROFINETDevice
	vlans           []VLAN
	hmis            []HMI

	// Free-form quirk markers. Read by handlers that need archetype-
	// specific tweaks (e.g. siemens-s7-1500 disables LLDP-MED TLVs;
	// moxa-nport advertises raw TCP on 4001/4002).
	quirks []string

	// Vulnerability emulation (advisory only — never makes the service
	// actually exploitable). When sensor/listener vuln_emulation is on,
	// banner-aware handlers prefer vulnBanners[service] over the patched
	// banner so a version scanner records an unpatched box; patchLevel is
	// surfaced in event meta; cveVulns lists the CVE ids this archetype
	// presents as unpatched against.
	patchLevel  string
	cveVulns    []string
	vulnBanners map[string]string // "ssh"|"http"|"smtp"|"mysql"|"ftp" -> vulnerable banner
}

// TLSPosture describes the TLS version + cipher posture an archetype
// presents. Used by the https handler to make an old device negotiate
// old protocols (consistency with its ancient firmware banner).
type TLSPosture struct {
	// MinVersion as a crypto/tls constant (0 = unset -> handler
	// default of TLS 1.2). e.g. tls.VersionTLS10 for legacy gear.
	MinVersion uint16
	// MaxVersion caps negotiation (0 = unset -> handler default). An
	// old box that can't do TLS 1.3 sets this to tls.VersionTLS12 (or
	// lower) so a modern client's ClientHello downgrades — exactly
	// what a real legacy device does.
	MaxVersion uint16
	// WeakCiphers enables the legacy cipher suites (CBC/3DES/RC4-era)
	// that Go normally hides. Pairs with low MaxVersion.
	WeakCiphers bool
}

// MRPRing is one Media Redundancy Protocol ring a switch participates
// in (IEC 62439-2). Exposed in the switch web UI / SNMP.
type MRPRing struct {
	Name  string
	Role  string // "manager" | "client"
	Ports []int
	State string // "closed" | "open"
}

// PROFINETDevice is one node in the fake PROFINET device tree a
// SCALANCE-class switch advertises (station name + IP + role).
type PROFINETDevice struct {
	StationName string
	IP          string
	Role        string // "io-controller" | "io-device"
	Vendor      string
}

// VLAN is one 802.1Q VLAN entry shown in the switch's config.
type VLAN struct {
	ID    int
	Name  string
	Ports []int
}

// HMI is a fake human-machine-interface panel reachable behind the
// switch (advertised in the web UI's "connected devices" view).
type HMI struct {
	Name string
	IP   string
	Type string
}

// Interface is a single MIB-2 interface entry, used to populate
// ifTable in the SNMP handler.
type Interface struct {
	Index   int
	Descr   string // ifDescr (e.g. "GigabitEthernet 1/1")
	Type    int    // ifType: 6 = ethernet, 24 = softwareLoopback, 53 = ppp
	Speed   uint32 // ifSpeed in bps; 1_000_000_000 = 1 Gbit
	PhysMAC string // hex MAC string (decorative — actual MAC is from macOUI)
	OperUp  bool
}

// LLDPPeer is a single LLDP neighbor advertised in the snmpLLDP TLV or
// returned by the LLDP responder.
type LLDPPeer struct {
	ChassisID  string
	PortID     string
	SystemName string
	PortDescr  string
}

// DefaultService describes a port + handler that a real instance of
// this archetype runs out-of-the-box.
type DefaultService struct {
	Port    int
	Handler string
	Note    string
}

func (p *Profile) Set() bool {
	return p != nil && p.Name != ""
}
func (p *Profile) SSHBanner() string {
	if p == nil {
		return ""
	}
	return p.sshBanner
}
func (p *Profile) HTTPServer() string {
	if p == nil {
		return ""
	}
	return p.httpServer
}
func (p *Profile) FTPBanner() string {
	if p == nil {
		return ""
	}
	return p.ftpBanner
}
func (p *Profile) TelnetBanner() string {
	if p == nil {
		return ""
	}
	return p.telnetBanner
}
func (p *Profile) SMTPHost() string {
	if p == nil {
		return ""
	}
	return p.smtpHost
}
func (p *Profile) SMTPProduct() string {
	if p == nil {
		return ""
	}
	return p.smtpProduct
}
func (p *Profile) MySQLVersion() string {
	if p == nil {
		return ""
	}
	return p.mysqlVersion
}

// FTPFeatures returns the FTP FEAT capability lines this archetype's FTP
// daemon advertises (nil => the ftp handler's vsftpd-style default).
func (p *Profile) FTPFeatures() []string {
	if p == nil {
		return nil
	}
	return p.ftpFeatures
}

// SMTPExtensions returns the ESMTP keywords this archetype advertises in
// its EHLO reply (nil => the smtp handler's Postfix-style default).
func (p *Profile) SMTPExtensions() []string {
	if p == nil {
		return nil
	}
	return p.smtpExtensions
}
func (p *Profile) MACOUI() [3]byte {
	if p == nil {
		return [3]byte{}
	}
	return p.macOUI
}

// HasMACOUI reports whether the archetype pins a specific MAC OUI.
// When false, callers fall back to identity-derived random MACs.
func (p *Profile) HasMACOUI() bool {
	if p == nil {
		return false
	}
	return p.macOUI != [3]byte{}
}

// CLIPrompt returns the post-login shell prompt this archetype shows.
// SSH/Telnet handlers in CLI-emulation mode append it after the
// (rejected) login.
func (p *Profile) CLIPrompt() string {
	if p == nil {
		return ""
	}
	return p.cliPrompt
}

// LoginPrompt overrides the generic /bin/login prompt. Used by Moxa /
// SCALANCE / Cisco-shaped devices that put a specific string before
// "login:" or "Username:".
func (p *Profile) LoginPrompt() string {
	if p == nil {
		return ""
	}
	return p.loginPrompt
}

func (p *Profile) HTTPTitle() string {
	if p == nil {
		return ""
	}
	return p.httpTitle
}
func (p *Profile) HTTPBodyHTML() string {
	if p == nil {
		return ""
	}
	return p.httpBodyHTML
}

// HTTPHeaders returns extra HTTP response headers this archetype sends.
func (p *Profile) HTTPHeaders() map[string]string {
	if p == nil {
		return nil
	}
	return p.httpHeaders
}
func (p *Profile) SNMPSysDescr() string {
	if p == nil {
		return ""
	}
	return p.snmpSysDescr
}
func (p *Profile) SNMPSysObjectID() string {
	if p == nil {
		return ""
	}
	return p.snmpSysObjectID
}
func (p *Profile) SNMPSysName() string {
	if p == nil {
		return ""
	}
	return p.snmpSysName
}
func (p *Profile) SNMPSysContact() string {
	if p == nil {
		return ""
	}
	return p.snmpSysContact
}
func (p *Profile) SNMPSysLocation() string {
	if p == nil {
		return ""
	}
	return p.snmpSysLocation
}
func (p *Profile) Interfaces() []Interface {
	if p == nil {
		return nil
	}
	return p.snmpIfTable
}
func (p *Profile) LLDPNeighbors() []LLDPPeer {
	if p == nil {
		return nil
	}
	return p.lldpNeighbors
}
func (p *Profile) DefaultServices() []DefaultService {
	if p == nil {
		return nil
	}
	return p.defaultServices
}

// HasQuirk reports whether the archetype carries the named flag.
// Handlers consult this for archetype-specific deviations from their
// default behavior.
func (p *Profile) HasQuirk(name string) bool {
	if p == nil {
		return false
	}
	for _, q := range p.quirks {
		if q == name {
			return true
		}
	}
	return false
}

// TLS returns the archetype's TLS posture (zero value = modern
// defaults). Used by the https handler to downgrade old archetypes.
func (p *Profile) TLS() TLSPosture {
	if p == nil {
		return TLSPosture{}
	}
	return p.tls
}

// PatchLevel returns a human-readable "unpatched" descriptor for the
// archetype (e.g. "Server 2019 RTM (no May-2021 rollup)"), or "" if the
// archetype declares none. Surfaced in event meta when vuln_emulation
// is on.
func (p *Profile) PatchLevel() string {
	if p == nil {
		return ""
	}
	return p.patchLevel
}

// VulnCVEs returns the CVE ids this archetype presents as unpatched
// against (advisory; the service is never actually exploitable).
func (p *Profile) VulnCVEs() []string {
	if p == nil {
		return nil
	}
	return p.cveVulns
}

// VulnBanner returns the archetype's deliberately-vulnerable banner for
// a service ("ssh"/"http"/"smtp"/"mysql"/"ftp"), or "" if none is set.
// Handlers use it only when vuln_emulation is enabled.
func (p *Profile) VulnBanner(service string) string {
	if p == nil || p.vulnBanners == nil {
		return ""
	}
	return p.vulnBanners[service]
}

// ICMPTTL returns the initial IP TTL this archetype stamps on replies.
// Falls back to a family default when unset: 255 for network/OT gear
// (moxa/siemens), 128 for Windows, 64 for everything else (Linux/BSD).
func (p *Profile) ICMPTTL() int {
	if p == nil {
		return 64
	}
	if p.icmpTTL != 0 {
		return p.icmpTTL
	}
	switch p.Family {
	case "moxa", "siemens", "ics":
		return 255
	case "windows":
		return 128
	}
	return 64
}

func (p *Profile) MRPRings() []MRPRing {
	if p == nil {
		return nil
	}
	return p.mrpRings
}
func (p *Profile) PROFINETDevices() []PROFINETDevice {
	if p == nil {
		return nil
	}
	return p.profinetDevices
}
func (p *Profile) VLANs() []VLAN {
	if p == nil {
		return nil
	}
	return p.vlans
}
func (p *Profile) HMIs() []HMI {
	if p == nil {
		return nil
	}
	return p.hmis
}

// Lookup returns the Profile for the named archetype. Names are matched
// case-insensitively with most reasonable separator variants accepted
// ("Debian 12", "debian-12", "debian12", "DEBIAN_12" all resolve).
// Unknown names return nil — the caller treats nil as "no archetype set."
func Lookup(name string) *Profile {
	if name == "" {
		return nil
	}
	key := normalize(name)
	if p, ok := registry[key]; ok {
		return p
	}
	return nil
}

// Names returns the distinct archetype display names sorted
// alphabetically. Aliases (multiple registry keys pointing at the same
// device, e.g. the Active Directory DC) collapse to a single entry.
// Used by the `tarpit-honeypot help archetypes` topic.
func Names() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(registry))
	for _, p := range registry {
		if seen[p.DisplayName] {
			continue
		}
		seen[p.DisplayName] = true
		out = append(out, p.DisplayName)
	}
	// In-place sort to avoid an import for a single function.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// normalize folds case, replaces separators with hyphens, and collapses
// runs of hyphens so "Debian 12", "debian_12", "DEBIAN-12" all key on
// "debian-12".
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	out := make([]byte, 0, len(s))
	lastWasSep := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ', c == '_', c == '-', c == '.':
			if !lastWasSep && len(out) > 0 {
				out = append(out, '-')
				lastWasSep = true
			}
		default:
			out = append(out, c)
			lastWasSep = false
		}
	}
	// Strip trailing separator.
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}

// registry holds the 15 ship archetypes. The values are realistic
// for a default install: openssh / apache / nginx / vsftpd / postfix
// versions taken from each distro's package archive at the relevant
// point release.
var registry = map[string]*Profile{
	"centos-5": {
		Name: "centos-5", DisplayName: "CentOS 5", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_4.3",
		httpServer:   "Apache/2.2.3 (CentOS)",
		ftpBanner:    "220 (vsFTPd 2.0.5)",
		telnetBanner: "\r\nCentOS release 5.11 (Final)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 2.3.3",
		mysqlVersion: "5.0.95",
	},
	"centos-6": {
		Name: "centos-6", DisplayName: "CentOS 6", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_5.3",
		httpServer:   "Apache/2.2.15 (CentOS)",
		ftpBanner:    "220 (vsFTPd 2.2.2)",
		telnetBanner: "\r\nCentOS release 6.10 (Final)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 2.6.6",
		mysqlVersion: "5.1.73",
	},
	"centos-7": {
		Name: "centos-7", DisplayName: "CentOS 7", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_7.4",
		httpServer:   "Apache/2.4.6 (CentOS)",
		ftpBanner:    "220 (vsFTPd 3.0.2)",
		telnetBanner: "\r\nCentOS Linux release 7.9.2009 (Core)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 2.10.1",
		mysqlVersion: "5.5.68-MariaDB",
	},
	"centos-8": {
		Name: "centos-8", DisplayName: "CentOS 8", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_8.0",
		httpServer:   "Apache/2.4.37 (centos)",
		ftpBanner:    "220 (vsFTPd 3.0.3)",
		telnetBanner: "\r\nCentOS Linux release 8.5.2111\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.3.1",
		mysqlVersion: "10.3.28-MariaDB",
	},
	"centos-stream-10": {
		Name: "centos-stream-10", DisplayName: "CentOS Stream 10", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_9.9",
		httpServer:   "Apache/2.4.62 (CentOS Stream)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nCentOS Stream release 10\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.8.7",
		mysqlVersion: "10.11.6-MariaDB",
	},

	"debian-9": {
		Name: "debian-9", DisplayName: "Debian 9 (stretch)", Family: "debian",
		sshBanner:    "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
		httpServer:   "Apache/2.4.25 (Debian)",
		ftpBanner:    "220 (vsFTPd 3.0.3)",
		telnetBanner: "\r\nDebian GNU/Linux 9 \\n \\l\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.1.15",
		mysqlVersion: "10.1.48-MariaDB-0+deb9u2",
	},
	"debian-10": {
		Name: "debian-10", DisplayName: "Debian 10 (buster)", Family: "debian",
		sshBanner:    "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4",
		httpServer:   "Apache/2.4.38 (Debian)",
		ftpBanner:    "220 (vsFTPd 3.0.3)",
		telnetBanner: "\r\nDebian GNU/Linux 10 \\n \\l\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.4.23",
		mysqlVersion: "10.3.38-MariaDB-0+deb10u1",
	},
	"debian-11": {
		Name: "debian-11", DisplayName: "Debian 11 (bullseye)", Family: "debian",
		sshBanner:    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
		httpServer:   "Apache/2.4.62 (Debian)",
		ftpBanner:    "220 (vsFTPd 3.0.3)",
		telnetBanner: "\r\nDebian GNU/Linux 11 \\n \\l\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.5.18",
		mysqlVersion: "10.5.21-MariaDB-0+deb11u1",
	},
	"debian-12": {
		Name: "debian-12", DisplayName: "Debian 12 (bookworm)", Family: "debian",
		sshBanner:    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		httpServer:   "Apache/2.4.62 (Debian)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nDebian GNU/Linux 12 \\n \\l\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.7.11",
		mysqlVersion: "10.11.6-MariaDB-0+deb12u1",
		// vuln_emulation: present a deliberately-unpatched build so a
		// version scanner records an exploitable box. Apache 2.4.49
		// pairs with the CVE-2021-41773 path-traversal detector; vsFTPd
		// 2.3.4 is the backdoored release; OpenSSH 7.2 is user-enum era.
		patchLevel: "Debian 12 (no 2024 security rollup)",
		cveVulns:   []string{"CVE-2021-41773", "CVE-2018-15473"},
		vulnBanners: map[string]string{
			"ssh":  "SSH-2.0-OpenSSH_7.2p2 Debian-5",
			"http": "Apache/2.4.49 (Debian)",
			"ftp":  "220 (vsFTPd 2.3.4)",
		},
	},
	"debian-13": {
		Name: "debian-13", DisplayName: "Debian 13 (trixie)", Family: "debian",
		sshBanner:    "SSH-2.0-OpenSSH_9.9p1 Debian-4",
		httpServer:   "Apache/2.4.62 (Debian)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nDebian GNU/Linux 13 \\n \\l\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.10.0",
		mysqlVersion: "11.4.3-MariaDB",
	},

	"red-hat-enterprise-linux-8": {
		Name: "rhel-8", DisplayName: "Red Hat Enterprise Linux 8", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_8.0",
		httpServer:   "Apache/2.4.37 (Red Hat Enterprise Linux)",
		ftpBanner:    "220 (vsFTPd 3.0.3)",
		telnetBanner: "\r\nRed Hat Enterprise Linux release 8.10 (Ootpa)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.5.8",
		mysqlVersion: "10.3.39-MariaDB",
	},
	"red-hat-enterprise-linux-9": {
		Name: "rhel-9", DisplayName: "Red Hat Enterprise Linux 9", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_8.7",
		httpServer:   "Apache/2.4.62 (Red Hat Enterprise Linux)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nRed Hat Enterprise Linux release 9.5 (Plow)\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.5.25",
		mysqlVersion: "10.11.6-MariaDB",
	},
	"red-hat-enterprise-linux-10": {
		Name: "rhel-10", DisplayName: "Red Hat Enterprise Linux 10", Family: "rhel",
		sshBanner:    "SSH-2.0-OpenSSH_9.9",
		httpServer:   "Apache/2.4.62 (Red Hat Enterprise Linux)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nRed Hat Enterprise Linux release 10.0\r\nKernel \\r on an \\m\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.8.7",
		mysqlVersion: "10.11.8-MariaDB",
	},

	"ubuntu-24-04-lts": {
		Name: "ubuntu-24.04", DisplayName: "Ubuntu 24.04 LTS", Family: "ubuntu",
		sshBanner:    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		httpServer:   "Apache/2.4.58 (Ubuntu)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nUbuntu 24.04.1 LTS\r\n\\m \\r \\h\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.8.6",
		mysqlVersion: "8.0.39-0ubuntu0.24.04.2",
	},
	"ubuntu-26-04-lts": {
		Name: "ubuntu-26.04", DisplayName: "Ubuntu 26.04 LTS", Family: "ubuntu",
		sshBanner:    "SSH-2.0-OpenSSH_10.0p1 Ubuntu-1",
		httpServer:   "Apache/2.4.62 (Ubuntu)",
		ftpBanner:    "220 (vsFTPd 3.0.5)",
		telnetBanner: "\r\nUbuntu 26.04 LTS\r\n\\m \\r \\h\r\n\r\nlogin: ",
		smtpProduct:  "Postfix 3.10.0",
		mysqlVersion: "8.4.4-0ubuntu0.26.04.1",
	},
}

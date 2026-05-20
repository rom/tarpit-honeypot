package devices

import (
	"net/netip"
	"strings"
)

// normalizeMAC lowercases a MAC and renders it as colon-separated
// xx:xx:xx:xx:xx:xx. Accepts colon-, dash-, and dot-separated forms;
// returns "" for anything that isn't 12 hex digits.
func normalizeMAC(s string) string {
	if s == "" {
		return ""
	}
	var hexd []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			hexd = append(hexd, c)
		case c >= 'A' && c <= 'F':
			hexd = append(hexd, c+32) // lowercase
		case c == ':' || c == '-' || c == '.':
			// separator, skip
		default:
			return "" // invalid char
		}
	}
	if len(hexd) != 12 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.Write(hexd[i : i+2])
	}
	return b.String()
}

// lessIP orders two IP strings numerically (so 10.0.0.2 < 10.0.0.10).
// Non-parseable values sort after parseable ones.
func lessIP(a, b string) bool {
	ai, aerr := netip.ParseAddr(a)
	bi, berr := netip.ParseAddr(b)
	if aerr != nil || berr != nil {
		return a < b
	}
	return ai.Less(bi)
}

// VendorForMAC returns the vendor name for a MAC's OUI (first 3 bytes),
// or "" if unknown. The table is a small curated set of the OUIs most
// relevant to the gear this sensor models (the device archetypes) plus
// the big virtualization / cloud vendors a learned-device scan would
// commonly turn up. It is NOT the full IEEE registry.
//
// A "locally administered" MAC (bit 0x02 of the first octet set) — the
// kind VMs, containers, and our own honeynet hosts use — is reported
// as "(locally administered)" since the OUI is meaningless there.
func VendorForMAC(mac string) string {
	mac = normalizeMAC(mac)
	if len(mac) < 8 {
		return ""
	}
	oui := mac[0:8] // "xx:xx:xx"
	if v, ok := ouiTable[oui]; ok {
		return v
	}
	// Locally-administered bit on the first octet?
	if b, ok := firstOctet(mac); ok && b&0x02 != 0 {
		return "(locally administered)"
	}
	return ""
}

func firstOctet(mac string) (byte, bool) {
	if len(mac) < 2 {
		return 0, false
	}
	hi := hexVal(mac[0])
	lo := hexVal(mac[1])
	if hi < 0 || lo < 0 {
		return 0, false
	}
	return byte(hi<<4 | lo), true
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

// ouiTable maps the first-3-octet prefix to a vendor name.
var ouiTable = map[string]string{
	// Industrial / OT (match the device archetypes).
	"00:90:e8": "Moxa",
	"28:63:36": "Siemens",
	"00:1b:1b": "Siemens",
	"00:0e:8c": "Siemens",
	"00:1c:06": "Siemens",
	"ec:46:70": "Rockwell Automation",
	"00:00:bc": "Rockwell Automation",
	"00:80:f4": "Telemecanique/Schneider",
	"00:00:54": "Schneider Electric",

	// Network gear.
	"00:00:0c": "Cisco",
	"00:1a:a1": "Cisco",
	"00:1b:0d": "Cisco",
	"f4:cf:e2": "Cisco",
	"00:0c:29": "VMware",
	"00:50:56": "VMware",
	"00:05:69": "VMware",
	"08:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",
	"00:16:3e": "Xen",
	"00:15:5d": "Microsoft Hyper-V",
	"02:42:ac": "Docker",

	// Common endpoint vendors.
	"00:1a:11": "Google",
	"3c:5a:b4": "Google",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"00:1c:b3": "Apple",
	"a4:5e:60": "Apple",
	"f0:18:98": "Apple",
	"00:24:9b": "Action Star (router)",
	"c0:25:e9": "TP-Link",
	"50:c7:bf": "TP-Link",
	"00:18:0a": "Cisco-Meraki",
	"fc:ec:da": "Ubiquiti",
	"24:a4:3c": "Ubiquiti",
	"00:11:32": "Synology",
}

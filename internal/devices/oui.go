package devices

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
)

// loadedOUI holds the full IEEE OUI registry when an operator supplies one
// via LoadOUIFile. It is consulted before the small built-in ouiTable, so a
// loaded database upgrades vendor resolution everywhere VendorForMAC is
// called (the device inventory + event enrichment). Lock-free reads.
var loadedOUI atomic.Pointer[map[string]string]

// LoadOUIFile loads a MAC-vendor (OUI) database from path and makes it the
// primary source for VendorForMAC. It accepts the IEEE oui.csv format
// (Registry,Assignment,Organization Name,…; MA-L rows only) and a simple
// "prefix,vendor" CSV. Returns the number of OUIs loaded. Intended to be
// called once at startup before events flow.
func LoadOUIFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = true
	m := map[string]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // tolerate a malformed line rather than abort the load
		}
		if prefix, vendor := parseOUIRecord(rec); prefix != "" && vendor != "" {
			m[prefix] = vendor
		}
	}
	if len(m) == 0 {
		return 0, fmt.Errorf("no OUI entries parsed from %s", path)
	}
	loadedOUI.Store(&m)
	return len(m), nil
}

// parseOUIRecord extracts a (24-bit OUI prefix, vendor) pair from one CSV
// record, or ("","") to skip it (header, MA-M/MA-S blocks, blank lines).
func parseOUIRecord(rec []string) (string, string) {
	if len(rec) >= 3 && rec[0] == "MA-L" {
		return ouiPrefixFromHex(rec[1]), strings.TrimSpace(rec[2])
	}
	if len(rec) >= 2 {
		if p := ouiPrefixFromHex(rec[0]); p != "" {
			return p, strings.TrimSpace(rec[1])
		}
	}
	return "", ""
}

// ouiPrefixFromHex normalizes the first three octets of a hex MAC/OUI string
// (any separators) into "xx:xx:xx" lowercase, or "" if it lacks 6 hex digits.
func ouiPrefixFromHex(s string) string {
	var h []byte
	for i := 0; i < len(s) && len(h) < 6; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			h = append(h, c)
		case c >= 'A' && c <= 'F':
			h = append(h, c+32)
		}
	}
	if len(h) < 6 {
		return ""
	}
	return string(h[0:2]) + ":" + string(h[2:4]) + ":" + string(h[4:6])
}

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
// or "" if unknown. When an operator has loaded the full IEEE registry via
// LoadOUIFile it is consulted first; otherwise a small curated built-in
// table covers the gear this sensor models (the device archetypes) plus the
// big virtualization / cloud vendors a learned-device scan commonly returns.
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
	// A loaded full IEEE database (if any) wins over the built-in table.
	if lm := loadedOUI.Load(); lm != nil {
		if v, ok := (*lm)[oui]; ok {
			return v
		}
	}
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

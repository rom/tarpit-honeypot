package archetype

import (
	"regexp"
	"strings"
)

// CPE 2.3 derivation for archetypes. An archetype maps to a real OS / device /
// appliance product, so we can express it as a CPE
// (cpe:2.3:<part>:<vendor>:<product>:<version>:*:*:*:*:*:*:*). Most are derived
// from Family (-> part + vendor + OS product) and Name (-> product + version);
// an archetype can override the result with an explicit `cpe:` field.

// familyVendor maps an archetype Family to its CPE vendor token. Missing entries
// fall back to the family name itself (already a reasonable vendor for the
// device/OT families, e.g. moxa / siemens / rockwell).
var familyVendor = map[string]string{
	"debian": "debian", "ubuntu": "canonical", "rhel": "redhat", "centos": "centos",
	"fedora": "redhat", "amazonlinux": "amazon", "arch": "archlinux", "gentoo": "gentoo",
	"alpine": "alpinelinux", "suse": "suse", "raspbian": "raspberrypi",
	"bsd": "freebsd", "solaris": "oracle", "aix": "ibm", "macos": "apple",
	"windows": "microsoft",
	"pfsense": "netgate", "opnsense": "opnsense", "fortios": "fortinet",
	"paloalto": "paloaltonetworks", "f5": "f5", "sonicwall": "sonicwall",
	"checkpoint": "checkpoint", "sophos": "sophos", "juniper": "juniper",
	"citrix": "citrix", "vyos": "vyos", "openwrt": "openwrt", "mikrotik": "mikrotik",
	"cisco": "cisco", "ciscoucs": "cisco", "ciscocucm": "cisco", "arista": "arista",
	"huawei": "huawei", "zyxel": "zyxel", "draytek": "draytek", "netgear": "netgear",
	"dlink": "dlink", "tplink": "tp-link", "asus": "asus",
	"ubiquiti": "ui", "teltonika": "teltonika", "nokia": "nokia",
	"vmware": "vmware", "esxi": "vmware", "proxmox": "proxmox", "truenas": "truenas",
	"synology": "synology", "qnap": "qnap",
	"dell": "dell", "hp": "hp", "hpeoa": "hpe", "ilom": "oracle", "supermicro": "supermicro",
	"lenovo": "lenovo", "fujitsu": "fujitsu", "apc": "apc", "raritan": "raritan",
	"lantronix": "lantronix", "opengear": "opengear", "digi": "digi",
	"moxa": "moxa", "siemens": "siemens", "schneider": "schneider", "rockwell": "rockwellautomation",
	"omron": "omron", "mitsubishi": "mitsubishielectric", "phoenix": "phoenixcontact",
	"wago": "wago", "beckhoff": "beckhoff", "abb": "abb", "honeywell": "honeywell",
	"ge": "ge", "yokogawa": "yokogawa", "emerson": "emerson", "hirschmann": "belden",
	"westermo": "westermo", "advantech": "advantech", "bachmann": "bachmann",
	"br": "br-automation", "bristol": "emerson", "redlion": "redlion", "echelon": "echelon",
	"sel": "selinc", "sma": "sma", "triconex": "schneider", "hima": "hima",
	"hikvision": "hikvision", "axis": "axis", "bosch": "bosch",
	"printer": "generic",
	"freepbx": "sangoma", "freeswitch": "signalwire", "3cx": "3cx", "avaya": "avaya",
	"mitel": "mitel", "ribbon": "ribboncommunications", "audiocodes": "audiocodes",
	"yealink": "yealink", "polycom": "poly", "grandstream": "grandstream",
}

// osProduct maps OS families to their CPE product token (where it differs from
// the vendor-default). For OS families the version is taken from the Name.
var osProduct = map[string]string{
	"debian": "debian_linux", "ubuntu": "ubuntu_linux", "rhel": "enterprise_linux",
	"centos": "centos", "fedora": "fedora", "amazonlinux": "amazon_linux",
	"arch": "arch_linux", "gentoo": "gentoo_linux", "alpine": "alpine_linux",
	"raspbian": "raspbian", "solaris": "solaris", "aix": "aix", "macos": "macos",
	"windows": "windows",
}

// osFamilies get CPE part "o" (operating system); hwFamilies get "h" (hardware
// device); everything else is "a" (application/appliance software).
var osFamilies = map[string]bool{
	"debian": true, "ubuntu": true, "rhel": true, "centos": true, "fedora": true,
	"amazonlinux": true, "arch": true, "gentoo": true, "alpine": true, "suse": true,
	"raspbian": true, "bsd": true, "solaris": true, "aix": true, "macos": true,
	"windows": true, "vyos": true, "openwrt": true, "fortios": true,
}

var hwFamilies = map[string]bool{
	"moxa": true, "siemens": true, "schneider": true, "rockwell": true, "omron": true,
	"mitsubishi": true, "phoenix": true, "wago": true, "beckhoff": true, "abb": true,
	"honeywell": true, "ge": true, "yokogawa": true, "emerson": true, "hirschmann": true,
	"westermo": true, "advantech": true, "bachmann": true, "br": true, "bristol": true,
	"redlion": true, "echelon": true, "sel": true, "sma": true, "triconex": true,
	"hima": true, "hikvision": true, "axis": true, "printer": true, "ubiquiti": true,
	"netgear": true, "draytek": true, "zyxel": true, "teltonika": true, "mikrotik": true,
	"cisco": true, "arista": true, "huawei": true, "apc": true, "raritan": true,
	"lantronix": true, "opengear": true, "yealink": true, "polycom": true,
	"grandstream": true, "audiocodes": true, "digi": true, "nokia": true,
	"dlink": true, "tplink": true, "asus": true,
}

var cpeTokenStrip = regexp.MustCompile(`[^a-z0-9._-]+`)
var cpeVersionTail = regexp.MustCompile(`[-_]([0-9][0-9a-z.]*)$`)

// cpeToken sanitizes a string into a CPE-safe token (lower-case, only
// a-z0-9._-), collapsing other runs to a single "_".
func cpeToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = cpeTokenStrip.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "unknown"
	}
	return s
}

// deriveCPE builds a CPE 2.3 string for an archetype from its Family + Name.
func deriveCPE(p *Profile) string {
	if p == nil || p.Name == "" {
		return ""
	}
	part := "a"
	switch {
	case osFamilies[p.Family]:
		part = "o"
	case hwFamilies[p.Family]:
		part = "h"
	}
	vendor := familyVendor[p.Family]
	if vendor == "" {
		vendor = cpeToken(p.Family)
	}
	// Product + version.
	var product, version string
	version = "*"
	if part == "o" {
		if prod := osProduct[p.Family]; prod != "" {
			product = prod
		} else if p.Family == "bsd" {
			// freebsd-13 / openbsd-7.4 -> product is the leading name token.
			product = cpeToken(strings.SplitN(p.Name, "-", 2)[0])
		} else {
			product = cpeToken(p.Family)
		}
		if m := cpeVersionTail.FindStringSubmatch(p.Name); m != nil {
			version = m[1]
		}
	} else {
		// Appliance / device: the Name is the product (strip a leading vendor
		// token + a trailing version).
		name := p.Name
		if m := cpeVersionTail.FindStringSubmatch(name); m != nil {
			version = m[1]
			name = name[:len(name)-len(m[0])]
		}
		name = strings.TrimPrefix(name, p.Family+"-")
		product = cpeToken(name)
	}
	return "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
}

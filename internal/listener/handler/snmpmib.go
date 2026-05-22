package handler

import (
	"net"
	"sort"
	"strconv"
	"strings"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// This file builds an ordered, *walkable* SNMP MIB so snmpwalk / snmpbulkwalk
// actually traverse the tree (the old handler "cheated" GetNext by answering
// like Get, so a real walk stalled). Entries are kept sorted by numeric OID
// so GetNext can return the lexicographic successor — the operation a walk
// is built on. A MIB profile selects which subtrees are exposed, and the
// honeynet topology is published as a real ipNetToMediaTable (ARP table) so a
// scanner walking the MIB enumerates the artificial L2/L3 inventory.

// SNMP MIB profiles, smallest to largest.
const (
	mibMinimal = "minimal" // system group only
	mibHost    = "host"    // + ifNumber + ifTable (default)
	mibNetwork = "network" // + ip group + ipNetToMediaTable (walkable topology)
	mibFull    = "full"    // everything we model
)

func validMIBProfile(p string) bool {
	switch p {
	case mibMinimal, mibHost, mibNetwork, mibFull:
		return true
	}
	return false
}

// mibEntry is one resolved OID instance and its typed value.
type mibEntry struct {
	oid []int
	typ g.Asn1BER
	val any
}

func (e mibEntry) name() string { return oidString(e.oid) }

// parseOID turns a dotted OID string into integer sub-identifiers, reusing
// atoiSafe so a fuzzer's "9999999999" can't drive a huge allocation.
func parseOID(s string) ([]int, bool) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, ok := atoiSafe(p)
		if !ok {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func oidString(o []int) string {
	var b strings.Builder
	for i, n := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

// oidLess reports whether a sorts before b under SNMP's component-wise
// numeric ordering (NOT string order: 1.2.10 sorts after 1.2.2).
func oidLess(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func oidEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// macBytes parses a MAC string into its 6 raw bytes (what a real agent
// returns for a PhysAddress); falls back to the raw string on parse error.
func macBytes(s string) []byte {
	if hw, err := net.ParseMAC(s); err == nil {
		return []byte(hw)
	}
	return []byte(s)
}

// buildSNMPMIB assembles the ordered MIB for the given archetype + honeynet
// topology under the named profile. Returns nil when there's no archetype
// (the handler then answers Null, identical to the no-archetype path).
func buildSNMPMIB(arch *archetype.Profile, hosts []HoneynetHost, profile string) []mibEntry {
	if arch == nil {
		return nil
	}
	if !validMIBProfile(profile) {
		profile = mibHost
	}
	var e []mibEntry
	add := func(oid string, typ g.Asn1BER, val any) {
		if o, ok := parseOID(oid); ok {
			e = append(e, mibEntry{o, typ, val})
		}
	}

	// system group — every profile.
	add("1.3.6.1.2.1.1.1.0", g.OctetString, []byte(arch.SNMPSysDescr()))
	add("1.3.6.1.2.1.1.2.0", g.ObjectIdentifier, arch.SNMPSysObjectID())
	add("1.3.6.1.2.1.1.3.0", g.TimeTicks, uint32(360000)) // 1h uptime
	add("1.3.6.1.2.1.1.4.0", g.OctetString, []byte(arch.SNMPSysContact()))
	add("1.3.6.1.2.1.1.5.0", g.OctetString, []byte(arch.SNMPSysName()))
	add("1.3.6.1.2.1.1.6.0", g.OctetString, []byte(arch.SNMPSysLocation()))
	add("1.3.6.1.2.1.1.7.0", g.Integer, 72)

	if profile == mibMinimal {
		sortMIB(e)
		return e
	}

	// interfaces group — host / network / full.
	ifs := arch.Interfaces()
	add("1.3.6.1.2.1.2.1.0", g.Integer, len(ifs)) // ifNumber
	for _, ifc := range ifs {
		base := "1.3.6.1.2.1.2.2.1."
		idx := strconv.Itoa(ifc.Index)
		add(base+"1."+idx, g.Integer, ifc.Index)                 // ifIndex
		add(base+"2."+idx, g.OctetString, []byte(ifc.Descr))     // ifDescr
		add(base+"3."+idx, g.Integer, ifc.Type)                  // ifType
		add(base+"4."+idx, g.Integer, 1500)                      // ifMtu
		add(base+"5."+idx, g.Gauge32, ifc.Speed)                 // ifSpeed
		add(base+"6."+idx, g.OctetString, macBytes(ifc.PhysMAC)) // ifPhysAddress
		add(base+"7."+idx, g.Integer, 1)                         // ifAdminStatus up
		oper := 2                                                // down
		if ifc.OperUp {
			oper = 1
		}
		add(base+"8."+idx, g.Integer, oper) // ifOperStatus
	}

	if profile == mibNetwork || profile == mibFull {
		// ip group scalar + the walkable topology (ARP / ipNetToMediaTable).
		add("1.3.6.1.2.1.4.1.0", g.Integer, 1) // ipForwarding = forwarding
		for _, h := range hosts {
			ip4 := net.ParseIP(h.IP).To4()
			if ip4 == nil {
				continue // ipNetToMediaTable is IPv4-indexed
			}
			ipStr := ip4.String()
			base := "1.3.6.1.2.1.4.22.1."
			suf := "1." + ipStr                                // ifIndex(1) . a.b.c.d
			add(base+"1."+suf, g.Integer, 1)                   // ipNetToMediaIfIndex
			add(base+"2."+suf, g.OctetString, macBytes(h.MAC)) // PhysAddress
			add(base+"3."+suf, g.IPAddress, ipStr)             // NetAddress
			add(base+"4."+suf, g.Integer, 3)                   // Type = dynamic
		}
	}

	sortMIB(e)
	return e
}

func sortMIB(e []mibEntry) {
	sort.Slice(e, func(i, j int) bool { return oidLess(e[i].oid, e[j].oid) })
}

// mibGet returns the exact-match instance for a Get.
func mibGet(mib []mibEntry, oid []int) (mibEntry, bool) {
	i := sort.Search(len(mib), func(i int) bool { return !oidLess(mib[i].oid, oid) })
	if i < len(mib) && oidEqual(mib[i].oid, oid) {
		return mib[i], true
	}
	return mibEntry{}, false
}

// mibNext returns the lexicographic successor instance for a GetNext — the
// primitive snmpwalk repeats to traverse the tree.
func mibNext(mib []mibEntry, oid []int) (mibEntry, bool) {
	i := sort.Search(len(mib), func(i int) bool { return oidLess(oid, mib[i].oid) })
	if i < len(mib) {
		return mib[i], true
	}
	return mibEntry{}, false
}

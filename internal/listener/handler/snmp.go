package handler

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// snmp parses incoming SNMPv1/v2c Get / GetNext / GetBulk packets, extracts
// the community string (a frequent credential-spraying target), and replies
// from a *walkable* MIB built from the configured archetype + honeynet
// topology (system group, ifTable, and the ipNetToMediaTable ARP view). A
// real snmpwalk / snmpbulkwalk traverses it; the exposed subtrees are chosen
// by listener.snmp.mib_profile, and a per-source walk rate-limit (with
// optional tarpit) slows mass walkers. v3 is not supported (auth would be
// complex and irrelevant for a honeypot).
type snmp struct {
	hosts []HoneynetHost
	arch  *archetype.Profile

	mu    sync.Mutex
	mib   []mibEntry
	built string // profile the cached MIB was built for ("" = not built)
	walks map[string]*snmpWalkState
}

// snmpWalkState tracks one source's GetNext/GetBulk volume in the current
// minute window for rate-limiting / tarpitting.
type snmpWalkState struct {
	windowStart time.Time
	count       int
}

// snmpBulkCap bounds GetBulk max-repetitions so a single request can't make
// us emit an unbounded response (and feeds the rate limiter honestly).
const snmpBulkCap = 60

func (s *snmp) Name() string { return "snmp" }

// SetHoneynetView lets the listener install topology data after the
// handler has been constructed via GetUDP; it invalidates the MIB cache so
// the next request rebuilds it with the new ipNetToMediaTable.
func (s *snmp) SetHoneynetView(v HoneynetSnapshot) {
	s.mu.Lock()
	s.hosts = v.Hosts
	s.mib, s.built = nil, ""
	s.mu.Unlock()
}

// mibFor returns the cached MIB for the requested profile, rebuilding it when
// the profile changed or the cache was invalidated. Caller must not hold s.mu.
func (s *snmp) mibFor(profile string) []mibEntry {
	if profile == "" {
		profile = mibHost
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mib == nil || s.built != profile {
		s.mib = buildSNMPMIB(s.arch, s.hosts, profile)
		s.built = profile
	}
	return s.mib
}

// allowWalk applies the per-source walk rate-limit. It returns whether to
// answer and, when over-limit-but-tarpitting, how long to delay first. steps
// is the number of varbinds this request will emit. Caller must not hold s.mu.
func (s *snmp) allowWalk(srcIP string, cfg config.SNMPListener, now time.Time, steps int) (allow bool, delay time.Duration, exceeded bool) {
	if cfg.WalkRatePerMin <= 0 {
		return true, 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.walks == nil {
		s.walks = map[string]*snmpWalkState{}
	}
	// Opportunistic GC so the map can't grow without bound.
	if len(s.walks) > 4096 {
		for ip, st := range s.walks {
			if now.Sub(st.windowStart) >= time.Minute {
				delete(s.walks, ip)
			}
		}
	}
	st := s.walks[srcIP]
	if st == nil || now.Sub(st.windowStart) >= time.Minute {
		st = &snmpWalkState{windowStart: now}
		s.walks[srcIP] = st
	}
	st.count += steps
	if st.count <= cfg.WalkRatePerMin {
		return true, 0, false
	}
	// Over the limit: tarpit (delay then answer) or drop.
	if cfg.WalkTarpit > 0 {
		return true, cfg.WalkTarpit, true
	}
	return false, 0, true
}

func (s *snmp) Handle(ctx context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}

	// gosnmp's SnmpPacket.UnmarshalMsg works on raw bytes via the GoSNMP
	// helper but constructing one for unmarshalling is awkward. We use the
	// low-level Unmarshal from gosnmp's package via the helper below.
	client := &g.GoSNMP{}
	pkt, err := client.SnmpDecodePacket(payload)
	if err != nil {
		res.Meta = map[string]any{"decode_err": err.Error()}
		// A malformed/oversized request the strict decoder rejected is exactly
		// the SNMP-subsystem exploit / fuzz class — run the tolerant inspector
		// so the structural anomalies + Cisco SNMP RCE CVEs still surface.
		applySNMPInspect(&res, inspectSNMP(payload))
		// Still record what we saw, just don't reply (don't echo crap).
		return res, nil
	}
	meta := map[string]any{
		"version":   versionName(pkt.Version),
		"community": pkt.Community,
		"pdu_type":  pduTypeName(pkt.PDUType),
	}
	// When the operator has configured a honeynet, the SNMP handler
	// advertises a synthesized "neighbor table" — list of IP+MAC pairs
	// from the topology. A scanner that walks our MIB sees a populated
	// L2/L3 inventory of the artificial network, reinforcing the lie
	// without us having to implement the full ipNetToMediaTable.
	if len(s.hosts) > 0 {
		neighbors := make([]map[string]string, 0, len(s.hosts))
		for _, h := range s.hosts {
			neighbors = append(neighbors, map[string]string{
				"ip": h.IP, "mac": h.MAC, "hostname": h.Hostname, "os": h.OS,
			})
		}
		meta["honeynet_neighbors"] = neighbors
	}
	if len(pkt.Variables) > 0 {
		oids := make([]string, 0, len(pkt.Variables))
		for _, v := range pkt.Variables {
			oids = append(oids, v.Name)
		}
		meta["oids"] = oids
	}
	// SNMPv3 USM: the msgUserName a client presents is the security identity
	// being used/brute-forced (gosnmp doesn't surface it on a decode-only
	// path, so pull it from the raw msgSecurityParameters).
	if pkt.Version == g.Version3 {
		if u := snmpV3UserName(payload); u != "" {
			meta["snmp_v3_user"] = safe.SanitizeForLog(u)
		}
	}
	res.Meta = meta
	// Tolerant structural inspection on the raw bytes: flags oversized/randomized
	// OIDs and the Cisco IOS / IOS XE SNMP RCE class even on a packet gosnmp
	// decoded cleanly (a crafted-but-valid-framing exploit OID).
	applySNMPInspect(&res, inspectSNMP(payload))

	// SNMPv3 USM: the act of presenting (or probing) a security name is
	// username enumeration / engine discovery — there is no legitimate reason
	// for an external party to USM-probe a decoy.
	if pkt.Version == g.Version3 {
		flagAnomaly(&res, "snmp-v3-user-enum")
		if u, _ := res.Meta["snmp_v3_user"].(string); u == "" {
			res.Meta["intent"] = "SNMPv3 engine-discovery probe (empty USM user)"
		} else {
			setIfEmpty(res.Meta, "intent", "SNMPv3 USM username enumeration / auth probe")
		}
	}

	// Protocol-misuse detection. An SNMP SetRequest is an attempt to
	// *write* the device's configuration — flip an interface, rewrite an
	// ACL, or trigger a running-config copy to an attacker TFTP server.
	// The honeypot never applies the write (we don't even reply), but a
	// write attempt against any of our SNMP-advertising archetypes
	// (switch / PLC / printer / camera) is a high-signal manipulation
	// event, so we flag it and capture the target OIDs + intended values.
	if pkt.PDUType == g.SetRequest {
		flagAnomaly(&res, "snmp-set-attempt")
		if len(pkt.Variables) > 0 {
			// Raw is fine here: the listener sanitizes res.Meta centrally
			// (safe.SanitizeMetaStrings) before anything reaches a sink.
			sets := make([]string, 0, len(pkt.Variables))
			for _, v := range pkt.Variables {
				sets = append(sets, v.Name+"="+snmpValueString(v))
				classifySNMPSetTarget(&res, v.Name)
			}
			res.Meta["snmp_set"] = sets
		}
	}

	// Reading a sensitive MIB table (process list, routing/ARP/TCP tables) is
	// host/network reconnaissance even on a read PDU with a valid community.
	if pkt.PDUType == g.GetRequest || pkt.PDUType == g.GetNextRequest || pkt.PDUType == g.GetBulkRequest {
		for _, v := range pkt.Variables {
			if what := snmpSensitiveOID(v.Name); what != "" {
				flagAnomaly(&res, "snmp-sensitive-oid-read")
				res.Meta["snmp_sensitive_oid"] = what
				setIfEmpty(res.Meta, "intent", "SNMP sensitive-table read — "+what)
				break
			}
		}
	}

	// GetBulk with a large max-repetitions is the SNMP amplification primitive
	// (one small request fans out into many varbinds). The walk rate-limiter
	// below bounds what we actually emit; this flags the intent.
	if pkt.PDUType == g.GetBulkRequest && pkt.MaxRepetitions >= 100 {
		flagAnomaly(&res, "snmp-getbulk-amplification")
		res.Meta["snmp_max_repetitions"] = pkt.MaxRepetitions
	}
	// Default community strings are the first credential a scanner tries —
	// worth surfacing as a (weak) captured credential.
	defaultCommunity := false
	if snmpIsDefaultCommunity(pkt.Community) {
		res.Meta["snmp_default_community"] = true
		defaultCommunity = true
		flagAnomaly(&res, "snmp-default-community")
	}
	// Fingerprint SNMP brute/spray tools from the (weak) community string.
	if tools := toolfp.IdentifySNMP(pkt.Community); len(tools) > 0 {
		res.Meta["tools"] = tools
		for _, t := range tools {
			flagAnomaly(&res, "tool:"+t)
		}
	}

	// Config-exfil / tampering: a request touching CISCO-CONFIG-COPY-MIB
	// (1.3.6.1.4.1.9.9.96, ccCopyTable) is the textbook "copy running-config to
	// my TFTP server" attack (or push a new config onto the device). Detect it
	// on any OID, whichever PDU carries it.
	configExfil := false
	for _, v := range pkt.Variables {
		if strings.Contains(v.Name, "1.3.6.1.4.1.9.9.96") {
			configExfil = true
			break
		}
	}
	if configExfil {
		flagAnomaly(&res, "snmp-config-exfil")
	}

	// Summarize what the attacker is actually doing (the human "intent" label).
	intent := ""
	switch {
	case configExfil:
		intent = "SNMP CISCO-CONFIG-COPY-MIB access — running-config exfil/overwrite to attacker TFTP"
	case pkt.PDUType == g.SetRequest:
		intent = "SNMP SET — writing device configuration (interface/ACL/route tampering)"
	case pkt.PDUType == g.GetBulkRequest && pkt.MaxRepetitions >= 100:
		intent = "SNMP GetBulk amplification — DRDoS reflector staging / bulk MIB exfil"
	case pkt.PDUType == g.GetNextRequest || pkt.PDUType == g.GetBulkRequest:
		intent = "SNMP MIB walk — device / network-inventory enumeration"
	case pkt.PDUType == g.GetRequest:
		intent = "SNMP GET — device fingerprint / OID probe"
	}
	if intent != "" {
		if defaultCommunity {
			intent += " (default community '" + pkt.Community + "')"
		}
		// setIfEmpty so the more specific SET-target / sensitive-read / v3 intents
		// set above win over this generic per-PDU label.
		setIfEmpty(res.Meta, "intent", intent)
	}

	// Only reply to Get / GetNext / GetBulk. Traps/responses (and the
	// SetRequest above) we just log.
	if pkt.PDUType != g.GetRequest && pkt.PDUType != g.GetNextRequest && pkt.PDUType != g.GetBulkRequest {
		return res, nil
	}

	mib := s.mibFor(cfg.SNMP.MIBProfile)
	res.Meta["mib_profile"] = effectiveMIBProfile(cfg.SNMP.MIBProfile)
	respPDUs := s.buildResponse(pkt, mib)

	// Walk rate-limit / tarpit: GetNext + GetBulk are the walk primitives.
	// Each emitted varbind counts as a step.
	if pkt.PDUType == g.GetNextRequest || pkt.PDUType == g.GetBulkRequest {
		allow, delay, exceeded := s.allowWalk(hostFromAddr(src), cfg.SNMP, time.Now(), len(respPDUs))
		if exceeded {
			flagAnomaly(&res, "snmp-walk-rate-exceeded")
		}
		if !allow {
			res.Meta["snmp_walk_dropped"] = true
			return res, nil // silently drop the over-limit walk step
		}
		if delay > 0 {
			res.Meta["snmp_walk_tarpit_ms"] = int(delay / time.Millisecond)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return res, nil
			}
		}
	}

	respPkt := &g.SnmpPacket{
		Version:    pkt.Version,
		Community:  pkt.Community,
		PDUType:    g.GetResponse,
		RequestID:  pkt.RequestID,
		Error:      0,
		ErrorIndex: 0,
		Variables:  respPDUs,
	}
	out, err := respPkt.MarshalMsg()
	if err != nil {
		res.Meta["marshal_err"] = err.Error()
		return res, nil
	}
	if _, err := pc.WriteTo(out, src); err != nil {
		res.Meta["write_err"] = err.Error()
	} else {
		res.BannerSent = fmt.Sprintf("snmp %s GetResponse (community=%s)", versionName(pkt.Version), pkt.Community)
	}
	_ = cfg
	return res, nil
}

// effectiveMIBProfile resolves the configured profile to the value actually
// used (empty / invalid → the "host" default).
func effectiveMIBProfile(p string) string {
	if p == "" || !validMIBProfile(p) {
		return mibHost
	}
	return p
}

// buildResponse turns a request packet into the response varbinds, honoring
// the PDU type: Get = exact match, GetNext = lexicographic successor, GetBulk
// = up to max-repetitions successors per repeater varbind. Unknown OIDs (and
// no-archetype) get Null; walking past the end returns the requested OID with
// Null so the client terminates the walk.
func (s *snmp) buildResponse(pkt *g.SnmpPacket, mib []mibEntry) []g.SnmpPDU {
	switch pkt.PDUType {
	case g.GetRequest:
		out := make([]g.SnmpPDU, 0, len(pkt.Variables))
		for _, v := range pkt.Variables {
			out = append(out, mibGetVarbind(mib, v.Name))
		}
		return out
	case g.GetNextRequest:
		out := make([]g.SnmpPDU, 0, len(pkt.Variables))
		for _, v := range pkt.Variables {
			out = append(out, mibNextVarbind(mib, v.Name))
		}
		return out
	case g.GetBulkRequest:
		return bulkResponse(mib, pkt)
	}
	return nil
}

// bulkResponse implements GetBulk: the first NonRepeaters varbinds get a
// single GetNext; each remaining (repeater) varbind walks forward up to
// MaxRepetitions (capped) successive OIDs.
func bulkResponse(mib []mibEntry, pkt *g.SnmpPacket) []g.SnmpPDU {
	nonRep := int(pkt.NonRepeaters)
	if nonRep < 0 {
		nonRep = 0
	}
	if nonRep > len(pkt.Variables) {
		nonRep = len(pkt.Variables)
	}
	maxRep := int(pkt.MaxRepetitions)
	if maxRep < 0 || maxRep > snmpBulkCap {
		maxRep = snmpBulkCap
	}
	var out []g.SnmpPDU
	for i, v := range pkt.Variables {
		if i < nonRep {
			out = append(out, mibNextVarbind(mib, v.Name))
			continue
		}
		cur := v.Name
		for r := 0; r < maxRep; r++ {
			pdu := mibNextVarbind(mib, cur)
			out = append(out, pdu)
			if pdu.Type == g.Null { // end of MIB for this repeater
				break
			}
			cur = pdu.Name
		}
	}
	return out
}

// mibGetVarbind answers a Get for one OID.
func mibGetVarbind(mib []mibEntry, name string) g.SnmpPDU {
	oid, ok := parseOID(name)
	if !ok {
		return g.SnmpPDU{Name: name, Type: g.Null}
	}
	if e, found := mibGet(mib, oid); found {
		return g.SnmpPDU{Name: name, Type: e.typ, Value: liveMibValue(e)}
	}
	return g.SnmpPDU{Name: name, Type: g.Null}
}

// snmpBaselineUptime makes the decoy present as an established, long-running box
// rather than one that just rebooted.
const snmpBaselineUptime = 86 * time.Hour // ~3.6 days

// snmpBootTime is the decoy's apparent boot instant (baseline before process
// start), so sysUpTime advances during the sensor's run instead of reporting a
// frozen value — a frozen uptime across repeated polls is a honeypot tell.
var snmpBootTime = time.Now().Add(-snmpBaselineUptime)

// uptime OIDs whose value must advance, not stay frozen in the cached MIB.
var snmpUptimeOIDs = map[string]bool{
	"1.3.6.1.2.1.1.3.0":    true, // sysUpTime
	"1.3.6.1.2.1.25.1.1.0": true, // hrSystemUptime
}

// liveMibValue returns the response value for a cached MIB entry, substituting a
// live, advancing tick count for the uptime OIDs (TimeTicks = 1/100 s).
func liveMibValue(e mibEntry) any {
	if snmpUptimeOIDs[e.name()] {
		return uint32(time.Since(snmpBootTime) / (10 * time.Millisecond))
	}
	return e.val
}

// mibNextVarbind answers a GetNext for one OID. Past the end of the MIB it
// echoes the requested OID with Null so the client stops walking.
func mibNextVarbind(mib []mibEntry, name string) g.SnmpPDU {
	oid, ok := parseOID(name)
	if !ok {
		return g.SnmpPDU{Name: name, Type: g.Null}
	}
	if e, found := mibNext(mib, oid); found {
		return g.SnmpPDU{Name: "." + e.name(), Type: e.typ, Value: liveMibValue(e)}
	}
	return g.SnmpPDU{Name: name, Type: g.Null}
}

// atoiSafe converts a decimal string to int with strict bounds — refuses
// negative values, refuses anything outside int32 range, returns ok=false
// on non-digit input. Used in OID parsing so fuzz-style "9999999999"
// can't bend us into a panic or huge allocation.
func atoiSafe(s string) (int, bool) {
	if s == "" || len(s) > 10 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	return n, true
}

// snmpValueString renders a varbind value for forensic capture. Strings
// stay strings (the caller sanitizes); everything else is formatted
// generically. Kept tiny and allocation-light — this only runs on the
// rare SetRequest path.
func snmpValueString(v g.SnmpPDU) string {
	switch val := v.Value.(type) {
	case []byte:
		return string(val)
	case string:
		return val
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", val)
	}
}

// snmpDefaultCommunities is the wordlist a scanner sprays first. Matched
// case-insensitively. Reaching a decoy with any of these is a credential
// guess, not just the canonical public/private pair.
var snmpDefaultCommunities = map[string]bool{
	"public": true, "private": true, "cisco": true, "ilmi": true, "secret": true,
	"admin": true, "read": true, "write": true, "snmpd": true, "community": true,
	"manager": true, "default": true, "monitor": true, "security": true, "0": true,
	"readwrite": true, "all private": true, "all public": true, "snmp": true,
}

func snmpIsDefaultCommunity(c string) bool {
	return snmpDefaultCommunities[strings.ToLower(strings.TrimSpace(c))]
}

// classifySNMPSetTarget flags high-signal SetRequest targets: command execution
// via the NET-SNMP-EXTEND-MIB (CVE-2020-15862), interface enable/disable, and
// device-identity rewrites — beyond the generic snmp-set-attempt marker.
func classifySNMPSetTarget(res *Result, oid string) {
	switch {
	case strings.Contains(oid, "1.3.6.1.4.1.8072.1.3.2"): // NET-SNMP-EXTEND-MIB nsExtendObjects
		flagAnomaly(res, "snmp-extend-exec")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2020-15862")
		flagAnomaly(res, "cve:CVE-2020-15862")
		res.Meta["intent"] = "SNMP SET to NET-SNMP-EXTEND-MIB — arbitrary command execution (CVE-2020-15862)"
	case strings.Contains(oid, "1.3.6.1.2.1.2.2.1.7"): // ifAdminStatus
		flagAnomaly(res, "snmp-interface-shutdown")
		res.Meta["intent"] = "SNMP SET ifAdminStatus — interface enable/disable (control manipulation)"
	case strings.Contains(oid, "1.3.6.1.2.1.1.4"), strings.Contains(oid, "1.3.6.1.2.1.1.5"), strings.Contains(oid, "1.3.6.1.2.1.1.6"): // sysContact/sysName/sysLocation
		flagAnomaly(res, "snmp-identity-rewrite")
		res.Meta["intent"] = "SNMP SET sysName/sysContact/sysLocation — device identity rewrite"
	case strings.Contains(oid, "1.3.6.1.2.1.43"): // Printer-MIB
		flagAnomaly(res, "snmp-device-control")
		res.Meta["intent"] = "SNMP SET to Printer-MIB — printer control/tampering"
	case strings.Contains(oid, "1.3.6.1.2.1.33"): // UPS-MIB (upsControl)
		flagAnomaly(res, "snmp-device-control")
		res.Meta["intent"] = "SNMP SET to UPS-MIB — power/UPS control (potential shutdown)"
	case strings.Contains(oid, "1.3.6.1.2.1.17"): // dot1dBridge
		flagAnomaly(res, "snmp-device-control")
		res.Meta["intent"] = "SNMP SET to BRIDGE-MIB — switch forwarding/VLAN tampering"
	}
}

// snmpSensitiveOID names the sensitive MIB table an OID targets, or "".
func snmpSensitiveOID(oid string) string {
	switch {
	case strings.Contains(oid, "1.3.6.1.2.1.25.4.2.1.2"):
		return "process list (hrSWRunName)"
	case strings.Contains(oid, "1.3.6.1.2.1.25.6.3.1.2"):
		return "installed software (hrSWInstalledName)"
	case strings.Contains(oid, "1.3.6.1.2.1.4.21"):
		return "routing table (ipRouteTable)"
	case strings.Contains(oid, "1.3.6.1.2.1.4.22"), strings.Contains(oid, "1.3.6.1.2.1.4.35"):
		return "ARP table (ipNetToMediaTable)"
	case strings.Contains(oid, "1.3.6.1.2.1.6.13"), strings.Contains(oid, "1.3.6.1.2.1.6.19"):
		return "TCP connection table (tcpConnTable)"
	}
	return ""
}

func versionName(v g.SnmpVersion) string {
	switch v {
	case g.Version1:
		return "v1"
	case g.Version2c:
		return "v2c"
	case g.Version3:
		return "v3"
	}
	return "unknown"
}

func pduTypeName(t g.PDUType) string {
	switch t {
	case g.GetRequest:
		return "GetRequest"
	case g.GetNextRequest:
		return "GetNextRequest"
	case g.GetResponse:
		return "GetResponse"
	case g.SetRequest:
		return "SetRequest"
	case g.Trap:
		return "Trap"
	case g.GetBulkRequest:
		return "GetBulkRequest"
	case g.InformRequest:
		return "InformRequest"
	case g.SNMPv2Trap:
		return "SNMPv2Trap"
	}
	return fmt.Sprintf("0x%02x", byte(t))
}

// berTLVAt reads one definite-length BER TLV at offset off, returning the tag,
// value, and the offset just past it. Bounds-checked.
func berTLVAt(b []byte, off int) (tag byte, val []byte, next int, ok bool) {
	if off < 0 || off+2 > len(b) {
		return 0, nil, 0, false
	}
	tag = b[off]
	l := int(b[off+1])
	p := off + 2
	if l&0x80 != 0 {
		nb := l & 0x7f
		if nb == 0 || nb > 4 || p+nb > len(b) {
			return 0, nil, 0, false
		}
		l = 0
		for i := 0; i < nb; i++ {
			l = l<<8 | int(b[p+i])
		}
		p += nb
	}
	if l < 0 || p+l > len(b) {
		return 0, nil, 0, false
	}
	return tag, b[p : p+l], p + l, true
}

// snmpV3UserName extracts msgUserName from a raw SNMPv3 message. The outer
// SEQUENCE is { msgVersion, msgGlobalData, msgSecurityParameters OCTET STRING,
// msgData }; the security parameters wrap a SEQUENCE whose 4th field is the
// userName (after engineID, engineBoots, engineTime).
func snmpV3UserName(b []byte) string {
	tag, outer, _, ok := berTLVAt(b, 0)
	if !ok || tag != 0x30 {
		return ""
	}
	var sec []byte
	off := 0
	for i := 0; i < 3 && off < len(outer); i++ {
		t, v, next, ok := berTLVAt(outer, off)
		if !ok {
			return ""
		}
		if i == 2 && t == 0x04 {
			sec = v
		}
		off = next
	}
	if sec == nil {
		return ""
	}
	t, inner, _, ok := berTLVAt(sec, 0)
	if !ok || t != 0x30 {
		return ""
	}
	o := 0
	for i := 0; i < 4 && o < len(inner); i++ {
		tt, vv, nx, ok := berTLVAt(inner, o)
		if !ok {
			return ""
		}
		if i == 3 && tt == 0x04 {
			return string(vv)
		}
		o = nx
	}
	return ""
}

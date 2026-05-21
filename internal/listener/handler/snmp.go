package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// snmp parses incoming SNMPv1/v2c GetRequest packets, extracts the
// community string (a frequent credential-spraying target), and replies
// with a GetResponse populated from the configured archetype's MIB-2
// identity (sysDescr / sysObjectID / sysName / sysContact /
// sysLocation / ifTable). v3 is not supported (auth would be complex
// and irrelevant for a honeypot).
type snmp struct {
	hosts []HoneynetHost
	arch  *archetype.Profile
}

func (s *snmp) Name() string { return "snmp" }

// SetHoneynetView lets the listener install topology data after the
// handler has been constructed via GetUDP.
func (s *snmp) SetHoneynetView(v HoneynetSnapshot) { s.hosts = v.Hosts }

func (s *snmp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}

	// gosnmp's SnmpPacket.UnmarshalMsg works on raw bytes via the GoSNMP
	// helper but constructing one for unmarshalling is awkward. We use the
	// low-level Unmarshal from gosnmp's package via the helper below.
	client := &g.GoSNMP{}
	pkt, err := client.SnmpDecodePacket(payload)
	if err != nil {
		res.Meta = map[string]any{"decode_err": err.Error()}
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
	res.Meta = meta

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
			}
			res.Meta["snmp_set"] = sets
		}
	}

	// Only reply to GetRequest / GetNextRequest. Traps/responses (and
	// the SetRequest above) we just log.
	if pkt.PDUType != g.GetRequest && pkt.PDUType != g.GetNextRequest {
		return res, nil
	}

	// Build a GetResponse populated from the archetype's MIB-2 view
	// where we have one; fall back to Null for unknown OIDs.
	respPDUs := make([]g.SnmpPDU, 0, len(pkt.Variables))
	for _, v := range pkt.Variables {
		respPDUs = append(respPDUs, s.respondVarbind(v, pkt.PDUType == g.GetNextRequest))
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

// respondVarbind crafts a single response PDU for the given request
// varbind. When the OID is one of the well-known MIB-2 system-group
// or ifTable entries AND we have an archetype loaded, we answer with
// the archetype's value; otherwise we return Null so we don't leak
// implementation details. The matching is intentionally narrow: we
// only answer prefixes we recognize, so a fuzzer's random OID list
// gets honest Null replies and can't drive us into a code path we
// haven't audited.
func (s *snmp) respondVarbind(req g.SnmpPDU, isGetNext bool) g.SnmpPDU {
	if s.arch == nil {
		return g.SnmpPDU{Name: req.Name, Type: g.Null}
	}
	// Strip leading dot. GoSNMP returns OIDs with a leading dot in
	// some Go versions; normalize.
	q := strings.TrimPrefix(req.Name, ".")
	// For GetNext we cheat: just answer like Get for system group OIDs.
	_ = isGetNext

	switch q {
	case "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.1": // sysDescr
		return g.SnmpPDU{Name: req.Name, Type: g.OctetString, Value: []byte(s.arch.SNMPSysDescr())}
	case "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.2": // sysObjectID
		return g.SnmpPDU{Name: req.Name, Type: g.ObjectIdentifier, Value: s.arch.SNMPSysObjectID()}
	case "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.3": // sysUpTime
		// Fixed 1-hour uptime in 1/100s.
		return g.SnmpPDU{Name: req.Name, Type: g.TimeTicks, Value: uint32(360000)}
	case "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.4": // sysContact
		return g.SnmpPDU{Name: req.Name, Type: g.OctetString, Value: []byte(s.arch.SNMPSysContact())}
	case "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5": // sysName
		return g.SnmpPDU{Name: req.Name, Type: g.OctetString, Value: []byte(s.arch.SNMPSysName())}
	case "1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.6": // sysLocation
		return g.SnmpPDU{Name: req.Name, Type: g.OctetString, Value: []byte(s.arch.SNMPSysLocation())}
	case "1.3.6.1.2.1.1.7.0", "1.3.6.1.2.1.1.7": // sysServices
		// 72 = application + end-to-end + internet + physical for a switch
		return g.SnmpPDU{Name: req.Name, Type: g.Integer, Value: 72}
	}
	// ifTable: 1.3.6.1.2.1.2.2.1.<col>.<ifIndex>.
	// Cols: 1=ifIndex, 2=ifDescr, 3=ifType, 5=ifSpeed, 6=ifPhysAddress, 8=ifOperStatus.
	if strings.HasPrefix(q, "1.3.6.1.2.1.2.2.1.") {
		parts := strings.Split(q[len("1.3.6.1.2.1.2.2.1."):], ".")
		if len(parts) == 2 {
			col := parts[0]
			idxStr := parts[1]
			idx, ok := atoiSafe(idxStr)
			if !ok {
				return g.SnmpPDU{Name: req.Name, Type: g.Null}
			}
			for _, ifc := range s.arch.Interfaces() {
				if ifc.Index != idx {
					continue
				}
				switch col {
				case "1":
					return g.SnmpPDU{Name: req.Name, Type: g.Integer, Value: ifc.Index}
				case "2":
					return g.SnmpPDU{Name: req.Name, Type: g.OctetString, Value: []byte(ifc.Descr)}
				case "3":
					return g.SnmpPDU{Name: req.Name, Type: g.Integer, Value: ifc.Type}
				case "5":
					return g.SnmpPDU{Name: req.Name, Type: g.Gauge32, Value: ifc.Speed}
				case "6":
					return g.SnmpPDU{Name: req.Name, Type: g.OctetString, Value: []byte(ifc.PhysMAC)}
				case "8":
					st := 2 // down
					if ifc.OperUp {
						st = 1
					}
					return g.SnmpPDU{Name: req.Name, Type: g.Integer, Value: st}
				}
			}
		}
	}
	return g.SnmpPDU{Name: req.Name, Type: g.Null}
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

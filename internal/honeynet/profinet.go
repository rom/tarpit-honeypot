package honeynet

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// ProfinetCfg controls the per-honeynet PROFINET-DCP responder. PROFINET
// Discovery and Configuration Protocol (DCP) is the L2 (EtherType 0x8892)
// mechanism Siemens PRONETA / TIA Portal / nmap profinet scripts use to
// enumerate PROFINET stations on a segment. When enabled, the sensor
// answers DCP "Identify" requests on behalf of each virtual industrial
// host so a scan sees a populated PROFINET cell — and, because a DCP
// Identify is itself a strong ICS-reconnaissance signal, emits a
// detection event for every request it observes.
//
// Linux + CAP_NET_RAW only (raw L2 socket); the non-Linux build returns
// an error so the operator gets a clean diagnostic.
type ProfinetCfg struct {
	Enabled   bool
	Interface string
}

// ProbeFunc is invoked for each DCP Identify request observed, so the
// sensor can raise a detection event without this package importing the
// event bus. meta carries requester_mac / name_filter / xid.
type ProbeFunc func(srcMAC string, meta map[string]any)

// StartProfinetDCP launches the responder. Returns when ctx is cancelled
// (Linux) or immediately with an error (other platforms).
func StartProfinetDCP(ctx context.Context, cfg ProfinetCfg, topo *Topology, onProbe ProbeFunc) error {
	return startProfinetDCP(ctx, cfg, topo, onProbe)
}

// PROFINET / DCP wire constants.
const (
	ethTypePROFINET    = 0x8892
	dcpFrameIDIdentReq = 0xFEFE
	dcpFrameIDIdentRes = 0xFEFF
	dcpFrameIDGetSet   = 0xFEFD

	dcpServiceGet         = 0x03
	dcpServiceSet         = 0x04
	dcpServiceIdentify    = 0x05
	dcpServiceTypeRequest = 0x00
	dcpServiceTypeRespOK  = 0x01

	dcpOptIP            = 0x01
	dcpSubIPParameter   = 0x02
	dcpOptDeviceProps   = 0x02
	dcpSubDeviceVendor  = 0x01
	dcpSubNameOfStation = 0x02
	dcpSubDeviceID      = 0x03
	dcpSubDeviceRole    = 0x04
	dcpOptControl       = 0x05
	dcpSubCtrlSignal    = 0x03
	dcpSubCtrlResponse  = 0x04
	dcpSubCtrlFactory   = 0x05
	dcpSubCtrlResetData = 0x06
	dcpOptAll           = 0xFF
)

// pnStation is one PROFINET node we answer DCP for.
type pnStation struct {
	name     string
	ip       string
	mac      [6]byte
	vendor   string // DeviceVendorValue, e.g. "Siemens"
	role     byte   // 0x01 io-device, 0x02 io-controller
	vendorID uint16
	deviceID uint16
}

// collectPNStations builds the responder's station list from the topology.
// A host's archetype PROFINET device tree (SCALANCE-class switches carry
// one) becomes one station per node, each with a MAC derived from the
// owning host's identity. Industrial hosts with no explicit tree advertise
// themselves as a single io-device.
func collectPNStations(topo *Topology) []pnStation {
	if topo == nil {
		return nil
	}
	var out []pnStation
	seen := map[string]bool{} // dedup by station name
	for _, n := range topo.nets {
		for _, h := range n.Hosts {
			if h.Archetype == nil {
				continue
			}
			devs := h.Archetype.PROFINETDevices()
			if len(devs) > 0 {
				for _, d := range devs {
					if d.StationName == "" || seen[d.StationName] {
						continue
					}
					seen[d.StationName] = true
					out = append(out, stationFromTree(h, d))
				}
				continue
			}
			if isIndustrial(h.Archetype.Family) && h.Hostname != "" && !seen[h.Hostname] {
				seen[h.Hostname] = true
				out = append(out, pnStation{
					name:     dcpName(h.Hostname),
					ip:       h.IP,
					mac:      h.MAC,
					vendor:   vendorString(h.Archetype.Family),
					role:     0x01,
					vendorID: vendorIDFor(h.Archetype.Family),
					deviceID: uint16(h.Identity.Uint32("profinet-devid")),
				})
			}
		}
	}
	return out
}

func stationFromTree(h *Host, d archetype.PROFINETDevice) pnStation {
	devID := h.Identity.Derive("profinet/" + d.StationName)
	mac := devID.MAC()
	if h.Archetype.HasMACOUI() {
		mac = devID.MACWithOUI(h.Archetype.MACOUI())
	}
	role := byte(0x01)
	if strings.Contains(strings.ToLower(d.Role), "controller") {
		role = 0x02
	}
	vendor := d.Vendor
	if vendor == "" {
		vendor = vendorString(h.Archetype.Family)
	}
	return pnStation{
		name:     dcpName(d.StationName),
		ip:       d.IP,
		mac:      mac,
		vendor:   vendor,
		role:     role,
		vendorID: vendorIDFor(vendor),
		deviceID: uint16(devID.Uint32("devid")),
	}
}

func isIndustrial(family string) bool {
	switch family {
	case "siemens", "moxa", "ics":
		return true
	}
	return false
}

func vendorString(family string) string {
	switch family {
	case "siemens":
		return "Siemens"
	case "moxa":
		return "Moxa"
	}
	return "PROFINET Device"
}

// vendorIDFor maps a vendor name/family to its registered PROFINET Vendor
// ID where known (Siemens 0x002A, Moxa 0x011C), else a generic value.
func vendorIDFor(vendor string) uint16 {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "siemens"):
		return 0x002A
	case strings.Contains(v, "moxa"):
		return 0x011C
	}
	return 0x0100
}

// dcpName lower-cases + trims a station name to the PROFINET naming rules
// (DCP NameOfStation is a lowercase DNS-ish label).
func dcpName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// parseDCPIdentify validates an inbound frame as a DCP Identify request
// and returns the requester MAC, the transaction id, and any
// NameOfStation filter ("" = identify-all). ok=false for non-DCP /
// non-Identify / malformed frames.
func parseDCPIdentify(frame []byte) (reqMAC [6]byte, xid uint32, nameFilter string, ok bool) {
	if len(frame) < 26 {
		return reqMAC, 0, "", false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypePROFINET {
		return reqMAC, 0, "", false
	}
	if binary.BigEndian.Uint16(frame[14:16]) != dcpFrameIDIdentReq {
		return reqMAC, 0, "", false
	}
	if frame[16] != dcpServiceIdentify || frame[17] != dcpServiceTypeRequest {
		return reqMAC, 0, "", false
	}
	copy(reqMAC[:], frame[6:12])
	xid = binary.BigEndian.Uint32(frame[18:22])
	dataLen := int(binary.BigEndian.Uint16(frame[24:26]))
	blocks := frame[26:]
	if dataLen < len(blocks) {
		blocks = blocks[:dataLen]
	}
	nameFilter = extractNameFilter(blocks)
	return reqMAC, xid, nameFilter, true
}

// extractNameFilter walks the request's filter blocks for a NameOfStation
// block (Option 0x02 / Suboption 0x02). Request filter blocks have NO
// BlockInfo field (unlike response blocks): Option, Suboption, Length,
// then the value.
func extractNameFilter(blocks []byte) string {
	p := 0
	for p+4 <= len(blocks) {
		option := blocks[p]
		sub := blocks[p+1]
		blen := int(binary.BigEndian.Uint16(blocks[p+2 : p+4]))
		p += 4
		if p+blen > len(blocks) {
			break
		}
		if option == dcpOptDeviceProps && sub == dcpSubNameOfStation {
			return string(blocks[p : p+blen])
		}
		p += blen
		if blen%2 == 1 {
			p++ // padding
		}
	}
	return ""
}

// dcpSet describes an observed DCP Set request — the configuration-change
// vector (reassign a station's NameOfStation/IP, or a Control/factory-reset).
type dcpSet struct {
	reqMAC  [6]byte // requester (engineering station)
	dstMAC  [6]byte // targeted PROFINET station
	xid     uint32
	option  byte
	sub     byte
	label   string // human-readable target, e.g. "NameOfStation"
	factory bool   // a reset-to-factory / reset-communication-parameters
}

// parseDCPSet validates an inbound frame as a DCP Set request (FrameID
// 0xFEFD, service 0x04) and returns what it targets. ok=false otherwise.
func parseDCPSet(frame []byte) (dcpSet, bool) {
	var s dcpSet
	if len(frame) < 26 {
		return s, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypePROFINET {
		return s, false
	}
	if binary.BigEndian.Uint16(frame[14:16]) != dcpFrameIDGetSet {
		return s, false
	}
	if frame[16] != dcpServiceSet || frame[17] != dcpServiceTypeRequest {
		return s, false
	}
	copy(s.dstMAC[:], frame[0:6])
	copy(s.reqMAC[:], frame[6:12])
	s.xid = binary.BigEndian.Uint32(frame[18:22])
	dataLen := int(binary.BigEndian.Uint16(frame[24:26]))
	blocks := frame[26:]
	if dataLen < len(blocks) {
		blocks = blocks[:dataLen]
	}
	if len(blocks) >= 2 {
		s.option, s.sub = blocks[0], blocks[1]
		s.label, s.factory = dcpSetLabel(s.option, s.sub)
	}
	return s, true
}

// dcpSetLabel names the target of a Set block and flags the destructive
// Control/reset sub-options.
func dcpSetLabel(option, sub byte) (string, bool) {
	switch {
	case option == dcpOptDeviceProps && sub == dcpSubNameOfStation:
		return "NameOfStation", false
	case option == dcpOptIP && sub == dcpSubIPParameter:
		return "IPParameter", false
	case option == dcpOptControl:
		switch sub {
		case dcpSubCtrlSignal:
			return "Control/Signal", false
		case dcpSubCtrlFactory:
			return "Control/ResetToFactory", true
		case dcpSubCtrlResetData:
			return "Control/ResetCommParameters", true
		}
		return "Control", false
	}
	return "option-" + itoaPN(int(option)) + "/" + itoaPN(int(sub)), false
}

// buildDCPSetResponse assembles a DCP Set response (service 0x04, type OK)
// carrying a Control/Response block that ACKs the set as successful — so an
// attacker probing with a Set believes it landed against a live station.
func buildDCPSetResponse(st pnStation, dstMAC [6]byte, xid uint32, setOpt, setSub byte) []byte {
	// Control/Response block payload: the set Option, Suboption, BlockError(0).
	blocks := dcpBlock(dcpOptControl, dcpSubCtrlResponse, 0x0000, []byte{setOpt, setSub, 0x00})

	hdr := make([]byte, 10)
	hdr[0] = dcpServiceSet
	hdr[1] = dcpServiceTypeRespOK
	binary.BigEndian.PutUint32(hdr[2:6], xid)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(blocks)))

	frame := make([]byte, 0, 16+len(hdr)+len(blocks))
	frame = append(frame, dstMAC[:]...)
	frame = append(frame, st.mac[:]...)
	frame = append(frame, byte(ethTypePROFINET>>8), byte(ethTypePROFINET&0xff))
	frame = append(frame, byte(dcpFrameIDGetSet>>8), byte(dcpFrameIDGetSet&0xff))
	frame = append(frame, hdr...)
	frame = append(frame, blocks...)
	return frame
}

func itoaPN(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// buildDCPIdentifyResponse assembles a full Ethernet+PROFINET+DCP Identify
// response frame for one station, addressed to the requester.
func buildDCPIdentifyResponse(st pnStation, dstMAC [6]byte, xid uint32) []byte {
	var blocks []byte
	// Device / NameOfStation.
	blocks = append(blocks, dcpBlock(dcpOptDeviceProps, dcpSubNameOfStation, 0x0000, []byte(st.name))...)
	// Device / DeviceVendor (device type string).
	blocks = append(blocks, dcpBlock(dcpOptDeviceProps, dcpSubDeviceVendor, 0x0000, []byte(st.vendor))...)
	// Device / DeviceID = VendorID(2) + DeviceID(2).
	idVal := make([]byte, 4)
	binary.BigEndian.PutUint16(idVal[0:2], st.vendorID)
	binary.BigEndian.PutUint16(idVal[2:4], st.deviceID)
	blocks = append(blocks, dcpBlock(dcpOptDeviceProps, dcpSubDeviceID, 0x0000, idVal)...)
	// Device / DeviceRole = role(1) + reserved(1).
	blocks = append(blocks, dcpBlock(dcpOptDeviceProps, dcpSubDeviceRole, 0x0000, []byte{st.role, 0x00})...)
	// IP / IPParameter: BlockInfo 0x0001 (IP set) + ip(4)+mask(4)+gw(4).
	// PROFINET-DCP is IPv4-only by specification — the IPParameter block carries
	// a fixed 4-byte address. An IPv6-only honeynet host has no IPv4 to
	// advertise, so 0.0.0.0 (the DCP "no IP set / DHCP" value) is the realistic
	// answer, not a truncated v6 address.
	ip := net.ParseIP(st.ip).To4()
	if ip == nil {
		ip = []byte{0, 0, 0, 0}
	}
	ipVal := make([]byte, 0, 12)
	ipVal = append(ipVal, ip...)
	ipVal = append(ipVal, 255, 255, 255, 0)       // /24 mask
	ipVal = append(ipVal, ip[0], ip[1], ip[2], 1) // gateway = .1
	blocks = append(blocks, dcpBlock(dcpOptIP, dcpSubIPParameter, 0x0001, ipVal)...)

	// DCP header.
	hdr := make([]byte, 10)
	hdr[0] = dcpServiceIdentify
	hdr[1] = dcpServiceTypeRespOK
	binary.BigEndian.PutUint32(hdr[2:6], xid)
	// hdr[6:8] reserved (0). DCPDataLength:
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(blocks)))

	frame := make([]byte, 0, 14+2+len(hdr)+len(blocks))
	frame = append(frame, dstMAC[:]...)
	frame = append(frame, st.mac[:]...)
	frame = append(frame, byte(ethTypePROFINET>>8), byte(ethTypePROFINET&0xff))
	frame = append(frame, byte(dcpFrameIDIdentRes>>8), byte(dcpFrameIDIdentRes&0xff))
	frame = append(frame, hdr...)
	frame = append(frame, blocks...)
	return frame
}

// dcpBlock builds one response DCP block: Option, Suboption, Length(2),
// BlockInfo(2), payload, and a pad byte when the (BlockInfo+payload)
// length is odd so the next block stays even-aligned.
func dcpBlock(option, sub byte, blockInfo uint16, payload []byte) []byte {
	length := 2 + len(payload) // BlockInfo + payload
	out := make([]byte, 0, 4+length+1)
	out = append(out, option, sub)
	out = append(out, byte(length>>8), byte(length&0xff))
	out = append(out, byte(blockInfo>>8), byte(blockInfo&0xff))
	out = append(out, payload...)
	if length%2 == 1 {
		out = append(out, 0x00)
	}
	return out
}

// stationsForRequest returns the stations that should answer a request:
// all of them for identify-all, or just the name-matching one.
func stationsForRequest(all []pnStation, nameFilter string) []pnStation {
	if nameFilter == "" {
		return all
	}
	want := dcpName(nameFilter)
	for _, s := range all {
		if s.name == want {
			return []pnStation{s}
		}
	}
	return nil
}

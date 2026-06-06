package honeynet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildDCPIdentifyRequest synthesizes an identify-all (or name-filtered)
// DCP request frame as a scanner would send it.
func buildDCPIdentifyRequest(reqMAC [6]byte, xid uint32, nameFilter string) []byte {
	var blocks []byte
	if nameFilter == "" {
		// All / All filter block (no BlockInfo in requests).
		blocks = []byte{dcpOptAll, 0xFF, 0x00, 0x00}
	} else {
		blocks = append(blocks, dcpOptDeviceProps, dcpSubNameOfStation)
		blocks = append(blocks, byte(len(nameFilter)>>8), byte(len(nameFilter)&0xff))
		blocks = append(blocks, []byte(nameFilter)...)
		if len(nameFilter)%2 == 1 {
			blocks = append(blocks, 0x00)
		}
	}
	frame := make([]byte, 26)
	mcast := [6]byte{0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00}
	copy(frame[0:6], mcast[:])
	copy(frame[6:12], reqMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], ethTypePROFINET)
	binary.BigEndian.PutUint16(frame[14:16], dcpFrameIDIdentReq)
	frame[16] = dcpServiceIdentify
	frame[17] = dcpServiceTypeRequest
	binary.BigEndian.PutUint32(frame[18:22], xid)
	binary.BigEndian.PutUint16(frame[24:26], uint16(len(blocks)))
	frame = append(frame, blocks...)
	return frame
}

func TestParseDCPIdentifyAll(t *testing.T) {
	req := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	frame := buildDCPIdentifyRequest(req, 0x12345678, "")
	mac, xid, name, ok := parseDCPIdentify(frame)
	if !ok {
		t.Fatal("parseDCPIdentify rejected a valid identify-all request")
	}
	if mac != req {
		t.Errorf("requester MAC = %x; want %x", mac, req)
	}
	if xid != 0x12345678 {
		t.Errorf("xid = %#x; want 0x12345678", xid)
	}
	if name != "" {
		t.Errorf("name filter = %q; want empty (identify-all)", name)
	}
}

func TestParseDCPIdentifyNameFilter(t *testing.T) {
	req := [6]byte{1, 2, 3, 4, 5, 6}
	frame := buildDCPIdentifyRequest(req, 7, "plc-cell3")
	_, _, name, ok := parseDCPIdentify(frame)
	if !ok {
		t.Fatal("parse rejected a valid name-filtered request")
	}
	if name != "plc-cell3" {
		t.Errorf("name filter = %q; want plc-cell3", name)
	}
}

func TestParseDCPIdentifyRejectsNonDCP(t *testing.T) {
	// Wrong EtherType.
	bad := make([]byte, 30)
	binary.BigEndian.PutUint16(bad[12:14], 0x0800)
	if _, _, _, ok := parseDCPIdentify(bad); ok {
		t.Error("accepted a non-PROFINET frame")
	}
	// PROFINET but a response FrameID, not a request.
	resp := make([]byte, 30)
	binary.BigEndian.PutUint16(resp[12:14], ethTypePROFINET)
	binary.BigEndian.PutUint16(resp[14:16], dcpFrameIDIdentRes)
	if _, _, _, ok := parseDCPIdentify(resp); ok {
		t.Error("accepted a DCP response as a request")
	}
}

func TestBuildDCPIdentifyResponseRoundTrips(t *testing.T) {
	st := pnStation{
		name:     "plc-cell3",
		ip:       "192.168.0.10",
		mac:      [6]byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25},
		vendor:   "Siemens",
		role:     0x02,
		vendorID: 0x002A,
		deviceID: 0x0301,
	}
	dst := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	frame := buildDCPIdentifyResponse(st, dst, 0xCAFEBABE)

	if !bytes.Equal(frame[0:6], dst[:]) {
		t.Errorf("dst MAC not the requester")
	}
	if !bytes.Equal(frame[6:12], st.mac[:]) {
		t.Errorf("src MAC not the station")
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypePROFINET {
		t.Errorf("ethertype not PROFINET")
	}
	if binary.BigEndian.Uint16(frame[14:16]) != dcpFrameIDIdentRes {
		t.Errorf("frameID not identify-response")
	}
	if frame[16] != dcpServiceIdentify || frame[17] != dcpServiceTypeRespOK {
		t.Errorf("service header wrong: %#x %#x", frame[16], frame[17])
	}
	if binary.BigEndian.Uint32(frame[18:22]) != 0xCAFEBABE {
		t.Errorf("xid not echoed")
	}
	dataLen := int(binary.BigEndian.Uint16(frame[24:26]))
	blocks := frame[26:]
	if dataLen != len(blocks) {
		t.Fatalf("DCPDataLength %d != actual block bytes %d", dataLen, len(blocks))
	}
	// The station name must appear in the NameOfStation block.
	if !bytes.Contains(blocks, []byte("plc-cell3")) {
		t.Errorf("station name not present in response blocks")
	}
	// Walk blocks and confirm every block length stays in bounds (well-formed TLVs).
	p := 0
	for p+4 <= len(blocks) {
		blen := int(binary.BigEndian.Uint16(blocks[p+2 : p+4]))
		p += 4 + blen
		if blen%2 == 1 {
			p++
		}
	}
	if p != len(blocks) {
		t.Errorf("blocks not exactly consumed (p=%d len=%d) — malformed TLV chain", p, len(blocks))
	}
}

func TestStationsForRequest(t *testing.T) {
	all := []pnStation{{name: "a"}, {name: "b"}}
	if got := stationsForRequest(all, ""); len(got) != 2 {
		t.Errorf("identify-all returned %d stations; want 2", len(got))
	}
	if got := stationsForRequest(all, "b"); len(got) != 1 || got[0].name != "b" {
		t.Errorf("name filter b returned %v; want [b]", got)
	}
	if got := stationsForRequest(all, "nope"); got != nil {
		t.Errorf("unknown name returned %v; want nil", got)
	}
}

func TestVendorIDFor(t *testing.T) {
	if vendorIDFor("Siemens AG") != 0x002A {
		t.Errorf("Siemens vendor ID wrong")
	}
	if vendorIDFor("Moxa Inc") != 0x011C {
		t.Errorf("Moxa vendor ID wrong")
	}
	if vendorIDFor("Acme") != 0x0100 {
		t.Errorf("default vendor ID wrong")
	}
}

// buildDCPSetRequest synthesizes a DCP Set request frame targeting one
// station MAC, setting the given option/suboption.
func buildDCPSetRequest(reqMAC, dstMAC [6]byte, xid uint32, option, sub byte, value []byte) []byte {
	// Set block: Option, Suboption, BlockLength(2), BlockQualifier(2), value.
	block := []byte{option, sub}
	bl := 2 + len(value) // BlockQualifier + value
	block = append(block, byte(bl>>8), byte(bl&0xff))
	block = append(block, 0x00, 0x01) // BlockQualifier: set permanent
	block = append(block, value...)
	if len(block)%2 == 1 {
		block = append(block, 0x00)
	}
	frame := make([]byte, 26)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], reqMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], ethTypePROFINET)
	binary.BigEndian.PutUint16(frame[14:16], dcpFrameIDGetSet)
	frame[16] = dcpServiceSet
	frame[17] = dcpServiceTypeRequest
	binary.BigEndian.PutUint32(frame[18:22], xid)
	binary.BigEndian.PutUint16(frame[24:26], uint16(len(block)))
	frame = append(frame, block...)
	return frame
}

func TestParseDCPSetNameOfStation(t *testing.T) {
	req := [6]byte{0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33}
	dst := [6]byte{0x00, 0x1b, 0x1b, 0x44, 0x55, 0x66}
	frame := buildDCPSetRequest(req, dst, 0xdeadbeef, dcpOptDeviceProps, dcpSubNameOfStation, []byte("plc-evil"))
	s, ok := parseDCPSet(frame)
	if !ok {
		t.Fatal("parseDCPSet failed on a valid Set frame")
	}
	if s.label != "NameOfStation" {
		t.Errorf("label = %q, want NameOfStation", s.label)
	}
	if s.factory {
		t.Error("NameOfStation set wrongly flagged as factory reset")
	}
	if s.reqMAC != req || s.dstMAC != dst || s.xid != 0xdeadbeef {
		t.Errorf("addressing/xid mismatch: %+v", s)
	}
	// A Set response should be built and addressed back to the requester.
	st := pnStation{name: "plc1", mac: dst}
	resp := buildDCPSetResponse(st, s.reqMAC, s.xid, s.option, s.sub)
	if !bytes.Equal(resp[0:6], req[:]) {
		t.Errorf("response dst = %x, want requester %x", resp[0:6], req)
	}
	if binary.BigEndian.Uint16(resp[14:16]) != dcpFrameIDGetSet || resp[16] != dcpServiceSet {
		t.Error("response is not a DCP Set response")
	}
}

func TestParseDCPSetFactoryReset(t *testing.T) {
	req := [6]byte{0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33}
	dst := [6]byte{0x00, 0x1b, 0x1b, 0x44, 0x55, 0x66}
	frame := buildDCPSetRequest(req, dst, 1, dcpOptControl, dcpSubCtrlFactory, nil)
	s, ok := parseDCPSet(frame)
	if !ok {
		t.Fatal("parseDCPSet failed on a Control/ResetToFactory frame")
	}
	if !s.factory {
		t.Errorf("factory reset not flagged; label=%q", s.label)
	}
}

// An Identify frame must not be misparsed as a Set.
func TestParseDCPSetRejectsIdentify(t *testing.T) {
	req := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	frame := buildDCPIdentifyRequest(req, 1, "")
	if _, ok := parseDCPSet(frame); ok {
		t.Error("parseDCPSet accepted an Identify frame")
	}
}

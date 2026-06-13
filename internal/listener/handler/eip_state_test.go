package handler

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func eipFrame(cmd uint16, session uint32, body []byte) []byte {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint16(hdr[0:2], cmd)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(body)))
	binary.LittleEndian.PutUint32(hdr[4:8], session)
	return append(hdr, body...)
}

// eipSendRRData wraps a CIP message-router request in a SendRRData (0x006F)
// encapsulation with the Common Packet Format.
func eipSendRRData(mr []byte) []byte {
	var data []byte
	data = binary.LittleEndian.AppendUint32(data, 0)      // interface handle
	data = binary.LittleEndian.AppendUint16(data, 0)      // timeout
	data = binary.LittleEndian.AppendUint16(data, 2)      // CPF item count
	data = binary.LittleEndian.AppendUint16(data, 0x0000) // null address item
	data = binary.LittleEndian.AppendUint16(data, 0)      // ...len 0
	data = binary.LittleEndian.AppendUint16(data, 0x00B2) // unconnected data item
	data = binary.LittleEndian.AppendUint16(data, uint16(len(mr)))
	data = append(data, mr...)
	return eipFrame(0x006F, 0xdeadbeef, data)
}

// cipSymPath builds an ANSI extended symbolic segment (0x91) for a tag name,
// padded to a 16-bit word boundary.
func cipSymPath(name string) []byte {
	p := append([]byte{0x91, byte(len(name))}, name...)
	if len(p)%2 != 0 {
		p = append(p, 0x00)
	}
	return p
}

func cipWriteTag(name string, typ uint16, value []byte) []byte {
	path := cipSymPath(name)
	mr := append([]byte{0x4D, byte(len(path) / 2)}, path...)
	mr = binary.LittleEndian.AppendUint16(mr, typ) // data type
	mr = binary.LittleEndian.AppendUint16(mr, 1)   // element count
	return append(mr, value...)
}

func cipReadTag(name string) []byte {
	path := cipSymPath(name)
	mr := append([]byte{0x4C, byte(len(path) / 2)}, path...)
	return binary.LittleEndian.AppendUint16(mr, 1) // element count
}

// A tag written via Write_Tag must read back its value on a later Read_Tag in
// the same session.
func TestEtherNetIPTagWriteThenRead(t *testing.T) {
	val := []byte{0x78, 0x56, 0x34, 0x12} // DINT 0x12345678 LE
	input := bytes.Join([][]byte{
		eipSendRRData(cipWriteTag("MyTag", 0x00C4, val)),
		eipSendRRData(cipReadTag("MyTag")),
		eipFrame(0x0066, 0xdeadbeef, nil), // UnRegisterSession -> handler returns
	}, nil)

	_, out := roundtrip(t, &ethernetip{}, string(input))
	want := append([]byte{0xC4, 0x00}, val...) // CIP DINT type + the written value
	if !bytes.Contains(out, want) {
		t.Errorf("Read_Tag did not return the written tag value\n want subsequence % x\n in            % x", want, out)
	}
}

// A Read_Tag of a tag never written returns a synthetic value (not the value
// from a different tag's write) — stable and non-empty.
func TestEtherNetIPUnwrittenTagSynthetic(t *testing.T) {
	input := bytes.Join([][]byte{
		eipSendRRData(cipReadTag("FreshTag")),
		eipFrame(0x0066, 0xdeadbeef, nil),
	}, nil)
	_, out := roundtrip(t, &ethernetip{}, string(input))
	// The read response carries a DINT type code 0xC4 followed by 4 value bytes.
	if !bytes.Contains(out, []byte{0xC4, 0x00}) {
		t.Errorf("unwritten Read_Tag returned no typed value: % x", out)
	}
}

package handler

import (
	"encoding/binary"
	"testing"
)

// smb2Negotiate builds an SMB2 NEGOTIATE request offering the given dialects and
// (optionally) a compression-capabilities negotiate context.
func smb2Negotiate(dialects []uint16, withCompression bool) []byte {
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0xFE, 'S', 'M', 'B'
	req := make([]byte, 36)
	binary.LittleEndian.PutUint16(req[0:2], 36)
	binary.LittleEndian.PutUint16(req[2:4], uint16(len(dialects)))
	body := append(hdr, req...)
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	if withCompression {
		// 8-byte align the context start.
		for len(body)%8 != 0 {
			body = append(body, 0)
		}
		ctxOff := len(body)
		ctx := make([]byte, 8)
		binary.LittleEndian.PutUint16(ctx[0:2], 0x0003) // SMB2_COMPRESSION_CAPABILITIES
		binary.LittleEndian.PutUint16(ctx[2:4], 0)      // data length
		body = append(body, ctx...)
		binary.LittleEndian.PutUint32(body[64+28:64+32], uint32(ctxOff))
		binary.LittleEndian.PutUint16(body[64+32:64+34], 1)
	}
	return body
}

func TestSMBGhostStructural(t *testing.T) {
	res := &Result{Meta: map[string]any{}}
	smbThreatMarkers(res, smb2Negotiate([]uint16{0x0202, 0x0210, 0x0300, 0x0311}, true))
	if !hasAnom(*res, "smb-compression-capabilities") || !hasAnom(*res, "cve:CVE-2020-0796") {
		t.Errorf("SMBGhost not flagged: %v", res.Meta["anomalies"])
	}
	// Without the compression context it must not fire.
	res2 := &Result{Meta: map[string]any{}}
	smbThreatMarkers(res2, smb2Negotiate([]uint16{0x0202, 0x0311}, false))
	if hasAnom(*res2, "smb-compression-capabilities") {
		t.Errorf("false positive without compression context: %v", res2.Meta["anomalies"])
	}
}

func TestSMBNegoexAndTrans(t *testing.T) {
	res := &Result{Meta: map[string]any{}}
	smbThreatMarkers(res, append([]byte{0xFE, 'S', 'M', 'B'}, []byte("....NEGOEXTS....")...))
	if !hasAnom(*res, "smb-negoex") || !hasAnom(*res, "cve:CVE-2022-37958") {
		t.Errorf("NEGOEX not flagged: %v", res.Meta["anomalies"])
	}

	// SMB1 Trans2 SESSION_SETUP (DoublePulsar).
	b := make([]byte, 64)
	b[0], b[1], b[2], b[3], b[4] = 0xFF, 'S', 'M', 'B', 0x32
	binary.LittleEndian.PutUint16(b[61:63], 0x000e)
	res3 := &Result{Meta: map[string]any{}}
	smbThreatMarkers(res3, b)
	if !hasAnom(*res3, "smb-doublepulsar") || !hasAnom(*res3, "smb-trans-exploit") {
		t.Errorf("DoublePulsar/Trans not flagged: %v", res3.Meta["anomalies"])
	}
}

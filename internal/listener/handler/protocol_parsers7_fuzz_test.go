package handler

// Seventh batch: handler-level fuzzing of the ICS / OT protocol decoys, seeded
// with valid frames via fuzzTCPHandler. These speak Siemens S7comm-plus, IEC
// MMS, Mitsubishi MELSEC, GE-SRTP, HART-IP, CoDeSys, PCWorx, Veeder-Root ATG,
// Niagara Fox, Omron FINS/TCP, SECS/GEM (HSMS) and Unitronics PCOM.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzMELSECHandler -fuzztime 60s

import "testing"

// tpktCOTPConnReq is a TPKT + COTP connection request — the opening frame for
// the S7 family (s7comm_plus, mms) which front their app layer with COTP.
var tpktCOTPConnReq = []byte{
	0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
	0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02,
}

func FuzzS7CommPlusHandler(f *testing.F) {
	fuzzTCPHandler(f, "s7comm_plus", tpktCOTPConnReq)
}

func FuzzMMSHandler(f *testing.F) {
	fuzzTCPHandler(f, "mms", tpktCOTPConnReq)
}

func FuzzMELSECHandler(f *testing.F) {
	// MELSEC MC 3E frame: subheader 0x0050 (request) + routing + a read command.
	fuzzTCPHandler(f, "melsec",
		[]byte{0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x0c, 0x00, 0x0a, 0x00,
			0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00})
}

func FuzzGESRTPHandler(f *testing.F) {
	// GE-SRTP service request (56-byte message; first byte marks a request).
	fuzzTCPHandler(f, "ge_srtp",
		append([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, make([]byte, 46)...))
}

func FuzzHARTIPHandler(f *testing.F) {
	// HART-IP header: version 1, request, session-initiate, status 0, seq, bytecount.
	fuzzTCPHandler(f, "hartip",
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08})
}

func FuzzCodesysHandler(f *testing.F) {
	// CoDeSys block-driver magic (0xbbbb) + a short header.
	fuzzTCPHandler(f, "codesys",
		[]byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzPCWorxHandler(f *testing.F) {
	fuzzTCPHandler(f, "pcworx",
		[]byte{0x01, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzATGHandler(f *testing.F) {
	// Veeder-Root ATG: Ctrl-A + an I20100 (in-tank inventory) command.
	fuzzTCPHandler(f, "atg",
		[]byte("\x01I20100"),
		[]byte("\x01I20200\r"))
}

func FuzzFoxHandler(f *testing.F) {
	// Niagara Fox hello (the client replies to our banner with its own hello).
	fuzzTCPHandler(f, "fox",
		[]byte("fox a 0 -1 fox hello\n{\nfox.version=s:1.0.1;\nid=i:1;\n};;\n"))
}

func FuzzFINSTCPHandler(f *testing.F) {
	// Omron FINS/TCP: "FINS" magic + length + frame.
	fuzzTCPHandler(f, "fins_tcp",
		[]byte{'F', 'I', 'N', 'S', 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func FuzzSECSGEMHandler(f *testing.F) {
	// HSMS: 4-byte length + 10-byte message header (SType 1 = Select.req).
	fuzzTCPHandler(f, "secs_gem",
		[]byte{0x00, 0x00, 0x00, 0x0a, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01})
}

func FuzzPCOMHandler(f *testing.F) {
	// Unitronics PCOM ASCII command framing.
	fuzzTCPHandler(f, "pcom",
		[]byte("/00ID\r"),
		[]byte{0x2f, 0x5f, 0x4f, 0x50, 0x4c, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// mms is an IEC 61850 MMS (Manufacturing Message Specification) responder
// on TCP 102 — the protocol substation IEDs (protection relays, bay
// controllers) speak over ISO-on-TCP, distinct from Siemens S7comm on the
// same port. The exchange is: COTP Connection Request → Connection Confirm,
// then an ISO session / presentation / ACSE AARQ carrying the MMS
// Initiate-Request. We complete the COTP handshake, capture the
// association/MMS request, reply with a believable AARE association accept,
// and flag the probe. Fingerprint-grade — no IED data model is served.
type mms struct{}

func (m *mms) Name() string { return "mms" }

func (m *mms) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// COTP Connection Request -> Connection Confirm (readTPKT returns the
	// COTP body and appends the raw frame to res.Payload).
	cr, ok := readTPKT(conn, &res)
	if !ok {
		return res, nil
	}
	if len(cr) < 7 || cr[1] != 0xE0 { // COTP CR type 0xE0
		res.Meta["cotp_type"] = fmtByte(safeAt(cr, 1))
		return res, nil
	}
	dstRef := binary.BigEndian.Uint16(cr[2:4])
	srcRef := binary.BigEndian.Uint16(cr[4:6])
	res.Meta["cotp_type"] = "CR"
	params := cr[7:]
	cc := []byte{byte(6 + len(params)), 0xD0}
	cc = binary.BigEndian.AppendUint16(cc, srcRef)
	cc = binary.BigEndian.AppendUint16(cc, dstRef)
	cc = append(cc, 0x00)
	cc = append(cc, params...)
	if err := writeTPKT(conn, cc); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "tpkt+cotp connection confirm"

	// Capture the association/MMS Initiate request (AARQ).
	aarq, ok := readTPKT(conn, &res)
	if !ok {
		flagAnomaly(&res, "ics-mms-probe")
		return res, nil
	}
	res.Meta["mms_request_len"] = len(aarq)
	flagAnomaly(&res, "ics-mms-probe")

	// ICCP / TASE.2 (IEC 60870-6) rides this same MMS/ISO-on-TCP stack but
	// between control centers rather than to a substation IED. The AARQ
	// carries the TASE.2 application-context / version objects, and the
	// session is full of TASE.2-named variables (Bilateral_Table, Transfer
	// Sets, VCC/ICC domains). Detecting it relabels the association and lets
	// us classify the inter-control-center operations downstream.
	if iccpAssociation(aarq) {
		res.Meta["mms_profile"] = "ICCP/TASE.2"
		flagAnomaly(&res, "ics-iccp-association")
		res.Meta["intent"] = "ICCP/TASE.2 association — inter-control-center (utility-to-utility) data exchange"
	}

	// Reply with a COTP DT carrying a canned AARE (association accept) + MMS
	// Initiate-Response. Structurally a valid ISO-on-TCP data PDU so the peer
	// records a live MMS server; the IED model itself is not emulated.
	if err := writeTPKT(conn, append([]byte{0x02, 0xF0, 0x80}, mmsInitiateResponse...)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "iec61850 mms initiate response"
	setIfEmpty(res.Meta, "intent", "IEC-61850 MMS association — substation IED access attempt")

	// After the association completes, the client issues MMS confirmed
	// requests. Read the first one and name the service — getNameList is data-
	// model enumeration, read/write touch the IED's logical nodes, a write to a
	// control object is the manipulation vector.
	for n := 0; n < 4; n++ {
		pdu, ok := readTPKT(conn, &res)
		if !ok {
			break
		}
		if name, svc, found := mmsDetectService(pdu); found {
			res.Meta["mms_service"] = name
			mmsClassify(svc, &res)
			classifyICCPObject(pdu, &res)
			break
		}
	}
	return res, nil
}

// iccpMarkers are the TASE.2 / ICCP object-name and identifier substrings
// that distinguish an inter-control-center association from a substation IED
// session. TASE.2 names its domains and variables from a fixed vocabulary
// (IEC 60870-6-503), so their ASCII presence in the BER-encoded PDU is a
// strong tell. Lower-cased compares are avoided — these are case-exact names.
var iccpMarkers = []string{
	"Bilateral_Table", "BILATERAL_TABLE", "Transfer_Set", "TransferSet",
	"DSTransferSet", "DSConditions", "TASE2", "TASE.2", "Supported_Features",
	"VCC", "Next_DSTransfer_Set", "Transfer_Report",
}

// iccpAssociation reports whether the association payload carries a TASE.2
// fingerprint — the TASE.2 version OID arc (1.0.10000) or a TASE.2 named
// object in the AARQ user-information.
func iccpAssociation(buf []byte) bool {
	// TASE.2 version object identifier arc: { iso(1) standard(0) iccp(10000) }
	// encoded in BER as 0x28 0xCE 0x10 (40*1+0=0x28, then 10000 as 0xCE 0x10).
	for i := 0; i+2 < len(buf); i++ {
		if buf[i] == 0x28 && buf[i+1] == 0xCE && buf[i+2] == 0x10 {
			return true
		}
	}
	return containsAnyBytes(buf, iccpMarkers)
}

// classifyICCPObject inspects a TASE.2 confirmed-request PDU for the operations
// that matter on an inter-control-center link: writing/operating a Device
// (TASE.2 Block 5 device control — actuating a remote breaker/setpoint across
// utilities), manipulating Transfer Sets (Block 2 — the reporting subscriptions
// that drive real-time exchange), and reading Bilateral Tables (the access
// agreement enumerating what the peer is allowed to see).
func classifyICCPObject(pdu []byte, res *Result) {
	if res.Meta["mms_profile"] == nil && !iccpAssociation(pdu) {
		return
	}
	switch {
	case containsAnyBytes(pdu, []string{"Transfer_Set", "TransferSet", "DSTransferSet", "DSConditions"}):
		flagAnomaly(res, "ics-iccp-transfer-set")
		res.Meta["intent"] = "ICCP Transfer Set operation — altering inter-control-center reporting subscriptions"
	case containsAnyBytes(pdu, []string{"Bilateral_Table", "BILATERAL_TABLE"}):
		flagAnomaly(res, "ics-iccp-bilateral-table")
		res.Meta["intent"] = "ICCP Bilateral Table access — enumerating the peer access agreement"
	}
	// A Write/Operate touching a Device/Command/Tag object on an ICCP link is
	// Block-5 device control — a cross-utility actuation.
	if svc, _ := res.Meta["mms_service"].(string); svc == "write" &&
		containsAnyBytes(pdu, []string{"Device", "Command", "_Tag", "SBO"}) {
		flagAnomaly(res, "ics-iccp-control")
		res.Meta["intent"] = "ICCP Device control (Block 5) — operating a remote control point across control centers"
	}
}

// containsAnyBytes reports whether any of subs appears as a byte substring of b.
func containsAnyBytes(b []byte, subs []string) bool {
	for _, s := range subs {
		if bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

// mmsDetectService locates an MMS confirmed-RequestPDU inside an ISO-on-TCP
// data PDU and returns the requested service. The PDU is BER-encoded and
// wrapped in session/presentation layers, so we scan for the confirmed-request
// tag (0xA0) followed by an invokeID INTEGER and read the service CHOICE tag.
func mmsDetectService(buf []byte) (string, byte, bool) {
	for i := 0; i+1 < len(buf); i++ {
		if buf[i] != 0xA0 { // confirmed-RequestPDU [0]
			continue
		}
		j := i + 2 // skip tag + (short-form) length
		if j+1 >= len(buf) || buf[j] != 0x02 {
			continue // expect invokeID INTEGER
		}
		k := j + 2 + int(buf[j+1])
		if k >= len(buf) {
			continue
		}
		if name := mmsServiceName(buf[k]); name != "" {
			return name, buf[k], true
		}
	}
	return "", 0, false
}

// mmsClassify flags the anomaly + intent for an MMS confirmed-service tag.
func mmsClassify(svc byte, res *Result) {
	switch svc {
	case 0xA1, 0xA2, 0xA6: // getNameList / identify / getVariableAccessAttributes
		flagAnomaly(res, "ics-field-device-probe")
		res.Meta["intent"] = "MMS " + mmsServiceName(svc) + " — enumerating the IEC-61850 data model"
	case 0xA4: // read
		flagAnomaly(res, "ics-process-data-access")
		res.Meta["intent"] = "MMS Read — reading IED logical-node values"
	case 0xA5: // write
		flagAnomaly(res, "ics-plc-write")
		res.Meta["intent"] = "MMS Write — writing an IED object (control / setpoint manipulation)"
	}
}

// mmsServiceName names the MMS confirmedServiceRequest CHOICE context tags a
// recon/attack tool emits.
func mmsServiceName(tag byte) string {
	switch tag {
	case 0xA1:
		return "getNameList"
	case 0xA2:
		return "identify"
	case 0xA4:
		return "read"
	case 0xA5:
		return "write"
	case 0xA6:
		return "getVariableAccessAttributes"
	}
	return ""
}

// mmsInitiateResponse is a canned ISO session ACCEPT + presentation CPA +
// ACSE AARE + MMS Initiate-Response advertising modest service support — the
// upper-layer payload that follows the COTP DT header. Representative bytes
// so the association completes; not a full IEC 61850 server.
var mmsInitiateResponse = []byte{
	// ISO 8327-1 session ACCEPT SPDU.
	0x0e, 0x02, 0xf0, 0x80,
	// ISO 8823 presentation CPA-PPDU (abbreviated).
	0x31, 0x80, 0x02, 0x01, 0x01,
	// ACSE AARE-apdu (association accept, result 0 = accepted).
	0x61, 0x1e, 0x30, 0x1c, 0x02, 0x01, 0x01, 0xa0, 0x03, 0x00, 0x00, 0x00,
	// MMS Initiate-ResponsePDU: negotiated PDU size, nesting, service support.
	0xa8, 0x12, 0x80, 0x03, 0x00, 0xfd, 0xe8, 0x81, 0x01, 0x0a, 0x82, 0x01,
	0x0a, 0x83, 0x01, 0x05, 0xa4, 0x03, 0x80, 0x01, 0x01,
}

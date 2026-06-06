package handler

import (
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
			break
		}
	}
	return res, nil
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

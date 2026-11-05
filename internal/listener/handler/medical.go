package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// This file holds healthcare / medical-device protocol decoys. Hospital
// networks expose two protocols almost universally unauthenticated on the
// wire — HL7 v2 over MLLP (clinical messaging between the EHR, lab, radiology
// and billing systems) and DICOM (medical imaging / PACS) — and an instance
// of either reachable from the internet is a protected-health-information
// goldmine and a documented attacker target (Shodan "DICOM"/"HL7" dorks,
// mass PACS exposure). Each handler answers just enough to look like a live
// clinical endpoint so a scanner/attacker keeps talking, captures the intent
// (patient-data queries, image retrieval, master-file tampering, injection),
// and flags the high-signal markers. Nothing is ever stored or acted on: the
// "patient" data is never real, every ACK/association grants nothing, and no
// request is executed.

// --- HL7 v2 over MLLP (Minimal Lower Layer Protocol, TCP 2575) ------------
//
// MLLP frames each HL7 message as <VT> message <FS><CR> (0x0B … 0x1C 0x0D).
// An HL7 v2 message is pipe-delimited and begins with an MSH segment whose
// MSH-1 is the field separator (normally '|') and MSH-2 the encoding
// characters ("^~\&"). We parse the MSH header, answer with a believable ACK
// (MSA|AA) so the peer keeps sending, and flag queries (PHI access), master-
// file updates (remote config tamper), order messages and injection attempts.

const (
	mllpVT = 0x0B // MLLP start-block
	mllpFS = 0x1C // MLLP end-block
	mllpCR = 0x0D // trailing carriage return
)

type hl7 struct{ id *identity.Identity }

func (h *hl7) Name() string { return "hl7" }

func (h *hl7) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 16384)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "hl7-probe")
	if len(got) == 0 {
		return res, nil
	}
	if len(got) >= len(buf) {
		flagAnomaly(&res, "hl7-oversized")
	}

	// Strip MLLP framing when present; a real HL7 sender always frames.
	raw := got
	if raw[0] == mllpVT {
		res.Meta["hl7_mllp_framed"] = true
		raw = raw[1:]
		if i := bytes.IndexByte(raw, mllpFS); i >= 0 {
			raw = raw[:i]
		}
	}
	text := string(raw)

	seg := firstSegment(text)
	if !strings.HasPrefix(seg, "MSH") || len(seg) < 4 {
		flagAnomaly(&res, "hl7-malformed")
		// Still answer (negative ACK) so a scanner confirms a live endpoint.
		h.writeACK(conn, &res, "|", "^~\\&", "", "AR", "")
		return res, nil
	}
	fsep := string(seg[3])
	fields := strings.Split(seg, fsep)
	get := func(i int) string {
		if i >= 0 && i < len(fields) {
			return fields[i]
		}
		return ""
	}
	enc := "^~\\&"
	if e := get(1); e != "" {
		enc = e
	}
	// MSH field map: fields[1]=encoding (MSH-2), [2]=MSH-3 sending app,
	// [3]=MSH-4 sending facility, [8]=MSH-9 message type, [9]=MSH-10 control
	// id, [11]=MSH-12 version id.
	msgType := get(8)
	ctrlID := get(9)
	res.Meta["hl7_sending_app"] = clipStr(get(2), 48)
	res.Meta["hl7_sending_facility"] = clipStr(get(3), 48)
	res.Meta["hl7_message_type"] = clipStr(msgType, 32)
	res.Meta["hl7_control_id"] = clipStr(ctrlID, 48)
	res.Meta["hl7_version"] = clipStr(get(11), 16)

	// Classify by the first component of MSH-9 (the message-type root).
	root := msgType
	if i := strings.IndexByte(root, '^'); i >= 0 {
		root = root[:i]
	}
	switch strings.ToUpper(root) {
	case "QBP", "QRY", "VQQ", "QSB", "RQQ": // patient-data query → PHI access / bulk pull
		flagAnomaly(&res, "hl7-patient-query")
	case "MFN": // master-file notification → remote catalog/config tamper
		flagAnomaly(&res, "hl7-master-file-update")
	case "ORM", "OMG", "OML", "OMP": // order messages → fraudulent-order risk
		flagAnomaly(&res, "hl7-order-message")
	}
	if hl7LooksInjected(text) {
		flagAnomaly(&res, "hl7-injection")
	}

	h.writeACK(conn, &res, fsep, enc, msgType, "AA", ctrlID)
	return res, nil
}

// hl7Apps / hl7Facs are plausible EHR/HIS product + facility names; the sensor
// picks deployment-stable entries so a scanner fingerprinting a fleet sees
// distinct clinical endpoints rather than one honeypot.
var hl7Apps = []string{"EPIC", "CERNER", "MEDITECH", "ALLSCRIPTS", "ORMLAB", "RADNET", "SUNQUEST"}
var hl7Facs = []string{"MAIN", "WESTWING", "RADIOLOGY", "LABCORP", "ER", "ONCOLOGY"}

func (h *hl7) pick(label string, pool []string, idx int) string {
	if h.id == nil {
		return pool[idx%len(pool)]
	}
	return pool[int(h.id.Uint32("hl7/"+label))%len(pool)]
}

// writeACK sends an MLLP-framed HL7 ACK. code is AA (accept), AR (reject) or
// AE (error); origCtrl echoes the inbound MSH-10 into MSA-2.
func (h *hl7) writeACK(conn net.Conn, res *Result, fsep, enc, msgType, code, origCtrl string) {
	app := h.pick("app", hl7Apps, 0)
	fac := h.pick("fac", hl7Facs, 0)
	ts := time.Now().UTC().Format("20060102150405")
	ctrl := "ACK" + ts
	ackType := "ACK"
	if i := strings.IndexByte(msgType, '^'); i >= 0 {
		ackType = "ACK" + msgType[i:] // ADT^A01 → ACK^A01
	}
	// MSH-3..MSH-12 after the "MSH"+sep+encoding prefix.
	rest := []string{app, fac, "", "", ts, "", ackType, ctrl, "P", "2.5"}
	msh := "MSH" + fsep + enc + fsep + strings.Join(rest, fsep)
	msa := "MSA" + fsep + code + fsep + origCtrl
	body := msh + "\r" + msa + "\r"

	frame := make([]byte, 0, len(body)+3)
	frame = append(frame, mllpVT)
	frame = append(frame, body...)
	frame = append(frame, mllpFS, mllpCR)
	_, _ = conn.Write(frame)
	res.BannerSent = "hl7 " + code + " ack"
}

// firstSegment returns the first HL7 segment (terminated by CR, or LF from a
// lax sender), trimming leading line breaks.
func firstSegment(s string) string {
	s = strings.TrimLeft(s, "\r\n")
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// hl7LooksInjected reports whether an HL7 message carries path-traversal,
// script, SQL or shell-injection markers — attempts to pop the downstream
// interface engine (many HL7 parsers template or shell out unsafely). The '|'
// field separator is intentionally not treated as a shell pipe.
func hl7LooksInjected(s string) bool {
	low := strings.ToLower(s)
	for _, m := range []string{
		"../", "..\\", "<script", "<?php", " or 1=1", "union select", "drop table",
		"$(", "/etc/passwd", "cmd.exe", "powershell", "; rm ", "&& ", "xp_cmdshell",
	} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// --- DICOM Upper Layer Protocol (PACS / medical imaging, TCP 104 / 11112) --
//
// A DICOM peer opens with an A-ASSOCIATE-RQ (PDU type 0x01) carrying the
// called/calling Application Entity (AE) titles and the proposed presentation
// contexts. We parse the request, accept it with an A-ASSOCIATE-AC echoing the
// offered presentation context + transfer syntax (so a real client / scanner
// proceeds), then read one follow-up PDU to capture the DIMSE operation —
// C-FIND (query), C-GET / C-MOVE (image retrieval / exfil), C-STORE
// (unsolicited image push) or C-ECHO (verification ping). AE-title scanning
// (empty or tool-default calling AE) is itself flagged as PACS discovery.

type dicom struct{}

func (h *dicom) Name() string { return "dicom" }

// DICOM PDU types.
const (
	dcmAssocRQ   = 0x01
	dcmAssocAC   = 0x02
	dcmAssocRJ   = 0x03
	dcmPData     = 0x04
	dcmReleaseRQ = 0x05
	dcmReleaseRP = 0x06
)

func (h *dicom) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 8192))
	res.Payload = got
	flagAnomaly(&res, "dicom-probe")
	if len(got) < 6 {
		return res, nil
	}
	pduType := got[0]
	res.Meta["dicom_pdu_type"] = int(pduType)
	res.Meta["dicom_pdu_len"] = int(binary.BigEndian.Uint32(got[2:6]))
	if pduType != dcmAssocRQ {
		flagAnomaly(&res, "dicom-nonstandard-pdu")
		return res, nil
	}
	if len(got) < 74 {
		flagAnomaly(&res, "dicom-malformed")
		return res, nil
	}
	flagAnomaly(&res, "dicom-associate")
	calledAE := strings.TrimSpace(string(got[10:26]))
	callingAE := strings.TrimSpace(string(got[26:42]))
	res.Meta["dicom_called_ae"] = clipStr(calledAE, 16)
	res.Meta["dicom_calling_ae"] = clipStr(callingAE, 16)
	if dicomScannerAE(callingAE) {
		flagAnomaly(&res, "dicom-ae-scan")
	}

	ac, ok := dicomBuildAC(got)
	if !ok {
		// Reject (A-ASSOCIATE-RJ): result permanent, source UL service-user,
		// reason "calling-AE-title-not-recognized" (0x03).
		_, _ = conn.Write([]byte{dcmAssocRJ, 0x00, 0, 0, 0, 4, 0x00, 0x01, 0x01, 0x03})
		res.BannerSent = "dicom a-associate-rj"
		return res, nil
	}
	_, _ = conn.Write(ac)
	res.BannerSent = "dicom a-associate-ac"

	// Capture the first DIMSE operation on the accepted association.
	more := readCapped(conn, cfg, make([]byte, 8192))
	if len(more) < 6 {
		return res, nil
	}
	res.Payload = append(res.Payload, more...)
	switch more[0] {
	case dcmPData:
		if cmd := dicomCommandField(more); cmd != 0 {
			res.Meta["dicom_dimse_command"] = int(cmd)
			switch cmd {
			case 0x0020:
				flagAnomaly(&res, "dicom-cfind") // patient/study query
			case 0x0010:
				flagAnomaly(&res, "dicom-cget") // retrieve images on this assoc
			case 0x0021:
				flagAnomaly(&res, "dicom-cmove") // retrieve to a destination AE
			case 0x0001:
				flagAnomaly(&res, "dicom-cstore") // unsolicited image push
			case 0x0030:
				flagAnomaly(&res, "dicom-cecho") // verification ping
			}
		}
	case dcmReleaseRQ:
		_, _ = conn.Write([]byte{dcmReleaseRP, 0x00, 0, 0, 0, 4, 0, 0, 0, 0})
	}
	return res, nil
}

// dicomScannerAE reports whether the calling AE title is empty or a known
// DICOM-tool / scanner default — a classic PACS-discovery fingerprint.
func dicomScannerAE(ae string) bool {
	a := strings.ToUpper(strings.TrimSpace(ae))
	if a == "" {
		return true
	}
	for _, s := range []string{
		"FINDSCU", "ECHOSCU", "STORESCU", "MOVESCU", "GETSCU", "DCMTK",
		"ANY-SCP", "ANYSCP", "PYNETDICOM", "TEST", "NMAP", "SCANNER", "SCAN",
	} {
		if strings.Contains(a, s) {
			return true
		}
	}
	return false
}

// dicomBuildAC builds an A-ASSOCIATE-AC accepting the association described by
// the A-ASSOCIATE-RQ: it echoes the Application Context and each offered
// presentation context (accepting the first transfer syntax of each) and the
// User Information item. Returns ok=false when no presentation context can be
// parsed (the caller then rejects).
func dicomBuildAC(rq []byte) (out []byte, ok bool) {
	if len(rq) < 74 {
		return nil, false
	}
	var appCtx, pcItems, userInfo []byte
	foundPC := false

	p := rq[74:]
	for len(p) >= 4 {
		it := p[0]
		ilen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+ilen > len(p) {
			break
		}
		body := p[4 : 4+ilen]
		switch it {
		case 0x10: // Application Context — echo verbatim.
			appCtx = dicomItem(0x10, body)
		case 0x20: // Presentation Context RQ → AC (0x21).
			if len(body) < 4 {
				break
			}
			pcid := body[0]
			ts := dicomFirstTransferSyntax(body[4:])
			if ts == nil {
				// No transfer syntax offered → reject this context (result 3,
				// "abstract-syntax-not-supported").
				pcItems = append(pcItems, dicomItem(0x21, []byte{pcid, 0x00, 0x03, 0x00})...)
			} else {
				acBody := []byte{pcid, 0x00, 0x00, 0x00} // result 0 = acceptance
				acBody = append(acBody, dicomItem(0x40, ts)...)
				pcItems = append(pcItems, dicomItem(0x21, acBody)...)
			}
			foundPC = true
		case 0x50: // User Information — echo (max-length, impl-class-uid, …).
			userInfo = dicomItem(0x50, body)
		}
		p = p[4+ilen:]
	}
	if !foundPC {
		return nil, false
	}
	if appCtx == nil {
		appCtx = dicomItem(0x10, []byte("1.2.840.10008.3.1.1.1")) // DICOM app-context name
	}
	if userInfo == nil {
		userInfo = dicomItem(0x50, dicomItem(0x51, []byte{0x00, 0x00, 0x40, 0x00})) // max PDU 16384
	}

	var variable []byte
	variable = append(variable, appCtx...)
	variable = append(variable, pcItems...)
	variable = append(variable, userInfo...)

	// Fixed AC region: protocol-version(2) + reserved(2) + called AE(16) +
	// calling AE(16) + reserved(32), echoing the RQ's AE-title fields.
	fixed := make([]byte, 68)
	fixed[1] = 0x01 // protocol version 1
	copy(fixed[4:20], rq[10:26])
	copy(fixed[20:36], rq[26:42])

	payload := append(fixed, variable...)
	out = []byte{dcmAssocAC, 0x00}
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, payload...)
	return out, true
}

// dicomItem builds a DICOM variable item: type(1) reserved(1) length(2 BE) body.
func dicomItem(t byte, body []byte) []byte {
	out := []byte{t, 0x00}
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// dicomFirstTransferSyntax returns the body of the first Transfer Syntax
// sub-item (0x40) in a presentation-context sub-item list, or nil.
func dicomFirstTransferSyntax(sub []byte) []byte {
	for len(sub) >= 4 {
		it := sub[0]
		ln := int(binary.BigEndian.Uint16(sub[2:4]))
		if 4+ln > len(sub) {
			return nil
		}
		if it == 0x40 {
			return append([]byte(nil), sub[4:4+ln]...)
		}
		sub = sub[4+ln:]
	}
	return nil
}

// dicomCommandField best-effort-scans a P-DATA-TF PDU for the DICOM Command
// Field element (0000,0100), implicit VR little-endian (tag 00 00 00 01, a
// 4-byte length of 2, then the 2-byte command value), and returns the command
// (e.g. 0x0020 = C-FIND-RQ). Returns 0 when not found.
func dicomCommandField(pdata []byte) uint16 {
	if len(pdata) < 12 {
		return 0
	}
	frag := pdata[12:] // skip PDU header(6) + PDV length(4) + PDV header(2)
	for i := 0; i+10 <= len(frag); i++ {
		if frag[i] == 0x00 && frag[i+1] == 0x00 && frag[i+2] == 0x00 && frag[i+3] == 0x01 {
			if binary.LittleEndian.Uint32(frag[i+4:i+8]) == 2 {
				return binary.LittleEndian.Uint16(frag[i+8 : i+10])
			}
		}
	}
	return 0
}

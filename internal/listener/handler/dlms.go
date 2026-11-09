package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// dlmsH emulates a DLMS/COSEM smart meter (IEC 62056) reached over the TCP
// "wrapper" transport (default port 4059). A client opens an Application
// Association with an AARQ APDU (tag 0x60); we answer a believable AARE and then
// decode the xDLMS service APDUs that follow on the association — GET / SET /
// ACTION requests — extracting the targeted COSEM object (class-id + OBIS code +
// attribute/method), so the SOC sees exactly which meter register was read or
// written (e.g. a remote-disconnect ACTION on the disconnect-control object)
// instead of just "an association happened". Complements the M-Bus handler for
// utility-metering coverage.
type dlmsH struct{}

func (dlmsH) Name() string { return "dlms" }

// dlmsMaxFollowups bounds how many post-association APDUs are read and decoded on
// one connection, so a client that keeps sending can't pin the handler.
const dlmsMaxFollowups = 4

func (dlmsH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "dlms-cosem"}}
	br := bufio.NewReader(conn)

	var cmds []string
	for i := 0; i <= dlmsMaxFollowups; i++ {
		if i > 0 {
			withTimeout(conn, cfg.ReadTimeout) // refresh the deadline each round
		}
		hdr, apdu, ok := readDLMSFrame(br, &res, i == 0)
		if !ok {
			break
		}
		res.Payload = append(res.Payload, hdr...)
		res.Payload = append(res.Payload, apdu...)
		if cmd := dlmsDecodeAPDU(apdu, &res); cmd != "" {
			cmds = append(cmds, cmd)
		}
		dlmsRespond(conn, hdr, apdu)
	}

	if len(cmds) > 0 {
		res.Meta["dlms_commands"] = cmds
		// Primary command for the detail page's "OT command" line: the first data
		// request (GET/SET/ACTION) if any, else the association/release request.
		primary := cmds[0]
		for _, c := range cmds {
			if !strings.HasPrefix(c, "AARQ") && !strings.HasPrefix(c, "RLRQ") {
				primary = c
				break
			}
		}
		res.Meta["dlms_apdu"] = primary
		if strings.Contains(strings.Join(cmds, " "), "AARQ") {
			res.BannerSent = "dlms AARE"
		} else {
			res.BannerSent = "dlms-cosem response"
		}
	}
	return res, nil
}

// readDLMSFrame reads one wrapper-framed APDU: version(2)=0x0001, src wPort(2),
// dst wPort(2), length(2), then <length> APDU bytes. recordFirst records the
// parse context (wrapper flag, ports) and parse errors into res only for the
// first frame, so a normal end-of-session read on a later frame doesn't look
// like an error.
func readDLMSFrame(br *bufio.Reader, res *Result, recordFirst bool) (hdr, apdu []byte, ok bool) {
	hdr = make([]byte, 8)
	if _, err := readFull(br, hdr); err != nil {
		if recordFirst && res != nil {
			res.Meta["read_err"] = err.Error()
		}
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(hdr[0:2]) != 0x0001 {
		if recordFirst && res != nil {
			res.Meta["non_dlms_wrapper"] = hex.EncodeToString(hdr[0:2])
		}
		return nil, nil, false
	}
	if recordFirst && res != nil {
		res.Meta["dlms_wrapper"] = true
		res.Meta["dlms_src"] = binary.BigEndian.Uint16(hdr[2:4])
		res.Meta["dlms_dst"] = binary.BigEndian.Uint16(hdr[4:6])
	}
	n := int(binary.BigEndian.Uint16(hdr[6:8]))
	if n > 4096 {
		if recordFirst && res != nil {
			res.Meta["bad_length"] = n
		}
		return nil, nil, false
	}
	apdu = make([]byte, n)
	if n > 0 {
		if _, err := readFull(br, apdu); err != nil {
			if recordFirst && res != nil {
				res.Meta["read_err"] = err.Error()
			}
			return nil, nil, false
		}
	}
	return hdr, apdu, true
}

// dlmsDecodeAPDU classifies one xDLMS APDU, enriches res, and returns a short
// command label (e.g. "GET-Request 1-0:1.8.0.255 attribute 2" or "AARQ"), or ""
// for an empty/unrecognized APDU (whose tag is recorded for the SIEM).
func dlmsDecodeAPDU(apdu []byte, res *Result) string {
	if len(apdu) == 0 {
		return ""
	}
	switch apdu[0] {
	case 0x60: // AARQ — association request
		flagAnomaly(res, "ics-dlms-association")
		flagAnomaly(res, "ics-field-device-probe")
		setIfEmpty(res.Meta, "intent", "DLMS/COSEM association request (AARQ) — smart-meter field-device access")
		return "AARQ"
	case 0x62: // RLRQ — release request
		setIfEmpty(res.Meta, "intent", "DLMS/COSEM release request (RLRQ) — closing the association")
		return "RLRQ"
	case 0xC0: // GET-Request
		return dlmsDataReq(apdu, res, "GET-Request", "ics-process-data-access",
			"reading meter register", "attribute")
	case 0xC1: // SET-Request
		return dlmsDataReq(apdu, res, "SET-Request", "ics-plc-program-access",
			"writing meter object (configuration / control)", "attribute")
	case 0xC3: // ACTION-Request
		return dlmsDataReq(apdu, res, "ACTION-Request", "ics-plc-mode-change",
			"invoking a method (e.g. remote disconnect / credit top-up)", "method")
	default:
		if name := dlmsAPDUName(apdu[0]); name != "" {
			return name
		}
		res.Meta["dlms_apdu_tag"] = hexByte(apdu[0])
		return ""
	}
}

// dlmsDataReq parses a GET/SET/ACTION-Request-Normal COSEM descriptor —
// tag(1) type(1) invoke(1) class-id(2) instance-id(6 OBIS) attribute/method-id(1)
// — recording the targeted object and returning a labeled command.
func dlmsDataReq(apdu []byte, res *Result, cmd, marker, verb, idKey string) string {
	flagAnomaly(res, marker)
	flagAnomaly(res, "ics-dlms-command")
	if len(apdu) >= 12 && apdu[1] == 0x01 { // normal form
		classID := binary.BigEndian.Uint16(apdu[3:5])
		o := apdu[5:11]
		id := int(int8(apdu[11]))
		obis := fmt.Sprintf("%d-%d:%d.%d.%d.%d", o[0], o[1], o[2], o[3], o[4], o[5])
		res.Meta["dlms_class_id"] = classID
		res.Meta["dlms_obis"] = obis
		res.Meta["dlms_"+idKey] = id
		res.Meta["intent"] = "DLMS/COSEM " + cmd + " — " + verb + " " + obis
		return fmt.Sprintf("%s %s %s %d", cmd, obis, idKey, id)
	}
	setIfEmpty(res.Meta, "intent", "DLMS/COSEM "+cmd+" — "+verb)
	return cmd
}

// dlmsAPDUName maps an xDLMS APDU tag to its name (responses and ciphered
// variants that dlmsDecodeAPDU doesn't parse in depth).
func dlmsAPDUName(tag byte) string {
	switch tag {
	case 0x61:
		return "AARE (association response)"
	case 0x63:
		return "RLRE (release response)"
	case 0xC2:
		return "EventNotification-Request"
	case 0xC4:
		return "GET-Response"
	case 0xC5:
		return "SET-Response"
	case 0xC7:
		return "ACTION-Response"
	case 0xC8:
		return "GLO-GET-Request (ciphered)"
	case 0xC9:
		return "GLO-SET-Request (ciphered)"
	case 0xCB:
		return "GLO-ACTION-Request (ciphered)"
	case 0xD8:
		return "ExceptionResponse"
	case 0xDB:
		return "general-glo-ciphering"
	default:
		return ""
	}
}

// dlmsRespond sends a believable wrapped response so a scanner proceeds to its
// next request (letting us capture the real GET/SET/ACTION), swapping the
// request's src/dst wPorts. Best-effort.
func dlmsRespond(conn net.Conn, reqHdr, apdu []byte) {
	if len(apdu) == 0 || len(reqHdr) < 8 {
		return
	}
	invoke := byte(0x01)
	if len(apdu) >= 3 {
		invoke = apdu[2]
	}
	var payload []byte
	switch apdu[0] {
	case 0x60: // AARQ -> AARE accepting the association
		payload = []byte{0x61, 0x29, 0xa1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
			0xa2, 0x03, 0x02, 0x01, 0x00, 0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x00}
	case 0xC0: // GET-Request -> GET-Response-Normal, success, double-long-unsigned value
		payload = []byte{0xC4, 0x01, invoke, 0x00, 0x06, 0x00, 0x00, 0x27, 0x10}
	case 0xC1: // SET-Request -> SET-Response-Normal, success
		payload = []byte{0xC5, 0x01, invoke, 0x00}
	case 0xC3: // ACTION-Request -> ACTION-Response-Normal, success, no return data
		payload = []byte{0xC7, 0x01, invoke, 0x00, 0x00}
	case 0x62: // RLRQ -> RLRE
		payload = []byte{0x63, 0x03, 0x80, 0x01, 0x00}
	default:
		return
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint16(out[0:2], 0x0001)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(reqHdr[4:6])) // src = request dst
	binary.BigEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(reqHdr[2:4])) // dst = request src
	binary.BigEndian.PutUint16(out[6:8], uint16(len(payload)))
	_, _ = conn.Write(append(out, payload...))
}

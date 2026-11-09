package handler

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// Process-historian binary protocols. GE Proficy Historian (14000), Canary Labs
// Historian / Sender (9990), and AspenTech InfoPlus.21 (10014) are the three
// big proprietary process historians whose data ports were previously captured
// raw. Like the OSIsoft/AVEVA PI responder (osisoft_pi, 5450) their wire
// protocols are closed and undocumented, so this is deliberately a
// fingerprint-grade surface, NOT a protocol implementation: it captures the
// client's opening message, classifies the framing it uses, scavenges any
// cleartext strings the handshake leaks (app/user/version names that these SDKs
// routinely send unencrypted), greets with a minimal product identification a
// scanner can grep, and surfaces the connection as historian / process-data
// access (a classic IT→OT pivot and data-exfil target). No tag/point database
// is served and nothing is ever read from or written to a real historian — we
// do not fabricate the proprietary record formats.

// historian is a parameterized fingerprint responder for a proprietary process
// historian's binary data port. proto is the handler name, label/version are the
// product identification ASCII a scanner records, and marker is the short
// protocol-id prefix placed ahead of the length-prefixed identification body.
type historian struct {
	proto   string
	label   string
	version string
	marker  []byte
	id      *identity.Identity
}

func (h *historian) Name() string { return h.proto }

func (h *historian) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"historian_protocol": h.proto}}

	got := readCapped(conn, cfg, make([]byte, 4096))
	if len(got) > 0 {
		res.Payload = got
		res.Meta["request_len"] = len(got)
		classifyHistorianFraming(&res, got)
		classifyHistorianOp(&res, got, h.label)
		if toks := amsPrintableStrings(got); len(toks) > 0 {
			res.Meta["ascii_tokens"] = toks
		}
	} else {
		// A bare connect with no client data is still a scanner reaching a
		// process historian — record it and greet anyway.
		res.Meta["read_err"] = "no data"
	}

	flagAnomaly(&res, h.proto+"-probe")
	flagAnomaly(&res, "ics-historian-access")
	flagAnomaly(&res, "ics-field-device-probe")
	setIfEmpty(res.Meta, "intent", h.label+" access — process-historian connection (IT→OT pivot / data exfil)")

	// Minimal product identification: marker bytes + a 2-byte big-endian length
	// + "<label> <version>\x00<host>\x00". Generic length-prefixed framing is the
	// shape these historians share; the value is the ASCII a scanner fingerprints.
	host := historianHostName(h.id)
	res.Meta["historian_server"] = host
	res.Meta["historian_version"] = h.version
	body := []byte(h.label + " " + h.version + "\x00" + host + "\x00")
	resp := append([]byte(nil), h.marker...)
	resp = append(resp, byte(len(body)>>8), byte(len(body)))
	resp = append(resp, body...)
	// Refresh the deadline: a bare connect spends the whole read budget waiting,
	// which would otherwise leave the write deadline already expired.
	withTimeout(conn, cfg.ReadTimeout)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = h.proto + " identification"
	return res, nil
}

// historianHostName derives a believable server hostname from the deployment
// identity, defaulting to a generic historian name.
func historianHostName(id *identity.Identity) string {
	if id != nil && id.HostName() != "" {
		return id.HostName()
	}
	return "HISTORIAN01"
}

// classifyHistorianFraming records the opening bytes and, when the leading
// 4 bytes are a plausible big- or little-endian length prefix for the datagram,
// tags the framing — the structural fingerprint that distinguishes these
// length-prefixed binary protocols from a raw byte stream.
func classifyHistorianFraming(res *Result, b []byte) {
	n := len(b)
	res.Meta["opening_bytes_hex"] = hex.EncodeToString(b[:min(16, n)])
	if n < 4 {
		return
	}
	be := int(binary.BigEndian.Uint32(b[:4]))
	le := int(binary.LittleEndian.Uint32(b[:4]))
	switch {
	case be == n || be == n-4:
		res.Meta["framing"] = "length-prefixed-be"
		res.Meta["frame_len"] = be
	case le == n || le == n-4:
		res.Meta["framing"] = "length-prefixed-le"
		res.Meta["frame_len"] = le
	default:
		res.Meta["framing"] = "binary-stream"
	}
}

// historianOps maps, most-specific-first, a historian client operation to the
// cleartext verb tokens these proprietary SDKs (PI API/SDK, GE ihSDK, AspenTech
// SQLplus/ADSA, Canary) routinely leak in their opening handshakes. This is an
// honest classification of observed cleartext — NOT a decode of the closed
// record formats and NOT fabricated: a token has to actually be present on the
// wire for the operation to be named.
var historianOps = []struct {
	op   string
	toks []string
}{
	{"write data", []string{"putsnapshot", "putarc", "putarchive", "updatevalue", "insertvalue", "writevalue", "pointupdate", "updatepoint"}},
	{"read archive data", []string{"getarchive", "getarcvalues", "recorded", "interpolated", "piplot", "plotvalues", "summaries", "getpointdata", "readraw", "trenddata", "archivevalues"}},
	{"tag/point lookup", []string{"findpoint", "getpoint", "pointlist", "pisearch", "findtag", "gettag", "taglist", "listpoints", "searchtag", "browsetags", "getpoints"}},
	{"subscribe / sign-up", []string{"signup", "subscribe", "piupdate", "datapipe"}},
	{"authentication", []string{"pitrust", "pimapping", "kerberos", "sspi", "ntlm", "login", "username", "password", "credential"}},
	{"protocol negotiation", []string{"version", "hello", "negotiate", "protocol", "handshake"}},
}

// historianOperation classifies the operation a historian client's opening
// message represents from its leaked cleartext tokens, returning the operation
// name and the token that matched (both "" when there is no data). A connection
// that leaks no verb is reported as a plain connection/handshake.
func historianOperation(got []byte) (op, token string) {
	if len(got) == 0 {
		return "", ""
	}
	low := strings.ToLower(asciiOnly(got))
	for _, r := range historianOps {
		for _, t := range r.toks {
			if strings.Contains(low, t) {
				return r.op, t
			}
		}
	}
	return "connection / handshake", ""
}

// classifyHistorianOp records the decoded operation (historian_operation) and,
// for the control-relevant ones, raises the matching marker and a precise
// intent. product is the human product name used in the intent line. Shared by
// the generic historian responder and the OSIsoft PI responder.
func classifyHistorianOp(res *Result, got []byte, product string) {
	op, tok := historianOperation(got)
	if op == "" {
		return
	}
	res.Meta["historian_operation"] = op
	if tok != "" {
		res.Meta["historian_op_token"] = tok
	}
	switch op {
	case "write data":
		flagAnomaly(res, "ics-historian-write")
		res.Meta["intent"] = product + " — writing historian data (process-record tampering)"
	case "read archive data":
		flagAnomaly(res, "ics-process-data-access")
		res.Meta["intent"] = product + " — reading archived process data (historian exfiltration)"
	case "tag/point lookup":
		res.Meta["intent"] = product + " — enumerating historian tags/points"
	case "authentication":
		flagAnomaly(res, "ics-historian-auth")
		res.Meta["intent"] = product + " — authenticating to the historian"
	}
}

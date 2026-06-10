package handler

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type smb struct {
	id *identity.Identity
}

func (s *smb) Name() string { return "smb" }

// SMB1 over direct TCP (port 445). The first message any client sends is a
// Negotiate Protocol Request (command 0x72). The wire format is:
//
//	NBSS header (4 bytes)
//	  type(1) = 0x00 (session message), reserved(1) = 0x00, length(2, big-endian)
//	SMB1 header (32 bytes)
//	  magic(4) = "\xFFSMB", command(1) = 0x72, status(4),
//	  flags(1), flags2(2), pid_high(2), security_features(8),
//	  reserved(2), tid(2), pid_low(2), uid(2), mid(2)
//	Negotiate payload
//	  word_count(1) = 0
//	  byte_count(2) = total payload bytes
//	  dialects = repeated: 0x02 + null-terminated dialect string
//
// For SMB1 we capture the offered dialects + signing flag and reply selecting
// the "NT LM 0.12" dialect with extended security disabled, a fixed 8-byte
// challenge, and a "WORKGROUP" name — enough for Shodan-class fingerprints and
// SMB scanners to mark us as an SMBv1 server. The SMB1 path stops at Negotiate.
//
// SMB2 (magic "\xFESMB") is negotiated for real and driven through the NTLMSSP
// SESSION_SETUP exchange to capture the client's NetNTLMv2 (see smb_ntlm.go) —
// this is how modern clients and credential-capture tooling authenticate. We
// always fail the logon; nothing is ever granted access.
func (s *smb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	// NetBIOS Session Service header.
	nbss := make([]byte, 4)
	if _, err := io.ReadFull(conn, nbss); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	// Length is 17-bit on paper but the high bit lives in the second byte;
	// for SMB it's effectively bytes[1:4] big-endian over 24 bits with the
	// top byte usually zero.
	length := int(uint32(nbss[1])<<16 | uint32(nbss[2])<<8 | uint32(nbss[3]))
	if length < 32 || length > 65535 {
		res.Meta = map[string]any{"bad_nbss_length": length}
		// SMBLoris reserves a huge per-connection buffer by declaring an
		// oversized NBSS length (classically 0x1ffff) and then never completing
		// the body — a memory-exhaustion DoS across many connections.
		if length > 65535 {
			flagAnomaly(&res, "smb-smbloris")
			res.Meta["intent"] = "SMBLoris oversized NBSS length — connection/memory-exhaustion DoS"
		}
		return res, nil
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(nbss, body...)

	// CVE exploit-attempt recognition (EternalBlue's "\PIPE\" tree path
	// appears as ASCII in the request). Detection only.
	for _, rec := range cve.MatchPayload("smb", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}
	// Structural exploit recognition that isn't a simple substring: SMBGhost /
	// SMBleed compression, SPNEGO NEGOEX, the MS17-010 Transaction family, and
	// the DoublePulsar implant ping.
	smbThreatMarkers(&res, body)

	if len(body) < 4 {
		return res, nil
	}

	// Distinguish SMB1 ("\xFFSMB") from SMB2 ("\xFESMB").
	magic := body[0:4]
	if magic[0] == 0xFE && string(magic[1:4]) == "SMB" {
		// SMB2 Negotiate. Drive the SMB2 + NTLMSSP SESSION_SETUP handshake to
		// capture the attacker's NetNTLMv2 (we always fail the logon — capture
		// only, never grant access). See smb_ntlm.go.
		res.Meta = map[string]any{"variant": "SMB2"}
		res.BannerSent = "smb2 negotiate response (ntlmssp)"
		handleSMB2(conn, body, cfg.ReadTimeout, s.id, &res)
		return res, nil
	}
	if magic[0] != 0xFF || string(magic[1:4]) != "SMB" {
		res.Meta = map[string]any{"non_smb": true}
		return res, nil
	}

	command := body[4]
	res.Meta = map[string]any{
		"variant": "SMB1",
		"command": smb1CommandName(command),
	}
	if command != 0x72 {
		// Anything other than Negotiate we just log.
		return res, nil
	}

	// Negotiate payload: WordCount(1)=0, ByteCount(2), then dialects.
	if len(body) < 32+3 {
		return res, nil
	}
	byteCount := binary.LittleEndian.Uint16(body[33:35])
	if 35+int(byteCount) > len(body) {
		return res, nil
	}
	dialectBytes := body[35 : 35+int(byteCount)]
	var dialects []string
	cursor := 0
	for cursor < len(dialectBytes) {
		if dialectBytes[cursor] != 0x02 {
			break
		}
		cursor++
		end := cursor
		for end < len(dialectBytes) && dialectBytes[end] != 0x00 {
			end++
		}
		dialects = append(dialects, string(dialectBytes[cursor:end]))
		cursor = end + 1
	}
	res.Meta["dialects"] = dialects
	// A client negotiating SMB1 at all is speaking a protocol disabled on modern
	// Windows — a legacy/downgrade posture (and the EternalBlue/MS17-010
	// precondition).
	flagAnomaly(&res, "smb-v1-negotiation")
	setIfEmpty(res.Meta, "intent", "SMBv1 negotiation — legacy/downgrade dialect (MS17-010 precondition)")

	// Pick the index of "NT LM 0.12" if offered, else the last dialect.
	chosen := -1
	for i, d := range dialects {
		if d == "NT LM 0.12" {
			chosen = i
			break
		}
	}
	if chosen < 0 && len(dialects) > 0 {
		chosen = len(dialects) - 1
	}
	if chosen < 0 {
		res.Meta["no_dialects"] = true
		return res, nil
	}

	out := smb1NegotiateResponse(body, uint16(chosen), s.id)
	if _, err := conn.Write(out); err != nil {
		res.Meta["write_err"] = err.Error()
	} else {
		res.BannerSent = "smb1 negotiate response (dialect " + dialects[chosen] + ")"
	}
	_ = strings.ToLower // keep import while sketching
	return res, nil
}

// smb1NegotiateResponse builds a NBSS+SMB1+payload response selecting the
// given dialect index. The challenge is a fixed 8 bytes; servername is
// "WORKGROUP\0" UTF-16LE.
func smb1NegotiateResponse(req []byte, dialectIndex uint16, id *identity.Identity) []byte {
	// Session key is per-deployment stable; the NTLM challenge is a fresh
	// per-connection nonce (what a real server sends) — a static challenge
	// is itself a fingerprint and enables precomputed/replay attacks.
	var sessionKey uint32 = 0xdeadbeef
	if id != nil {
		sessionKey = id.Uint32("smb-session-key")
	}
	challenge := make([]byte, 8)
	if _, err := crand.Read(challenge); err != nil && id != nil {
		challenge = id.Bytes("smb-challenge", 8)
	}

	// Word data fields (NT LM 0.12 response, no extended security).
	wordData := make([]byte, 0, 34)
	wordData = binary.LittleEndian.AppendUint16(wordData, dialectIndex)
	wordData = append(wordData, 0x03)                                 // SecurityMode: user-level + plaintext
	wordData = binary.LittleEndian.AppendUint16(wordData, 50)         // MaxMpxCount
	wordData = binary.LittleEndian.AppendUint16(wordData, 1)          // MaxNumberVcs
	wordData = binary.LittleEndian.AppendUint32(wordData, 16644)      // MaxBufferSize
	wordData = binary.LittleEndian.AppendUint32(wordData, 65536)      // MaxRawSize
	wordData = binary.LittleEndian.AppendUint32(wordData, sessionKey) // SessionKey (per-deployment)
	wordData = binary.LittleEndian.AppendUint32(wordData, 0x8001f3fd) // Capabilities (UNICODE+...)
	// SystemTime: a real server stamps the current time here as a 64-bit
	// FILETIME; leaving it zero (the old behavior) is an obvious tell.
	now := filetimeNow()
	wordData = binary.LittleEndian.AppendUint32(wordData, uint32(now&0xffffffff)) // SystemTime low
	wordData = binary.LittleEndian.AppendUint32(wordData, uint32(now>>32))        // SystemTime high
	wordData = binary.LittleEndian.AppendUint16(wordData, 0)                      // ServerTimeZone (UTC)
	wordData = append(wordData, 0x08)                                             // EncryptionKeyLength = 8

	// Byte data: 8-byte challenge (per-deployment) + UTF-16LE "WORKGROUP\0"
	bytesField := append([]byte{}, challenge...)
	wg := []byte("W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00\x00\x00")
	bytesField = append(bytesField, wg...)

	smb1Header := make([]byte, 32)
	smb1Header[0] = 0xFF
	smb1Header[1] = 'S'
	smb1Header[2] = 'M'
	smb1Header[3] = 'B'
	smb1Header[4] = 0x72 // command = Negotiate
	// status = 0 (success); flags / flags2 mirror common defaults
	smb1Header[9] = 0x88                                     // flags = response
	binary.LittleEndian.PutUint16(smb1Header[10:12], 0xc003) // flags2 = unicode + nt status + etc
	// pid, tid, uid, mid: copy from the request so the client correlates.
	copy(smb1Header[12:14], req[12:14])
	copy(smb1Header[24:28], req[24:28])
	copy(smb1Header[28:32], req[28:32])

	wordCount := byte(17) // 17 words = 34 bytes for NT LM 0.12 response
	payload := make([]byte, 0, 1+len(wordData)+2+len(bytesField))
	payload = append(payload, wordCount)
	payload = append(payload, wordData...)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(bytesField)))
	payload = append(payload, bytesField...)

	frame := append(smb1Header, payload...)
	nbss := []byte{0x00, 0, 0, 0}
	binary.BigEndian.PutUint32(nbss, uint32(len(frame))) // top byte stays zero
	return append(nbss, frame...)
}

func smb1CommandName(c byte) string {
	switch c {
	case 0x72:
		return "SMB_COM_NEGOTIATE"
	case 0x73:
		return "SMB_COM_SESSION_SETUP_ANDX"
	case 0x75:
		return "SMB_COM_TREE_CONNECT_ANDX"
	case 0x71:
		return "SMB_COM_LOGOFF_ANDX"
	}
	return ""
}

// smbThreatMarkers flags SMB exploits that are structural, not simple
// substrings: SMBGhost/SMBleed (SMBv3.1.1 compression), the SPNEGO NEGOEX
// pre-auth overflow, the MS17-010 Transaction family, and the DoublePulsar
// implant ping. Detection only; bounds-checked against malformed input.
func smbThreatMarkers(res *Result, body []byte) {
	// SMBGhost / SMBleed: SMB2 NEGOTIATE offering dialect 0x0311 together with a
	// compression-capabilities negotiate context (type 0x0003).
	if len(body) >= 4 && body[0] == 0xFE && string(body[1:4]) == "SMB" {
		if smb2OffersDialect(body, 0x0311) && smb2HasNegContext(body, 0x0003) {
			flagAnomaly(res, "smb-compression-capabilities")
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2020-0796")
			flagAnomaly(res, "cve:CVE-2020-0796")
			flagAnomaly(res, "cve:CVE-2020-1206")
			res.Meta["intent"] = "SMBv3.1.1 compression negotiation — SMBGhost/SMBleed probe (CVE-2020-0796/-1206)"
		}
	}
	// Compressed-transform header (\xfcSMB) = an actual SMBGhost exploit packet.
	if bytes.Contains(body, []byte{0xfc, 'S', 'M', 'B'}) {
		flagAnomaly(res, "smb-compression-transform")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2020-0796")
		flagAnomaly(res, "cve:CVE-2020-0796")
		res.Meta["intent"] = "SMBv3 compressed-transform packet — SMBGhost exploit (CVE-2020-0796)"
	}
	// SPNEGO NEGOEX token — the CVE-2022-37958 pre-auth heap-overflow surface.
	if bytes.Contains(body, []byte("NEGOEXTS")) {
		flagAnomaly(res, "smb-negoex")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2022-37958")
		flagAnomaly(res, "cve:CVE-2022-37958")
		setIfEmpty(res.Meta, "intent", "SMB SPNEGO NEGOEX token — pre-auth overflow probe (CVE-2022-37958)")
	}
	// SMB1 Transaction (0x25) / Transaction2 (0x32): the MS17-010 exploit family
	// and the DoublePulsar implant ride these.
	if len(body) >= 5 && body[0] == 0xFF && string(body[1:4]) == "SMB" {
		switch body[4] {
		case 0x25: // SMB_COM_TRANSACTION
			flagAnomaly(res, "smb-trans-exploit")
			setIfEmpty(res.Meta, "intent", "SMBv1 Transaction — MS17-010 exploit family / named-pipe RCE")
		case 0x32: // SMB_COM_TRANSACTION2
			flagAnomaly(res, "smb-trans-exploit")
			// Trans2 Setup[0] (the Trans2 subcommand) lives just past the
			// 28-byte fixed parameter block: 32-byte SMB header + WordCount(1).
			if len(body) >= 63 && binary.LittleEndian.Uint16(body[61:63]) == 0x000e {
				flagAnomaly(res, "smb-doublepulsar")
				res.Meta["intent"] = "SMBv1 Trans2 SESSION_SETUP — DoublePulsar implant ping"
			}
		}
	}
}

// smb2OffersDialect reports whether an SMB2 NEGOTIATE request offers the given
// dialect revision. Layout: 64-byte SMB2 header, then NEGOTIATE request
// (StructureSize@0=36, DialectCount@2, ... Dialects[]@36, 2 bytes LE each).
func smb2OffersDialect(body []byte, dialect uint16) bool {
	const hdr = 64
	if len(body) < hdr+38 {
		return false
	}
	count := int(binary.LittleEndian.Uint16(body[hdr+2 : hdr+4]))
	if count <= 0 || count > 64 {
		return false
	}
	off := hdr + 36
	for i := 0; i < count && off+2 <= len(body); i++ {
		if binary.LittleEndian.Uint16(body[off:off+2]) == dialect {
			return true
		}
		off += 2
	}
	return false
}

// smb2HasNegContext reports whether an SMB2 NEGOTIATE request carries a
// negotiate context of the given type. NegotiateContextOffset is at header+28,
// NegotiateContextCount at header+34 in the request body.
func smb2HasNegContext(body []byte, ctxType uint16) bool {
	const hdr = 64
	if len(body) < hdr+38 {
		return false
	}
	off := int(binary.LittleEndian.Uint32(body[hdr+28 : hdr+32]))
	count := int(binary.LittleEndian.Uint16(body[hdr+32 : hdr+34]))
	if off <= 0 || off >= len(body) || count <= 0 || count > 64 {
		return false
	}
	for i := 0; i < count && off+8 <= len(body); i++ {
		t := binary.LittleEndian.Uint16(body[off : off+2])
		dlen := int(binary.LittleEndian.Uint16(body[off+2 : off+4]))
		if t == ctxType {
			return true
		}
		// Contexts are 8-byte aligned: header(8) + data, padded.
		adv := 8 + dlen
		if rem := adv % 8; rem != 0 {
			adv += 8 - rem
		}
		off += adv
	}
	return false
}

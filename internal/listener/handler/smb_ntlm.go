package handler

import (
	"crypto/md5"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

// SMB2 + NTLMSSP authentication capture. The base smb handler answers SMB1
// and, previously, rejected SMB2 outright — which meant modern clients and
// credential-capture tooling (impacket, CrackMapExec, coerced Windows auth)
// never reached the authentication exchange. This file negotiates SMB2 for
// real and drives the NTLMSSP SESSION_SETUP handshake to completion so we
// capture the attacker's **NetNTLM** response (username, domain, and the
// offline-crackable hash — NetNTLMv2 / hashcat 5600, or NetNTLMv1 / 5500 for a
// client pinned to LmCompatibilityLevel <= 2) — then always fails the logon (we
// never grant access; capture only).
//
// Flow: client SMB2 NEGOTIATE -> our NEGOTIATE response offering NTLM via a
// SPNEGO blob -> client SESSION_SETUP with NTLMSSP NEGOTIATE (type 1) -> our
// SESSION_SETUP (STATUS_MORE_PROCESSING_REQUIRED) carrying an NTLMSSP
// CHALLENGE (type 2) with a random server challenge -> client SESSION_SETUP
// with NTLMSSP AUTHENTICATE (type 3) -> we extract the NetNTLM hash and reply
// STATUS_LOGON_FAILURE.

const (
	smb2HeaderSize         = 64
	smb2CmdNegotiate       = 0x0000
	smb2CmdSessionSetup    = 0x0001
	smb2FlagsServerToRedir = 0x00000001
	ntStatusMoreProcessing = 0xC0000016
	ntStatusLogonFailure   = 0xC000006D
	smb2MaxMessages        = 8
)

// handleSMB2 services a direct-SMB2 client starting from its first message
// (the NEGOTIATE request already read into firstMsg). It records the captured
// NetNTLMv2 credential into res.Meta. The connection is read in a bounded loop.
func handleSMB2(conn net.Conn, firstMsg []byte, readTimeout time.Duration, id *identity.Identity, res *Result) {
	// The first message is the SMB2 NEGOTIATE request.
	if len(firstMsg) < smb2HeaderSize {
		return
	}
	negMsgID := smb2MessageID(firstMsg)
	serverGUID := smb2ServerGUID(id)
	if _, err := conn.Write(buildNBSS(smb2NegotiateResponse(negMsgID, serverGUID))); err != nil {
		res.Meta["smb2_write_err"] = err.Error()
		return
	}

	var serverChallenge []byte
	sessionID := smb2SessionID(id)
	for i := 0; i < smb2MaxMessages; i++ {
		if readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		}
		msg, ok := readNBSS(conn, 1<<16)
		if !ok || len(msg) < smb2HeaderSize+8 {
			return
		}
		if string(msg[0:4]) != "\xfeSMB" {
			return
		}
		cmd := binary.LittleEndian.Uint16(msg[12:14])
		msgID := smb2MessageID(msg)
		if cmd != smb2CmdSessionSetup {
			return // we only service the authentication exchange
		}
		secBuf, ok := smb2SessionSetupSecBuffer(msg)
		if !ok {
			return
		}
		ntlm := findNTLMSSP(secBuf)
		if ntlm == nil || len(ntlm) < 12 {
			return
		}
		switch binary.LittleEndian.Uint32(ntlm[8:12]) { // NTLMSSP MessageType
		case 1: // NEGOTIATE -> send CHALLENGE
			serverChallenge = randomChallenge(id)
			chal := ntlmsspChallenge(serverChallenge)
			resp := smb2SessionSetupResponse(msgID, sessionID, ntStatusMoreProcessing, spnegoChallenge(chal))
			if _, err := conn.Write(buildNBSS(resp)); err != nil {
				return
			}
		case 3: // AUTHENTICATE -> capture and fail
			captureNetNTLM("smb", ntlm, serverChallenge, res)
			resp := smb2SessionSetupResponse(msgID, sessionID, ntStatusLogonFailure, nil)
			_, _ = conn.Write(buildNBSS(resp))
			return
		default:
			return
		}
	}
}

// --- SMB2 framing ----------------------------------------------------------

func smb2MessageID(msg []byte) uint64 {
	if len(msg) < 32 {
		return 0
	}
	return binary.LittleEndian.Uint64(msg[24:32])
}

// readNBSS reads one NetBIOS-framed message (4-byte header + payload).
func readNBSS(conn net.Conn, max int) ([]byte, bool) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, false
	}
	n := int(uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
	if n <= 0 || n > max {
		return nil, false
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, false
	}
	return body, true
}

// buildNBSS prepends the 4-byte NetBIOS session header to an SMB message.
func buildNBSS(msg []byte) []byte {
	out := make([]byte, 4+len(msg))
	out[0] = 0
	out[1] = byte(len(msg) >> 16)
	out[2] = byte(len(msg) >> 8)
	out[3] = byte(len(msg))
	copy(out[4:], msg)
	return out
}

// smb2Header builds a 64-byte SMB2 response header.
func smb2Header(command uint16, status uint32, msgID, sessionID uint64) []byte {
	h := make([]byte, smb2HeaderSize)
	copy(h[0:4], "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:6], smb2HeaderSize) // StructureSize
	binary.LittleEndian.PutUint32(h[8:12], status)
	binary.LittleEndian.PutUint16(h[12:14], command)
	binary.LittleEndian.PutUint16(h[14:16], 1) // CreditResponse
	binary.LittleEndian.PutUint32(h[16:20], smb2FlagsServerToRedir)
	binary.LittleEndian.PutUint64(h[24:32], msgID)
	binary.LittleEndian.PutUint64(h[40:48], sessionID)
	return h
}

// smb2NegotiateResponse builds an SMB 2.0.2 NEGOTIATE response whose security
// buffer is a SPNEGO negTokenInit offering NTLMSSP.
func smb2NegotiateResponse(msgID uint64, serverGUID []byte) []byte {
	hdr := smb2Header(smb2CmdNegotiate, 0, msgID, 0)
	sec := spnegoNegTokenInit()
	const fixed = 64 // negotiate response fixed body
	body := make([]byte, fixed)
	binary.LittleEndian.PutUint16(body[0:2], 65)     // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 1)      // SecurityMode = signing enabled
	binary.LittleEndian.PutUint16(body[4:6], 0x0202) // DialectRevision = SMB 2.0.2
	copy(body[8:24], serverGUID)
	binary.LittleEndian.PutUint32(body[24:28], 0x00000007) // Capabilities (DFS|LEASING|LARGE_MTU)
	binary.LittleEndian.PutUint32(body[28:32], 0x00100000) // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:36], 0x00100000) // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 0x00100000) // MaxWriteSize
	binary.LittleEndian.PutUint64(body[40:48], filetimeNow())
	secOff := smb2HeaderSize + fixed
	binary.LittleEndian.PutUint16(body[56:58], uint16(secOff))
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(sec)))
	return append(append(hdr, body...), sec...)
}

// smb2SessionSetupResponse builds a SESSION_SETUP response carrying secBuf.
func smb2SessionSetupResponse(msgID, sessionID uint64, status uint32, secBuf []byte) []byte {
	hdr := smb2Header(smb2CmdSessionSetup, status, msgID, sessionID)
	const fixed = 8
	body := make([]byte, fixed)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0) // SessionFlags
	secOff := smb2HeaderSize + fixed
	binary.LittleEndian.PutUint16(body[4:6], uint16(secOff))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(secBuf)))
	return append(append(hdr, body...), secBuf...)
}

// smb2SessionSetupSecBuffer returns the security buffer of a SESSION_SETUP
// request message (the SPNEGO/NTLMSSP token).
func smb2SessionSetupSecBuffer(msg []byte) ([]byte, bool) {
	if len(msg) < smb2HeaderSize+24 {
		return nil, false
	}
	b := msg[smb2HeaderSize:]
	secOff := int(binary.LittleEndian.Uint16(b[12:14]))
	secLen := int(binary.LittleEndian.Uint16(b[14:16]))
	if secOff < smb2HeaderSize || secOff+secLen > len(msg) || secLen <= 0 {
		return nil, false
	}
	return msg[secOff : secOff+secLen], true
}

// --- NTLMSSP ---------------------------------------------------------------
//
// (findNTLMSSP is shared with the RDP handler in rdp.go — it scans for the
// NTLMSSP signature inside a CredSSP/SPNEGO blob.)

var ntlmsspSig = []byte("NTLMSSP\x00")

// ntlmsspChallenge builds an NTLMSSP CHALLENGE (type 2) message with the given
// 8-byte server challenge and a target-info block (AV_PAIRs) — required for the
// client to compute a NetNTLMv2 response.
func ntlmsspChallenge(serverChallenge []byte) []byte {
	targetName := utf16le("WORKGROUP")
	targetInfo := ntlmTargetInfo()

	const fixed = 56 // up to end of TargetInfoFields (no version)
	out := make([]byte, fixed)
	copy(out[0:8], ntlmsspSig)
	binary.LittleEndian.PutUint32(out[8:12], 2) // MessageType = CHALLENGE
	// NegotiateFlags: UNICODE | REQUEST_TARGET | NTLM | TARGET_INFO |
	// TARGET_TYPE_DOMAIN | EXTENDED_SESSIONSECURITY | ALWAYS_SIGN.
	flags := uint32(0x00000001 | 0x00000004 | 0x00000200 | 0x00800000 |
		0x00010000 | 0x00080000 | 0x00008000)
	tnOff := fixed
	binary.LittleEndian.PutUint16(out[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(out[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(out[16:20], uint32(tnOff))
	binary.LittleEndian.PutUint32(out[20:24], flags)
	copy(out[24:32], serverChallenge)
	// out[32:40] Reserved = 0
	tiOff := tnOff + len(targetName)
	binary.LittleEndian.PutUint16(out[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(out[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(out[44:48], uint32(tiOff))
	// out[48:56] Version = 0

	out = append(out, targetName...)
	out = append(out, targetInfo...)
	return out
}

// ntlmTargetInfo builds the AV_PAIR target-info block (NetBIOS + DNS names),
// terminated by an MsvAvEOL pair.
func ntlmTargetInfo() []byte {
	av := func(id uint16, val []byte) []byte {
		b := make([]byte, 4+len(val))
		binary.LittleEndian.PutUint16(b[0:2], id)
		binary.LittleEndian.PutUint16(b[2:4], uint16(len(val)))
		copy(b[4:], val)
		return b
	}
	var out []byte
	out = append(out, av(2, utf16le("WORKGROUP"))...)                 // NetBIOS domain
	out = append(out, av(1, utf16le("FILESRV01"))...)                 // NetBIOS computer
	out = append(out, av(4, utf16le("workgroup.local"))...)           // DNS domain
	out = append(out, av(3, utf16le("filesrv01.workgroup.local"))...) // DNS computer
	out = append(out, av(0, nil)...)                                  // EOL
	return out
}

// ntlmField returns (offset, length) of an NTLMSSP field descriptor at off.
func ntlmField(msg []byte, off int) (int, int, bool) {
	if off+8 > len(msg) {
		return 0, 0, false
	}
	l := int(binary.LittleEndian.Uint16(msg[off : off+2]))
	o := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
	if o < 0 || l < 0 || o+l > len(msg) {
		return 0, 0, false
	}
	return o, l, true
}

// captureNetNTLM parses an NTLMSSP AUTHENTICATE (type 3) message and records the
// captured credential into res.Meta. It distinguishes the two NetNTLM dialects
// by the NtChallengeResponse length:
//
//   - NetNTLMv2 — a variable-length response (NTProofStr(16) + AV-pair blob,
//     always > 24 bytes): emitted as a hashcat mode-5600 line in ntlmv2_hash.
//   - NetNTLMv1 — a fixed 24-byte DES response: emitted as a hashcat mode-5500
//     line in ntlmv1_hash. This includes the NTLM2 "session response" / ESS
//     variant (negotiated when we advertise EXTENDED_SESSIONSECURITY), where the
//     LM field carries an 8-byte client challenge padded with 16 zero bytes; for
//     that case the effective challenge is MD5(serverChallenge||clientChallenge)
//     truncated to 8 bytes, and ntlm_ess is set.
//
// source names the protocol the capture came over (e.g. "smb", "rdp") and
// prefixes the emitted anomaly marker. The credential is never validated.
func captureNetNTLM(source string, msg, serverChallenge []byte, res *Result) {
	if len(msg) < 64 || len(serverChallenge) != 8 {
		return
	}
	// Field descriptors: LmChallengeResponse@12, NtChallengeResponse@20,
	// DomainName@28, UserName@36, Workstation@44.
	lmOff, lmLen, _ := ntlmField(msg, 12)
	ntOff, ntLen, ok := ntlmField(msg, 20)
	dOff, dLen, _ := ntlmField(msg, 28)
	uOff, uLen, _ := ntlmField(msg, 36)
	wOff, wLen, _ := ntlmField(msg, 44)
	if !ok {
		return
	}
	domain := fromUTF16le(msg[dOff : dOff+dLen])
	user := fromUTF16le(msg[uOff : uOff+uLen])
	workstation := fromUTF16le(msg[wOff : wOff+wLen])
	ntResp := msg[ntOff : ntOff+ntLen]
	lmResp := msg[lmOff : lmOff+lmLen]

	if user != "" {
		res.Meta["ntlm_user"] = user
	}
	if domain != "" {
		res.Meta["ntlm_domain"] = domain
	}
	if workstation != "" {
		res.Meta["ntlm_workstation"] = workstation
	}
	res.Meta["ntlm_response_hex"] = hex.EncodeToString(ntResp)

	u := user
	if u == "" {
		u = "(null)"
	}
	switch {
	case len(ntResp) == 24:
		// NetNTLMv1 (or the ESS / NTLM2 session-response variant).
		res.Meta["auth_type"] = "ntlmv1"
		flagAnomaly(res, source+"-ntlmv1-capture")
		chal := serverChallenge
		// ESS: LM field = 8-byte client challenge + 16 zero bytes. The NT
		// response was then computed against MD5(serverChal||clientChal)[:8].
		if len(lmResp) == 24 && isZeroBytes(lmResp[8:24]) && !isZeroBytes(lmResp[:8]) {
			res.Meta["ntlm_ess"] = true
			sum := md5.Sum(append(append([]byte{}, serverChallenge...), lmResp[:8]...))
			chal = sum[:8]
		}
		// hashcat mode 5500: user::domain:LMresponse:NTresponse:challenge
		res.Meta["ntlmv1_hash"] = u + "::" + domain + ":" +
			hex.EncodeToString(lmResp) + ":" + hex.EncodeToString(ntResp) + ":" +
			hex.EncodeToString(chal)
	case len(ntResp) > 24:
		// NetNTLMv2: NTProofStr(16) + blob.
		res.Meta["auth_type"] = "ntlmv2"
		flagAnomaly(res, source+"-ntlmv2-capture")
		ntProof := ntResp[:16]
		blob := ntResp[16:]
		// hashcat mode 5600: user::domain:serverchallenge:ntproofstr:blob
		res.Meta["ntlmv2_hash"] = u + "::" + domain + ":" +
			hex.EncodeToString(serverChallenge) + ":" +
			hex.EncodeToString(ntProof) + ":" + hex.EncodeToString(blob)
	}
}

// isZeroBytes reports whether every byte of b is zero.
func isZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// --- SPNEGO (minimal DER) --------------------------------------------------

// OID bytes (full 0x06 TLV).
var (
	oidSPNEGO  = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLMSSP = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

// der wraps content in a DER tag/length/value.
func der(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derEncLen(len(content))...)
	return append(out, content...)
}

func derEncLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// spnegoNegTokenInit builds the GSSAPI InitialContextToken (SPNEGO
// negTokenInit) offering the NTLMSSP mechanism — the server's "I support NTLM"
// blob in the SMB2 NEGOTIATE response.
func spnegoNegTokenInit() []byte {
	mechTypes := der(0x30, oidNTLMSSP) // MechTypeList: SEQUENCE OF OID
	a0 := der(0xa0, mechTypes)         // [0] mechTypes
	negInit := der(0x30, a0)           // negTokenInit ::= SEQUENCE
	tagged := der(0xa0, negInit)       // [0] NegTokenInit
	inner := append(append([]byte{}, oidSPNEGO...), tagged...)
	return der(0x60, inner) // [APPLICATION 0] InitialContextToken
}

// spnegoChallenge wraps an NTLMSSP CHALLENGE in a SPNEGO negTokenResp with
// negState = accept-incomplete (1) and supportedMech = NTLMSSP.
func spnegoChallenge(ntlm []byte) []byte {
	negState := der(0xa0, []byte{0x0a, 0x01, 0x01}) // [0] ENUMERATED 1
	supported := der(0xa1, oidNTLMSSP)              // [1] supportedMech
	respToken := der(0xa2, der(0x04, ntlm))         // [2] responseToken OCTET STRING
	seq := der(0x30, append(append(negState, supported...), respToken...))
	return der(0xa1, seq) // [1] NegTokenResp
}

// --- helpers ---------------------------------------------------------------
// (utf16le / fromUTF16le are shared with the mssql handler.)

// randomChallenge returns a fresh 8-byte server challenge (falling back to the
// deployment identity if the RNG is unavailable).
func randomChallenge(id *identity.Identity) []byte {
	c := make([]byte, 8)
	if _, err := crand.Read(c); err != nil && id != nil {
		return id.Bytes("smb2-challenge", 8)
	}
	return c
}

func smb2ServerGUID(id *identity.Identity) []byte {
	if id != nil {
		return id.Bytes("smb2-server-guid", 16)
	}
	g := make([]byte, 16)
	_, _ = crand.Read(g)
	return g
}

func smb2SessionID(id *identity.Identity) uint64 {
	if id != nil {
		return uint64(id.Uint32("smb2-session-id"))<<32 | 0x1234
	}
	return 0x1100000000004321
}

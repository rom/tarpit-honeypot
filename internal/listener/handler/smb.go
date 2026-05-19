package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type smb struct{}

func (s *smb) Name() string { return "smb" }

// SMB1 over direct TCP (port 445). The first message any client sends is a
// Negotiate Protocol Request (command 0x72). The wire format is:
//
//   NBSS header (4 bytes)
//     type(1) = 0x00 (session message), reserved(1) = 0x00, length(2, big-endian)
//   SMB1 header (32 bytes)
//     magic(4) = "\xFFSMB", command(1) = 0x72, status(4),
//     flags(1), flags2(2), pid_high(2), security_features(8),
//     reserved(2), tid(2), pid_low(2), uid(2), mid(2)
//   Negotiate payload
//     word_count(1) = 0
//     byte_count(2) = total payload bytes
//     dialects = repeated: 0x02 + null-terminated dialect string
//
// We capture the offered dialects + signing flag and reply selecting the
// "NT LM 0.12" dialect with extended security disabled, a fixed 8-byte
// challenge, and a "WORKGROUP" name — enough for Shodan-class fingerprints
// and SMB scanners to mark us as an SMBv1 server. We deliberately stop
// at Negotiate; Session Setup needs real NTLMSSP which is huge.
//
// SMB2 is detected (magic "\xFESMB" right after the NBSS header) and we
// respond with SMB_COM_NEGOTIATE indicating no dialects are supported
// (dialect_index=0xFFFF), which makes most SMB2 clients close cleanly.
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
		return res, nil
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(nbss, body...)

	if len(body) < 4 {
		return res, nil
	}

	// Distinguish SMB1 ("\xFFSMB") from SMB2 ("\xFESMB").
	magic := body[0:4]
	if magic[0] == 0xFE && string(magic[1:4]) == "SMB" {
		// SMB2 Negotiate. Reply with a polite "no dialects supported".
		out := smb1NegotiateRejection(body)
		_, _ = conn.Write(out)
		res.BannerSent = "smb2 negotiate rejection (no common dialect)"
		res.Meta = map[string]any{"variant": "SMB2"}
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

	out := smb1NegotiateResponse(body, uint16(chosen))
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
func smb1NegotiateResponse(req []byte, dialectIndex uint16) []byte {
	// Word data fields (NT LM 0.12 response, no extended security).
	wordData := make([]byte, 0, 34)
	wordData = binary.LittleEndian.AppendUint16(wordData, dialectIndex)
	wordData = append(wordData, 0x03)                                          // SecurityMode: user-level + plaintext
	wordData = binary.LittleEndian.AppendUint16(wordData, 50)                  // MaxMpxCount
	wordData = binary.LittleEndian.AppendUint16(wordData, 1)                   // MaxNumberVcs
	wordData = binary.LittleEndian.AppendUint32(wordData, 16644)               // MaxBufferSize
	wordData = binary.LittleEndian.AppendUint32(wordData, 65536)               // MaxRawSize
	wordData = binary.LittleEndian.AppendUint32(wordData, 0xdeadbeef)          // SessionKey
	wordData = binary.LittleEndian.AppendUint32(wordData, 0x8001f3fd)          // Capabilities (UNICODE+...)
	wordData = binary.LittleEndian.AppendUint32(wordData, 0)                   // SystemTime low
	wordData = binary.LittleEndian.AppendUint32(wordData, 0)                   // SystemTime high
	wordData = binary.LittleEndian.AppendUint16(wordData, 0)                   // ServerTimeZone
	wordData = append(wordData, 0x08)                                          // EncryptionKeyLength = 8

	// Byte data: 8-byte challenge + UTF-16LE "WORKGROUP\0"
	bytesField := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	wg := []byte("W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00\x00\x00")
	bytesField = append(bytesField, wg...)

	smb1Header := make([]byte, 32)
	smb1Header[0] = 0xFF
	smb1Header[1] = 'S'
	smb1Header[2] = 'M'
	smb1Header[3] = 'B'
	smb1Header[4] = 0x72                                       // command = Negotiate
	// status = 0 (success); flags / flags2 mirror common defaults
	smb1Header[9] = 0x88                                       // flags = response
	binary.LittleEndian.PutUint16(smb1Header[10:12], 0xc003)   // flags2 = unicode + nt status + etc
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

// smb1NegotiateRejection is sent in response to SMB2 negotiate requests.
// Mirrors the SMB1 negotiate response shape but with DialectIndex 0xFFFF
// (no protocols accepted), which makes the client close the connection.
func smb1NegotiateRejection(req []byte) []byte {
	_ = req
	// status = STATUS_NOT_IMPLEMENTED = 0xC0000002, little-endian.
	hdr := []byte{0xFF, 'S', 'M', 'B', 0x72,
		0x02, 0x00, 0x00, 0xC0,
		0x88,
		0x03, 0xC0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	body := []byte{0x01, 0xFF, 0xFF, 0x00, 0x00}
	frame := append(hdr, body...)
	nbss := []byte{0x00, 0, 0, 0}
	binary.BigEndian.PutUint32(nbss, uint32(len(frame)))
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

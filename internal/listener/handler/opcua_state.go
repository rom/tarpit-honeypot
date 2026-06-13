package handler

import (
	"encoding/binary"
	"time"
)

// OPC-UA (IEEE/IEC 62541) binary-protocol responder for the discovery flow.
//
// The base handler does HEL→ACK and captures the OpenSecureChannel policy. This
// file lets the handshake progress one believable step further: it answers an
// OpenSecureChannel (SecurityPolicy#None) so the channel opens, which unlocks
// the client's next request (GetEndpoints / CreateSession / Read / Write) — the
// attacker intent we then classify. SecurityPolicy#None is plaintext, so no
// crypto is involved.
//
// Bounded-safe: every builder here is only used once the request parsed cleanly
// (uaParseOpnRequest ok). On anything we can't parse, the handler keeps its
// current capture-and-drop behavior, so the floor is the existing handler — a
// malformed response is never emitted.

// --- OPC-UA binary encoding primitives (all little-endian) ---

func uaU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// uaStr encodes an OPC-UA String: int32 length + UTF-8 bytes. "" is encoded as
// a null string (length -1), which every field here tolerates.
func uaStr(s string) []byte {
	if s == "" {
		return []byte{0xff, 0xff, 0xff, 0xff}
	}
	return append(uaU32(uint32(len(s))), s...)
}

// uaByteString encodes an OPC-UA ByteString. nil → null (-1); empty slice →
// length 0.
func uaByteString(b []byte) []byte {
	if b == nil {
		return []byte{0xff, 0xff, 0xff, 0xff}
	}
	return append(uaU32(uint32(len(b))), b...)
}

// uaDateTimeNow encodes the current time as an OPC-UA DateTime: int64 count of
// 100-ns intervals since 1601-01-01 UTC (Windows FILETIME epoch).
func uaDateTimeNow() []byte {
	ft := uint64(time.Now().UnixNano()/100) + 116444736000000000
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}

// uaNodeIdNumeric encodes a FourByte NodeId (namespace 0, numeric identifier).
func uaNodeIdNumeric(id uint16) []byte {
	return []byte{0x01, 0x00, byte(id), byte(id >> 8)}
}

// uaNodeIdNull is the TwoByte NodeId i=0 (used for null AdditionalHeader etc.).
func uaNodeIdNull() []byte { return []byte{0x00, 0x00} }

// uaResponseHeader builds a ResponseHeader with the echoed request handle and
// the given service result, no diagnostics, a null string table, and a null
// AdditionalHeader (ExtensionObject with no body).
func uaResponseHeader(requestHandle, serviceResult uint32) []byte {
	var h []byte
	h = append(h, uaDateTimeNow()...)      // Timestamp
	h = append(h, uaU32(requestHandle)...) // RequestHandle
	h = append(h, uaU32(serviceResult)...) // ServiceResult
	h = append(h, 0x00)                    // ServiceDiagnostics: encoding mask 0
	h = append(h, 0xff, 0xff, 0xff, 0xff)  // StringTable: null array
	h = append(h, uaNodeIdNull()...)       // AdditionalHeader TypeId (null)
	h = append(h, 0x00)                    // AdditionalHeader encoding: no body
	return h
}

// --- OpenSecureChannelResponse (#None) ---

// uaOpenChannelResponseBody is the OpenSecureChannelResponse service body:
// TypeId i=449, ResponseHeader, ServerProtocolVersion, ChannelSecurityToken,
// ServerNonce.
func uaOpenChannelResponseBody(requestHandle, channelID, tokenID uint32) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(449)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaU32(0)...) // ServerProtocolVersion
	// ChannelSecurityToken: channelId, tokenId, createdAt, revisedLifetime(ms)
	b = append(b, uaU32(channelID)...)
	b = append(b, uaU32(tokenID)...)
	b = append(b, uaDateTimeNow()...)
	b = append(b, uaU32(3600000)...)
	b = append(b, uaByteString([]byte{})...) // ServerNonce: empty for #None
	return b
}

// uaOpnFrame wraps a body in an OPN message with the asymmetric security header
// for #None (policy URI, null certificates) and the sequence header. The token
// id lives in the body's ChannelSecurityToken, not this header.
func uaOpnFrame(channelID, seqNum, requestID uint32, policyURI string, body []byte) []byte {
	var sec []byte
	sec = append(sec, uaU32(channelID)...)
	sec = append(sec, uaStr(policyURI)...)  // SecurityPolicyUri
	sec = append(sec, uaByteString(nil)...) // SenderCertificate: null
	sec = append(sec, uaByteString(nil)...) // ReceiverCertificateThumbprint: null
	sec = append(sec, uaU32(seqNum)...)     // SequenceNumber
	sec = append(sec, uaU32(requestID)...)  // RequestId
	sec = append(sec, body...)
	out := append([]byte("OPNF"), uaU32(uint32(8+len(sec)))...)
	return append(out, sec...)
}

// --- request parsing (defensive: returns ok=false rather than panicking) ---

func uaReadStr(b []byte, off int) (string, int, bool) {
	if off+4 > len(b) {
		return "", off, false
	}
	n := int32(binary.LittleEndian.Uint32(b[off : off+4]))
	off += 4
	if n < 0 { // null string
		return "", off, true
	}
	if off+int(n) > len(b) {
		return "", off, false
	}
	return string(b[off : off+int(n)]), off + int(n), true
}

func uaSkipByteString(b []byte, off int) (int, bool) {
	if off+4 > len(b) {
		return off, false
	}
	n := int32(binary.LittleEndian.Uint32(b[off : off+4]))
	off += 4
	if n < 0 {
		return off, true
	}
	if off+int(n) > len(b) {
		return off, false
	}
	return off + int(n), true
}

// uaSkipNodeId advances past a NodeId of any of the common encodings.
func uaSkipNodeId(b []byte, off int) (int, bool) {
	if off >= len(b) {
		return off, false
	}
	enc := b[off] & 0x0F
	off++
	switch enc {
	case 0x00: // TwoByte: id(1)
		off += 1
	case 0x01: // FourByte: ns(1)+id(2)
		off += 3
	case 0x02: // Numeric: ns(2)+id(4)
		off += 6
	case 0x03, 0x05: // String / ByteString: ns(2) + (len4+bytes)
		if off+2 > len(b) {
			return off, false
		}
		return uaSkipByteString(b, off+2)
	case 0x04: // Guid: ns(2)+16
		off += 18
	default:
		return off, false
	}
	if off > len(b) {
		return off, false
	}
	return off, true
}

// uaParseOpnRequest pulls the SecurityPolicyUri (always, as far as it gets) and,
// when the full request parses, the SequenceHeader RequestId and the
// RequestHeader RequestHandle that the response must echo. The body is the OPN
// message payload after the 8-byte message header.
func uaParseOpnRequest(b []byte) (policyURI string, requestID, requestHandle uint32, ok bool) {
	off := 4 // skip SecureChannelId
	policyURI, off, ok = uaReadStr(b, off)
	if !ok {
		return policyURI, 0, 0, false
	}
	if off, ok = uaSkipByteString(b, off); !ok { // SenderCertificate
		return policyURI, 0, 0, false
	}
	if off, ok = uaSkipByteString(b, off); !ok { // ReceiverCertificateThumbprint
		return policyURI, 0, 0, false
	}
	if off+8 > len(b) { // SequenceHeader
		return policyURI, 0, 0, false
	}
	requestID = binary.LittleEndian.Uint32(b[off+4 : off+8])
	off += 8
	if off, ok = uaSkipNodeId(b, off); !ok { // message TypeId
		return policyURI, requestID, 0, false
	}
	if off, ok = uaSkipNodeId(b, off); !ok { // RequestHeader.AuthenticationToken
		return policyURI, requestID, 0, false
	}
	off += 8 // RequestHeader.Timestamp
	if off+4 > len(b) {
		return policyURI, requestID, 0, false
	}
	requestHandle = binary.LittleEndian.Uint32(b[off : off+4])
	return policyURI, requestID, requestHandle, true
}

// uaMsgServiceID extracts the service TypeId numeric identifier from a symmetric
// MSG body (after the 8-byte message header): SecureChannelId(4) + TokenId(4) +
// SequenceHeader(8) = 16 bytes, then the request TypeId NodeId.
func uaMsgServiceID(b []byte) (uint16, bool) {
	const off = 16
	if off >= len(b) {
		return 0, false
	}
	switch b[off] & 0x0F {
	case 0x00: // TwoByte
		if off+2 > len(b) {
			return 0, false
		}
		return uint16(b[off+1]), true
	case 0x01: // FourByte
		if off+4 > len(b) {
			return 0, false
		}
		return binary.LittleEndian.Uint16(b[off+2 : off+4]), true
	case 0x02: // Numeric
		if off+7 > len(b) {
			return 0, false
		}
		return uint16(binary.LittleEndian.Uint32(b[off+3 : off+7])), true
	}
	return 0, false
}

// uaServiceName maps a request TypeId numeric id to its service name.
func uaServiceName(id uint16) string {
	switch id {
	case 428:
		return "GetEndpoints"
	case 461:
		return "CreateSession"
	case 467:
		return "ActivateSession"
	case 473:
		return "CloseSession"
	case 527:
		return "Browse"
	case 629:
		return "Read"
	case 671:
		return "Write"
	case 785:
		return "CallRequest"
	}
	return ""
}

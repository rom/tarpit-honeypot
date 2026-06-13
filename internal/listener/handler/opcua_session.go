package handler

import (
	"encoding/binary"
	"math"
)

// OPC-UA session + service layer: CreateSession → ActivateSession → Read/Write,
// built on top of the OpenSecureChannel (#None) response in opcua_state.go.
//
// Once the channel is open and a session is created/activated, a Write of a
// node's Value is stored in a per-connection overlay and a later Read of the
// same node returns it — the write-then-read-back coherence the other ICS
// handlers got. Inputs not written return a stable synthetic value.
//
// Built to the IEC-62541 binary encoding. Bounded-safe: a service is answered
// only when its request parses cleanly; otherwise the message is captured and
// the handler does not reply (floor = the prior capture-and-drop behavior).

const uaPolicyNoneURI = "http://opcfoundation.org/UA/SecurityPolicy#None"

// uaNodes is the per-connection node-value overlay (NodeId encoded bytes →
// Variant bytes). Bounded.
type uaNodes struct{ vals map[string][]byte }

const uaNodeCap = 1024

func newUANodes() *uaNodes { return &uaNodes{vals: make(map[string][]byte)} }

func (n *uaNodes) get(key string) ([]byte, bool) { v, ok := n.vals[key]; return v, ok }
func (n *uaNodes) set(key string, variant []byte) {
	if _, ok := n.vals[key]; !ok && len(n.vals) >= uaNodeCap {
		return
	}
	n.vals[key] = append([]byte(nil), variant...)
}

func uaDouble(v float64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(v))
	return b
}

// --- NodeId / Variant read helpers (defensive) ---

// uaReadNodeId returns the encoded NodeId bytes (usable as a map key) and the
// offset past it.
func uaReadNodeId(b []byte, off int) (key string, newOff int, ok bool) {
	if off >= len(b) {
		return "", off, false
	}
	var size int
	switch b[off] & 0x0F {
	case 0x00: // TwoByte
		size = 2
	case 0x01: // FourByte
		size = 4
	case 0x02: // Numeric
		size = 7
	case 0x03, 0x05: // String / ByteString: enc(1)+ns(2)+len(4)+bytes
		if off+7 > len(b) {
			return "", off, false
		}
		n := int(int32(binary.LittleEndian.Uint32(b[off+3 : off+7])))
		if n < 0 {
			n = 0
		}
		size = 7 + n
	case 0x04: // Guid: enc(1)+ns(2)+16
		size = 19
	default:
		return "", off, false
	}
	if off+size > len(b) {
		return "", off, false
	}
	return string(b[off : off+size]), off + size, true
}

func uaReadServiceTypeID(b []byte, off int) (uint16, int, bool) {
	if off >= len(b) {
		return 0, off, false
	}
	switch b[off] & 0x0F {
	case 0x00:
		if off+2 > len(b) {
			return 0, off, false
		}
		return uint16(b[off+1]), off + 2, true
	case 0x01:
		if off+4 > len(b) {
			return 0, off, false
		}
		return binary.LittleEndian.Uint16(b[off+2 : off+4]), off + 4, true
	case 0x02:
		if off+7 > len(b) {
			return 0, off, false
		}
		return uint16(binary.LittleEndian.Uint32(b[off+3 : off+7])), off + 7, true
	}
	return 0, off, false
}

// uaSkipScalar advances past one Variant scalar value of the given builtin type.
func uaSkipScalar(b []byte, off int, t byte) (int, bool) {
	switch t {
	case 0:
		return off, true
	case 1, 2, 3:
		off += 1
	case 4, 5:
		off += 2
	case 6, 7, 10:
		off += 4
	case 8, 9, 11, 13:
		off += 8
	case 14:
		off += 16
	case 12, 15, 16:
		return uaSkipByteString(b, off)
	case 17:
		_, no, ok := uaReadNodeId(b, off)
		return no, ok
	default:
		return off, false // unmodeled type — bail
	}
	if off > len(b) {
		return off, false
	}
	return off, true
}

// uaSkipVariant advances past a Variant (scalar or single-dimension array).
func uaSkipVariant(b []byte, off int) (int, bool) {
	if off >= len(b) {
		return off, false
	}
	enc := b[off]
	off++
	t := enc & 0x3F
	if enc&0x80 != 0 { // array
		if off+4 > len(b) {
			return off, false
		}
		n := int(int32(binary.LittleEndian.Uint32(b[off : off+4])))
		off += 4
		if n < 0 {
			return off, true
		}
		for i := 0; i < n; i++ {
			var ok bool
			if off, ok = uaSkipScalar(b, off, t); !ok {
				return off, false
			}
		}
		return off, true
	}
	return uaSkipScalar(b, off, t)
}

// uaReadDataValueVariant returns the encoded Variant bytes of a DataValue's
// Value (or nil if absent) and the offset past the whole DataValue.
func uaReadDataValueVariant(b []byte, off int) (variant []byte, newOff int, ok bool) {
	if off >= len(b) {
		return nil, off, false
	}
	mask := b[off]
	off++
	if mask&0x01 != 0 { // Value present
		start := off
		var ok2 bool
		if off, ok2 = uaSkipVariant(b, off); !ok2 {
			return nil, off, false
		}
		variant = append([]byte(nil), b[start:off]...)
	}
	if mask&0x02 != 0 {
		off += 4 // StatusCode
	}
	if mask&0x04 != 0 {
		off += 8 // SourceTimestamp
	}
	if mask&0x10 != 0 {
		off += 2 // SourcePicoseconds
	}
	if mask&0x08 != 0 {
		off += 8 // ServerTimestamp
	}
	if mask&0x20 != 0 {
		off += 2 // ServerPicoseconds
	}
	if off > len(b) {
		return variant, off, false
	}
	return variant, off, true
}

// uaParseMsgRequest extracts the service TypeId, the SequenceHeader RequestId,
// the RequestHeader RequestHandle, and the offset of the service parameters
// from a symmetric MSG body.
func uaParseMsgRequest(b []byte) (serviceID uint16, requestID, requestHandle uint32, paramsOff int, ok bool) {
	if len(b) < 16 {
		return 0, 0, 0, 0, false
	}
	requestID = binary.LittleEndian.Uint32(b[12:16])
	off := 16
	serviceID, off, ok = uaReadServiceTypeID(b, off)
	if !ok {
		return serviceID, requestID, 0, 0, false
	}
	// RequestHeader: AuthenticationToken(NodeId), Timestamp(8), RequestHandle(4),
	// ReturnDiagnostics(4), AuditEntryId(string), TimeoutHint(4), AdditionalHeader.
	if _, off, ok = uaReadNodeId(b, off); !ok {
		return serviceID, requestID, 0, 0, false
	}
	if off+12 > len(b) {
		return serviceID, requestID, 0, 0, false
	}
	requestHandle = binary.LittleEndian.Uint32(b[off+8 : off+12])
	off += 16                                    // Timestamp(8) + RequestHandle(4) + ReturnDiagnostics(4)
	if off, ok = uaSkipByteString(b, off); !ok { // AuditEntryId
		return serviceID, requestID, requestHandle, 0, false
	}
	off += 4                                    // TimeoutHint
	if _, off, ok = uaReadNodeId(b, off); !ok { // AdditionalHeader TypeId
		return serviceID, requestID, requestHandle, 0, false
	}
	if off >= len(b) {
		return serviceID, requestID, requestHandle, 0, false
	}
	enc := b[off]
	off++
	if enc != 0x00 { // body present
		if off, ok = uaSkipByteString(b, off); !ok {
			return serviceID, requestID, requestHandle, 0, false
		}
	}
	return serviceID, requestID, requestHandle, off, true
}

// uaParseReadNodes returns the NodeId keys of a ReadRequest's NodesToRead.
func uaParseReadNodes(b []byte, off int) []string {
	off += 12 // MaxAge(double 8) + TimestampsToReturn(enum 4)
	if off+4 > len(b) {
		return nil
	}
	count := int(int32(binary.LittleEndian.Uint32(b[off : off+4])))
	off += 4
	if count < 0 || count > 256 {
		return nil
	}
	var keys []string
	for i := 0; i < count; i++ {
		key, no, ok := uaReadNodeId(b, off)
		if !ok {
			break
		}
		off = no + 4                                 // + AttributeId
		if off, ok = uaSkipByteString(b, off); !ok { // IndexRange
			break
		}
		// DataEncoding QualifiedName: ns(2) + name(string)
		if off+2 > len(b) {
			break
		}
		off += 2
		if off, ok = uaSkipByteString(b, off); !ok { // name
			break
		}
		keys = append(keys, key)
	}
	return keys
}

type uaWrite struct {
	key     string
	variant []byte
}

// uaParseWriteNodes returns the (NodeId, Variant) pairs of a WriteRequest's
// NodesToWrite.
func uaParseWriteNodes(b []byte, off int) []uaWrite {
	if off+4 > len(b) {
		return nil
	}
	count := int(int32(binary.LittleEndian.Uint32(b[off : off+4])))
	off += 4
	if count < 0 || count > 256 {
		return nil
	}
	var writes []uaWrite
	for i := 0; i < count; i++ {
		key, no, ok := uaReadNodeId(b, off)
		if !ok {
			break
		}
		off = no + 4                                 // + AttributeId
		if off, ok = uaSkipByteString(b, off); !ok { // IndexRange
			break
		}
		variant, no2, ok2 := uaReadDataValueVariant(b, off)
		if !ok2 {
			break
		}
		off = no2
		if variant != nil {
			writes = append(writes, uaWrite{key, variant})
		}
	}
	return writes
}

// uaSynthVariant is a stable synthetic Int32 Variant for an unwritten node.
func uaSynthVariant(key string) []byte {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h = (h ^ uint32(key[i])) * 16777619
	}
	return append([]byte{6}, uaU32(1000+(h%9000))...) // Variant: Int32
}

// uaDataValue wraps a Variant in a DataValue carrying only the Value.
func uaDataValue(variant []byte) []byte { return append([]byte{0x01}, variant...) }

// --- response bodies ---

func uaLocalizedText(text string) []byte { return append([]byte{0x02}, uaStr(text)...) }

func uaUserTokenPolicy(policyID string, tokenType uint32) []byte {
	var b []byte
	b = append(b, uaStr(policyID)...)
	b = append(b, uaU32(tokenType)...) // 0 = Anonymous
	b = append(b, uaStr("")...)        // issuedTokenType (null)
	b = append(b, uaStr("")...)        // issuerEndpointUrl (null)
	b = append(b, uaStr("")...)        // securityPolicyUri (null)
	return b
}

func uaApplicationDescription() []byte {
	var b []byte
	b = append(b, uaStr("urn:tarpit:opcua:server")...)
	b = append(b, uaStr("urn:tarpit:opcua")...)
	b = append(b, uaLocalizedText("Tarpit OPC-UA Server")...)
	b = append(b, uaU32(0)...) // ApplicationType = Server
	b = append(b, uaStr("")...)
	b = append(b, uaStr("")...)
	b = append(b, uaU32(0xffffffff)...) // DiscoveryUrls: null array
	return b
}

func uaEndpointDescription(endpointURL string) []byte {
	var b []byte
	b = append(b, uaStr(endpointURL)...)
	b = append(b, uaApplicationDescription()...)
	b = append(b, uaByteString(nil)...) // ServerCertificate (null)
	b = append(b, uaU32(1)...)          // MessageSecurityMode = None
	b = append(b, uaStr(uaPolicyNoneURI)...)
	b = append(b, uaU32(1)...) // UserIdentityTokens count
	b = append(b, uaUserTokenPolicy("anonymous", 0)...)
	b = append(b, uaStr("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")...)
	b = append(b, 0x00) // SecurityLevel
	return b
}

func uaGetEndpointsResponse(requestHandle uint32, endpointURL string) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(431)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaU32(1)...) // Endpoints count
	return append(b, uaEndpointDescription(endpointURL)...)
}

func uaCreateSessionResponse(requestHandle uint32, endpointURL string) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(464)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaNodeIdNumeric(1000)...)          // SessionId
	b = append(b, uaNodeIdNumeric(1001)...)          // AuthenticationToken
	b = append(b, uaDouble(1200000)...)              // RevisedSessionTimeout
	b = append(b, uaByteString(make([]byte, 32))...) // ServerNonce
	b = append(b, uaByteString(nil)...)              // ServerCertificate (null)
	b = append(b, uaU32(1)...)                       // ServerEndpoints count
	b = append(b, uaEndpointDescription(endpointURL)...)
	b = append(b, uaU32(0)...)          // ServerSoftwareCertificates count
	b = append(b, uaStr("")...)         // ServerSignature.Algorithm (null)
	b = append(b, uaByteString(nil)...) // ServerSignature.Signature (null)
	b = append(b, uaU32(0x1000000)...)  // MaxRequestMessageSize
	return b
}

func uaActivateSessionResponse(requestHandle uint32) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(470)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaByteString(make([]byte, 32))...) // ServerNonce
	b = append(b, uaU32(0)...)                       // Results count
	b = append(b, uaU32(0xffffffff)...)              // DiagnosticInfos null
	return b
}

func uaReadResponse(requestHandle uint32, dataValues [][]byte) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(632)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaU32(uint32(len(dataValues)))...)
	for _, dv := range dataValues {
		b = append(b, dv...)
	}
	return append(b, uaU32(0xffffffff)...) // DiagnosticInfos null
}

func uaWriteResponse(requestHandle uint32, n int) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(674)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaU32(uint32(n))...)
	for i := 0; i < n; i++ {
		b = append(b, uaU32(0)...) // StatusCode Good
	}
	return append(b, uaU32(0xffffffff)...) // DiagnosticInfos null
}

func uaBrowseResponse(requestHandle uint32) []byte {
	var b []byte
	b = append(b, uaNodeIdNumeric(530)...)
	b = append(b, uaResponseHeader(requestHandle, 0)...)
	b = append(b, uaU32(0)...)             // Results count
	return append(b, uaU32(0xffffffff)...) // DiagnosticInfos null
}

func uaCloseSessionResponse(requestHandle uint32) []byte {
	return append(uaNodeIdNumeric(476), uaResponseHeader(requestHandle, 0)...)
}

// uaMsgFrame wraps a service-response body in a symmetric MSG message.
func uaMsgFrame(channelID, tokenID, seqNum, requestID uint32, body []byte) []byte {
	var sec []byte
	sec = append(sec, uaU32(channelID)...)
	sec = append(sec, uaU32(tokenID)...)
	sec = append(sec, uaU32(seqNum)...)
	sec = append(sec, uaU32(requestID)...)
	sec = append(sec, body...)
	out := append([]byte("MSGF"), uaU32(uint32(8+len(sec)))...)
	return append(out, sec...)
}

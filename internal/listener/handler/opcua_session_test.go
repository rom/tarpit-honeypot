package handler

import (
	"bytes"
	"testing"
)

// uaReqHeader builds a minimal RequestHeader (null auth token, zero timestamp,
// the given handle, null audit entry, null additional header).
func uaReqHeader(handle uint32) []byte {
	var h []byte
	h = append(h, uaNodeIdNull()...)  // AuthenticationToken
	h = append(h, make([]byte, 8)...) // Timestamp
	h = append(h, uaU32(handle)...)   // RequestHandle
	h = append(h, uaU32(0)...)        // ReturnDiagnostics
	h = append(h, uaStr("")...)       // AuditEntryId (null)
	h = append(h, uaU32(0)...)        // TimeoutHint
	h = append(h, uaNodeIdNull()...)  // AdditionalHeader TypeId
	h = append(h, 0x00)               // AdditionalHeader: no body
	return h
}

// uaMsgReqFrame wraps a service-request body in a symmetric MSG.
func uaMsgReqFrame(body []byte) []byte {
	var sec []byte
	sec = append(sec, uaU32(0x1A2B3C4D)...) // SecureChannelId
	sec = append(sec, uaU32(1)...)          // TokenId
	sec = append(sec, uaU32(2)...)          // SequenceNumber
	sec = append(sec, uaU32(7)...)          // RequestId
	sec = append(sec, body...)
	return append(append([]byte("MSGF"), uaU32(uint32(8+len(sec)))...), sec...)
}

// uaServiceMsg builds a request carrying only TypeId + RequestHeader (enough for
// the canned-response services: GetEndpoints / CreateSession / ActivateSession).
func uaServiceMsg(serviceID uint16) []byte {
	body := append(uaNodeIdNumeric(serviceID), uaReqHeader(1)...)
	return uaMsgReqFrame(body)
}

func uaWriteMsg(node, variant []byte) []byte {
	var body []byte
	body = append(body, uaNodeIdNumeric(671)...) // WriteRequest
	body = append(body, uaReqHeader(1)...)
	body = append(body, uaU32(1)...)  // NodesToWrite count
	body = append(body, node...)      // NodeId
	body = append(body, uaU32(13)...) // AttributeId = Value
	body = append(body, uaStr("")...) // IndexRange (null)
	body = append(body, 0x01)         // DataValue mask: Value present
	body = append(body, variant...)   // Variant
	return uaMsgReqFrame(body)
}

func uaReadMsg(node []byte) []byte {
	var body []byte
	body = append(body, uaNodeIdNumeric(629)...) // ReadRequest
	body = append(body, uaReqHeader(1)...)
	body = append(body, uaDouble(0)...) // MaxAge
	body = append(body, uaU32(0)...)    // TimestampsToReturn
	body = append(body, uaU32(1)...)    // NodesToRead count
	body = append(body, node...)        // NodeId
	body = append(body, uaU32(13)...)   // AttributeId = Value
	body = append(body, uaStr("")...)   // IndexRange (null)
	body = append(body, 0x00, 0x00)     // DataEncoding QualifiedName namespace
	body = append(body, uaStr("")...)   // DataEncoding name (null)
	return uaMsgReqFrame(body)
}

// A node written via Write reads back its value on a later Read in the session.
func TestOPCUAWriteThenReadCoherent(t *testing.T) {
	node := uaNodeIdNumeric(2000)
	variant := append([]byte{0x06}, uaU32(0xCAFE)...) // Variant: Int32 0xCAFE
	input := bytes.Join([][]byte{
		uaHel("opc.tcp://t/UA"),
		uaOpnRequest(uaPolicyNone, 1, 1),
		uaWriteMsg(node, variant),
		uaReadMsg(node),
		uaClo(),
	}, nil)
	_, out := roundtrip(t, &opcua{}, string(input))
	// The Read response must carry a DataValue (mask 0x01) holding the written
	// Variant.
	want := append([]byte{0x01}, variant...)
	if !bytes.Contains(out, want) {
		t.Errorf("Read did not return the written node value\n want subseq % x\n in            % x", want, out)
	}
}

// CreateSession and ActivateSession requests get their typed responses.
func TestOPCUASessionFlow(t *testing.T) {
	input := bytes.Join([][]byte{
		uaHel("opc.tcp://t/UA"),
		uaOpnRequest(uaPolicyNone, 1, 1),
		uaServiceMsg(461), // CreateSession
		uaServiceMsg(467), // ActivateSession
		uaClo(),
	}, nil)
	_, out := roundtrip(t, &opcua{}, string(input))
	if !bytes.Contains(out, uaNodeIdNumeric(464)) {
		t.Errorf("missing CreateSessionResponse (i=464)")
	}
	if !bytes.Contains(out, uaNodeIdNumeric(470)) {
		t.Errorf("missing ActivateSessionResponse (i=470)")
	}
}

// GetEndpoints returns an endpoint list advertising the #None policy.
func TestOPCUAGetEndpoints(t *testing.T) {
	input := bytes.Join([][]byte{
		uaHel("opc.tcp://target:4840/UA"),
		uaOpnRequest(uaPolicyNone, 1, 1),
		uaServiceMsg(428), // GetEndpoints
		uaClo(),
	}, nil)
	_, out := roundtrip(t, &opcua{}, string(input))
	if !bytes.Contains(out, uaNodeIdNumeric(431)) {
		t.Errorf("missing GetEndpointsResponse (i=431)")
	}
	if !bytes.Contains(out, []byte(uaPolicyNoneURI)) {
		t.Errorf("endpoint response did not advertise the #None policy")
	}
}

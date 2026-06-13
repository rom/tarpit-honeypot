package handler

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func uaHel(endpoint string) []byte {
	hb := make([]byte, 20) // version + 4 buffer-size fields (zeros are fine)
	hb = append(hb, uaU32(uint32(len(endpoint)))...)
	hb = append(hb, endpoint...)
	return append(append([]byte("HELF"), uaU32(uint32(8+len(hb)))...), hb...)
}

// uaOpnRequest builds an OpenSecureChannel request parseable through the
// RequestHeader's RequestHandle (which is all uaParseOpnRequest reads).
func uaOpnRequest(policyURI string, requestID, requestHandle uint32) []byte {
	var b []byte
	b = append(b, uaU32(0)...)             // SecureChannelId (new)
	b = append(b, uaStr(policyURI)...)     // SecurityPolicyUri
	b = append(b, uaByteString(nil)...)    // SenderCertificate
	b = append(b, uaByteString(nil)...)    // ReceiverCertificateThumbprint
	b = append(b, uaU32(100)...)           // SequenceNumber
	b = append(b, uaU32(requestID)...)     // RequestId
	b = append(b, uaNodeIdNumeric(446)...) // TypeId: OpenSecureChannelRequest
	b = append(b, uaNodeIdNull()...)       // RequestHeader.AuthenticationToken
	b = append(b, make([]byte, 8)...)      // Timestamp
	b = append(b, uaU32(requestHandle)...) // RequestHandle
	b = append(b, make([]byte, 8)...)      // trailing request fields (ignored)
	return append(append([]byte("OPNF"), uaU32(uint32(8+len(b)))...), b...)
}

// uaMsgRequest builds a symmetric MSG carrying a service request TypeId.
func uaMsgRequest(serviceID uint16) []byte {
	var b []byte
	b = append(b, uaU32(0x1A2B3C4D)...) // SecureChannelId
	b = append(b, uaU32(1)...)          // TokenId
	b = append(b, uaU32(2)...)          // SequenceNumber
	b = append(b, uaU32(2)...)          // RequestId
	b = append(b, uaNodeIdNumeric(serviceID)...)
	return append(append([]byte("MSGF"), uaU32(uint32(8+len(b)))...), b...)
}

func uaClo() []byte { return append([]byte("CLOF"), uaU32(8)...) }

const uaPolicyNone = "http://opcfoundation.org/UA/SecurityPolicy#None"

// A well-formed OpenSecureChannel gets a valid OPN response: the assigned
// channel id, the echoed request id, and the OpenSecureChannelResponse TypeId.
func TestOPCUAOpenChannelResponse(t *testing.T) {
	input := bytes.Join([][]byte{
		uaHel("opc.tcp://target/UA"),
		uaOpnRequest(uaPolicyNone, 0x11223344, 0x55667788),
		uaClo(),
	}, nil)
	_, out := roundtrip(t, &opcua{}, string(input))

	// out = ACK (28 bytes) followed by the OPN response.
	if len(out) < 28+16 {
		t.Fatalf("no OPN response emitted (out=%d bytes)", len(out))
	}
	resp := out[28:]
	if string(resp[0:4]) != "OPNF" {
		t.Fatalf("expected an OPN response after the ACK, got % x", resp[:min(8, len(resp))])
	}
	if got := binary.LittleEndian.Uint32(resp[8:12]); got != 0x1A2B3C4D {
		t.Errorf("SecureChannelId = %#x; want 0x1A2B3C4D", got)
	}
	if !bytes.Contains(resp, uaNodeIdNumeric(449)) {
		t.Errorf("response missing OpenSecureChannelResponse TypeId (i=449)")
	}
	if !bytes.Contains(resp, uaU32(0x11223344)) {
		t.Errorf("response did not echo the request id 0x11223344")
	}
}

// The simplified OPN frame from the existing fingerprint test must still be
// captured (policy + anomaly) and must NOT trigger a malformed response.
func TestOPCUAInsecurePolicyStillCaptured(t *testing.T) {
	// ob = SecureChannelId(4) + [policy-uri string] + 8 trailing bytes — parses
	// the policy but not the full request, so no response is sent.
	ob := append(uaU32(0), uaStr(uaPolicyNone)...)
	ob = append(ob, make([]byte, 8)...)
	opn := append(append([]byte("OPNF"), uaU32(uint32(8+len(ob)))...), ob...)
	input := bytes.Join([][]byte{uaHel("opc.tcp://t/UA"), opn, uaClo()}, nil)

	res, out := roundtrip(t, &opcua{}, string(input))
	if p, _ := res.Meta["opcua_security_policy"].(string); p != uaPolicyNone {
		t.Errorf("policy not captured: %v", res.Meta["opcua_security_policy"])
	}
	if !hasAnom(res, "ics-opcua-insecure-policy") {
		t.Errorf("insecure policy not flagged: %v", res.Meta["anomalies"])
	}
	// Only the ACK should have been written (no OPN response for the half-frame).
	if len(out) > 28 {
		t.Errorf("unexpected bytes after ACK for an unparseable OPN: % x", out[28:])
	}
}

// A Read service request on the open channel is classified as process-data access.
func TestOPCUAReadServiceClassified(t *testing.T) {
	input := bytes.Join([][]byte{
		uaHel("opc.tcp://t/UA"),
		uaOpnRequest(uaPolicyNone, 1, 1),
		uaMsgRequest(629), // ReadRequest
		uaClo(),
	}, nil)
	res, _ := roundtrip(t, &opcua{}, string(input))
	if res.Meta["opcua_service"] != "Read" {
		t.Errorf("opcua_service = %v; want Read", res.Meta["opcua_service"])
	}
	if !hasAnom(res, "ics-process-data-access") {
		t.Errorf("Read not flagged: %v", res.Meta["anomalies"])
	}
}

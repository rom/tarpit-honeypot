package handler

import "testing"

// efsrpcWireUUID is MS-EFSRPC (c681d488-d850-11d0-8c52-00c04fd90f7e) in the
// DCE/RPC on-wire mixed-endian encoding.
var efsrpcWireUUID = []byte{
	0x88, 0xd4, 0x81, 0xc6, // field1 LE
	0x50, 0xd8, // field2 LE
	0xd0, 0x11, // field3 LE
	0x8c, 0x52, // field4 BE
	0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e, // field5 BE
}

func TestDCERPCCoercedAuthPetitPotam(t *testing.T) {
	res := runDCERPC(t, buildBindPDU(efsrpcWireUUID))
	if res.Meta["dcerpc_interface"] != "efsrpc" {
		t.Fatalf("interface not resolved to efsrpc: %v", res.Meta["dcerpc_interface"])
	}
	if !hasAnom(res, "dcerpc-coerced-auth") || !hasAnom(res, "cve:CVE-2021-36942") {
		t.Errorf("PetitPotam coercion not flagged: %v", res.Meta["anomalies"])
	}
}

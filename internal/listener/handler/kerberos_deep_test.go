package handler

import "testing"

// padata wraps a 1-byte padata-type in the [1] INTEGER form the scanner
// matches (0xA1 0x03 0x02 0x01 <type>).
func padata1(t byte) []byte { return []byte{0xA1, 0x03, 0x02, 0x01, t} }

// padata2 wraps a 2-byte padata-type (>=128) as 0xA1 0x04 0x02 0x02 hi lo.
func padata2(t int) []byte {
	return []byte{0xA1, 0x04, 0x02, 0x02, byte(t >> 8), byte(t)}
}

func TestKerberosASREPRoast(t *testing.T) {
	// AS-REQ (0x6A) with no PA-ENC-TIMESTAMP padata = AS-REP roasting probe.
	body := append([]byte{0x6A, 0x08, 0x02, 0x01, 0x05}, 0x00, 0x00, 0x00)
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	if !hasAnom(res, "kerberos-asrep-roast") {
		t.Errorf("AS-REQ without preauth not flagged as AS-REP roast: %v", res.Meta["anomalies"])
	}
}

func TestKerberosASREQWithPreauthNotRoast(t *testing.T) {
	// AS-REQ that DOES carry PA-ENC-TIMESTAMP (type 2) must not be flagged.
	body := append([]byte{0x6A, 0x10}, padata1(2)...)
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	if hasAnom(res, "kerberos-asrep-roast") {
		t.Errorf("AS-REQ with preauth wrongly flagged as AS-REP roast: %v", res.Meta["anomalies"])
	}
}

func TestKerberosPKINIT(t *testing.T) {
	body := append([]byte{0x6A, 0x10}, padata1(16)...) // PA-PK-AS-REQ
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	if !hasAnom(res, "kerberos-pkinit") {
		t.Errorf("PKINIT padata not flagged: %v", res.Meta["anomalies"])
	}
}

func TestKerberosS4U(t *testing.T) {
	body := append([]byte{0x6C, 0x12}, padata2(129)...) // TGS-REQ + PA-FOR-USER
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	if !hasAnom(res, "kerberos-s4u") {
		t.Errorf("S4U2Self padata not flagged: %v", res.Meta["anomalies"])
	}
}

func TestKerberosBronzeBit(t *testing.T) {
	body := append([]byte{0x6C, 0x12}, padata2(167)...) // PA-PAC-OPTIONS
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	if !hasAnom(res, "kerberos-pac-options") {
		t.Errorf("PA-PAC-OPTIONS not flagged: %v", res.Meta["anomalies"])
	}
}

func TestKerberosV4Legacy(t *testing.T) {
	// Kerberos 4 / KTH-KRB: protocol version 4, msg-type AUTH_MSG_KDC_REQUEST.
	body := []byte{0x04, 0x02, 0x00, 0x00, 'A', 'C', 'M', 'E'}
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	if res.Meta["kerberos_version"] != 4 {
		t.Errorf("kerberos_version = %v; want 4", res.Meta["kerberos_version"])
	}
	if !hasAnom(res, "kerberos-v4-legacy") {
		t.Errorf("KRB4 not flagged as legacy: %v", res.Meta["anomalies"])
	}
}

func TestKerberosV4OverUDP(t *testing.T) {
	pkt := []byte{0x04, 0x02, 0x00, 0x00, 'A', 'C', 'M', 'E'}
	res := udpResult(t, &kerberosUDP{}, pkt)
	if !hasAnom(res, "kerberos-v4-legacy") {
		t.Errorf("KRB4 over UDP not flagged: %v", res.Meta["anomalies"])
	}
}

package handler

import "testing"

// Second batch of protocol-deepening enrichments: coap, knx, fins, radius,
// cldap, isakmp, nbns, profinet, stun, mssql_browser. Each adds a higher-signal
// anomaly or a captured field. These tests pin the new behavior.

func TestCoAPResourceDiscovery(t *testing.T) {
	// CoAP GET (code 0x01), two Uri-Path options (11) = ".well-known" + "core".
	pkt := []byte{0x40, 0x01, 0x12, 0x34}
	pkt = append(pkt, 0xbb) // delta 11, len 11
	pkt = append(pkt, []byte(".well-known")...)
	pkt = append(pkt, 0x04) // delta 0, len 4
	pkt = append(pkt, []byte("core")...)
	res := udpResult(t, &coap{lim: newUDPReflectLimiter()}, pkt)
	if !hasAnomaly(res, "coap-resource-discovery") || !hasAnomaly(res, "amplification-probe") {
		t.Errorf("coap discovery: %v", res.Meta["anomalies"])
	}
}

func TestFINSWriteFlagged(t *testing.T) {
	// FINS header (12 bytes): MRC at [10]=0x01, SRC at [11]=0x02 = MEMORY_AREA_WRITE.
	pkt := make([]byte, 18)
	pkt[10], pkt[11] = 0x01, 0x02
	res := udpResult(t, &fins{lim: newUDPReflectLimiter()}, pkt)
	if !hasAnomaly(res, "ics-plc-write") {
		t.Errorf("fins write: %v", res.Meta["anomalies"])
	}
}

func TestISAKMPAggressiveMode(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[17] = 0x10 // IKEv1
	pkt[18] = 4    // aggressive
	res := udpResult(t, isakmp{}, pkt)
	if !hasAnomaly(res, "ike-aggressive-mode") {
		t.Errorf("ike aggressive: %v", res.Meta["anomalies"])
	}
}

func TestProfinetIODWrite(t *testing.T) {
	pkt := make([]byte, 32)
	pkt[0] = 0x04 // DCE-RPC v4
	pkt[1] = 0x00 // request
	pkt[28] = 0x03
	pkt[29] = 0x00 // opnum 3 = IODWriteReq
	res := udpResult(t, &profinet{}, pkt)
	if !hasAnomaly(res, "profinet-iod-write") {
		t.Errorf("profinet write: %v", res.Meta["anomalies"])
	}
	if res.Meta["profinet_operation"] != "IODWrite" {
		t.Errorf("profinet_operation = %v, want IODWrite", res.Meta["profinet_operation"])
	}
}

func TestProfinetIODReadIsRecon(t *testing.T) {
	pkt := make([]byte, 32)
	pkt[0] = 0x04 // DCE-RPC v4
	pkt[1] = 0x00 // request
	pkt[28] = 0x02
	pkt[29] = 0x00 // opnum 2 = IODReadReq
	res := udpResult(t, &profinet{}, pkt)
	if !hasAnomaly(res, "ics-process-data-access") {
		t.Errorf("profinet read not flagged as recon: %v", res.Meta["anomalies"])
	}
	if res.Meta["profinet_operation"] != "IODRead" {
		t.Errorf("profinet_operation = %v, want IODRead", res.Meta["profinet_operation"])
	}
}

func TestSTUNClassicAmplification(t *testing.T) {
	// Binding request (0x0001) with NO magic cookie = classic STUN.
	pkt := make([]byte, 20)
	pkt[0], pkt[1] = 0x00, 0x01
	res := udpResult(t, &stun{lim: newUDPReflectLimiter()}, pkt)
	if !hasAnomaly(res, "stun-classic-amplification") {
		t.Errorf("classic stun: %v", res.Meta["anomalies"])
	}
}

func TestCLDAPNetlogonAmplification(t *testing.T) {
	pkt := buildTestCLDAPSearch()
	res := udpResult(t, &cldap{}, pkt)
	if !hasAnomaly(res, "amplification-probe") || !hasAnomaly(res, "cldap-netlogon-probe") {
		t.Errorf("cldap netlogon: %v", res.Meta["anomalies"])
	}
}

// buildTestCLDAPSearch builds a minimal LDAP SearchRequest (op 0x63) message.
func buildTestCLDAPSearch() []byte {
	// SEQUENCE { messageID INTEGER 1, [APPLICATION 3] SearchRequest {} }
	body := []byte{0x02, 0x01, 0x01, 0x63, 0x00}
	return append([]byte{0x30, byte(len(body))}, body...)
}

package handler

import (
	"encoding/binary"
	"testing"
)

// --- Intel AMT digest-auth bypass (CVE-2017-5689), end-to-end ---

func TestIntelAMTDigestBypassHandler(t *testing.T) {
	req := "GET /index.htm HTTP/1.1\r\n" +
		"Host: 10.0.0.5:16992\r\n" +
		"Authorization: Digest username=\"admin\", realm=\"Digest:A4070000\", " +
		"nonce=\"deadbeefcafebabe\", uri=\"/index.htm\", response=\"\"\r\n\r\n"
	res, _ := roundtrip(t, &mgmtWeb{kind: "intel_amt"}, req)
	if !hasAnom(res, "cve:CVE-2017-5689") || !cveHit(res, "CVE-2017-5689") {
		t.Errorf("Intel AMT empty-digest bypass not flagged: anomalies=%v cves=%v",
			res.Meta["anomalies"], res.CVEHits)
	}
}

// --- Oracle TNS Poison remote registration (CVE-2012-1675) ---

func buildTNSConnect(desc string) string {
	body := []byte(desc)
	total := 8 + len(body)
	pkt := make([]byte, total)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(total))
	pkt[4] = 1 // packet type = CONNECT
	copy(pkt[8:], body)
	return string(pkt)
}

func TestOracleTNSPoisonRegistration(t *testing.T) {
	in := buildTNSConnect("(DESCRIPTION=(CONNECT_DATA=(COMMAND=SERVICE_REGISTER_NSGR)))")
	res, _ := roundtrip(t, &oracleTNS{}, in)
	if !hasAnom(res, "cve:CVE-2012-1675") || !hasAnom(res, "oracle-tns-poison-registration") {
		t.Errorf("TNS Poison not flagged: %v", res.Meta["anomalies"])
	}
	if !cveHit(res, "CVE-2012-1675") {
		t.Errorf("CVE-2012-1675 not in CVEHits: %v", res.CVEHits)
	}
}

func TestOracleTNSVersionProbeNotPoison(t *testing.T) {
	in := buildTNSConnect("(CONNECT_DATA=(COMMAND=version))")
	res, _ := roundtrip(t, &oracleTNS{}, in)
	if hasAnom(res, "cve:CVE-2012-1675") {
		t.Errorf("benign version probe wrongly flagged as TNS Poison")
	}
}

// --- Mosquitto pattern-ACL bypass (CVE-2017-7650) ---

func mqttConnect(clientID, username string) []byte {
	mqStr := func(s string) []byte {
		b := make([]byte, 2+len(s))
		binary.BigEndian.PutUint16(b[0:2], uint16(len(s)))
		copy(b[2:], s)
		return b
	}
	vh := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04} // proto name "MQTT", level 4
	flags := byte(0x02)                                // clean session
	if username != "" {
		flags |= 0x80
	}
	vh = append(vh, flags, 0x00, 0x3c) // flags + keepalive 60
	body := append(vh, mqStr(clientID)...)
	if username != "" {
		body = append(body, mqStr(username)...)
	}
	return append([]byte{0x10, byte(len(body))}, body...) // CONNECT + remaining length
}

func TestMQTTMosquittoACLBypass(t *testing.T) {
	in := append(mqttConnect("#", ""), 0xE0, 0x00) // CONNECT(client id "#") + DISCONNECT
	res, _ := roundtrip(t, &mqtt{}, string(in))
	if !hasAnom(res, "cve:CVE-2017-7650") || !hasAnom(res, "mqtt-acl-pattern-bypass") {
		t.Errorf("Mosquitto ACL bypass not flagged: %v", res.Meta["anomalies"])
	}
	if !cveHit(res, "CVE-2017-7650") {
		t.Errorf("CVE-2017-7650 not in CVEHits: %v", res.CVEHits)
	}
}

func TestMQTTNormalClientNotFlagged(t *testing.T) {
	in := append(mqttConnect("mosquitto_pub_4821", "sensor"), 0xE0, 0x00)
	res, _ := roundtrip(t, &mqtt{}, string(in))
	if hasAnom(res, "cve:CVE-2017-7650") {
		t.Errorf("normal MQTT client wrongly flagged as CVE-2017-7650")
	}
}

// --- memcached binary-protocol integer overflows (CVE-2016-8704/05/06) ---

// memcachedBinReq builds a 24-byte binary request header plus `bodyLen` filler
// bytes (so the handler's bounded body read returns immediately instead of
// waiting out the read timeout).
func memcachedBinReq(opcode byte, keyLen uint16, extLen byte, totalBody uint32, bodyLen int) string {
	hdr := make([]byte, 24)
	hdr[0] = 0x80 // request magic
	hdr[1] = opcode
	binary.BigEndian.PutUint16(hdr[2:4], keyLen)
	hdr[4] = extLen
	binary.BigEndian.PutUint32(hdr[8:12], totalBody)
	return string(hdr) + string(make([]byte, bodyLen))
}

func TestMemcachedBinarySASLOverflow(t *testing.T) {
	// SASL auth (0x21) whose declared key length exceeds the body — the
	// malformed length the process_bin_sasl_auth overflow needs.
	in := memcachedBinReq(0x21, 0xffff, 0, 4, 4)
	res, _ := roundtrip(t, &memcached{}, in)
	if !hasAnom(res, "memcached-binary-protocol") {
		t.Errorf("binary protocol not flagged: %v", res.Meta["anomalies"])
	}
	if !hasAnom(res, "cve:CVE-2016-8706") || !cveHit(res, "CVE-2016-8706") {
		t.Errorf("SASL overflow not flagged: anomalies=%v cves=%v", res.Meta["anomalies"], res.CVEHits)
	}
}

func TestMemcachedBinaryAppendOverflow(t *testing.T) {
	// APPEND (0x0e) with an implausibly large total body (> 16 MiB cap).
	in := memcachedBinReq(0x0e, 0, 0, 1<<25, 8)
	res, _ := roundtrip(t, &memcached{}, in)
	if !hasAnom(res, "cve:CVE-2016-8704") || !cveHit(res, "CVE-2016-8704") {
		t.Errorf("append overflow not flagged: anomalies=%v cves=%v", res.Meta["anomalies"], res.CVEHits)
	}
}

func TestMemcachedBinaryBenignNotCVE(t *testing.T) {
	// A well-formed binary SET (0x01): 8-byte extras + 3-byte key + 5-byte
	// value = 16-byte body, all lengths consistent. Binary protocol is noted,
	// but no CVE is attributed.
	in := memcachedBinReq(0x01, 3, 8, 16, 16)
	res, _ := roundtrip(t, &memcached{}, in)
	if !hasAnom(res, "memcached-binary-protocol") {
		t.Errorf("binary protocol not flagged for benign SET")
	}
	for _, id := range []string{"CVE-2016-8704", "CVE-2016-8705", "CVE-2016-8706"} {
		if hasAnom(res, "cve:"+id) {
			t.Errorf("benign binary SET wrongly flagged as %s", id)
		}
	}
}

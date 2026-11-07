package handler

import (
	"strings"
	"testing"
)

func TestASTMResultRecordFlagged(t *testing.T) {
	// ENQ + a result record (R|) — clinical PHI.
	req := append([]byte{0x05}, []byte("R|1|^^^Glucose|105|mg/dL|H||F\r")...)
	res, reply := runDevsvc(t, &astm{}, req)
	if !containsStr(basAnoms(res), "astm-probe") {
		t.Errorf("want astm-probe, got %v", basAnoms(res))
	}
	if res.Meta["astm_record"] != "result" {
		t.Errorf("astm_record = %v want result", res.Meta["astm_record"])
	}
	if len(reply) != 1 || reply[0] != 0x06 {
		t.Errorf("want single ACK (0x06), got %v", reply)
	}
}

func TestASTMInjection(t *testing.T) {
	req := []byte("P|1||MRN123||DOE^JOHN||19700101|M|||../../etc/passwd\r")
	res, _ := runDevsvc(t, &astm{}, req)
	if !containsStr(basAnoms(res), "astm-injection") {
		t.Errorf("path traversal in ASTM should flag astm-injection, got %v", basAnoms(res))
	}
}

func TestPOCT1Observation(t *testing.T) {
	req := []byte(`<?xml version="1.0"?><OBS.R01 xmlns="urn:astm-org:POCT1-A"><SVC/></OBS.R01>`)
	res, reply := runDevsvc(t, &poct1{}, req)
	if res.Meta["poct1_msg"] != "OBS" {
		t.Errorf("poct1_msg = %v want OBS", res.Meta["poct1_msg"])
	}
	if !strings.Contains(string(reply), "ACK") {
		t.Errorf("want POCT1 ACK, got %q", reply)
	}
}

func TestFHIRPatientQueryFlagged(t *testing.T) {
	res, reply := runDevsvc(t, &fhir{}, []byte("GET /fhir/Patient?name=smith HTTP/1.1\r\nHost: ehr\r\n\r\n"))
	if res.Meta["fhir_resource"] != "Patient" {
		t.Errorf("fhir_resource = %v want Patient", res.Meta["fhir_resource"])
	}
	if !strings.Contains(string(res.Meta["intent"].(string)), "PHI") {
		t.Errorf("Patient query intent should mention PHI, got %v", res.Meta["intent"])
	}
	if !strings.Contains(string(reply), "Bundle") {
		t.Errorf("want FHIR Bundle reply, got %q", reply)
	}
}

func TestFHIRWriteFlagged(t *testing.T) {
	res, _ := runDevsvc(t, &fhir{}, []byte("POST /fhir/Observation HTTP/1.1\r\nHost: ehr\r\nContent-Length: 2\r\n\r\n{}"))
	if !containsStr(basAnoms(res), "fhir-write") {
		t.Errorf("POST should flag fhir-write, got %v", basAnoms(res))
	}
}

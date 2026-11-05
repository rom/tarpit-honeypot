package handler

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- HL7 / MLLP ----------------------------------------------------------

func mllp(s string) []byte {
	b := []byte{mllpVT}
	b = append(b, s...)
	return append(b, mllpFS, mllpCR)
}

func TestHL7ACK(t *testing.T) {
	msg := "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101120000||ADT^A01|MSG0001|P|2.5\r" +
		"PID|1||12345^^^MRN||DOE^JOHN\r"
	res, reply := runDevsvc(t, &hl7{}, mllp(msg))

	if len(reply) < 3 || reply[0] != mllpVT || reply[len(reply)-2] != mllpFS || reply[len(reply)-1] != mllpCR {
		t.Fatalf("reply not MLLP-framed: %v", reply)
	}
	body := string(reply)
	if !strings.Contains(body, "MSA|AA|MSG0001") {
		t.Errorf("ACK missing MSA|AA with echoed control id: %q", body)
	}
	if !strings.Contains(body, "ACK^A01") {
		t.Errorf("ACK did not echo trigger event ACK^A01: %q", body)
	}
	if res.Meta["hl7_message_type"] != "ADT^A01" {
		t.Errorf("hl7_message_type = %v; want ADT^A01", res.Meta["hl7_message_type"])
	}
	if res.Meta["hl7_control_id"] != "MSG0001" {
		t.Errorf("hl7_control_id = %v; want MSG0001", res.Meta["hl7_control_id"])
	}
	if res.Meta["hl7_mllp_framed"] != true {
		t.Errorf("hl7_mllp_framed not set")
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "hl7-probe") {
		t.Errorf("anomalies = %v; want hl7-probe", anoms)
	}
}

func TestHL7PatientQueryFlagged(t *testing.T) {
	msg := "MSH|^~\\&|SCANNER|X|HIS|MAIN|20260101000000||QBP^Q22|Q1|P|2.5\r"
	res, _ := runDevsvc(t, &hl7{}, mllp(msg))
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "hl7-patient-query") {
		t.Errorf("anomalies = %v; want hl7-patient-query", anoms)
	}
}

func TestHL7InjectionFlagged(t *testing.T) {
	msg := "MSH|^~\\&|A|B|C|D|20260101000000||ADT^A01|I1|P|2.5\r" +
		"PID|1||../../etc/passwd||X\r"
	res, _ := runDevsvc(t, &hl7{}, mllp(msg))
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "hl7-injection") {
		t.Errorf("anomalies = %v; want hl7-injection", anoms)
	}
}

func TestHL7MalformedStillAnswers(t *testing.T) {
	res, reply := runDevsvc(t, &hl7{}, mllp("not an hl7 message"))
	if len(reply) == 0 || reply[0] != mllpVT {
		t.Errorf("malformed input should still get an MLLP reply: %v", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "hl7-malformed") {
		t.Errorf("anomalies = %v; want hl7-malformed", anoms)
	}
}

// --- DICOM ---------------------------------------------------------------

func dcmPad16(s string) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
	return b
}

func dcmSub(t byte, body []byte) []byte {
	out := []byte{t, 0x00}
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// buildAssocRQ constructs a minimal A-ASSOCIATE-RQ. withPC adds a presentation
// context (abstract syntax + transfer syntax); when false the request carries
// only the application context + user info (so the handler rejects it).
func buildAssocRQ(called, calling string, withPC bool) []byte {
	var variable []byte
	variable = append(variable, dcmSub(0x10, []byte("1.2.840.10008.3.1.1.1"))...)
	if withPC {
		pc := []byte{0x01, 0x00, 0x00, 0x00}
		pc = append(pc, dcmSub(0x30, []byte("1.2.840.10008.1.1"))...) // abstract syntax
		pc = append(pc, dcmSub(0x40, []byte("1.2.840.10008.1.2"))...) // transfer syntax (implicit VR LE)
		variable = append(variable, dcmSub(0x20, pc)...)
	}
	variable = append(variable, dcmSub(0x50, dcmSub(0x51, []byte{0, 0, 0x40, 0}))...)

	payload := make([]byte, 68)
	payload[1] = 0x01 // protocol version
	copy(payload[4:20], dcmPad16(called))
	copy(payload[20:36], dcmPad16(calling))
	payload = append(payload, variable...)

	out := []byte{dcmAssocRQ, 0x00}
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

// buildPData wraps a DICOM Command Field (implicit VR LE) in a P-DATA-TF PDU.
func buildPData(cmd uint16) []byte {
	elem := []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00}
	elem = binary.LittleEndian.AppendUint16(elem, cmd)
	pdv := append([]byte{0x01, 0x03}, elem...) // pcid=1, control=command+last
	out := []byte{dcmPData, 0x00}
	out = binary.BigEndian.AppendUint32(out, uint32(4+len(pdv)))
	out = binary.BigEndian.AppendUint32(out, uint32(len(pdv)))
	return append(out, pdv...)
}

func TestDICOMAssociateAccepted(t *testing.T) {
	res, reply := runDevsvc(t, &dicom{}, buildAssocRQ("HONEYPACS", "WORKSTATION01", true))
	if len(reply) < 1 || reply[0] != dcmAssocAC {
		t.Fatalf("reply PDU type = %v; want A-ASSOCIATE-AC (0x02)", reply)
	}
	if res.Meta["dicom_called_ae"] != "HONEYPACS" || res.Meta["dicom_calling_ae"] != "WORKSTATION01" {
		t.Errorf("AE titles wrong: %+v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "dicom-associate") {
		t.Errorf("anomalies = %v; want dicom-associate", anoms)
	}
	if containsStr(anoms, "dicom-ae-scan") {
		t.Errorf("legit calling AE should not be flagged as scan: %v", anoms)
	}
}

func TestDICOMAEScanFlagged(t *testing.T) {
	res, _ := runDevsvc(t, &dicom{}, buildAssocRQ("ORTHANC", "FINDSCU", true))
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "dicom-ae-scan") {
		t.Errorf("anomalies = %v; want dicom-ae-scan", anoms)
	}
}

func TestDICOMRejectWithoutPresentationContext(t *testing.T) {
	_, reply := runDevsvc(t, &dicom{}, buildAssocRQ("PACS", "WS", false))
	if len(reply) < 1 || reply[0] != dcmAssocRJ {
		t.Fatalf("reply PDU type = %v; want A-ASSOCIATE-RJ (0x03)", reply)
	}
}

func TestDICOMNonStandardPDU(t *testing.T) {
	// A P-DATA-TF (0x04) as the opening PDU is not a valid association start.
	res, _ := runDevsvc(t, &dicom{}, []byte{dcmPData, 0x00, 0, 0, 0, 2, 0, 0})
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "dicom-nonstandard-pdu") {
		t.Errorf("anomalies = %v; want dicom-nonstandard-pdu", anoms)
	}
}

func TestDICOMCFindCaptured(t *testing.T) {
	res := dicomExchange(t, buildAssocRQ("ORTHANC", "WS01", true), buildPData(0x0020))
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "dicom-cfind") {
		t.Errorf("anomalies = %v; want dicom-cfind", anoms)
	}
	if res.Meta["dicom_dimse_command"] != 0x0020 {
		t.Errorf("dicom_dimse_command = %v; want 32 (0x0020)", res.Meta["dicom_dimse_command"])
	}
}

// dicomExchange drives a two-step association: send the A-ASSOCIATE-RQ, read
// the AC, then send a follow-up PDU and collect the handler's Result.
func dicomExchange(t *testing.T, rq, follow []byte) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "dicom", ReadTimeout: time.Second}
	done := make(chan Result, 1)
	go func() {
		r, _ := (&dicom{}).Handle(context.Background(), server, cfg)
		done <- r
	}()
	_, _ = client.Write(rq)
	buf := make([]byte, 1024)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf) // drain the AC so the handler's AC write unblocks
	_, _ = client.Write(follow)
	client.Close()
	select {
	case r := <-done:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("dicom handler did not return")
		return Result{}
	}
}

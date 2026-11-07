package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Additional medical / medtech protocol decoys beyond HL7-MLLP + DICOM: the
// lab-instrument and point-of-care line protocols, and the modern FHIR REST
// API. Each captures the request + intent (PHI access, device control,
// injection) and answers just enough to look like a live clinical endpoint.
// Nothing is stored or acted on — the "patient" data is never real.

// --- ASTM E1381/E1394 (LIS ↔ lab analyzer line protocol, TCP) ---------------
//
// Clinical lab instruments (chemistry/haematology analyzers) talk to the LIS
// over ASTM: an ENQ (0x05) to open, then frames STX <seq> <record> ETX <chk>
// CR LF, EOT (0x04) to close. Records are pipe/caret-delimited and begin with a
// type letter — H (header), P (patient), O (order), R (result), C (comment),
// L (terminator). Patient/order/result records are raw PHI, so an endpoint
// reachable off the lab VLAN is a disclosure target.
type astm struct{}

func (a *astm) Name() string { return "astm" }

func (a *astm) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 16384)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "astm-probe")
	res.Meta["medtech_product"] = "ASTM E1381/1394 lab instrument / LIS"
	setIfEmpty(res.Meta, "intent", "ASTM lab-instrument / LIS access — clinical result records (PHI)")
	if len(got) == 0 {
		// Prompt a real analyzer to begin: answer ENQ with ACK.
		_, _ = conn.Write([]byte{0x06})
		res.BannerSent = "astm-ack"
		return res, nil
	}
	s := string(got)
	if got[0] == 0x05 { // ENQ — establishment phase
		res.Meta["astm_phase"] = "ENQ"
	}
	// Classify by the first record type letter (after any STX/sequence).
	rec := strings.TrimLeft(s, "\x05\x02 0123456789")
	switch {
	case strings.HasPrefix(rec, "H|") || strings.Contains(s, "H|\\^&"):
		res.Meta["astm_record"] = "header"
	case strings.HasPrefix(rec, "P|"):
		res.Meta["astm_record"] = "patient"
		res.Meta["intent"] = "ASTM patient record — PHI disclosure"
		noteCWE(&res, "CWE-200")
	case strings.HasPrefix(rec, "O|"):
		res.Meta["astm_record"] = "order"
	case strings.HasPrefix(rec, "R|"):
		res.Meta["astm_record"] = "result"
		res.Meta["intent"] = "ASTM result record — clinical result data (PHI)"
		noteCWE(&res, "CWE-200")
	}
	res.Meta["astm_data"] = safe.SanitizeForLog(clipStr(s, 256))
	if astmLooksInjected(s) {
		flagAnomaly(&res, "astm-injection")
	}
	_, _ = conn.Write([]byte{0x06}) // ACK the frame so the sender continues
	res.BannerSent = "astm-ack"
	return res, nil
}

// astmLooksInjected flags path-traversal / shell / SQL metacharacters smuggled
// into ASTM fields (analyzers never send these).
func astmLooksInjected(s string) bool {
	for _, n := range []string{"../", "..\\", "';", "<script", "$(", "|sh", "/etc/passwd"} {
		if strings.Contains(strings.ToLower(s), n) {
			return true
		}
	}
	return false
}

// --- POCT1-A (point-of-care testing ↔ data manager, TCP XML) ----------------
//
// POCT1-A carries glucose meters, blood-gas and other bedside devices to a
// POC data manager as XML messages framed by a leading 0x0B / <?xml ...?>. The
// device sends <HELLO.../>, the manager <ACK.../>, then OBS (observation) and
// patient messages flow — again raw PHI.
type poct1 struct{}

func (p *poct1) Name() string { return "poct1" }

func (p *poct1) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 16384)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "poct1-probe")
	res.Meta["medtech_product"] = "POCT1-A point-of-care data manager"
	setIfEmpty(res.Meta, "intent", "POCT1-A point-of-care testing device access — bedside clinical observations (PHI)")
	s := string(got)
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "<hello"):
		res.Meta["poct1_msg"] = "HELLO"
	case strings.Contains(lower, "<obs") || strings.Contains(lower, "observation"):
		res.Meta["poct1_msg"] = "OBS"
		res.Meta["intent"] = "POCT1-A observation message — clinical result data (PHI)"
		noteCWE(&res, "CWE-200")
	case strings.Contains(lower, "<pt") || strings.Contains(lower, "patient"):
		res.Meta["poct1_msg"] = "patient"
		noteCWE(&res, "CWE-200")
	case strings.Contains(lower, "<eot"):
		res.Meta["poct1_msg"] = "EOT"
	}
	if len(got) > 0 {
		res.Meta["poct1_data"] = safe.SanitizeForLog(clipStr(s, 256))
	}
	// Answer a device HELLO with an ACK so it keeps talking.
	ack := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<ACK xmlns=\"urn:astm-org:POCT1-A\"/>\r\n"
	_, _ = conn.Write([]byte(ack))
	res.BannerSent = "poct1-ack"
	return res, nil
}

// --- HL7 FHIR (RESTful clinical API, TCP/HTTP) ------------------------------
//
// FHIR is the modern HL7 standard: a REST/JSON (or XML) API exposing clinical
// data as resources (Patient, Observation, Encounter, MedicationRequest, …).
// Internet-exposed FHIR servers leak PHI directly; the conformance document is
// at /metadata. We answer a believable CapabilityStatement, flag resource reads
// as PHI access, and flag writes (POST/PUT/DELETE) as record tampering.
type fhir struct{}

func (f *fhir) Name() string { return "fhir" }

func (f *fhir) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 16384)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "fhir-probe")
	res.Meta["medtech_product"] = "HL7 FHIR server"
	setIfEmpty(res.Meta, "intent", "HL7 FHIR API access — EHR/clinical data (patient records)")
	req := string(got)
	line := req
	if i := strings.IndexAny(req, "\r\n"); i >= 0 {
		line = req[:i]
	}
	if line != "" {
		res.Meta["http_request"] = safe.SanitizeForLog(clipStr(line, 256))
	}
	method := strings.ToUpper(extractMethod(line))
	path := extractPath(line)
	lower := strings.ToLower(path)
	status := "200 OK"
	body := `{"resourceType":"CapabilityStatement","status":"active","fhirVersion":"4.0.1","format":["json","xml"],"rest":[{"mode":"server"}]}`
	switch {
	case method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH":
		flagAnomaly(&res, "fhir-write")
		res.Meta["intent"] = "FHIR " + method + " — creating/altering/deleting a clinical record"
		noteCWE(&res, "CWE-306")
		status, body = "201 Created", `{"resourceType":"OperationOutcome","issue":[{"severity":"information","code":"informational"}]}`
	case strings.Contains(lower, "/patient"):
		res.Meta["fhir_resource"] = "Patient"
		res.Meta["intent"] = "FHIR Patient query — PHI disclosure"
		noteCWE(&res, "CWE-200")
		body = `{"resourceType":"Bundle","type":"searchset","total":0,"entry":[]}`
	case strings.Contains(lower, "/observation") || strings.Contains(lower, "/medicationrequest") || strings.Contains(lower, "/encounter"):
		res.Meta["fhir_resource"] = "clinical"
		res.Meta["intent"] = "FHIR clinical-resource query — PHI disclosure"
		noteCWE(&res, "CWE-200")
		body = `{"resourceType":"Bundle","type":"searchset","total":0,"entry":[]}`
	case strings.Contains(lower, "/metadata"):
		res.Meta["fhir_resource"] = "metadata"
	}
	resp := "HTTP/1.1 " + status + "\r\nContent-Type: application/fhir+json\r\nServer: HAPI FHIR Server\r\nContent-Length: " +
		itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	_, _ = conn.Write([]byte(resp))
	res.BannerSent = "fhir-response"
	return res, nil
}

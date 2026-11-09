package handler

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// driveHistorian runs a historian handler against a client message and returns
// the captured Result plus the bytes the handler wrote back.
func driveHistorian(t *testing.T, h *historian, msg []byte) (Result, []byte) {
	t.Helper()
	client, server := pipePair(t)
	// Short server read timeout so a bare connect greets quickly; the client
	// waits longer so it always sees the greeting.
	cfg := config.Listener{Handler: h.proto, ReadTimeout: 200 * time.Millisecond}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = h.Handle(context.Background(), server, cfg) }()
	if len(msg) > 0 {
		_, _ = client.Write(msg)
	}
	out := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(out)
	client.Close()
	<-done
	return res, out[:n]
}

func TestHistorianClassifiesAndIdentifies(t *testing.T) {
	h := &historian{
		proto: "proficy_historian", label: "GE Proficy Historian Data Archiver",
		version: "Historian 2023 (10.5)", marker: []byte{'G', 'E', 'H', 'I'},
	}

	// A length-prefixed (big-endian) opening message that leaks an app + user
	// string the way these SDK handshakes do.
	body := []byte("ProficyClient\x00operator\x00")
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, uint32(len(body)))
	msg = append(msg, body...)

	res, reply := driveHistorian(t, h, msg)

	if res.Meta["historian_protocol"] != "proficy_historian" {
		t.Errorf("protocol = %v", res.Meta["historian_protocol"])
	}
	if res.Meta["framing"] != "length-prefixed-be" {
		t.Errorf("framing = %v; want length-prefixed-be", res.Meta["framing"])
	}
	toks, _ := res.Meta["ascii_tokens"].([]string)
	if !containsStr(toks, "ProficyClient") || !containsStr(toks, "operator") {
		t.Errorf("ascii tokens missing leaked strings: %v", toks)
	}
	if !hasAnom(res, "ics-historian-access") || !hasAnom(res, "proficy_historian-probe") {
		t.Errorf("expected historian anomalies: %v", res.Meta["anomalies"])
	}
	if res.Meta["historian_version"] != "Historian 2023 (10.5)" {
		t.Errorf("version = %v", res.Meta["historian_version"])
	}
	// The reply must carry the marker + the product label a scanner greps for.
	if len(reply) < 6 || string(reply[:4]) != "GEHI" {
		t.Fatalf("reply missing marker: % x", reply)
	}
	if !containsSub(reply, "GE Proficy Historian") {
		t.Errorf("reply missing product label: %q", reply)
	}
}

func TestHistorianBareConnect(t *testing.T) {
	h := &historian{
		proto: "canary_historian", label: "Canary Labs Historian (Sender)",
		version: "Canary 23.3", marker: []byte{'C', 'N', 'R', 'Y'},
	}
	res, reply := driveHistorian(t, h, nil)
	if res.Meta["read_err"] != "no data" {
		t.Errorf("bare connect should record read_err: %v", res.Meta)
	}
	// Still greets so a scanner records a live service.
	if len(reply) < 4 || string(reply[:4]) != "CNRY" {
		t.Errorf("bare connect not greeted: % x", reply)
	}
	if !hasAnom(res, "ics-historian-access") {
		t.Errorf("historian access not flagged on bare connect: %v", res.Meta["anomalies"])
	}
}

// TestHistorianOperationClassification: the operation is classified from the
// cleartext verbs these SDKs leak, and the control-relevant ones raise a marker.
func TestHistorianOperationClassification(t *testing.T) {
	for _, c := range []struct{ name, data, wantOp string }{
		{"read", "piar getarchive tag=SINUSOID", "read archive data"},
		{"write", "PutSnapshot point=FIC101 value=42", "write data"},
		{"lookup", "FindPoint mask=*", "tag/point lookup"},
		{"auth", "PITrust login=svc", "authentication"},
		{"plain", "ProficyClient\x00operator\x00", "connection / handshake"},
		{"empty", "", ""},
	} {
		if op, _ := historianOperation([]byte(c.data)); op != c.wantOp {
			t.Errorf("%s: historianOperation = %q; want %q", c.name, op, c.wantOp)
		}
	}

	// End-to-end: a leaked read verb drives historian_operation + the marker
	// through the handler.
	h := &historian{proto: "aspen_ip21", label: "AspenTech InfoPlus.21", version: "V14", marker: []byte{'I', 'P', '2', '1'}}
	body := []byte("SQLplus select getarchive from ip_analogdef\x00")
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, uint32(len(body)))
	msg = append(msg, body...)
	res, _ := driveHistorian(t, h, msg)
	if res.Meta["historian_operation"] != "read archive data" {
		t.Errorf("historian_operation = %v; want read archive data", res.Meta["historian_operation"])
	}
	if !hasAnom(res, "ics-process-data-access") {
		t.Errorf("read not flagged as process-data access: %v", res.Meta["anomalies"])
	}
}

func containsSub(b []byte, sub string) bool {
	return len(sub) == 0 || indexOf(b, sub) >= 0
}

func indexOf(b []byte, sub string) int {
	s := []byte(sub)
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == sub {
			return i
		}
	}
	return -1
}

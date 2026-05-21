package handler

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// runIPP drives the ipp handler with one IPP-over-HTTP request (op + an
// optional raw attribute blob) and returns the captured Result. The
// handler's HTTP response is drained so it never blocks on write.
func runIPP(t *testing.T, op uint16, extra string) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ipp", ReadBytes: 65535, ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&ipp{}).Handle(context.Background(), server, cfg); resC <- r }()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	body := []byte{0x02, 0x00, byte(op >> 8), byte(op), 0, 0, 0, 1}
	body = append(body, []byte(extra)...)
	body = append(body, 0x03) // end-of-attributes
	req := "POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n"
	_, _ = client.Write(append([]byte(req), body...))
	_ = client.Close()
	return <-resC
}

func TestIPPCUPSFoomaticRCE(t *testing.T) {
	// op Print-Job (0x0002) carrying the foomatic-rip RCE primitive.
	r := runIPP(t, 0x0002, "\x01G\x00\x00\x00\x00FoomaticRIPCommandLine=echo pwned > /tmp/x")
	if !containsStr(r.CVEHits, "CVE-2024-47177") {
		t.Errorf("CUPS foomatic CVE not detected: %v", r.CVEHits)
	}
	if a := pjlAnoms(r); !containsStr(a, "printer-cups-rce") {
		t.Errorf("printer-cups-rce not flagged: %v", a)
	}
}

func TestIPPAdminOp(t *testing.T) {
	// CUPS-Add-Modify-Printer (0x4003) — the op that plants a malicious
	// printer/PPD in the CUPS chain.
	r := runIPP(t, 0x4003, "")
	if r.Meta["ipp_op_name"] != "CUPS-Add-Modify-Printer" {
		t.Errorf("op name = %v", r.Meta["ipp_op_name"])
	}
	if a := pjlAnoms(r); !containsStr(a, "printer-ipp-admin-op") {
		t.Errorf("admin op not flagged: %v", a)
	}
}

func TestIPPCmdInjection(t *testing.T) {
	r := runIPP(t, 0x4003, "device-uri=ipp://x/`touch /tmp/p`;id")
	if a := pjlAnoms(r); !containsStr(a, "printer-ipp-cmd-injection") {
		t.Errorf("command injection not flagged: %v", a)
	}
}

func TestIPPBenignNoFalsePositive(t *testing.T) {
	// A plain Get-Printer-Attributes must not trip any printer-* anomaly.
	r := runIPP(t, 0x000B, "")
	for _, a := range pjlAnoms(r) {
		if len(a) >= 8 && a[:8] == "printer-" {
			t.Errorf("benign IPP query flagged %q", a)
		}
	}
	if len(r.CVEHits) != 0 {
		t.Errorf("benign IPP query produced CVE hits: %v", r.CVEHits)
	}
}

func TestIPPArchetypeIdentity(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ipp", ReadBytes: 65535, ReadTimeout: 2 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&ipp{arch: archetype.Lookup("xerox-versalink")}).Handle(context.Background(), server, cfg)
	}()
	body := []byte{0x02, 0x00, 0x00, 0x0B, 0, 0, 0, 1, 0x03}
	req := "POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n"
	_, _ = client.Write(append([]byte(req), body...))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done
	resp := string(buf[:n])
	if !strings.Contains(resp, "Xerox") {
		t.Errorf("IPP reply did not use the bound archetype identity: %q", resp)
	}
	// Richer attribute set the emulation now advertises.
	if !strings.Contains(resp, "marker-levels") || !strings.Contains(resp, "document-format-supported") {
		t.Errorf("IPP reply missing richer attributes: %q", resp)
	}
}

// runLPD drives the lpd handler with one byte slice, draining the daemon's
// 0x00 acks so it never blocks.
func runLPD(t *testing.T, in []byte) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "lpd", ReadBytes: 8192, ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&lpd{}).Handle(context.Background(), server, cfg); resC <- r }()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	_, _ = client.Write(in)
	_ = client.Close()
	return <-resC
}

func TestLPDQueueInjection(t *testing.T) {
	// Receive-job (0x02) with shell metacharacters in the queue name.
	r := runLPD(t, append([]byte{0x02}, []byte("lp;id|cat\n")...))
	a := pjlAnoms(r)
	if !containsStr(a, "printer-lpd-command") {
		t.Errorf("lpd command not flagged: %v", a)
	}
	if !containsStr(a, "printer-lpd-injection") {
		t.Errorf("queue injection not flagged: %v", a)
	}
}

func TestLPDControlFileInjection(t *testing.T) {
	// Command line + batched control file with an injectable host field.
	in := append([]byte{0x02}, []byte("lp\nHevil`id`\nProot;rm -rf /\nfdfA001\n")...)
	r := runLPD(t, in)
	if a := pjlAnoms(r); !containsStr(a, "printer-lpd-injection") {
		t.Errorf("control-file injection not flagged: %v", a)
	}
}

func TestLPDOverflow(t *testing.T) {
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'A'
	}
	in := append([]byte{0x03}, append(long, '\n')...)
	r := runLPD(t, in)
	if a := pjlAnoms(r); !containsStr(a, "printer-lpd-overflow") {
		t.Errorf("overlong queue not flagged: %v", a)
	}
}

func TestLPDBenign(t *testing.T) {
	// queue-state-long (0x04) for a normal queue: command flagged, but no
	// injection/overflow false positives.
	r := runLPD(t, append([]byte{0x04}, []byte("lp\n")...))
	a := pjlAnoms(r)
	if !containsStr(a, "printer-lpd-command") {
		t.Errorf("lpd command not flagged: %v", a)
	}
	if containsStr(a, "printer-lpd-injection") || containsStr(a, "printer-lpd-overflow") {
		t.Errorf("benign lpd request false-positived: %v", a)
	}
	if r.Meta["lpd_command"] != "queue-state-long" {
		t.Errorf("command name = %v", r.Meta["lpd_command"])
	}
}

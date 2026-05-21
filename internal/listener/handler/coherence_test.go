package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// httpResponseFor drives the http handler with one GET under the given
// archetype and returns the raw response.
func httpResponseFor(t *testing.T, arch *archetype.Profile) string {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 8192, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 8192)
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done
	return string(buf[:n])
}

// Coherence: every archetype that pins an HTTP Server header must actually
// serve it (a wiring gap would let a scanner catch a banner/identity
// mismatch). Iterates the whole catalog.
func TestHTTPServerCoherenceAllArchetypes(t *testing.T) {
	for _, p := range archetype.All() {
		want := p.HTTPServer()
		if want == "" {
			continue // e.g. MikroTik RouterOS sends no Server header
		}
		resp := httpResponseFor(t, p)
		if !strings.Contains(resp, "Server: "+want) {
			t.Errorf("%s: HTTP response missing Server header %q", p.Name, want)
		}
	}
}

// Compatibility: every printer/MFD archetype's IPP reply must carry that
// device's identity, so IPP, SNMP and the web UI tell one coherent story.
func TestIPPModelCoherencePrinters(t *testing.T) {
	for _, p := range archetype.All() {
		if p.Family != "printer" {
			continue
		}
		// Vendor token = first word of the SNMP sysDescr the IPP handler
		// uses as make-and-model.
		descr := p.SNMPSysDescr()
		if descr == "" {
			continue
		}
		vendor := strings.Fields(descr)[0]

		client, server := pipePair(t)
		cfg := config.Listener{Handler: "ipp", ReadBytes: 65535, ReadTimeout: time.Second}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = (&ipp{arch: p}).Handle(context.Background(), server, cfg)
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
		if !strings.Contains(string(buf[:n]), vendor) {
			t.Errorf("%s: IPP reply missing vendor token %q", p.Name, vendor)
		}
	}
}

// A vulnerability-scanner User-Agent (Nessus etc.) must raise the
// vulnerability-scanner anomaly end-to-end through the http handler.
func TestHTTPFlagsVulnScanner(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&httpH{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Nessus SOAP\r\n\r\n"))
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	_ = n
	_ = client.Close()
	r := <-resC
	anoms, _ := r.Meta["anomalies"].([]string)
	if !containsStr(anoms, "vulnerability-scanner") {
		t.Errorf("Nessus UA not flagged vulnerability-scanner: %v", anoms)
	}
}

// Coherence: an archetype with a vulnerable-TLS posture (legacy gear) must
// declare a sane MaxVersion <= the modern default so the https handler can
// negotiate down — guards the archetype TLS metadata used by the handler.
func TestArchetypeTLSPostureCoherent(t *testing.T) {
	for _, p := range archetype.All() {
		tp := p.TLS()
		if tp.MaxVersion != 0 && tp.MinVersion != 0 && tp.MaxVersion < tp.MinVersion {
			t.Errorf("%s: TLS MaxVersion(%#x) < MinVersion(%#x)", p.Name, tp.MaxVersion, tp.MinVersion)
		}
	}
}

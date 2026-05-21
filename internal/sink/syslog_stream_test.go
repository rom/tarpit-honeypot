package sink

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

func sampleEvent() *event.Event {
	return &event.Event{
		ID: "e", RuleID: "scan:port", Severity: event.SeverityCritical,
		Source: event.Endpoint{IP: "1.2.3.4"}, Time: time.Now(),
	}
}

// assertSyslogFrame checks an RFC 6587 octet-counted RFC 5424 frame:
// "<LEN> <PRI>1 ...". critical+daemon => PRI 26.
func assertSyslogFrame(t *testing.T, got string) {
	t.Helper()
	if got == "" {
		t.Fatal("no frame received")
	}
	if got[0] < '0' || got[0] > '9' {
		t.Errorf("frame not octet-counted (no length prefix): %q", got)
	}
	sp := strings.IndexByte(got, ' ')
	if sp < 0 || !strings.HasPrefix(got[sp+1:], "<26>1 ") {
		t.Errorf("missing RFC5424 header with PRI 26: %q", got)
	}
}

func TestStreamSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recv := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8192)
		n, _ := c.Read(buf)
		recv <- string(buf[:n])
	}()

	f, _ := format.Get("json")
	s, err := newSyslog(config.Channel{ID: "s", Network: "tcp", Address: ln.Addr().String(), Tag: "tp"}, f)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-recv:
		assertSyslogFrame(t, got)
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog frame received over tcp")
	}
}

func TestStreamSyslogTLS(t *testing.T) {
	cert := selfSignedCert(t)
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(tcpLn, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer ln.Close()
	recv := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8192)
		n, _ := c.Read(buf)
		recv <- string(buf[:n])
	}()

	f, _ := format.Get("json")
	s, err := newSyslog(config.Channel{
		ID: "s", Network: "tls", Address: ln.Addr().String(), Tag: "tp",
		TLSInsecure: true,
	}, f)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-recv:
		assertSyslogFrame(t, got)
	case <-time.After(3 * time.Second):
		t.Fatal("no syslog frame received over tls")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

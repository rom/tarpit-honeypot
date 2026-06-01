package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// startTestTLS spins a throwaway TLS server that accepts a handshake and
// immediately closes, returning its address.
func startTestTLS(t *testing.T) string {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				c.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestJARMProbeProducesFingerprint(t *testing.T) {
	addr := startTestTLS(t)
	probes := make([]fingerprint.JARMProbe, len(jarmProbeConfigs))
	responded := 0
	for i, pc := range jarmProbeConfigs {
		probes[i] = runJARMProbe(addr, "", pc, 3*time.Second)
		if probes[i].Responded {
			responded++
		}
	}
	if responded == 0 {
		t.Fatal("no JARM probe completed a handshake against the test server")
	}
	fp := fingerprint.JARM(probes)
	if len(fp) != 62 {
		t.Errorf("JARM fingerprint = %q (len %d), want 62 chars", fp, len(fp))
	}
}

func TestJARMProbeUnreachableIsNotResponded(t *testing.T) {
	// An address with nothing listening: every probe must report Responded=false
	// rather than hang or panic.
	closed := func() string {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		a := l.Addr().String()
		l.Close()
		return a
	}()
	p := runJARMProbe(closed, "", jarmProbeConfigs[0], 500*time.Millisecond)
	if p.Responded {
		t.Errorf("probe against a closed port should not be Responded")
	}
}

func TestCmdJARMRejectsBadTarget(t *testing.T) {
	if err := cmdJARM([]string{"not-a-host-port"}); err == nil {
		t.Error("expected error for a target without host:port")
	}
	if err := cmdJARM(nil); err == nil {
		t.Error("expected usage error with no target")
	}
}

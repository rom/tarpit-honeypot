package fingerprint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
)

func TestJA4SSH(t *testing.T) {
	s := SSHSample{
		ClientLens: []int{36, 36, 36, 44},
		ServerLens: []int{52, 52},
		Acks:       3,
	}
	got := JA4SSH(s)
	want := "c36s52_4_2_3" // modal client 36, modal server 52, 4 c-pkts, 2 s-pkts, 3 acks
	if got != want {
		t.Errorf("JA4SSH = %q, want %q", got, want)
	}
	if JA4SSH(SSHSample{}) != "" {
		t.Errorf("empty sample should yield empty JA4SSH")
	}
}

func TestModeInt(t *testing.T) {
	if got := modeInt([]int{1, 2, 2, 3}); got != 2 {
		t.Errorf("modeInt = %d, want 2", got)
	}
	// Tie → lowest value wins.
	if got := modeInt([]int{5, 5, 9, 9}); got != 5 {
		t.Errorf("modeInt tie = %d, want 5", got)
	}
	if got := modeInt(nil); got != 0 {
		t.Errorf("modeInt(nil) = %d, want 0", got)
	}
}

func TestJA4L(t *testing.T) {
	if got := JA4L(4200, 64); got != "4200_64" {
		t.Errorf("JA4L = %q, want 4200_64", got)
	}
	if JA4L(0, 0) != "" {
		t.Errorf("JA4L with no signal should be empty")
	}
	// TTL alone is still a signal.
	if JA4L(0, 128) != "0_128" {
		t.Errorf("JA4L ttl-only = %q, want 0_128", JA4L(0, 128))
	}
}

func TestJA4XStableAndStructural(t *testing.T) {
	c1 := makeTestCert(t, "example.com", "Acme")
	c2 := makeTestCert(t, "other.net", "Acme") // same RDN structure, different values
	a := JA4X(c1)
	b := JA4X(c2)
	if a == "" {
		t.Fatal("JA4X returned empty for a real cert")
	}
	if len(strings.Split(a, "_")) != 3 {
		t.Errorf("JA4X = %q, want three underscore segments", a)
	}
	// Same RDN component set/order + same extensions → identical issuer/subject
	// structure hashes even though CN/values differ. (CN is the same OID, so the
	// subject *structure* matches.)
	if a != b {
		t.Errorf("JA4X should cluster certs of identical RDN/ext structure: %q vs %q", a, b)
	}
	if JA4X(nil) != "" {
		t.Errorf("JA4X(nil) should be empty")
	}
}

func makeTestCert(t *testing.T, cn, org string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		Issuer:       pkix.Name{CommonName: cn, Organization: []string{org}},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

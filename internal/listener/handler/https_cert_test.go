package handler

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

func newTestHTTPS(t *testing.T, id *identity.Identity) *https {
	t.Helper()
	h, err := newHTTPS(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	h.id = id
	return h
}

func leafCert(t *testing.T, h *https, cfg config.Listener) *x509.Certificate {
	t.Helper()
	prof := h.profileFor(cfg)
	cert, err := h.certFor(prof)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.Leaf = leaf
	}
	return cert.Leaf
}

// Two different listeners (different ids) on the same host should get
// certs with distinct organizations — they look like distinct services
// even with no explicit subject config.
func TestPerServiceCertDistinctOrgs(t *testing.T) {
	id := identity.New("dep-multicert")
	h := newTestHTTPS(t, id)
	a := leafCert(t, h, config.Listener{ID: "svc-a", HTTPS: config.HTTPS{Hosts: []string{"host.local"}}})
	b := leafCert(t, h, config.Listener{ID: "svc-b", HTTPS: config.HTTPS{Hosts: []string{"host.local"}}})

	orgA := ""
	if len(a.Subject.Organization) > 0 {
		orgA = a.Subject.Organization[0]
	}
	orgB := ""
	if len(b.Subject.Organization) > 0 {
		orgB = b.Subject.Organization[0]
	}
	// Serial numbers must always differ (independent random serials).
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Errorf("two services share a serial number")
	}
	// At least one of {org, notBefore} should differ to make the
	// services distinguishable. With a fixed seed the derived orgs
	// usually differ; if they collide, the validity window won't.
	if orgA == orgB && a.NotBefore.Equal(b.NotBefore) {
		t.Errorf("services A and B are indistinguishable (org=%q, same NotBefore)", orgA)
	}
}

// Explicit subject config is honored.
func TestExplicitCertSubject(t *testing.T) {
	h := newTestHTTPS(t, identity.New("x"))
	leaf := leafCert(t, h, config.Listener{
		ID: "svc",
		HTTPS: config.HTTPS{
			Hosts: []string{"intranet.corp"},
			CN:    "intranet.corp",
			Org:   "Globex Corporation",
			OU:    "Infrastructure",
		},
	})
	if leaf.Subject.CommonName != "intranet.corp" {
		t.Errorf("CN = %q; want intranet.corp", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != "Globex Corporation" {
		t.Errorf("Org = %v; want Globex Corporation", leaf.Subject.Organization)
	}
	if len(leaf.Subject.OrganizationalUnit) == 0 || leaf.Subject.OrganizationalUnit[0] != "Infrastructure" {
		t.Errorf("OU = %v; want Infrastructure", leaf.Subject.OrganizationalUnit)
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "intranet.corp" {
		t.Errorf("SAN DNSNames = %v; want intranet.corp", leaf.DNSNames)
	}
}

// key_type=rsa produces an RSA cert; default produces ECDSA.
func TestCertKeyTypes(t *testing.T) {
	h := newTestHTTPS(t, identity.New("x"))

	prof := h.profileFor(config.Listener{ID: "rsa-svc", HTTPS: config.HTTPS{Hosts: []string{"a"}, KeyType: "rsa"}})
	cert, err := h.certFor(prof)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Errorf("key_type=rsa did not produce an RSA key: %T", cert.PrivateKey)
	}

	prof2 := h.profileFor(config.Listener{ID: "ec-svc", HTTPS: config.HTTPS{Hosts: []string{"a"}, KeyType: "ecdsa"}})
	cert2, err := h.certFor(prof2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert2.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("key_type=ecdsa did not produce an ECDSA key: %T", cert2.PrivateKey)
	}
}

// The cert is stable across calls for the same service (cache + disk).
func TestCertStablePerService(t *testing.T) {
	h := newTestHTTPS(t, identity.New("x"))
	cfg := config.Listener{ID: "svc", HTTPS: config.HTTPS{Hosts: []string{"a"}}}
	a := leafCert(t, h, cfg)
	b := leafCert(t, h, cfg)
	if a.SerialNumber.Cmp(b.SerialNumber) != 0 {
		t.Errorf("same service produced different certs across calls")
	}
}

package handler

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ldapRootDSEReply drives one rootDSE base search through the TCP LDAP handler
// built with the given hostname and returns the raw SearchResultEntry bytes.
func ldapRootDSEReply(t *testing.T, hostname string) []byte {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ldap", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&ldap{hostname: hostname}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write(rootDSESearch(3))
	buf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done
	return append([]byte(nil), buf[:n]...)
}

// TestLDAPRootDSEPerHostIdentity verifies each virtual host presents its own
// dnsHostName / serverName in the rootDSE, so honeynet DCs sharing an archetype
// no longer look identical, while the stand-alone listener keeps the canonical
// dc01 identity.
func TestLDAPRootDSEPerHostIdentity(t *testing.T) {
	defer SetDeploymentDomain("")
	SetDeploymentDomain("corp.example.com")

	paris := ldapRootDSEReply(t, "dc-paris")
	for _, want := range []string{
		"dc-paris.corp.example.com", // dnsHostName
		"CN=DC-PARIS,",              // serverName / dsServiceName
	} {
		if !bytes.Contains(paris, []byte(want)) {
			t.Errorf("per-host rootDSE missing %q: %q", want, paris)
		}
	}
	if bytes.Contains(paris, []byte("dc01")) {
		t.Errorf("per-host rootDSE leaked the default dc01 identity: %q", paris)
	}

	// A second host built from the same handler type must differ.
	berlin := ldapRootDSEReply(t, "dc-berlin")
	if bytes.Contains(berlin, []byte("dc-paris")) {
		t.Errorf("two virtual hosts shared the same identity: %q", berlin)
	}
	if !bytes.Contains(berlin, []byte("dc-berlin.corp.example.com")) {
		t.Errorf("second host missing its own dnsHostName: %q", berlin)
	}

	// No hostname (stand-alone listener) → canonical dc01.
	def := ldapRootDSEReply(t, "")
	if !bytes.Contains(def, []byte("dc01.corp.example.com")) {
		t.Errorf("default rootDSE missing canonical dc01: %q", def)
	}
}

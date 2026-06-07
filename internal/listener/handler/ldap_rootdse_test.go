package handler

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// rootDSESearch builds an LDAPMessage: SearchRequest with an empty baseObject
// (rootDSE), base scope, requesting namingContexts.
func rootDSESearch(msgID byte) []byte {
	// SearchRequest [APP 3] body: baseObject "" + scope(0) + deref(0) +
	// sizeLimit(0) + timeLimit(0) + typesOnly(false) + filter present(objectClass=*)
	// + attrs. We only need an empty baseObject for isRootDSESearch.
	body := []byte{
		0x04, 0x00, // baseObject ""
		0x0a, 0x01, 0x00, // scope base
		0x0a, 0x01, 0x00, // derefAliases
		0x02, 0x01, 0x00, // sizeLimit
		0x02, 0x01, 0x00, // timeLimit
		0x01, 0x01, 0x00, // typesOnly
		0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's', // present filter
		0x30, 0x00, // attributes (empty)
	}
	op := append([]byte{0x63, byte(len(body))}, body...)
	msg := append([]byte{0x02, 0x01, msgID}, op...)
	return append([]byte{0x30, byte(len(msg))}, msg...)
}

func TestLDAPRootDSEDefaultNamingContext(t *testing.T) {
	defer SetDeploymentDomain("")
	SetDeploymentDomain("corp.example.com")
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ldap", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&ldap{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write(rootDSESearch(2))
	buf := make([]byte, 2048)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done
	out := buf[:n]
	if !bytes.Contains(out, []byte("defaultNamingContext")) {
		t.Errorf("rootDSE reply missing defaultNamingContext: % x", out)
	}
	if !bytes.Contains(out, []byte("DC=corp,DC=example,DC=com")) {
		t.Errorf("rootDSE reply missing the domain DN: %q", out)
	}
	if res.Meta["ldap_default_naming_context"] != "DC=corp,DC=example,DC=com" {
		t.Errorf("meta naming context = %v", res.Meta["ldap_default_naming_context"])
	}
}

func TestCLDAPRootDSEEmitted(t *testing.T) {
	defer SetDeploymentDomain("")
	SetDeploymentDomain("acme.lan")
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 389}
	res, _ := (&cldap{lim: newUDPReflectLimiter()}).Handle(context.Background(), rootDSESearch(5), src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 CLDAP reply; got %d", len(pc.written))
	}
	if !bytes.Contains(pc.written[0], []byte("DC=acme,DC=lan")) {
		t.Errorf("CLDAP reply missing domain DN: % x", pc.written[0])
	}
	if !hasAnom(res, "cldap-netlogon-probe") {
		t.Errorf("cldap probe not flagged: %v", res.Meta["anomalies"])
	}
}

func TestCLDAPAmplifierSuppression(t *testing.T) {
	defer SetReplyPolicy("full", false)
	defer SetDeploymentDomain("")
	SetDeploymentDomain("acme.lan")
	SetReplyPolicy("full", true) // suppress amplifier replies
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 389}
	res, _ := (&cldap{lim: newUDPReflectLimiter()}).Handle(context.Background(), rootDSESearch(5), src, pc, config.Listener{})
	if len(pc.written) != 0 {
		t.Errorf("amplifier suppression should drop the CLDAP reply; got %d", len(pc.written))
	}
	if res.Meta["amplifier_suppressed"] != true {
		t.Errorf("expected amplifier_suppressed meta: %v", res.Meta)
	}
}

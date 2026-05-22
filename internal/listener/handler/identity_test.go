package handler

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// kerberosReq frames a Kerberos TCP message (4-byte length + body).
func kerberosReq(body []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

func TestKerberosRoastingTells(t *testing.T) {
	// A TGS-REQ (tag 0x6C) whose etype list includes RC4-HMAC (02 01 17).
	body := []byte{0x6C, 0x10, 0x02, 0x01, 0x17, 0x00, 0x00}
	res := runConn(t, &kerberos{}, string(kerberosReq(body)))
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "kerberos-tgs-request") {
		t.Errorf("TGS-REQ not flagged: %v", anoms)
	}
	if !containsStr(anoms, "kerberos-rc4-requested") {
		t.Errorf("RC4 etype not flagged: %v", anoms)
	}
}

// ldapBind builds a minimal anonymous BindRequest LDAPMessage.
func ldapBind(msgID int) []byte {
	// BindRequest body: version INTEGER 3, name "" (0x04 00), simple-auth "" (0x80 00)
	bindBody := []byte{0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	op := append([]byte{0x60, byte(len(bindBody))}, bindBody...)
	body := append([]byte{0x02, 0x01, byte(msgID)}, op...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// ldapSearchSPN builds a SearchRequest LDAPMessage whose body contains the
// servicePrincipalName attribute string (the Kerberoasting recon filter).
func ldapSearchSPN(msgID int) []byte {
	attr := []byte("servicePrincipalName")
	// SearchRequest [APPLICATION 3] = 0x63; body just needs to carry the
	// attribute string for the byte-scan detector.
	op := append([]byte{0x63, byte(len(attr))}, attr...)
	body := append([]byte{0x02, 0x01, byte(msgID)}, op...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func TestLDAPSPNEnumeration(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	var res Result
	done := make(chan struct{})
	go func() { defer close(done); res, _ = (&ldap{}).Handle(context.Background(), server, cfg) }()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	// Anonymous bind (accepted), then an SPN search.
	_, _ = client.Write(ldapBind(1))
	_, _ = client.Write(ldapSearchSPN(2))
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ldap handler did not return")
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ldap-spn-enumeration") {
		t.Errorf("SPN search not flagged: %v anoms=%v", res.Meta["ops"], anoms)
	}
}

func TestDetectLDAPEnumeration(t *testing.T) {
	var res Result
	detectLDAPEnumeration(&res, []byte("...userAccountControl:1.2.840.113556.1.4.803:=4194304..."))
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ldap-asrep-roast-recon") {
		t.Errorf("AS-REP roast filter not flagged: %v", anoms)
	}
}

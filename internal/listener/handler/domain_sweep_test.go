package handler

import (
	"bytes"
	"testing"
)

func TestKRBErrorCarriesRealm(t *testing.T) {
	defer SetDeploymentDomain("")
	SetDeploymentDomain("corp.example.com")
	err := buildKRBError(25)
	// Realm is uppercased deployment domain as a GeneralString (tag 0x1B).
	if !bytes.Contains(err, append([]byte{0x1b, byte(len("CORP.EXAMPLE.COM"))}, []byte("CORP.EXAMPLE.COM")...)) {
		t.Errorf("KRB-ERROR missing realm CORP.EXAMPLE.COM: % x", err)
	}
	if err[0] != 0x7e {
		t.Errorf("KRB-ERROR outer tag = %#x; want 0x7e", err[0])
	}
}

func TestIPPPrinterURIUsesDomain(t *testing.T) {
	defer SetDeploymentDomain("")
	SetDeploymentDomain("corp.example.com")
	attrs := (&ipp{}).buildOK(1, "PRN", "Model X")
	if !bytes.Contains(attrs, []byte("printer.corp.example.com")) {
		t.Errorf("IPP printer-uri missing deployment domain: %q", attrs)
	}
	SetDeploymentDomain("")
	attrs = (&ipp{}).buildOK(1, "PRN", "Model X")
	if !bytes.Contains(attrs, []byte("printer.local")) {
		t.Errorf("IPP default should be printer.local: %q", attrs)
	}
}

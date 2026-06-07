package handler

import "testing"

func TestNetbiosDomain(t *testing.T) {
	defer SetDeploymentDomain("")
	SetDeploymentDomain("corp.example.com")
	if got := netbiosDomain("WORKGROUP"); got != "CORP" {
		t.Errorf("netbiosDomain = %q; want CORP", got)
	}
	if got := deploymentDomainOr("workgroup.local"); got != "corp.example.com" {
		t.Errorf("deploymentDomainOr = %q; want corp.example.com", got)
	}
	SetDeploymentDomain("")
	if got := netbiosDomain("WORKGROUP"); got != "WORKGROUP" {
		t.Errorf("unset netbiosDomain = %q; want fallback WORKGROUP", got)
	}
	// NTLM target info should now carry the derived NetBIOS domain.
	SetDeploymentDomain("acme.lan")
	ti := ntlmTargetInfo()
	if !containsBytes(ti, utf16le("ACME")) {
		t.Errorf("ntlmTargetInfo missing derived NetBIOS domain ACME")
	}
}

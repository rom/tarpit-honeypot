package archetype

import "testing"

func TestActiveDirectoryLookupAliases(t *testing.T) {
	for _, name := range []string{"active-directory", "Active Directory", "domain controller", "windows server 2019 dc"} {
		p := Lookup(name)
		if p == nil {
			t.Fatalf("archetype %q not found", name)
		}
		if p.Family != "windows" {
			t.Errorf("%q family = %q; want windows", name, p.Family)
		}
	}
}

func TestActiveDirectoryProtocolsAndPatchLevel(t *testing.T) {
	p := Lookup("active-directory")
	if p == nil {
		t.Fatal("active-directory archetype missing")
	}
	// The AD protocol mix must be present in default services.
	want := map[int]string{88: "kerberos", 389: "ldap", 445: "smb", 53: "dns", 5985: "winrm", 135: "dcerpc"}
	got := map[int]string{}
	for _, s := range p.DefaultServices() {
		got[s.Port] = s.Handler
	}
	for port, h := range want {
		if got[port] != h {
			t.Errorf("AD service %d = %q; want %q", port, got[port], h)
		}
	}
	if p.PatchLevel() == "" {
		t.Error("AD archetype should declare a patch level")
	}
	if len(p.VulnCVEs()) == 0 {
		t.Error("AD archetype should declare emulated CVEs")
	}
	// PowerShell prompt routes the shell to the PS emulator.
	if p.CLIPrompt() == "" || p.CLIPrompt()[:2] != "PS" {
		t.Errorf("AD cliPrompt = %q; want a PowerShell prompt", p.CLIPrompt())
	}
}

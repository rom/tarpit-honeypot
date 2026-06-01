package luaengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

// runScriptFile compiles a shipped script and runs it against input, returning
// the captured anomalies + meta.
func runScriptFile(t *testing.T, name, input string) ([]string, map[string]any, string) {
	t.Helper()
	path := filepath.Join("..", "..", "configs", "scripts", name)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	e, err := Compile(name, src, identity.New("seed-A"), "debian-12", "debian")
	if err != nil {
		t.Fatalf("%s compile: %v", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := e.Run(ctx, newConn(input), "9.9.9.9")
	if r.Meta["lua_error"] != nil {
		t.Fatalf("%s runtime error: %v", name, r.Meta["lua_error"])
	}
	return r.Anomalies, r.Meta, r.BannerSent
}

func hasFlag(anoms []string, want string) bool {
	for _, a := range anoms {
		if a == "lua:"+want {
			return true
		}
	}
	return false
}

func TestNewScriptsCaptureBehavior(t *testing.T) {
	cases := []struct {
		name, input, wantFlag string
	}{
		{"phpmyadmin.lua",
			"POST /index.php HTTP/1.1\r\nContent-Length: 41\r\n\r\npma_username=root&pma_password=Summer2025!",
			"phpmyadmin-login-attempt"},
		{"adminer.lua",
			"POST / HTTP/1.1\r\nContent-Length: 33\r\n\r\nauth[server]=169.254.169.254&x=1",
			"adminer-ssrf-attempt"},
		{"gitea.lua",
			"GET /api/v1/users/search HTTP/1.1\r\nHost: x\r\n\r\n",
			"gitea-api-probe"},
		{"ollama.lua",
			"POST /api/pull HTTP/1.1\r\nContent-Length: 30\r\n\r\n{\"model\":\"../../../etc/passwd\"}",
			"ollama-path-traversal"},
		{"zabbix.lua",
			"system.run[id]\n",
			"zabbix-command-exec"},
		{"rocketmq.lua",
			"\x00\x00\x00\x20{\"code\":25,\"updateBrokerConfig\":1}",
			"rocketmq-config-push"},
	}
	for _, c := range cases {
		anoms, _, banner := runScriptFile(t, c.name, c.input)
		if !hasFlag(anoms, c.wantFlag) {
			t.Errorf("%s: expected flag %q; anomalies=%v", c.name, c.wantFlag, anoms)
		}
		if banner == "" {
			t.Errorf("%s: expected some response banner", c.name)
		}
	}
}

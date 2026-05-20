package handler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

func TestLuaHandlerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "svc.lua")
	if err := os.WriteFile(script, []byte(`
		local p = personality()
		conn:write("220 " .. p.hostname .. " ready\r\n")
		local line = conn:readline()
		if line and line:find("HELP") then
			conn:write("commands: HELP QUIT\r\n")
			flag("help-probe")
		end
	`), 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := Get("lua", Deps{Identity: identity.New("seed"), Jitter: jitter.New(0, 0), Script: script})
	if err != nil {
		t.Fatalf("Get(lua): %v", err)
	}

	client, server := loopbackPair(t)
	go func() {
		// read the greeting, then send a command.
		buf := make([]byte, 256)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = client.Read(buf)
		_, _ = client.Write([]byte("HELP\r\n"))
	}()
	res, err := h.Handle(context.Background(), server, config.Listener{ReadTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.BannerSent, " ready") || !strings.Contains(res.BannerSent, "commands:") {
		t.Errorf("lua handler banner = %q", res.BannerSent)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	found := false
	for _, a := range anoms {
		if a == "lua:help-probe" {
			found = true
		}
	}
	if !found {
		t.Errorf("lua flag not promoted to anomalies: %v", anoms)
	}
}

func TestLuaHandlerMissingScript(t *testing.T) {
	if _, err := Get("lua", Deps{}); err == nil {
		t.Error("lua handler without a script should error")
	}
}

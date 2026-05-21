package luaengine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

type fakeConn struct {
	in  *bytes.Reader
	out *bytes.Buffer
}

func newConn(input string) *fakeConn {
	return &fakeConn{in: bytes.NewReader([]byte(input)), out: &bytes.Buffer{}}
}
func (c *fakeConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return c.out.Write(p) }

func compile(t *testing.T, src string) *Engine {
	t.Helper()
	e, err := Compile("t.lua", []byte(src), identity.New("seed-A"), "debian-12", "debian")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return e
}

func TestLuaWriteAndReadEcho(t *testing.T) {
	e := compile(t, `
		conn:write("hello\r\n")
		local line = conn:readline()
		if line then conn:write("you said: " .. line) end
		meta("got", line)
	`)
	r := e.Run(context.Background(), newConn("ping\n"), "1.2.3.4")
	if !strings.HasPrefix(r.BannerSent, "hello\r\n") || !strings.Contains(r.BannerSent, "you said: ping") {
		t.Errorf("banner = %q", r.BannerSent)
	}
	if string(r.Payload) != "ping\n" {
		t.Errorf("payload = %q; want captured input", r.Payload)
	}
	if r.Meta["got"] != "ping\n" {
		t.Errorf("meta got = %v", r.Meta["got"])
	}
}

func TestLuaPersonalityDeterministic(t *testing.T) {
	e := compile(t, `local p = personality(); conn:write(p.hostname .. "|" .. p.version)`)
	a := e.Run(context.Background(), newConn(""), "10.0.0.5").BannerSent
	b := e.Run(context.Background(), newConn(""), "10.0.0.5").BannerSent
	if a != b || a == "" {
		t.Errorf("personality not stable per host: %q vs %q", a, b)
	}
	c := e.Run(context.Background(), newConn(""), "10.0.0.99").BannerSent
	// Different hosts should (very likely) differ; at minimum it must
	// still be non-empty + stable for that host.
	if c == "" {
		t.Error("empty personality for second host")
	}
	if c2 := e.Run(context.Background(), newConn(""), "10.0.0.99").BannerSent; c2 != c {
		t.Errorf("second host persona not stable: %q vs %q", c, c2)
	}
}

func TestLuaRngDeterministic(t *testing.T) {
	e := compile(t, `conn:write(tostring(rng:int(1000000)))`)
	a := e.Run(context.Background(), newConn(""), "1.1.1.1").BannerSent
	b := e.Run(context.Background(), newConn(""), "1.1.1.1").BannerSent
	if a != b {
		t.Errorf("rng not deterministic per host: %q vs %q", a, b)
	}
}

func TestLuaHostStatePersists(t *testing.T) {
	e := compile(t, `
		local n = host:get("count") or 0
		n = n + 1
		host:set("count", n)
		conn:write("visit " .. tostring(n))
	`)
	if got := e.Run(context.Background(), newConn(""), "2.2.2.2").BannerSent; got != "visit 1" {
		t.Errorf("first visit = %q", got)
	}
	if got := e.Run(context.Background(), newConn(""), "2.2.2.2").BannerSent; got != "visit 2" {
		t.Errorf("second visit = %q; host state did not persist", got)
	}
	// A different host starts fresh.
	if got := e.Run(context.Background(), newConn(""), "3.3.3.3").BannerSent; got != "visit 1" {
		t.Errorf("different host should start fresh; got %q", got)
	}
}

func TestLuaWriteBudgetCaps(t *testing.T) {
	// A script trying to amplify must be capped at the write budget.
	e := compile(t, `for i=1,100000 do conn:write(string.rep("A", 4096)) end`)
	r := e.Run(context.Background(), newConn(""), "4.4.4.4")
	if len(r.BannerSent) > defaultWriteBudget {
		t.Errorf("write budget not enforced: wrote %d > %d", len(r.BannerSent), defaultWriteBudget)
	}
}

func TestLuaInfiniteLoopCancelled(t *testing.T) {
	e := compile(t, `while true do end`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := e.Run(ctx, newConn(""), "5.5.5.5")
	if r.Meta["lua_error"] == nil {
		t.Error("infinite loop should be cancelled by the context deadline")
	}
}

// Every shipped configs/scripts/*.lua must compile and run end-to-end
// without a Lua error against representative input — a guard so a broken
// script can't ship.
func TestShippedScriptsCompileAndRun(t *testing.T) {
	dir := filepath.Join("..", "..", "configs", "scripts")
	files, err := filepath.Glob(filepath.Join(dir, "*.lua"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 5 {
		t.Fatalf("expected several shipped scripts, found %d in %s", len(files), dir)
	}
	input := "PING\r\nINFO\r\nstats\r\nversion\r\nEHLO x\r\nUSER a\r\nPASS b\r\nshow version\r\nQUIT\r\n"
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		name := filepath.Base(f)
		e, err := Compile(name, src, identity.New("seed-A"), "debian-12", "debian")
		if err != nil {
			t.Errorf("%s: compile: %v", name, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		r := e.Run(ctx, newConn(input), "9.9.9.9")
		cancel()
		if r.Meta["lua_error"] != nil {
			t.Errorf("%s: runtime error: %v", name, r.Meta["lua_error"])
		}
	}
}

func TestLuaTimeAPI(t *testing.T) {
	e := compile(t, `
		meta("now_ok", time.now() > 1700000000)
		meta("utc", time.utc())
		meta("uptime_ok", time.uptime() >= 0)
	`)
	r := e.Run(context.Background(), newConn(""), "8.8.8.8")
	if r.Meta["now_ok"] != true {
		t.Errorf("time.now() looks wrong: %v", r.Meta["now_ok"])
	}
	if s, _ := r.Meta["utc"].(string); !strings.HasSuffix(s, "GMT") {
		t.Errorf("time.utc() = %q; want an HTTP-date ending GMT", s)
	}
	if r.Meta["uptime_ok"] != true {
		t.Errorf("time.uptime() negative: %v", r.Meta["uptime_ok"])
	}
}

func TestLuaSandboxNoIO(t *testing.T) {
	// os/io must be unavailable; the call errors and is flagged.
	e := compile(t, `os.execute("id")`)
	r := e.Run(context.Background(), newConn(""), "6.6.6.6")
	if r.Meta["lua_error"] == nil {
		t.Error("os.* should not be available in the sandbox")
	}
}

func TestLuaFlagAndCompileError(t *testing.T) {
	e := compile(t, `flag("suspicious"); conn:write("ok")`)
	r := e.Run(context.Background(), newConn(""), "7.7.7.7")
	found := false
	for _, a := range r.Anomalies {
		if a == "lua:suspicious" {
			found = true
		}
	}
	if !found {
		t.Errorf("flag() not recorded: %v", r.Anomalies)
	}
	if _, err := Compile("bad.lua", []byte("this is not lua ===="), nil, "", ""); err == nil {
		t.Error("expected a compile error for invalid script")
	}
}

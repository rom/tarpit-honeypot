// Package luaengine runs operator-supplied Lua scripts as dynamic
// protocol responders. Each script is compiled once and executed per
// connection in a sandboxed gopher-lua VM (no io/os/debug libraries, a
// context deadline, and read/write/sleep budgets) so a script can't
// exhaust the sensor or turn it into an amplifier.
//
// Scripts get a small, deterministic API:
//
//	conn:read(n) / conn:readline() / conn:write(s)   -- drive the socket
//	peer                                             -- source IP (string)
//	session                                          -- per-connection table
//	host:get(k) / host:set(k,v)                      -- per-source persistent state
//	rng:int(n) / rng:choice(t) / rng:hex(n)          -- deterministic per (deployment, host, script)
//	personality()                                    -- stable per-host {hostname,version,firmware,serial}
//	sleep(ms)                                         -- bounded delay (timers)
//	time.now() / time.ms() / time.utc() / time.uptime() -- clock (timestamps/TTL)
//	log(s) / flag(marker) / meta(k,v)                -- record into the event
//	archetype                                        -- {name, family}
//
// "Deterministic randomness" means two queries from the same source see
// the same persona, and two deployments differ — driven by
// sensor.deployment_id.
package luaengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"

	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Limits bound a single script execution.
const (
	defaultReadBudget  = 64 << 10  // total bytes a script may read
	defaultWriteBudget = 256 << 10 // total bytes a script may write (anti-amplification)
	maxSleepBudget     = 30 * time.Second
	registrySize       = 64 * 1024
	callStackSize      = 256
)

// Conn is the minimal socket a script drives.
type Conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// Result is what a script run produced, mapped by the caller into a
// handler.Result.
type Result struct {
	BannerSent string
	Payload    []byte // bytes the attacker sent (captured)
	Meta       map[string]any
	Anomalies  []string
}

// Engine is one compiled script, reusable across connections.
type Engine struct {
	name    string
	proto   *lua.FunctionProto
	id      *identity.Identity
	arch    archInfo
	hosts   *hostStore
	started time.Time // for time.uptime()
}

type archInfo struct{ Name, Family string }

// Compile parses + compiles a Lua script. name is used in error messages
// and as part of the deterministic RNG seed.
func Compile(name string, src []byte, id *identity.Identity, archName, archFamily string) (*Engine, error) {
	chunk, err := parse.Parse(bytes.NewReader(src), name)
	if err != nil {
		return nil, fmt.Errorf("lua: parse %s: %w", name, err)
	}
	proto, err := lua.Compile(chunk, name)
	if err != nil {
		return nil, fmt.Errorf("lua: compile %s: %w", name, err)
	}
	return &Engine{name: name, proto: proto, id: id, arch: archInfo{archName, archFamily}, hosts: newHostStore(), started: time.Now()}, nil
}

// Run executes the script for one connection. The deadline comes from
// ctx; budgets cap reads/writes/sleeps.
func (e *Engine) Run(ctx context.Context, conn Conn, srcIP string) Result {
	res := &Result{Meta: map[string]any{}}
	st := &runState{
		conn:        conn,
		br:          bufio.NewReader(conn),
		res:         res,
		readBudget:  defaultReadBudget,
		writeBudget: defaultWriteBudget,
		sleepBudget: maxSleepBudget,
		rng:         mrand.New(mrand.NewSource(e.seed(srcIP))),
		host:        e.hosts.entry(srcIP),
	}

	L := lua.NewState(lua.Options{SkipOpenLibs: true, RegistrySize: registrySize, CallStackSize: callStackSize})
	defer L.Close()
	L.SetContext(ctx)
	openSafeLibs(L)
	e.install(L, st, srcIP)

	L.Push(L.NewFunctionFromProto(e.proto))
	if err := L.PCall(0, 0, nil); err != nil {
		res.Meta["lua_error"] = safe.SanitizeForLog(err.Error())
		res.Anomalies = appendUnique(res.Anomalies, "lua-script-error")
	}
	return *res
}

// seed derives the per-(deployment, host, script) RNG seed so a source
// sees a consistent persona and two deployments differ.
func (e *Engine) seed(srcIP string) int64 {
	if e.id != nil {
		return int64(e.id.Uint32("lua/" + e.name + "/" + srcIP))
	}
	var h uint64 = 1469598103934665603
	for _, c := range e.name + "/" + srcIP {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return int64(h)
}

// openSafeLibs loads only the non-IO standard libraries and removes the
// few base globals that touch the filesystem / loader.
func openSafeLibs(L *lua.LState) {
	lua.OpenBase(L)
	lua.OpenString(L)
	lua.OpenTable(L)
	lua.OpenMath(L)
	for _, g := range []string{"dofile", "loadfile", "load", "loadstring", "require", "module", "collectgarbage", "print"} {
		L.SetGlobal(g, lua.LNil)
	}
}

type runState struct {
	conn        Conn
	br          *bufio.Reader
	res         *Result
	readBudget  int
	writeBudget int
	sleepBudget time.Duration
	rng         *mrand.Rand
	host        *hostEntry
}

// install wires the sandboxed API onto the LState.
func (e *Engine) install(L *lua.LState, st *runState, srcIP string) {
	L.SetGlobal("peer", lua.LString(srcIP))
	L.SetGlobal("session", L.NewTable())

	// conn:read / readline / write. Method (":") syntax passes the table
	// as arg 1, so real arguments start at index 2.
	conn := L.NewTable()
	L.SetField(conn, "read", L.NewFunction(func(L *lua.LState) int {
		n := L.OptInt(2, 4096)
		if n <= 0 || st.readBudget <= 0 {
			L.Push(lua.LNil)
			return 1
		}
		if n > st.readBudget {
			n = st.readBudget
		}
		if n > 4096 {
			n = 4096
		}
		buf := make([]byte, n)
		m, _ := st.br.Read(buf)
		if m <= 0 {
			L.Push(lua.LNil)
			return 1
		}
		st.readBudget -= m
		st.res.Payload = append(st.res.Payload, buf[:m]...)
		L.Push(lua.LString(buf[:m]))
		return 1
	}))
	L.SetField(conn, "readline", L.NewFunction(func(L *lua.LState) int {
		if st.readBudget <= 0 {
			L.Push(lua.LNil)
			return 1
		}
		max := 8192
		if max > st.readBudget {
			max = st.readBudget
		}
		var sb bytes.Buffer
		for sb.Len() < max {
			b, err := st.br.ReadByte()
			if err != nil {
				break
			}
			sb.WriteByte(b)
			if b == '\n' {
				break
			}
		}
		if sb.Len() == 0 {
			L.Push(lua.LNil)
			return 1
		}
		st.readBudget -= sb.Len()
		st.res.Payload = append(st.res.Payload, sb.Bytes()...)
		L.Push(lua.LString(sb.String()))
		return 1
	}))
	L.SetField(conn, "write", L.NewFunction(func(L *lua.LState) int {
		s := L.CheckString(2)
		if st.writeBudget <= 0 {
			return 0
		}
		if len(s) > st.writeBudget {
			s = s[:st.writeBudget]
		}
		_, err := st.conn.Write([]byte(s))
		if err == nil {
			st.writeBudget -= len(s)
			st.res.BannerSent += s
		}
		return 0
	}))
	L.SetGlobal("conn", conn)

	// host:get / host:set — per-source persistent state.
	host := L.NewTable()
	L.SetField(host, "get", L.NewFunction(func(L *lua.LState) int {
		L.Push(goToLua(L, st.host.get(L.CheckString(2))))
		return 1
	}))
	L.SetField(host, "set", L.NewFunction(func(L *lua.LState) int {
		st.host.set(L.CheckString(2), luaToGo(L.CheckAny(3)))
		return 0
	}))
	L.SetGlobal("host", host)

	// rng:int / choice / hex — deterministic per host.
	rng := L.NewTable()
	L.SetField(rng, "int", L.NewFunction(func(L *lua.LState) int {
		n := L.OptInt(2, 1<<31-1)
		if n <= 0 {
			n = 1
		}
		L.Push(lua.LNumber(st.rng.Intn(n)))
		return 1
	}))
	L.SetField(rng, "choice", L.NewFunction(func(L *lua.LState) int {
		t := L.CheckTable(2)
		n := t.Len()
		if n == 0 {
			L.Push(lua.LNil)
			return 1
		}
		L.Push(t.RawGetInt(st.rng.Intn(n) + 1))
		return 1
	}))
	L.SetField(rng, "hex", L.NewFunction(func(L *lua.LState) int {
		n := L.OptInt(2, 8)
		if n <= 0 || n > 64 {
			n = 8
		}
		b := make([]byte, n)
		_, _ = st.rng.Read(b)
		L.Push(lua.LString(hex.EncodeToString(b)))
		return 1
	}))
	L.SetGlobal("rng", rng)

	// personality() — stable per-host identity, independent of the rng
	// stream so it never drifts with script control flow.
	L.SetGlobal("personality", L.NewFunction(func(L *lua.LState) int {
		p := L.NewTable()
		L.SetField(p, "hostname", lua.LString(e.persona(srcIP, "hostname")))
		L.SetField(p, "version", lua.LString(e.persona(srcIP, "version")))
		L.SetField(p, "firmware", lua.LString(e.persona(srcIP, "firmware")))
		L.SetField(p, "serial", lua.LString(e.persona(srcIP, "serial")))
		L.Push(p)
		return 1
	}))

	// sleep(ms) — bounded delay (timers).
	L.SetGlobal("sleep", L.NewFunction(func(L *lua.LState) int {
		ms := L.CheckInt(1)
		if ms <= 0 {
			return 0
		}
		d := time.Duration(ms) * time.Millisecond
		if d > st.sleepBudget {
			d = st.sleepBudget
		}
		st.sleepBudget -= d
		select {
		case <-time.After(d):
		case <-L.Context().Done():
		}
		return 0
	}))

	// time — wall clock + process uptime, for dynamic banners that carry a
	// timestamp / counter / TTL (e.g. an SMTP RFC822 date, a fake device
	// uptime, an HTTP Date). Read-only; benign to expose to the sandbox.
	tmod := L.NewTable()
	L.SetField(tmod, "now", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(time.Now().Unix()))
		return 1
	}))
	L.SetField(tmod, "ms", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(time.Now().UnixMilli()))
		return 1
	}))
	L.SetField(tmod, "utc", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")))
		return 1
	}))
	L.SetField(tmod, "uptime", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(int(time.Since(e.started).Seconds())))
		return 1
	}))
	L.SetGlobal("time", tmod)

	// log / flag / meta — recording into the event.
	L.SetGlobal("log", L.NewFunction(func(L *lua.LState) int {
		s := safe.SanitizeForLog(L.CheckString(1))
		cur, _ := st.res.Meta["lua_log"].([]string)
		st.res.Meta["lua_log"] = append(cur, s)
		return 0
	}))
	L.SetGlobal("flag", L.NewFunction(func(L *lua.LState) int {
		st.res.Anomalies = appendUnique(st.res.Anomalies, "lua:"+L.CheckString(1))
		return 0
	}))
	L.SetGlobal("meta", L.NewFunction(func(L *lua.LState) int {
		st.res.Meta[L.CheckString(1)] = luaToGo(L.CheckAny(2))
		return 0
	}))

	arch := L.NewTable()
	L.SetField(arch, "name", lua.LString(e.arch.Name))
	L.SetField(arch, "family", lua.LString(e.arch.Family))
	L.SetGlobal("archetype", arch)
}

// persona derives a stable per-host string for a field, independent of
// the mutable rng stream.
func (e *Engine) persona(srcIP, field string) string {
	r := mrand.New(mrand.NewSource(e.seed(srcIP + "/" + field)))
	switch field {
	case "hostname":
		return personaHostnames[r.Intn(len(personaHostnames))] + "-" + fmt.Sprintf("%02d", r.Intn(100))
	case "version":
		return personaVersions[r.Intn(len(personaVersions))]
	case "firmware":
		return fmt.Sprintf("v%d.%d.%d", 1+r.Intn(6), r.Intn(20), r.Intn(40))
	case "serial":
		b := make([]byte, 6)
		_, _ = r.Read(b)
		return hex.EncodeToString(b)
	}
	return ""
}

var personaHostnames = []string{"srv", "host", "node", "dev", "ws", "app", "db", "edge", "core", "gw"}
var personaVersions = []string{"1.2.3", "2.0.1", "3.4.0", "4.1.2", "5.0.0", "6.2.1"}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

// ---- per-source host state ----

type hostStore struct {
	mu      sync.Mutex
	entries map[string]*hostEntry
	lastGC  time.Time
}

type hostEntry struct {
	mu   sync.Mutex
	data map[string]any
	last time.Time
}

func newHostStore() *hostStore { return &hostStore{entries: map[string]*hostEntry{}} }

const hostTTL = time.Hour

func (s *hostStore) entry(ip string) *hostEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.lastGC) > hostTTL {
		for k, e := range s.entries {
			if now.Sub(e.last) > hostTTL {
				delete(s.entries, k)
			}
		}
		s.lastGC = now
	}
	e := s.entries[ip]
	if e == nil {
		e = &hostEntry{data: map[string]any{}}
		s.entries[ip] = e
	}
	e.last = now
	return e
}

func (e *hostEntry) get(k string) any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.data[k]
}

func (e *hostEntry) set(k string, v any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.data) > 256 && e.data[k] == nil {
		return // bound per-host state
	}
	e.data[k] = v
}

// luaToGo converts a Lua value to a plain Go value (string/float/bool).
func luaToGo(v lua.LValue) any {
	switch t := v.(type) {
	case lua.LString:
		return string(t)
	case lua.LNumber:
		return float64(t)
	case lua.LBool:
		return bool(t)
	}
	return v.String()
}

func goToLua(L *lua.LState, v any) lua.LValue {
	switch t := v.(type) {
	case nil:
		return lua.LNil
	case string:
		return lua.LString(t)
	case float64:
		return lua.LNumber(t)
	case bool:
		return lua.LBool(t)
	}
	return lua.LString(fmt.Sprintf("%v", v))
}

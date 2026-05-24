package testharness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
)

// Target is the system under test. It abstracts three backends behind a common
// Dial/lifecycle surface:
//   - managed network: the harness spawns the sensor binary and can respawn it
//   - external network: an already-running sensor (restart via RestartCmd)
//   - module: a protocol handler driven in-process over an in-memory pipe
type Target struct {
	cfg  *Config
	deps handler.Deps // module mode

	mu   sync.Mutex
	proc *exec.Cmd // managed network target
}

// NewTarget builds a target for the config (does not start it).
func NewTarget(cfg *Config) (*Target, error) {
	t := &Target{cfg: cfg}
	if cfg.Mode == "module" {
		t.deps = handler.Deps{Identity: identity.New("testharness"), DataDir: os.TempDir()}
	}
	return t, nil
}

// Managed reports whether the harness owns the target process.
func (t *Target) Managed() bool { return t.cfg.Mode == "network" && t.cfg.Spawn.Binary != "" }

// Start brings the target up: module is a no-op; a managed target is spawned
// and waited on; an external target is waited on only when a health URL gives a
// positive readiness signal — otherwise we trust the operator that it is up, so
// that probing its endpoints (e.g. a deliberately-closed port) is not mistaken
// for the whole target being down.
func (t *Target) Start(ctx context.Context) error {
	switch {
	case t.cfg.Mode == "module":
		return nil
	case t.Managed():
		if err := t.spawn(ctx); err != nil {
			return err
		}
		return t.waitReady(ctx)
	case t.cfg.Spawn.HealthURL != "":
		return t.waitReady(ctx)
	default:
		return nil
	}
}

// Restart kills + respawns a managed target, runs RestartCmd for an external
// one, or is a no-op for module mode. Then waits for readiness.
func (t *Target) Restart(ctx context.Context) error {
	switch {
	case t.cfg.Mode == "module":
		return nil
	case t.Managed():
		t.kill()
		if err := t.spawn(ctx); err != nil {
			return err
		}
	case t.cfg.RestartCmd != "":
		cmd := exec.CommandContext(ctx, "sh", "-c", t.cfg.RestartCmd)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("restart_cmd: %w", err)
		}
	default:
		return nil // external with no restart hook — just retry against it
	}
	return t.waitReady(ctx)
}

// Stop tears down a managed target.
func (t *Target) Stop() { t.kill() }

func (t *Target) spawn(ctx context.Context) error {
	args := []string{"run"}
	if t.cfg.Spawn.Config != "" {
		args = append(args, "-c", t.cfg.Spawn.Config)
	}
	args = append(args, t.cfg.Spawn.Args...)
	cmd := exec.Command(t.cfg.Spawn.Binary, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn %s: %w", t.cfg.Spawn.Binary, err)
	}
	t.mu.Lock()
	t.proc = cmd
	t.mu.Unlock()
	go func() { _ = cmd.Wait() }() // reap; Alive() checks ProcessState
	return nil
}

func (t *Target) kill() {
	t.mu.Lock()
	p := t.proc
	t.proc = nil
	t.mu.Unlock()
	if p != nil && p.Process != nil {
		_ = p.Process.Kill()
		_, _ = p.Process.Wait()
	}
}

// waitReady polls until the target answers (health URL or any TCP endpoint),
// bounded by Spawn.ReadyTimeout.
func (t *Target) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(t.cfg.Spawn.ReadyTimeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if t.ready() {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	if t.ready() {
		return nil
	}
	return fmt.Errorf("target did not become ready within %s", t.cfg.Spawn.ReadyTimeout)
}

func (t *Target) ready() bool {
	if u := t.cfg.Spawn.HealthURL; u != "" {
		c := &http.Client{Timeout: time.Second}
		resp, err := c.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			return resp.StatusCode < 500
		}
		return false
	}
	for _, e := range t.cfg.Endpoints {
		if e.Proto == "tcp" {
			conn, err := net.DialTimeout("tcp", t.addr(e), time.Second)
			if err == nil {
				_ = conn.Close()
				return true
			}
		}
	}
	// No TCP endpoint / health url to probe — assume up.
	return len(t.cfg.Endpoints) == 0 || !t.anyTCP()
}

func (t *Target) anyTCP() bool {
	for _, e := range t.cfg.Endpoints {
		if e.Proto == "tcp" {
			return true
		}
	}
	return false
}

// Alive reports whether the target still responds — used to distinguish a
// crashed/hung target from an ordinary case finding.
func (t *Target) Alive(ctx context.Context) bool {
	if t.cfg.Mode == "module" {
		return true
	}
	if t.Managed() {
		t.mu.Lock()
		p := t.proc
		t.mu.Unlock()
		if p == nil || (p.ProcessState != nil && p.ProcessState.Exited()) {
			return false
		}
	}
	return t.ready()
}

func (t *Target) addr(e Endpoint) string {
	return net.JoinHostPort(t.cfg.Host, strconv.Itoa(e.Port))
}

// Endpoint looks up a configured endpoint by label.
func (t *Target) Endpoint(label string) (Endpoint, bool) {
	for _, e := range t.cfg.Endpoints {
		if e.Label == label {
			return e, true
		}
	}
	return Endpoint{}, false
}

// Dial opens a connection to an endpoint (network: dial host:port; module:
// instantiate the handler over an in-memory pipe). The caller closes it.
func (t *Target) Dial(ctx context.Context, e Endpoint) (net.Conn, error) {
	if t.cfg.Mode == "module" {
		return t.dialModule(ctx, e)
	}
	d := net.Dialer{Timeout: t.cfg.Timeout}
	return d.DialContext(ctx, e.Proto, t.addr(e))
}

func (t *Target) dialModule(ctx context.Context, e Endpoint) (net.Conn, error) {
	h, err := handler.Get(e.Handler, t.deps)
	if err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	lc := config.Listener{Handler: e.Handler, ReadTimeout: t.cfg.Timeout}
	go func() {
		defer func() {
			_ = recover() // a handler bug must surface as no-response, not a harness crash
			_ = server.Close()
		}()
		_, _ = h.Handle(ctx, server, lc)
	}()
	return client, nil
}

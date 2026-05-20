package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// syncBuffer is a goroutine-safe bytes.Buffer: the reader goroutine
// io.Copy's into it while the test polls String(), so both sides must lock.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// loopbackPair sets up a localhost listener and returns one accepted
// server-side conn + one dialed client-side conn. Unlike net.Pipe,
// these are real sockets with kernel buffering, which crypto/ssh's
// handshake needs to make progress in both directions.
func loopbackPair(t *testing.T) (clientConn, serverConn net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return c, s
}

// Connect a real x/crypto/ssh client to the interactive handler,
// fail two password attempts, succeed on the third, request a shell,
// type a command, see the canned response, and verify the captured
// credentials + shell command land in res.Meta.
func TestSSHInteractiveEngagement(t *testing.T) {
	client, server := loopbackPair(t)

	h := &sshInteractive{
		arch: archetype.Lookup("debian 12"),
		dir:  t.TempDir(),
	}

	// Server side.
	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	// Client side: try wrong passwords first, then the right one.
	// RetryableAuthMethod wraps the underlying password callback so
	// crypto/ssh re-attempts up to N times with a fresh password.
	clientCfg := &xssh.ClientConfig{
		User: "admin",
		Auth: []xssh.AuthMethod{
			xssh.RetryableAuthMethod(xssh.PasswordCallback(func() (string, error) {
				return passwordSeries(), nil
			}), 5),
		},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	c, chans, reqs, err := xssh.NewClientConn(client, "host:22", clientCfg)
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	defer c.Close()
	cli := xssh.NewClient(c, chans, reqs)
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdoutR, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stdout syncBuffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = io.Copy(&stdout, stdoutR)
	}()

	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	// Wait for the initial prompt before pushing the first command.
	waitFor := func(needle string, timeout time.Duration) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if strings.Contains(stdout.String(), needle) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitFor("# ", 2*time.Second)
	_, _ = io.WriteString(stdin, "whoami\n")
	waitFor("root\r\n", 2*time.Second)
	_, _ = io.WriteString(stdin, "cat /etc/shadow\n")
	waitFor("Permission denied", 2*time.Second)
	_, _ = io.WriteString(stdin, "exit\n")
	_ = stdin.Close()
	_ = sess.Wait()
	<-readDone
	_ = c.Close()

	select {
	case res := <-resC:
		// Auth attempts captured.
		attempts, _ := res.Meta["auth_attempts"].([]map[string]any)
		if len(attempts) < acceptAuthAfter {
			t.Errorf("attempts captured = %d; want >= %d", len(attempts), acceptAuthAfter)
		}
		// Shell commands captured.
		cmds, _ := res.Meta["shell_commands"].([]string)
		if len(cmds) < 2 {
			t.Errorf("shell_commands = %v; want at least 2", cmds)
		}
		// /etc/shadow should have produced an anomaly marker.
		anoms, _ := res.Meta["anomalies"].([]string)
		if !containsStr(anoms, "shell-shadow-read") {
			t.Errorf("anomalies = %v; want shell-shadow-read", anoms)
		}
		// Output should include Debian-style prompt and shadow denial.
		out := stdout.String()
		if !strings.Contains(out, "Permission denied") {
			t.Errorf("stdout missing Permission denied: %q", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}

// passwordSeries returns increasing fake passwords so we accumulate
// distinct auth attempts in the handler.
var pwIdx = 0
var pwOptions = []string{"root", "admin", "password123"}

func passwordSeries() string {
	p := pwOptions[pwIdx%len(pwOptions)]
	pwIdx++
	return p
}

// Public-key attempts should be captured as fingerprints but never
// succeed — the handler forces password fallback so the password
// capture path runs.
func TestSSHInteractiveRejectsPubkey(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{dir: t.TempDir()}

	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	// Build a throwaway key.
	signer, err := xssh.NewSignerFromKey(generatedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &xssh.ClientConfig{
		User: "admin",
		Auth: []xssh.AuthMethod{
			xssh.PublicKeys(signer),
		},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	_, _, _, _ = xssh.NewClientConn(client, "host:22", cfg)
	_ = client.Close()

	select {
	case res := <-resC:
		attempts, _ := res.Meta["auth_attempts"].([]map[string]any)
		hasPubkey := false
		for _, a := range attempts {
			if a["method"] == "publickey" {
				hasPubkey = true
				if a["key_fp_sha256"] == "" {
					t.Errorf("pubkey attempt missing fingerprint")
				}
			}
		}
		if !hasPubkey {
			t.Errorf("expected pubkey attempt in auth_attempts: %v", attempts)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not return")
	}
}

// generatedKey builds an in-process ed25519 key for the test client.
func generatedKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

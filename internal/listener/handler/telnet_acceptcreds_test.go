package handler

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

// driveTelnet runs the telnet handler on one end of a pipe, feeds it the given
// client input after a short delay (so the banner is read first), and returns
// everything the handler wrote plus the finished Result.
func driveTelnet(t *testing.T, h *telnet, clientInput string) (string, Result) {
	t.Helper()
	client, server := pipePair(t)
	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "telnet", ReadTimeout: 2 * time.Second})
		resC <- res
	}()
	// Reader: drain everything the server sends.
	outC := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(client)
		outC <- string(b)
	}()
	// Feed the client input, then wait for the handler to finish.
	time.Sleep(50 * time.Millisecond)
	_, _ = client.Write([]byte(clientInput))
	select {
	case res := <-resC:
		// Handle never closes the conn (the listener does), so close the client
		// side to unblock the output reader's ReadAll with EOF.
		_ = client.Close()
		return <-outC, res
	case <-time.After(5 * time.Second):
		t.Fatal("telnet handler did not return")
		return "", Result{}
	}
}

// accept_creds=any: the login is accepted on the FIRST attempt — no "Login
// incorrect", straight to the welcome line + shell.
func TestTelnetAcceptCredsAnyFirstTry(t *testing.T) {
	h := &telnet{jit: jitter.New(0, 0), arch: archetype.Lookup("debian 12"), dataDir: t.TempDir(), acceptCreds: "any"}
	out, res := driveTelnet(t, h, "root\r\nhunter2\r\nexit\r\n")
	if strings.Contains(out, "Login incorrect") {
		t.Errorf("accept_creds=any should not say 'Login incorrect'; output:\n%s", out)
	}
	if !strings.Contains(out, "Last login") {
		t.Errorf("expected welcome line after first-try accept; output:\n%s", out)
	}
	if res.Meta["accepted_user"] != "root" {
		t.Errorf("accepted_user = %v; want root", res.Meta["accepted_user"])
	}
	if res.Meta["accept_policy"] != "any" {
		t.Errorf("accept_policy = %v; want any", res.Meta["accept_policy"])
	}
}

// Default (no accept_creds): the first attempt fails with "Login incorrect"
// (the existing capture-first behavior is preserved).
func TestTelnetNoAcceptCredsStillFailsFirst(t *testing.T) {
	h := &telnet{jit: jitter.New(0, 0), arch: archetype.Lookup("debian 12"), dataDir: t.TempDir()}
	out, res := driveTelnet(t, h, "root\r\nroot\r\nroot\r\nroot\r\nexit\r\n")
	if !strings.Contains(out, "Login incorrect") {
		t.Errorf("default telnet should fail the first attempt with 'Login incorrect'; output:\n%s", out)
	}
	if res.Meta["accepted_user"] != nil {
		t.Errorf("accepted_user = %v; want nil (no accept policy)", res.Meta["accepted_user"])
	}
}

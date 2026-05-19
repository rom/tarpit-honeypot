package handler

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// SSH handler should advertise the archetype-supplied banner verbatim
// when no explicit cfg.Banner overrides it.
func TestSSHBannerFromArchetype(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	if arch == nil {
		t.Fatal("debian 12 archetype missing")
	}
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ssh", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&ssh{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	_, _ = client.Write([]byte("SSH-2.0-Client\r\n"))
	client.Close()
	<-done
	want := arch.SSHBanner()
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), want) {
		t.Errorf("SSH banner = %q; want prefix %q", line, want)
	}
}

// HTTP handler should report the archetype's Server header instead of
// the identity-based randomization.
func TestHTTPServerFromArchetype(t *testing.T) {
	arch := archetype.Lookup("ubuntu 24.04 lts")
	if arch == nil {
		t.Fatal("ubuntu 24.04 lts archetype missing")
	}
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	client.Close()
	<-done
	resp := string(buf[:n])
	want := "Server: " + arch.HTTPServer()
	if !strings.Contains(resp, want) {
		t.Errorf("response missing %q; got: %s", want, resp)
	}
}

// FTP handler should send the archetype's 220 banner.
func TestFTPBannerFromArchetype(t *testing.T) {
	arch := archetype.Lookup("centos 7")
	if arch == nil {
		t.Fatal("centos 7 archetype missing")
	}
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ftp", ReadBytes: 256, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&ftp{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	br := bufio.NewReader(client)
	line, _ := br.ReadString('\n')
	_, _ = client.Write([]byte("USER root\r\n"))
	_, _ = br.ReadString('\n')
	_, _ = client.Write([]byte("PASS x\r\n"))
	client.Close()
	<-done
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), arch.FTPBanner()) {
		t.Errorf("FTP banner = %q; want prefix %q", line, arch.FTPBanner())
	}
}

// Telnet handler should emit the archetype's issue-string banner.
func TestTelnetBannerFromArchetype(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	if arch == nil {
		t.Fatal("debian 12 archetype missing")
	}
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "telnet", ReadBytes: 8, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&telnet{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	// Drain both the IAC negotiation and the banner. The handler then
	// reads up to ReadBytes from us before returning; close the conn
	// so it returns promptly.
	var collected []byte
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(collected) < 4096 {
		buf := make([]byte, 256)
		n, err := client.Read(buf)
		if n > 0 {
			collected = append(collected, buf[:n]...)
		}
		if err != nil {
			break
		}
		if strings.Contains(string(collected), "login:") {
			break
		}
	}
	client.Close()
	<-done
	if !strings.Contains(string(collected), "Debian GNU/Linux 12") {
		t.Errorf("Telnet banner did not contain archetype string; got: %q", string(collected))
	}
}

// SMTP handler should embed the archetype's product / host strings in
// the 220 greeting.
func TestSMTPGreetingFromArchetype(t *testing.T) {
	arch := archetype.Lookup("debian 11")
	if arch == nil {
		t.Fatal("debian 11 archetype missing")
	}
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "smtp_recv", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&smtpRecv{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	br := bufio.NewReader(client)
	greet, _ := br.ReadString('\n')
	_, _ = client.Write([]byte("QUIT\r\n"))
	_, _ = br.ReadString('\n')
	client.Close()
	<-done
	if !strings.Contains(greet, arch.SMTPProduct()) {
		t.Errorf("SMTP greeting %q lacks product %q", greet, arch.SMTPProduct())
	}
}

// MySQL handler should advertise the archetype-supplied server version
// inside the handshake packet body.
func TestMySQLVersionFromArchetype(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	if arch == nil {
		t.Fatal("debian 12 archetype missing")
	}
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "mysql", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&mysql{arch: arch}).Handle(context.Background(), server, cfg)
	}()
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	// Drop the connection (we don't need to walk the full handshake).
	client.Close()
	<-done
	if !strings.Contains(string(buf[:n]), arch.MySQLVersion()) {
		t.Errorf("handshake packet missing version %q", arch.MySQLVersion())
	}
}

// When the archetype is nil, the handlers should fall back to the
// identity-based or static default — i.e. no panic and a non-empty
// banner still goes out.
func TestSSHNoArchetypeFallback(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ssh", ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&ssh{}).Handle(context.Background(), server, cfg)
	}()
	br := bufio.NewReader(client)
	line, _ := br.ReadString('\n')
	_, _ = client.Write([]byte("SSH-2.0-Client\r\n"))
	client.Close()
	<-done
	if !strings.HasPrefix(line, "SSH-2.0-") {
		t.Errorf("fallback SSH banner missing: %q", line)
	}
}

package handler

import (
	"bufio"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestVMwareAuthd(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 256}
	resC := make(chan Result, 1)
	go func() { r, _ := (&vmwareAuthd{}).Handle(context.Background(), server, cfg); resC <- r }()
	br := bufio.NewReader(client)
	banner, _ := br.ReadString('\n')
	if !strings.Contains(banner, "VMware Authentication Daemon") {
		t.Fatalf("banner = %q", banner)
	}
	_, _ = client.Write([]byte("USER root\r\n"))
	_, _ = br.ReadString('\n') // 331
	_, _ = client.Write([]byte("PASS secret\r\n"))
	_, _ = br.ReadString('\n') // 530
	_ = client.Close()
	r := <-resC
	if r.Meta["user"] != "root" || r.Meta["pass"] != "secret" {
		t.Errorf("creds = %v", r.Meta)
	}
}

func TestX11(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&x11{}).Handle(context.Background(), server, cfg); resC <- r }()
	// little-endian: 'l',0, major=11, minor=0, nameLen=18, dataLen=16, 0,0
	hdr := []byte{'l', 0, 11, 0, 0, 0, 18, 0, 16, 0, 0, 0}
	name := append([]byte("MIT-MAGIC-COOKIE-1"), 0, 0) // 18 -> pad to 20
	data := make([]byte, 16)
	_, _ = client.Write(append(append(hdr, name...), data...))
	buf := make([]byte, 64)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	if n < 1 || buf[0] != 0 {
		t.Errorf("x11 reply not Failed: % x", buf[:n])
	}
	if r.Meta["x11_auth_name"] != "MIT-MAGIC-COOKIE-1" {
		t.Errorf("auth name = %v", r.Meta["x11_auth_name"])
	}
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "x11-connection-attempt") {
		t.Errorf("not flagged: %v", r.Meta["anomalies"])
	}
}

func TestRlogin(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&rlogin{}).Handle(context.Background(), server, cfg); resC <- r }()
	go func() {
		b := make([]byte, 256)
		for {
			if _, err := client.Read(b); err != nil {
				return
			}
		}
	}()
	_, _ = client.Write([]byte("\x00alice\x00root\x00xterm/38400\x00"))
	time.Sleep(25 * time.Millisecond)
	_, _ = client.Write([]byte("hunter2\n"))
	time.Sleep(25 * time.Millisecond)
	_ = client.Close()
	r := <-resC
	if r.Meta["client_user"] != "alice" || r.Meta["server_user"] != "root" {
		t.Errorf("users = %v", r.Meta)
	}
	if r.Meta["password"] != "hunter2" {
		t.Errorf("password = %v", r.Meta["password"])
	}
}

func TestNX(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&nx{}).Handle(context.Background(), server, cfg); resC <- r }()
	br := bufio.NewReader(client)
	banner, _ := br.ReadString('\n')
	if !strings.HasPrefix(banner, "HELLO NXSERVER") {
		t.Fatalf("banner = %q", banner)
	}
	_, _ = client.Write([]byte("HELLO NXCLIENT - Version 3.5.0\r\n"))
	_ = client.Close()
	r := <-resC
	if s, _ := r.Meta["nx_client"].(string); !strings.Contains(s, "NXCLIENT") {
		t.Errorf("nx_client = %v", r.Meta["nx_client"])
	}
}

func TestRedfish(t *testing.T) {
	// Service root is unauthenticated.
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	go func() { _, _ = (&redfish{}).Handle(context.Background(), server, cfg) }()
	_, _ = client.Write([]byte("GET /redfish/v1 HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 2048)
	n, _ := client.Read(buf)
	_ = client.Close()
	if !strings.Contains(string(buf[:n]), "ServiceRoot") || !strings.Contains(string(buf[:n]), "RedfishVersion") {
		t.Errorf("service root: %q", string(buf[:n]))
	}

	// Protected resource with Basic auth → 401 + captured creds.
	client2, server2 := pipePair(t)
	resC := make(chan Result, 1)
	go func() { r, _ := (&redfish{}).Handle(context.Background(), server2, cfg); resC <- r }()
	cred := base64.StdEncoding.EncodeToString([]byte("admin:calvin"))
	_, _ = client2.Write([]byte("GET /redfish/v1/Systems HTTP/1.1\r\nHost: x\r\nAuthorization: Basic " + cred + "\r\n\r\n"))
	buf2 := make([]byte, 1024)
	n2, _ := client2.Read(buf2)
	_ = client2.Close()
	r := <-resC
	if !strings.Contains(string(buf2[:n2]), "401") {
		t.Errorf("expected 401: %q", string(buf2[:n2]))
	}
	if r.Meta["basic_user"] != "admin" || r.Meta["basic_pass"] != "calvin" {
		t.Errorf("creds = %v", r.Meta)
	}
}

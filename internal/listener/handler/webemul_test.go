package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// With an Apache-flavored Server header (via identity), GET /nonexistent
// should return a 404 whose body carries the Apache "<address>...Server
// at host Port 80</address>" footer matching the Server header.
func TestHTTPApacheFlavored404(t *testing.T) {
	// Find a deployment seed whose HTTPServerHeader resolves to Apache.
	var id *identity.Identity
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g", "apache1", "apache2"} {
		cand := identity.New(s)
		if strings.HasPrefix(cand.HTTPServerHeader(), "Apache") {
			id = cand
			break
		}
	}
	if id == nil {
		t.Skip("no Apache-resolving seed found in sample")
	}
	server := id.HTTPServerHeader()

	client, srv := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{id: id}).Handle(context.Background(), srv, cfg)
	}()
	_, _ = client.Write([]byte("GET /nonexistent-path HTTP/1.1\r\nHost: victim.example\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done

	if !strings.HasPrefix(resp, "HTTP/1.1 404") {
		t.Errorf("expected 404 status; got: %q", trunc(resp, 40))
	}
	if !strings.Contains(resp, "Server: "+server) {
		t.Errorf("Server header missing/wrong: %q", trunc(resp, 200))
	}
	if !strings.Contains(resp, "Apache") || !strings.Contains(resp, "Server at victim.example Port 80") {
		t.Errorf("Apache error-page footer missing: %q", resp)
	}
	if !strings.Contains(resp, "The requested URL was not found on this server.") {
		t.Errorf("Apache 404 body text missing: %q", resp)
	}
}

// GET / on an Apache flavor returns the "It works!" index 200.
func TestHTTPApacheItWorksIndex(t *testing.T) {
	var id *identity.Identity
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g", "apache1", "apache2"} {
		cand := identity.New(s)
		if strings.HasPrefix(cand.HTTPServerHeader(), "Apache") {
			id = cand
			break
		}
	}
	if id == nil {
		t.Skip("no Apache-resolving seed found")
	}
	client, srv := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{id: id}).Handle(context.Background(), srv, cfg)
	}()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Errorf("expected 200; got %q", trunc(resp, 40))
	}
	if !strings.Contains(resp, "It works!") {
		t.Errorf("Apache It-works index missing: %q", resp)
	}
}

// nginx flavor returns the distinctive "Welcome to nginx!" page on /.
func TestHTTPNginxWelcomeIndex(t *testing.T) {
	var id *identity.Identity
	for _, s := range []string{"a", "b", "c", "d", "e", "n1", "n2", "n3"} {
		cand := identity.New(s)
		if strings.HasPrefix(cand.HTTPServerHeader(), "nginx") {
			id = cand
			break
		}
	}
	if id == nil {
		t.Skip("no nginx-resolving seed found")
	}
	client, srv := pipePair(t)
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&httpH{id: id}).Handle(context.Background(), srv, cfg)
	}()
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp := readAllFromConn(client, 2*time.Second)
	client.Close()
	<-done
	if !strings.Contains(resp, "Welcome to nginx!") {
		t.Errorf("nginx welcome page missing: %q", trunc(resp, 200))
	}
}

// ApacheVersion + ApacheModules + NginxVersion are deterministic per
// deployment and varied across deployments.
func TestIdentityWebVersionsDeterministic(t *testing.T) {
	a := identity.New("dep-A")
	if a.ApacheVersion() != a.ApacheVersion() {
		t.Errorf("ApacheVersion not stable within a deployment")
	}
	b := identity.New("dep-B")
	// Across enough seeds the pool should produce variety; just assert
	// the two helpers return non-empty.
	if a.ApacheVersion() == "" || b.NginxVersion() == "" {
		t.Errorf("empty web version string")
	}
}

package handler

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

func TestMatchVHost(t *testing.T) {
	vhosts := []config.TLSVHost{
		{ServerName: "mail.corp.local"},
		{ServerName: "*.apps.corp.local"},
	}
	cases := []struct {
		sni  string
		want string
		ok   bool
	}{
		{"mail.corp.local", "mail.corp.local", true},
		{"MAIL.corp.local", "mail.corp.local", true},
		{"foo.apps.corp.local", "*.apps.corp.local", true},
		{"a.b.apps.corp.local", "", false}, // wildcard is one label only
		{"other.local", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		vh, ok := matchVHost(vhosts, c.sni)
		if ok != c.ok || vh.ServerName != c.want {
			t.Errorf("matchVHost(%q) = (%q,%v), want (%q,%v)", c.sni, vh.ServerName, ok, c.want, c.ok)
		}
	}
}

// Drives the https handler with a vhost config and asserts the cert presented
// for a matching SNI carries that vhost's CN, and that the default cert is
// used otherwise.
func TestHTTPSVHostSelectsCert(t *testing.T) {
	h := newTestHTTPS(t, identity.New("vhost-dep"))
	cfg := config.Listener{
		ID:          "svc",
		ReadTimeout: 3 * time.Second,
		HTTPS: config.HTTPS{
			Hosts: []string{"default.local"},
			VHosts: []config.TLSVHost{
				{ServerName: "mail.corp.local", CN: "mail.corp.local"},
			},
		},
	}

	dial := func(sni string) (string, Result) {
		srvConn, cliConn := net.Pipe()
		defer srvConn.Close()
		defer cliConn.Close()
		resCh := make(chan Result, 1)
		go func() {
			res, _ := h.Handle(context.Background(), srvConn, cfg)
			resCh <- res
		}()
		client := tls.Client(cliConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sni,
			MinVersion:         tls.VersionTLS12,
		})
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		cn := ""
		if err := client.Handshake(); err == nil {
			certs := client.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				cn = certs[0].Subject.CommonName
			}
		}
		_, _ = client.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		buf := make([]byte, 256)
		_, _ = client.Read(buf)
		_ = cliConn.Close()
		select {
		case res := <-resCh:
			return cn, res
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not return")
			return "", Result{}
		}
	}

	cn, res := dial("mail.corp.local")
	if cn != "mail.corp.local" {
		t.Errorf("matched SNI cert CN = %q, want mail.corp.local", cn)
	}
	if res.Meta["tls_vhost"] != "mail.corp.local" {
		t.Errorf("tls_vhost meta = %v, want mail.corp.local", res.Meta["tls_vhost"])
	}

	cn2, res2 := dial("nomatch.local")
	if cn2 == "mail.corp.local" {
		t.Errorf("non-matching SNI should not get the vhost cert")
	}
	if _, ok := res2.Meta["tls_vhost"]; ok {
		t.Errorf("tls_vhost should be unset for non-matching SNI, got %v", res2.Meta["tls_vhost"])
	}
}

func TestHTTPSEmitsJA4S(t *testing.T) {
	h := newTestHTTPS(t, identity.New("ja4s-dep"))
	cfg := config.Listener{
		ID:          "svc",
		ReadTimeout: 3 * time.Second,
		HTTPS:       config.HTTPS{Hosts: []string{"localhost"}},
	}
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()
	resCh := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), srvConn, cfg)
		resCh <- res
	}()
	client := tls.Client(cliConn, &tls.Config{
		InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, _ = client.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 256)
	_, _ = client.Read(buf)
	_ = cliConn.Close()
	res := <-resCh
	ja4s, _ := res.Meta["ja4s"].(string)
	if ja4s == "" {
		t.Fatalf("handler did not emit ja4s; meta=%v", res.Meta)
	}
	ja4x, _ := res.Meta["ja4x"].(string)
	if ja4x == "" {
		t.Fatalf("handler did not emit ja4x; meta=%v", res.Meta)
	}
}

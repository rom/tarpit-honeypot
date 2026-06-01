package decoygen

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startBanner spins up a TCP listener that writes a banner on connect, and
// returns its port.
func startBanner(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				_, _ = c.Write([]byte(banner))
			}
			c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return p
}

func TestScanFindsOpenPortAndClassifiesBanner(t *testing.T) {
	// A fake SSH server on a random (non-22) port: the banner must drive
	// classification to the ssh handler regardless of the port number.
	port := startBanner(t, "SSH-2.0-OpenSSH_9.6\r\n")

	res, err := Scan(context.Background(), Options{
		Targets:     []string{"127.0.0.1:" + strconv.Itoa(port)},
		Timeout:     2 * time.Second,
		GrabBanners: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Services) != 1 {
		t.Fatalf("services = %+v; want exactly one open port", res.Services)
	}
	svc := res.Services[0]
	if svc.Handler != "ssh" {
		t.Errorf("handler = %q; want ssh (banner-classified)", svc.Handler)
	}
	if !strings.Contains(svc.Banner, "OpenSSH") {
		t.Errorf("banner not captured: %q", svc.Banner)
	}
}

func TestScanClosedPortYieldsNothing(t *testing.T) {
	// Bind then immediately close to get a port that is almost certainly closed.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	res, err := Scan(context.Background(), Options{
		Targets: []string{"127.0.0.1:" + portStr},
		Timeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Services) != 0 {
		t.Errorf("expected no services on a closed port, got %+v", res.Services)
	}
}

func TestScanRejectsOversizedCIDR(t *testing.T) {
	_, err := Scan(context.Background(), Options{
		Targets:  []string{"10.0.0.0/8"},
		MaxHosts: 256,
	})
	if err == nil {
		t.Fatal("expected a scope-too-large error for a /8")
	}
}

func TestScanNoTargets(t *testing.T) {
	if _, err := Scan(context.Background(), Options{}); err == nil {
		t.Fatal("expected an error with no targets")
	}
}

func TestExpandCIDRSmall(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/30", 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 {
		t.Errorf("/30 expanded to %d addresses; want 4 (%v)", len(ips), ips)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9":              "ssh",
		"HTTP/1.1 200 OK":                "http",
		"220 ProFTPD 1.3.5 Server ready": "ftp",
		"220 mail.example.com ESMTP":     "smtp_recv",
		"+OK POP3 ready":                 "pop3",
		"-ERR unknown command":           "redis",
		"random junk":                    "",
	}
	for banner, want := range cases {
		if got := classify(0, banner); got != want {
			t.Errorf("classify(%q) = %q; want %q", banner, got, want)
		}
	}
}

func TestGenerateProducesValidYAMLShape(t *testing.T) {
	res := Result{
		Hosts: 2, Ports: 4,
		Services: []Service{
			{Host: "10.0.0.1", Port: 22, Handler: "ssh", Banner: "SSH-2.0-OpenSSH_9.6"},
			{Host: "10.0.0.2", Port: 22, Handler: "ssh"},
			{Host: "10.0.0.1", Port: 443, Handler: "https", TLS: true, CertCN: "intranet.corp"},
		},
	}
	out, err := Generate(res, GenOptions{Bind: "0.0.0.0", Archetype: "ubuntu-22"})
	if err != nil {
		t.Fatal(err)
	}
	// One listener per distinct port (22 deduped across the two hosts).
	if c := strings.Count(out, "proto: tcp"); c != 2 {
		t.Errorf("expected 2 listeners (ports 22, 443), got %d\n%s", c, out)
	}
	for _, want := range []string{"handler: ssh", "handler: https", "0.0.0.0:22", "0.0.0.0:443",
		"archetype: ubuntu-22", "cn: intranet.corp", "REVIEW BEFORE USE"} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config missing %q\n%s", want, out)
		}
	}
}

func TestJoinHostPortIPv6(t *testing.T) {
	if got := joinHostPort("::", 80); got != "[::]:80" {
		t.Errorf("joinHostPort(::,80) = %q; want [::]:80", got)
	}
	if got := joinHostPort("0.0.0.0", 80); got != "0.0.0.0:80" {
		t.Errorf("joinHostPort = %q; want 0.0.0.0:80", got)
	}
}

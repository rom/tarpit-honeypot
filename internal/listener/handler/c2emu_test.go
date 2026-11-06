package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func c2Probe(t *testing.T, reqLine, ua string) Result {
	t.Helper()
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := (c2Emulator{}).Handle(context.Background(), srv, config.Listener{ID: "c2", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	req := reqLine + "\r\nHost: cdn.example.com\r\n"
	if ua != "" {
		req += "User-Agent: " + ua + "\r\n"
	}
	req += "\r\n"
	_, _ = cli.Write([]byte(req))
	buf := make([]byte, 512)
	_, _ = cli.Read(buf) // drain the server reply so the handler finishes writing
	_ = cli.Close()
	return <-resCh
}

func TestC2EmulatorProfiles(t *testing.T) {
	cases := []struct {
		name, reqLine, ua, wantFW, wantKind string
	}{
		{"cobaltstrike-stager", "GET /aaa9 HTTP/1.1", "Mozilla/5.0", "cobaltstrike", "stager"},
		{"cobaltstrike-profile", "GET /submit.php?id=1776 HTTP/1.1", "curl/8", "cobaltstrike", "beacon-checkin"},
		{"empire", "GET /admin/get.php HTTP/1.1", "Mozilla/4.0", "empire", "beacon-checkin"},
		{"poshc2", "GET /images/static/content/x HTTP/1.1", "python-requests/2", "poshc2", "beacon-checkin"},
		{"metasploit", "GET /abcd HTTP/1.1", "Mozilla/4.0 (compatible; MSIE 6.0)", "metasploit", "stager"},
	}
	for _, c := range cases {
		res := c2Probe(t, c.reqLine, c.ua)
		if res.Meta["c2_framework"] != c.wantFW {
			t.Errorf("%s: c2_framework=%v want %s", c.name, res.Meta["c2_framework"], c.wantFW)
		}
		if res.Meta["c2_profile"] != c.wantKind {
			t.Errorf("%s: c2_profile=%v want %s", c.name, res.Meta["c2_profile"], c.wantKind)
		}
		if !metaHasAnomaly(res.Meta, "c2-beacon-checkin") {
			t.Errorf("%s: missing c2-beacon-checkin: %v", c.name, res.Meta["anomalies"])
		}
		if !metaHasAnomaly(res.Meta, "c2:"+c.wantFW) {
			t.Errorf("%s: missing c2:%s label", c.name, c.wantFW)
		}
	}
}

func TestC2EmulatorProbeNoMatch(t *testing.T) {
	res := c2Probe(t, "GET /index.html HTTP/1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	if _, ok := res.Meta["c2_framework"]; ok {
		t.Errorf("benign request matched a framework: %v", res.Meta["c2_framework"])
	}
	if !metaHasAnomaly(res.Meta, "c2-server-probe") {
		t.Errorf("missing c2-server-probe: %v", res.Meta["anomalies"])
	}
}

func TestC2CookieCapture(t *testing.T) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := (c2Emulator{}).Handle(context.Background(), srv, config.Listener{ID: "c2", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = cli.Write([]byte("GET /ca HTTP/1.1\r\nHost: x\r\nCookie: SESSIONID=bWV0YWRhdGE=\r\n\r\n"))
	buf := make([]byte, 256)
	_, _ = cli.Read(buf)
	_ = cli.Close()
	res := <-resCh
	if res.Meta["c2_framework"] != "cobaltstrike" {
		t.Fatalf("c2_framework=%v want cobaltstrike", res.Meta["c2_framework"])
	}
	if res.Meta["c2_cookie"] != "SESSIONID=bWV0YWRhdGE=" {
		t.Errorf("c2_cookie=%v", res.Meta["c2_cookie"])
	}
}

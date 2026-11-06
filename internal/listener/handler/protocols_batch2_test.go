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
)

func TestNNTPHandler(t *testing.T) {
	cli, resCh := runHandler(nntpH{})
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { _, _ = io.Copy(io.Discard, cli) }()
	for _, l := range []string{"AUTHINFO USER spammer\r\n", "AUTHINFO PASS hunter2\r\n", "POST\r\n", "QUIT\r\n"} {
		_, _ = cli.Write([]byte(l))
	}
	_ = cli.Close()
	res := <-resCh
	if res.Meta["nntp_user"] != "spammer" {
		t.Errorf("nntp_user=%v", res.Meta["nntp_user"])
	}
	for _, a := range []string{"nntp-auth", "nntp-post"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing %q: %v", a, res.Meta["anomalies"])
		}
	}
}

func TestIdentHandler(t *testing.T) {
	cli, resCh := runHandler(identH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = cli.Write([]byte("6667, 12345\r\n"))
	buf := make([]byte, 128)
	n, _ := cli.Read(buf)
	if !strings.Contains(string(buf[:n]), "USERID") {
		t.Errorf("ident reply=%q", string(buf[:n]))
	}
	_ = cli.Close()
	res := <-resCh
	if !metaHasAnomaly(res.Meta, "ident-query") {
		t.Errorf("missing ident-query: %v", res.Meta["anomalies"])
	}
}

func TestDLMSHandler(t *testing.T) {
	cli, resCh := runHandler(dlmsH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	// wrapper(version 0x0001, src 0x0010, dst 0x0001, len 4) + AARQ(0x60).
	_, _ = cli.Write([]byte{0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x04, 0x60, 0x02, 0x80, 0x00})
	br := bufio.NewReader(cli)
	rh := make([]byte, 8)
	if _, err := io.ReadFull(br, rh); err != nil {
		t.Fatalf("read wrapper: %v", err)
	}
	apdu0, _ := br.ReadByte()
	if apdu0 != 0x61 {
		t.Errorf("DLMS reply APDU tag=0x%02x want 0x61 (AARE)", apdu0)
	}
	_ = cli.Close()
	res := <-resCh
	if res.Meta["dlms_apdu"] != "AARQ" || !metaHasAnomaly(res.Meta, "ics-dlms-association") {
		t.Errorf("dlms meta=%v anomalies=%v", res.Meta["dlms_apdu"], res.Meta["anomalies"])
	}
}

func TestAFPHandler(t *testing.T) {
	cli, resCh := runHandler(afpH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	// DSI GetStatus: flags=0 (request), command=3, requestID=1, rest zero.
	_, _ = cli.Write([]byte{0x00, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	br := bufio.NewReader(cli)
	rh := make([]byte, 16)
	if _, err := io.ReadFull(br, rh); err != nil {
		t.Fatalf("read DSI reply: %v", err)
	}
	if rh[0] != 0x01 || rh[1] != 0x03 {
		t.Errorf("AFP reply header flags=0x%02x cmd=0x%02x want reply/GetStatus", rh[0], rh[1])
	}
	_ = cli.Close()
	res := <-resCh
	if !metaHasAnomaly(res.Meta, "afp-getstatus") {
		t.Errorf("missing afp-getstatus: %v", res.Meta["anomalies"])
	}
}

func TestBeanstalkdHandler(t *testing.T) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := (beanstalkdH{}).Handle(context.Background(), srv, config.Listener{ID: "b", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { _, _ = io.Copy(io.Discard, cli) }()
	for _, l := range []string{"use secrets\r\n", "stats\r\n", "put 0 0 10 3\r\n", "abc\r\n", "quit\r\n"} {
		_, _ = cli.Write([]byte(l))
	}
	_ = cli.Close()
	res := <-resCh
	if tubes, _ := res.Meta["beanstalkd_tubes"].([]string); len(tubes) == 0 || tubes[0] != "secrets" {
		t.Errorf("beanstalkd_tubes=%v", res.Meta["beanstalkd_tubes"])
	}
	for _, a := range []string{"beanstalkd-stats", "beanstalkd-put"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing %q: %v", a, res.Meta["anomalies"])
		}
	}
}

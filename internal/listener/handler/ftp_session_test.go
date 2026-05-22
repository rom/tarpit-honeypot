package handler

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

func TestFTPCapturesCredsThenPostAuth(t *testing.T) {
	h := &ftp{jit: jitter.New(0, 0), arch: &archetype.Profile{}}
	// First PASS fails (creds captured); the retry logs in; then abuse.
	in := "USER root\r\nPASS hunter2\r\nPASS hunter2\r\n" +
		"STOR evil.sh\r\nRETR /etc/passwd\r\nSITE EXEC id\r\nPORT 9,9,9,9,4,1\r\nQUIT\r\n"
	res := runConn(t, h, in)

	if res.Meta["user_line"] != "root" || res.Meta["pass_line"] != "hunter2" {
		t.Errorf("creds not captured: user=%v pass=%v", res.Meta["user_line"], res.Meta["pass_line"])
	}
	cmds, _ := res.Meta["ftp_commands"].([]string)
	if len(cmds) == 0 {
		t.Fatalf("no post-auth commands captured")
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	for _, want := range []string{"ftp-upload-attempt", "ftp-download-attempt", "ftp-site-command", "ftp-bounce-scan"} {
		if !containsStr(anoms, want) {
			t.Errorf("missing anomaly %q; got %v", want, anoms)
		}
	}
	if res.Meta["ftp_bounce_target"] != "9.9.9.9" {
		t.Errorf("bounce target = %v; want 9.9.9.9", res.Meta["ftp_bounce_target"])
	}
}

func TestPortCmdIP(t *testing.T) {
	if got := portCmdIP("192,168,1,5,200,21"); got != "192.168.1.5" {
		t.Errorf("portCmdIP = %q; want 192.168.1.5", got)
	}
	if got := portCmdIP("garbage"); got != "" {
		t.Errorf("portCmdIP(garbage) = %q; want empty", got)
	}
}

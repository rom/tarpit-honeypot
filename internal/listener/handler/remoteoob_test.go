package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// runServerFirst drives a server-speaks-first handler: it reads the handler's
// opening banner, sends clientReq, then reads any follow-up so the handler's
// writes never block on the synchronous test pipe.
func runServerFirst(t *testing.T, h Handler, clientReq []byte) (Result, []byte) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: h.Name(), ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = h.Handle(context.Background(), server, cfg) }()
	buf := make([]byte, 1024)
	n, _ := client.Read(buf) // opening banner
	banner := append([]byte(nil), buf[:n]...)
	_, _ = client.Write(clientReq)
	// Drain any follow-up the handler writes after reading our request.
	go func() {
		b := make([]byte, 1024)
		for {
			if _, err := client.Read(b); err != nil {
				return
			}
		}
	}()
	<-done
	client.Close()
	return res, banner
}

func TestRexecCapturesCredsAndCommand(t *testing.T) {
	req := []byte("0\x00root\x00s3cret\x00/bin/id\x00")
	res, _ := runDevsvc(t, &rexec{}, req)
	if res.Meta["username"] != "root" || res.Meta["password"] != "s3cret" {
		t.Errorf("creds not captured: %v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "rexec-command") {
		t.Errorf("anomalies = %v; want rexec-command", anoms)
	}
}

func TestRshCapturesUsersAndCommand(t *testing.T) {
	req := []byte("0\x00localuser\x00remoteroot\x00cat /etc/passwd\x00")
	res, _ := runDevsvc(t, &rsh{}, req)
	if res.Meta["remote_user"] != "remoteroot" {
		t.Errorf("remote_user not captured: %v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "rsh-command") {
		t.Errorf("anomalies = %v; want rsh-command", anoms)
	}
}

func TestSpiceLinkReply(t *testing.T) {
	req := append([]byte("REDQ"), make([]byte, 12)...)
	res, reply := runDevsvc(t, &spice{}, req)
	if len(reply) < 4 || string(reply[0:4]) != "REDQ" {
		t.Errorf("reply = %v; want a SpiceLinkReply (REDQ)", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "spice-probe") {
		t.Errorf("anomalies = %v; want spice-probe", anoms)
	}
}

func TestRadminProbe(t *testing.T) {
	res, _ := runDevsvc(t, &radmin{}, []byte{0x01, 0x00, 0x00, 0x00})
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "radmin-probe") {
		t.Errorf("anomalies = %v; want radmin-probe", anoms)
	}
}

func TestLantronixSetupBanner(t *testing.T) {
	res, banner := runServerFirst(t, &lantronix{}, []byte("\r\n"))
	if !strings.Contains(string(banner), "Lantronix") {
		t.Errorf("banner = %q; want a Lantronix setup banner", banner)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "lantronix-probe") {
		t.Errorf("anomalies = %v; want lantronix-probe", anoms)
	}
}

func TestTN3270Logon(t *testing.T) {
	res, banner := runServerFirst(t, &tn3270{}, []byte{0xff, 0xfd, 0x18})
	if len(banner) < 3 || banner[0] != 0xff {
		t.Errorf("banner = %v; want TN3270 IAC negotiation", banner)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "tn3270-probe") {
		t.Errorf("anomalies = %v; want tn3270-probe", anoms)
	}
}

func TestPcAnywhereAndDamewareProbes(t *testing.T) {
	res, _ := runServerFirst(t, &pcanywhere{}, []byte{0x00})
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "pcanywhere-probe") {
		t.Errorf("anomalies = %v; want pcanywhere-probe", anoms)
	}
	res2, _ := runServerFirst(t, &dameware{}, []byte{0x00})
	a2, _ := res2.Meta["anomalies"].([]string)
	if !containsStr(a2, "dameware-probe") {
		t.Errorf("anomalies = %v; want dameware-probe", a2)
	}
}

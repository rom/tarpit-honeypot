package handler

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

// The smtp_recv and ftp handlers now run the CVE signature catalog over their
// captured transcript, so a catalogued mail/FTP exploit attempt becomes a
// cve:<id> hit. These end-to-end tests confirm the wiring (not just the
// catalog).
func TestSMTPHandlerEmitsCVEHit(t *testing.T) {
	// OpenSMTPD MAIL FROM command injection (CVE-2020-7247).
	res := smtpDrive(t, []string{
		"HELO x",
		"MAIL FROM:<;sleep 7;>",
		"QUIT",
	})
	if !containsStr(res.CVEHits, "CVE-2020-7247") {
		t.Errorf("smtp CVEHits = %v; want CVE-2020-7247", res.CVEHits)
	}
}

func TestFTPHandlerEmitsCVEHit(t *testing.T) {
	// ProFTPD mod_copy SITE CPFR (CVE-2015-3306).
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ftp", ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := (&ftp{jit: jitter.New(0, 0), id: identity.New("ftp-cve")}).Handle(context.Background(), server, cfg)
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
	for _, l := range []string{"USER anonymous", "PASS x@x", "SITE CPFR /etc/passwd", "QUIT"} {
		_, _ = client.Write([]byte(l + "\r\n"))
		time.Sleep(15 * time.Millisecond)
	}
	_ = client.Close()
	select {
	case r := <-resC:
		if !containsStr(r.CVEHits, "CVE-2015-3306") {
			t.Errorf("ftp CVEHits = %v; want CVE-2015-3306", r.CVEHits)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ftp handler did not return")
	}
}

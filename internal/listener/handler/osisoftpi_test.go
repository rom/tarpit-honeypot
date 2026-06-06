package handler

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestOSIsoftPIIdentifies(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "osisoft_pi", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&osisoftPI{}).Handle(context.Background(), server, cfg) }()
	// A PI client opening message (opaque); the handler captures + greets.
	_, _ = client.Write([]byte{0x01, 0x00, 0x00, 0x08, 'P', 'I', 'N', 'E', 'T'})
	out := make([]byte, 128)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(out)
	client.Close()
	<-done
	if n < 4 || out[0] != 'P' || out[1] != 'I' {
		t.Errorf("reply not a PI ident frame: % x", out[:n])
	}
	if res.Meta["pi_version"] == nil {
		t.Errorf("no PI version captured: %v", res.Meta)
	}
	if !hasAnom(res, "ics-historian-access") {
		t.Errorf("historian access not flagged: %v", res.Meta["anomalies"])
	}
}

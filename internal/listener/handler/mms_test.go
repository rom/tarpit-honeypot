package handler

import (
	"bufio"
	"context"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func readTPKTFrame(t *testing.T, br *bufio.Reader) []byte {
	t.Helper()
	h := make([]byte, 4)
	if _, err := io.ReadFull(br, h); err != nil {
		return nil
	}
	n := int(h[2])<<8 | int(h[3])
	if n < 4 || n > 8192 {
		return nil
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil
	}
	return append(h, body...)
}

func TestMMS(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&mms{}).Handle(context.Background(), server, cfg); resC <- r }()

	// COTP Connection Request (TPKT total 0x16).
	cr := []byte{
		0x03, 0x00, 0x00, 0x16,
		0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
		0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02,
	}
	if _, err := client.Write(cr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	cc := readTPKTFrame(t, br)
	if cc == nil || cc[5] != 0xd0 { // COTP CC type
		t.Fatalf("no Connection Confirm: % x", cc)
	}
	// Send an MMS/AARQ data PDU.
	_, _ = client.Write([]byte{0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, 0x61})
	if aare := readTPKTFrame(t, br); aare == nil {
		t.Fatal("no AARE response")
	}
	_ = client.Close()
	r := <-resC
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "ics-mms-probe") {
		t.Errorf("anomalies = %v; want ics-mms-probe", r.Meta["anomalies"])
	}
}

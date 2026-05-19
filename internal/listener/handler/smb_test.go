package handler

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// buildSMBNegotiateReq makes a minimal SMB1 Negotiate Protocol Request that
// offers NT LM 0.12. Wire layout matches what Windows clients actually send.
func buildSMBNegotiateReq() []byte {
	dialectField := []byte{0x02}
	dialectField = append(dialectField, []byte("NT LM 0.12")...)
	dialectField = append(dialectField, 0)

	smb := make([]byte, 32, 32+3+len(dialectField))
	smb[0] = 0xFF
	smb[1] = 'S'
	smb[2] = 'M'
	smb[3] = 'B'
	smb[4] = 0x72 // Negotiate
	smb[9] = 0x18 // flags (canonicalized paths + case)
	binary.LittleEndian.PutUint16(smb[10:12], 0xC807)

	smb = append(smb, 0x00) // WordCount = 0
	smb = binary.LittleEndian.AppendUint16(smb, uint16(len(dialectField)))
	smb = append(smb, dialectField...)

	nbss := make([]byte, 4)
	binary.BigEndian.PutUint32(nbss, uint32(len(smb)))
	return append(nbss, smb...)
}

func TestSMB1NegotiateRoundTrip(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "smb", ReadBytes: 4096, ReadTimeout: time.Second}

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&smb{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(buildSMBNegotiateReq()); err != nil {
		t.Fatal(err)
	}
	// Read response NBSS header first.
	hdr := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	respLen := binary.BigEndian.Uint32(hdr)
	body := make([]byte, respLen)
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}
	if string(body[0:4]) != "\xFFSMB" {
		t.Errorf("response not SMB1: %x", body[0:4])
	}
	if body[4] != 0x72 {
		t.Errorf("response command = %x; want 0x72", body[4])
	}
	if body[9]&0x80 == 0 {
		t.Errorf("response flag bit not set (should be flagged as response): %x", body[9])
	}
	client.Close()
	<-done
	if res.Meta["variant"] != "SMB1" {
		t.Errorf("variant: %v", res.Meta["variant"])
	}
	if dialects, ok := res.Meta["dialects"].([]string); !ok || len(dialects) != 1 || dialects[0] != "NT LM 0.12" {
		t.Errorf("dialects: %v", res.Meta["dialects"])
	}
}

func TestSMB2GetsRejection(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "smb", ReadBytes: 4096, ReadTimeout: time.Second}

	// SMB2 Negotiate frame: NBSS + "\xFESMB" magic.
	body := []byte{0xFE, 'S', 'M', 'B', 0x40, 0x00, 0x00, 0x00}
	// Pad out to typical SMB2 NEGOTIATE size (just need length >= 32 for our parser).
	for len(body) < 64 {
		body = append(body, 0)
	}
	nbss := make([]byte, 4)
	binary.BigEndian.PutUint32(nbss, uint32(len(body)))

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&smb{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(append(nbss, body...)); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	respLen := binary.BigEndian.Uint32(hdr)
	respBody := make([]byte, respLen)
	if _, err := io.ReadFull(client, respBody); err != nil {
		t.Fatal(err)
	}
	// Status field should be STATUS_NOT_SUPPORTED (0xC0000002 little-endian
	// at offset 5..9). The rejection builder writes 00 00 C0 02.
	if respBody[8] != 0xC0 {
		t.Errorf("status high byte = %x; want 0xC0 (STATUS_NOT_SUPPORTED)", respBody[8])
	}
	client.Close()
	<-done
	if res.Meta["variant"] != "SMB2" {
		t.Errorf("variant: %v", res.Meta["variant"])
	}
}

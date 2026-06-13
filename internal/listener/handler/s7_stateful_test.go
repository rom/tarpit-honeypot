package handler

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// driveS7Capture runs the S7 handler over a pipe, returning everything it
// writes back. It appends a short terminator frame so the handler breaks its
// read loop and returns *after* flushing every response — closing the client
// the instant the request is consumed would race the handler's final write
// (which is why driveDrain, that only inspects Meta, never had to).
func driveS7Capture(t *testing.T, send []byte) []byte {
	t.Helper()
	client, server := pipePair(t)
	var out bytes.Buffer
	rdone := make(chan struct{})
	go func() { defer close(rdone); _, _ = io.Copy(&out, client) }()
	hdone := make(chan struct{})
	go func() {
		defer close(hdone)
		_, _ = (&s7{}).Handle(context.Background(), server, config.Listener{ReadTimeout: time.Second})
	}()
	send = append(append([]byte{}, send...), s7Frame([]byte{0x00})...) // terminator (non-S7 DT)
	if _, err := client.Write(send); err != nil && err != io.ErrClosedPipe {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-hdone:
	case <-time.After(3 * time.Second):
		t.Fatal("s7 handler timeout")
	}
	_ = client.Close()
	<-rdone
	return out.Bytes()
}

func s7Frame(pdu []byte) []byte {
	total := 4 + 3 + len(pdu) // TPKT(4) + COTP DT(3) + S7 PDU
	f := []byte{0x03, 0x00, byte(total >> 8), byte(total), 0x02, 0xF0, 0x80}
	return append(f, pdu...)
}

var (
	s7CR = []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}

	s7Setup = []byte{0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80,
		0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
		0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0}

	// Write Var: WORD 0xBEEF -> DB1.DBB0 (2 bytes @ area DB, db 1, byte 0).
	s7WriteVarPDU = []byte{
		0x32, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0E, 0x00, 0x06, // parlen 14, datlen 6
		0x05, 0x01, // Write Var, 1 item
		0x12, 0x0A, 0x10, 0x02, 0x00, 0x02, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00, // BYTE x2 @ DB1.0
		0x00, 0x04, 0x00, 0x10, 0xBE, 0xEF, // data: 16-bit value 0xBEEF
	}

	// Read Var: 2 bytes @ DB1.DBB0 (same address as the write above).
	s7ReadVarPDU = []byte{
		0x32, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x00, // parlen 14, datlen 0
		0x04, 0x01, // Read Var, 1 item
		0x12, 0x0A, 0x10, 0x02, 0x00, 0x02, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00, // BYTE x2 @ DB1.0
	}

	// The data item a Read Var returns for the address: success, BYTE transport,
	// 16-bit length, then the 2 value bytes.
	s7WrittenItem   = []byte{0xFF, 0x04, 0x00, 0x10, 0xBE, 0xEF} // reflects the write
	s7SyntheticItem = []byte{0xFF, 0x04, 0x00, 0x10, 0x03, 0xE8} // synthetic default (1000)
)

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// A value written with Write Var must come back on a later Read Var of the
// same address within the session.
func TestS7WriteThenReadCoherent(t *testing.T) {
	out := driveS7Capture(t, concatBytes(s7CR, s7Setup, s7Frame(s7WriteVarPDU), s7Frame(s7ReadVarPDU)))
	if !bytes.Contains(out, s7WrittenItem) {
		t.Errorf("Read Var did not reflect the prior Write Var (0xBEEF):\n% x", out)
	}
}

// Without a prior write, the same Read Var returns the synthetic value, not
// 0xBEEF — proving the coherence test above isn't a coincidence.
func TestS7ReadWithoutWriteSynthetic(t *testing.T) {
	out := driveS7Capture(t, concatBytes(s7CR, s7Setup, s7Frame(s7ReadVarPDU)))
	if bytes.Contains(out, []byte{0xBE, 0xEF}) {
		t.Errorf("Read Var returned 0xBEEF with no prior write:\n% x", out)
	}
	if !bytes.Contains(out, s7SyntheticItem) {
		t.Errorf("Read Var missing the synthetic data item:\n% x", out)
	}
}

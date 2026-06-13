package handler

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- pure application-layer logic ---

// OPERATE a binary output (CROB latch-on) then READ Binary Output Status: the
// operated point must read back energized — the write-then-read-back coherence.
func TestDNP3OperateThenReadCoherent(t *testing.T) {
	mem := newDNP3Mem()
	crob := []byte{0x03, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x00} // op=LATCH_ON, count1, times, status0
	operate := append([]byte{0x0C, 0x01, 0x17, 0x01, 0x05}, crob...)
	dnp3ControlResponse(operate, mem, 0, true)
	if !mem.binOutGet(5) {
		t.Fatalf("CROB latch-on did not energize binary output 5")
	}
	resp := dnp3ReadResponse([]byte{0x0A, 0x02, 0x00, 0x00, 0x07}, mem, 0) // read g10 0..7
	obj := resp[4:]                                                        // skip app-control, func, IIN(2)
	if len(obj) < 5+8 || obj[0] != 0x0A {
		t.Fatalf("expected a group-10 object: % x", obj)
	}
	if flag5 := obj[5+5]; flag5&0x80 == 0 { // header(5) + point index 5
		t.Errorf("binary output 5 not reflected ON in g10 read: flag=0x%02X", flag5)
	}
	if flag4 := obj[5+4]; flag4&0x80 != 0 { // an un-operated point stays OFF
		t.Errorf("binary output 4 unexpectedly ON: flag=0x%02X", flag4)
	}
}

// SELECT (without OPERATE) must NOT actuate.
func TestDNP3SelectDoesNotActuate(t *testing.T) {
	mem := newDNP3Mem()
	crob := []byte{0x03, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x00}
	sel := append([]byte{0x0C, 0x01, 0x17, 0x01, 0x02}, crob...)
	dnp3ControlResponse(sel, mem, 0, false) // apply=false for SELECT
	if mem.binOutGet(2) {
		t.Errorf("SELECT actuated output 2; it should only arm")
	}
}

// An analog output operate (AOB 16-bit) reflects in a group-40 read.
func TestDNP3AnalogOperateThenRead(t *testing.T) {
	mem := newDNP3Mem()
	aob := []byte{0x34, 0x12, 0x00} // value 0x1234 LE + status0
	operate := append([]byte{0x29, 0x02, 0x17, 0x01, 0x03}, aob...)
	dnp3ControlResponse(operate, mem, 0, true)
	resp := dnp3ReadResponse([]byte{0x28, 0x02, 0x00, 0x00, 0x07}, mem, 0) // read g40 0..7
	obj := resp[4:]
	if obj[0] != 0x28 {
		t.Fatalf("expected a group-40 object: % x", obj)
	}
	// header(5) then per point: flag(1)+value(2). point 3 value at 5 + 3*3 + 1.
	base := 5 + 3*3
	if got := binary.LittleEndian.Uint16(obj[base+1 : base+3]); got != 0x1234 {
		t.Errorf("analog output 3 = 0x%04X; want 0x1234", got)
	}
}

// A class-0 READ returns the full static image (groups 1, 10, 30, 40).
func TestDNP3ReadClass0Groups(t *testing.T) {
	resp := dnp3ReadResponse([]byte{0x3C, 0x01, 0x06}, newDNP3Mem(), 0)
	if resp[1] != 0x81 {
		t.Fatalf("not a RESPONSE (0x81): % x", resp[:4])
	}
	body := resp[4:]
	for _, g := range []byte{0x01, 0x0A, 0x1E, 0x28} {
		found := false
		for i := 0; i+1 < len(body); i++ {
			if body[i] == g && body[i+1] == 0x02 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("class-0 response missing group 0x%02X", g)
		}
	}
}

// Malformed control objects must be echoed verbatim, never panic.
func TestDNP3ControlMalformedSafe(t *testing.T) {
	mem := newDNP3Mem()
	// unknown qualifier 0x99 -> echo as-is, no overlay change, no panic.
	resp := dnp3ControlResponse([]byte{0x0C, 0x01, 0x99, 0xAA, 0xBB}, mem, 0, true)
	if len(resp) < 4 {
		t.Fatalf("short response")
	}
	if len(mem.binOut) != 0 {
		t.Errorf("malformed control mutated the overlay")
	}
}

// --- framing: every block carries a valid DNP3 CRC ---

func TestDNP3WrapAppFraming(t *testing.T) {
	frame := dnp3WrapApp(1, 10, dnp3NullResponse(0))
	if frame[0] != 0x05 || frame[1] != 0x64 {
		t.Fatalf("bad start octets: % x", frame[:2])
	}
	if frame[3] != 0x44 {
		t.Errorf("control byte = 0x%02X; want 0x44 (outstation UNCONFIRMED_USER_DATA)", frame[3])
	}
	if binary.LittleEndian.Uint16(frame[4:6]) != 1 || binary.LittleEndian.Uint16(frame[6:8]) != 10 {
		t.Errorf("addresses wrong: % x", frame[4:8])
	}
	if binary.LittleEndian.Uint16(frame[8:10]) != dnp3CRC(frame[0:8]) {
		t.Errorf("header CRC invalid")
	}
	// user = transport(1) + null-response(4) = 5 bytes; LEN = 5 + 5 = 10.
	if frame[2] != 10 {
		t.Errorf("LEN = %d; want 10", frame[2])
	}
	user := frame[10:]
	if len(user) != 7 { // 5 data + 2 CRC
		t.Fatalf("user block = %d bytes; want 7", len(user))
	}
	if binary.LittleEndian.Uint16(user[5:7]) != dnp3CRC(user[0:5]) {
		t.Errorf("block CRC invalid")
	}
}

// A large (multi-block) response must have a valid CRC on every 16-byte block.
func TestDNP3MultiBlockCRC(t *testing.T) {
	frame := dnp3WrapApp(1, 10, dnp3ReadResponse([]byte{0x3C, 0x01, 0x06}, newDNP3Mem(), 0))
	user := frame[10:]
	if len(user) <= 18 {
		t.Fatalf("expected a multi-block response, got %d user bytes", len(user))
	}
	for off := 0; off < len(user); off += 18 {
		end := off + 18
		if end > len(user) {
			end = len(user)
		}
		blk := user[off:end]
		if len(blk) < 3 {
			t.Fatalf("runt block at %d", off)
		}
		dataLen := len(blk) - 2
		if binary.LittleEndian.Uint16(blk[dataLen:]) != dnp3CRC(blk[:dataLen]) {
			t.Errorf("block at offset %d has an invalid CRC", off)
		}
	}
}

// --- end-to-end through Handle ---

func dnp3Request(dest, src uint16, ctrl byte, app []byte) []byte {
	user := append([]byte{0xC0}, app...)
	hdr := []byte{0x05, 0x64, byte(5 + len(user)), ctrl}
	hdr = binary.LittleEndian.AppendUint16(hdr, dest)
	hdr = binary.LittleEndian.AppendUint16(hdr, src)
	hdr = binary.LittleEndian.AppendUint16(hdr, dnp3CRC(hdr))
	out := append([]byte{}, hdr...)
	for off := 0; off < len(user); off += 16 {
		end := off + 16
		if end > len(user) {
			end = len(user)
		}
		out = append(out, user[off:end]...)
		out = binary.LittleEndian.AppendUint16(out, dnp3CRC(user[off:end]))
	}
	return out
}

func dnp3Deblock(frame []byte) []byte {
	if len(frame) < 10 {
		return nil
	}
	user := frame[10:]
	var data []byte
	for off := 0; off < len(user); off += 18 {
		end := off + 18
		if end > len(user) {
			end = len(user)
		}
		if end-off <= 2 {
			break
		}
		data = append(data, user[off:end-2]...)
	}
	return data
}

func TestDNP3ReadResponseE2E(t *testing.T) {
	client, server := loopbackPair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&dnp3{}).Handle(context.Background(), server, cfg) }()

	// UNCONFIRMED_USER_DATA (ctrl 0xC4) carrying app READ of Class 0.
	if _, err := client.Write(dnp3Request(10, 1, 0xC4, []byte{0xC1, 0x01, 0x3C, 0x01, 0x06})); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done

	if n < 10 || buf[0] != 0x05 || buf[1] != 0x64 {
		t.Fatalf("no DNP3 frame in response: n=%d", n)
	}
	if data := dnp3Deblock(buf[:n]); len(data) < 3 || data[2] != 0x81 {
		t.Errorf("response is not an application RESPONSE (0x81): % x", data)
	}
	if !hasAnom(res, "ics-process-data-access") {
		t.Errorf("READ not flagged: %v", res.Meta["anomalies"])
	}
}

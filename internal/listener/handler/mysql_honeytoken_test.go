package handler

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// mysqlSaltFromHandshake extracts the 20-byte native_password salt (auth-plugin
// data part1 + part2) from a server handshake body.
func mysqlSaltFromHandshake(body []byte) []byte {
	// body[0]=proto(0x0a), then version\0, connid(4), salt1(8), filler(1),
	// caplow(2), charset(1), status(2), caphigh(2), authlen(1), reserved(10),
	// salt2(12), \0.
	i := 1
	for i < len(body) && body[i] != 0 {
		i++
	}
	off := i + 1 + 4 // skip version NUL + connid
	salt1 := body[off : off+8]
	s2 := off + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	salt2 := body[s2 : s2+12]
	return append(append([]byte{}, salt1...), salt2...)
}

// mysqlScramble computes the mysql_native_password client response.
func mysqlScramble(pw string, salt []byte) []byte {
	h1 := sha1.Sum([]byte(pw))
	h2 := sha1.Sum(h1[:])
	hh := sha1.New()
	hh.Write(salt[:20])
	hh.Write(h2[:])
	tok := hh.Sum(nil)
	out := make([]byte, sha1.Size)
	for i := range out {
		out[i] = h1[i] ^ tok[i]
	}
	return out
}

func TestMySQLHoneytokenLoginAccepted(t *testing.T) {
	id := identity.New("deploy-xyz")
	wantPass := webappHoneyCreds(id).dbPass

	client, server := pipePair(t)
	cfg := config.Listener{Handler: "mysql", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&mysql{id: id}).Handle(context.Background(), server, cfg) }()

	hdr := make([]byte, 4)
	_, _ = io.ReadFull(client, hdr)
	blen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	body := make([]byte, blen)
	_, _ = io.ReadFull(client, body)
	salt := mysqlSaltFromHandshake(body)

	// Client response: user intranet_app + correct native scramble, no DB.
	scr := mysqlScramble(wantPass, salt)
	rb := make([]byte, 0, 96)
	rb = binary.LittleEndian.AppendUint32(rb, 0x000a8200) // caps incl. PLUGIN_AUTH (0x80000)
	rb = binary.LittleEndian.AppendUint32(rb, 16777216)
	rb = append(rb, 0x21)
	rb = append(rb, make([]byte, 23)...)
	rb = append(rb, []byte(webDBUser)...)
	rb = append(rb, 0)
	rb = append(rb, byte(len(scr)))
	rb = append(rb, scr...)
	pkt := make([]byte, 4+len(rb))
	pkt[0] = byte(len(rb))
	pkt[1] = byte(len(rb) >> 8)
	pkt[2] = byte(len(rb) >> 16)
	pkt[3] = 1
	copy(pkt[4:], rb)
	_, _ = client.Write(pkt)

	// Expect an OK packet (marker 0x00), then send COM_QUIT.
	ok := make([]byte, 11)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := io.ReadFull(client, ok)
	if n < 5 || ok[4] != 0x00 {
		t.Errorf("expected OK packet (0x00 marker); got % x", ok[:n])
	}
	_ = client.Close()
	<-done
	if res.Meta["auth_accepted"] != true {
		t.Errorf("honeytoken login not accepted: %v", res.Meta)
	}
	if !hasAnom(res, "mysql-honeytoken-auth") {
		t.Errorf("honeytoken auth not flagged: %v", res.Meta["anomalies"])
	}
}

func TestMySQLWrongPasswordDenied(t *testing.T) {
	id := identity.New("deploy-xyz")
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "mysql", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&mysql{id: id}).Handle(context.Background(), server, cfg) }()
	hdr := make([]byte, 4)
	_, _ = io.ReadFull(client, hdr)
	blen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	_, _ = io.ReadFull(client, make([]byte, blen))
	// intranet_app but a WRONG 20-byte scramble.
	rb := make([]byte, 0, 96)
	rb = binary.LittleEndian.AppendUint32(rb, 0x000a8200)
	rb = binary.LittleEndian.AppendUint32(rb, 16777216)
	rb = append(rb, 0x21)
	rb = append(rb, make([]byte, 23)...)
	rb = append(rb, []byte(webDBUser)...)
	rb = append(rb, 0, 20)
	rb = append(rb, make([]byte, 20)...) // all-zero (wrong) scramble
	pkt := make([]byte, 4+len(rb))
	pkt[0] = byte(len(rb))
	pkt[3] = 1
	copy(pkt[4:], rb)
	_, _ = client.Write(pkt)
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done
	if n >= 5 && buf[4] == 0x00 {
		t.Error("wrong password should be denied (ERR), not OK")
	}
	if res.Meta["auth_accepted"] == true {
		t.Error("wrong password must not be accepted")
	}
}

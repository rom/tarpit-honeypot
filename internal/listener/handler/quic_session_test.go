package handler

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// TestQUICRetryIntegrityTagRFCVector checks the Retry Integrity Tag against the
// published RFC 9001 Appendix A.4 test vector — the authoritative correctness
// check for the Retry crypto we emit.
func TestQUICRetryIntegrityTagRFCVector(t *testing.T) {
	odcid := mustHex(t, "8394c8f03e515708")
	// The Retry packet from A.4 without its 16-byte integrity tag:
	// ff 00000001 00 08 f067a5502a4262b5 746f6b656e ("token").
	retryNoTag := mustHex(t, "ff000000010008f067a5502a4262b5746f6b656e")
	tag, ok := quicRetryIntegrityTag(0x00000001, odcid, retryNoTag)
	if !ok {
		t.Fatal("quicRetryIntegrityTag failed for v1")
	}
	if got := hex.EncodeToString(tag); got != "04a265ba2eff4d829058fb3f0f2496ba" {
		t.Fatalf("retry integrity tag = %s; want RFC 9001 A.4 vector", got)
	}
}

// quicEncVarint encodes a QUIC variable-length integer (test helper).
func quicEncVarint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	default:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

// cryptoFrame builds a QUIC CRYPTO frame (test helper).
func cryptoFrame(off int, data []byte) []byte {
	f := []byte{0x06}
	f = append(f, quicEncVarint(uint64(off))...)
	f = append(f, quicEncVarint(uint64(len(data)))...)
	return append(f, data...)
}

// buildInitialFrames builds a QUIC Initial packet carrying arbitrary frames,
// with a chosen SCID + token, padded to at least minLen bytes (test helper).
func buildInitialFrames(t *testing.T, version uint32, dcid, scid, token, frames []byte, minLen int) []byte {
	t.Helper()
	salt, ok := quicSaltFor(version)
	if !ok {
		t.Fatalf("no salt for version %#x", version)
	}
	key, iv, hp, err := quicInitialKeys(salt, dcid)
	if err != nil {
		t.Fatal(err)
	}
	const pnLen = 1
	const pn = byte(0)

	build := func(payload []byte) []byte {
		payloadLen := pnLen + len(payload) + 16 // PN + frames + AEAD tag
		hdr := []byte{0xc0 | byte(pnLen-1)}
		ver := make([]byte, 4)
		binary.BigEndian.PutUint32(ver, version)
		hdr = append(hdr, ver...)
		hdr = append(hdr, byte(len(dcid)))
		hdr = append(hdr, dcid...)
		hdr = append(hdr, byte(len(scid)))
		hdr = append(hdr, scid...)
		hdr = append(hdr, quicEncVarint(uint64(len(token)))...)
		hdr = append(hdr, token...)
		hdr = append(hdr, quicEncVarint(uint64(payloadLen))...)
		pnOffset := len(hdr)
		hdr = append(hdr, pn)

		block, _ := aes.NewCipher(key)
		aead, _ := cipher.NewGCM(block)
		nonce := make([]byte, len(iv))
		copy(nonce, iv) // pn=0 → nonce == iv
		sealed := aead.Seal(nil, nonce, payload, hdr)
		pkt := append(append([]byte(nil), hdr...), sealed...)

		sampleOff := pnOffset + 4
		hpBlock, _ := aes.NewCipher(hp)
		mask := make([]byte, 16)
		hpBlock.Encrypt(mask, pkt[sampleOff:sampleOff+16])
		pkt[0] ^= mask[0] & 0x0f
		for i := 0; i < pnLen; i++ {
			pkt[pnOffset+i] ^= mask[1+i]
		}
		return pkt
	}

	payload := append([]byte(nil), frames...)
	for len(payload) < 64 { // ensure the HP sample is present
		payload = append(payload, 0x00) // PADDING
	}
	pkt := build(payload)
	for len(pkt) < minLen {
		payload = append(payload, 0x00) // PADDING frames lift the datagram size
		pkt = build(payload)
	}
	return pkt
}

// TestQUICSessionReassemblesFragmentedClientHello proves the session path
// reassembles a ClientHello split across two Initial datagrams — something the
// stateless single-datagram path cannot do.
func TestQUICSessionReassemblesFragmentedClientHello(t *testing.T) {
	ch := richTLSClientHello("h3.example.com", []string{"h3"})
	dcid := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	split := len(ch) / 2

	// Two Initials (same DCID) carrying CRYPTO at offsets 0 and split. Keep them
	// small so the Retry path doesn't engage (this isolates reassembly).
	d1 := buildInitialFrames(t, 0x00000001, dcid, nil, nil, cryptoFrame(0, ch[:split]), 100)
	d2 := buildInitialFrames(t, 0x00000001, dcid, nil, nil, cryptoFrame(split, ch[split:]), 100)

	pc := &chanPacketConn{wrote: make(chan []byte, 4)}
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 4), Port: 50000}
	sess := NewUDPSession(src, pc, 64)
	sess.Deliver(d1)
	sess.Deliver(d2)
	sess.Close()

	res, _ := (&quicH{}).HandleSession(context.Background(), sess, config.Listener{Handler: "quic", ReadTimeout: 500 * time.Millisecond})

	if res.Meta["quic_sni"] != "h3.example.com" {
		t.Errorf("reassembled SNI = %v; want h3.example.com (datagrams=%v)", res.Meta["quic_sni"], res.Meta["quic_datagrams"])
	}
	if res.Meta["http3"] != true {
		t.Errorf("expected http3 from ALPN h3; meta=%v", res.Meta)
	}
	if res.Meta["ja4"] != fingerprint.JA4(ch) {
		t.Errorf("ja4 over reassembled CH = %v; want %v", res.Meta["ja4"], fingerprint.JA4(ch))
	}
}

// TestQUICSessionRetryAndAddressValidation drives the full Retry exchange: the
// session issues a Retry for a >=1200-byte Initial, and a retried Initial that
// echoes the token is recognised as an address-validated source.
func TestQUICSessionRetryAndAddressValidation(t *testing.T) {
	defer SetReplyPolicy("full", false)
	SetReplyPolicy("full", false) // default policy: amplifier replies allowed

	ch := richTLSClientHello("quic.example.net", []string{"h3"})
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44}
	initial := buildInitialFrames(t, 0x00000001, dcid, scid, nil, cryptoFrame(0, ch), 1300)

	pc := &chanPacketConn{wrote: make(chan []byte, 4)}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 443}
	sess := NewUDPSession(src, pc, 64)
	sess.Deliver(initial)

	resCh := make(chan Result, 1)
	go func() {
		r, _ := (&quicH{}).HandleSession(context.Background(), sess, config.Listener{Handler: "quic", ReadTimeout: time.Second})
		resCh <- r
	}()

	// Grab the Retry, confirm it is well-formed, and extract its SCID + token.
	var retry []byte
	select {
	case retry = <-pc.wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not emit a Retry")
	}
	rv, rdcid, rscid, token := parseRetryPacket(t, retry)
	if rv != 0x00000001 {
		t.Errorf("retry version = %#x", rv)
	}
	// The Retry's DCID must echo the client's SCID.
	if hex.EncodeToString(rdcid) != hex.EncodeToString(scid) {
		t.Errorf("retry DCID = %x; want client SCID %x", rdcid, scid)
	}
	if len(token) == 0 {
		t.Fatal("retry carried no token")
	}

	// The client retries: new DCID = the Retry's SCID, echoing the token.
	retried := buildInitialFrames(t, 0x00000001, rscid, scid, token, cryptoFrame(0, ch), 1300)
	sess.Deliver(retried)
	sess.Close()

	res := <-resCh
	if res.Meta["quic_retry_issued"] != true {
		t.Errorf("expected quic_retry_issued; meta=%v", res.Meta)
	}
	if res.Meta["quic_address_validated"] != true {
		t.Errorf("retried token echo should validate the address; meta=%v", res.Meta)
	}
	if res.Meta["quic_sni"] != "quic.example.net" {
		t.Errorf("SNI = %v; want quic.example.net", res.Meta["quic_sni"])
	}
}

// TestQUICSessionRetrySuppressedUnderNoAmplifier confirms the no-amplifier reply
// policy suppresses the Retry while still capturing the ClientHello.
func TestQUICSessionRetrySuppressedUnderNoAmplifier(t *testing.T) {
	defer SetReplyPolicy("full", false)
	SetReplyPolicy("full", true) // suppress amplifier replies

	ch := richTLSClientHello("noamp.example", []string{"h3"})
	dcid := []byte{0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02}
	initial := buildInitialFrames(t, 0x00000001, dcid, []byte{0xab, 0xcd}, nil, cryptoFrame(0, ch), 1300)

	pc := &chanPacketConn{wrote: make(chan []byte, 4)}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443}
	sess := NewUDPSession(src, pc, 64)
	sess.Deliver(initial)
	sess.Close()

	res, _ := (&quicH{}).HandleSession(context.Background(), sess, config.Listener{Handler: "quic", ReadTimeout: 500 * time.Millisecond})
	if res.Meta["quic_retry_suppressed"] != true {
		t.Errorf("expected quic_retry_suppressed under no-amplifier policy; meta=%v", res.Meta)
	}
	if len(pc.wrote) != 0 {
		t.Errorf("no Retry should be written under suppression; got %d", len(pc.wrote))
	}
	if res.Meta["quic_sni"] != "noamp.example" {
		t.Errorf("capture should still work; SNI=%v", res.Meta["quic_sni"])
	}
}

// parseRetryPacket pulls the version, DCID, SCID, and token out of a Retry
// packet (test helper). Layout: first(1) ver(4) dcidlen(1) dcid scidlen(1) scid
// token tag(16).
func parseRetryPacket(t *testing.T, p []byte) (version uint32, dcid, scid, token []byte) {
	t.Helper()
	if len(p) < 7+16 {
		t.Fatalf("retry too short: %d", len(p))
	}
	version = binary.BigEndian.Uint32(p[1:5])
	off := 5
	dl := int(p[off])
	off++
	dcid = p[off : off+dl]
	off += dl
	sl := int(p[off])
	off++
	scid = p[off : off+sl]
	off += sl
	token = p[off : len(p)-16]
	return version, dcid, scid, token
}

// chanPacketConn is a net.PacketConn that publishes each WriteTo on a channel,
// so a test can react to a reply mid-session.
type chanPacketConn struct{ wrote chan []byte }

func (c *chanPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.wrote <- append([]byte(nil), b...)
	return len(b), nil
}
func (c *chanPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *chanPacketConn) Close() error                           { return nil }
func (c *chanPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{Port: 443} }
func (c *chanPacketConn) SetDeadline(time.Time) error            { return nil }
func (c *chanPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *chanPacketConn) SetWriteDeadline(time.Time) error       { return nil }

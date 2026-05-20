package handler

import (
	"encoding/binary"
	"net"
	"sync"
)

// captureConn wraps a net.Conn to record the leading bytes the *server*
// writes during a TLS handshake, so we can recover the ServerHello and
// compute its JA3S fingerprint. crypto/tls writes the ServerHello as the
// first outbound handshake record; we buffer outbound bytes up to max,
// then stop. Reads pass straight through to the wrapped conn.
type captureConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
	max int
}

func newCaptureConn(c net.Conn, max int) *captureConn {
	return &captureConn{Conn: c, max: max}
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) < c.max {
		room := c.max - len(c.buf)
		if room > len(b) {
			room = len(b)
		}
		c.buf = append(c.buf, b[:room]...)
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// serverHello returns the first ServerHello handshake message (bytes
// starting with handshake type 0x02) found in the captured outbound
// stream, or nil if none is present yet / the bytes are malformed.
func (c *captureConn) serverHello() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return firstServerHello(c.buf)
}

// firstServerHello scans concatenated TLS records for the first
// Handshake record (type 0x16) and returns the first handshake message
// inside it when that message is a ServerHello (type 0x02). The returned
// slice is type(1)+length(3)+body so it can be fed directly to
// fingerprint.JA3S.
func firstServerHello(buf []byte) []byte {
	p := 0
	for p+5 <= len(buf) {
		recType := buf[p]
		recLen := int(binary.BigEndian.Uint16(buf[p+3 : p+5]))
		if recLen <= 0 || p+5+recLen > len(buf) {
			return nil // record not fully captured
		}
		payload := buf[p+5 : p+5+recLen]
		if recType == 0x16 { // Handshake
			if len(payload) >= 4 && payload[0] == 0x02 { // ServerHello
				hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
				if 4+hsLen <= len(payload) {
					return payload[:4+hsLen]
				}
			}
			return nil
		}
		p += 5 + recLen
	}
	return nil
}

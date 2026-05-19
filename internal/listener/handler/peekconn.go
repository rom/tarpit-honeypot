package handler

import (
	"encoding/binary"
	"io"
	"net"
)

// peekConn wraps a net.Conn so we can read the leading TLS ClientHello
// record for fingerprinting without breaking the real TLS handshake.
// peekClientHello fills the internal buffer; later Read() calls drain
// the buffer first before delegating to the underlying connection.
//
// Only the first Read sequence is satisfied from buf; subsequent reads
// go straight through. That matches what crypto/tls does — it issues one
// Read for the record header (5 bytes) and then another for the rest.
type peekConn struct {
	net.Conn
	buf []byte // bytes we've already pulled off but not yet returned
}

func newPeekConn(c net.Conn) *peekConn {
	return &peekConn{Conn: c}
}

func (p *peekConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// peekClientHello pulls the leading TLS Handshake message off the wire
// (without consuming it from the caller's perspective) and returns the
// raw ClientHello bytes ready for JA3 / JA4 parsing.
//
// TLS record layout: type(1) version(2) length(2) -> Handshake bytes.
// We only care if type == 0x16 (Handshake).
func (p *peekConn) peekClientHello() ([]byte, bool) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(p.Conn, hdr); err != nil {
		return nil, false
	}
	p.buf = append(p.buf, hdr...)
	if hdr[0] != 0x16 {
		return nil, false
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > 65535 {
		return nil, false
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(p.Conn, body); err != nil {
		return nil, false
	}
	p.buf = append(p.buf, body...)
	return body, true
}

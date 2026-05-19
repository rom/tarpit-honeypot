package capture

import "net"

// Conn wraps a net.Conn so all bytes read and written flow through the
// associated Session. Wrap a connection in the listener as soon as it
// is accepted, before passing it to a handler.
type Conn struct {
	net.Conn
	Sess *Session
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.Sess.recordBytes(DirIn, p[:n])
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.Sess.recordBytes(DirOut, p[:n])
	}
	return n, err
}

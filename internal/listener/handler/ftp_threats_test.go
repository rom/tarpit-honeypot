package handler

import (
	"net"
	"testing"
	"time"
)

// nullConn is a net.Conn whose writes are discarded and reads block-then-EOF;
// enough to exercise ftpSession.reply without a real socket.
type nullConn struct{}

func (nullConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (nullConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nullConn) Close() error                     { return nil }
func (nullConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (nullConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (nullConn) SetDeadline(time.Time) error      { return nil }
func (nullConn) SetReadDeadline(time.Time) error  { return nil }
func (nullConn) SetWriteDeadline(time.Time) error { return nil }

func TestFTPPathTraversalHelper(t *testing.T) {
	for _, p := range []string{"../../etc/passwd", "..%2f..%2fetc", "dir\\..\\..\\x", "%2e%2e%2fboot"} {
		if !ftpPathTraversal(p) {
			t.Errorf("traversal not detected: %q", p)
		}
	}
	for _, p := range []string{"file.txt", "/pub/incoming/x.zip", "report-2024.pdf"} {
		if ftpPathTraversal(p) {
			t.Errorf("false positive: %q", p)
		}
	}
}

func TestFTPPostMarkers(t *testing.T) {
	mk := func(cmd, arg string) Result {
		res := Result{Meta: map[string]any{}}
		s := &ftpSession{conn: nullConn{}, res: &res, cwd: "/"}
		s.post(cmd, arg)
		return res
	}
	if r := mk("CWD", "../../../../etc"); !hasAnom(r, "ftp-path-traversal") {
		t.Errorf("CWD traversal not flagged: %v", r.Meta["anomalies"])
	}
	if r := mk("SITE", "EXEC /bin/sh -c id"); !hasAnom(r, "ftp-site-exec") {
		t.Errorf("SITE EXEC not flagged: %v", r.Meta["anomalies"])
	}
}

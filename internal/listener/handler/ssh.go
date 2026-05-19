package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

type ssh struct{}

func (s *ssh) Name() string { return "ssh" }

// SSH identification string per RFC 4253 §4.2. We send a believable banner,
// read the client's identification line, then (optionally) read one
// SSH_MSG_KEXINIT packet so we can compute the HASSH fingerprint, then
// send a fake "Protocol mismatch" and close.
func (s *ssh) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	banner := cfg.Banner
	if banner == "" {
		banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"
	}
	res := Result{BannerSent: banner}
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta = map[string]any{"write_err": err.Error()}
		return res, nil
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err == nil && line != "" {
		res.Payload = []byte(line)
		res.Meta = map[string]any{"client_id": line}
	} else if err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
	}

	// Try to read one binary-packet (likely SSH_MSG_KEXINIT) for HASSH.
	if hashRaw, hashSum, ok := readHASSH(br); ok {
		if res.Meta == nil {
			res.Meta = map[string]any{}
		}
		res.Meta["hassh"] = hashSum
		res.Meta["hassh_algorithms"] = hashRaw
	}

	_, _ = conn.Write([]byte("Protocol mismatch.\r\n"))
	return res, nil
}

// readHASSH reads one SSH binary packet from br (RFC 4253 §6), and feeds
// the payload to fingerprint.HASSH. Returns ("","",false) on any failure.
func readHASSH(br *bufio.Reader) (string, string, bool) {
	hdr, err := peekN(br, 5)
	if err != nil {
		return "", "", false
	}
	pktLen := binary.BigEndian.Uint32(hdr[0:4])
	if pktLen < 1 || pktLen > 65535 {
		return "", "", false
	}
	full := make([]byte, 4+pktLen)
	if _, err := io.ReadFull(br, full); err != nil {
		return "", "", false
	}
	raw, sum := fingerprint.HASSH(full)
	return raw, sum, raw != ""
}

func peekN(br *bufio.Reader, n int) ([]byte, error) {
	b, err := br.Peek(n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, b)
	return out, nil
}

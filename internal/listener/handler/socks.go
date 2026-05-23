package handler

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// socksH emulates a SOCKS proxy (TCP 1080, SOCKS4/4a + SOCKS5). An open
// SOCKS proxy is abused to relay attacks and anonymize C2, so the high
// signal here is the CONNECT target the client asks us to reach — we
// capture it and flag the proxy attempt, then return a success-shaped
// reply and close WITHOUT ever relaying a byte.
type socksH struct{}

func (socksH) Name() string { return "socks" }

func (socksH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = "short"
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr...)

	switch hdr[0] {
	case 0x05:
		socks5(conn, &res, hdr)
	case 0x04:
		socks4(conn, &res, hdr)
	default:
		res.Meta["non_socks"] = true
	}
	return res, nil
}

func socks5(conn net.Conn, res *Result, hdr []byte) {
	res.Meta["socks_version"] = 5
	// hdr[1] = nmethods; read+discard the method bytes.
	if n := int(hdr[1]); n > 0 && n <= 255 {
		methods := make([]byte, n)
		_, _ = io.ReadFull(conn, methods)
		res.Payload = append(res.Payload, methods...)
	}
	// Offer "no authentication required".
	_, _ = conn.Write([]byte{0x05, 0x00})

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		res.Meta["read_err"] = "no-request"
		return
	}
	res.Payload = append(res.Payload, req...)
	host := ""
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		_, _ = io.ReadFull(conn, b)
		res.Payload = append(res.Payload, b...)
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		_, _ = io.ReadFull(conn, l)
		d := make([]byte, int(l[0]))
		_, _ = io.ReadFull(conn, d)
		res.Payload = append(res.Payload, append(l, d...)...)
		host = string(d)
	case 0x04: // IPv6
		b := make([]byte, 16)
		_, _ = io.ReadFull(conn, b)
		res.Payload = append(res.Payload, b...)
		host = net.IP(b).String()
	}
	port := make([]byte, 2)
	_, _ = io.ReadFull(conn, port)
	res.Payload = append(res.Payload, port...)
	target := fmt.Sprintf("%s:%d", host, int(port[0])<<8|int(port[1]))
	res.Meta["socks_cmd"] = socksCmdName(req[1])
	res.Meta["socks_target"] = target
	flagAnomaly(res, "socks-proxy-attempt")
	res.BannerSent = "socks5 connect " + target
	// Success reply, bound to 0.0.0.0:0; we never actually connect.
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func socks4(conn net.Conn, res *Result, hdr []byte) {
	res.Meta["socks_version"] = 4
	// hdr = [VER, CMD]; read PORT(2) + IP(4).
	rest := make([]byte, 6)
	if _, err := io.ReadFull(conn, rest); err != nil {
		res.Meta["read_err"] = "short"
		return
	}
	res.Payload = append(res.Payload, rest...)
	port := int(rest[0])<<8 | int(rest[1])
	ip := net.IP(rest[2:6]).String()
	// Read the (null-terminated) userid, capped.
	uid := make([]byte, 0, 64)
	one := make([]byte, 1)
	for i := 0; i < 256; i++ {
		if _, err := io.ReadFull(conn, one); err != nil || one[0] == 0 {
			break
		}
		uid = append(uid, one[0])
	}
	host := ip
	// SOCKS4a: IP 0.0.0.x with a trailing hostname.
	if strings.HasPrefix(ip, "0.0.0.") {
		name := make([]byte, 0, 64)
		for i := 0; i < 256; i++ {
			if _, err := io.ReadFull(conn, one); err != nil || one[0] == 0 {
				break
			}
			name = append(name, one[0])
		}
		if len(name) > 0 {
			host = string(name)
		}
	}
	target := fmt.Sprintf("%s:%d", host, port)
	res.Meta["socks_cmd"] = socksCmdName(hdr[1])
	res.Meta["socks_target"] = target
	if len(uid) > 0 {
		res.Meta["socks_userid"] = string(uid)
	}
	flagAnomaly(res, "socks-proxy-attempt")
	res.BannerSent = "socks4 connect " + target
	// Request granted (0x5A); we never relay.
	_, _ = conn.Write([]byte{0x00, 0x5A, rest[0], rest[1], rest[2], rest[3], rest[4], rest[5]})
}

func socksCmdName(c byte) string {
	switch c {
	case 1:
		return "CONNECT"
	case 2:
		return "BIND"
	case 3:
		return "UDP-ASSOCIATE"
	}
	return fmt.Sprintf("cmd-%d", c)
}

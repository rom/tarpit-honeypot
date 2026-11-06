package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// identH emulates an Ident / auth daemon (TCP 113, RFC 1413). An exposed ident
// service discloses the username owning a TCP connection — classic account
// enumeration that still appears on IRC bouncers, mail servers and legacy
// UNIX hosts. We answer with a believable USERID response and flag the query.
type identH struct{}

func (identH) Name() string { return "ident" }

func (identH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	line, _ := readLineCapped(br, maxLineBytes)
	q := strings.TrimRight(line, "\r\n")
	res.Payload = []byte(q)
	res.Meta["ident_query"] = q
	flagAnomaly(&res, "ident-query")
	res.Meta["intent"] = "Ident (RFC 1413) query — connection-owner account disclosure (T1087)"

	// Request is "<server-port>,<client-port>"; echo it back with a USERID.
	ports := strings.ReplaceAll(q, " ", "")
	if a, b, ok := strings.Cut(ports, ","); ok && a != "" && b != "" {
		_, _ = conn.Write([]byte(a + "," + b + " : USERID : UNIX : svc-www\r\n"))
	} else {
		_, _ = conn.Write([]byte(ports + " : ERROR : INVALID-PORT\r\n"))
	}
	res.BannerSent = "ident USERID"
	return res, nil
}

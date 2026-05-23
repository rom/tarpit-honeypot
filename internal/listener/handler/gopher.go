package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// gopherH emulates a Gopher server (TCP 70). Gopher is a flagship SSRF
// pivot: gopher:// URLs let an attacker craft arbitrary TCP payloads
// through a vulnerable proxy, so a request whose selector smuggles CRLF
// or another protocol's verbs is flagged as an SSRF gadget. Otherwise we
// return a believable decoy menu.
type gopherH struct{}

func (gopherH) Name() string { return "gopher" }

func (gopherH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	selector, _ := br.ReadString('\n')
	raw := strings.TrimRight(selector, "\r\n")
	res.Payload = append([]byte(nil), []byte(selector)...)
	res.Meta["gopher_selector"] = raw
	flagAnomaly(&res, "gopher-request")

	// SSRF gadget tells: embedded CRLF (multi-line smuggle) or another
	// protocol's verbs riding inside the selector.
	low := strings.ToLower(selector)
	if strings.Count(selector, "\n") > 1 || strings.Contains(low, "\r\n") ||
		strings.Contains(low, "host:") || strings.Contains(low, "set ") ||
		strings.HasPrefix(low, "get ") || strings.Contains(low, "*1\r\n") {
		flagAnomaly(&res, "gopher-ssrf")
	}

	menu := "iWelcome to the archive server\tfake\t(NULL)\t0\r\n" +
		"1Documents\t/docs\tlocalhost\t70\r\n" +
		"1Backups\t/backups\tlocalhost\t70\r\n" +
		"0README\t/readme.txt\tlocalhost\t70\r\n.\r\n"
	if _, err := conn.Write([]byte(menu)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "gopher menu"
	return res, nil
}

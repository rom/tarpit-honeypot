package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// fingerH emulates a Finger daemon (TCP 79, RFC 1288). An exposed finger
// service is a classic account-enumeration finding (it predates and inspired
// much modern recon). We capture the query, answer a believable listing / user
// record, and flag the enumeration — plus the "user@host" forwarding syntax
// that turns an open finger daemon into a relay/amplifier.
type fingerH struct{}

func (fingerH) Name() string { return "finger" }

func (fingerH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	line, _ := readLineCapped(br, maxLineBytes)
	query := strings.TrimRight(line, "\r\n")
	res.Payload = []byte(query)
	res.Meta["finger_query"] = query

	// "/W" is the verbose (long) flag; strip it to get the target.
	target := strings.TrimSpace(strings.TrimPrefix(query, "/W"))

	switch {
	case target == "":
		// Bare query → list logged-in users (account disclosure).
		flagAnomaly(&res, "finger-user-list")
		res.Meta["intent"] = "Finger user listing — account enumeration (T1087)"
		_, _ = conn.Write([]byte(
			"Login     Name           TTY   Idle   When\r\n" +
				"root      System Admin   con    0:12  Mon 09:03\r\n" +
				"svc-bkp   Backup Service pts/0  1:40  Mon 07:51\r\n"))
		res.BannerSent = "finger user list"
	case strings.Contains(target, "@"):
		// user@host → finger forwarding: an open relay / amplification vector.
		flagAnomaly(&res, "finger-forwarding")
		res.Meta["intent"] = "Finger forwarding query (user@host) — open-relay / recon pivot"
		_, _ = conn.Write([]byte("Finger forwarding service denied.\r\n"))
		res.BannerSent = "finger forward denied"
	default:
		flagAnomaly(&res, "finger-user-query")
		res.Meta["finger_user"] = target
		res.Meta["intent"] = "Finger user query (" + target + ") — account enumeration (T1087)"
		_, _ = conn.Write([]byte(
			"Login: " + target + "\t\t\tName: " + target + "\r\n" +
				"Directory: /home/" + target + "         \tShell: /bin/bash\r\n" +
				"Never logged in.\r\nNo mail.\r\nNo Plan.\r\n"))
		res.BannerSent = "finger user record"
	}
	return res, nil
}

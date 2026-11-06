package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// nntpH emulates an NNTP news server (TCP 119 / 563 for NNTPS). An exposed,
// posting-allowed news server is an open relay / spam-injection finding; we
// greet like a real NNRP server, answer the common commands, and capture an
// AUTHINFO USER/PASS credential attempt.
type nntpH struct{}

func (nntpH) Name() string { return "nntp" }

func (nntpH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	if _, err := conn.Write([]byte("200 news.local NNRP Service Ready - posting allowed\r\n")); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "200 NNRP ready"

	br := bufio.NewReader(conn)
	var cmds []string
	var user string
	for i := 0; i < 12; i++ {
		line, err := readLineCapped(br, maxLineBytes)
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		res.Payload = append(res.Payload, []byte(line+"\n")...)
		verb, args := ircSplit(line) // "<VERB> <rest>" split, reused
		up := strings.ToUpper(verb)
		cmds = appendUnique(cmds, up)
		switch up {
		case "AUTHINFO":
			sub, val := ircSplit(args)
			switch strings.ToUpper(sub) {
			case "USER":
				user = val
				res.Meta["nntp_user"] = val
				_, _ = conn.Write([]byte("381 Password required\r\n"))
			case "PASS":
				flagAnomaly(&res, "nntp-auth")
				flagDefaultCred(&res, user, val)
				res.Meta["intent"] = "NNTP AUTHINFO login — news-server credential attempt"
				_, _ = conn.Write([]byte("281 Authentication accepted\r\n"))
			default:
				_, _ = conn.Write([]byte("501 Syntax error\r\n"))
			}
		case "GROUP":
			res.Meta["nntp_group"] = args
			_, _ = conn.Write([]byte("211 0 0 0 " + args + "\r\n"))
		case "LIST":
			_, _ = conn.Write([]byte("215 list of newsgroups follows\r\n.\r\n"))
		case "POST":
			flagAnomaly(&res, "nntp-post")
			res.Meta["intent"] = "NNTP POST — article injection / open-relay abuse"
			_, _ = conn.Write([]byte("340 Send article\r\n"))
		case "ARTICLE", "BODY", "HEAD", "STAT":
			_, _ = conn.Write([]byte("430 No such article\r\n"))
		case "MODE":
			_, _ = conn.Write([]byte("200 posting allowed\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("205 Goodbye\r\n"))
			return finishNNTP(&res, cmds), nil
		default:
			_, _ = conn.Write([]byte("500 Command not recognized\r\n"))
		}
	}
	return finishNNTP(&res, cmds), nil
}

func finishNNTP(res *Result, cmds []string) Result {
	if len(cmds) > 0 {
		res.Meta["nntp_commands"] = cmds
	}
	return *res
}

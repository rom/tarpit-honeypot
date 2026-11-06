package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// beanstalkdH emulates a beanstalkd work queue (TCP 11300). beanstalkd has no
// authentication, so an exposed instance is a data-access / job-injection
// finding (attackers enumerate tubes and read/insert jobs). We answer the
// common text commands believably and capture the tubes/commands touched.
type beanstalkdH struct{}

func (beanstalkdH) Name() string { return "beanstalkd" }

func (beanstalkdH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "beanstalkd"}}
	br := bufio.NewReader(conn)

	var cmds, tubes []string
	for i := 0; i < 10; i++ {
		line, err := readLineCapped(br, maxLineBytes)
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		res.Payload = append(res.Payload, []byte(line+"\n")...)
		verb, args := ircSplit(line)
		verb = strings.ToLower(verb)
		cmds = appendUnique(cmds, verb)
		switch verb {
		case "use", "watch", "ignore":
			if args != "" {
				tubes = appendUnique(tubes, args)
			}
			_, _ = conn.Write([]byte("USING " + firstField(args) + "\r\n"))
		case "list-tubes", "list-tubes-watched":
			body := "---\n- default\n- jobs\n"
			_, _ = conn.Write([]byte("OK " + intToStr(len(body)) + "\r\n" + body + "\r\n"))
		case "stats":
			body := "---\ncurrent-jobs-ready: 0\ncurrent-connections: 1\npid: 1\nversion: 1.13\n"
			_, _ = conn.Write([]byte("OK " + intToStr(len(body)) + "\r\n" + body + "\r\n"))
			flagAnomaly(&res, "beanstalkd-stats")
		case "put":
			flagAnomaly(&res, "beanstalkd-put")
			res.Meta["intent"] = "beanstalkd PUT — job injection into an unauthenticated queue"
			// A put body follows on the next line; consume it best-effort.
			_, _ = readLineCapped(br, maxLineBytes)
			_, _ = conn.Write([]byte("INSERTED 1\r\n"))
		case "reserve", "reserve-with-timeout", "peek-ready":
			flagAnomaly(&res, "beanstalkd-reserve")
			res.Meta["intent"] = "beanstalkd RESERVE/PEEK — reading jobs from an unauthenticated queue"
			_, _ = conn.Write([]byte("TIMED_OUT\r\n"))
		case "quit":
			return finishBeanstalkd(&res, cmds, tubes), nil
		default:
			_, _ = conn.Write([]byte("UNKNOWN_COMMAND\r\n"))
		}
	}
	return finishBeanstalkd(&res, cmds, tubes), nil
}

func finishBeanstalkd(res *Result, cmds, tubes []string) Result {
	if len(cmds) > 0 {
		res.Meta["beanstalkd_commands"] = cmds
	}
	if len(tubes) > 0 {
		res.Meta["beanstalkd_tubes"] = tubes
	}
	return *res
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "default"
	}
	return s
}

package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// stompH emulates a STOMP message broker (TCP 61613 — ActiveMQ / RabbitMQ /
// Artemis). STOMP is a simple text framing: a command line, headers, a blank
// line, a body, and a NUL terminator. An exposed broker is a data-access /
// lateral-movement finding; we complete the CONNECT handshake (capturing the
// login/passcode credential), answer SUBSCRIBE/SEND, and flag the access.
type stompH struct{}

func (stompH) Name() string { return "stomp" }

func (stompH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)

	var commands, dests []string
	done := false
	for i := 0; i < 6 && !done; i++ {
		cmd, headers, ok := readSTOMPFrame(br)
		if !ok {
			break
		}
		commands = appendUnique(commands, cmd)
		res.Payload = append(res.Payload, []byte(cmd+"\n")...)
		switch cmd {
		case "CONNECT", "STOMP":
			if l := headers["login"]; l != "" {
				res.Meta["stomp_login"] = l
				flagDefaultCred(&res, l, headers["passcode"])
			}
			flagAnomaly(&res, "stomp-connect")
			res.Meta["intent"] = "STOMP broker CONNECT — message-broker access / credential attempt"
			// CONNECTED reply so the client proceeds.
			_, _ = conn.Write([]byte("CONNECTED\nversion:1.2\nserver:ActiveMQ/5.18.3\nheart-beat:0,0\n\n\x00"))
			res.BannerSent = "stomp CONNECTED"
		case "SUBSCRIBE":
			if d := headers["destination"]; d != "" {
				dests = appendUnique(dests, d)
			}
			flagAnomaly(&res, "stomp-subscribe")
		case "SEND":
			if d := headers["destination"]; d != "" {
				dests = appendUnique(dests, d)
			}
			flagAnomaly(&res, "stomp-send")
		case "DISCONNECT":
			done = true
		}
	}
	if len(commands) > 0 {
		res.Meta["stomp_commands"] = commands
	}
	if len(dests) > 0 {
		res.Meta["stomp_destinations"] = dests
	}
	return res, nil
}

// readSTOMPFrame reads one STOMP frame: a command line, header lines until a
// blank line, then the NUL-terminated body (which we discard, bounded).
func readSTOMPFrame(br *bufio.Reader) (cmd string, headers map[string]string, ok bool) {
	line, err := readLineCapped(br, maxLineBytes)
	if err != nil {
		return "", nil, false
	}
	cmd = strings.TrimRight(line, "\r\n")
	// Skip leading blank lines / stray NULs between frames.
	for cmd == "" || cmd == "\x00" {
		line, err = readLineCapped(br, maxLineBytes)
		if err != nil {
			return "", nil, false
		}
		cmd = strings.TrimRight(strings.TrimLeft(line, "\x00"), "\r\n")
	}
	headers = map[string]string{}
	for i := 0; i < 32; i++ {
		h, err := readLineCapped(br, maxLineBytes)
		if err != nil {
			return "", nil, false
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break // end of headers
		}
		if k, v, found := strings.Cut(h, ":"); found {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	// Body up to the NUL terminator, bounded.
	_, _ = br.ReadString(0x00)
	return cmd, headers, true
}

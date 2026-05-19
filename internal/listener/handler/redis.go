package handler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type redis struct{}

func (r *redis) Name() string { return "redis" }

// Redis RESP protocol (port 6379). Clients open with either:
//   - inline command:  "AUTH foo\r\n" / "PING\r\n"
//   - multi-bulk array: "*N\r\n$len\r\nVAL\r\n..."
//
// Common scanner workflow: AUTH <password>, INFO, CONFIG GET *,
// and the "unprotected mode" abuse — SET / CONFIG SET dir / etc.
//
// We capture the first few commands, return RESP errors so the client
// stops, and never execute anything.
func (r *redis) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	var commands []string
	for i := 0; i < 4; i++ {
		cmd, err := readRESPCommand(br)
		if err != nil {
			if i == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		if len(cmd) == 0 {
			break
		}
		res.Payload = append(res.Payload, []byte(strings.Join(cmd, " ")+"\n")...)
		commands = append(commands, strings.Join(cmd, " "))
		switch strings.ToUpper(cmd[0]) {
		case "AUTH":
			if len(cmd) >= 2 {
				res.Meta["auth_password"] = cmd[len(cmd)-1] // ACL: "AUTH user pass"
			}
			_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("+OK\r\n"))
			res.Meta["commands"] = commands
			return res, nil
		default:
			_, _ = conn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s'\r\n", cmd[0])))
		}
	}
	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	res.BannerSent = "redis RESP errors"
	return res, nil
}

// readRESPCommand parses one Redis command from br as a list of strings.
// Handles both inline ("PING\r\n") and multi-bulk ("*N\r\n$len\r\nVAL\r\n...").
func readRESPCommand(br *bufio.Reader) ([]string, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] != '*' {
		// Inline command
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		return strings.Fields(strings.TrimRight(line, "\r\n")), nil
	}
	header, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
	if err != nil || n < 0 || n > 64 {
		return nil, fmt.Errorf("bad array length")
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		dollar, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(dollar) < 1 || dollar[0] != '$' {
			return nil, fmt.Errorf("expected $-prefixed bulk")
		}
		blen, err := strconv.Atoi(strings.TrimRight(dollar[1:], "\r\n"))
		if err != nil || blen < 0 || blen > 8192 {
			return nil, fmt.Errorf("bad bulk length")
		}
		buf := make([]byte, blen)
		if _, err := br.Read(buf); err != nil {
			return nil, err
		}
		// consume trailing CRLF
		_, _ = br.ReadByte()
		_, _ = br.ReadByte()
		out = append(out, string(buf))
	}
	return out, nil
}

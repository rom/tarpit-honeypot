package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// memcached emulates the memcached text protocol over TCP (port 11211).
// Exposed memcached is a classic data-theft + UDP-amplification target;
// this handler is TCP-only — it never reflects, so it cannot be abused as an
// amplifier — and records the commands a scanner runs (version, stats, get,
// set). It answers believably and stores nothing.
type memcached struct{}

func (m *memcached) Name() string { return "memcached" }

func (m *memcached) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	var commands []string
	for i := 0; i < 8; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			if i == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		res.Payload = append(res.Payload, []byte(line+"\n")...)
		commands = append(commands, line)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "version":
			_, _ = conn.Write([]byte("VERSION 1.6.21\r\n"))
		case "stats":
			// "stats" enumeration is the recon a scanner runs before
			// dumping keys (and the basis of the UDP amplification abuse).
			flagAnomaly(&res, "memcached-stats-probe")
			_, _ = conn.Write([]byte("STAT pid 1\r\nSTAT version 1.6.21\r\nSTAT curr_items 0\r\nSTAT total_items 0\r\nEND\r\n"))
		case "get", "gets":
			_, _ = conn.Write([]byte("END\r\n"))
		case "set", "add", "replace", "append", "prepend", "cas":
			flagAnomaly(&res, "memcached-write-attempt")
			_, _ = br.ReadString('\n') // consume the (bounded) data line
			_, _ = conn.Write([]byte("STORED\r\n"))
		case "delete":
			_, _ = conn.Write([]byte("NOT_FOUND\r\n"))
		case "flush_all":
			flagAnomaly(&res, "memcached-flush")
			_, _ = conn.Write([]byte("OK\r\n"))
		case "quit":
			res.Meta["commands"] = commands
			return res, nil
		default:
			_, _ = conn.Write([]byte("ERROR\r\n"))
		}
	}
	if len(commands) > 0 {
		res.Meta["commands"] = commands
	}
	res.BannerSent = "memcached text responses"
	return res, nil
}

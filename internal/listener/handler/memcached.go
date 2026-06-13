package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// memcached emulates the memcached text protocol over TCP (port 11211).
// Exposed memcached is a classic data-theft + UDP-amplification target;
// this handler is TCP-only — it never reflects, so it cannot be abused as an
// amplifier — and records the commands a scanner runs (version, stats, get,
// set). It answers believably and stores nothing.
type memcached struct{ id *identity.Identity }

func (m *memcached) Name() string { return "memcached" }

func (m *memcached) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	ver := "1.6.21"
	if m.id != nil {
		ver = m.id.MemcachedVersion()
	}

	br := bufio.NewReader(conn)

	// memcached binary protocol (request magic 0x80). Exposed binary-protocol
	// probing is the vector for the 2016 Talos integer-overflow RCEs
	// (CVE-2016-8704/8705/8706); the text protocol below never reaches those
	// code paths. Detect + capture it separately. TCP-only — never reflects.
	if bb, _ := br.Peek(1); len(bb) == 1 && bb[0] == 0x80 {
		memcachedBinary(conn, br, &res)
		return res, nil
	}

	var commands []string
	for i := 0; i < 12; i++ {
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
			_, _ = conn.Write([]byte("VERSION " + ver + "\r\n"))
		case "stats":
			// "stats" enumeration is the recon a scanner runs before
			// dumping keys (and the basis of the UDP amplification abuse).
			flagAnomaly(&res, "memcached-stats-probe")
			_, _ = conn.Write([]byte(memcachedStats(fields, ver)))
		case "get", "gets", "gat", "gats":
			_, _ = conn.Write([]byte("END\r\n"))
		case "set", "add", "replace", "append", "prepend", "cas":
			flagAnomaly(&res, "memcached-write-attempt")
			_, _ = br.ReadString('\n') // consume the (bounded) data line
			_, _ = conn.Write([]byte("STORED\r\n"))
		case "incr", "decr":
			// A real server returns the new value, or NOT_FOUND for a
			// missing key (what a fresh box returns to a scanner).
			_, _ = conn.Write([]byte("NOT_FOUND\r\n"))
		case "touch":
			_, _ = conn.Write([]byte("NOT_FOUND\r\n"))
		case "delete":
			_, _ = conn.Write([]byte("NOT_FOUND\r\n"))
		case "flush_all":
			flagAnomaly(&res, "memcached-flush")
			_, _ = conn.Write([]byte("OK\r\n"))
		case "verbosity":
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
	res.BannerSent = "memcached text responses (" + ver + ")"
	return res, nil
}

// memcachedBinary handles a memcached *binary* protocol request (magic 0x80).
// It parses the 24-byte request header, classifies the opcode, and — when the
// declared length fields are overflow-shaped (the malformed lengths the 2016
// Talos integer overflows require) — flags the matching CVE. It never executes
// the operation: it captures the bytes and returns a single bounded binary
// error. The connection is TCP, so this never reflects or amplifies.
func memcachedBinary(conn net.Conn, br *bufio.Reader, res *Result) {
	flagAnomaly(res, "memcached-binary-protocol")

	hdr := make([]byte, 24)
	if _, err := io.ReadFull(br, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return
	}
	res.Payload = append(res.Payload, hdr...)
	opcode := hdr[1]
	keyLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	extLen := int(hdr[4])
	totalBody := int(binary.BigEndian.Uint32(hdr[8:12]))
	res.Meta["binary_opcode"] = fmtByte(opcode)

	// Capture whatever of the declared body has already arrived (bounded), so a
	// bogus huge totalBody can't be used to make us read 4 GiB.
	if totalBody > 0 {
		body := make([]byte, 8192)
		if n, _ := br.Read(body); n > 0 {
			res.Payload = append(res.Payload, body[:n]...)
		}
	}

	// Overflow-shaped header: the body can't even contain its declared
	// key+extras, or totalBody is implausibly large (memcached's default item
	// cap is 1 MiB). That is exactly the malformed length the integer overflows
	// in the process_bin_* handlers require — high-signal, not benign traffic.
	overflowShaped := extLen+keyLen > totalBody || keyLen > totalBody || totalBody >= 1<<24
	if overflowShaped {
		var id, fn string
		switch opcode {
		case 0x0e, 0x0f, 0x19, 0x1a: // APPEND / PREPEND (+ quiet variants)
			id, fn = "CVE-2016-8704", "process_bin_append_prepend"
		case 0x01, 0x02, 0x03, 0x11, 0x12, 0x13: // SET / ADD / REPLACE (+ quiet)
			id, fn = "CVE-2016-8705", "process_bin_update"
		case 0x20, 0x21, 0x22: // SASL list-mechs / auth / step
			id, fn = "CVE-2016-8706", "process_bin_sasl_auth"
		}
		if id != "" {
			res.CVEHits = appendUnique(res.CVEHits, id)
			flagAnomaly(res, "cve:"+id)
			res.Meta["intent"] = "memcached binary-protocol integer overflow (" + fn + ") — heap-overflow RCE attempt (" + id + ")"
		}
	}

	// Single bounded binary response: magic 0x81, echo opcode, status 0x0084
	// ("internal error"). Never executes the op.
	resp := make([]byte, 24)
	resp[0] = 0x81
	resp[1] = opcode
	binary.BigEndian.PutUint16(resp[6:8], 0x0084)
	_, _ = conn.Write(resp)
	res.BannerSent = "memcached binary error"
}

// memcachedStats renders a believable reply for the "stats" family. Bare
// "stats" returns the full server-stats block a real daemon emits (~30
// lines); the documented sub-stats (settings / items / slabs / sizes)
// return their characteristic shapes so a scanner walking them stays fooled.
func memcachedStats(fields []string, ver string) string {
	sub := ""
	if len(fields) >= 2 {
		sub = strings.ToLower(fields[1])
	}
	switch sub {
	case "settings":
		return "STAT maxbytes 67108864\r\n" +
			"STAT maxconns 1024\r\n" +
			"STAT tcpport 11211\r\n" +
			"STAT udpport 11211\r\n" +
			"STAT verbosity 0\r\n" +
			"STAT num_threads 4\r\n" +
			"STAT growth_factor 1.25\r\n" +
			"STAT evictions on\r\n" +
			"END\r\n"
	case "items":
		return "END\r\n"
	case "slabs":
		return "STAT active_slabs 0\r\nSTAT total_malloced 0\r\nEND\r\n"
	case "sizes":
		return "STAT 0 0\r\nEND\r\n"
	case "conns":
		return "STAT 1:addr tcp:127.0.0.1:11211\r\nEND\r\n"
	}
	// Bare "stats": the general server statistics block.
	return "STAT pid 1\r\n" +
		"STAT uptime 864231\r\n" +
		"STAT time 1700000000\r\n" +
		"STAT version " + ver + "\r\n" +
		"STAT pointer_size 64\r\n" +
		"STAT curr_connections 1\r\n" +
		"STAT total_connections 42\r\n" +
		"STAT cmd_get 0\r\n" +
		"STAT cmd_set 0\r\n" +
		"STAT get_hits 0\r\n" +
		"STAT get_misses 0\r\n" +
		"STAT bytes_read 128\r\n" +
		"STAT bytes_written 1024\r\n" +
		"STAT limit_maxbytes 67108864\r\n" +
		"STAT threads 4\r\n" +
		"STAT curr_items 0\r\n" +
		"STAT total_items 0\r\n" +
		"STAT bytes 0\r\n" +
		"STAT evictions 0\r\n" +
		"END\r\n"
}

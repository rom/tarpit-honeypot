package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// neo4j emulates the Neo4j Bolt protocol (TCP 7687). Exposed graph databases
// are a data-theft target and Bolt carries the login (principal + credentials)
// in cleartext PackStream inside the HELLO / LOGON message — which is where the
// value is. We complete the Bolt version handshake, accept the connection,
// capture the credentials and any follow-up Cypher (RUN) query, and store
// nothing.
//
// Bolt handshake: client sends magic 0x6060B017 + four 4-byte proposed
// versions; the server replies with one chosen 4-byte version. Messages are
// then PackStream structures wrapped in 16-bit-length chunks terminated by a
// zero-length chunk.
type neo4j struct{}

func (n *neo4j) Name() string { return "neo4j" }

func (n *neo4j) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	withTimeout(conn, cfg.ReadTimeout)

	hs := make([]byte, 20)
	if _, err := io.ReadFull(conn, hs); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, hs...)
	if hs[0] != 0x60 || hs[1] != 0x60 || hs[2] != 0xB0 || hs[3] != 0x17 {
		res.Meta["non_bolt"] = true
		return res, nil
	}
	flagAnomaly(&res, "neo4j-bolt-probe")
	setIfEmpty(res.Meta, "intent", "Neo4j Bolt handshake — graph-database access attempt")

	// Choose the first offered version with a non-zero major/minor, as a
	// concrete version (zeroing the range byte).
	ver := []byte{0, 0, 0, 0}
	for i := 4; i+4 <= 20; i += 4 {
		if hs[i+2] != 0 || hs[i+3] != 0 {
			ver = []byte{0x00, 0x00, hs[i+2], hs[i+3]}
			break
		}
	}
	if _, err := conn.Write(ver); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "neo4j bolt version"
	if ver[3] == 0 && ver[2] == 0 {
		return res, nil // no acceptable version — the client disconnects
	}
	res.Meta["bolt_version"] = itoa(int(ver[3])) + "." + itoa(int(ver[2]))

	for i := 0; i < 8; i++ {
		withTimeout(conn, cfg.ReadTimeout)
		msg, err := boltReadMessage(conn)
		if err != nil || len(msg) < 2 || msg[0]&0xF0 != 0xB0 {
			break
		}
		res.Payload = append(res.Payload, msg...)
		sig := msg[1]
		fields := msg[2:]
		switch sig {
		case 0x01, 0x6A: // HELLO / LOGON — carries the auth dict
			auth, _, _ := boltReadMap(fields, 0)
			user, pass := auth["principal"], auth["credentials"]
			if user != "" || pass != "" {
				res.Meta["auth_user"] = safe.SanitizeForLog(user)
				res.Meta["auth_pass"] = safe.SanitizeForLog(pass)
				flagAnomaly(&res, "neo4j-credential-attempt")
				flagDefaultCred(&res, user, pass)
				if user == "neo4j" && pass == "neo4j" {
					flagAnomaly(&res, "neo4j-default-login")
				}
				res.Meta["intent"] = "Neo4j Bolt login — graph-DB credential attempt (" + safe.SanitizeForLog(user) + ")"
			}
			// Accept so the client proceeds to issue queries (more intent).
			n.write(conn, &res, boltSuccess(boltMap("server", "Neo4j/5.13.0", "connection_id", "bolt-1")))
		case 0x10: // RUN — a Cypher query
			if q, _, ok := boltReadString(fields, 0); ok && q != "" {
				res.Meta["cypher_query"] = safe.SanitizeForLog(q)
				flagAnomaly(&res, "neo4j-query")
				res.Meta["intent"] = "Neo4j Cypher query — " + safe.SanitizeForLog(q)
			}
			n.write(conn, &res, boltFailure("Neo.ClientError.Security.Unauthorized", "unauthorized"))
		case 0x02: // GOODBYE
			return res, nil
		default:
			n.write(conn, &res, boltSuccess(boltMap()))
		}
	}
	return res, nil
}

func (n *neo4j) write(conn net.Conn, res *Result, b []byte) {
	if _, err := conn.Write(b); err != nil {
		res.Meta["write_err"] = err.Error()
	}
}

// boltReadMessage de-chunks one Bolt message (16-bit-length chunks ended by a
// zero-length chunk), bounded.
func boltReadMessage(conn net.Conn) ([]byte, error) {
	var msg []byte
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(conn, h); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(h))
		if n == 0 {
			return msg, nil
		}
		if len(msg)+n > 1<<20 {
			return msg, nil
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return nil, err
		}
		msg = append(msg, chunk...)
	}
}

// --- minimal PackStream (decode for the auth map / query; encode for replies) ---

func boltReadString(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	m := b[off]
	off++
	var n int
	switch {
	case m >= 0x80 && m <= 0x8F:
		n = int(m & 0x0F)
	case m == 0xD0:
		if off+1 > len(b) {
			return "", off, false
		}
		n = int(b[off])
		off++
	case m == 0xD1:
		if off+2 > len(b) {
			return "", off, false
		}
		n = int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
	case m == 0xD2:
		if off+4 > len(b) {
			return "", off, false
		}
		n = int(binary.BigEndian.Uint32(b[off : off+4]))
		off += 4
	default:
		return "", off, false
	}
	if n < 0 || off+n > len(b) {
		return "", off, false
	}
	return string(b[off : off+n]), off + n, true
}

// boltReadMap parses a PackStream map, returning its string→string entries
// (non-string values are skipped). Used to pull principal/credentials out of
// the HELLO/LOGON auth dict.
func boltReadMap(b []byte, off int) (map[string]string, int, bool) {
	if off >= len(b) {
		return nil, off, false
	}
	m := b[off]
	off++
	var size int
	switch {
	case m >= 0xA0 && m <= 0xAF:
		size = int(m & 0x0F)
	case m == 0xD8:
		if off+1 > len(b) {
			return nil, off, false
		}
		size = int(b[off])
		off++
	case m == 0xD9:
		if off+2 > len(b) {
			return nil, off, false
		}
		size = int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
	default:
		return nil, off, false
	}
	out := make(map[string]string, size)
	for i := 0; i < size; i++ {
		key, no, ok := boltReadString(b, off)
		if !ok {
			return out, off, false
		}
		off = no
		if val, no2, ok2 := boltReadString(b, off); ok2 {
			out[key] = val
			off = no2
			continue
		}
		no3, ok3 := boltSkip(b, off, 0)
		if !ok3 {
			return out, off, false
		}
		off = no3
	}
	return out, off, true
}

// boltSkip advances past any PackStream value (so a non-string map value or
// list/struct field doesn't derail the map walk). Bounded by depth.
func boltSkip(b []byte, off, depth int) (int, bool) {
	if depth > 32 || off >= len(b) {
		return off, false
	}
	m := b[off]
	off++
	skipN := func(off, n int) (int, bool) {
		if n < 0 || off+n > len(b) {
			return off, false
		}
		return off + n, true
	}
	switch {
	case m <= 0x7F, m >= 0xF0: // tiny int
		return off, true
	case m >= 0x80 && m <= 0x8F: // tiny string
		return skipN(off, int(m&0x0F))
	case m >= 0x90 && m <= 0x9F: // tiny list
		return boltSkipItems(b, off, int(m&0x0F), depth)
	case m >= 0xA0 && m <= 0xAF: // tiny map
		return boltSkipItems(b, off, 2*int(m&0x0F), depth)
	case m >= 0xB0 && m <= 0xBF: // struct: signature + fields
		if off >= len(b) {
			return off, false
		}
		return boltSkipItems(b, off+1, int(m&0x0F), depth)
	case m == 0xC0, m == 0xC2, m == 0xC3: // null / false / true
		return off, true
	case m == 0xC8:
		return skipN(off, 1)
	case m == 0xC9:
		return skipN(off, 2)
	case m == 0xCA:
		return skipN(off, 4)
	case m == 0xC1, m == 0xCB: // float64 / int64
		return skipN(off, 8)
	case m == 0xD0, m == 0xCC: // string8 / bytes8
		if off+1 > len(b) {
			return off, false
		}
		return skipN(off+1, int(b[off]))
	case m == 0xD1, m == 0xCD: // string16 / bytes16
		if off+2 > len(b) {
			return off, false
		}
		return skipN(off+2, int(binary.BigEndian.Uint16(b[off:off+2])))
	case m == 0xD2, m == 0xCE: // string32 / bytes32
		if off+4 > len(b) {
			return off, false
		}
		return skipN(off+4, int(binary.BigEndian.Uint32(b[off:off+4])))
	case m == 0xD4: // list8
		if off+1 > len(b) {
			return off, false
		}
		return boltSkipItems(b, off+1, int(b[off]), depth)
	case m == 0xD5: // list16
		if off+2 > len(b) {
			return off, false
		}
		return boltSkipItems(b, off+2, int(binary.BigEndian.Uint16(b[off:off+2])), depth)
	case m == 0xD8: // map8
		if off+1 > len(b) {
			return off, false
		}
		return boltSkipItems(b, off+1, 2*int(b[off]), depth)
	case m == 0xD9: // map16
		if off+2 > len(b) {
			return off, false
		}
		return boltSkipItems(b, off+2, 2*int(binary.BigEndian.Uint16(b[off:off+2])), depth)
	}
	return off, false
}

func boltSkipItems(b []byte, off, count, depth int) (int, bool) {
	for i := 0; i < count; i++ {
		no, ok := boltSkip(b, off, depth+1)
		if !ok {
			return off, false
		}
		off = no
	}
	return off, true
}

func boltString(s string) []byte {
	switch {
	case len(s) <= 15:
		return append([]byte{0x80 | byte(len(s))}, s...)
	case len(s) < 256:
		return append([]byte{0xD0, byte(len(s))}, s...)
	default:
		return append([]byte{0xD1, byte(len(s) >> 8), byte(len(s))}, s...)
	}
}

// boltMap encodes a small (≤15 entry) string map from k1,v1,k2,v2,… arguments.
func boltMap(kv ...string) []byte {
	out := []byte{0xA0 | byte(len(kv)/2)}
	for _, s := range kv {
		out = append(out, boltString(s)...)
	}
	return out
}

func boltChunk(msg []byte) []byte {
	out := []byte{byte(len(msg) >> 8), byte(len(msg))}
	out = append(out, msg...)
	return append(out, 0x00, 0x00) // end-of-message marker
}

func boltSuccess(meta []byte) []byte { return boltChunk(append([]byte{0xB1, 0x70}, meta...)) }

func boltFailure(code, message string) []byte {
	return boltChunk(append([]byte{0xB1, 0x7F}, boltMap("code", code, "message", message)...))
}

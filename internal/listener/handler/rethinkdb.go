package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// rethinkdb emulates the RethinkDB driver handshake (TCP 28015). A client opens
// with a 4-byte little-endian magic (V1_0 = 0x34c2bdc3); the server replies with
// a null-terminated JSON server-version document, then the two run SCRAM-SHA-256
// as null-terminated JSON. The SCRAM client-first message carries the username
// in the clear (`n,,n=admin,r=<nonce>`), so we capture it (and the proof from
// client-final), advertise a believable challenge, and reject. Stores nothing.
type rethinkdb struct{}

func (r *rethinkdb) Name() string { return "rethinkdb" }

const rethinkV1Magic = 0x34c2bdc3

func (r *rethinkdb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	withTimeout(conn, cfg.ReadTimeout)

	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, magic...)
	if binary.LittleEndian.Uint32(magic) != rethinkV1Magic {
		res.Meta["non_rethinkdb"] = true
		return res, nil
	}
	flagAnomaly(&res, "rethinkdb-probe")
	setIfEmpty(res.Meta, "intent", "RethinkDB driver handshake — database access attempt")
	r.writeJSON(conn, &res, `{"success":true,"min_protocol_version":0,"max_protocol_version":0,"server_version":"2.4.1"}`)

	br := bufio.NewReader(conn)
	for i := 0; i < 4; i++ {
		withTimeout(conn, cfg.ReadTimeout)
		raw, err := readDelimCapped(br, 0x00, maxLineBytes)
		if err != nil && len(raw) == 0 {
			break
		}
		msg := raw
		if len(msg) > 0 && msg[len(msg)-1] == 0x00 {
			msg = msg[:len(msg)-1] // drop the trailing NUL when present
		}
		if len(msg) == 0 {
			continue
		}
		res.Payload = append(res.Payload, msg...)
		auth := rethinkAuthField(msg)
		if auth == "" {
			continue
		}
		switch {
		case scramField(auth, "p=") != "":
			// client-final: capture the proof; we can't verify it, so reject.
			res.Meta["scram_proof"] = safe.SanitizeForLog(scramField(auth, "p="))
			r.writeJSON(conn, &res, `{"success":false,"error":"Wrong password","error_code":12}`)
			return res, nil
		case scramField(auth, "n=") != "":
			// client-first: capture the username + nonce, send a SCRAM challenge.
			user := scramField(auth, "n=")
			res.Meta["auth_user"] = safe.SanitizeForLog(user)
			flagAnomaly(&res, "rethinkdb-credential-attempt")
			res.Meta["intent"] = "RethinkDB login — SCRAM credential attempt (" + safe.SanitizeForLog(user) + ")"
			nonce := scramField(auth, "r=") + "dGFycGl0c2VydmVy"
			r.writeJSON(conn, &res, `{"success":true,"authentication":"r=`+nonce+`,s=cnN0YXJwaXRzYWx0MDA=,i=4096"}`)
		}
	}
	return res, nil
}

func (r *rethinkdb) writeJSON(conn net.Conn, res *Result, doc string) {
	if _, err := conn.Write(append([]byte(doc), 0x00)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "rethinkdb handshake"
}

// rethinkAuthField returns the "authentication" string from a SCRAM JSON message.
func rethinkAuthField(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m["authentication"].(string)
	return s
}

// scramField returns the value of a `prefix<value>` token (up to the next comma)
// from a SCRAM message string.
func scramField(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	rest := s[i+len(prefix):]
	if j := strings.IndexByte(rest, ','); j >= 0 {
		return rest[:j]
	}
	return rest
}

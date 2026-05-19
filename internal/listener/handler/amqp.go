package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// amqp implements just enough of AMQP 0-9-1 (TCP 5672) to fool a
// RabbitMQ scanner. The protocol opens with the client sending an 8-byte
// header "AMQP" + 0 + major + minor + revision. A real server replies
// with a Connection.Start frame announcing supported SASL mechanisms,
// to which the client typically sends Connection.StartOk carrying the
// PLAIN credentials.
//
// We capture the protocol version + the StartOk auth response (which
// contains the PLAIN \0user\0pass blob) and then send a
// Connection.Close with reply-code 530 (NOT_ALLOWED) so the scanner
// records a real-but-rejecting RabbitMQ.
//
// AMQP frame layout (after the 8-byte protocol header):
//
//	byte 0     = frame type (1=method, 2=header, 3=body, 8=heartbeat)
//	bytes 1..2 = channel
//	bytes 3..6 = payload length
//	N bytes    = payload
//	byte N+1   = frame-end marker (0xCE)
type amqp struct{}

func (a *amqp) Name() string { return "amqp" }

const (
	amqpFrameMethod = 1
	amqpFrameEnd    = 0xCE

	// Class IDs.
	amqpClassConnection = 10
	// Method IDs (combined as class<<16 | method below).
	amqpMethodStart   = 10
	amqpMethodStartOk = 11
	amqpMethodClose   = 50
)

func (a *amqp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, hdr...)
	res.Meta["proto_header"] = byteToHex(hdr)
	if string(hdr[:4]) != "AMQP" {
		res.Meta["non_amqp"] = true
		// Echo any AMQP-style protocol header back so the scanner sees
		// the version it should speak.
		_, _ = conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1})
		return res, nil
	}
	res.Meta["proto_major"] = hdr[5]
	res.Meta["proto_minor"] = hdr[6]
	res.Meta["proto_rev"] = hdr[7]

	// Send Connection.Start (class=10, method=10).
	start := a.buildStart()
	if _, err := conn.Write(start); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "amqp Connection.Start"

	// Read one frame — the StartOk reply.
	fhdr := make([]byte, 7)
	if _, err := io.ReadFull(conn, fhdr); err != nil {
		return res, nil
	}
	payloadLen := binary.BigEndian.Uint32(fhdr[3:7])
	if payloadLen > 65536 {
		res.Meta["bad_len"] = payloadLen
		return res, nil
	}
	body := make([]byte, int(payloadLen)+1) // +1 for frame-end byte
	if _, err := io.ReadFull(conn, body); err != nil {
		return res, nil
	}
	res.Payload = append(res.Payload, fhdr...)
	res.Payload = append(res.Payload, body...)
	if len(body) > 0 && body[len(body)-1] != amqpFrameEnd {
		res.Meta["bad_frame_end"] = true
	}
	a.parseStartOk(body[:payloadLen], res.Meta)

	// Send Connection.Close with reply-code 530 NOT_ALLOWED so the
	// scanner records "this is RabbitMQ but my credentials are wrong".
	closeFrame := a.buildClose(530, "NOT_ALLOWED - access to vhost '/' refused")
	_, _ = conn.Write(closeFrame)
	return res, nil
}

func (a *amqp) buildStart() []byte {
	// Method args: version-major(1) version-minor(1) server-props(table)
	// mechanisms(longstr) locales(longstr).
	props := a.buildPropsTable(map[string]string{
		"product":     "RabbitMQ",
		"version":     "3.12.13",
		"platform":    "Erlang/OTP 26.2.1",
		"copyright":   "Copyright (c) 2007-2024 Broadcom Inc. and/or its subsidiaries",
		"information": "Licensed under the MPL 2.0. https://www.rabbitmq.com/",
	})
	args := []byte{0, 9} // 0-9-1 version-major / version-minor
	args = append(args, props...)
	args = appendLongStr(args, []byte("PLAIN AMQPLAIN"))
	args = appendLongStr(args, []byte("en_US"))
	return a.method(0, amqpClassConnection, amqpMethodStart, args)
}

func (a *amqp) buildClose(code uint16, text string) []byte {
	args := make([]byte, 0, 64)
	args = binary.BigEndian.AppendUint16(args, code)
	args = appendShortStr(args, []byte(text))
	args = binary.BigEndian.AppendUint16(args, amqpClassConnection)
	args = binary.BigEndian.AppendUint16(args, amqpMethodClose)
	return a.method(0, amqpClassConnection, amqpMethodClose, args)
}

func (a *amqp) method(channel uint16, class, method uint16, args []byte) []byte {
	body := make([]byte, 0, 4+len(args))
	body = binary.BigEndian.AppendUint16(body, class)
	body = binary.BigEndian.AppendUint16(body, method)
	body = append(body, args...)
	out := make([]byte, 0, 8+len(body))
	out = append(out, amqpFrameMethod)
	out = binary.BigEndian.AppendUint16(out, channel)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	out = append(out, amqpFrameEnd)
	return out
}

// parseStartOk pulls the SASL mechanism + response (which carries PLAIN
// credentials) out of a Connection.StartOk body.
func (a *amqp) parseStartOk(body []byte, meta map[string]any) {
	if len(body) < 4 {
		return
	}
	cls := binary.BigEndian.Uint16(body[0:2])
	mth := binary.BigEndian.Uint16(body[2:4])
	if cls != amqpClassConnection || mth != amqpMethodStartOk {
		meta["startok_class"] = cls
		meta["startok_method"] = mth
		return
	}
	off := 4
	// client-properties: long string table — skip.
	if off+4 > len(body) {
		return
	}
	tlen := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	if off+int(tlen) > len(body) {
		return
	}
	off += int(tlen)
	// mechanism: short string
	if off >= len(body) {
		return
	}
	mlen := int(body[off])
	off++
	if off+mlen > len(body) {
		return
	}
	mech := string(body[off : off+mlen])
	off += mlen
	meta["auth_mech"] = mech
	// response: long string
	if off+4 > len(body) {
		return
	}
	rlen := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	if off+int(rlen) > len(body) {
		return
	}
	resp := body[off : off+int(rlen)]
	meta["auth_response_hex"] = byteToHex(resp)
	if mech == "PLAIN" {
		// PLAIN body: authzid\0username\0password
		parts := splitN(resp, 0, 3)
		if len(parts) == 3 {
			meta["auth_user"] = string(parts[1])
			meta["auth_pass"] = string(parts[2])
		}
	}
}

func splitN(b []byte, sep byte, n int) [][]byte {
	out := make([][]byte, 0, n)
	last := 0
	for i := 0; i < len(b) && len(out) < n-1; i++ {
		if b[i] == sep {
			out = append(out, b[last:i])
			last = i + 1
		}
	}
	out = append(out, b[last:])
	return out
}

// buildPropsTable emits an AMQP field-table with string ("S") values.
func (a *amqp) buildPropsTable(props map[string]string) []byte {
	body := make([]byte, 0, 256)
	for k, v := range props {
		body = appendShortStr(body, []byte(k))
		body = append(body, 'S')
		body = appendLongStr(body, []byte(v))
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

func appendShortStr(b, s []byte) []byte {
	b = append(b, byte(len(s)))
	b = append(b, s...)
	return b
}
func appendLongStr(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	b = append(b, s...)
	return b
}

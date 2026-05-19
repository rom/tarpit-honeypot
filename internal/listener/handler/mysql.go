package handler

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type mysql struct{}

func (m *mysql) Name() string { return "mysql" }

// MySQL protocol (port 3306). The server speaks first with a "Handshake
// Initialization Packet" (protocol 10) that advertises capabilities and
// includes a 20-byte salt. The client replies with a "Handshake Response"
// packet carrying username + auth_response (hashed password). We capture
// the username + raw auth_response bytes, then reply with an ERR_Packet
// 1045 (Access denied).
//
// Every MySQL packet has a 4-byte header: length(3) + sequence(1).
func (m *mysql) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// Build handshake packet (sequence id = 0).
	salt1 := make([]byte, 8)
	salt2 := make([]byte, 12)
	_, _ = rand.Read(salt1)
	_, _ = rand.Read(salt2)

	body := []byte{}
	body = append(body, 0x0a)                          // protocol version 10
	body = append(body, []byte("5.7.42-honeypot")...)  // server version
	body = append(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 1)   // connection id
	body = append(body, salt1...)                       // auth_plugin_data_part_1
	body = append(body, 0)                              // filler
	body = append(body, 0xff, 0xf7)                     // capability flags low
	body = append(body, 0x21)                           // utf8_general_ci
	body = append(body, 0x02, 0x00)                     // status flags
	body = append(body, 0xff, 0x81)                     // capability flags high (CLIENT_PLUGIN_AUTH)
	body = append(body, 0x15)                           // length of auth-plugin-data = 21
	body = append(body, make([]byte, 10)...)            // reserved 10 bytes of 0
	body = append(body, salt2...)                       // auth_plugin_data_part_2
	body = append(body, 0)                              // null terminator
	body = append(body, []byte("mysql_native_password")...)
	body = append(body, 0)

	pkt := make([]byte, 4+len(body))
	pkt[0] = byte(len(body))
	pkt[1] = byte(len(body) >> 8)
	pkt[2] = byte(len(body) >> 16)
	pkt[3] = 0
	copy(pkt[4:], body)
	if _, err := conn.Write(pkt); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "mysql handshake (5.7.42-honeypot)"

	// Read client handshake response.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	respLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if respLen < 4 || respLen > 8192 {
		res.Meta["bad_response_len"] = respLen
		return res, nil
	}
	respBody := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBody); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(hdr, respBody...)

	// Parse: client_capabilities(4) max_packet(4) charset(1) reserved(23) username\0 ...
	if len(respBody) >= 32 {
		capFlags := binary.LittleEndian.Uint32(respBody[0:4])
		res.Meta["client_caps"] = capFlags
		p := 32
		nullEnd := indexByte(respBody[p:], 0)
		if nullEnd > 0 {
			res.Meta["username"] = string(respBody[p : p+nullEnd])
			p += nullEnd + 1
		}
		// Auth-response: either length-encoded (CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
		// or 1-byte length + bytes (default). Most clients send 1 byte len.
		if p < len(respBody) {
			alen := int(respBody[p])
			p++
			if p+alen <= len(respBody) && alen > 0 {
				res.Meta["auth_response_hex"] = byteToHex(respBody[p : p+alen])
				p += alen
			}
		}
		// Optional database name (null-terminated string).
		if p < len(respBody) {
			dbEnd := indexByte(respBody[p:], 0)
			if dbEnd > 0 {
				res.Meta["database"] = string(respBody[p : p+dbEnd])
			}
		}
	}

	// Send ERR_Packet 1045 Access denied. Sequence id = 2.
	errBody := []byte{}
	errBody = append(errBody, 0xff)                                   // ERR_Packet marker
	errBody = binary.LittleEndian.AppendUint16(errBody, 1045)         // error code
	errBody = append(errBody, '#')
	errBody = append(errBody, []byte("28000")...)                     // SQL state
	errBody = append(errBody, []byte("Access denied for user")...)    // message
	errPkt := make([]byte, 4+len(errBody))
	errPkt[0] = byte(len(errBody))
	errPkt[1] = byte(len(errBody) >> 8)
	errPkt[2] = byte(len(errBody) >> 16)
	errPkt[3] = 2
	copy(errPkt[4:], errBody)
	_, _ = conn.Write(errPkt)
	return res, nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

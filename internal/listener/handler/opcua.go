package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type opcua struct{}

func (o *opcua) Name() string { return "opcua" }

// OPC-UA TCP (port 4840). The very first message any client sends is a
// Hello (HEL) — 4-byte type code, 'F' (chunk type "final"), 4-byte length,
// then protocol version + buffer sizes + endpoint URL. We respond with an
// Acknowledge (ACK) advertising buffer sizes the client will accept.
//
// We do NOT do the OpenSecureChannel / CreateSession dance — that needs
// real OPC-UA crypto and is out of scope for a fingerprint-grade trap.
func (o *opcua) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	mtype := string(hdr[0:3])
	chunkType := hdr[3]
	msgLen := binary.LittleEndian.Uint32(hdr[4:8])
	res.Meta = map[string]any{
		"message_type": mtype,
		"chunk_type":   string([]byte{chunkType}),
		"message_len":  msgLen,
	}
	if msgLen < 8 || msgLen > 65535 {
		res.Meta["bad_message_len"] = true
		return res, nil
	}

	body := make([]byte, int(msgLen)-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(hdr, body...)

	if mtype != "HEL" {
		// We only know how to fake the very first message. Anything else
		// gets recorded and dropped.
		return res, nil
	}

	// HEL body layout:
	//   version(4) | receive_buf(4) | send_buf(4) | max_msg(4) | max_chunk(4) | endpoint(len-prefixed)
	if len(body) < 20 {
		res.Meta["short_hello"] = true
		return res, nil
	}
	version := binary.LittleEndian.Uint32(body[0:4])
	rxBuf := binary.LittleEndian.Uint32(body[4:8])
	txBuf := binary.LittleEndian.Uint32(body[8:12])
	maxMsg := binary.LittleEndian.Uint32(body[12:16])
	maxChunk := binary.LittleEndian.Uint32(body[16:20])
	res.Meta["version"] = version
	res.Meta["rx_buf"] = rxBuf
	res.Meta["tx_buf"] = txBuf
	res.Meta["max_msg"] = maxMsg
	res.Meta["max_chunks"] = maxChunk

	// Endpoint URL: 4-byte length (int32) + bytes.
	endpoint := ""
	if len(body) >= 24 {
		l := int32(binary.LittleEndian.Uint32(body[20:24]))
		if l > 0 && 24+int(l) <= len(body) {
			endpoint = string(body[24 : 24+int(l)])
		}
	}
	if endpoint != "" {
		res.Meta["endpoint_url"] = endpoint
	}

	// Build ACK: "ACKF" + total length + version + buffer sizes + max_msg + max_chunks
	const ackBodyLen = 20
	const ackTotal = 8 + ackBodyLen
	ack := make([]byte, ackTotal)
	copy(ack[0:4], []byte("ACKF"))
	binary.LittleEndian.PutUint32(ack[4:8], ackTotal)
	binary.LittleEndian.PutUint32(ack[8:12], version)
	binary.LittleEndian.PutUint32(ack[12:16], 65536) // we'd accept 64KB
	binary.LittleEndian.PutUint32(ack[16:20], 65536)
	binary.LittleEndian.PutUint32(ack[20:24], 16777216) // 16MB max msg
	binary.LittleEndian.PutUint32(ack[24:28], 0)

	if _, err := conn.Write(ack); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "opcua ACK"
	return res, nil
}

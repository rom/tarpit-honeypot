package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// mongodb emulates the MongoDB wire protocol (TCP 27017). Unauthenticated
// MongoDB is a classic data-breach source; a client opens with a hello /
// isMaster handshake, then issues find/aggregate/listDatabases to enumerate
// and exfiltrate. We answer the handshake believably, capture the command,
// flag data-access commands, and serve no documents.
type mongodb struct{}

func (m *mongodb) Name() string { return "mongodb" }

// MongoDB opcodes.
const (
	opReply = 1
	opQuery = 2004
	opMsg   = 2013
)

func (m *mongodb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(br, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	msgLen := int(int32(binary.LittleEndian.Uint32(hdr[0:4])))
	reqID := int32(binary.LittleEndian.Uint32(hdr[4:8]))
	opCode := int32(binary.LittleEndian.Uint32(hdr[12:16]))
	res.Meta["mongo_opcode"] = int(opCode)
	if msgLen < 16 || msgLen > 48*1024*1024 {
		res.Meta["mongo_bad_length"] = msgLen
		return res, nil
	}
	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(br, body); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(append([]byte(nil), hdr...), body...)

	if cmd := mongoCommand(opCode, body); cmd != "" {
		res.Meta["mongo_command"] = cmd
		if marker := mongoAbuse(cmd); marker != "" {
			flagAnomaly(&res, marker)
		}
	}

	reply := mongoHelloReply(opCode, reqID)
	_, _ = conn.Write(reply)
	res.BannerSent = "mongodb hello reply"
	return res, nil
}

// mongoCommand pulls the command name (OP_MSG) or collection (OP_QUERY) from
// a request body for logging / abuse detection.
func mongoCommand(opCode int32, body []byte) string {
	switch opCode {
	case opMsg:
		// flagBits(4) + section kind(1) + BSON document.
		if len(body) < 5 || body[4] != 0 {
			return ""
		}
		return firstBSONKey(body[5:])
	case opQuery:
		// flags(4) + cstring fullCollectionName + ...
		if len(body) < 5 {
			return ""
		}
		end := 4
		for end < len(body) && body[end] != 0 {
			end++
		}
		return string(body[4:end])
	}
	return ""
}

// mongoAbuse flags MongoDB commands that read or enumerate data (vs the
// benign handshake commands hello / isMaster / buildInfo / ping).
func mongoAbuse(cmd string) string {
	switch strings.ToLower(cmd) {
	case "find", "aggregate", "getmore", "listcollections", "listdatabases", "count", "distinct", "mapreduce":
		return "mongodb-data-access"
	}
	return ""
}

// firstBSONKey returns the name of the first element in a BSON document
// (int32 length, then type byte + cstring name + value). "" on malformed.
func firstBSONKey(doc []byte) string {
	if len(doc) < 6 {
		return ""
	}
	i := 5 // skip int32 length (4) + element type (1)
	j := i
	for j < len(doc) && doc[j] != 0 {
		j++
	}
	if j >= len(doc) {
		return ""
	}
	return string(doc[i:j])
}

// mongoHelloReply builds an OP_MSG (or OP_REPLY for a legacy OP_QUERY)
// carrying a believable hello/isMaster response document.
func mongoHelloReply(reqOpCode, respTo int32) []byte {
	doc := bsonDoc(
		bsonBool("helloOk", true),
		bsonBool("ismaster", true),
		bsonInt32("maxBsonObjectSize", 16777216),
		bsonInt32("maxMessageSizeBytes", 48000000),
		bsonInt32("maxWriteBatchSize", 100000),
		bsonInt32("maxWireVersion", 17),
		bsonInt32("minWireVersion", 0),
		bsonBool("readOnly", false),
		bsonDouble("ok", 1),
	)
	if reqOpCode == opMsg {
		payload := []byte{0, 0, 0, 0, 0} // flagBits(4) + section kind 0
		payload = append(payload, doc...)
		return append(mongoHeader(int32(16+len(payload)), 1, respTo, opMsg), payload...)
	}
	// Legacy OP_QUERY → OP_REPLY.
	var payload []byte
	payload = append(payload, 0, 0, 0, 0)             // responseFlags
	payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0) // cursorID
	payload = append(payload, 0, 0, 0, 0)             // startingFrom
	payload = append(payload, 1, 0, 0, 0)             // numberReturned = 1
	payload = append(payload, doc...)
	return append(mongoHeader(int32(16+len(payload)), 1, respTo, opReply), payload...)
}

func mongoHeader(msgLen, reqID, respTo, opCode int32) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(h[4:8], uint32(reqID))
	binary.LittleEndian.PutUint32(h[8:12], uint32(respTo))
	binary.LittleEndian.PutUint32(h[12:16], uint32(opCode))
	return h
}

// --- minimal BSON encoder (only the element types the hello doc needs) ---

func bsonDoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	out := make([]byte, 4, 4+len(body)+1)
	binary.LittleEndian.PutUint32(out, uint32(4+len(body)+1))
	out = append(out, body...)
	return append(out, 0x00)
}

func bsonElem(typ byte, name string) []byte {
	e := make([]byte, 0, 2+len(name))
	e = append(e, typ)
	e = append(e, name...)
	return append(e, 0x00)
}

func bsonBool(name string, v bool) []byte {
	e := bsonElem(0x08, name)
	if v {
		return append(e, 0x01)
	}
	return append(e, 0x00)
}

func bsonInt32(name string, v int32) []byte {
	e := bsonElem(0x10, name)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return append(e, b...)
}

func bsonDouble(name string, v float64) []byte {
	e := bsonElem(0x01, name)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(v))
	return append(e, b...)
}

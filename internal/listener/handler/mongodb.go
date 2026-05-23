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
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// mongodb emulates the MongoDB wire protocol (TCP 27017). Unauthenticated
// MongoDB is a classic data-breach source; a client opens with a hello /
// isMaster handshake, then issues find/aggregate/listDatabases to enumerate
// and exfiltrate. We answer the handshake + the common recon commands
// (buildInfo / listDatabases / ping) believably, capture the command, flag
// data-access commands, and serve no documents.
type mongodb struct{ id *identity.Identity }

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

	version, wire := "7.0.8", int32(21)
	if m.id != nil {
		version, wire = m.id.MongoVersion()
	}

	cmd := mongoCommand(opCode, body)
	if cmd != "" {
		res.Meta["mongo_command"] = cmd
		if marker := mongoAbuse(cmd); marker != "" {
			flagAnomaly(&res, marker)
		}
	}

	doc := mongoReplyDoc(cmd, version, wire)
	_, _ = conn.Write(mongoFrameReply(opCode, reqID, doc))
	res.BannerSent = "mongodb reply (" + version + ")"
	return res, nil
}

// mongoReplyDoc picks the BSON response body for a command: the hello/isMaster
// handshake, the believable buildInfo / listDatabases / ping recon answers,
// or an "unauthorized" error for the data-access commands (what a locked-down
// modern MongoDB returns — which still looks like a real server).
func mongoReplyDoc(cmd, version string, wire int32) []byte {
	switch strings.ToLower(cmd) {
	case "buildinfo":
		return mongoBuildInfoDoc(version)
	case "listdatabases":
		return mongoListDatabasesDoc()
	case "ping", "ismaster", "":
		if strings.EqualFold(cmd, "ping") {
			return bsonDoc(bsonDouble("ok", 1))
		}
		return mongoHelloDoc(wire)
	case "hello":
		return mongoHelloDoc(wire)
	case "getcmdlineopts":
		return bsonDoc(
			bsonArray("argv", []byte{}),
			bsonSubdoc("parsed", bsonDoc()),
			bsonDouble("ok", 1),
		)
	case "connectionstatus":
		return bsonDoc(
			bsonSubdoc("authInfo", bsonDoc(
				bsonArray("authenticatedUsers", []byte{}),
				bsonArray("authenticatedUserRoles", []byte{}),
			)),
			bsonDouble("ok", 1),
		)
	case "find", "aggregate", "getmore", "listcollections", "count", "distinct", "mapreduce":
		// A real authenticated-only deployment rejects these with code 13.
		return bsonDoc(
			bsonDouble("ok", 0),
			bsonString("errmsg", "command "+cmd+" requires authentication"),
			bsonInt32("code", 13),
			bsonString("codeName", "Unauthorized"),
		)
	default:
		return mongoHelloDoc(wire)
	}
}

// mongoFrameReply wraps a reply BSON doc in the right envelope for the
// request opcode (OP_MSG for modern OP_MSG/unknown, OP_REPLY for legacy
// OP_QUERY) with a correct length prefix.
func mongoFrameReply(reqOpCode, respTo int32, doc []byte) []byte {
	if reqOpCode == opQuery {
		var payload []byte
		payload = append(payload, 0, 0, 0, 0)             // responseFlags
		payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0) // cursorID
		payload = append(payload, 0, 0, 0, 0)             // startingFrom
		payload = append(payload, 1, 0, 0, 0)             // numberReturned = 1
		payload = append(payload, doc...)
		return append(mongoHeader(int32(16+len(payload)), 1, respTo, opReply), payload...)
	}
	payload := []byte{0, 0, 0, 0, 0} // flagBits(4) + section kind 0
	payload = append(payload, doc...)
	return append(mongoHeader(int32(16+len(payload)), 1, respTo, opMsg), payload...)
}

// mongoBuildInfoDoc returns a believable buildInfo response for a version.
func mongoBuildInfoDoc(version string) []byte {
	parts := strings.SplitN(version, ".", 3)
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	maj, min, pat := atoiOr(parts[0], 7), atoiOr(parts[1], 0), atoiOr(parts[2], 0)
	return bsonDoc(
		bsonString("version", version),
		bsonString("gitVersion", "unknown"),
		bsonArray("versionArray", bsonDoc(
			bsonInt32("0", int32(maj)), bsonInt32("1", int32(min)),
			bsonInt32("2", int32(pat)), bsonInt32("3", 0),
		)),
		bsonString("openssl", "OpenSSL 3.0.2 15 Mar 2022"),
		bsonString("allocator", "tcmalloc"),
		bsonString("javascriptEngine", "mozjs"),
		bsonInt32("bits", 64),
		bsonBool("debug", false),
		bsonInt32("maxBsonObjectSize", 16777216),
		bsonDouble("ok", 1),
	)
}

// mongoListDatabasesDoc returns a believable listDatabases response naming
// the default system databases (admin / config / local).
func mongoListDatabasesDoc() []byte {
	db := func(name string, size int32) []byte {
		return bsonDoc(
			bsonString("name", name),
			bsonInt32("sizeOnDisk", size),
			bsonBool("empty", false),
		)
	}
	dbs := bsonDoc(
		bsonSubdoc("0", db("admin", 40960)),
		bsonSubdoc("1", db("config", 110592)),
		bsonSubdoc("2", db("local", 73728)),
	)
	return bsonDoc(
		bsonArray("databases", dbs),
		bsonInt32("totalSize", 225280),
		bsonDouble("ok", 1),
	)
}

func atoiOr(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return def
	}
	return n
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

// mongoHelloDoc builds a believable hello/isMaster response document for the
// negotiated max wire version (framing is added by mongoFrameReply).
func mongoHelloDoc(wire int32) []byte {
	return bsonDoc(
		bsonBool("helloOk", true),
		bsonBool("ismaster", true),
		bsonInt32("maxBsonObjectSize", 16777216),
		bsonInt32("maxMessageSizeBytes", 48000000),
		bsonInt32("maxWriteBatchSize", 100000),
		bsonInt32("maxWireVersion", wire),
		bsonInt32("minWireVersion", 0),
		bsonBool("readOnly", false),
		bsonDouble("ok", 1),
	)
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

// bsonString encodes a UTF-8 string element (type 0x02): int32 byte-length
// (including the trailing NUL) followed by the bytes + NUL.
func bsonString(name, v string) []byte {
	e := bsonElem(0x02, name)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(v)+1))
	e = append(e, b...)
	e = append(e, v...)
	return append(e, 0x00)
}

// bsonSubdoc embeds an already-encoded document as an element (type 0x03).
func bsonSubdoc(name string, doc []byte) []byte {
	e := bsonElem(0x03, name)
	return append(e, doc...)
}

// bsonArray embeds an already-encoded document as a BSON array element
// (type 0x04). The caller builds the doc with integer-string keys ("0",
// "1", …); pass an empty slice for an empty array.
func bsonArray(name string, doc []byte) []byte {
	e := bsonElem(0x04, name)
	if len(doc) == 0 {
		// empty document: int32 length(5) + terminator.
		return append(e, 0x05, 0x00, 0x00, 0x00, 0x00)
	}
	return append(e, doc...)
}

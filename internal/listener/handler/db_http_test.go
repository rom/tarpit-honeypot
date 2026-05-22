package handler

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// opMsgRequest frames a MongoDB OP_MSG carrying a single-element BSON body
// whose first key is cmd (the command name).
func opMsgRequest(cmd string) []byte {
	doc := bsonDoc(bsonInt32(cmd, 1))
	payload := append([]byte{0, 0, 0, 0, 0}, doc...) // flagBits + section kind 0
	return append(mongoHeader(int32(16+len(payload)), 7, 0, opMsg), payload...)
}

func TestMongoDBHelloReplyAndAbuse(t *testing.T) {
	// A "find" command must be flagged as data access, and the reply must be
	// a well-framed OP_MSG whose length prefix matches its byte count.
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	var res Result
	done := make(chan struct{})
	go func() { defer close(done); res, _ = (&mongodb{}).Handle(context.Background(), server, cfg) }()

	reply := make(chan []byte, 1)
	go func() {
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(client, hdr); err != nil {
			reply <- nil
			return
		}
		n := int(int32(binary.LittleEndian.Uint32(hdr[0:4])))
		rest := make([]byte, n-16)
		_, _ = io.ReadFull(client, rest)
		reply <- append(hdr, rest...)
	}()

	if _, err := client.Write(opMsgRequest("find")); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := <-reply
	<-done

	if r == nil || len(r) < 16 {
		t.Fatalf("no/short reply: %v", r)
	}
	if op := int32(binary.LittleEndian.Uint32(r[12:16])); op != opMsg {
		t.Errorf("reply opcode = %d; want %d (OP_MSG)", op, opMsg)
	}
	if int(int32(binary.LittleEndian.Uint32(r[0:4]))) != len(r) {
		t.Errorf("reply length prefix %d != actual %d", binary.LittleEndian.Uint32(r[0:4]), len(r))
	}
	if res.Meta["mongo_command"] != "find" {
		t.Errorf("mongo_command = %v; want find", res.Meta["mongo_command"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "mongodb-data-access") {
		t.Errorf("find not flagged as data access: %v", anoms)
	}
}

func TestElasticsearchBannerAndRecon(t *testing.T) {
	res := runConn(t, &elasticsearch{}, "GET /_cat/indices HTTP/1.1\r\nHost: es\r\n\r\n")
	if res.Meta["http_path"] != "/_cat/indices" {
		t.Errorf("path = %v", res.Meta["http_path"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "elasticsearch-recon") {
		t.Errorf("_cat/indices not flagged recon: %v", anoms)
	}

	// A _search hits the data-access path.
	res = runConn(t, &elasticsearch{}, "GET /my-index/_search HTTP/1.1\r\nHost: es\r\n\r\n")
	anoms, _ = res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "elasticsearch-data-access") {
		t.Errorf("_search not flagged data access: %v", anoms)
	}
}

func TestElasticBodyBanner(t *testing.T) {
	if !strings.Contains(elasticBody("/"), "You Know, for Search") {
		t.Errorf("root banner missing tagline")
	}
}

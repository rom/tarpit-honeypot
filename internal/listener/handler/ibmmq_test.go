package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// An IBM MQ Initial Data (TSH opcode 0x01) flow is captured: the connect is
// flagged, the SVRCONN channel name extracted, and an intent recorded.
func TestIBMMQConnectCapture(t *testing.T) {
	cli, srv := net.Pipe()
	out := make(chan Result, 1)
	go func() {
		r, _ := (&ibmmq{}).Handle(context.Background(), srv, config.Listener{ReadTimeout: 2 * time.Second})
		out <- r
	}()

	seg := []byte("TSH ")
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 120) // MQSegmLen
	hdr[4] = 0x01                             // ByteOrder
	hdr[5] = 0x01                             // SegmType = INITIAL_DATA
	seg = append(seg, hdr...)
	seg = append(seg, []byte("ID  ")...)            // Initial Data struct id
	seg = append(seg, 0x0b, 0x00, 0x00, 0x00)       // FAP level etc.
	seg = append(seg, []byte("DEV.APP.SVRCONN")...) // channel name
	seg = append(seg, 0x00)
	seg = append(seg, []byte("QM.PROD")...) // queue manager
	_, _ = cli.Write(seg)
	_ = cli.Close()

	r := <-out
	if !hasAnom(r, "ibmmq-connect") {
		t.Errorf("ibmmq-connect not flagged: %v", r.Meta["anomalies"])
	}
	if r.Meta["mq_opcode"] != "INITIAL_DATA" {
		t.Errorf("mq_opcode = %v, want INITIAL_DATA", r.Meta["mq_opcode"])
	}
	if r.Meta["mq_channel"] != "DEV.APP.SVRCONN" {
		t.Errorf("mq_channel = %v, want DEV.APP.SVRCONN", r.Meta["mq_channel"])
	}
	if it, _ := r.Meta["intent"].(string); !strings.Contains(it, "reconnaissance") {
		t.Errorf("intent = %q", it)
	}
}

func TestIBMMQNonMQ(t *testing.T) {
	cli, srv := net.Pipe()
	out := make(chan Result, 1)
	go func() {
		r, _ := (&ibmmq{}).Handle(context.Background(), srv, config.Listener{ReadTimeout: 2 * time.Second})
		out <- r
	}()
	_, _ = cli.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_ = cli.Close()
	r := <-out
	if r.Meta["non_mq"] != true {
		t.Errorf("non-MQ payload should be flagged non_mq: %v", r.Meta)
	}
}

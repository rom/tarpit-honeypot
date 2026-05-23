package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestCassandraOptionsSupported(t *testing.T) {
	req := []byte{0x04, 0x00, 0x00, 0x01, 0x05} // v4, stream 1, OPTIONS
	req = binary.BigEndian.AppendUint32(req, 0) // length 0
	res, reply := runDevsvc(t, &cassandra{}, req)
	if len(reply) < 5 || reply[4] != 0x06 { // SUPPORTED opcode
		t.Errorf("reply = %v; want SUPPORTED (0x06)", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "cassandra-probe") {
		t.Errorf("anomalies = %v; want cassandra-probe", anoms)
	}
}

func TestNatsGreetsAndCapturesConnect(t *testing.T) {
	// NATS is server-speaks-first, so read the greeting before sending.
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "nats", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&natsBroker{}).Handle(context.Background(), server, cfg) }()
	buf := make([]byte, 256)
	n, _ := client.Read(buf) // greeting
	if n < 4 || string(buf[:4]) != "INFO" {
		t.Errorf("greeting = %q; want INFO", buf[:n])
	}
	_, _ = client.Write([]byte("CONNECT {\"user\":\"admin\",\"pass\":\"x\"}\r\n"))
	_, _ = client.Read(buf) // +OK
	client.Close()
	<-done
	if res.Meta["nats_connect"] == nil {
		t.Errorf("CONNECT not captured: %v", res.Meta)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "nats-connect") {
		t.Errorf("anomalies = %v; want nats-connect", anoms)
	}
}

func TestRpcbindDumpFlagged(t *testing.T) {
	msg := make([]byte, 28)
	binary.BigEndian.PutUint32(msg[4:8], 0)        // mtype CALL
	binary.BigEndian.PutUint32(msg[8:12], 2)       // rpcvers
	binary.BigEndian.PutUint32(msg[12:16], 100000) // portmapper
	binary.BigEndian.PutUint32(msg[16:20], 2)      // vers
	binary.BigEndian.PutUint32(msg[20:24], 4)      // proc DUMP
	req := binary.BigEndian.AppendUint32(nil, uint32(len(msg))|0x80000000)
	req = append(req, msg...)
	res, reply := runDevsvc(t, &rpcbind{}, req)
	if res.Meta["rpc_program"] != uint32(100000) {
		t.Errorf("rpc_program = %v; want 100000", res.Meta["rpc_program"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "rpcbind-dump") {
		t.Errorf("anomalies = %v; want rpcbind-dump", anoms)
	}
	if len(reply) == 0 {
		t.Errorf("expected an accepted RPC reply")
	}
}

func TestPPTPReplySCCRP(t *testing.T) {
	req := make([]byte, 12)
	binary.BigEndian.PutUint16(req[0:2], 156)
	binary.BigEndian.PutUint16(req[2:4], 1)
	binary.BigEndian.PutUint32(req[4:8], 0x1A2B3C4D)
	binary.BigEndian.PutUint16(req[8:10], 1) // SCCRQ
	res, reply := runDevsvc(t, &pptp{}, req)
	if len(reply) != 156 || binary.BigEndian.Uint16(reply[8:10]) != 2 {
		t.Errorf("reply len=%d type=%v; want 156-byte SCCRP", len(reply), reply[8:10])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "pptp-probe") {
		t.Errorf("anomalies = %v; want pptp-probe", anoms)
	}
}

// capPC captures the single datagram a UDP handler writes back.
type capPC struct {
	wrote []byte
	to    net.Addr
}

func (c *capPC) WriteTo(b []byte, a net.Addr) (int, error) {
	c.wrote = append([]byte(nil), b...)
	c.to = a
	return len(b), nil
}
func (c *capPC) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *capPC) Close() error                           { return nil }
func (c *capPC) LocalAddr() net.Addr                    { return nil }
func (c *capPC) SetDeadline(time.Time) error            { return nil }
func (c *capPC) SetReadDeadline(time.Time) error        { return nil }
func (c *capPC) SetWriteDeadline(time.Time) error       { return nil }

func TestStunBindingResponse(t *testing.T) {
	req := []byte{0x00, 0x01, 0x00, 0x00} // Binding Request, len 0
	req = binary.BigEndian.AppendUint32(req, 0x2112A442)
	req = append(req, make([]byte, 12)...) // txid
	pc := &capPC{}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 50000}
	res, _ := (&stun{lim: newUDPReflectLimiter()}).Handle(context.Background(), req, src, pc, config.Listener{})
	if len(pc.wrote) < 4 || pc.wrote[0] != 0x01 || pc.wrote[1] != 0x01 {
		t.Errorf("stun response = %v; want Binding Success (0x0101)", pc.wrote)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "stun-binding") {
		t.Errorf("anomalies = %v; want stun-binding", anoms)
	}
}

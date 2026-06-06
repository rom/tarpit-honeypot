package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func bgpHeader(msgType byte, body []byte) []byte {
	m := make([]byte, 19)
	for i := 0; i < 16; i++ {
		m[i] = 0xFF
	}
	binary.BigEndian.PutUint16(m[16:18], uint16(19+len(body)))
	m[18] = msgType
	return append(m, body...)
}

func drive(t *testing.T, h func(net.Conn) Result, msg []byte) Result {
	t.Helper()
	cli, srv := net.Pipe()
	out := make(chan Result, 1)
	go func() { out <- h(srv) }()
	_, _ = cli.Write(msg)
	_ = cli.Close()
	select {
	case r := <-out:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("handler timed out")
		return Result{}
	}
}

// A BGP UPDATE carrying NLRI is a route-injection (prefix-hijack) attempt.
func TestBGPRouteInjection(t *testing.T) {
	body := []byte{0, 0, 0, 0, 24, 10, 0, 0} // withdrawn-len=0, attr-len=0, NLRI 10.0.0.0/24
	r := drive(t, func(c net.Conn) Result {
		res, _ := bgpH{}.Handle(context.Background(), c, config.Listener{ReadTimeout: 2 * time.Second})
		return res
	}, bgpHeader(2, body))
	if !hasAnom(r, "bgp-route-injection") {
		t.Errorf("route injection not flagged: %v", r.Meta["anomalies"])
	}
	if it, _ := r.Meta["intent"].(string); it == "" {
		t.Error("missing intent")
	}
}

// A SunRPC GETPORT lookup for the nfs program is NFS-mount reconnaissance.
func TestRPCBindNFSEnum(t *testing.T) {
	msg := make([]byte, 56)
	binary.BigEndian.PutUint32(msg[8:12], 2)       // rpcvers
	binary.BigEndian.PutUint32(msg[12:16], 100000) // portmapper
	binary.BigEndian.PutUint32(msg[16:20], 2)      // vers
	binary.BigEndian.PutUint32(msg[20:24], 3)      // GETPORT
	// cred (flavor@24,len@28)=0, verf (flavor@32,len@36)=0 already zero.
	binary.BigEndian.PutUint32(msg[40:44], 100003) // target program = nfs
	binary.BigEndian.PutUint32(msg[44:48], 3)      // vers
	binary.BigEndian.PutUint32(msg[48:52], 6)      // proto tcp
	rec := binary.BigEndian.AppendUint32(nil, uint32(len(msg))|0x80000000)
	rec = append(rec, msg...)

	r := drive(t, func(c net.Conn) Result {
		res, _ := (&rpcbind{}).Handle(context.Background(), c, config.Listener{ReadTimeout: 2 * time.Second})
		return res
	}, rec)
	if r.Meta["rpc_target_name"] != "nfs" {
		t.Errorf("rpc_target_name = %v, want nfs", r.Meta["rpc_target_name"])
	}
	if !hasAnom(r, "rpcbind-nfs-enum") {
		t.Errorf("rpcbind-nfs-enum not flagged: %v", r.Meta["anomalies"])
	}
}

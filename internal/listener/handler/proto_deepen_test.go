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

// rpcRecord wraps an RPC message body in a last-fragment record marker.
func rpcRecord(msg []byte) []byte {
	rec := binary.BigEndian.AppendUint32(nil, uint32(len(msg))|0x80000000)
	return append(rec, msg...)
}

// nfsCall builds a record-marked NFS RPC CALL with the given version/proc, an
// AUTH_UNIX cred carrying uid, and trailing procedure-argument bytes.
func nfsCall(vers, proc, uid uint32, args []byte) []byte {
	msg := make([]byte, 24)
	binary.BigEndian.PutUint32(msg[0:4], 0xC0FFEE00) // xid
	// msg_type=0 (CALL) at [4:8] already zero
	binary.BigEndian.PutUint32(msg[8:12], 2)       // rpcvers
	binary.BigEndian.PutUint32(msg[12:16], 100003) // nfs
	binary.BigEndian.PutUint32(msg[16:20], vers)
	binary.BigEndian.PutUint32(msg[20:24], proc)
	// AUTH_UNIX cred: stamp(4)+machinename<0>(4)+uid(4)+gid(4)+numgids(4) = 20.
	cred := make([]byte, 20)
	binary.BigEndian.PutUint32(cred[8:12], uid)
	msg = binary.BigEndian.AppendUint32(msg, 1) // cred flavor AUTH_UNIX
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(cred)))
	msg = append(msg, cred...)
	msg = binary.BigEndian.AppendUint32(msg, 0) // verf flavor AUTH_NULL
	msg = binary.BigEndian.AppendUint32(msg, 0) // verf length
	msg = append(msg, args...)
	return rpcRecord(msg)
}

// An NFSv4 COMPOUND of PUTROOTFH;GETFH;READDIR as uid 0 is export traversal
// plus a no_root_squash bypass.
func TestNFSCompoundEnum(t *testing.T) {
	// COMPOUND args: tag<0>, minorversion=0, numops=3, ops.
	var args []byte
	args = binary.BigEndian.AppendUint32(args, 0)  // tag length 0
	args = binary.BigEndian.AppendUint32(args, 0)  // minorversion
	args = binary.BigEndian.AppendUint32(args, 3)  // numops
	args = binary.BigEndian.AppendUint32(args, 24) // PUTROOTFH
	args = binary.BigEndian.AppendUint32(args, 10) // GETFH
	args = binary.BigEndian.AppendUint32(args, 26) // READDIR
	// READDIR args: cookie(8)+verf(8)+dircount(4)+maxcount(4)+attrbitmap count 0(4).
	args = append(args, make([]byte, 28)...)

	r := drive(t, func(c net.Conn) Result {
		res, _ := (&nfs{}).Handle(context.Background(), c, config.Listener{ReadTimeout: 2 * time.Second})
		return res
	}, nfsCall(4, 1, 0, args))

	ops, _ := r.Meta["nfs_ops"].([]string)
	found := false
	for _, o := range ops {
		if o == "READDIR" {
			found = true
		}
	}
	if !found {
		t.Errorf("READDIR not parsed from COMPOUND ops: %v", ops)
	}
	if !hasAnom(r, "nfs-export-enum") {
		t.Errorf("nfs-export-enum not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "nfs-root-access") {
		t.Errorf("nfs-root-access (uid 0) not flagged: %v", r.Meta["anomalies"])
	}
	if r.Meta["nfs_auth_uid"] != uint32(0) {
		t.Errorf("nfs_auth_uid = %v, want 0", r.Meta["nfs_auth_uid"])
	}
	if it, _ := r.Meta["intent"].(string); it == "" {
		t.Error("missing intent")
	}
}

// An NFSv3 READ is a file-read over the share.
func TestNFSv3Read(t *testing.T) {
	r := drive(t, func(c net.Conn) Result {
		res, _ := (&nfs{}).Handle(context.Background(), c, config.Listener{ReadTimeout: 2 * time.Second})
		return res
	}, nfsCall(3, 6, 1000, nil))

	if r.Meta["nfs_proc"] != "READ" {
		t.Errorf("nfs_proc = %v, want READ", r.Meta["nfs_proc"])
	}
	if !hasAnom(r, "nfs-file-read") {
		t.Errorf("nfs-file-read not flagged: %v", r.Meta["anomalies"])
	}
}

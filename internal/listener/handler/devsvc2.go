package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Round-two protocol decoys: the Cassandra CQL native protocol, the NATS
// messaging text protocol, the SunRPC portmapper (the NFS-enumeration entry
// point), PPTP VPN control, and STUN (UDP). As with devsvc.go each reads a
// bounded request, answers just enough to look real, captures it, and flags
// the high-signal markers.

// --- Cassandra CQL native protocol (9042) --------------------------------
//
// CQL frames are [version(1)][flags(1)][stream(2)][opcode(1)][length(4)]
// [body]. A scanner sends OPTIONS or STARTUP; we answer SUPPORTED /
// AUTHENTICATE so it records a live (auth-required) cluster, and capture any
// AUTH_RESPONSE credentials.
type cassandra struct{}

func (h *cassandra) Name() string { return "cassandra" }

func cqlFrame(stream []byte, opcode byte, body []byte) []byte {
	f := []byte{0x84, 0x00}  // response version (v4), no flags
	f = append(f, stream...) // echo the 2-byte stream id
	f = append(f, opcode)
	f = binary.BigEndian.AppendUint32(f, uint32(len(body)))
	return append(f, body...)
}

func cqlString(s string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...)
}

func (h *cassandra) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "cassandra-probe")
	if len(got) < 9 || got[0]&0x7f < 3 || got[0]&0x7f > 5 {
		return res, nil // not a CQL frame
	}
	stream, opcode := got[2:4], got[4]
	res.Meta["cql_version"] = int(got[0] & 0x7f)
	res.Meta["cql_opcode"] = int(opcode)
	switch opcode {
	case 0x05: // OPTIONS -> SUPPORTED (empty string-multimap)
		_, _ = conn.Write(cqlFrame(stream, 0x06, []byte{0x00, 0x00}))
	case 0x0f: // AUTH_RESPONSE -> capture SASL token, reply ERROR
		if len(got) > 13 {
			tok := got[13:]
			if i := strings.IndexByte(string(tok), 0); i >= 0 { // PLAIN: \0user\0pass
				res.Meta["cql_auth"] = strings.ReplaceAll(strings.TrimLeft(string(tok), "\x00"), "\x00", ":")
			}
		}
		flagAnomaly(&res, "cassandra-auth-attempt")
		body := append(binary.BigEndian.AppendUint32(nil, 0x0100), cqlString("Bad credentials")...)
		_, _ = conn.Write(cqlFrame(stream, 0x00, body))
	default: // STARTUP / others -> AUTHENTICATE
		_, _ = conn.Write(cqlFrame(stream, 0x03, cqlString("org.apache.cassandra.auth.PasswordAuthenticator")))
	}
	res.BannerSent = "cassandra cql frame"
	return res, nil
}

// --- NATS messaging (4222) -----------------------------------------------
//
// NATS greets with INFO {json}; clients send CONNECT (often with
// user/pass/auth_token), PUB and SUB. We greet, answer +OK/PONG, and
// capture CONNECT credentials + published subjects.
type natsBroker struct{}

func (h *natsBroker) Name() string { return "nats" }

func (h *natsBroker) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	withTimeout(conn, cfg.ReadTimeout)
	_, _ = conn.Write([]byte("INFO {\"server_id\":\"NDXYZ\",\"version\":\"2.10.16\",\"proto\":1," +
		"\"go\":\"go1.22.4\",\"max_payload\":1048576,\"auth_required\":true,\"tls_required\":false}\r\n"))
	res.BannerSent = "nats INFO"
	buf := make([]byte, 1024)
	for i := 0; i < 16; i++ {
		withTimeout(conn, cfg.ReadTimeout)
		n, err := conn.Read(buf)
		if n > 0 {
			res.Payload = append(res.Payload, buf[:n]...)
		}
		if err != nil {
			break
		}
		line := strings.TrimRight(string(buf[:n]), "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "CONNECT":
			res.Meta["nats_connect"] = line
			flagAnomaly(&res, "nats-connect")
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "PUB", "HPUB":
			flagAnomaly(&res, "nats-publish")
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "SUB":
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("PONG\r\n"))
		case "":
			// payload continuation line; ignore
		default:
			_, _ = conn.Write([]byte("-ERR 'Unknown Protocol Operation'\r\n"))
		}
	}
	return res, nil
}

// --- SunRPC portmapper / rpcbind (111) -----------------------------------
//
// The portmapper is how an attacker enumerates a host's RPC services
// (NFS/mountd/nlockmgr) before mounting shares. We parse the RPC call
// (record-marked), capture program/proc, and answer an accepted-but-empty
// reply. DUMP / GETPORT are flagged.
type rpcbind struct{}

func (h *rpcbind) Name() string { return "rpcbind" }

func (h *rpcbind) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "rpcbind-query")
	if len(got) < 28 {
		return res, nil
	}
	msg := got[4:] // skip the 4-byte record-marking header
	if binary.BigEndian.Uint32(msg[4:8]) != 0 {
		return res, nil // not an RPC call
	}
	xid := msg[0:4]
	prog := binary.BigEndian.Uint32(msg[12:16])
	proc := binary.BigEndian.Uint32(msg[20:24])
	res.Meta["rpc_program"] = prog
	res.Meta["rpc_proc"] = proc
	if prog == 100000 { // portmapper
		switch proc {
		case 4:
			flagAnomaly(&res, "rpcbind-dump")
		case 3:
			flagAnomaly(&res, "rpcbind-getport")
		}
	}
	reply := append([]byte{}, xid...)
	reply = binary.BigEndian.AppendUint32(reply, 1) // REPLY
	reply = binary.BigEndian.AppendUint32(reply, 0) // MSG_ACCEPTED
	reply = binary.BigEndian.AppendUint32(reply, 0) // verf flavor AUTH_NULL
	reply = binary.BigEndian.AppendUint32(reply, 0) // verf length
	reply = binary.BigEndian.AppendUint32(reply, 0) // accept_stat SUCCESS
	reply = binary.BigEndian.AppendUint32(reply, 0) // DUMP: no entries / GETPORT: port 0
	out := binary.BigEndian.AppendUint32(nil, uint32(len(reply))|0x80000000)
	out = append(out, reply...)
	_, _ = conn.Write(out)
	res.BannerSent = "rpc accepted reply"
	return res, nil
}

// --- PPTP VPN control (1723) ---------------------------------------------
//
// PPTP control messages start with length(2), control-packet-type(2),
// magic cookie 0x1A2B3C4D, control-message-type(2). We verify the cookie,
// answer a Start-Control-Connection-Reply to a SCCRQ, and flag the probe.
type pptp struct{}

func (h *pptp) Name() string { return "pptp" }

func (h *pptp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 256))
	res.Payload = got
	flagAnomaly(&res, "pptp-probe")
	if len(got) < 10 || binary.BigEndian.Uint32(got[4:8]) != 0x1A2B3C4D {
		return res, nil
	}
	ctrlType := binary.BigEndian.Uint16(got[8:10])
	res.Meta["pptp_ctrl_type"] = int(ctrlType)
	if ctrlType == 1 { // Start-Control-Connection-Request -> Reply (type 2)
		r := make([]byte, 156)
		binary.BigEndian.PutUint16(r[0:2], 156)        // length
		binary.BigEndian.PutUint16(r[2:4], 1)          // control packet
		binary.BigEndian.PutUint32(r[4:8], 0x1A2B3C4D) // magic cookie
		binary.BigEndian.PutUint16(r[8:10], 2)         // SCCRP
		binary.BigEndian.PutUint16(r[12:14], 0x0100)   // protocol version 1.0
		r[14] = 1                                      // result code: OK
		binary.BigEndian.PutUint16(r[16:18], 1)        // framing capabilities
		binary.BigEndian.PutUint16(r[18:20], 1)        // bearer capabilities
		binary.BigEndian.PutUint16(r[22:24], 1)        // max channels
		copy(r[26:], "MikroTik")                       // host name (decorative)
		_, _ = conn.Write(r)
		res.BannerSent = "pptp SCCRP"
	}
	return res, nil
}

// --- STUN (UDP 3478) -----------------------------------------------------
//
// STUN is a NAT/VoIP-recon probe. A Binding Request gets a Binding Success
// Response carrying the source's XOR-MAPPED-ADDRESS — the same size as the
// request, so this is reflection-safe (and still rate-limited). Flags the
// binding so VoIP/NAT reconnaissance is recorded.
type stun struct{ lim *udpReflectLimiter }

func (h *stun) Name() string { return "stun" }

func (h *stun) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}, Payload: payload}
	if len(payload) < 20 || binary.BigEndian.Uint32(payload[4:8]) != 0x2112A442 {
		flagAnomaly(&res, "stun-malformed")
		// Classic STUN (RFC 3489, no magic cookie) Binding Request is a
		// reflection/amplification vector — larger reply, spoofable source. We
		// never answer it; we flag it.
		if len(payload) >= 2 && binary.BigEndian.Uint16(payload[0:2]) == 0x0001 {
			flagAnomaly(&res, "stun-classic-amplification")
		}
		return res, nil
	}
	msgType := binary.BigEndian.Uint16(payload[0:2])
	res.Meta["stun_msg_type"] = int(msgType)
	flagAnomaly(&res, "stun-binding")
	if msgType != 0x0001 || !h.lim.allow() {
		return res, nil // only answer Binding Requests; bounded
	}
	host, portStr, err := net.SplitHostPort(src.String())
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return res, nil
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	// XOR-MAPPED-ADDRESS (RFC 5389 §15.2). The port is always XORed with the
	// high 16 bits of the magic cookie; the address is XORed with the cookie
	// (IPv4) or the cookie+transaction-id (IPv6). STUN is heavily used by
	// WebRTC/VoIP over IPv6, so we answer both families.
	attr := []byte{0x00, 0x20} // XOR-MAPPED-ADDRESS attribute type
	if v4 := ip.To4(); v4 != nil {
		attr = append(attr, 0x00, 0x08, 0x00, 0x01) // len 8, family IPv4
		attr = binary.BigEndian.AppendUint16(attr, uint16(port)^0x2112)
		attr = append(attr, v4[0]^0x21, v4[1]^0x12, v4[2]^0xA4, v4[3]^0x42)
	} else {
		v6 := ip.To16()
		attr = append(attr, 0x00, 0x14, 0x00, 0x02) // len 20, family IPv6
		attr = binary.BigEndian.AppendUint16(attr, uint16(port)^0x2112)
		// Address XOR key = magic cookie (payload[4:8]) || transaction id
		// (payload[8:20]).
		key := payload[4:20]
		xaddr := make([]byte, 16)
		for i := 0; i < 16; i++ {
			xaddr[i] = v6[i] ^ key[i]
		}
		attr = append(attr, xaddr...)
	}
	resp := []byte{0x01, 0x01} // Binding Success Response
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(attr)))
	resp = append(resp, payload[4:20]...) // magic cookie + txid
	resp = append(resp, attr...)
	_, _ = pc.WriteTo(resp, src)
	res.BannerSent = "stun binding success"
	return res, nil
}

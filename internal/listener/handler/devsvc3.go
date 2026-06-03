package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Round-three protocol decoys: the Android Debug Bridge (a botnet-scale IoT
// RCE surface), the Apache JServ Protocol (Ghostcat), the Erlang Port Mapper
// (cluster / lateral-movement enumeration), TACACS+ (network-gear AAA), and
// the SQL Server Resolution Protocol browser (UDP). As with devsvc.go /
// devsvc2.go each reads a bounded request, answers just enough to look real,
// captures it, and flags the high-signal markers.

// --- Android Debug Bridge (5555) -----------------------------------------
//
// An exposed ADB daemon is unauthenticated remote code execution — the basis
// of ADB.Miner and a long tail of Android-IoT botnets. Messages are a 24-byte
// little-endian header [command][arg0][arg1][data_len][data_check][magic]
// where magic = command ^ 0xffffffff. We answer a CNXN with a believable
// device identity (so a scanner records a live device) and flag any OPEN of a
// shell/exec stream — the actual code-execution step.
type adb struct{}

func (h *adb) Name() string { return "adb" }

func adbMessage(cmd string, arg0, arg1 uint32, payload []byte) []byte {
	b := make([]byte, 24)
	copy(b[0:4], cmd)
	binary.LittleEndian.PutUint32(b[4:8], arg0)
	binary.LittleEndian.PutUint32(b[8:12], arg1)
	binary.LittleEndian.PutUint32(b[12:16], uint32(len(payload)))
	var sum uint32
	for _, c := range payload { // ADB v1 data_check is a simple byte sum
		sum += uint32(c)
	}
	binary.LittleEndian.PutUint32(b[16:20], sum)
	binary.LittleEndian.PutUint32(b[20:24], binary.LittleEndian.Uint32(b[0:4])^0xffffffff)
	return append(b, payload...)
}

func (h *adb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 1024))
	res.Payload = got
	flagAnomaly(&res, "adb-connect")
	if len(got) < 24 {
		return res, nil
	}
	cmd := string(got[0:4])
	res.Meta["adb_command"] = cmd
	dataLen := int(binary.LittleEndian.Uint32(got[12:16]))
	var payload []byte
	if dataLen > 0 && len(got) > 24 {
		end := 24 + dataLen
		if end > len(got) {
			end = len(got)
		}
		payload = got[24:end]
	}
	switch cmd {
	case "CNXN": // connection handshake -> advertise our own device identity
		if len(payload) > 0 {
			res.Meta["adb_client_banner"] = strings.TrimRight(string(payload), "\x00")
		}
		sysid := "device::ro.product.name=raven;ro.product.model=Pixel 6;ro.product.device=raven;features=cmd,shell_v2,stat_v2,ls_v2\x00"
		_, _ = conn.Write(adbMessage("CNXN", 0x01000001, 256*1024, []byte(sysid)))
		res.BannerSent = "adb CNXN device"
	case "OPEN": // open a stream — "shell:" / "exec:" is hands-on code execution
		dest := strings.TrimRight(string(payload), "\x00")
		res.Meta["adb_open"] = dest
		if strings.HasPrefix(dest, "shell") || strings.HasPrefix(dest, "exec") {
			flagAnomaly(&res, "adb-shell-open")
		}
		_, _ = conn.Write(adbMessage("CLSE", 0, binary.LittleEndian.Uint32(got[4:8]), nil))
	case "AUTH": // RSA-key auth — ask for a signature so the client keeps talking
		flagAnomaly(&res, "adb-auth")
		_, _ = conn.Write(adbMessage("AUTH", 1, 0, []byte("\x00")))
	}
	return res, nil
}

// --- Apache JServ Protocol / AJP13 (8009) --------------------------------
//
// AJP connects a front-end web server to a servlet container (Tomcat). Left
// exposed it is the Ghostcat file-read / -inclusion vector (CVE-2020-1938).
// Client packets are [0x12 0x34][length(2)][prefix-code][...]; prefix 2 is a
// Forward Request, 10/8 are CPing/Ping. We answer so a scanner sees a live
// connector and flag forward requests (the attack carrier).
type ajp13 struct{}

func (h *ajp13) Name() string { return "ajp13" }

func (h *ajp13) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 2048))
	res.Payload = got
	flagAnomaly(&res, "ajp-probe")
	if len(got) < 5 || got[0] != 0x12 || got[1] != 0x34 {
		return res, nil
	}
	res.Meta["ajp_length"] = int(binary.BigEndian.Uint16(got[2:4]))
	prefix := got[4]
	res.Meta["ajp_prefix_code"] = int(prefix)
	switch prefix {
	case 2: // Forward Request -> Send Headers (200) + End Response (container->server: 'A''B')
		flagAnomaly(&res, "ajp-forward-request")
		_, _ = conn.Write([]byte{0x41, 0x42, 0x00, 0x02, 0x05, 0x01}) // End Response, reuse=1
		res.BannerSent = "ajp end-response"
	case 8, 10: // Ping / CPing -> CPong (prefix 9)
		_, _ = conn.Write([]byte{0x41, 0x42, 0x00, 0x01, 0x09})
		res.BannerSent = "ajp cpong"
	}
	return res, nil
}

// --- Erlang Port Mapper Daemon / epmd (4369) -----------------------------
//
// epmd brokers the ports of every Erlang/Elixir node on a host (RabbitMQ,
// CouchDB, ejabberd, Riak) and is the entry point for cluster lateral
// movement — a guessed/leaked cookie yields code execution on the node. A
// request is [length(2)][op]; op 110 ('n') NAMES, 122 ('z') PORT_PLEASE2. We
// answer with a node list / port reply so the enumeration "succeeds".
type epmd struct{}

func (h *epmd) Name() string { return "epmd" }

func (h *epmd) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "epmd-query")
	if len(got) < 3 {
		return res, nil
	}
	op := got[2]
	res.Meta["epmd_op"] = int(op)
	switch op {
	case 110: // NAMES_REQ -> [epmd port(4)][ASCII node list]
		flagAnomaly(&res, "epmd-names")
		out := binary.BigEndian.AppendUint32(nil, 4369)
		out = append(out, "name rabbit at port 25672\nname couchdb at port 25673\n"...)
		_, _ = conn.Write(out)
		res.BannerSent = "epmd names"
	case 122: // PORT_PLEASE2_REQ -> PORT2_RESP for the named node
		if len(got) > 3 {
			res.Meta["epmd_node"] = strings.TrimSpace(string(got[3:]))
		}
		const name = "rabbit"
		resp := []byte{119, 0} // 'w', result OK
		resp = binary.BigEndian.AppendUint16(resp, 25672)
		resp = append(resp, 77, 0)                                    // nodetype=normal, proto=tcp
		resp = binary.BigEndian.AppendUint16(resp, 6)                 // highest dist version
		resp = binary.BigEndian.AppendUint16(resp, 5)                 // lowest dist version
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(name))) // name length
		resp = append(resp, name...)
		resp = binary.BigEndian.AppendUint16(resp, 0) // extra length
		_, _ = conn.Write(resp)
		res.BannerSent = "epmd port2 resp"
	}
	return res, nil
}

// --- TACACS+ (49) --------------------------------------------------------
//
// TACACS+ is Cisco's AAA protocol — the credential gate in front of routers,
// switches and firewalls, and a high-value brute-force / spray target. The
// 12-byte header is [version][type][seq][flags][session_id(4)][length(4)];
// the body is obfuscated with the shared secret so credentials can't be read,
// but the probe and authentication-START are recorded, and we reply with an
// AUTHEN REPLY so a scanner sees a live AAA service.
type tacacs struct{}

func (h *tacacs) Name() string { return "tacacs" }

func (h *tacacs) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "tacacs-probe")
	if len(got) < 12 {
		return res, nil
	}
	ver, typ, seq := got[0], got[1], got[2]
	res.Meta["tacacs_version"] = int(ver)
	res.Meta["tacacs_type"] = int(typ)
	if typ == 1 { // AUTHEN
		flagAnomaly(&res, "tacacs-auth-start")
	}
	// AUTHEN REPLY, status = ERROR (0x07): server_msg_len(2)=0, data_len(2)=0.
	body := []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x00}
	hdr := []byte{ver, 0x01, seq + 1, 0x00}
	hdr = append(hdr, got[4:8]...) // echo session id
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(body)))
	_, _ = conn.Write(append(hdr, body...))
	res.BannerSent = "tacacs authen reply"
	return res, nil
}

// --- SQL Server Resolution Protocol / SQL Browser (UDP 1434) -------------
//
// The SSRP browser enumerates the instances and dynamic ports of a SQL Server
// host (the SQL Slammer port) and is a reflection-amplification vector. A
// single-byte CLNT_BCAST_EX/UCAST request gets a SVR_RESP carrying the
// instance string; because the reply is larger than the request it is
// rate-limited by the global reflector limiter (and the response is bounded).
type mssqlBrowser struct{ lim *udpReflectLimiter }

func (h *mssqlBrowser) Name() string { return "mssql_browser" }

func (h *mssqlBrowser) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}, Payload: payload}
	if len(payload) == 0 {
		return res, nil
	}
	res.Meta["ssrp_request"] = int(payload[0])
	flagAnomaly(&res, "mssql-browser-query")
	// CLNT_BCAST_EX (0x02) is the broadcast enumeration the SQL Browser
	// reflection/amplification abuse rides (small request → instance-list
	// reply); a named-instance request (0x04) carries the instance the scanner
	// is hunting for — capture it.
	if payload[0] == 0x02 {
		flagAnomaly(&res, "amplification-probe")
	}
	if payload[0] == 0x04 && len(payload) > 1 {
		if inst := asciiRun(payload[1:]); len(inst) >= 1 {
			res.Meta["mssql_requested_instance"] = safe.SanitizeForLog(clipStr(inst, 64))
		}
	}
	switch payload[0] {
	case 0x02, 0x03, 0x04: // CLNT_BCAST_EX / CLNT_UCAST_EX / CLNT_UCAST_INST
		if !h.lim.allow() {
			return res, nil
		}
		info := "ServerName;SQLPROD01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;;"
		resp := []byte{0x05}
		resp = binary.LittleEndian.AppendUint16(resp, uint16(len(info))) //nolint:gosec // bounded constant
		resp = append(resp, info...)
		_, _ = pc.WriteTo(resp, src)
		res.BannerSent = "ssrp svr_resp"
	}
	return res, nil
}

package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Round-four OT/ICS protocol decoys: Omron FINS over TCP, the SEMI HSMS /
// SECS-GEM semiconductor-equipment protocol, Unitronics PCOM (the topical
// water-utility PLC), PROFINET-IO over UDP, and the VxWorks WDB target agent
// (an embedded/OT RTOS debug-RCE surface). As with the other decoy files each
// reads a bounded request, answers just enough to look real to an ICS scanner
// (PLCScan / nmap ot scripts), captures it, and flags the high-signal markers.
// The UDP handlers are reflection-safe: PROFINET never replies (a spoofable
// source must not be answered) and WDB replies only under the global
// reflector rate limiter with a bounded datagram.

// --- Omron FINS/TCP (9600) -----------------------------------------------
//
// FINS is Omron's PLC protocol. Over TCP it is framed "FINS"[len][command]
// [error][payload]; command 0 is the node-address handshake, command 2 carries
// a FINS frame whose MRC/SRC select Memory-Area Read/Write, RUN/STOP, or
// Program-Area Write (a logic download). We complete the handshake, answer
// frames, and flag writes / mode changes / program downloads.
type finsTCP struct{}

func (h *finsTCP) Name() string { return "fins_tcp" }

func (h *finsTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 1024))
	res.Payload = got
	flagAnomaly(&res, "fins-tcp-probe")
	if len(got) < 12 || string(got[0:4]) != "FINS" {
		return res, nil
	}
	cmd := binary.BigEndian.Uint32(got[8:12])
	res.Meta["fins_tcp_command"] = int(cmd)
	switch cmd {
	case 0: // node-address handshake -> reply command 1 with client+server nodes
		resp := append([]byte{}, "FINS"...)
		resp = binary.BigEndian.AppendUint32(resp, 16) // length of the rest
		resp = binary.BigEndian.AppendUint32(resp, 1)  // command: node address data send
		resp = binary.BigEndian.AppendUint32(resp, 0)  // error code
		resp = binary.BigEndian.AppendUint32(resp, 1)  // client node address
		resp = binary.BigEndian.AppendUint32(resp, 2)  // server node address
		_, _ = conn.Write(resp)
		res.BannerSent = "fins node address"
	case 2: // FINS frame send -> classify the embedded command, reply success
		if len(got) >= 28 {
			mrcSrc := binary.BigEndian.Uint16(got[26:28])
			res.Meta["fins_command_code"] = int(mrcSrc)
			switch mrcSrc {
			case 0x0101, 0x0103: // Memory Area Read / Fill
				flagAnomaly(&res, "ics-process-data-access")
				res.Meta["intent"] = "FINS/TCP Memory-Area Read — reading the PLC process image"
			case 0x0102: // Memory Area Write
				flagAnomaly(&res, "fins-tcp-write-attempt")
				res.Meta["intent"] = "FINS/TCP Memory-Area Write — writing PLC memory (control manipulation)"
			case 0x0401, 0x0402: // RUN / STOP
				flagAnomaly(&res, "fins-run-mode-change")
				res.Meta["intent"] = "FINS/TCP RUN/STOP — changing the PLC operating mode"
			case 0x0307: // Program Area Write (logic download)
				flagAnomaly(&res, "fins-program-download")
				res.Meta["intent"] = "FINS/TCP Program-Area Write — downloading PLC logic"
			case 0x0501, 0x0601: // CPU Unit Data / Status read
				flagAnomaly(&res, "ics-field-device-probe")
				res.Meta["intent"] = "FINS/TCP CPU data read — fingerprinting the Omron PLC"
			}
		}
		// FINS/TCP response: command 2, a FINS frame with end code 0x0000.
		frame := []byte{0xC1, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00}
		resp := append([]byte{}, "FINS"...)
		resp = binary.BigEndian.AppendUint32(resp, uint32(8+len(frame)))
		resp = binary.BigEndian.AppendUint32(resp, 2) // command: FINS frame send
		resp = binary.BigEndian.AppendUint32(resp, 0) // error code
		resp = append(resp, frame...)
		_, _ = conn.Write(resp)
		res.BannerSent = "fins frame response"
	}
	return res, nil
}

// --- SEMI HSMS / SECS-GEM (5000) -----------------------------------------
//
// HSMS carries SECS-II between a semiconductor fab host and tool equipment.
// Messages are [len(4)][session(2)][b2][b3][ptype][stype][systembytes(4)];
// stype 1/5 are the Select/Linktest control messages and stype 0 is a data
// message whose stream/function (e.g. S7F3 process-program send, S2F41 host
// command) is the equipment-control surface. We answer Select/Linktest and
// S1F1, and flag program sends + remote commands.
type secsGEM struct{}

func (h *secsGEM) Name() string { return "secs_gem" }

func hsms(session []byte, b2, b3, sType byte, sysBytes []byte) []byte {
	body := append([]byte{}, session...) // 2
	body = append(body, b2, b3, 0x00, sType)
	body = append(body, sysBytes...) // 4
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(out, body...)
}

func (h *secsGEM) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 1024))
	res.Payload = got
	flagAnomaly(&res, "secs-probe")
	if len(got) < 14 {
		return res, nil
	}
	hdr := got[4:14]
	session, sType, sysBytes := hdr[0:2], hdr[5], hdr[6:10]
	res.Meta["hsms_stype"] = int(sType)
	switch sType {
	case 1: // Select.req -> Select.rsp (stype 2, status 0)
		_, _ = conn.Write(hsms(session, 0x00, 0x00, 2, sysBytes))
		res.BannerSent = "hsms select.rsp"
	case 5: // Linktest.req -> Linktest.rsp (stype 6)
		_, _ = conn.Write(hsms(session, 0x00, 0x00, 6, sysBytes))
		res.BannerSent = "hsms linktest.rsp"
	case 0: // SECS-II data message
		stream, function := hdr[2]&0x7f, hdr[3]
		res.Meta["secs_stream"], res.Meta["secs_function"] = int(stream), int(function)
		switch {
		case stream == 7 && function == 3: // S7F3 process-program send (logic download)
			flagAnomaly(&res, "secs-program-send")
		case stream == 2 && function == 41: // S2F41 host command send
			flagAnomaly(&res, "secs-remote-command")
		}
		// Reply S1F2 (on-line data) shaped minimally; W-bit cleared.
		_, _ = conn.Write(hsms(session, 0x01, 0x02, 0, sysBytes))
		res.BannerSent = "secs data reply"
	}
	return res, nil
}

// --- Unitronics PCOM (20256) ---------------------------------------------
//
// PCOM is the protocol of Unitronics Vision PLCs — the controllers behind the
// 2023 water-utility intrusions (CISA ICSA-23-348; default password 1111).
// PCOM/TCP wraps an ASCII ("/00ID…") or binary ("/_OPLC") command. We answer
// an identification request and flag value writes (SB/SW/SA set), RUN/STOP
// mode changes, and logic downloads.
type pcom struct{}

func (h *pcom) Name() string { return "pcom" }

func (h *pcom) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 1024))
	res.Payload = got
	flagAnomaly(&res, "pcom-probe")
	if len(got) == 0 {
		return res, nil
	}
	s := string(got)
	binMode := strings.Contains(s, "/_OPLC")
	res.Meta["pcom_binary"] = binMode
	up := strings.ToUpper(s)
	cmd := stripPrefix(up)
	switch {
	case strings.Contains(up, "CCD") || strings.Contains(up, "DOWNLOAD") || strings.Contains(up, "BLOCKCHANGE"):
		flagAnomaly(&res, "pcom-program-download")
	case strings.Contains(up, "RUN") || strings.Contains(up, "STOP") || strings.Contains(up, "MODE"):
		flagAnomaly(&res, "pcom-mode-change")
	case strings.HasPrefix(cmd, "SB") || strings.HasPrefix(cmd, "SW") || strings.HasPrefix(cmd, "SA") ||
		strings.HasPrefix(cmd, "SNB") || strings.HasPrefix(cmd, "SI") || strings.HasPrefix(cmd, "SL"):
		flagAnomaly(&res, "pcom-write-attempt")
	}
	// Answer an identification request so a scanner records a live Vision PLC.
	if strings.Contains(up, "ID") {
		res.Meta["pcom_request"] = "identification"
		_, _ = conn.Write([]byte("/A00ID03V230 B10 \r"))
	} else {
		_, _ = conn.Write([]byte("/A00\r"))
	}
	res.BannerSent = "pcom reply"
	return res, nil
}

// stripPrefix drops a leading "/NN" unit prefix so the command-letter scan
// doesn't match on the address digits.
func stripPrefix(s string) string {
	if len(s) >= 3 && s[0] == '/' {
		return s[3:]
	}
	return s
}

// --- PROFINET-IO / DCE-RPC (UDP 34964) -----------------------------------
//
// PROFINET-IO uses DCE-RPC over UDP 34964 to set up cyclic I/O with Siemens /
// industrial devices. This is detection-only: we capture and classify the
// request but never reply — a DCE-RPC response to a spoofable UDP source would
// be a reflection primitive the sensor must not become.
type profinet struct{}

func (h *profinet) Name() string { return "profinet" }

func (h *profinet) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}, Payload: payload}
	flagAnomaly(&res, "profinet-io-probe")
	res.Meta["intent"] = "PROFINET-IO probe — enumerating cyclic-I/O field devices"
	if len(payload) >= 2 && payload[0] == 0x04 { // DCE-RPC version 4
		res.Meta["dce_rpc_ptype"] = int(payload[1])
		if payload[1] == 0x00 { // request PDU = a Connect / IODControl attempt
			flagAnomaly(&res, "profinet-connect")
			// The CL DCE-RPC v4 header carries the operation number (little-
			// endian) at offset 28. PROFINET CM opnums: 0 Connect, 1 Release,
			// 2 Read (IODReadReq), 3 Write (IODWriteReq), 4 Control
			// (IODControlReq), 5 ReadImplicit.
			if len(payload) >= 30 {
				opnum := binary.LittleEndian.Uint16(payload[28:30])
				res.Meta["profinet_opnum"] = opnum
				res.Meta["profinet_operation"] = profinetOpName(opnum)
				switch opnum {
				case 0: // Connect — establish the application relation (cyclic I/O)
					res.Meta["intent"] = "PROFINET-IO Connect — establishing an application relation (cyclic I/O foothold)"
				case 2, 5: // IODRead / ReadImplicit — reading device records/params
					flagAnomaly(&res, "ics-process-data-access")
					res.Meta["intent"] = "PROFINET-IO " + profinetOpName(opnum) + " — reading device records/parameters"
				case 3: // IODWrite — write a device parameter/record
					flagAnomaly(&res, "profinet-iod-write")
					res.Meta["intent"] = "PROFINET-IO IODWrite — writing a device parameter/record (control manipulation)"
				case 4: // IODControl — application-ready / mode change
					flagAnomaly(&res, "profinet-iod-control")
					res.Meta["intent"] = "PROFINET-IO IODControl — application-ready / device mode change"
				}
			}
		}
	}
	return res, nil
}

// profinetOpName names the PROFINET CM (Context Manager) DCE-RPC operations.
func profinetOpName(op uint16) string {
	switch op {
	case 0:
		return "Connect"
	case 1:
		return "Release"
	case 2:
		return "IODRead"
	case 3:
		return "IODWrite"
	case 4:
		return "IODControl"
	case 5:
		return "ReadImplicit"
	}
	return "op-" + itoa(int(op))
}

// --- VxWorks WDB target agent (UDP 17185) --------------------------------
//
// The WDB target agent is VxWorks' remote debug interface — left enabled it is
// memory read/write and code execution on the RTOS behind a great deal of OT
// and embedded gear (the URGENT/11 class). We flag the probe and, rate-limited
// and bounded, answer so a scanner records a live agent.
type wdbrpc struct{ lim *udpReflectLimiter }

func (h *wdbrpc) Name() string { return "wdbrpc" }

// WDBPROG is the ONC-RPC program number of the VxWorks WDB agent (WDBPROG).
const wdbProg = 0x55555555

func (h *wdbrpc) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}, Payload: payload}
	flagAnomaly(&res, "wdbrpc-probe")
	if len(payload) < 4 {
		return res, nil
	}
	flagAnomaly(&res, "wdbrpc-connect")
	// The WDB agent being reachable at all is the exposure URGENT/11 warned of.
	res.CVEHits = appendUnique(res.CVEHits, "CVE-2010-2965")
	flagAnomaly(&res, "cve:CVE-2010-2965")
	setIfEmpty(res.Meta, "intent", "VxWorks WDB agent access — RTOS debug interface (memory r/w + RCE)")

	// WDBRPC rides ONC-RPC: xid(4), msg_type(4)=0 call, rpcvers(4)=2, prog(4)=
	// 0x55555555 (WDBPROG), vers(4), proc(4). Parse it when present.
	wdbConfirmed := false
	if len(payload) >= 24 && binary.BigEndian.Uint32(payload[4:8]) == 0 {
		if binary.BigEndian.Uint32(payload[12:16]) == wdbProg {
			wdbConfirmed = true
			res.Meta["wdb_program"] = "WDBPROG"
			proc := binary.BigEndian.Uint32(payload[20:24])
			res.Meta["wdb_proc"] = proc
			h.classifyWDBProc(proc, &res)
		}
	}
	// URGENT/11 heuristic: an oversized / malformed WDB datagram (the IPnet
	// stack-overflow payloads are large) against the agent.
	if len(payload) > 1400 {
		flagAnomaly(&res, "wdbrpc-urgent11")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2019-12256")
		flagAnomaly(&res, "cve:CVE-2019-12256")
		res.Meta["intent"] = "VxWorks WDB oversized request — possible URGENT/11 IPnet overflow"
	}

	if h.lim.allow() {
		// A small, bounded WDB-style reply (echoes the leading xid, marks an
		// accepted reply) so the agent looks live without amplifying.
		resp := []byte{payload[0], payload[1], payload[2], payload[3], 0x00, 0x00, 0x00, 0x00}
		_, _ = pc.WriteTo(resp, src)
		res.BannerSent = "wdb reply"
	}
	_ = wdbConfirmed
	return res, nil
}

// classifyWDBProc classifies a WDB procedure: memory read (info disclosure),
// memory write / context-create / function-call (the RCE primitives), and
// run-control. Proc numbers vary across WDB versions, so we group by the
// documented WDB request families and also key on size.
func (h *wdbrpc) classifyWDBProc(proc uint32, res *Result) {
	switch {
	case proc == 1 || proc == 2: // CONNECT / DISCONNECT / TARGET_PING
		res.Meta["wdb_op"] = "connect/ping"
	case proc >= 0x40 && proc <= 0x4F: // memory access family
		// Reads disclose firmware/keys; writes are the RCE primitive.
		flagAnomaly(res, "wdbrpc-mem-access")
		res.Meta["wdb_op"] = "memory-access"
		res.Meta["intent"] = "VxWorks WDB memory read/write — RTOS memory access (firmware/RCE)"
	case proc >= 0x60 && proc <= 0x7F: // context / function-call family = RCE
		flagAnomaly(res, "wdbrpc-rce")
		res.Meta["wdb_op"] = "context/func-call"
		res.Meta["intent"] = "VxWorks WDB context-create / function-call — remote code execution on the RTOS"
	default:
		res.Meta["wdb_op"] = "wdb-proc"
	}
}

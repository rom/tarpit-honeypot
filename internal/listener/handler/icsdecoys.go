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
			case 0x0102: // Memory Area Write
				flagAnomaly(&res, "fins-tcp-write-attempt")
			case 0x0401, 0x0402: // RUN / STOP
				flagAnomaly(&res, "fins-run-mode-change")
			case 0x0307: // Program Area Write (logic download)
				flagAnomaly(&res, "fins-program-download")
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
	if len(payload) >= 2 && payload[0] == 0x04 { // DCE-RPC version 4
		res.Meta["dce_rpc_ptype"] = int(payload[1])
		if payload[1] == 0x00 { // request PDU = a Connect / IODControl attempt
			flagAnomaly(&res, "profinet-connect")
		}
	}
	return res, nil
}

// --- VxWorks WDB target agent (UDP 17185) --------------------------------
//
// The WDB target agent is VxWorks' remote debug interface — left enabled it is
// memory read/write and code execution on the RTOS behind a great deal of OT
// and embedded gear (the URGENT/11 class). We flag the probe and, rate-limited
// and bounded, answer so a scanner records a live agent.
type wdbrpc struct{ lim *udpReflectLimiter }

func (h *wdbrpc) Name() string { return "wdbrpc" }

func (h *wdbrpc) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}, Payload: payload}
	flagAnomaly(&res, "wdbrpc-probe")
	if len(payload) >= 4 {
		flagAnomaly(&res, "wdbrpc-connect")
		if h.lim.allow() {
			// A small, bounded WDB-style reply (echoes the leading xid, marks an
			// accepted reply) so the agent looks live without amplifying.
			resp := []byte{payload[0], payload[1], payload[2], payload[3], 0x00, 0x00, 0x00, 0x00}
			_, _ = pc.WriteTo(resp, src)
			res.BannerSent = "wdb reply"
		}
	}
	return res, nil
}

package handler

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// bacnetSC emulates a BACnet Secure Connect (BACnet/SC) hub endpoint — the
// WebSocket+TLS data link defined in ASHRAE 135-2020 Annex AB that is
// replacing the legacy BACnet/IP (UDP 47808) broadcast network for building
// automation. A node connects by opening a WebSocket with the subprotocol
// `hub.bsc.bacnet.org` (hub) or `dc.bsc.bacnet.org` (direct connect), then
// exchanges BVLC-SC messages; the first is a Connect-Request carrying the
// node's 6-byte VMAC and 16-byte device UUID.
//
// We complete the WebSocket handshake, recognize the BACnet/SC subprotocol
// and/or the BVLC-SC framing, parse the Connect-Request (VMAC + device UUID),
// reply with a believable Connect-Accept so the node proceeds, answer
// Heartbeat-Requests, and flag the building-control recon / write markers the
// OT detection rules key on. Deploy behind TLS (handler `bacnet_scs`) for the
// real-world form; the plaintext `bacnet_sc` still captures scanners probing
// the WebSocket path.
type bacnetSC struct{}

func (h *bacnetSC) Name() string { return "bacnet_sc" }

// BACnet/SC WebSocket subprotocol identifiers (ASHRAE 135-2020 Annex AB).
const (
	bscHubProto    = "hub.bsc.bacnet.org"
	bscDirectProto = "dc.bsc.bacnet.org"
)

// BVLC-SC function codes (Clause AB.2.2).
var bvlcSCFunc = map[byte]string{
	0x00: "BVLC-Result",
	0x01: "Encapsulated-NPDU",
	0x02: "Address-Resolution",
	0x03: "Address-Resolution-ACK",
	0x04: "Advertisement",
	0x05: "Advertisement-Solicitation",
	0x06: "Connect-Request",
	0x07: "Connect-Accept",
	0x08: "Disconnect-Request",
	0x09: "Disconnect-ACK",
	0x0A: "Heartbeat-Request",
	0x0B: "Heartbeat-ACK",
	0x0C: "Proprietary-Message",
}

func (h *bacnetSC) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"service": "bacnet-sc"}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	var key, path, proto, userAgent string
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				path = parts[1]
			}
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "sec-websocket-key:"):
			key = strings.TrimSpace(line[18:])
		case strings.HasPrefix(lower, "sec-websocket-protocol:"):
			proto = strings.TrimSpace(line[23:])
		case strings.HasPrefix(lower, "user-agent:"):
			userAgent = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["path"] = path
	if userAgent != "" {
		res.Meta["user_agent"] = userAgent
	}
	if proto != "" {
		res.Meta["ws_subprotocol"] = proto
	}

	// The BACnet/SC subprotocol in the handshake is a definitive tell on its
	// own, before any BVLC-SC frame is seen.
	bscProto := ""
	for _, p := range strings.Split(proto, ",") {
		switch strings.TrimSpace(p) {
		case bscHubProto:
			bscProto = bscHubProto
		case bscDirectProto:
			if bscProto == "" {
				bscProto = bscDirectProto
			}
		}
	}
	if bscProto != "" {
		flagAnomaly(&res, "bacnet-sc")
		res.Meta["bacnet_sc"] = true
		res.Meta["bacnet_sc_role"] = map[string]string{bscHubProto: "hub", bscDirectProto: "direct-connect"}[bscProto]
	}

	// Not a WebSocket upgrade — answer like a plain server so a probe still
	// gets a believable reply.
	if key == "" {
		body := "Upgrade Required"
		resp := "HTTP/1.1 426 Upgrade Required\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Length: " + intToStr(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
		_, _ = conn.Write([]byte(resp))
		res.Meta["ws_upgrade"] = false
		res.BannerSent = "bacnet-sc 426"
		return res, nil
	}

	// Complete the handshake, echoing the BACnet/SC subprotocol when offered
	// (a real hub selects hub.bsc.bacnet.org) else the first offered one.
	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	selProto := bscProto
	if selProto == "" && proto != "" {
		selProto = strings.TrimSpace(strings.Split(proto, ",")[0])
	}
	if selProto != "" {
		resp += "Sec-WebSocket-Protocol: " + selProto + "\r\n"
	}
	resp += "\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.Meta["ws_upgrade"] = true
	res.BannerSent = "bacnet-sc 101"

	// Hub identity, deterministic per listener (stable VMAC/UUID a scanner can
	// re-observe), used in our Connect-Accept.
	hubVMAC, hubUUID := bscIdentity(cfg.ID)

	var funcs []string
	for i := 0; i < 8; i++ {
		payload, opcode, ok := readWSFrame(br, capN)
		if !ok {
			break
		}
		if opcode == 0x8 { // WebSocket close
			break
		}
		if opcode != 0x2 && opcode != 0x0 && len(payload) > 0 {
			// BACnet/SC carries binary BVLC frames; a text frame here is a
			// generic WS probe, not a BACnet/SC node.
			continue
		}
		fn, done := bscHandleFrame(conn, payload, &res, &funcs, hubVMAC, hubUUID)
		if done {
			break
		}
		_ = fn
	}
	if len(funcs) > 0 {
		res.Meta["bvlc_sc_functions"] = funcs
	}

	// Polite WebSocket close (status 1000).
	_, _ = conn.Write([]byte{0x88, 0x02, 0x03, 0xe8})
	return res, nil
}

// bscHandleFrame parses one BVLC-SC message from a WebSocket binary frame,
// records it, and sends the hub reply a real node would expect. Returns the
// function code and whether the session should end.
func bscHandleFrame(conn net.Conn, b []byte, res *Result, funcs *[]string, hubVMAC []byte, hubUUID []byte) (byte, bool) {
	if len(b) < 4 {
		return 0, true
	}
	fn := b[0]
	msgID := binary.BigEndian.Uint16(b[2:4])
	name := bvlcSCFunc[fn]
	if name == "" {
		name = fmt.Sprintf("Unknown-0x%02x", fn)
	}
	*funcs = appendUnique(*funcs, name)
	// Any valid BVLC-SC frame confirms BACnet/SC even without the subprotocol.
	flagAnomaly(res, "bacnet-sc")
	res.Meta["bacnet_sc"] = true

	switch fn {
	case 0x06: // Connect-Request: VMAC(6) + Device-UUID(16) + max sizes
		body := b[4:]
		if len(body) >= 22 {
			vmac := body[0:6]
			uuid := body[6:22]
			res.Meta["node_vmac"] = hex.EncodeToString(vmac)
			res.Meta["device_uuid"] = formatUUID(uuid)
		}
		flagAnomaly(res, "ics-bacnet-sc-connect")
		flagAnomaly(res, "ics-field-device-probe")
		res.Meta["intent"] = "BACnet/SC node Connect-Request — joining the secure building-control network (BMS enumeration / foothold)"
		// Reply Connect-Accept with the hub's identity so the node proceeds.
		reply := append([]byte{0x07, 0x00, b[2], b[3]}, hubVMAC...)
		reply = append(reply, hubUUID...)
		reply = append(reply, 0x05, 0xf2, 0x05, 0xf2) // max BVLC / NPDU sizes
		_ = writeWSBinary(conn, reply)
		return fn, false
	case 0x0A: // Heartbeat-Request → Heartbeat-ACK (keep the node engaged)
		_ = writeWSBinary(conn, []byte{0x0B, 0x00, b[2], b[3]})
		return fn, false
	case 0x01: // Encapsulated-NPDU: a BACnet APDU rides inside
		flagAnomaly(res, "ics-process-data-access")
		if bscNPDUHasWrite(b[4:]) {
			flagAnomaly(res, "ics-plc-write")
			res.Meta["intent"] = "BACnet/SC WriteProperty — set-point / control-point write over Secure Connect"
		}
		return fn, false
	case 0x05: // Advertisement-Solicitation — hub/network discovery
		flagAnomaly(res, "ics-bacnet-sc-discovery")
		res.Meta["intent"] = "BACnet/SC Advertisement-Solicitation — discovering the secure BMS network"
		return fn, false
	case 0x08: // Disconnect-Request → Disconnect-ACK, then end
		_ = writeWSBinary(conn, []byte{0x09, 0x00, b[2], b[3]})
		return fn, true
	}
	_ = msgID
	return fn, false
}

// bscNPDUHasWrite reports whether an encapsulated NPDU/APDU looks like a
// confirmed WriteProperty / WritePropertyMultiple request. Conservative: it
// scans for the confirmed-request PDU type (0x0n) followed by the
// WriteProperty (0x0F) or WritePropertyMultiple (0x10) service choice, the
// control-write primitive defenders care about.
func bscNPDUHasWrite(apdu []byte) bool {
	// Skip a short NPDU header heuristically; scan a bounded window.
	for i := 0; i+1 < len(apdu) && i < 32; i++ {
		if apdu[i]&0xF0 == 0x00 { // confirmed-request PDU type
			svc := apdu[i+1]
			// service choice sits a couple of bytes in; check a small window.
			for j := i + 1; j < i+4 && j < len(apdu); j++ {
				if apdu[j] == 0x0F || apdu[j] == 0x10 {
					return true
				}
			}
			_ = svc
		}
	}
	return false
}

// bscIdentity derives a stable hub VMAC (6 bytes) and device UUID (16 bytes)
// from the listener id, so a scanner re-observes the same hub identity.
func bscIdentity(id string) (vmac []byte, uuid []byte) {
	sum := sha1.Sum([]byte("bacnet-sc-hub:" + id))
	vmac = make([]byte, 6)
	copy(vmac, sum[0:6])
	uuid = make([]byte, 16)
	copy(uuid, sum[4:20])
	// RFC 4122 version/variant bits so it looks like a real v4 UUID.
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return vmac, uuid
}

// formatUUID renders 16 bytes as the canonical 8-4-4-4-12 UUID string.
func formatUUID(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

// writeWSBinary sends payload as a single unmasked server WebSocket binary
// frame (FIN=1, opcode=0x2). Bounded to the 2-byte extended length a hub
// reply ever needs.
func writeWSBinary(conn net.Conn, payload []byte) error {
	var hdr []byte
	n := len(payload)
	switch {
	case n < 126:
		hdr = []byte{0x82, byte(n)}
	default:
		hdr = []byte{0x82, 126, byte(n >> 8), byte(n)}
	}
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

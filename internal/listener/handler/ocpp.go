package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// ocpp emulates an EV-charging OCPP (Open Charge Point Protocol) endpoint — the
// WebSocket JSON transport (OCPP-J 1.6 / 2.0.1) a charge point uses to talk to
// a Central System, and which a Central System exposes for charge points to
// connect to. Exposed, unauthenticated OCPP endpoints let an attacker spoof a
// charge point, read/alter charging sessions and tariffs, push firmware, and
// reset or disable chargers (availability + fraud + safety impact across a
// charging network). The handler completes the WebSocket upgrade so a scanner
// records a live OCPP endpoint, captures the charge-point identity +
// subprotocol, and classifies the OCPP CALL actions — flagging the management /
// actuation ones (remote start/stop, config change, firmware update, reset).
// It performs no charging action.
//
// OCPP-J frames are JSON arrays: [MessageTypeId, "uniqueId", "Action", {payload}].
// MessageTypeId 2 = CALL (request). The URL's last path segment is the
// charge-point id (ws://host/<ChargePointId>).
type ocppH struct{}

func (h *ocppH) Name() string { return "ocpp" }

func (h *ocppH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head
	flagAnomaly(&res, "ocpp-connect")

	var key, path, proto, ua string
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			if f := strings.Fields(line); len(f) >= 2 {
				path = f[1]
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
			ua = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["path"] = safe.SanitizeForLog(path)
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}
	if proto != "" {
		res.Meta["ocpp_subprotocol"] = safe.SanitizeForLog(clipStr(proto, 64))
	}
	// Charge-point id = last non-empty path segment.
	if cp := lastPathSegment(path); cp != "" {
		res.Meta["ocpp_charge_point"] = safe.SanitizeForLog(clipStr(cp, 96))
	}
	setIfEmpty(res.Meta, "intent", "OCPP endpoint connect — EV charge-point/central-system WebSocket")

	if key == "" {
		// Not a WebSocket upgrade; answer 426 so a probe still gets a reply.
		body := "Upgrade Required"
		_, _ = conn.Write([]byte("HTTP/1.1 426 Upgrade Required\r\nContent-Type: text/plain\r\nContent-Length: " +
			intToStr(len(body)) + "\r\nConnection: close\r\n\r\n" + body))
		res.Meta["ws_upgrade"] = false
		res.BannerSent = "ocpp 426"
		return res, nil
	}

	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n"
	if proto != "" {
		resp += "Sec-WebSocket-Protocol: " + strings.TrimSpace(strings.Split(proto, ",")[0]) + "\r\n"
	}
	resp += "\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.Meta["ws_upgrade"] = true
	res.BannerSent = "ocpp 101"

	// Read a few OCPP frames and classify the CALL actions.
	var actions []string
	for i := 0; i < 4; i++ {
		payload, opcode, ok := readWSFrame(br, capN)
		if !ok || opcode == 0x8 {
			break
		}
		if len(payload) == 0 {
			continue
		}
		if a := classifyOCPP(string(payload), &res); a != "" {
			actions = appendUnique(actions, a)
		}
	}
	if len(actions) > 0 {
		res.Meta["ocpp_actions"] = actions
	}
	_, _ = conn.Write([]byte{0x88, 0x02, 0x03, 0xe8}) // close 1000
	return res, nil
}

// classifyOCPP extracts the Action from an OCPP-J CALL frame and flags the
// management / actuation ones. Returns the action name (or "").
func classifyOCPP(frame string, res *Result) string {
	action := ocppAction(frame)
	if action == "" {
		return ""
	}
	flagAnomaly(res, "ocpp-message")
	switch action {
	case "RemoteStartTransaction", "RemoteStopTransaction", "RequestStartTransaction", "RequestStopTransaction":
		flagAnomaly(res, "ocpp-remote-transaction")
		res.Meta["intent"] = "OCPP remote start/stop transaction — controlling a charging session on an exposed endpoint"
	case "ChangeConfiguration", "SetChargingProfile", "SetVariables", "ChangeAvailability":
		flagAnomaly(res, "ocpp-config-change")
		res.Meta["intent"] = "OCPP configuration/charging-profile change on an exposed endpoint"
	case "UpdateFirmware", "PublishFirmware":
		flagAnomaly(res, "ocpp-firmware-update")
		res.Meta["intent"] = "OCPP firmware update push to an exposed charge point"
	case "Reset":
		flagAnomaly(res, "ocpp-reset")
		res.Meta["intent"] = "OCPP Reset — rebooting/disabling an exposed charge point (availability impact)"
	case "SendLocalList", "ClearCache":
		flagAnomaly(res, "ocpp-authlist-tamper")
		res.Meta["intent"] = "OCPP local auth-list tamper / cache clear (charging fraud) on an exposed endpoint"
	}
	return action
}

// ocppAction pulls the Action (3rd element) out of an OCPP-J CALL array. It is
// a minimal extractor: find the MessageTypeId 2, then the third quoted string.
func ocppAction(frame string) string {
	s := strings.TrimSpace(frame)
	if len(s) < 4 || s[0] != '[' {
		return ""
	}
	// Collect the first few quoted strings; the action is the one after the
	// uniqueId in a CALL ([2,"id","Action",...]).
	var quoted []string
	for i := 0; i < len(s) && len(quoted) < 3; i++ {
		if s[i] == '"' {
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				break
			}
			quoted = append(quoted, s[i+1:i+1+j])
			i += j + 1
		}
	}
	// [2,"uniqueId","Action"] → quoted[1] is the action. Some stacks omit the
	// id quoting oddities; fall back to the last captured string.
	if len(quoted) >= 2 {
		return quoted[1]
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return ""
}

// lastPathSegment returns the final non-empty segment of a URL path (query
// stripped), used as the OCPP charge-point identity.
func lastPathSegment(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

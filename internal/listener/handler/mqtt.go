package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type mqtt struct{}

func (m *mqtt) Name() string { return "mqtt" }

// MQTT v3.1.1 / v5 over TCP (port 1883). First packet from any client is
// always CONNECT (type 0x1). We parse the variable header for protocol
// name, version, and the optional username/password from the payload,
// then reply with CONNACK (success). That covers what every scanner and
// brute-force tool sends first.
func (m *mqtt) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	br := bufio.NewReader(conn)
	first, err := br.ReadByte()
	if err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if first&0xF0 != 0x10 {
		res.Meta = map[string]any{"non_mqtt_first_byte": fmtByte(first)}
		return res, nil
	}
	remLen, err := readVarint(br)
	if err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if remLen > 4096 {
		res.Meta = map[string]any{"oversize_remaining_length": remLen}
		return res, nil
	}
	body := make([]byte, remLen)
	if _, err := io.ReadFull(br, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = body

	meta := map[string]any{"packet_type": "CONNECT"}
	res.Meta = meta

	// Variable header: protocol name (len-prefixed string), protocol level,
	// connect flags, keepalive.
	if len(body) < 2 {
		return res, nil
	}
	nameLen := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+nameLen > len(body) {
		return res, nil
	}
	protoName := string(body[2 : 2+nameLen])
	meta["protocol_name"] = protoName
	idx := 2 + nameLen
	if idx >= len(body) {
		return res, nil
	}
	protoLevel := body[idx]
	meta["protocol_level"] = protoLevel
	idx++
	if idx >= len(body) {
		return res, nil
	}
	flags := body[idx]
	idx++
	if idx+2 > len(body) {
		return res, nil
	}
	keepalive := binary.BigEndian.Uint16(body[idx : idx+2])
	idx += 2
	meta["keepalive"] = keepalive

	// Payload: ClientID first, then optional fields based on flags.
	cid, idx2, ok := readMQTTString(body, idx)
	if ok {
		meta["client_id"] = cid
		idx = idx2
	}
	// Skip Will Topic + Will Message if Will flag set.
	willFlag := flags&0x04 != 0
	if willFlag {
		_, idx2, ok = readMQTTString(body, idx)
		if ok {
			idx = idx2
		}
		_, idx2, ok = readMQTTString(body, idx)
		if ok {
			idx = idx2
		}
	}
	if flags&0x80 != 0 {
		if user, idx2, ok := readMQTTString(body, idx); ok {
			meta["username"] = user
			idx = idx2
		}
	}
	if flags&0x40 != 0 {
		if pass, _, ok := readMQTTString(body, idx); ok {
			meta["password"] = pass
		}
	}

	// CONNACK: fixed header (type=0x20, remlen=2) + session_present(0) + return_code(0)
	connack := []byte{0x20, 0x02, 0x00, 0x00}
	if _, err := conn.Write(connack); err != nil {
		meta["write_err"] = err.Error()
		res.BannerSent = "mqtt CONNACK accepted"
		return res, nil
	}
	res.BannerSent = "mqtt CONNACK accepted"

	// Post-CONNACK session: answer the control packets a real broker would so
	// a scanner/brute-forcer that proceeds past the handshake keeps talking —
	// SUBSCRIBE (and wildcard data-harvesting), PUBLISH, PINGREQ keepalives.
	mqttSession(conn, br, &res, meta)
	return res, nil
}

// mqttSession reads a bounded number of post-CONNACK control packets and
// answers them like a broker would, capturing subscribed/published topics.
func mqttSession(conn net.Conn, br *bufio.Reader, res *Result, meta map[string]any) {
	var subTopics, pubTopics []string
	defer func() {
		if len(subTopics) > 0 {
			meta["subscribed_topics"] = subTopics
		}
		if len(pubTopics) > 0 {
			meta["published_topics"] = pubTopics
		}
	}()
	for i := 0; i < 8; i++ {
		first, err := br.ReadByte()
		if err != nil {
			break
		}
		remLen, err := readVarint(br)
		if err != nil || remLen > 8192 {
			break
		}
		body := make([]byte, remLen)
		if _, err := io.ReadFull(br, body); err != nil {
			break
		}
		res.Payload = append(res.Payload, body...)
		switch first & 0xF0 {
		case 0x80: // SUBSCRIBE
			if len(body) < 2 {
				return
			}
			pktID := body[0:2]
			idx := 2
			for idx+2 <= len(body) {
				topic, ni, ok := readMQTTString(body, idx)
				if !ok {
					break
				}
				idx = ni
				if idx < len(body) { // requested QoS byte
					idx++
				}
				subTopics = append(subTopics, topic)
				if strings.ContainsAny(topic, "#+") || strings.HasPrefix(topic, "$SYS") {
					flagAnomaly(res, "mqtt-wildcard-subscribe")
				}
			}
			// SUBACK: type 0x90, remlen = 2 (pktID) + 1 granted QoS per topic.
			n := len(subTopics)
			if n == 0 {
				n = 1
			}
			suback := []byte{0x90, byte(2 + n)}
			suback = append(suback, pktID...)
			for j := 0; j < n; j++ {
				suback = append(suback, 0x00) // granted QoS 0
			}
			if _, err := conn.Write(suback); err != nil {
				return
			}
		case 0xA0: // UNSUBSCRIBE
			if len(body) >= 2 {
				_, _ = conn.Write(append([]byte{0xB0, 0x02}, body[0:2]...)) // UNSUBACK
			}
		case 0x30: // PUBLISH
			qos := (first >> 1) & 0x03
			topic, ni, ok := readMQTTString(body, 0)
			if ok {
				pubTopics = append(pubTopics, topic)
				if qos > 0 && ni+2 <= len(body) {
					pktID := body[ni : ni+2]
					_, _ = conn.Write(append([]byte{0x40, 0x02}, pktID...)) // PUBACK
				}
			}
			flagAnomaly(res, "mqtt-publish")
		case 0xC0: // PINGREQ
			if _, err := conn.Write([]byte{0xD0, 0x00}); err != nil { // PINGRESP
				return
			}
		case 0xE0: // DISCONNECT
			return
		default:
			return
		}
	}
}

func readVarint(br *bufio.Reader) (int, error) {
	val, mult := 0, 1
	for i := 0; i < 4; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		val += int(b&0x7F) * mult
		if b&0x80 == 0 {
			return val, nil
		}
		mult *= 128
	}
	return 0, fmt.Errorf("mqtt: varint too long")
}

func readMQTTString(b []byte, idx int) (string, int, bool) {
	// Guard a negative or out-of-range idx (and the idx+2 overflow it could
	// cause) before slicing. idx > len(b)-2 also rejects a huge idx whose
	// idx+2 would overflow negative.
	if idx < 0 || idx > len(b)-2 {
		return "", idx, false
	}
	n := int(binary.BigEndian.Uint16(b[idx : idx+2]))
	if idx+2+n > len(b) {
		return "", idx, false
	}
	return string(b[idx+2 : idx+2+n]), idx + 2 + n, true
}

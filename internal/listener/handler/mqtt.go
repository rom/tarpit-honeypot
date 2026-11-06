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
	// Will Topic + Will Message (captured, not skipped): a Sparkplug B edge
	// node registers its Will as spBv1.0/<group>/NDEATH/<node>, so the LWT
	// topic alone identifies an IIoT node at CONNECT time.
	willFlag := flags&0x04 != 0
	if willFlag {
		if willTopic, idx2, ok := readMQTTString(body, idx); ok {
			idx = idx2
			meta["will_topic"] = willTopic
			sparkplugRecognize(willTopic, &res, meta)
		}
		if _, idx2, ok := readMQTTString(body, idx); ok {
			idx = idx2
		}
	}
	var mqUser, mqPass string
	if flags&0x80 != 0 {
		if user, idx2, ok := readMQTTString(body, idx); ok {
			meta["username"] = user
			mqUser = user
			idx = idx2
		}
	}
	if flags&0x40 != 0 {
		if pass, _, ok := readMQTTString(body, idx); ok {
			meta["password"] = pass
			mqPass = pass
		}
	}
	// Cleartext MQTT credentials — record the attempt and check the default-
	// credential corpus so an IoT broker brute-force is detected like any other.
	if mqUser != "" {
		flagAnomaly(&res, "mqtt-credential-attempt")
		flagDefaultCred(&res, mqUser, mqPass)
		meta["intent"] = "MQTT broker login — IoT/message-broker credential attempt"
	} else {
		meta["intent"] = "MQTT CONNECT — anonymous broker access / probe"
	}

	// CVE-2017-7650: Eclipse Mosquitto pattern-based ACLs are bypassed by a
	// client whose client id or username is/contains an MQTT topic wildcard
	// ('#' or '+') — the %c/%u substitution then matches topics it shouldn't.
	// Legitimate client ids/usernames never contain these characters.
	if strings.ContainsAny(cid, "#+") || strings.ContainsAny(mqUser, "#+") {
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2017-7650")
		flagAnomaly(&res, "cve:CVE-2017-7650")
		flagAnomaly(&res, "mqtt-acl-pattern-bypass")
		meta["intent"] = "MQTT client id/username contains a topic wildcard ('#'/'+') — Mosquitto pattern-ACL bypass (CVE-2017-7650)"
	}

	// CONNACK, version-aware. v3.1/3.1.1 (level 3/4) carry session_present +
	// a 1-byte return code; v5 (level 5) adds a properties-length byte. An
	// unsupported protocol level gets the "unacceptable protocol version" reject
	// a real broker returns (0x01) — and we don't run the v3 session after it.
	var connack []byte
	switch protoLevel {
	case 3, 4:
		connack = []byte{0x20, 0x02, 0x00, 0x00} // accepted
	case 5:
		connack = []byte{0x20, 0x03, 0x00, 0x00, 0x00} // accepted + 0 properties
	default:
		connack = []byte{0x20, 0x02, 0x00, 0x01} // unacceptable protocol version
		flagAnomaly(&res, "mqtt-unsupported-protocol-level")
	}
	if _, err := conn.Write(connack); err != nil {
		meta["write_err"] = err.Error()
		res.BannerSent = "mqtt CONNACK"
		return res, nil
	}
	res.BannerSent = "mqtt CONNACK"

	// Post-CONNACK session: answer the control packets a real broker would so a
	// scanner/brute-forcer that proceeds past the handshake keeps talking —
	// SUBSCRIBE (and wildcard data-harvesting), PUBLISH, PINGREQ keepalives. The
	// session emits v3-shaped control packets, so only run it for an accepted
	// v3.x client (a rejected level disconnects; v5 framing differs).
	if protoLevel == 3 || protoLevel == 4 {
		mqttSession(conn, br, &res, meta)
	}
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
					meta["intent"] = "MQTT wildcard subscribe (" + topic + ") — harvesting all broker topics / data exfiltration"
				}
				sparkplugRecognize(topic, res, meta)
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
				sparkplugRecognize(topic, res, meta)
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

// sparkplugRecognize detects the Eclipse Sparkplug B payload convention
// (namespace "spBv1.0") on an MQTT topic and records the parsed topic
// structure plus OT-relevant anomaly markers. Sparkplug runs IIoT edge
// nodes / PLC gateways over MQTT; the canonical topic is
// spBv1.0/<group_id>/<message_type>/<edge_node_id>[/<device_id>], with the
// special primary-host form spBv1.0/STATE/<host_id>. NCMD/DCMD are
// write/control commands to an edge node or device — the OT manipulation
// signal defenders most want surfaced. Returns true when the namespace
// matched. No-op on empty/non-Sparkplug topics, so it is cheap to call on
// every topic a scanner touches.
func sparkplugRecognize(topic string, res *Result, meta map[string]any) bool {
	parts := strings.Split(topic, "/")
	if len(parts) < 2 || !strings.EqualFold(parts[0], "spBv1.0") {
		return false
	}
	flagAnomaly(res, "mqtt-sparkplug")
	meta["sparkplug"] = true
	// Primary-host STATE birth/death: spBv1.0/STATE/<sparkplug_host_id>.
	if strings.EqualFold(parts[1], "STATE") {
		meta["sparkplug_msg_type"] = "STATE"
		if len(parts) >= 3 {
			meta["sparkplug_host_id"] = parts[2]
		}
		return true
	}
	meta["sparkplug_group"] = parts[1]
	if len(parts) < 3 {
		return true // namespace seen but topic is malformed/truncated
	}
	msgType := strings.ToUpper(parts[2])
	meta["sparkplug_msg_type"] = msgType
	if len(parts) >= 4 {
		meta["sparkplug_edge_node"] = parts[3]
	}
	if len(parts) >= 5 {
		meta["sparkplug_device"] = parts[4]
	}
	switch msgType {
	case "NCMD", "DCMD":
		// A command written to an edge node / device: OT control manipulation.
		flagAnomaly(res, "ics-sparkplug-command")
		flagAnomaly(res, "ics-plc-write")
		meta["intent"] = "Sparkplug B " + msgType + " — write/control command to an IIoT edge node/device (" + topic + ")"
	case "NBIRTH", "DBIRTH":
		flagAnomaly(res, "ics-sparkplug-birth")
	}
	return true
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

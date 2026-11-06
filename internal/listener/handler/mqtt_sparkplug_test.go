package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func metaHasAnomaly(meta map[string]any, want string) bool {
	list, _ := meta["anomalies"].([]string)
	for _, m := range list {
		if m == want {
			return true
		}
	}
	return false
}

func TestSparkplugRecognize(t *testing.T) {
	cases := []struct {
		name, topic     string
		match           bool
		msgType         string
		wantAnoms       []string
		dontWantAnoms   []string
		wantGroup, node string
	}{
		{name: "ncmd-command", topic: "spBv1.0/PlantA/NCMD/EdgeNode1", match: true, msgType: "NCMD",
			wantAnoms: []string{"mqtt-sparkplug", "ics-sparkplug-command", "ics-plc-write"},
			wantGroup: "PlantA", node: "EdgeNode1"},
		{name: "dcmd-device-command", topic: "spBv1.0/PlantA/DCMD/EdgeNode1/PLC7", match: true, msgType: "DCMD",
			wantAnoms: []string{"mqtt-sparkplug", "ics-sparkplug-command", "ics-plc-write"}},
		{name: "nbirth", topic: "spBv1.0/PlantA/NBIRTH/EdgeNode1", match: true, msgType: "NBIRTH",
			wantAnoms:     []string{"mqtt-sparkplug", "ics-sparkplug-birth"},
			dontWantAnoms: []string{"ics-plc-write"}},
		{name: "ndata-no-write", topic: "spBv1.0/PlantA/NDATA/EdgeNode1", match: true, msgType: "NDATA",
			wantAnoms:     []string{"mqtt-sparkplug"},
			dontWantAnoms: []string{"ics-plc-write", "ics-sparkplug-command"}},
		{name: "state-host", topic: "spBv1.0/STATE/scada-host-1", match: true, msgType: "STATE"},
		{name: "not-sparkplug", topic: "sensors/temp/room1", match: false},
		{name: "empty", topic: "", match: false},
	}
	for _, c := range cases {
		// In the handler, res.Meta and the meta map passed to sparkplugRecognize
		// are the same map; mirror that here so flagAnomaly's writes are visible.
		meta := map[string]any{}
		res := &Result{Meta: meta}
		got := sparkplugRecognize(c.topic, res, meta)
		if got != c.match {
			t.Errorf("%s: recognize=%v want %v", c.name, got, c.match)
			continue
		}
		if !c.match {
			if _, ok := meta["sparkplug"]; ok {
				t.Errorf("%s: non-sparkplug topic set sparkplug meta", c.name)
			}
			continue
		}
		if meta["sparkplug"] != true {
			t.Errorf("%s: sparkplug meta not set", c.name)
		}
		if c.msgType != "" && meta["sparkplug_msg_type"] != c.msgType {
			t.Errorf("%s: msg_type=%v want %s", c.name, meta["sparkplug_msg_type"], c.msgType)
		}
		if c.wantGroup != "" && meta["sparkplug_group"] != c.wantGroup {
			t.Errorf("%s: group=%v want %s", c.name, meta["sparkplug_group"], c.wantGroup)
		}
		if c.node != "" && meta["sparkplug_edge_node"] != c.node {
			t.Errorf("%s: edge_node=%v want %s", c.name, meta["sparkplug_edge_node"], c.node)
		}
		for _, a := range c.wantAnoms {
			if !metaHasAnomaly(meta, a) {
				t.Errorf("%s: missing anomaly %q in %v", c.name, a, meta["anomalies"])
			}
		}
		for _, a := range c.dontWantAnoms {
			if metaHasAnomaly(meta, a) {
				t.Errorf("%s: unexpected anomaly %q", c.name, a)
			}
		}
	}
}

// mqttStr appends an MQTT length-prefixed UTF-8 string.
func mqttStr(b []byte, s string) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(s)))
	return append(append(b, l[:]...), s...)
}

// TestMQTTSparkplugSession drives the full handler: a CONNECT carrying a
// Sparkplug NDEATH Will topic, then a SUBSCRIBE to an NCMD command topic.
func TestMQTTSparkplugSession(t *testing.T) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		m := &mqtt{}
		r, _ := m.Handle(context.Background(), srv, config.Listener{ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))

	// CONNECT (v3.1.1, Will flag set).
	var vh []byte
	vh = mqttStr(vh, "MQTT")
	vh = append(vh, 0x04)       // protocol level 4
	vh = append(vh, 0x04)       // connect flags: Will
	vh = append(vh, 0x00, 0x3C) // keepalive 60
	var pl []byte
	pl = mqttStr(pl, "edge1")                           // client id
	pl = mqttStr(pl, "spBv1.0/PlantA/NDEATH/EdgeNode1") // will topic
	pl = mqttStr(pl, "offline")                         // will message
	connect := append([]byte{0x10, byte(len(vh) + len(pl))}, append(vh, pl...)...)
	if _, err := cli.Write(connect); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	connack := make([]byte, 4)
	if _, err := cli.Read(connack); err != nil {
		t.Fatalf("read connack: %v", err)
	}
	if connack[0] != 0x20 || connack[3] != 0x00 {
		t.Fatalf("connack = %v, want accepted", connack)
	}

	// SUBSCRIBE to a Sparkplug NCMD (write/control) topic.
	var sb []byte
	sb = append(sb, 0x00, 0x01) // packet id
	sb = mqttStr(sb, "spBv1.0/PlantA/NCMD/EdgeNode1")
	sb = append(sb, 0x00) // requested QoS 0
	subscribe := append([]byte{0x82, byte(len(sb))}, sb...)
	if _, err := cli.Write(subscribe); err != nil {
		t.Fatalf("write subscribe: %v", err)
	}
	suback := make([]byte, 5)
	if _, err := cli.Read(suback); err != nil {
		t.Fatalf("read suback: %v", err)
	}

	// DISCONNECT to end the session.
	_, _ = cli.Write([]byte{0xE0, 0x00})
	_ = cli.Close()

	res := <-resCh
	if res.Meta["will_topic"] != "spBv1.0/PlantA/NDEATH/EdgeNode1" {
		t.Errorf("will_topic = %v", res.Meta["will_topic"])
	}
	if res.Meta["sparkplug"] != true {
		t.Errorf("sparkplug not recognized from the session: %v", res.Meta)
	}
	if res.Meta["sparkplug_msg_type"] != "NCMD" {
		t.Errorf("sparkplug_msg_type = %v want NCMD", res.Meta["sparkplug_msg_type"])
	}
	for _, a := range []string{"mqtt-sparkplug", "ics-sparkplug-command", "ics-plc-write"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("session missing anomaly %q in %v", a, res.Meta["anomalies"])
		}
	}
}

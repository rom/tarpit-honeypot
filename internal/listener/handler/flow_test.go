package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestNetflowV5DecodesFlows(t *testing.T) {
	// NetFlow v5: 24-byte header (version=5, count=1) + one 48-byte record.
	pkt := make([]byte, 24+48)
	binary.BigEndian.PutUint16(pkt[0:2], 5) // version
	binary.BigEndian.PutUint16(pkt[2:4], 1) // count
	rec := pkt[24:]
	copy(rec[0:4], net.IPv4(10, 1, 1, 1).To4())   // src
	copy(rec[4:8], net.IPv4(10, 2, 2, 2).To4())   // dst
	binary.BigEndian.PutUint32(rec[16:20], 42)    // packets
	binary.BigEndian.PutUint32(rec[20:24], 4096)  // bytes
	binary.BigEndian.PutUint16(rec[32:34], 12345) // src port
	binary.BigEndian.PutUint16(rec[34:36], 443)   // dst port
	rec[38] = 6                                   // protocol TCP

	res, err := (&netflow{}).Handle(context.Background(), pkt, &net.UDPAddr{}, nil, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["netflow_version"] != 5 {
		t.Errorf("version = %v, want 5", res.Meta["netflow_version"])
	}
	flows, _ := res.Meta["flows"].([]map[string]any)
	if len(flows) != 1 {
		t.Fatalf("expected 1 decoded flow, got %d", len(flows))
	}
	if flows[0]["src"] != "10.1.1.1" || flows[0]["dst"] != "10.2.2.2" || flows[0]["dst_port"] != 443 {
		t.Errorf("flow decoded wrong: %v", flows[0])
	}
	if !hasAnomaly(res, "netflow-export-received") {
		t.Errorf("export not flagged: %v", anomaliesOf(res))
	}
}

func TestNetflowIPFIXHeader(t *testing.T) {
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint16(pkt[0:2], 10) // IPFIX
	binary.BigEndian.PutUint32(pkt[12:16], 7)
	res, _ := (&netflow{}).Handle(context.Background(), pkt, &net.UDPAddr{}, nil, config.Listener{})
	if res.Meta["ipfix"] != true || res.Meta["observation_domain"] != uint32(7) {
		t.Errorf("IPFIX header not parsed: %v", res.Meta)
	}
}

func TestSflowV5Header(t *testing.T) {
	// v5 datagram with an IPv4 agent address.
	pkt := make([]byte, 8+4+16)
	binary.BigEndian.PutUint32(pkt[0:4], 5) // version
	binary.BigEndian.PutUint32(pkt[4:8], 1) // agent addr type IPv4
	copy(pkt[8:12], net.IPv4(192, 0, 2, 254).To4())
	binary.BigEndian.PutUint32(pkt[12:16], 0)  // sub-agent
	binary.BigEndian.PutUint32(pkt[16:20], 99) // sequence
	binary.BigEndian.PutUint32(pkt[24:28], 3)  // sample count

	res, _ := (&sflow{}).Handle(context.Background(), pkt, &net.UDPAddr{}, nil, config.Listener{})
	if res.Meta["sflow_version"] != 5 {
		t.Errorf("version = %v, want 5", res.Meta["sflow_version"])
	}
	if res.Meta["agent_address"] != "192.0.2.254" {
		t.Errorf("agent address = %v, want 192.0.2.254", res.Meta["agent_address"])
	}
	if res.Meta["sample_count"] != uint32(3) {
		t.Errorf("sample_count = %v, want 3", res.Meta["sample_count"])
	}
	if !hasAnomaly(res, "sflow-export-received") {
		t.Errorf("export not flagged: %v", anomaliesOf(res))
	}
}

func TestFlowCollectorsShortInput(t *testing.T) {
	if res, _ := (&netflow{}).Handle(context.Background(), []byte{1}, &net.UDPAddr{}, nil, config.Listener{}); res.Meta["netflow"] != "short" {
		t.Errorf("short netflow not handled: %v", res.Meta)
	}
	if res, _ := (&sflow{}).Handle(context.Background(), []byte{1}, &net.UDPAddr{}, nil, config.Listener{}); res.Meta["sflow"] != "short" {
		t.Errorf("short sflow not handled: %v", res.Meta)
	}
}

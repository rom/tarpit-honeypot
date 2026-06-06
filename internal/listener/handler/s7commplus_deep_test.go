package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestS7CommPlusSetVariable(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	// S7comm-Plus SetVariable (0x0524) request, version 2 (S7-1500).
	dt := []byte{0x03, 0x00, 0x00, 0x10, 0x02, 0xF0, 0x80, 0x72, 0x02, 0x00, 0x10, 0x31, 0x00, 0x00, 0x05, 0x24}
	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&s7commPlus{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, append(cr, dt...))
	if r.Meta["s7_protocol"] != "S7comm-Plus" {
		t.Errorf("protocol = %v", r.Meta["s7_protocol"])
	}
	if r.Meta["s7plus_function"] != "SetVariable" {
		t.Errorf("function = %v, want SetVariable", r.Meta["s7plus_function"])
	}
	if r.Meta["s7plus_family"] != "S7-1500" {
		t.Errorf("family = %v, want S7-1500", r.Meta["s7plus_family"])
	}
	if !hasAnom(r, "ics-plc-write") {
		t.Errorf("SetVariable not classified as write: %v", r.Meta["anomalies"])
	}
}

func TestS7CommPlusExplore(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	dt := []byte{0x03, 0x00, 0x00, 0x10, 0x02, 0xF0, 0x80, 0x72, 0x01, 0x00, 0x10, 0x31, 0x00, 0x00, 0x04, 0xBB}
	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&s7commPlus{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, append(cr, dt...))
	if r.Meta["s7plus_function"] != "Explore" || !hasAnom(r, "ics-field-device-probe") {
		t.Errorf("explore not classified: fn=%v anoms=%v", r.Meta["s7plus_function"], r.Meta["anomalies"])
	}
}

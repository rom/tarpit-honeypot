package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Second OT / building-automation batch. Capture-only.
//
//   pcom_udp (20256), synchrophasor (4713), loxone (7700),
//   amx_netlinx (1319), vantage (3001)

// pcomUDP — Unitronics PCOM/PLC over UDP (UDP 20256). Unitronics Vision/Samba
// PLCs (the gear breached in the 2023 water-utility attacks) speak PCOM; a
// read/write command from an untrusted source is a PLC manipulation attempt.
type pcomUDP struct{}

func (p *pcomUDP) Name() string { return "pcom_udp" }

func (p *pcomUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ics-pcom-udp-probe")
	body := string(payload)
	// PCOM ASCII command frames start with "/" then a 2-digit unit id; the
	// binary frame starts with 0x2f 0x5f ("/_").
	if len(payload) >= 2 && payload[0] == 0x2f {
		res.Meta["pcom_frame"] = "unitronics"
		flagAnomaly(&res, "ics-unitronics-plc")
	}
	if indexFold(body, "/_OPLC") >= 0 || indexFold(body, "RW") >= 0 {
		flagAnomaly(&res, "ics-plc-write")
	}
	return res, nil
}

// synchrophasor — IEEE C37.118 synchrophasor / PMU stream (UDP 4713). Power-grid
// phasor measurement; a command frame (type 4) can reconfigure a PMU.
type synchrophasor struct{}

func (s *synchrophasor) Name() string { return "synchrophasor" }

func (s *synchrophasor) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ics-synchrophasor-probe")
	if len(payload) >= 4 && payload[0] == 0xaa {
		frameType := (payload[1] >> 4) & 0x07
		res.Meta["c37118_frame_type"] = frameType
		res.Meta["c37118_id_code"] = binary.BigEndian.Uint16(payload[2:4])
		if frameType == 4 { // command frame
			flagAnomaly(&res, "ics-pmu-command")
		}
	}
	return res, nil
}

// loxone — Loxone Miniserver (UDP 7700). Smart-building controller; capture the
// command text (lighting/HVAC/blinds actuation).
type loxone struct{}

func (l *loxone) Name() string { return "loxone" }

func (l *loxone) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-loxone-probe")
	if r := asciiRun(payload); len(r) >= 3 {
		res.Meta["loxone_text"] = safe.SanitizeForLog(clipStr(r, 128))
		if indexFold(r, "jdev") >= 0 || indexFold(r, "dev/sps") >= 0 {
			flagAnomaly(&res, "ba-building-control")
		}
	}
	return res, nil
}

// amxNetlinx — AMX NetLinx control system (UDP 1319). Building AV / room
// automation; a probe enumerates NetLinx masters.
type amxNetlinx struct{}

func (a *amxNetlinx) Name() string { return "amx_netlinx" }

func (a *amxNetlinx) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-amx-netlinx-probe")
	if len(payload) >= 4 {
		res.Meta["amx_protocol"] = payload[0]
		res.Meta["amx_length"] = binary.BigEndian.Uint16(payload[2:4])
	}
	flagAnomaly(&res, "ba-av-control-probe")
	return res, nil
}

// vantage — Vantage InFusion lighting/building controller (UDP 3001). Capture
// the host-command text; load/scene commands are actuation.
type vantage struct{}

func (v *vantage) Name() string { return "vantage" }

func (v *vantage) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-vantage-probe")
	if r := asciiRun(payload); len(r) >= 3 {
		res.Meta["vantage_text"] = safe.SanitizeForLog(clipStr(r, 128))
		switch {
		case indexFold(r, "load ") >= 0, indexFold(r, "vsw") >= 0, indexFold(r, "task ") >= 0:
			flagAnomaly(&res, "ba-lighting-control")
		}
	}
	return res, nil
}

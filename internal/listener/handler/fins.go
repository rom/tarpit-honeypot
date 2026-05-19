package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// fins is the Omron FINS (Factory Interface Network Service) UDP
// receiver (default port 9600). Frame layout:
//
//   ICF(1) RSV(1) GCT(1) DNA(1) DA1(1) DA2(1) SNA(1) SA1(1) SA2(1)
//   SID(1) MRC(1) SRC(1) <data>
//
// Common scanner request: CPU_UNIT_DATA_READ (MRC=0x05, SRC=0x01) —
// returns the PLC model string. We capture the command + reply with a
// plausible CPU-data response advertising a "CJ2M-CPU33".
type fins struct{}

func (f *fins) Name() string { return "fins" }

func (f *fins) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 12 {
		res.Meta["short_packet"] = true
		return res, nil
	}
	icf := payload[0]
	mrc := payload[10]
	src_ := payload[11]
	res.Meta["icf"] = icf
	res.Meta["mrc"] = mrc
	res.Meta["src"] = src_
	res.Meta["dna"] = payload[3]
	res.Meta["sna"] = payload[6]
	res.Meta["sid"] = payload[9]

	// Build reply: swap source/destination, set ICF response bit,
	// echo MRC/SRC, append END code 0x0000 + plausible data.
	reply := make([]byte, len(payload))
	copy(reply, payload)
	reply[0] = 0xC0 // response
	reply[3], reply[6] = payload[6], payload[3]
	reply[4], reply[7] = payload[7], payload[4]
	reply[5], reply[8] = payload[8], payload[5]

	switch {
	case mrc == 0x05 && src_ == 0x01: // CPU_UNIT_DATA_READ
		// END code 00 00 + 20-byte model string + 20-byte version
		extra := []byte{0x00, 0x00}
		model := "CJ2M-CPU33          "
		version := "REV.2.0             "
		extra = append(extra, []byte(model)...)
		extra = append(extra, []byte(version)...)
		reply = append(reply[:12], extra...)
	default:
		// Generic acknowledge: END 00 00
		reply = append(reply[:12], 0x00, 0x00)
	}

	if _, err := pc.WriteTo(reply, src); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "fins response (cpu=CJ2M-CPU33)"
	_ = cfg
	return res, nil
}

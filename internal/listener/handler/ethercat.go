package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ethercat emulates an EtherCAT segment reached over the UDP encapsulation
// (EtherCAT-over-UDP, port 0x88A4 = 34980). EtherCAT is normally an L2-only
// fieldbus, so a master datagram arriving over IP is itself anomalous targeted
// OT recon. We parse the EtherCAT header + first datagram, classify the command
// (slave register/process reads = recon, writes = control manipulation,
// broadcast read = segment enumeration), and answer by echoing the frame with
// the Working Counter incremented (so the master believes slaves processed it)
// and read data filled. Response is the same size as the request (no
// amplification) and rate-limited.
type ethercat struct{ lim *udpReflectLimiter }

func (e *ethercat) Name() string { return "ethercat" }

func (e *ethercat) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 2 {
		res.Meta["short_frame"] = true
		return res, nil
	}
	h := binary.LittleEndian.Uint16(payload[0:2])
	frameType := (h >> 12) & 0x0F
	res.Meta["ethercat_type"] = frameType
	if frameType != 0x01 { // 0x1 = EtherCAT command datagrams
		res.Meta["non_ethercat_type"] = frameType
		return res, nil
	}
	flagAnomaly(&res, "ethercat-probe")
	setIfEmpty(res.Meta, "intent", "EtherCAT-over-UDP probe — fieldbus recon over IP (EtherCAT is normally L2-only)")

	// First datagram: cmd(1) idx(1) address(4) len+flags(2) irq(2) data(dlen) wkc(2).
	const dgHdr = 10
	if len(payload) < 2+dgHdr {
		return res, nil
	}
	dg := payload[2:]
	cmd := dg[0]
	res.Meta["ethercat_cmd"] = ethercatCmdName(cmd)
	dlen := int(binary.LittleEndian.Uint16(dg[6:8]) & 0x07FF)

	wkc := uint16(1)
	switch {
	case ethercatIsWrite(cmd):
		flagAnomaly(&res, "ics-plc-write")
		res.Meta["intent"] = "EtherCAT " + ethercatCmdName(cmd) + " — writing slave registers / process image (control manipulation)"
	case cmd == 7 || cmd == 9: // BRD / BRW — broadcast: enumerate the segment
		flagAnomaly(&res, "ics-field-device-probe")
		res.Meta["intent"] = "EtherCAT " + ethercatCmdName(cmd) + " — broadcast read, enumerating the EtherCAT segment"
		wkc = 3 // three slaves "answered"
	case ethercatIsRead(cmd):
		flagAnomaly(&res, "ics-process-data-access")
		res.Meta["intent"] = "EtherCAT " + ethercatCmdName(cmd) + " — reading slave registers / process data"
	}

	// Echo the frame with the data region filled (for reads) and the WKC set.
	resp := append([]byte(nil), payload...)
	dataStart := 2 + dgHdr
	wkcPos := dataStart + dlen
	if wkcPos+2 <= len(resp) {
		if ethercatIsRead(cmd) || cmd == 7 || cmd == 9 {
			for i := dataStart; i < wkcPos; i++ {
				resp[i] = byte((i*37 + 11) & 0xFF) // believable non-zero process data
			}
		}
		binary.LittleEndian.PutUint16(resp[wkcPos:wkcPos+2], wkc)
	}
	if e.lim.allow() {
		if _, err := pc.WriteTo(resp, src); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = "ethercat reply (wkc " + itoa(int(wkc)) + ")"
	}
	_ = cfg
	return res, nil
}

func ethercatIsRead(cmd byte) bool {
	switch cmd {
	case 1, 3, 4, 6, 7, 9, 10, 12, 13, 14: // APRD/APRW/FPRD/FPRW/BRD/BRW/LRD/LRW/ARMW/FRMW
		return true
	}
	return false
}

func ethercatIsWrite(cmd byte) bool {
	switch cmd {
	case 2, 5, 8, 11: // APWR / FPWR / BWR / LWR
		return true
	}
	return false
}

func ethercatCmdName(cmd byte) string {
	switch cmd {
	case 0:
		return "NOP"
	case 1:
		return "APRD"
	case 2:
		return "APWR"
	case 3:
		return "APRW"
	case 4:
		return "FPRD"
	case 5:
		return "FPWR"
	case 6:
		return "FPRW"
	case 7:
		return "BRD"
	case 8:
		return "BWR"
	case 9:
		return "BRW"
	case 10:
		return "LRD"
	case 11:
		return "LWR"
	case 12:
		return "LRW"
	case 13:
		return "ARMW"
	case 14:
		return "FRMW"
	}
	return "cmd-0x" + itoa(int(cmd))
}

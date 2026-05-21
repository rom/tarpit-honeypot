package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ads emulates the Beckhoff ADS/AMS protocol (TCP 48898) — the engineering
// channel of TwinCAT PLCs / CX embedded PCs. Framing: a 6-byte AMS/TCP
// header (2 reserved + 4-byte little-endian length) then a 32-byte AMS
// header (target/source AmsNetId+port, command id, state flags, lengths,
// invoke id) and the command data. We parse the AMS header, capture the
// command + AmsNetIds, and answer a Read-Device-Info request with a
// believable TwinCAT identity. Fingerprint-grade — no PLC symbols served.
type ads struct{}

func (a *ads) Name() string { return "ads" }

// AMS command ids.
const adsReadDeviceInfo = 1

func (a *ads) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 6) // AMS/TCP header: reserved(2) + length(4, LE)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	plen := binary.LittleEndian.Uint32(hdr[2:6])
	if plen < 32 || plen > 8192 {
		res.Meta["bad_ams_len"] = plen
		return res, nil
	}
	pkt := make([]byte, plen)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(append([]byte(nil), hdr...), pkt...)

	// AMS header layout (offsets): target AmsNetId[0:6] port[6:8],
	// source AmsNetId[8:14] port[14:16], commandId[16:18], stateFlags[18:20],
	// dataLength[20:24], errorCode[24:28], invokeId[28:32].
	cmdID := binary.LittleEndian.Uint16(pkt[16:18])
	stateFlags := binary.LittleEndian.Uint16(pkt[18:20])
	res.Meta["ads_command"] = adsCommandName(cmdID)
	res.Meta["ams_target"] = amsNetID(pkt[0:6])
	res.Meta["ams_source"] = amsNetID(pkt[8:14])
	flagAnomaly(&res, "ics-ads-probe")

	// Read Device Info -> reply with a TwinCAT identity.
	var data []byte
	if cmdID == adsReadDeviceInfo {
		data = make([]byte, 24)
		// result(4)=0, version major(1)/minor(1)/build(2), name[16].
		data[4] = 3 // TwinCAT major
		data[5] = 1 // minor
		binary.LittleEndian.PutUint16(data[6:8], 4024)
		copy(data[8:], "TwinCAT")
	} else {
		data = make([]byte, 4) // generic ADS response: result(4)=0
	}

	resp := make([]byte, 32+len(data))
	copy(resp[0:6], pkt[8:14])  // target = request source
	copy(resp[6:8], pkt[14:16]) // target port = request source port
	copy(resp[8:14], pkt[0:6])  // source = request target
	copy(resp[14:16], pkt[6:8]) // source port = request target port
	binary.LittleEndian.PutUint16(resp[16:18], cmdID)
	binary.LittleEndian.PutUint16(resp[18:20], stateFlags|0x0001) // mark response
	binary.LittleEndian.PutUint32(resp[20:24], uint32(len(data)))
	// errorCode[24:28]=0, invokeId[28:32] echoed.
	copy(resp[28:32], pkt[28:32])
	copy(resp[32:], data)

	frame := make([]byte, 6+len(resp))
	binary.LittleEndian.PutUint32(frame[2:6], uint32(len(resp)))
	copy(frame[6:], resp)
	if _, err := conn.Write(frame); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "beckhoff ads response"
	return res, nil
}

func amsNetID(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	d := "0123456789"
	out := make([]byte, 0, 17)
	for i, x := range b {
		if i > 0 {
			out = append(out, '.')
		}
		if x >= 100 {
			out = append(out, d[x/100])
		}
		if x >= 10 {
			out = append(out, d[(x/10)%10])
		}
		out = append(out, d[x%10])
	}
	return string(out)
}

func adsCommandName(id uint16) string {
	switch id {
	case 1:
		return "ReadDeviceInfo"
	case 2:
		return "Read"
	case 3:
		return "Write"
	case 4:
		return "ReadState"
	case 5:
		return "WriteControl"
	case 6:
		return "AddDeviceNotification"
	case 9:
		return "ReadWrite"
	}
	return "unknown"
}

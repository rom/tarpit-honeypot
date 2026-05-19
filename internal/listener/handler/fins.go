package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// fins is the Omron FINS (Factory Interface Network Service) UDP
// receiver (default port 9600). FINS frame layout:
//
//   ICF(1) RSV(1) GCT(1) DNA(1) DA1(1) DA2(1) SNA(1) SA1(1) SA2(1)
//   SID(1) MRC(1) SRC(1) <data>
//
// We capture the command + reply with plausible data for the four
// MRC/SRC pairs a scanner usually emits:
//
//   0x05 / 0x01  CPU_UNIT_DATA_READ      -> 20-byte model + 20-byte version
//   0x06 / 0x01  CPU_UNIT_STATUS_READ    -> RUN mode + no fatal errors
//   0x01 / 0x01  MEMORY_AREA_READ        -> N words of plausible PV data
//   0x07 / 0x01  CYCLE_TIME_READ         -> 1ms avg / 5ms peak
//
// All other commands get a generic END=0x0000 acknowledge. Unknown
// MRC pairs aren't silently dropped because that distinguishes a
// honeypot from a real PLC (which ack-and-execute).
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
	res.Meta["command"] = finsCommandName(mrc, src_)
	res.Meta["dna"] = payload[3]
	res.Meta["sna"] = payload[6]
	res.Meta["sid"] = payload[9]

	// Build reply header: swap source/destination, set ICF response bit,
	// echo MRC/SRC.
	header := make([]byte, 12)
	copy(header, payload)
	header[0] = 0xC0 // response
	header[3], header[6] = payload[6], payload[3]
	header[4], header[7] = payload[7], payload[4]
	header[5], header[8] = payload[8], payload[5]

	var extra []byte
	switch {
	case mrc == 0x05 && src_ == 0x01: // CPU_UNIT_DATA_READ
		// END 0x0000 + 20-byte model + 20-byte version + 40-byte sysReserved
		// + 12-byte areaData. Real CJ2M response is ~96 bytes after END.
		extra = append(extra, 0x00, 0x00)
		extra = append(extra, padTo("CJ2M-CPU33", 20)...)
		extra = append(extra, padTo("REV.2.0", 20)...)
		extra = append(extra, make([]byte, 40)...)
		// areaData: number of words per area (DM=32768, CIO=6144, ...).
		extra = append(extra, 0x80, 0x00, 0x18, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	case mrc == 0x06 && src_ == 0x01: // CPU_UNIT_STATUS_READ
		// END(2) + Status(1)=0x01 RUN + Mode(1)=0x02 MONITOR + Error(2)=0
		// + ErrorMessage(16) "" + FAL/FALS(2)=0 + ErrorMessage(16) "" .
		extra = append(extra, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00)
		extra = append(extra, make([]byte, 16)...)
		extra = append(extra, 0x00, 0x00)
		extra = append(extra, make([]byte, 16)...)
	case mrc == 0x01 && src_ == 0x01: // MEMORY_AREA_READ
		// Request body: area code(1) + address(3) + count(2).
		// Response: END(2) + count*2 bytes of data.
		count := 0
		if len(payload) >= 18 {
			area := payload[12]
			res.Meta["mem_area"] = area
			res.Meta["mem_area_name"] = finsAreaName(area)
			res.Meta["mem_addr"] = uint32(payload[13])<<16 | uint32(payload[14])<<8 | uint32(payload[15])
			count = int(binary.BigEndian.Uint16(payload[16:18]))
			res.Meta["mem_count"] = count
		}
		// Cap at 256 words to avoid an oversized response to a fuzz request.
		if count < 0 || count > 256 {
			count = 0
		}
		extra = append(extra, 0x00, 0x00)
		// Generate believable-looking process values: a small sine-ish
		// pattern instead of all zeros (less suspicious to an analyst
		// dumping the memory area for the first time).
		for i := 0; i < count; i++ {
			val := uint16(1000 + (i*173)%500)
			extra = append(extra, byte(val>>8), byte(val))
		}
	case mrc == 0x07 && src_ == 0x01: // CYCLE_TIME_READ
		// END(2) + avg(4 LE) + max(4 LE) + min(4 LE), in 0.1ms units.
		extra = append(extra, 0x00, 0x00)
		extra = binary.LittleEndian.AppendUint32(extra, 10)  // 1.0ms avg
		extra = binary.LittleEndian.AppendUint32(extra, 50)  // 5.0ms max
		extra = binary.LittleEndian.AppendUint32(extra, 8)   // 0.8ms min
	case mrc == 0x09 && src_ == 0x20: // CLOCK_READ
		// END + year(1 BCD) + month + day + hour + min + sec + dayOfWeek.
		extra = []byte{0x00, 0x00, 0x25, 0x05, 0x19, 0x14, 0x30, 0x00, 0x01}
	default:
		// Generic acknowledge: END 00 00.
		extra = []byte{0x00, 0x00}
	}

	reply := append(header, extra...)
	if _, err := pc.WriteTo(reply, src); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "fins " + finsCommandName(mrc, src_)
	_ = cfg
	return res, nil
}

func finsCommandName(mrc, src byte) string {
	switch {
	case mrc == 0x01 && src == 0x01:
		return "MEMORY_AREA_READ"
	case mrc == 0x01 && src == 0x02:
		return "MEMORY_AREA_WRITE"
	case mrc == 0x01 && src == 0x03:
		return "MEMORY_AREA_FILL"
	case mrc == 0x04 && src == 0x01:
		return "RUN"
	case mrc == 0x04 && src == 0x02:
		return "STOP"
	case mrc == 0x05 && src == 0x01:
		return "CPU_UNIT_DATA_READ"
	case mrc == 0x06 && src == 0x01:
		return "CPU_UNIT_STATUS_READ"
	case mrc == 0x07 && src == 0x01:
		return "CYCLE_TIME_READ"
	case mrc == 0x09 && src == 0x20:
		return "CLOCK_READ"
	case mrc == 0x09 && src == 0x21:
		return "CLOCK_WRITE"
	case mrc == 0x21 && src == 0x02:
		return "ERROR_CLEAR"
	case mrc == 0x22 && src == 0x01:
		return "FILE_READ"
	}
	return ""
}

// finsAreaName decodes the FINS memory-area code byte to its symbolic
// name (DM = Data Memory, CIO = Common I/O, HR = Holding, WR = Work).
// Lets the SIEM see "scanner read DM area starting at 100, count 50"
// instead of just opaque hex.
func finsAreaName(a byte) string {
	switch a {
	case 0x30, 0xB0:
		return "CIO" // bit / word
	case 0x31, 0xB1:
		return "WR"
	case 0x32, 0xB2:
		return "HR"
	case 0x33, 0xB3:
		return "AR"
	case 0x82:
		return "DM"
	case 0x89:
		return "EM"
	}
	return ""
}

// padTo right-pads s with spaces (FINS strings) to n bytes. If s is
// already >= n, it's truncated.
func padTo(s string, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = ' '
	}
	copy(out, s)
	return out
}

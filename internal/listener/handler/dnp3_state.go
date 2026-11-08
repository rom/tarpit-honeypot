package handler

import "encoding/binary"

// DNP3 application-layer responder + per-session point overlay.
//
// The base handler (dnp3.go) classifies the application function and replies at
// the link layer. This file adds believable *application* responses so a master
// that READs gets point data back, and so a control action (OPERATE a binary
// output via a CROB, or an analog output via an AOB) is reflected by a later
// READ of the corresponding status group — the write-then-read-back coherence a
// careful DNP3 master uses to confirm an actuation landed.
//
// Everything here is built to the IEEE-1815 wire format and is bounded-safe: an
// object/qualifier the parser doesn't model is echoed or skipped, never
// malformed, and the base handler keeps its link-layer reply whenever this
// layer declines to produce a response (returns nil).

// dnp3Mem is the per-connection overlay for writable points: binary outputs
// (group 10, driven by CROB operates) and analog outputs (group 40, driven by
// AOB operates). Inputs (groups 1/30) are read-only synthetic. Bounded.
type dnp3Mem struct {
	binOut map[int]bool
	anaOut map[int]uint32 // 32-bit so g41v1 (32-bit) writes are stored losslessly
}

const dnp3MemCap = 1024

func newDNP3Mem() *dnp3Mem {
	return &dnp3Mem{binOut: make(map[int]bool), anaOut: make(map[int]uint32)}
}

func (m *dnp3Mem) binOutGet(i int) bool { return m.binOut[i] } // default de-energized
func (m *dnp3Mem) binOutSet(i int, on bool) {
	if _, ok := m.binOut[i]; !ok && len(m.binOut) >= dnp3MemCap {
		return
	}
	m.binOut[i] = on
}
func (m *dnp3Mem) anaOutGet(i int) uint32 { return m.anaOut[i] } // default 0 setpoint
func (m *dnp3Mem) anaOutSet(i int, v uint32) {
	if _, ok := m.anaOut[i]; !ok && len(m.anaOut) >= dnp3MemCap {
		return
	}
	m.anaOut[i] = v
}

// dnp3SynthBinIn / dnp3SynthAnaIn are stable per-index synthetic input values.
func dnp3SynthBinIn(i int) bool   { return i%3 == 0 }
func dnp3SynthAnaIn(i int) uint16 { return uint16(100 + i*7) }

const (
	dnp3MaxBin = 16 // modeled binary input / output points
	dnp3MaxAna = 8  // modeled analog input / output points
)

// dnp3NullResponse is an application response carrying no objects (WRITE / any
// success acknowledgement): app-control (FIR|FIN|seq), function 0x81, IIN=0000.
func dnp3NullResponse(seq byte) []byte {
	return []byte{0xC0 | (seq & 0x0F), 0x81, 0x00, 0x00}
}

// dnp3ReadResponse builds a RESPONSE (0x81) carrying the requested points.
func dnp3ReadResponse(objs []byte, mem *dnp3Mem, seq byte) []byte {
	app := []byte{0xC0 | (seq & 0x0F), 0x81, 0x00, 0x00}
	groups := dnp3ParseReadRequest(objs)
	if len(groups) == 0 {
		groups = []dnp3ReadGroup{{group: 60, all: true}} // empty/unparsed -> class 0
	}
	var body []byte
	for _, g := range groups {
		if len(app)+len(body) > 230 { // keep the response inside one believable frame
			break
		}
		body = append(body, dnp3EncodeGroup(g, mem)...)
	}
	return append(app, body...)
}

type dnp3ReadGroup struct {
	group       byte
	variation   byte // requested object variation (e.g. g40v1=32-bit, v2=16-bit)
	start, stop int
	all         bool
}

// dnp3ParseReadRequest walks the object headers of a READ request. READ headers
// carry no point data, only group/variation/qualifier and an optional range.
func dnp3ParseReadRequest(objs []byte) []dnp3ReadGroup {
	var out []dnp3ReadGroup
	i := 0
	for i+3 <= len(objs) && len(out) < 16 {
		g, variation, q := objs[i], objs[i+1], objs[i+2]
		i += 3
		rg := dnp3ReadGroup{group: g, variation: variation}
		switch q {
		case 0x06: // all points
			rg.all = true
		case 0x00: // 8-bit start/stop
			if i+2 > len(objs) {
				return out
			}
			rg.start, rg.stop = int(objs[i]), int(objs[i+1])
			i += 2
		case 0x01: // 16-bit start/stop
			if i+4 > len(objs) {
				return out
			}
			rg.start = int(binary.LittleEndian.Uint16(objs[i : i+2]))
			rg.stop = int(binary.LittleEndian.Uint16(objs[i+2 : i+4]))
			i += 4
		case 0x07: // 8-bit count
			if i+1 > len(objs) {
				return out
			}
			rg.stop = int(objs[i]) - 1
			i++
		case 0x08: // 16-bit count
			if i+2 > len(objs) {
				return out
			}
			rg.stop = int(binary.LittleEndian.Uint16(objs[i:i+2])) - 1
			i += 2
		default:
			rg.all = true // unknown qualifier — return all of this group, stop
			out = append(out, rg)
			return out
		}
		out = append(out, rg)
	}
	return out
}

// dnp3EncodeGroup encodes one requested group's points. Class data (group 60)
// expands to the full static set. Unmodeled groups are skipped.
func dnp3EncodeGroup(r dnp3ReadGroup, mem *dnp3Mem) []byte {
	switch r.group {
	case 1: // Binary Input
		s, e := dnp3Clamp(r, dnp3MaxBin)
		return dnp3EncBinary(0x01, s, e, dnp3SynthBinIn)
	case 10: // Binary Output Status (overlay)
		s, e := dnp3Clamp(r, dnp3MaxBin)
		return dnp3EncBinary(0x0A, s, e, mem.binOutGet)
	case 30: // Analog Input
		s, e := dnp3Clamp(r, dnp3MaxAna)
		return dnp3EncAnalog16(0x1E, s, e, dnp3SynthAnaIn)
	case 40: // Analog Output Status (overlay)
		s, e := dnp3Clamp(r, dnp3MaxAna)
		// Honor the requested variation: v1 = 32-bit, v2 (or unspecified) =
		// 16-bit (the low word), so a 32-bit g41v1 write round-trips losslessly
		// via a g40v1 read while 16-bit masters keep seeing 16-bit values.
		if r.variation == 0x01 {
			return dnp3EncAnalog32(0x28, s, e, mem.anaOutGet)
		}
		return dnp3EncAnalog16(0x28, s, e, dnp3Ana16Getter(mem.anaOutGet))
	case 60: // class data -> the full static image
		var out []byte
		out = append(out, dnp3EncBinary(0x01, 0, dnp3MaxBin-1, dnp3SynthBinIn)...)
		out = append(out, dnp3EncBinary(0x0A, 0, dnp3MaxBin-1, mem.binOutGet)...)
		out = append(out, dnp3EncAnalog16(0x1E, 0, dnp3MaxAna-1, dnp3SynthAnaIn)...)
		out = append(out, dnp3EncAnalog16(0x28, 0, dnp3MaxAna-1, dnp3Ana16Getter(mem.anaOutGet))...)
		return out
	}
	return nil
}

func dnp3Clamp(r dnp3ReadGroup, max int) (int, int) {
	if r.all {
		return 0, max - 1
	}
	s, e := r.start, r.stop
	if s < 0 {
		s = 0
	}
	if e >= max {
		e = max - 1
	}
	if e < s {
		e = s
	}
	return s, e
}

// dnp3EncBinary encodes group var 2 (binary, with flags): one flag byte per
// point, bit0=ONLINE, bit7=state. Qualifier 0x00 (8-bit start/stop).
func dnp3EncBinary(group byte, start, stop int, get func(int) bool) []byte {
	if stop < start {
		return nil
	}
	data := make([]byte, 0, stop-start+1)
	for i := start; i <= stop; i++ {
		f := byte(0x01)
		if get(i) {
			f |= 0x80
		}
		data = append(data, f)
	}
	return dnp3Object(group, 0x02, byte(start), byte(stop), data)
}

// dnp3EncAnalog16 encodes group var 2 (16-bit analog, with flag): flag(1) +
// value(2 LE) per point. Qualifier 0x00.
func dnp3EncAnalog16(group byte, start, stop int, get func(int) uint16) []byte {
	if stop < start {
		return nil
	}
	data := make([]byte, 0, (stop-start+1)*3)
	for i := start; i <= stop; i++ {
		data = append(data, 0x01) // ONLINE
		data = binary.LittleEndian.AppendUint16(data, get(i))
	}
	return dnp3Object(group, 0x02, byte(start), byte(stop), data)
}

// dnp3EncAnalog32 encodes group var 1 (32-bit analog, with flag): flag(1) +
// value(4) per point. Used for a g40v1 read so a 32-bit analog-output write
// (g41v1) reflects its full value on read-back.
func dnp3EncAnalog32(group byte, start, stop int, get func(int) uint32) []byte {
	if stop < start {
		return nil
	}
	data := make([]byte, 0, (stop-start+1)*5)
	for i := start; i <= stop; i++ {
		data = append(data, 0x01) // ONLINE
		data = binary.LittleEndian.AppendUint32(data, get(i))
	}
	return dnp3Object(group, 0x01, byte(start), byte(stop), data)
}

// dnp3Ana16Getter adapts a 32-bit analog getter to the 16-bit encoder by
// returning the low word (what a 16-bit master requested).
func dnp3Ana16Getter(get func(int) uint32) func(int) uint16 {
	return func(i int) uint16 { return uint16(get(i)) }
}

// dnp3Object frames an object header (group, variation, qualifier 0x00 with an
// 8-bit start/stop range) followed by its point data.
func dnp3Object(group, variation, start, stop byte, data []byte) []byte {
	return append([]byte{group, variation, 0x00, start, stop}, data...)
}

// dnp3ControlResponse echoes a SELECT / OPERATE control request with each
// point's status byte set to SUCCESS (0), and (when apply) updates the overlay
// so a later READ of the output-status group reflects the actuation.
func dnp3ControlResponse(objs []byte, mem *dnp3Mem, seq byte, apply bool) []byte {
	app := []byte{0xC0 | (seq & 0x0F), 0x81, 0x00, 0x00}
	return append(app, dnp3ProcessControl(objs, mem, apply)...)
}

// dnp3ProcessControl parses CROB (group 12 var 1) and Analog Output Block
// (group 41 var 1/2) requests under the prefixed-index qualifiers 0x17 (8-bit)
// and 0x28 (16-bit), updates the overlay, and returns the echoed objects with
// status = SUCCESS. Anything it can't model is echoed verbatim (still believable).
func dnp3ProcessControl(objs []byte, mem *dnp3Mem, apply bool) []byte {
	if len(objs) < 4 {
		return objs
	}
	group, variation, qual := objs[0], objs[1], objs[2]
	i := 3
	var idxSize, count int
	switch qual {
	case 0x17: // 8-bit count + 8-bit index prefix
		count, idxSize = int(objs[i]), 1
		i++
	case 0x28: // 16-bit count + 16-bit index prefix
		if i+2 > len(objs) {
			return objs
		}
		count, idxSize = int(binary.LittleEndian.Uint16(objs[i:i+2])), 2
		i += 2
	default:
		return objs
	}
	body := dnp3ControlBodySize(group, variation)
	if body == 0 || count <= 0 || count > 64 {
		return objs
	}
	echo := append([]byte{}, objs[:i]...) // group/var/qual + count prefix
	for n := 0; n < count; n++ {
		if i+idxSize+body > len(objs) {
			break
		}
		idxBytes := objs[i : i+idxSize]
		idx := int(idxBytes[0])
		if idxSize == 2 {
			idx = int(binary.LittleEndian.Uint16(idxBytes))
		}
		i += idxSize
		pt := append([]byte(nil), objs[i:i+body]...)
		i += body
		if apply {
			dnp3ApplyControl(group, variation, idx, pt, mem)
		}
		pt[len(pt)-1] = 0x00 // status = SUCCESS
		echo = append(echo, idxBytes...)
		echo = append(echo, pt...)
	}
	return echo
}

// dnp3ControlBodySize is the per-point body length (incl. trailing status byte)
// for the control object types we model.
func dnp3ControlBodySize(group, variation byte) int {
	switch {
	case group == 0x0C && variation == 0x01: // CROB
		return 11
	case group == 0x29 && variation == 0x01: // Analog Output Block, 32-bit
		return 5
	case group == 0x29 && variation == 0x02: // Analog Output Block, 16-bit
		return 3
	}
	return 0
}

// dnp3ApplyControl updates the overlay from one control point.
func dnp3ApplyControl(group, variation byte, idx int, pt []byte, mem *dnp3Mem) {
	switch {
	case group == 0x0C && variation == 0x01: // CROB
		op := pt[0] & 0x0F         // operation type
		tcc := (pt[0] >> 6) & 0x03 // trip-close code
		on := op == 1 || op == 3 || tcc == 1
		if op == 2 || op == 4 || tcc == 2 {
			on = false
		}
		mem.binOutSet(idx, on)
	case group == 0x29 && variation == 0x01: // AOB, 32-bit value (g41v1)
		mem.anaOutSet(idx, binary.LittleEndian.Uint32(pt[0:4]))
	case group == 0x29 && variation == 0x02: // AOB, 16-bit value (g41v2)
		mem.anaOutSet(idx, uint32(binary.LittleEndian.Uint16(pt[0:2])))
	}
}

// dnp3WrapApp wraps an application payload in a transport segment + DNP3
// data-link frame addressed to the master, blocking the user data into 16-byte
// chunks each followed by a CRC. Control byte 0x44 = DIR(outstation), PRM,
// UNCONFIRMED_USER_DATA — the conventional outstation-response framing.
func dnp3WrapApp(toAddr, fromAddr uint16, app []byte) []byte {
	user := append([]byte{0xC0}, app...) // transport: FIR|FIN, segment 0
	if len(user) > 250 {
		user = user[:250]
	}
	out := []byte{0x05, 0x64, byte(5 + len(user)), 0x44}
	out = binary.LittleEndian.AppendUint16(out, toAddr)
	out = binary.LittleEndian.AppendUint16(out, fromAddr)
	out = binary.LittleEndian.AppendUint16(out, dnp3CRC(out))
	for off := 0; off < len(user); off += 16 {
		end := off + 16
		if end > len(user) {
			end = len(user)
		}
		out = append(out, user[off:end]...)
		out = binary.LittleEndian.AppendUint16(out, dnp3CRC(user[off:end]))
	}
	return out
}

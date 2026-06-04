package handler

import (
	"encoding/binary"
	"unicode/utf16"
)

// Minimal NDR (Network Data Representation) codec for the OPC-DA / DCOM call
// layer — little-endian transfer syntax only (drep 0x10), which is what every
// real OPC client negotiates. NDR is the wire encoding DCE/RPC stub data uses:
// primitives are aligned to their own size and complex types (strings, arrays,
// pointers) carry conformance/offset/referent prefixes. We implement just the
// slice of NDR the OPC-DA IOPCServer / IOPCItemMgt / IOPCSyncIO calls need:
// uint16/32/64, [string,unique] wide strings (conformant+varying), and unique
// pointer referents. This is enough to decode the item IDs / group names an
// attacker asks for and to marshal a believable OPCSERVERSTATUS back.

// ndrEnc builds an NDR-encoded little-endian stub.
type ndrEnc struct{ buf []byte }

func (e *ndrEnc) align(n int) {
	for len(e.buf)%n != 0 {
		e.buf = append(e.buf, 0)
	}
}

func (e *ndrEnc) u16(v uint16) {
	e.align(2)
	e.buf = binary.LittleEndian.AppendUint16(e.buf, v)
}

func (e *ndrEnc) u32(v uint32) {
	e.align(4)
	e.buf = binary.LittleEndian.AppendUint32(e.buf, v)
}

func (e *ndrEnc) u64(v uint64) {
	e.align(8)
	e.buf = binary.LittleEndian.AppendUint64(e.buf, v)
}

func (e *ndrEnc) bytes(b []byte) { e.buf = append(e.buf, b...) }

// uniquePtr writes a non-null unique-pointer referent id (any non-zero value).
func (e *ndrEnc) uniquePtr(ref uint32) { e.u32(ref) }

// nullPtr writes a null unique pointer.
func (e *ndrEnc) nullPtr() { e.u32(0) }

// wstr writes a [string,unique] wchar_t* as NDR: a conformant+varying array of
// UTF-16LE code units, NUL-terminated, with max_count / offset / actual_count
// prefixes. The referent id must already have been written by the caller.
func (e *ndrEnc) wstr(s string) {
	units := utf16.Encode([]rune(s))
	units = append(units, 0) // NUL terminator counts toward the string length
	n := uint32(len(units))
	e.u32(n) // max_count
	e.u32(0) // offset
	e.u32(n) // actual_count
	for _, u := range units {
		e.u16(u)
	}
}

// ndrDec reads from an NDR-encoded little-endian stub.
type ndrDec struct {
	buf []byte
	pos int
}

func (d *ndrDec) remaining() int { return len(d.buf) - d.pos }

func (d *ndrDec) align(n int) {
	for d.pos%n != 0 && d.pos < len(d.buf) {
		d.pos++
	}
}

func (d *ndrDec) u16() (uint16, bool) {
	d.align(2)
	if d.pos+2 > len(d.buf) {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(d.buf[d.pos:])
	d.pos += 2
	return v, true
}

func (d *ndrDec) u32() (uint32, bool) {
	d.align(4)
	if d.pos+4 > len(d.buf) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(d.buf[d.pos:])
	d.pos += 4
	return v, true
}

// skip advances n bytes if available.
func (d *ndrDec) skip(n int) bool {
	if d.pos+n > len(d.buf) {
		return false
	}
	d.pos += n
	return true
}

// wstr reads a [string,unique] wchar_t* (conformant+varying UTF-16LE array)
// and returns the decoded string with any trailing NUL trimmed. The referent
// id is assumed already consumed by the caller (or absent for an inline
// [string] member).
func (d *ndrDec) wstr() (string, bool) {
	maxCount, ok := d.u32()
	if !ok {
		return "", false
	}
	if _, ok = d.u32(); !ok { // offset
		return "", false
	}
	actual, ok := d.u32()
	if !ok {
		return "", false
	}
	// Guard against a hostile length: bound to the buffer and the conformance.
	if actual > maxCount || actual > 65536 || int(actual)*2 > d.remaining()+4 {
		return "", false
	}
	units := make([]uint16, 0, actual)
	for i := uint32(0); i < actual; i++ {
		u, ok := d.u16()
		if !ok {
			return "", false
		}
		units = append(units, u)
	}
	// Trim trailing NUL terminator(s).
	for len(units) > 0 && units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	return string(utf16.Decode(units)), true
}

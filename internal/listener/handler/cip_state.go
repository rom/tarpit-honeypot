package handler

import (
	"encoding/binary"

	"github.com/rom/tarpit-honeypot/internal/safe"
)

// EtherNet/IP CIP symbolic-tag overlay. The base handler answers a Read_Tag
// with a fixed "DINT 42" and acks a Write_Tag without recording it, so a tag
// written earlier in the session does not read back — the write-then-read-back
// coherence a CIP client (or an attacker validating a controller write) checks.
//
// cipTags is a per-connection store keyed by symbolic tag name; the stored
// bytes are exactly a Read_Tag response payload (CIP type(2 LE) + value), so a
// later read returns them verbatim. Bounded, per-connection — no shared state.
type cipTags struct {
	vals map[string][]byte
}

const cipTagCap = 1024

func newCIPTags() *cipTags { return &cipTags{vals: make(map[string][]byte)} }

func (c *cipTags) get(name string) ([]byte, bool) { v, ok := c.vals[name]; return v, ok }

func (c *cipTags) set(name string, typeVal []byte) {
	if _, ok := c.vals[name]; !ok && len(c.vals) >= cipTagCap {
		return
	}
	c.vals[name] = append([]byte(nil), typeVal...)
}

// cipParsePath returns the symbolic tag name (ANSI extended symbol segment
// 0x91) from a CIP message-router request, if the request path is symbolic, and
// the offset where the request data begins (after service byte + path). A
// logical path (class/instance/attribute, e.g. 0x20/0x24) yields name "".
func cipParsePath(cip []byte) (name string, dataOff int, ok bool) {
	if len(cip) < 2 {
		return "", 0, false
	}
	pathBytes := int(cip[1]) * 2 // request_path_size is in 16-bit words
	const pathStart = 2
	if pathStart+pathBytes > len(cip) {
		return "", 0, false
	}
	path := cip[pathStart : pathStart+pathBytes]
	if len(path) >= 2 && path[0] == 0x91 {
		nlen := int(path[1])
		if 2+nlen <= len(path) {
			name = string(path[2 : 2+nlen])
		}
	}
	return name, pathStart + pathBytes, true
}

// cipSynthValue is the believable default for an unwritten tag: a DINT
// (type 0x00C4) whose value is stable per tag name (FNV-1a), so repeated reads
// of the same tag agree.
func cipSynthValue(name string) []byte {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h = (h ^ uint32(name[i])) * 16777619
	}
	out := []byte{0xC4, 0x00} // CIP type DINT, little-endian
	return binary.LittleEndian.AppendUint32(out, 1000+(h%9000))
}

// cipTagResponse builds the CIP message-router reply for a tag service: a
// success header (service|0x80, reserved, general-status 0, additional 0)
// followed, for reads, by the tag's stored or synthetic type+value. A Write_Tag
// records the written type+value in the overlay so a later read reflects it.
func cipTagResponse(service byte, cip []byte, tags *cipTags, res *Result) []byte {
	ok := []byte{service | 0x80, 0x00, 0x00, 0x00}
	switch service {
	case 0x4C, 0x52: // Read_Tag / Read_Tag_Fragmented
		name, _, _ := cipParsePath(cip)
		if name == "" {
			return append(ok, 0xC4, 0x00, 0x2A, 0x00, 0x00, 0x00) // logical path: generic DINT 42
		}
		res.Meta["cip_tag"] = safe.SanitizeForLog(name)
		if v, found := tags.get(name); found {
			return append(ok, v...)
		}
		return append(ok, cipSynthValue(name)...)
	case 0x4D, 0x53: // Write_Tag / Write_Tag_Fragmented
		name, dataOff, parsed := cipParsePath(cip)
		if parsed && name != "" {
			res.Meta["cip_tag"] = safe.SanitizeForLog(name)
			// request data: data_type(2) + element_count(2) [+ byte_offset(4) for
			// the fragmented service] + value(...).
			valStart := dataOff + 4
			if service == 0x53 {
				valStart += 4
			}
			if dataOff+2 <= len(cip) && valStart <= len(cip) {
				stored := append([]byte(nil), cip[dataOff:dataOff+2]...) // type
				stored = append(stored, cip[valStart:]...)               // value
				tags.set(name, stored)
			}
		}
		return ok
	case 0x0E: // Get_Attribute_Single — logical addressing, synthetic
		return append(ok, 0xC4, 0x00, 0x2A, 0x00, 0x00, 0x00)
	}
	return ok
}

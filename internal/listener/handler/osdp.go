package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// osdp is an OSDP (SIA Open Supervised Device Protocol, IEC 60839-11-5)
// responder. OSDP links an access-control unit (ACU / panel) to peripheral
// devices (PD) — card readers, keypads, door controllers. It is natively an
// RS-485 bus, but OSDP-over-IP serial gateways tunnel the same framing over
// TCP, which is what reaches a network honeypot.
//
// OSDP packet:
//
//	SOM(1)=0x53 | ADDR(1) | LEN_LSB(1) | LEN_MSB(1) | CTRL(1)
//	[ optional security control block ] | CMD/REPLY(1) | data... | CKSUM/CRC
//
// ADDR bit 7 set marks a reply (PD->ACU); CTRL bit 2 selects CRC-16 over a
// single-byte checksum. The ACU drives the bus with commands; the dangerous
// ones for a honeypot to surface are osdp_OUT (energize an output — unlock a
// door strike), osdp_COMSET (change the PD's bus address / baud — hijack the
// channel), and osdp_KEYSET / osdp_CHLNG (install or negotiate the secure
// channel key — an attacker pairing their own key to the reader). We parse
// and classify the command, then answer with a believable osdp_ACK / osdp_PDID
// so a scanner records a live access-control PD. Fingerprint-grade.
type osdp struct{}

func (o *osdp) Name() string { return "osdp" }

const osdpSOM = 0x53

// OSDP command codes (ACU -> PD).
const (
	osdpPOLL   = 0x60
	osdpID     = 0x61
	osdpCAP    = 0x62
	osdpOUT    = 0x68 // output control (door strike / relay)
	osdpLED    = 0x69
	osdpBUZ    = 0x6A
	osdpTEXT   = 0x6B
	osdpCOMSET = 0x6E // change PD address / baud
	osdpKEYSET = 0x75 // install secure-channel key
	osdpCHLNG  = 0x76 // secure-channel challenge
	osdpSCRYPT = 0x77 // secure-channel server cryptogram
)

// OSDP reply codes (PD -> ACU).
const (
	osdpACK  = 0x40
	osdpNAK  = 0x41
	osdpPDID = 0x45
)

func (o *osdp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 6 {
		res.Meta["read_err"] = "short"
		return res, nil
	}
	pkt := buf[:n]
	res.Payload = append([]byte(nil), pkt...)
	if pkt[0] != osdpSOM {
		res.Meta["non_osdp"] = true
		return res, nil
	}
	addr := pkt[1] & 0x7F
	ctrl := pkt[4]
	useCRC := ctrl&0x04 != 0
	secure := ctrl&0x08 != 0
	// CMD sits after the 5-byte header (and, when present, the security block).
	cmdOff := 5
	if secure && n > 7 {
		// Security control block: SCB length is the first SCB byte.
		scbLen := int(pkt[5])
		if scbLen > 0 && 5+scbLen < n {
			cmdOff = 5 + scbLen
		}
	}
	if cmdOff >= n {
		res.Meta["malformed"] = true
		return res, nil
	}
	cmd := pkt[cmdOff]
	res.Meta["osdp_address"] = addr
	res.Meta["osdp_command"] = osdpCmdName(cmd)
	res.Meta["osdp_secure_channel"] = secure
	flagAnomaly(&res, "ics-field-device-probe")
	setIfEmpty(res.Meta, "intent", "OSDP probe — access-control reader/panel enumeration")

	reply := byte(osdpACK)
	switch cmd {
	case osdpID, osdpCAP:
		reply = osdpPDID
	case osdpOUT:
		flagAnomaly(&res, "ics-actuator-command")
		res.Meta["intent"] = "OSDP osdp_OUT — energizing an output (door-strike / relay actuation)"
	case osdpCOMSET:
		flagAnomaly(&res, "ics-comms-reconfigure")
		res.Meta["intent"] = "OSDP osdp_COMSET — changing reader bus address/baud (channel hijack)"
	case osdpKEYSET:
		flagAnomaly(&res, "ics-key-install")
		res.Meta["intent"] = "OSDP osdp_KEYSET — installing a secure-channel key (rogue pairing)"
	case osdpCHLNG, osdpSCRYPT:
		flagAnomaly(&res, "ics-secure-channel-setup")
		res.Meta["intent"] = "OSDP secure-channel negotiation (osdp_CHLNG/SCRYPT)"
	case osdpTEXT, osdpLED, osdpBUZ:
		res.Meta["intent"] = "OSDP reader feedback command (LED/buzzer/text)"
	}

	o.writeReply(conn, &res, addr, reply, useCRC)
	res.BannerSent = "osdp " + osdpReplyName(reply)
	return res, nil
}

// writeReply emits a minimal OSDP reply frame: ADDR with the reply bit set,
// the reply code, a small believable body for osdp_PDID, and the matching
// checksum/CRC trailer.
func (o *osdp) writeReply(conn net.Conn, res *Result, addr, reply byte, useCRC bool) {
	var body []byte
	if reply == osdpPDID {
		// osdp_PDID: vendor code(3) + model(1) + version(1) + serial(4) +
		// firmware(3). A plausible HID/Mercury-class reader identity.
		body = []byte{0x00, 0x06, 0x8E, 0x01, 0x02, 0x12, 0x34, 0x56, 0x78, 0x01, 0x00, 0x05}
	}
	ctrl := byte(0x00)
	if useCRC {
		ctrl |= 0x04
	}
	// header(5) + reply(1) + body + trailer(1 or 2).
	trailer := 1
	if useCRC {
		trailer = 2
	}
	total := 6 + len(body) + trailer
	frame := make([]byte, 5+1+len(body))
	frame[0] = osdpSOM
	frame[1] = addr | 0x80 // reply bit
	frame[2] = byte(total & 0xFF)
	frame[3] = byte(total >> 8)
	frame[4] = ctrl
	frame[5] = reply
	copy(frame[6:], body)
	if useCRC {
		crc := osdpCRC(frame)
		frame = append(frame, byte(crc&0xFF), byte(crc>>8))
	} else {
		frame = append(frame, osdpChecksum(frame))
	}
	if _, err := conn.Write(frame); err != nil {
		res.Meta["write_err"] = err.Error()
	}
}

func osdpCmdName(c byte) string {
	switch c {
	case osdpPOLL:
		return "osdp_POLL"
	case osdpID:
		return "osdp_ID"
	case osdpCAP:
		return "osdp_CAP"
	case osdpOUT:
		return "osdp_OUT"
	case osdpLED:
		return "osdp_LED"
	case osdpBUZ:
		return "osdp_BUZ"
	case osdpTEXT:
		return "osdp_TEXT"
	case osdpCOMSET:
		return "osdp_COMSET"
	case osdpKEYSET:
		return "osdp_KEYSET"
	case osdpCHLNG:
		return "osdp_CHLNG"
	case osdpSCRYPT:
		return "osdp_SCRYPT"
	}
	return "cmd_" + fmtByte(c)
}

func osdpReplyName(r byte) string {
	switch r {
	case osdpACK:
		return "osdp_ACK"
	case osdpNAK:
		return "osdp_NAK"
	case osdpPDID:
		return "osdp_PDID"
	}
	return "reply_" + fmtByte(r)
}

// osdpChecksum is the OSDP single-byte checksum: the 2's-complement of the
// sum of all preceding bytes.
func osdpChecksum(b []byte) byte {
	var sum byte
	for _, x := range b {
		sum += x
	}
	return byte(-int8(sum))
}

// osdpCRC computes the OSDP CRC-16 (poly 0x1021, init 0x1EAF) over the frame.
func osdpCRC(b []byte) uint16 {
	crc := uint16(0x1EAF)
	for _, x := range b {
		crc ^= uint16(x) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

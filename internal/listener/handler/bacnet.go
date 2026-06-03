package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type bacnet struct{}

func (b *bacnet) Name() string { return "bacnet" }

// BACnet/IP (port 47808 UDP). Frame:
//
//	BVLC: type(1)=0x81 | function(1) | length(2) | NPDU/APDU...
//
// Scanners typically send Who-Is broadcast (BVLC function 0x0B,
// "Original-Broadcast-NPDU"). A real device replies with I-Am
// (APDU type Unconfirmed-Request, service 0x00). We reply with a
// minimal I-Am announcing device instance 1234, max APDU 1476,
// segmentation = no, vendor 260 (BACnet International).
func (b *bacnet) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}

	if len(payload) < 4 || payload[0] != 0x81 {
		res.Meta = map[string]any{"non_bacnet": true}
		return res, nil
	}
	bvlcFunc := payload[1]
	bvlcLen := binary.BigEndian.Uint16(payload[2:4])
	res.Meta = map[string]any{
		"bvlc_func":   bvlcFuncName(bvlcFunc),
		"bvlc_length": bvlcLen,
	}

	// Look inside the NPDU/APDU. We only care about Who-Is for replies.
	// NPDU starts at offset 4. Minimal NPDU header is 2 bytes (version+control).
	if len(payload) < 6 {
		return res, nil
	}
	npduCtl := payload[5]
	// If control byte has bit 0x08 set, addresses follow. We skip them by
	// walking the standard NPDU layout — keeping it minimal here.
	apduStart := 6
	if npduCtl&0x20 != 0 {
		// Destination present: DNET(2) + DLEN(1) + DADR(DLEN)
		if apduStart+3 > len(payload) {
			return res, nil
		}
		dlen := int(payload[apduStart+2])
		apduStart += 3 + dlen
	}
	if npduCtl&0x08 != 0 {
		// Source present: SNET(2) + SLEN(1) + SADR(SLEN)
		if apduStart+3 > len(payload) {
			return res, nil
		}
		slen := int(payload[apduStart+2])
		apduStart += 3 + slen
	}
	if npduCtl&0x20 != 0 {
		// Hop count
		apduStart++
	}
	if apduStart >= len(payload) {
		return res, nil
	}

	apduType := payload[apduStart] >> 4
	// 0x0 = Confirmed-Request (WriteProperty / ReadProperty / ...). For an
	// unsegmented confirmed request the layout is byte0(type|flags)
	// byte1(max-segs/resp) byte2(invoke-id) byte3(service-choice). We
	// acknowledge WriteProperty with a SimpleACK + flag the write attempt
	// (a real value-change attempt against a control point is notable).
	if apduType == 0x0 {
		if apduStart+3 >= len(payload) {
			return res, nil
		}
		invokeID := payload[apduStart+2]
		csvc := payload[apduStart+3]
		res.Meta["apdu_service"] = bacnetConfirmedName(csvc)
		switch csvc {
		case 0x0F, 0x10: // WriteProperty / WritePropertyMultiple
			flagAnomaly(&res, "bacnet-write-attempt")
			ack := buildSimpleACK(invokeID, csvc)
			if _, err := pc.WriteTo(ack, src); err != nil {
				res.Meta["write_err"] = err.Error()
			} else {
				res.BannerSent = "bacnet SimpleACK (WriteProperty)"
			}
		case 0x11: // DeviceCommunicationControl — disable a device's comms (DoS)
			flagAnomaly(&res, "bacnet-device-comm-control")
		case 0x14: // ReinitializeDevice — warm/cold reboot
			flagAnomaly(&res, "bacnet-reinitialize-device")
		case 0x07: // AtomicWriteFile — overwrite a device file
			flagAnomaly(&res, "bacnet-file-write-attempt")
		}
		_ = cfg
		return res, nil
	}
	// 0x1 = Unconfirmed-Request. Service code is next byte.
	if apduType != 0x1 {
		return res, nil
	}
	if apduStart+1 >= len(payload) {
		return res, nil
	}
	service := payload[apduStart+1]
	res.Meta["apdu_service"] = bacnetServiceName(service)
	if service != 0x08 {
		// 0x08 = Who-Is. We only respond to Who-Is.
		return res, nil
	}

	// Build I-Am reply.
	iAm := buildIAm(1234, 1476, 3, 260)
	if _, err := pc.WriteTo(iAm, src); err != nil {
		res.Meta["write_err"] = err.Error()
	} else {
		res.BannerSent = "bacnet I-Am (instance=1234)"
	}
	_ = cfg
	return res, nil
}

// buildIAm constructs a full BVLC+NPDU+APDU I-Am frame.
//
// APDU (I-Am, service 0x00):
//
//	0x10 0x00  | uint context-tagged BACnetObjectIdentifier(device, instance)
//	           | uint Max APDU Length Accepted
//	           | enum Segmentation
//	           | uint Vendor ID
func buildIAm(instance uint32, maxAPDU uint16, segmentation byte, vendorID uint16) []byte {
	// Application-encoded BACnet primitives:
	// BACnetObjectIdentifier tag = application tag 12 (0xC4 indicates app
	// tag 12 with length 4).
	deviceID := (uint32(8) << 22) | (instance & 0x3FFFFF)
	objID := []byte{0xC4, byte(deviceID >> 24), byte(deviceID >> 16), byte(deviceID >> 8), byte(deviceID)}
	// Max APDU: unsigned int tag 2 length 2 (0x22) + 2 bytes.
	apdu := []byte{0x22, byte(maxAPDU >> 8), byte(maxAPDU)}
	// Segmentation: enum (tag 9) length 1.
	seg := []byte{0x91, segmentation}
	// Vendor ID: unsigned int (tag 2) length 2.
	vid := []byte{0x22, byte(vendorID >> 8), byte(vendorID)}

	apduBody := append([]byte{0x10, 0x00}, objID...)
	apduBody = append(apduBody, apdu...)
	apduBody = append(apduBody, seg...)
	apduBody = append(apduBody, vid...)

	// NPDU: version=1, control=0x00 (no addressing, expecting reply false).
	npdu := []byte{0x01, 0x00}
	body := append(npdu, apduBody...)

	// BVLC: type=0x81, function=0x0B (Original-Broadcast-NPDU) so listeners
	// expecting the broadcast shape still parse us, length = total.
	total := 4 + len(body)
	frame := make([]byte, 4, total)
	frame[0] = 0x81
	frame[1] = 0x0B
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	frame = append(frame, body...)
	return frame
}

// buildSimpleACK builds a BVLC+NPDU+SimpleACK frame for a confirmed
// service (APDU type 2). Used to acknowledge a WriteProperty so a
// scanner's write appears to succeed against the decoy point.
func buildSimpleACK(invokeID, service byte) []byte {
	apdu := []byte{0x20, invokeID, service} // type 2 (SimpleACK), invoke-id, service-choice
	body := append([]byte{0x01, 0x00}, apdu...)
	total := 4 + len(body)
	frame := make([]byte, 4, total)
	frame[0] = 0x81
	frame[1] = 0x0A // Original-Unicast-NPDU
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	return append(frame, body...)
}

// bacnetConfirmedName maps a confirmed-service choice to its name.
func bacnetConfirmedName(s byte) string {
	switch s {
	case 0x0C:
		return "ReadProperty"
	case 0x0E:
		return "ReadPropertyMultiple"
	case 0x0F:
		return "WriteProperty"
	case 0x10:
		return "WritePropertyMultiple"
	}
	return "confirmed-" + itoa(int(s))
}

func bvlcFuncName(f byte) string {
	switch f {
	case 0x00:
		return "BVLC-Result"
	case 0x0A:
		return "Original-Unicast-NPDU"
	case 0x0B:
		return "Original-Broadcast-NPDU"
	case 0x09:
		return "Distribute-Broadcast-To-Network"
	}
	return ""
}

func bacnetServiceName(s byte) string {
	switch s {
	case 0x00:
		return "I-Am"
	case 0x01:
		return "I-Have"
	case 0x08:
		return "Who-Is"
	case 0x07:
		return "Who-Has"
	}
	return ""
}

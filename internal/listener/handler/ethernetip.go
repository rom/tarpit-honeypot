package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type ethernetip struct {
	id *identity.Identity
}

func (e *ethernetip) Name() string { return "ethernetip" }

// EtherNet/IP (Rockwell / Allen-Bradley, port 44818). Encapsulation header
// is 24 bytes:
//
//	command(2) | length(2) | session_handle(4) | status(4) |
//	sender_context(8) | options(4)
//
// Followed by command-specific data. The two commands a scanner cares
// about are RegisterSession (0x0065) and ListIdentity (0x0063). We answer
// both — RegisterSession returns a synthetic session handle, ListIdentity
// returns one identity entry advertising a fake Rockwell ControlLogix
// device which is what Shodan-style scanners use to classify the host.
func (e *ethernetip) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}

	// One symbolic-tag overlay shared across the connection's encapsulation
	// frames (RegisterSession → SendRRData reads/writes → UnRegisterSession all
	// ride one TCP session), so a tag written earlier reads back later.
	tags := newCIPTags()
	const maxFrames = 32

	for f := 0; f < maxFrames; f++ {
		withTimeout(conn, cfg.ReadTimeout)
		hdr := make([]byte, 24)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if f == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		cmd := binary.LittleEndian.Uint16(hdr[0:2])
		dataLen := binary.LittleEndian.Uint16(hdr[2:4])
		session := binary.LittleEndian.Uint32(hdr[4:8])
		senderCtx := append([]byte(nil), hdr[12:20]...)

		res.Meta["command"] = commandName(cmd)
		res.Meta["command_code"] = cmd
		res.Meta["data_length"] = dataLen
		res.Meta["session_handle"] = session

		var body []byte
		if dataLen > 0 && dataLen <= 1024 {
			body = make([]byte, dataLen)
			if _, err := io.ReadFull(conn, body); err != nil {
				res.Meta["read_err"] = err.Error()
				break
			}
		}
		res.Payload = append(res.Payload, hdr...)
		res.Payload = append(res.Payload, body...)

		// Build response.
		switch cmd {
		case 0x0065: // RegisterSession
			// echo body (protocol_version(2) + options_flags(2)) + assign session
			out := make([]byte, 24+4)
			binary.LittleEndian.PutUint16(out[0:2], 0x0065)
			binary.LittleEndian.PutUint16(out[2:4], 4)
			binary.LittleEndian.PutUint32(out[4:8], 0xdeadbeef) // session handle we'll honor
			// status = 0, reserved zeros, sender context echoed
			copy(out[12:20], senderCtx)
			// body: protocol version + options
			binary.LittleEndian.PutUint16(out[24:26], 1)
			binary.LittleEndian.PutUint16(out[26:28], 0)
			if _, err := conn.Write(out); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			setIfEmpty(res.Meta, "intent", "EtherNet/IP RegisterSession — opening a CIP session to the controller")
			res.BannerSent = "ethernetip RegisterSession reply"

		case 0x006F, 0x0070: // SendRRData / SendUnitData — carries the CIP request
			e.serviceCIP(conn, cmd, body, senderCtx, session, tags, &res)

		case 0x0066: // UnRegisterSession — the client closes the CIP session.
			setIfEmpty(res.Meta, "intent", "EtherNet/IP UnRegisterSession — closing the CIP session")
			return res, nil

		case 0x0063: // ListIdentity
			// Build identity item.
			// item_count(2) + item_type(2)=0x000C + item_length(2) + identity data
			productName := []byte("1756-L73/B LOGIX5573")
			identity := make([]byte, 0, 64)
			identity = binary.LittleEndian.AppendUint16(identity, 1) // protocol version
			identity = append(identity, make([]byte, 16)...)         // socket_address (16 bytes, zero)
			// Real devices put sa_family + port + addr here; zeros are fine.
			identity = binary.LittleEndian.AppendUint16(identity, 0x0001) // vendor id (Rockwell)
			identity = binary.LittleEndian.AppendUint16(identity, 0x000E) // device type
			identity = binary.LittleEndian.AppendUint16(identity, 0x0036) // product code
			identity = append(identity, 0x14, 0x0B)                       // revision (major/minor)
			identity = binary.LittleEndian.AppendUint16(identity, 0x0040) // status
			var serial uint32 = 0xdeadbeef
			if e.id != nil {
				serial = e.id.SerialNumber()
			}
			identity = binary.LittleEndian.AppendUint32(identity, serial) // serial (per-deployment)
			identity = append(identity, byte(len(productName)))           // product name length
			identity = append(identity, productName...)
			identity = append(identity, 0xFF) // state

			respBody := make([]byte, 0, 8+len(identity))
			respBody = binary.LittleEndian.AppendUint16(respBody, 1)      // item count
			respBody = binary.LittleEndian.AppendUint16(respBody, 0x000C) // item type CIP_ITEM_LISTIDENTITY_RESPONSE
			respBody = binary.LittleEndian.AppendUint16(respBody, uint16(len(identity)))
			respBody = append(respBody, identity...)

			out := make([]byte, 24+len(respBody))
			binary.LittleEndian.PutUint16(out[0:2], 0x0063)
			binary.LittleEndian.PutUint16(out[2:4], uint16(len(respBody)))
			copy(out[12:20], senderCtx)
			copy(out[24:], respBody)
			if _, err := conn.Write(out); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			setIfEmpty(res.Meta, "intent", "EtherNet/IP ListIdentity — fingerprinting the Rockwell/CIP device")
			res.BannerSent = "ethernetip ListIdentity reply (1756-L73)"

		default:
			// Unsupported command — return status 0x0001 (invalid/unsupported).
			out := make([]byte, 24)
			binary.LittleEndian.PutUint16(out[0:2], cmd)
			binary.LittleEndian.PutUint32(out[8:12], 0x0001)
			copy(out[12:20], senderCtx)
			if _, err := conn.Write(out); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			res.BannerSent = "ethernetip unsupported-command reply"
		}
	}
	return res, nil
}

// serviceCIP parses the CIP request carried in a SendRRData / SendUnitData
// command, classifies the CIP service (tag reads = recon, writes =
// manipulation, Reset/Stop = device restart, Forward_Open = controller
// session), and answers with a believable CIP success response.
func (e *ethernetip) serviceCIP(conn net.Conn, cmd uint16, body, senderCtx []byte, session uint32, tags *cipTags, res *Result) {
	setIfEmpty(res.Meta, "intent", "EtherNet/IP CIP request — interacting with the controller")
	cip := locateCIP(body)
	if len(cip) < 1 {
		e.writeEncap(conn, cmd, session, senderCtx, nil, res)
		res.BannerSent = "ethernetip SendRRData reply"
		return
	}
	service := cip[0] & 0x7F
	res.Meta["cip_service"] = cipServiceName(service)
	switch service {
	case 0x01, 0x03, 0x0E, 0x4C, 0x52: // Get_Attribute(s) / Read Tag — recon/collection
		flagAnomaly(res, "ics-process-data-access")
		res.Meta["intent"] = "EtherNet/IP CIP " + cipServiceName(service) + " — reading controller tags/attributes"
	case 0x02, 0x04, 0x10, 0x4D, 0x53: // Set_Attribute(s) / Write Tag — manipulation
		flagAnomaly(res, "ics-plc-write")
		res.Meta["intent"] = "EtherNet/IP CIP " + cipServiceName(service) + " — writing controller tags/attributes (control manipulation)"
	case 0x05, 0x07: // Reset / Stop — device restart / halt
		flagAnomaly(res, "ics-device-restart")
		res.Meta["intent"] = "EtherNet/IP CIP " + cipServiceName(service) + " — resetting/stopping the controller"
	case 0x06: // Start — RUN-mode change
		flagAnomaly(res, "ics-plc-mode-change")
		res.Meta["intent"] = "EtherNet/IP CIP Start — switching the controller to RUN"
	case 0x54, 0x5B, 0x4E: // Forward_Open / Large_Forward_Open / Forward_Close
		flagAnomaly(res, "ics-field-device-probe")
		res.Meta["intent"] = "EtherNet/IP CIP " + cipServiceName(service) + " — establishing a CIP connection to the controller"
	}

	// CIP reply. Tag services (Read_Tag / Write_Tag, fragmented variants) go
	// through the per-session tag overlay so a written tag reads back; other
	// services get a success reply (with a synthetic value for the logical-path
	// Get_Attribute_Single read).
	cipResp := cipTagResponse(service, cip, tags, res)
	e.writeEncap(conn, cmd, session, senderCtx, cipResp, res)
	res.BannerSent = "ethernetip CIP reply (" + cipServiceName(service) + ")"
}

// writeEncap sends a SendRRData/SendUnitData encapsulation reply wrapping the
// given CIP response bytes in the Common Packet Format.
func (e *ethernetip) writeEncap(conn net.Conn, cmd uint16, session uint32, senderCtx, cipResp []byte, res *Result) {
	var data []byte
	data = binary.LittleEndian.AppendUint32(data, 0) // interface handle
	data = binary.LittleEndian.AppendUint16(data, 0) // timeout
	data = binary.LittleEndian.AppendUint16(data, 2) // CPF item count
	data = binary.LittleEndian.AppendUint16(data, 0x0000)
	data = binary.LittleEndian.AppendUint16(data, 0) // null address item len
	data = binary.LittleEndian.AppendUint16(data, 0x00B2)
	data = binary.LittleEndian.AppendUint16(data, uint16(len(cipResp)))
	data = append(data, cipResp...)

	out := make([]byte, 24+len(data))
	binary.LittleEndian.PutUint16(out[0:2], cmd)
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(data)))
	binary.LittleEndian.PutUint32(out[4:8], session)
	copy(out[12:20], senderCtx)
	copy(out[24:], data)
	if _, err := conn.Write(out); err != nil {
		res.Meta["write_err"] = err.Error()
	}
}

// locateCIP walks the SendRRData/SendUnitData CPF and returns the embedded CIP
// message-router request bytes (service + path + data).
func locateCIP(body []byte) []byte {
	if len(body) < 8 {
		return nil
	}
	p := 6 // skip interface handle(4) + timeout(2)
	if p+2 > len(body) {
		return nil
	}
	itemCount := int(binary.LittleEndian.Uint16(body[p : p+2]))
	p += 2
	for n := 0; n < itemCount && p+4 <= len(body); n++ {
		typ := binary.LittleEndian.Uint16(body[p : p+2])
		ln := int(binary.LittleEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+ln > len(body) {
			return nil
		}
		data := body[p : p+ln]
		switch typ {
		case 0x00B2: // unconnected data item — CIP MR directly
			return data
		case 0x00B1: // connected data item — 2-byte seq count then CIP MR
			if len(data) >= 2 {
				return data[2:]
			}
		}
		p += ln
	}
	return nil
}

func cipServiceName(s byte) string {
	switch s {
	case 0x01:
		return "Get_Attributes_All"
	case 0x02:
		return "Set_Attributes_All"
	case 0x03:
		return "Get_Attribute_List"
	case 0x04:
		return "Set_Attribute_List"
	case 0x05:
		return "Reset"
	case 0x06:
		return "Start"
	case 0x07:
		return "Stop"
	case 0x0A:
		return "Multiple_Service_Packet"
	case 0x0E:
		return "Get_Attribute_Single"
	case 0x10:
		return "Set_Attribute_Single"
	case 0x4C:
		return "Read_Tag"
	case 0x4D:
		return "Write_Tag"
	case 0x4E:
		return "Forward_Close"
	case 0x52:
		return "Read_Tag_Fragmented"
	case 0x53:
		return "Write_Tag_Fragmented"
	case 0x54:
		return "Forward_Open"
	case 0x5B:
		return "Large_Forward_Open"
	}
	return "service-0x" + itoa(int(s))
}

func commandName(c uint16) string {
	switch c {
	case 0x0001:
		return "NOP"
	case 0x0004:
		return "ListServices"
	case 0x0063:
		return "ListIdentity"
	case 0x0064:
		return "ListInterfaces"
	case 0x0065:
		return "RegisterSession"
	case 0x0066:
		return "UnRegisterSession"
	case 0x006F:
		return "SendRRData"
	case 0x0070:
		return "SendUnitData"
	}
	return ""
}

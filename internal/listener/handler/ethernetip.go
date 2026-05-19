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
//   command(2) | length(2) | session_handle(4) | status(4) |
//   sender_context(8) | options(4)
//
// Followed by command-specific data. The two commands a scanner cares
// about are RegisterSession (0x0065) and ListIdentity (0x0063). We answer
// both — RegisterSession returns a synthetic session handle, ListIdentity
// returns one identity entry advertising a fake Rockwell ControlLogix
// device which is what Shodan-style scanners use to classify the host.
func (e *ethernetip) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	hdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	cmd := binary.LittleEndian.Uint16(hdr[0:2])
	dataLen := binary.LittleEndian.Uint16(hdr[2:4])
	session := binary.LittleEndian.Uint32(hdr[4:8])
	senderCtx := append([]byte(nil), hdr[12:20]...)

	res.Meta = map[string]any{
		"command":        commandName(cmd),
		"command_code":   cmd,
		"data_length":    dataLen,
		"session_handle": session,
	}

	var body []byte
	if dataLen > 0 && dataLen <= 1024 {
		body = make([]byte, dataLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			res.Meta["read_err"] = err.Error()
			return res, nil
		}
	}
	res.Payload = append(hdr, body...)

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
		res.BannerSent = "ethernetip RegisterSession reply"

	case 0x0063: // ListIdentity
		// Build identity item.
		// item_count(2) + item_type(2)=0x000C + item_length(2) + identity data
		productName := []byte("1756-L73/B LOGIX5573")
		identity := make([]byte, 0, 64)
		identity = binary.LittleEndian.AppendUint16(identity, 1)      // protocol version
		identity = append(identity, make([]byte, 16)...)              // socket_address (16 bytes, zero)
		// Real devices put sa_family + port + addr here; zeros are fine.
		identity = binary.LittleEndian.AppendUint16(identity, 0x0001) // vendor id (Rockwell)
		identity = binary.LittleEndian.AppendUint16(identity, 0x000E) // device type
		identity = binary.LittleEndian.AppendUint16(identity, 0x0036) // product code
		identity = append(identity, 0x14, 0x0B)                         // revision (major/minor)
		identity = binary.LittleEndian.AppendUint16(identity, 0x0040) // status
		var serial uint32 = 0xdeadbeef
		if e.id != nil {
			serial = e.id.SerialNumber()
		}
		identity = binary.LittleEndian.AppendUint32(identity, serial) // serial (per-deployment)
		identity = append(identity, byte(len(productName)))             // product name length
		identity = append(identity, productName...)
		identity = append(identity, 0xFF)                               // state

		respBody := make([]byte, 0, 8+len(identity))
		respBody = binary.LittleEndian.AppendUint16(respBody, 1)                    // item count
		respBody = binary.LittleEndian.AppendUint16(respBody, 0x000C)               // item type CIP_ITEM_LISTIDENTITY_RESPONSE
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
	return res, nil
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

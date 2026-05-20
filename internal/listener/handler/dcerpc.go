package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type dcerpc struct {
	hosts []HoneynetHost
}

func (d *dcerpc) Name() string { return "dcerpc" }

// SetHoneynetView installs the honeynet topology so the handler can
// advertise virtual endpoint entries in the event meta.
func (d *dcerpc) SetHoneynetView(v HoneynetSnapshot) { d.hosts = v.Hosts }

// DCE/RPC over TCP (port 135). The very first PDU from any client is a
// "bind" (PDU type 0x0B). PDU layout:
//
//	rpc_vers(1)=5   rpc_vers_minor(1)   ptype(1)   pfc_flags(1)
//	packed_drep(4)  frag_length(2)      auth_length(2)  call_id(4)
//	max_xmit(2)     max_recv(2)         assoc_group(4)
//	p_context_elem(1) ... rest is context list with abstract+transfer UUIDs
//
// We parse just the header + first abstract UUID (the interface the
// scanner cares about) and reply with a bind_ack that grants context 0.
func (d *dcerpc) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if hdr[0] != 5 {
		res.Meta = map[string]any{"non_dcerpc_version": hdr[0]}
		return res, nil
	}
	ptype := hdr[2]
	fragLen := binary.LittleEndian.Uint16(hdr[8:10])
	callID := binary.LittleEndian.Uint32(hdr[12:16])

	bodyLen := int(fragLen) - 16
	if bodyLen < 0 || bodyLen > 4096 {
		res.Meta = map[string]any{"bad_frag_len": fragLen}
		return res, nil
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(hdr, body...)

	res.Meta = map[string]any{
		"ptype":   pTypeName(ptype),
		"call_id": callID,
	}

	if ptype == 0x0B && len(body) >= 8 {
		// Skip past max_xmit/max_recv/assoc_group/n_context_elem/reserved/reserved2 = 12 bytes
		// into the context list. Layout from offset 8: ctx_id(2) n_xfer(1) reserved(1) abstract_uuid(16) abstract_ver(4)
		ctxStart := 8 // body offsets after hdr
		if len(body) >= ctxStart+24 {
			uuid := body[ctxStart+4 : ctxStart+20]
			res.Meta["bind_abstract_uuid"] = uuidString(uuid)
		}
	}

	// Build bind_ack (ptype=0x0C). Minimal but valid: echo call_id, advertise
	// 1 context result = accept, no negotiated transfer syntax dance.
	resp := make([]byte, 0, 64)
	resp = append(resp, 5, 0, 0x0C, 0x03)             // ver, ver_minor, ptype=bind_ack, flags=first|last
	resp = append(resp, 0x10, 0, 0, 0)                // drep little-endian
	resp = binary.LittleEndian.AppendUint16(resp, 60) // frag_length (will fix below)
	resp = binary.LittleEndian.AppendUint16(resp, 0)  // auth_length
	resp = binary.LittleEndian.AppendUint32(resp, callID)
	// bind_ack body
	resp = binary.LittleEndian.AppendUint16(resp, 4280) // max_xmit
	resp = binary.LittleEndian.AppendUint16(resp, 4280) // max_recv
	resp = binary.LittleEndian.AppendUint32(resp, 0)    // assoc_group
	resp = binary.LittleEndian.AppendUint16(resp, 13)   // sec addr length
	resp = append(resp, []byte("\\PIPE\\lsass\x00")...) // sec addr
	resp = append(resp, 0)                              // pad to 4-byte align
	resp = append(resp, 1, 0, 0, 0)                     // n_results = 1
	resp = binary.LittleEndian.AppendUint16(resp, 0)    // result = acceptance
	resp = binary.LittleEndian.AppendUint16(resp, 0)    // reason = 0
	// transfer syntax: NDR (8a885d04-...)
	resp = append(resp, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60)
	resp = binary.LittleEndian.AppendUint32(resp, 2) // version
	// Fix frag_length now that we know the actual size.
	binary.LittleEndian.PutUint16(resp[8:10], uint16(len(resp)))

	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "dcerpc bind_ack"
	// Advertise the honeynet's virtual endpoints if any. Real EPM
	// implementations return them via Lookup RPCs; we surface them in
	// meta so the operator's pipeline at least sees what topology was
	// available at lookup time.
	if len(d.hosts) > 0 {
		endpoints := make([]map[string]any, 0, len(d.hosts))
		for _, h := range d.hosts {
			for _, sv := range h.Services {
				endpoints = append(endpoints, map[string]any{
					"hostname": h.Hostname, "ip": h.IP,
					"port": sv.Port, "service": sv.Handler,
				})
			}
		}
		res.Meta["honeynet_endpoints"] = endpoints
	}
	return res, nil
}

func pTypeName(p byte) string {
	switch p {
	case 0x0B:
		return "bind"
	case 0x0C:
		return "bind_ack"
	case 0x0D:
		return "bind_nak"
	case 0x0E:
		return "alter_context"
	case 0x00:
		return "request"
	case 0x02:
		return "response"
	}
	return ""
}

// uuidString formats a 16-byte UUID in canonical 8-4-4-4-12 hex.
func uuidString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	// DCE/RPC ships UUIDs in mixed-endian: first 3 fields little-endian,
	// last 8 bytes big-endian. Rewrite into canonical.
	out := make([]byte, 36)
	hex := "0123456789abcdef"
	o := 0
	w := func(start, n int, dashAfter bool) {
		for i := 0; i < n; i++ {
			v := b[start+i]
			out[o] = hex[v>>4]
			out[o+1] = hex[v&0x0F]
			o += 2
		}
		if dashAfter {
			out[o] = '-'
			o++
		}
	}
	// uint32 little endian
	w(3, 1, false)
	w(2, 1, false)
	w(1, 1, false)
	w(0, 1, true)
	w(5, 1, false)
	w(4, 1, true)
	w(7, 1, false)
	w(6, 1, true)
	w(8, 2, true)
	w(10, 6, false)
	return string(out)
}

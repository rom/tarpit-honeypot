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

	var boundUUID string
	if ptype == 0x0B && len(body) >= 8 {
		// Skip past max_xmit/max_recv/assoc_group/n_context_elem/reserved/reserved2 = 12 bytes
		// into the context list. Layout from offset 8: ctx_id(2) n_xfer(1) reserved(1) abstract_uuid(16) abstract_ver(4)
		ctxStart := 8 // body offsets after hdr
		if len(body) >= ctxStart+24 {
			u := uuidString(body[ctxStart+4 : ctxStart+20])
			boundUUID = u
			res.Meta["bind_abstract_uuid"] = u
			if name := dcerpcInterfaceName(u); name != "" {
				res.Meta["dcerpc_interface"] = name
				// Binding a sensitive MSRPC interface on a honeypot is a
				// high-signal AD-enumeration / lateral-movement tell.
				if marker := dcerpcAbuse(name); marker != "" {
					flagAnomaly(&res, marker)
				}
			}
			// OPC-DA (classic, DCOM): a bind to OPCEnum / IOPCServer(List)
			// is OPC discovery. Flag it + advertise believable OPC-DA
			// servers so the scanner records a live OPC host.
			if isOPCInterface(u) {
				flagAnomaly(&res, "ics-opc-da-probe")
				res.Meta["opc_servers"] = opcServerProgIDs
			}
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

	// OPC-DA call layer: once an OPC interface is bound, service the
	// subsequent Request PDUs — decode the item IDs / group names the
	// attacker reaches for and marshal believable NDR responses
	// (OPCSERVERSTATUS, AddGroup, …). Capture-only; see dcerpc_opc.go.
	if isOPCInterface(boundUUID) {
		handleDCERPCRequests(conn, boundUUID, cfg.ReadTimeout, &res)
	}
	// The endpoint mapper advertises the interfaces registered on this
	// host. Always surface the well-known set — including OPCEnum, the
	// OPC-DA (classic, DCOM) discovery interface — so a scanner walking
	// EPM records an OPC-DA server present.
	res.Meta["epm_interfaces"] = epmInterfaces()
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

// dcerpcInterfaces maps canonical interface UUIDs to a human name. Covers
// the OPC-DA (classic / DCOM) interface family plus the common Windows
// MSRPC interfaces a scanner enumerates over port 135.
var dcerpcInterfaces = map[string]string{
	// OPC-DA (classic, DCOM).
	"13486d44-4821-11d2-a494-3cb306c10000": "OPCEnum",
	"13486d50-4821-11d2-a494-3cb306c10000": "IOPCServerList",
	"9dd0b56c-ad9e-43ee-8305-487f3188bf7a": "IOPCServerList2",
	"39c13a4d-011e-11d0-9675-0020afd8adb3": "IOPCServer",
	"39c13a4f-011e-11d0-9675-0020afd8adb3": "IOPCBrowse",
	"39c13a50-011e-11d0-9675-0020afd8adb3": "IOPCItemMgt",
	"39c13a52-011e-11d0-9675-0020afd8adb3": "IOPCSyncIO",
	// DCOM core (activation / object resolution).
	"e1af8308-5d1f-11c9-91a4-08002b14a0fa": "epmapper",
	"99fcfec4-5260-101b-bbcb-00aa0021347a": "IOXIDResolver",
	"000001a0-0000-0000-c000-000000000046": "ISystemActivator",
	// Common Windows MSRPC named interfaces.
	"367abb81-9844-35f1-ad32-98f038001003": "svcctl",
	"12345778-1234-abcd-ef00-0123456789ac": "samr",
	"12345778-1234-abcd-ef00-0123456789ab": "lsarpc",
	"4b324fc8-1670-01d3-1278-5a47bf6ee188": "srvsvc",
	"338cd001-2244-31f1-aaaa-900038001003": "winreg",
	"e3514235-4b06-11d1-ab04-00c04fc2dcd2": "drsuapi", // AD replication → DCSync
	"12345678-1234-abcd-ef00-01234567cffb": "netlogon",
	"8a885d04-1ceb-11c9-9fe8-08002b104860": "ndr",
}

// dcerpcAbuse maps a sensitive MSRPC interface to an anomaly marker. Binding
// these on a honeypot is reconnaissance or lateral movement: SAMR/LSARPC
// (account + SID enumeration, BloodHound), srvsvc (share enumeration),
// svcctl (remote service create = PsExec), winreg (SAM/LSA hive read),
// drsuapi (DCSync), netlogon (ZeroLogon / NetrServerPasswordSet abuse).
func dcerpcAbuse(iface string) string {
	switch iface {
	case "samr":
		return "dcerpc-samr-enum"
	case "lsarpc":
		return "dcerpc-lsarpc-enum"
	case "srvsvc":
		return "dcerpc-srvsvc-enum"
	case "svcctl":
		return "dcerpc-svcctl-access"
	case "winreg":
		return "dcerpc-winreg-access"
	case "drsuapi":
		return "dcerpc-dcsync"
	case "netlogon":
		return "dcerpc-netlogon-access"
	}
	return ""
}

// opcInterfaces is the subset of dcerpcInterfaces that means "OPC-DA".
var opcInterfaces = map[string]bool{
	"13486d44-4821-11d2-a494-3cb306c10000": true, // OPCEnum
	"13486d50-4821-11d2-a494-3cb306c10000": true, // IOPCServerList
	"9dd0b56c-ad9e-43ee-8305-487f3188bf7a": true, // IOPCServerList2
	"39c13a4d-011e-11d0-9675-0020afd8adb3": true, // IOPCServer
	"39c13a4f-011e-11d0-9675-0020afd8adb3": true, // IOPCBrowse
	"39c13a50-011e-11d0-9675-0020afd8adb3": true, // IOPCItemMgt
	"39c13a52-011e-11d0-9675-0020afd8adb3": true, // IOPCSyncIO
}

// opcServerProgIDs are believable OPC-DA server ProgIDs an OPCEnum
// enumeration would return (decoration so the deception is richer).
var opcServerProgIDs = []string{
	"Matrikon.OPC.Simulation.1",
	"OPC.SimaticNET",
	"RSLinx OPC Server",
	"Kepware.KEPServerEX.V6",
}

// epmInterfaces returns the well-known interface set the endpoint mapper
// reports, including OPCEnum so OPC-DA is discoverable over 135. It builds
// fresh maps on every call: the result lands in res.Meta, which the
// listener sanitizes in place (safe.SanitizeMetaStrings), and connections
// are handled concurrently — a shared []map[string]any would be mutated by
// multiple goroutines at once and crash with "concurrent map writes".
func epmInterfaces() []map[string]any {
	return []map[string]any{
		{"name": "OPCEnum", "uuid": "13486d44-4821-11d2-a494-3cb306c10000", "port": 135},
		{"name": "IOPCServerList", "uuid": "13486d50-4821-11d2-a494-3cb306c10000", "port": 49152},
		{"name": "epmapper", "uuid": "e1af8308-5d1f-11c9-91a4-08002b14a0fa", "port": 135},
	}
}

func dcerpcInterfaceName(uuid string) string { return dcerpcInterfaces[uuid] }

func isOPCInterface(uuid string) bool { return opcInterfaces[uuid] }

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

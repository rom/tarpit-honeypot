package handler

import (
	"encoding/binary"
	"io"
	"net"
	"time"
	"unicode/utf16"
)

// OPC-DA (classic, DCOM) call layer. After the bind_ack, a client that bound
// an OPC interface issues DCE/RPC Request PDUs (ptype 0x00) carrying ORPCTHIS
// + NDR-marshaled arguments. This file reads those requests, decodes the
// interesting arguments (the OPC item IDs / group names an attacker wants to
// read or write — high-value ICS intel), and marshals believable NDR
// responses: a full OPCSERVERSTATUS for GetStatus, and structurally-valid
// stubs for the common AddGroup / AddItems / Read / Write calls so a client
// progresses past the bind.
//
// Scope note: this services calls made *directly* against the bound interface.
// Full DCOM activation (IOXIDResolver / ISystemActivator OXID resolution that
// hands a real interface pointer) is not completed, so an end-to-end OPC-DA
// client that insists on activation first won't reach these calls — but
// scanners and tools that bind the interface directly will, and every call is
// captured either way. See docs/design.md §15.

// DCE/RPC PDU types used here.
const (
	dcerpcRequest  = 0x00
	dcerpcResponse = 0x02
	dcerpcFault    = 0x03
	pfcFirstLast   = 0x03
	pfcObjectUUID  = 0x80
)

// opcMaxRequests bounds how many post-bind requests we service on one
// connection so a client can't pin a goroutine indefinitely.
const opcMaxRequests = 16

// opcOpNames maps (interface uuid, opnum) to a method name. Opnums 0-2 are the
// IUnknown slots (QueryInterface/AddRef/Release) present on every DCOM vtable;
// interface methods start at 3.
var opcOpNames = map[string]map[uint16]string{
	// IOPCServer
	"39c13a4d-011e-11d0-9675-0020afd8adb3": {
		3: "AddGroup", 4: "GetErrorString", 5: "GetGroupByName",
		6: "GetStatus", 7: "RemoveGroup", 8: "CreateGroupEnumerator",
	},
	// IOPCItemMgt
	"39c13a50-011e-11d0-9675-0020afd8adb3": {
		3: "AddItems", 4: "ValidateItems", 5: "RemoveItems",
		6: "SetActiveState", 7: "SetClientHandles", 8: "SetDatatypes",
		9: "CreateEnumerator",
	},
	// IOPCSyncIO
	"39c13a52-011e-11d0-9675-0020afd8adb3": {
		3: "Read", 4: "Write",
	},
	// IOPCBrowse / IOPCBrowseServerAddressSpace
	"39c13a4f-011e-11d0-9675-0020afd8adb3": {
		3: "QueryOrganization", 4: "ChangeBrowsePosition", 5: "BrowseOPCItemIDs",
		6: "GetItemID", 7: "BrowseAccessPaths",
	},
}

// opcCallName returns the method name for an interface UUID + opnum, or "".
func opcCallName(uuid string, opnum uint16) string {
	if m := opcOpNames[uuid]; m != nil {
		return m[opnum]
	}
	return ""
}

// handleDCERPCRequests services post-bind Request PDUs on conn. boundUUID is
// the interface granted at bind time. It records each call (opnum, method,
// decoded argument strings) into res.Meta["dcerpc_calls"] and replies with an
// NDR response or fault. Bounded by opcMaxRequests and the read timeout.
func handleDCERPCRequests(conn net.Conn, boundUUID, opcVendor string, readTimeout time.Duration, res *Result) {
	var calls []map[string]any
	var itemStrings []string
	for n := 0; n < opcMaxRequests; n++ {
		if readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		}
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			break
		}
		if hdr[0] != 5 {
			break
		}
		ptype := hdr[2]
		flags := hdr[3]
		fragLen := binary.LittleEndian.Uint16(hdr[8:10])
		callID := binary.LittleEndian.Uint32(hdr[12:16])
		bodyLen := int(fragLen) - 16
		if bodyLen < 0 || bodyLen > 65535 {
			break
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			break
		}
		if ptype != dcerpcRequest || len(body) < 8 {
			// Not a request (e.g. a co_cancel / orphaned) — stop servicing.
			break
		}
		// Request header: alloc_hint(4) p_cont_id(2) opnum(2) [object uuid(16)].
		contID := binary.LittleEndian.Uint16(body[4:6])
		opnum := binary.LittleEndian.Uint16(body[6:8])
		stub := body[8:]
		if flags&pfcObjectUUID != 0 && len(stub) >= 16 {
			stub = stub[16:] // skip the object UUID DCOM prepends
		}

		method := opcCallName(boundUUID, opnum)
		call := map[string]any{"opnum": opnum}
		if method != "" {
			call["method"] = method
		}
		// Decode the argument strings (item IDs / group names) from the stub.
		// They live after the ORPCTHIS header; a generic conformant-varying
		// wstring scavenge pulls them out without per-call layout knowledge.
		if args := scavengeWStrings(stub); len(args) > 0 {
			call["args"] = args
			itemStrings = appendUniqueAll(itemStrings, args)
		}
		calls = append(calls, call)

		// Reply with a believable NDR response.
		var resp []byte
		switch {
		case method == "GetStatus":
			resp = buildResponsePDU(callID, contID, opcServerStatusStub(opcVendor))
		case method == "AddGroup":
			resp = buildResponsePDU(callID, contID, opcAddGroupStub())
		case method == "Read" || method == "AddItems" || method == "ValidateItems":
			resp = buildResponsePDU(callID, contID, opcGenericOKStub())
		case method != "":
			resp = buildResponsePDU(callID, contID, opcGenericOKStub())
		default:
			// Unknown opnum on the bound interface: a DCE/RPC fault is the
			// honest, real-server reply (nca_s_op_rng_error).
			resp = buildFaultPDU(callID, contID, 0x1c010002)
		}
		if _, err := conn.Write(resp); err != nil {
			break
		}
	}
	if len(calls) > 0 {
		res.Meta["dcerpc_calls"] = calls
		flagAnomaly(res, "ics-opc-da-call")
	}
	if len(itemStrings) > 0 {
		res.Meta["opc_strings"] = itemStrings
		flagAnomaly(res, "ics-opc-da-item-access")
	}
}

// scavengeWStrings pulls conformant+varying UTF-16LE NDR strings out of a stub
// without needing the exact per-call argument layout. It walks 4-byte-aligned
// offsets looking for the [max_count][offset=0][actual_count][UTF-16LE...]
// shape and collects the printable results — the OPC item IDs and group names
// an attacker is reaching for.
func scavengeWStrings(stub []byte) []string {
	var out []string
	for off := 0; off+12 <= len(stub); off += 4 {
		maxCount := binary.LittleEndian.Uint32(stub[off:])
		offset := binary.LittleEndian.Uint32(stub[off+4:])
		actual := binary.LittleEndian.Uint32(stub[off+8:])
		if offset != 0 || actual == 0 || actual > maxCount || actual > 1024 {
			continue
		}
		need := off + 12 + int(actual)*2
		if need > len(stub) {
			continue
		}
		units := make([]uint16, 0, actual)
		for i := 0; i < int(actual); i++ {
			units = append(units, binary.LittleEndian.Uint16(stub[off+12+i*2:]))
		}
		for len(units) > 0 && units[len(units)-1] == 0 {
			units = units[:len(units)-1]
		}
		s := string(utf16.Decode(units))
		if isPrintableOPCID(s) && len(s) >= 2 {
			out = appendUnique(out, s)
			if len(out) >= 32 {
				break
			}
		}
	}
	return out
}

// isPrintableOPCID reports whether s looks like a real OPC item ID / name
// (printable, no control characters). Filters scavenge false positives.
func isPrintableOPCID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// --- response / fault PDU builders -----------------------------------------

// buildResponsePDU wraps NDR stub data in a DCE/RPC Response PDU (ptype 0x02).
func buildResponsePDU(callID uint32, contID uint16, stub []byte) []byte {
	out := make([]byte, 0, 24+len(stub))
	out = append(out, 5, 0, dcerpcResponse, pfcFirstLast)
	out = append(out, 0x10, 0, 0, 0)               // drep little-endian
	out = binary.LittleEndian.AppendUint16(out, 0) // frag_length (fixed below)
	out = binary.LittleEndian.AppendUint16(out, 0) // auth_length
	out = binary.LittleEndian.AppendUint32(out, callID)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(stub))) // alloc_hint
	out = binary.LittleEndian.AppendUint16(out, contID)
	out = append(out, 0, 0) // cancel_count, reserved
	out = append(out, stub...)
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
	return out
}

// buildFaultPDU builds a DCE/RPC Fault PDU (ptype 0x03) with the given status.
func buildFaultPDU(callID uint32, contID uint16, status uint32) []byte {
	out := make([]byte, 0, 32)
	out = append(out, 5, 0, dcerpcFault, pfcFirstLast)
	out = append(out, 0x10, 0, 0, 0)
	out = binary.LittleEndian.AppendUint16(out, 0) // frag_length (fixed below)
	out = binary.LittleEndian.AppendUint16(out, 0) // auth_length
	out = binary.LittleEndian.AppendUint32(out, callID)
	out = binary.LittleEndian.AppendUint32(out, 0) // alloc_hint
	out = binary.LittleEndian.AppendUint16(out, contID)
	out = append(out, 0, 0) // cancel_count, reserved
	out = binary.LittleEndian.AppendUint32(out, status)
	out = binary.LittleEndian.AppendUint32(out, 0) // reserved2
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
	return out
}

// --- NDR-marshaled OPC out-params ------------------------------------------

// orpcThat writes the minimal ORPCTHAT header every DCOM response stub starts
// with: flags(4)=0 + a null extensions pointer(4).
func orpcThat(e *ndrEnc) {
	e.u32(0)
	e.nullPtr()
}

// opcServerStatusStub marshals an IOPCServer::GetStatus response: ORPCTHAT,
// a unique pointer to an OPCSERVERSTATUS (running, with vendor info), then the
// HRESULT (S_OK). The structure is the real OPC-DA layout so a decoder sees a
// live, running OPC server.
func opcServerStatusStub(vendor string) []byte {
	if vendor == "" {
		vendor = "Matrikon OPC Server for Simulation"
	}
	e := &ndrEnc{}
	orpcThat(e)
	e.uniquePtr(0x20000) // referent for ppServerStatus
	// OPCSERVERSTATUS. FILETIME is a struct of two DWORDs (NDR alignment 4,
	// not an 8-aligned hyper) — emit low/high u32 so the layout is byte-exact.
	now := filetimeNow()
	writeFiletime(e, filetimeAgo(now, 36*time.Hour))  // ftStartTime
	writeFiletime(e, now)                             // ftCurrentTime
	writeFiletime(e, filetimeAgo(now, 2*time.Second)) // ftLastUpdateTime
	e.u32(1)                                          // dwServerState = OPC_STATUS_RUNNING
	e.u32(3)                                          // dwGroupCount
	e.u32(0)                                          // dwBandWidth (0xFFFFFFFF = N/A; 0 ok)
	e.u16(2)                                          // wMajorVersion
	e.u16(5)                                          // wMinorVersion
	e.u16(1408)                                       // wBuildNumber
	e.u16(0)                                          // wReserved
	e.uniquePtr(0x20004)                              // referent for szVendorInfo
	e.wstr(vendor)
	e.u32(0) // HRESULT S_OK
	return e.buf
}

// opcAddGroupStub marshals an IOPCServer::AddGroup response: ORPCTHAT, a
// server group handle, the revised update rate, a null group interface
// pointer, and S_OK.
func opcAddGroupStub() []byte {
	e := &ndrEnc{}
	orpcThat(e)
	e.u32(0x1001) // phServerGroup
	e.u32(1000)   // pRevisedUpdateRate (ms)
	e.nullPtr()   // ppUnk (group interface pointer; null keeps it simple)
	e.u32(0)      // HRESULT S_OK
	return e.buf
}

// opcGenericOKStub marshals a minimal ORPCTHAT + S_OK response for calls whose
// full out-param layout we don't model — enough to look like a success.
func opcGenericOKStub() []byte {
	e := &ndrEnc{}
	orpcThat(e)
	e.u32(0) // HRESULT S_OK
	return e.buf
}

// writeFiletime emits a Windows FILETIME as two NDR DWORDs (low then high),
// matching the struct's 4-byte alignment.
func writeFiletime(e *ndrEnc, ft uint64) {
	e.u32(uint32(ft))
	e.u32(uint32(ft >> 32))
}

// filetimeNow returns the current time as a Windows FILETIME (100ns ticks
// since 1601-01-01).
func filetimeNow() uint64 { return unixToFiletime(time.Now()) }

func filetimeAgo(now uint64, d time.Duration) uint64 {
	ticks := uint64(d / 100) // 100ns ticks
	if ticks > now {
		return 0
	}
	return now - ticks
}

func unixToFiletime(t time.Time) uint64 {
	// 11644473600 seconds between 1601-01-01 and 1970-01-01.
	const epochDiff = 11644473600
	return uint64((t.Unix() + epochDiff)) * 10000000
}

// appendUniqueAll folds src into dst, de-duplicating.
func appendUniqueAll(dst, src []string) []string {
	for _, s := range src {
		dst = appendUnique(dst, s)
	}
	return dst
}

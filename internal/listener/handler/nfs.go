package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- NFS (2049) ----------------------------------------------------------
//
// NFSv4 folds mount/lock/portmap into a single stream on 2049, so a modern
// NFS attacker connects here directly and issues a COMPOUND of operations to
// walk the export tree (PUTROOTFH -> GETFH -> READDIR/LOOKUP) and read files;
// NFSv3 clients also reach 2049 for the data procedures after a portmap/mount
// lookup. The rpcbind (111) handler captures the *enumeration* that precedes a
// mount; this captures the mount/traversal/read attempt itself.
//
// We parse the record-marked RPC call, name the program/version/procedure (and,
// for COMPOUND, the operation list), capture the AUTH_UNIX uid/gid the client
// claims (a uid 0 is a no_root_squash bypass attempt), flag export enumeration
// and file-read attempts, and answer like a live-but-locked-down NFSv4 root:
// PUTROOTFH/PUTFH/GETFH succeed (the attacker gets a root filehandle and keeps
// probing) while any traversal/read returns NFS4ERR_ACCESS — no real data
// leaves, but the service looks real.
type nfs struct{}

func (h *nfs) Name() string { return "nfs" }

func (h *nfs) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 8192))
	res.Payload = got
	flagAnomaly(&res, "nfs-access")
	if len(got) < 28 {
		return res, nil
	}
	msg := got[4:] // skip the 4-byte record-marking header
	if binary.BigEndian.Uint32(msg[4:8]) != 0 {
		return res, nil // not an RPC CALL
	}
	xid := msg[0:4]
	prog := binary.BigEndian.Uint32(msg[12:16])
	vers := binary.BigEndian.Uint32(msg[16:20])
	proc := binary.BigEndian.Uint32(msg[20:24])
	res.Meta["rpc_program"] = prog
	res.Meta["rpc_program_name"] = rpcProgramName(prog)
	res.Meta["nfs_version"] = vers
	res.Meta["nfs_proc"] = nfsProcName(vers, proc)

	// AUTH_UNIX cred (flavor 1) carries the uid/gid/hostname the client claims.
	// A uid of 0 against a normally root-squashed export is the classic
	// no_root_squash privilege grab, worth flagging on its own.
	credFlavor := binary.BigEndian.Uint32(msg[24:28])
	res.Meta["rpc_auth"] = rpcAuthName(credFlavor)
	if credFlavor == 1 && len(msg) >= 32 {
		credLen := int(binary.BigEndian.Uint32(msg[28:32]))
		if credLen >= 20 && 32+credLen <= len(msg) {
			c := msg[32 : 32+credLen]
			mlen := int(binary.BigEndian.Uint32(c[4:8]))
			off := 8 + roundUp4(mlen)
			if mlen > 0 && 8+mlen <= len(c) {
				res.Meta["nfs_auth_machine"] = string(c[8 : 8+mlen])
			}
			if off+8 <= len(c) {
				uid := binary.BigEndian.Uint32(c[off : off+4])
				gid := binary.BigEndian.Uint32(c[off+4 : off+8])
				res.Meta["nfs_auth_uid"] = uid
				res.Meta["nfs_auth_gid"] = gid
				if uid == 0 {
					flagAnomaly(&res, "nfs-root-access")
					res.Meta["intent"] = "NFS access as uid 0 — no_root_squash privilege bypass"
				}
			}
		}
	}

	// MOUNT protocol (program 100005): showmount enumeration + mount attempts.
	// In single-listener honeypot deployments mountd is reached here on 2049, so
	// name the procedure correctly and flag the recon/mount intent — the generic
	// nfsProcName above would otherwise mislabel these as NFS data procs.
	if prog == 100005 {
		nfsHandleMount(conn, xid, proc, &res)
		return res, nil
	}

	switch {
	case proc == 0:
		res.Meta["intent"] = "NFS NULL ping — confirming the NFS service is live"
		nfsWriteAccepted(conn, xid, nil)
		res.BannerSent = "nfs NULL reply"
	case vers == 4 && proc == 1:
		nfsHandleCompound(conn, msg, xid, &res)
	default:
		// NFSv3 (or other) data procedure. Name the intent from the proc and
		// return a generic nfsstat3 "access denied" (NFS3ERR_ACCES = 13) with a
		// no-attrs-follow trailer — a plausible reply for the common procs.
		switch nfsProcName(vers, proc) {
		case "READ":
			flagAnomaly(&res, "nfs-file-read")
			setIfEmpty(res.Meta, "intent", "NFSv3 READ — reading file contents over NFS")
		case "LOOKUP", "READDIR", "READDIRPLUS":
			flagAnomaly(&res, "nfs-export-enum")
			setIfEmpty(res.Meta, "intent", "NFSv3 directory traversal — enumerating share contents")
		case "GETATTR", "FSINFO", "FSSTAT", "PATHCONF":
			setIfEmpty(res.Meta, "intent", "NFSv3 attribute probe — fingerprinting the export")
		default:
			setIfEmpty(res.Meta, "intent", "NFSv3 "+nfsProcName(vers, proc)+" on an exported share")
		}
		body := binary.BigEndian.AppendUint32(nil, 13) // NFS3ERR_ACCES
		body = binary.BigEndian.AppendUint32(body, 0)  // attributes-follow = false
		nfsWriteAccepted(conn, xid, body)
		res.BannerSent = "nfs accepted reply"
	}
	return res, nil
}

// nfsHandleMount answers the MOUNT protocol (program 100005). EXPORT/DUMP are
// the showmount enumeration (`showmount -e` / `-a`); MNT is a mount attempt. We
// flag the intent, overwrite the NFS-proc mislabel with the real mountd
// procedure, and reply believably — an empty export list and an access-denied
// mount — without ever exposing a share.
func nfsHandleMount(conn net.Conn, xid []byte, proc uint32, res *Result) {
	res.Meta["nfs_proc"] = "MOUNT/" + mountProcName(proc)
	switch proc {
	case 0: // NULL
		setIfEmpty(res.Meta, "intent", "MOUNT NULL ping — confirming mountd is live")
		nfsWriteAccepted(conn, xid, nil)
	case 5, 2, 6: // EXPORT / DUMP / EXPORTALL
		flagAnomaly(res, "nfs-showmount-enum")
		res.Meta["intent"] = "showmount export enumeration (MOUNT " + mountProcName(proc) + ") — listing NFS shares before mounting"
		nfsWriteAccepted(conn, xid, []byte{0, 0, 0, 0}) // exportnode list: no entries follow
	case 1: // MNT
		flagAnomaly(res, "nfs-mount-attempt")
		res.Meta["intent"] = "NFS MOUNT request — attempting to mount an exported share"
		nfsWriteAccepted(conn, xid, binary.BigEndian.AppendUint32(nil, 13)) // mountstat3 MNT3ERR_ACCES
	default: // UMNT / UMNTALL / other
		setIfEmpty(res.Meta, "intent", "MOUNT "+mountProcName(proc)+" request")
		nfsWriteAccepted(conn, xid, nil)
	}
	res.BannerSent = "nfs mountd reply"
}

// mountProcName names a MOUNT (mountd, program 100005) RPC procedure.
func mountProcName(proc uint32) string {
	switch proc {
	case 0:
		return "NULL"
	case 1:
		return "MNT"
	case 2:
		return "DUMP"
	case 3:
		return "UMNT"
	case 4:
		return "UMNTALL"
	case 5:
		return "EXPORT"
	case 6:
		return "EXPORTALL"
	}
	return "PROC" + itoaU(proc)
}

// nfsHandleCompound parses an NFSv4 COMPOUND's operation list for intent and
// answers it: PUTROOTFH/PUTFH/GETFH succeed (handing back a root filehandle),
// the first traversal/read op is denied with NFS4ERR_ACCESS and ends the chain.
func nfsHandleCompound(conn net.Conn, msg []byte, xid []byte, res *Result) {
	off, ok := rpcArgsOffset(msg)
	if !ok {
		nfsWriteAccepted(conn, xid, nfsCompoundBody(nil, 0, 0, nil))
		res.BannerSent = "nfs COMPOUND reply"
		return
	}
	a := msg[off:]
	var tag []byte
	if len(a) >= 4 {
		tlen := int(binary.BigEndian.Uint32(a[0:4]))
		if 4+tlen <= len(a) {
			tag = a[4 : 4+tlen]
		}
		off2 := 4 + roundUp4(tlen)
		if off2+8 <= len(a) {
			ops := nfsParseOps(a[off2+8:], int(binary.BigEndian.Uint32(a[off2+4:off2+8])))
			res.Meta["nfs_ops"] = nfsOpNames(ops)
			nfsClassifyOps(ops, res)
			body, st, numres := nfsCompoundResults(ops)
			nfsWriteAccepted(conn, xid, nfsCompoundBody(tag, st, numres, body))
			res.BannerSent = "nfs COMPOUND reply"
			return
		}
	}
	nfsWriteAccepted(conn, xid, nfsCompoundBody(tag, 0, 0, nil))
	res.BannerSent = "nfs COMPOUND reply"
}

// nfsParseOps walks the COMPOUND op array, returning the opnums it can follow.
// Each op's arguments vary, so we skip the ones we know and stop at the first
// op whose layout we don't model — the leading ops carry the attacker intent.
func nfsParseOps(b []byte, numops int) []uint32 {
	if numops > 64 {
		numops = 64
	}
	var ops []uint32
	off := 0
	for i := 0; i < numops; i++ {
		if off+4 > len(b) {
			break
		}
		op := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		ops = append(ops, op)
		skip, ok := nfsSkipOpArgs(op, b, off)
		if !ok {
			break
		}
		off = skip
	}
	return ops
}

// nfsSkipOpArgs advances past the argument block of the ops we model.
func nfsSkipOpArgs(op uint32, b []byte, off int) (int, bool) {
	switch op {
	case 10, 24: // GETFH, PUTROOTFH — no args
		return off, true
	case 3: // ACCESS — access:uint32
		return off + 4, off+4 <= len(b)
	case 25: // READ — stateid(16)+offset(8)+count(4)
		return off + 28, off+28 <= len(b)
	case 22, 11, 15, 33: // PUTFH/LINK/LOOKUP/SECINFO — one opaque<>
		return skipOpaque(b, off)
	case 9: // GETATTR — bitmap: count(4)+count*4
		return skipBitmap(b, off)
	case 26: // READDIR — cookie(8)+verf(8)+dircount(4)+maxcount(4)+bitmap
		if off+24 > len(b) {
			return off, false
		}
		return skipBitmap(b, off+24)
	default:
		return off, false // OPEN/SETCLIENTID/EXCHANGE_ID/etc. — stop here
	}
}

// nfsClassifyOps flags anomalies and sets an intent from the op list.
func nfsClassifyOps(ops []uint32, res *Result) {
	var enum, read, setup, root bool
	for _, op := range ops {
		switch op {
		case 15, 26, 33: // LOOKUP, READDIR, SECINFO
			enum = true
		case 25, 9: // READ, GETATTR
			if op == 25 {
				read = true
			} else {
				enum = true
			}
		case 24, 10, 22: // PUTROOTFH, GETFH, PUTFH
			root = true
		case 34, 35, 42: // SETCLIENTID, SETCLIENTID_CONFIRM, EXCHANGE_ID
			setup = true
		}
	}
	switch {
	case read:
		flagAnomaly(res, "nfs-file-read")
		setIfEmpty(res.Meta, "intent", "NFSv4 READ — reading file contents over NFS")
	case enum:
		flagAnomaly(res, "nfs-export-enum")
		setIfEmpty(res.Meta, "intent", "NFSv4 export traversal — enumerating shares/files")
	case setup:
		flagAnomaly(res, "nfs-client-setup")
		setIfEmpty(res.Meta, "intent", "NFSv4 client negotiation — establishing an NFS session")
	case root:
		flagAnomaly(res, "nfs-root-probe")
		setIfEmpty(res.Meta, "intent", "NFSv4 root probe — locating mountable exports")
	}
}

// nfsCompoundResults builds the resarray bytes, the overall COMPOUND status and
// the number of op-results, stopping at the first denied/unmodelled op.
func nfsCompoundResults(ops []uint32) (resarray []byte, status uint32, numres uint32) {
	const nfs4errAccess = 13
	for _, op := range ops {
		numres++
		switch op {
		case 24, 22: // PUTROOTFH / PUTFH -> OK (status only)
			resarray = binary.BigEndian.AppendUint32(resarray, op)
			resarray = binary.BigEndian.AppendUint32(resarray, 0)
			status = 0
		case 10: // GETFH -> OK + a 32-byte root filehandle
			resarray = binary.BigEndian.AppendUint32(resarray, op)
			resarray = binary.BigEndian.AppendUint32(resarray, 0)
			fh := make([]byte, 32)
			copy(fh, "tarpit-nfs-root-fh")
			resarray = binary.BigEndian.AppendUint32(resarray, uint32(len(fh)))
			resarray = append(resarray, fh...)
			status = 0
		default: // traversal/read/attr -> denied, ends the chain
			resarray = binary.BigEndian.AppendUint32(resarray, op)
			resarray = binary.BigEndian.AppendUint32(resarray, nfs4errAccess)
			return resarray, nfs4errAccess, numres
		}
	}
	return resarray, status, numres
}

// nfsCompoundBody frames a COMPOUND4res: status + tag + resarray<numres>.
func nfsCompoundBody(tag []byte, status, numres uint32, resarray []byte) []byte {
	body := binary.BigEndian.AppendUint32(nil, status)
	body = binary.BigEndian.AppendUint32(body, uint32(len(tag)))
	body = append(body, tag...)
	body = append(body, make([]byte, roundUp4(len(tag))-len(tag))...)
	body = binary.BigEndian.AppendUint32(body, numres)
	return append(body, resarray...)
}

// nfsWriteAccepted sends a record-marked RPC MSG_ACCEPTED / SUCCESS reply whose
// procedure-result bytes are body.
func nfsWriteAccepted(conn net.Conn, xid, body []byte) {
	reply := append([]byte{}, xid...)
	reply = binary.BigEndian.AppendUint32(reply, 1) // REPLY
	reply = binary.BigEndian.AppendUint32(reply, 0) // MSG_ACCEPTED
	reply = binary.BigEndian.AppendUint32(reply, 0) // verf flavor AUTH_NULL
	reply = binary.BigEndian.AppendUint32(reply, 0) // verf length
	reply = binary.BigEndian.AppendUint32(reply, 0) // accept_stat SUCCESS
	reply = append(reply, body...)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(reply))|0x80000000)
	out = append(out, reply...)
	_, _ = conn.Write(out)
}

// rpcArgsOffset returns the offset (within the RPC message, record header
// already stripped) of the procedure arguments, having skipped the variable
// cred and verf opaque blocks.
func rpcArgsOffset(msg []byte) (int, bool) {
	if len(msg) < 32 {
		return 0, false
	}
	credLen := int(binary.BigEndian.Uint32(msg[28:32]))
	off := 32 + roundUp4(credLen)
	if off+8 > len(msg) {
		return 0, false
	}
	vlen := int(binary.BigEndian.Uint32(msg[off+4 : off+8]))
	off = off + 8 + roundUp4(vlen)
	if off > len(msg) {
		return 0, false
	}
	return off, true
}

// skipOpaque advances past an XDR opaque<> (length-prefixed, 4-byte padded).
func skipOpaque(b []byte, off int) (int, bool) {
	if off+4 > len(b) {
		return off, false
	}
	n := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4 + roundUp4(n)
	return off, off <= len(b)
}

// skipBitmap advances past an XDR bitmap4 (count then count uint32 words).
func skipBitmap(b []byte, off int) (int, bool) {
	if off+4 > len(b) {
		return off, false
	}
	n := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4 + n*4
	return off, off <= len(b)
}

func roundUp4(n int) int {
	if n < 0 {
		return 0
	}
	return (n + 3) &^ 3
}

func setIfEmpty(m map[string]any, k, v string) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

func rpcAuthName(flavor uint32) string {
	switch flavor {
	case 0:
		return "AUTH_NULL"
	case 1:
		return "AUTH_UNIX"
	case 6:
		return "RPCSEC_GSS"
	default:
		return "AUTH_OTHER"
	}
}

// nfsProcName names an NFS RPC procedure by version (v3 has many data procs;
// v4 collapses everything into NULL + COMPOUND).
func nfsProcName(vers, proc uint32) string {
	if vers == 4 {
		switch proc {
		case 0:
			return "NULL"
		case 1:
			return "COMPOUND"
		}
		return "PROC" + itoaU(proc)
	}
	// NFSv2/v3 procedure numbers (v3 superset).
	switch proc {
	case 0:
		return "NULL"
	case 1:
		return "GETATTR"
	case 2:
		return "SETATTR"
	case 3:
		return "LOOKUP"
	case 4:
		return "ACCESS"
	case 5:
		return "READLINK"
	case 6:
		return "READ"
	case 7:
		return "WRITE"
	case 8:
		return "CREATE"
	case 9:
		return "MKDIR"
	case 10:
		return "SYMLINK"
	case 11:
		return "MKNOD"
	case 12:
		return "REMOVE"
	case 13:
		return "RMDIR"
	case 14:
		return "RENAME"
	case 15:
		return "LINK"
	case 16:
		return "READDIR"
	case 17:
		return "READDIRPLUS"
	case 18:
		return "FSSTAT"
	case 19:
		return "FSINFO"
	case 20:
		return "PATHCONF"
	case 21:
		return "COMMIT"
	}
	return "PROC" + itoaU(proc)
}

// nfsOpNames maps NFSv4 COMPOUND opnums to their names for the captured op list.
func nfsOpNames(ops []uint32) []string {
	names := make([]string, 0, len(ops))
	for _, op := range ops {
		names = append(names, nfsOpName(op))
	}
	return names
}

func nfsOpName(op uint32) string {
	switch op {
	case 3:
		return "ACCESS"
	case 4:
		return "CLOSE"
	case 9:
		return "GETATTR"
	case 10:
		return "GETFH"
	case 11:
		return "LINK"
	case 15:
		return "LOOKUP"
	case 16:
		return "LOOKUPP"
	case 18:
		return "OPEN"
	case 22:
		return "PUTFH"
	case 24:
		return "PUTROOTFH"
	case 25:
		return "READ"
	case 26:
		return "READDIR"
	case 27:
		return "READLINK"
	case 28:
		return "REMOVE"
	case 31:
		return "RESTOREFH"
	case 32:
		return "SAVEFH"
	case 33:
		return "SECINFO"
	case 34:
		return "SETCLIENTID"
	case 35:
		return "SETCLIENTID_CONFIRM"
	case 42:
		return "EXCHANGE_ID"
	case 43:
		return "CREATE_SESSION"
	case 53:
		return "SEQUENCE"
	}
	return "OP" + itoaU(op)
}

func itoaU(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

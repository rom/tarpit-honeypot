package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// oracleTNS emulates the Oracle Net (TNS) listener (TCP 1521). A
// client opens with a CONNECT packet (type 1) carrying a connect
// descriptor like "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL))...)".
// We capture the descriptor (service name / SID are valuable recon
// fields) and reply with a TNS REFUSE (type 4) carrying the classic
// "ORA-12514: TNS:listener does not currently know of service" — what
// a real listener returns for an unknown service, which keeps the
// scanner believing it found Oracle without us granting anything.
//
// TNS packet header (8 bytes, big-endian):
//
//	length(2) checksum(2) type(1) reserved(1) hdrchecksum(2)
type oracleTNS struct{ id *identity.Identity }

func (o *oracleTNS) Name() string { return "oracle_tns" }

// oracleVer is a believable listener version + its matching VSNNUM (the packed
// version Oracle reports: major<<24 | minor<<20 | patch<<12 | port<<8 | update).
type oracleVer struct {
	ver    string
	vsnnum uint32
}

func oracleVersions() []oracleVer {
	mk := func(maj, min, pat, port, pu uint32, s string) oracleVer {
		return oracleVer{ver: s, vsnnum: maj<<24 | min<<20 | pat<<12 | port<<8 | pu}
	}
	return []oracleVer{
		mk(19, 0, 0, 0, 0, "19.0.0.0.0"),
		mk(21, 0, 0, 0, 0, "21.0.0.0.0"),
		mk(18, 0, 0, 0, 0, "18.0.0.0.0"),
		mk(12, 2, 0, 1, 0, "12.2.0.1.0"),
		mk(12, 1, 0, 2, 0, "12.1.0.2.0"),
		mk(11, 2, 0, 4, 0, "11.2.0.4.0"),
	}
}

// version picks a per-deployment listener version so a scanner correlating
// Oracle banners across sensors sees a believable spread rather than a single
// hardcoded build.
func (o *oracleTNS) version() oracleVer {
	pool := oracleVersions()
	if o.id == nil {
		return pool[0]
	}
	return pool[int(o.id.Derive("oracle-tns-version").Uint32("pick"))%len(pool)]
}

const (
	tnsConnect = 1
	tnsAccept  = 2
	tnsRefuse  = 4
	tnsData    = 6
	tnsResend  = 11
)

func (o *oracleTNS) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	length := int(binary.BigEndian.Uint16(hdr[0:2]))
	pktType := hdr[4]
	res.Meta["tns_packet_type"] = pktType
	res.Meta["tns_type_name"] = tnsTypeName(pktType)
	if length < 8 || length > 8192 {
		res.Meta["bad_tns_length"] = length
		return res, nil
	}
	body, ok := safe.AllocBytes(length - 8)
	if !ok {
		res.Meta["alloc_err"] = length
		return res, nil
	}
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(hdr, body...)

	if pktType != tnsConnect {
		res.Meta["non_connect"] = true
		return res, nil
	}

	// The connect descriptor is ASCII text inside the CONNECT body
	// (after a 26-byte fixed header in classic TNS; we just scan for
	// the "(DESCRIPTION" marker to be version-robust).
	desc := extractTNSDescriptor(body)
	cmd := ""
	if desc != "" {
		res.Meta["connect_descriptor"] = safe.SanitizeForLog(desc)
		if svc := tnsField(desc, "SERVICE_NAME"); svc != "" {
			res.Meta["service_name"] = safe.SanitizeForLog(svc)
		}
		if sid := tnsField(desc, "SID"); sid != "" {
			res.Meta["sid"] = safe.SanitizeForLog(sid)
		}
		cmd = strings.ToLower(tnsField(desc, "COMMAND"))
		if cmd != "" {
			res.Meta["tns_command"] = safe.SanitizeForLog(cmd)
		}
	}
	flagAnomaly(&res, "oracle-tns-probe")

	// The `tnscmd`/nmap oracle-tns-version probe sends a CONNECT carrying
	// (COMMAND=version|status|services|ping). A real listener answers those
	// with a DATA packet (the version banner / status), NOT a refuse — so
	// answering one keeps the version scan fooled.
	switch cmd {
	case "version", "status", "services", "ping", "reload":
		data := o.buildVersionData()
		if _, err := conn.Write(data); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = "oracle TNS listener version data"
		return res, nil
	}

	// Otherwise REFUSE with ORA-12514 (unknown service) — what a real
	// listener returns for a service-name connect it doesn't host.
	refuse := o.buildRefuse("(DESCRIPTION=(ERR=12514)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))")
	if _, err := conn.Write(refuse); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "oracle TNS refuse ORA-12514"
	return res, nil
}

// buildVersionData assembles a TNS DATA packet carrying a believable listener
// version banner — the response shape the oracle-tns-version probe parses.
func (o *oracleTNS) buildVersionData() []byte {
	v := o.version()
	banner := "(DESCRIPTION=(TMP=)(VSNNUM=" + itoa(int(v.vsnnum)) + ")(ERR=0)(ALIAS=LISTENER))" +
		"\nTNSLSNR for Linux: Version " + v.ver + " - Production\n" +
		"TNS for Linux: Version " + v.ver + " - Production\n"
	// DATA packet body: 2-byte data flags (0x0000) + payload.
	body := []byte{0x00, 0x00}
	body = append(body, []byte(banner)...)
	return wrapTNS(tnsData, body)
}

func (o *oracleTNS) buildRefuse(data string) []byte {
	// REFUSE body: refuse-reason-user(1) refuse-reason-system(1)
	// data-length(2) + data.
	body := []byte{0x00, 0x00}
	body = binary.BigEndian.AppendUint16(body, uint16(len(data)))
	body = append(body, []byte(data)...)
	return wrapTNS(tnsRefuse, body)
}

// wrapTNS prepends the 8-byte TNS header.
func wrapTNS(pktType byte, body []byte) []byte {
	total := 8 + len(body)
	out := make([]byte, total)
	binary.BigEndian.PutUint16(out[0:2], uint16(total))
	// checksum 0, type, reserved 0, header checksum 0.
	out[4] = pktType
	copy(out[8:], body)
	return out
}

// extractTNSDescriptor returns the "(DESCRIPTION=...)" connect string
// from a CONNECT body, or "" if not present.
func extractTNSDescriptor(body []byte) string {
	s := string(body)
	i := strings.Index(s, "(DESCRIPTION")
	if i < 0 {
		i = strings.Index(s, "(CONNECT_DATA")
		if i < 0 {
			return ""
		}
	}
	// Trim trailing NULs / control bytes.
	desc := s[i:]
	if j := strings.IndexByte(desc, 0); j >= 0 {
		desc = desc[:j]
	}
	if len(desc) > 1024 {
		desc = desc[:1024]
	}
	return desc
}

// tnsField pulls "(KEY=value)" out of a connect descriptor.
func tnsField(desc, key string) string {
	marker := "(" + key + "="
	i := strings.Index(strings.ToUpper(desc), marker)
	if i < 0 {
		return ""
	}
	rest := desc[i+len(marker):]
	if j := strings.IndexByte(rest, ')'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func tnsTypeName(t byte) string {
	switch t {
	case tnsConnect:
		return "CONNECT"
	case tnsAccept:
		return "ACCEPT"
	case tnsRefuse:
		return "REFUSE"
	case tnsData:
		return "DATA"
	case tnsResend:
		return "RESEND"
	}
	return ""
}

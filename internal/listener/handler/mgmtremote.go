package handler

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// vmwareAuthd emulates the VMware Authentication Daemon on TCP 902 — the
// management agent fronting ESXi / Workstation. It sends the distinctive
// 220 banner scanners key on, then captures the FTP-style USER/PASS auth.
type vmwareAuthd struct{}

func (v *vmwareAuthd) Name() string { return "vmware_authd" }

func (v *vmwareAuthd) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	banner := "220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t\r\n"
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = banner
	br := bufio.NewReader(conn)
	var user, pass string
	for i := 0; i < 8; i++ {
		line, err := readFTPLine(br, cfg.ReadBytes)
		if err != nil {
			break
		}
		res.Payload = append(res.Payload, line...)
		cmd, arg := splitFTPCmd(line)
		switch cmd {
		case "USER":
			user = arg
			_, _ = conn.Write([]byte("331 Password required for " + safe.SanitizeHeader(arg) + ".\r\n"))
		case "PASS":
			pass = arg
			_, _ = conn.Write([]byte("530 Login incorrect\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("221 Goodbye.\r\n"))
		default:
			if cmd != "" {
				_, _ = conn.Write([]byte("500 Unknown command\r\n"))
			}
		}
		if user != "" && pass != "" {
			break
		}
	}
	res.Meta["user"] = safe.SanitizeForLog(strings.TrimSpace(user))
	res.Meta["pass"] = safe.SanitizeForLog(strings.TrimSpace(pass))
	flagDefaultCred(&res, strings.TrimSpace(user), strings.TrimSpace(pass))
	flagAnomaly(&res, "vmware-authd-login")
	// The daemon banner says "SSL Required"; a client that submits USER/PASS in
	// plaintext (no SSL upgrade) exposes the ESXi/vCenter credentials in the clear.
	if strings.TrimSpace(user) != "" && strings.TrimSpace(pass) != "" {
		flagAnomaly(&res, "vmware-authd-cleartext-creds")
		res.Meta["intent"] = "VMware authd credentials sent without SSL — cleartext credential exposure"
	}
	return res, nil
}

// x11 emulates an X11 display server on TCP 6000+. It parses the X11
// connection setup request (RFC / X protocol §8) to capture the
// authorization-protocol name an attacker offers, then returns a Failed
// setup reply. An exposed X server is a known data-exfil risk (keylogging
// / screen capture), so any connection attempt is flagged.
type x11 struct{}

func (x *x11) Name() string { return "x11" }

func (x *x11) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	hdr := make([]byte, 12)
	n, _ := conn.Read(hdr)
	if n < 12 {
		res.Meta["read_err"] = "short setup"
		return res, nil
	}
	res.Payload = append([]byte(nil), hdr[:n]...)
	var bo binary.ByteOrder
	switch hdr[0] {
	case 'B':
		bo = binary.BigEndian
	case 'l':
		bo = binary.LittleEndian
	default:
		res.Meta["non_x11"] = true
		return res, nil
	}
	res.Meta["x11_major"] = bo.Uint16(hdr[2:4])
	res.Meta["x11_minor"] = bo.Uint16(hdr[4:6])
	nameLen := int(bo.Uint16(hdr[6:8]))
	dataLen := int(bo.Uint16(hdr[8:10]))
	if nameLen > 0 && nameLen <= 256 {
		// auth-protocol-name follows the header, padded to 4 bytes.
		name := make([]byte, (nameLen+3)&^3)
		if _, err := io.ReadFull(conn, name); err == nil {
			res.Meta["x11_auth_name"] = safe.SanitizeForLog(string(name[:nameLen]))
			res.Payload = append(res.Payload, name...)
		}
	}
	// Drain the auth-protocol-data (padded) so the whole setup record is
	// consumed before we reply.
	if dataLen > 0 && dataLen <= 4096 {
		data := make([]byte, (dataLen+3)&^3)
		if _, err := io.ReadFull(conn, data); err == nil {
			res.Payload = append(res.Payload, data...)
		}
	}
	flagAnomaly(&res, "x11-connection-attempt")

	// Failed setup reply: success=0, reason-length, major, minor,
	// additional-data length (in 4-byte units), then the reason string.
	reason := "No protocol specified\n"
	body := make([]byte, 0, 8+len(reason))
	body = append(body, 0, byte(len(reason))) // Failed, reason length
	tmp := make([]byte, 2)
	bo.PutUint16(tmp, 11)
	body = append(body, tmp...) // protocol major
	bo.PutUint16(tmp, 0)
	body = append(body, tmp...) // protocol minor
	bo.PutUint16(tmp, uint16((len(reason)+3)/4))
	body = append(body, tmp...) // length of additional data / 4
	body = append(body, []byte(reason)...)
	_, _ = conn.Write(body)
	res.BannerSent = "x11 setup failed"
	return res, nil
}

// rlogin emulates the BSD rlogin service (TCP 513). The client opens with a
// NUL-separated record: \0 client-user \0 server-user \0 termtype/speed \0.
// We capture the offered usernames + terminal, then prompt for a password
// (rlogind falls back to /bin/login) and capture that too.
type rlogin struct{}

func (r *rlogin) Name() string { return "rlogin" }

func (r *rlogin) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	res.Payload = append([]byte(nil), buf[:n]...)
	fields := strings.Split(string(buf[:n]), "\x00")
	// fields[0] is the empty leading record; [1]=client-user, [2]=server-user, [3]=term.
	if len(fields) >= 2 {
		res.Meta["client_user"] = safe.SanitizeForLog(fields[1])
	}
	if len(fields) >= 3 {
		res.Meta["server_user"] = safe.SanitizeForLog(fields[2])
	}
	if len(fields) >= 4 {
		res.Meta["term"] = safe.SanitizeForLog(fields[3])
	}
	flagAnomaly(&res, "rlogin-attempt")

	// 0x00 = "ok, continue", then fall back to a password prompt.
	_, _ = conn.Write([]byte{0x00})
	_, _ = conn.Write([]byte("\r\nPassword: "))
	pass, _ := readBoundedLineFromReader(bufio.NewReader(conn), 256)
	pass = strings.TrimRight(pass, "\r\n")
	if pass != "" {
		res.Meta["password"] = safe.SanitizeForLog(pass)
		su, _ := res.Meta["server_user"].(string)
		flagDefaultCred(&res, su, pass)
	}
	_, _ = conn.Write([]byte("\r\nLogin incorrect\r\n"))
	res.BannerSent = "rlogin login"
	return res, nil
}

// nx emulates the NoMachine NX server (TCP 4000). It sends the HELLO
// NXSERVER banner scanners fingerprint, then captures the client's hello +
// any login it offers.
type nx struct{}

func (n *nx) Name() string { return "nx" }

func (n *nx) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	banner := "HELLO NXSERVER - Version 3.5.0-9\r\n"
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = banner
	br := bufio.NewReader(conn)
	for i := 0; i < 8; i++ {
		line, err := readBoundedLineFromReader(br, 512)
		if err != nil {
			break
		}
		c := strings.TrimRight(line, "\r\n")
		if c == "" {
			continue
		}
		res.Payload = append(res.Payload, []byte(c+"\n")...)
		upper := strings.ToUpper(c)
		switch {
		case strings.HasPrefix(upper, "HELLO"):
			res.Meta["nx_client"] = safe.SanitizeForLog(c)
			_, _ = conn.Write([]byte("NX> 105 "))
		case strings.HasPrefix(upper, "LOGIN"):
			_, _ = conn.Write([]byte("NX> 101 User: "))
		case strings.HasPrefix(upper, "BYE"):
			_, _ = conn.Write([]byte("NX> 999 Bye\r\n"))
			i = 1 << 30
		default:
			res.Meta["nx_line"] = safe.SanitizeForLog(c)
			_, _ = conn.Write([]byte("NX> 500 Error\r\n"))
		}
	}
	flagAnomaly(&res, "nx-probe")
	return res, nil
}

// redfish emulates a BMC's Redfish REST API (TCP 443/8000) — the modern
// out-of-band management interface on iLO / iDRAC / XCC / Supermicro. It
// serves the unauthenticated service root, demands auth for anything below
// it, and captures Basic-auth credentials. Read-only, never executes.
type redfish struct{}

func (rf *redfish) Name() string { return "redfish" }

func (rf *redfish) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// Bounded per-line reads (not ReadString, which buffers a newline-less
	// stream up to the read deadline) so a peer can't force a large
	// allocation through the request line or a header — including the
	// base64 in an Authorization header.
	lineCap := cfg.ReadBytes
	if lineCap <= 0 || lineCap > 16384 {
		lineCap = 8192
	}
	br := bufio.NewReader(conn)
	reqLine, err := readFTPLine(br, lineCap)
	if err != nil && reqLine == "" {
		res.Meta["read_err"] = "no request"
		return res, nil
	}
	res.Payload = []byte(reqLine)
	method := extractMethod(strings.TrimSpace(reqLine))
	path := extractPath(strings.TrimSpace(reqLine))
	res.Meta["request_line"] = safe.SanitizeForLog(strings.TrimSpace(reqLine))

	authUser, authPass := "", ""
	for i := 0; i < 40; i++ {
		h, err := readFTPLine(br, lineCap)
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
		res.Payload = append(res.Payload, h...)
		if strings.HasPrefix(strings.ToLower(h), "authorization:") {
			authUser, authPass = parseBasicAuth(h)
		}
	}

	server := "Server: Apache\r\n"
	switch {
	case path == "/redfish" || path == "/redfish/":
		body := `{"v1":"/redfish/v1/"}`
		writeRedfish(conn, "200 OK", server, body)
	case path == "/redfish/v1" || path == "/redfish/v1/":
		writeRedfish(conn, "200 OK", server, redfishServiceRoot())
	default:
		// Anything below the service root needs auth.
		if authUser != "" || authPass != "" {
			res.Meta["basic_user"] = safe.SanitizeForLog(authUser)
			res.Meta["basic_pass"] = safe.SanitizeForLog(authPass)
			flagDefaultCred(&res, authUser, authPass)
			flagAnomaly(&res, "redfish-auth-attempt")
			writeRedfish(conn, "401 Unauthorized", server+"WWW-Authenticate: Basic realm=\"RedfishService\"\r\n",
				`{"error":{"code":"Base.1.0.GeneralError","message":"Login required"}}`)
		} else {
			writeRedfish(conn, "401 Unauthorized", server+"WWW-Authenticate: Basic realm=\"RedfishService\"\r\n",
				`{"error":{"code":"Base.1.0.GeneralError","message":"Authentication required"}}`)
		}
	}
	res.Meta["method"] = method
	res.BannerSent = "redfish"
	return res, nil
}

func redfishServiceRoot() string {
	return `{"@odata.id":"/redfish/v1/","@odata.type":"#ServiceRoot.v1_5_0.ServiceRoot",` +
		`"Id":"RootService","Name":"Root Service","RedfishVersion":"1.6.0",` +
		`"UUID":"00000000-0000-0000-0000-000000000000",` +
		`"Systems":{"@odata.id":"/redfish/v1/Systems"},` +
		`"Managers":{"@odata.id":"/redfish/v1/Managers"},` +
		`"SessionService":{"@odata.id":"/redfish/v1/SessionService"},` +
		`"Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}}}`
}

func writeRedfish(conn net.Conn, status, extraHeaders, body string) {
	resp := "HTTP/1.1 " + status + "\r\n" + extraHeaders +
		"Content-Type: application/json\r\n" +
		"OData-Version: 4.0\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, _ = conn.Write([]byte(resp))
}

// parseBasicAuth decodes an "Authorization: Basic <b64>" header line into
// (user, pass). Returns ("","") on anything else.
func parseBasicAuth(line string) (string, string) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", ""
	}
	v := strings.TrimSpace(line[i+1:])
	if !strings.HasPrefix(strings.ToLower(v), "basic ") {
		return "", ""
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
	if err != nil {
		return "", ""
	}
	u, p, _ := strings.Cut(string(dec), ":")
	return u, p
}

package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// codesys is a CODESYS V3 responder on TCP 1217 — the gateway/runtime control
// channel embedded by many soft-PLC vendors (WAGO, Beckhoff, Schneider, ABB,
// Festo, Eaton, …). The block-driver/datagram/channel/service stack is
// proprietary, so this is fingerprint-grade at the wire level, but it parses
// the block-driver header and classifies the targeted CODESYS *component /
// service* (CmpUserMgr login, CmpFileTransfer, CmpApp start/stop/download,
// online change, CmpDevice info) from the component tokens CODESYS carries in
// the clear — so the SOC sees whether the attacker is logging in, downloading
// logic, or stopping the PLC, and the CODESYS no-auth / RCE CVEs are attributed.
type codesys struct{}

func (c *codesys) Name() string { return "codesys" }

func (c *codesys) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	got := buf[:n]
	res.Payload = append([]byte(nil), got...)
	res.Meta["bytes"] = n
	flagAnomaly(&res, "ics-codesys-probe")
	setIfEmpty(res.Meta, "intent", "CODESYS V3 runtime/gateway probe — soft-PLC control-channel access attempt")

	// Block-driver header: a CODESYS V3 TCP datagram opens with a small magic
	// (commonly 0xC5-class) + a length/command field. Record the magic so the
	// SIEM can distinguish a real CODESYS open from a generic scanner poke.
	if n >= 2 {
		res.Meta["codesys_magic"] = fmtByte(got[0]) + fmtByte(got[1])
	}

	// Classify the targeted CODESYS component/service from the in-clear tokens.
	c.classify(got, &res)

	// Minimal channel-open acknowledgement (header + zero status) so a scanner
	// records a live CODESYS runtime.
	resp := []byte{0xC5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "codesys ack"
	return res, nil
}

// codesysComponents maps a CODESYS component-token (carried in the clear in the
// service request) to a (service-name, short-command, marker, intent)
// classification. cmd is the concise decoded command surfaced as codesys_command.
var codesysComponents = []struct {
	token, name, cmd, marker, intent string
}{
	{"cmpusermgr", "CmpUserMgr (login)", "Login", "ics-codesys-login", "CODESYS V3 login — runtime authentication attempt"},
	{"cmpfiletransfer", "CmpFileTransfer", "File transfer", "ics-plc-program-access", "CODESYS V3 file transfer — uploading/downloading PLC files"},
	{"cmpapp", "CmpApp", "Application service", "ics-plc-program-access", "CODESYS V3 application service — program download / online change"},
	{"cmpappbp", "CmpAppBP (breakpoints)", "Debug / breakpoints", "ics-plc-program-access", "CODESYS V3 application debug — breakpoint/online manipulation"},
	{"cmpdevice", "CmpDevice", "Device info", "ics-field-device-probe", "CODESYS V3 device info — runtime/CPU fingerprinting"},
	{"cmpopcua", "CmpOPCUAServer", "OPC UA access", "ics-field-device-probe", "CODESYS V3 OPC-UA component access"},
	{"cmpcodemeter", "CmpCodeMeter (licensing)", "Licensing", "ics-codesys-probe", "CODESYS V3 licensing component access"},
	{"cmptraceMgr", "CmpTraceMgr", "Trace read", "ics-process-data-access", "CODESYS V3 trace — reading live process variables"},
}

// classify inspects the request for CODESYS component tokens and PLC-control
// verbs, raising the matching markers + CVE attribution and recording the
// decoded component (codesys_component) and concise command (codesys_command).
func (c *codesys) classify(got []byte, res *Result) {
	low := strings.ToLower(asciiOnly(got))
	matched := false
	var cmd string
	for _, comp := range codesysComponents {
		if strings.Contains(low, comp.token) {
			matched = true
			flagAnomaly(res, comp.marker)
			res.Meta["codesys_component"] = comp.name
			res.Meta["intent"] = comp.intent
			if cmd == "" {
				cmd = comp.cmd // first matched component is the primary command
			}
		}
	}
	// PLC run-state control verbs (start/stop/reset) and program-access verbs seen
	// in the app service — the most specific action wins the codesys_command.
	switch {
	case strings.Contains(low, "stopapp"):
		flagAnomaly(res, "ics-plc-mode-change")
		cmd = "PLC Stop"
		res.Meta["intent"] = "CODESYS V3 PLC STOP — halting the controller (denial of control)"
	case strings.Contains(low, "startapp"):
		flagAnomaly(res, "ics-plc-mode-change")
		cmd = "PLC Start"
		res.Meta["intent"] = "CODESYS V3 PLC START — starting the controller"
	case strings.Contains(low, "resetapp"):
		flagAnomaly(res, "ics-plc-mode-change")
		cmd = "PLC Reset"
		res.Meta["intent"] = "CODESYS V3 PLC RESET — resetting the controller"
	case strings.Contains(low, "download"):
		flagAnomaly(res, "ics-plc-program-access")
		cmd = "Program download"
		res.Meta["intent"] = "CODESYS V3 program download — writing PLC logic"
	case strings.Contains(low, "onlinechange"):
		flagAnomaly(res, "ics-plc-program-access")
		cmd = "Online change"
		res.Meta["intent"] = "CODESYS V3 online change — patching running PLC logic"
	}
	if cmd != "" {
		res.Meta["codesys_command"] = cmd
	}

	// CODESYS Control runtimes ship without password protection by default and
	// the gateway has an auth-bypass — attribute the no-auth control weakness
	// whenever a control/login/file service is reached.
	if matched {
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2022-31806")
		flagAnomaly(res, "cve:CVE-2022-31806")
		if strings.Contains(low, "cmpusermgr") {
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2022-31802")
			flagAnomaly(res, "cve:CVE-2022-31802")
		}
	}
}

// asciiOnly returns the printable-ASCII characters of b (collapsing the rest),
// so token matching works across the binary block-driver framing.
func asciiOnly(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, ' ')
		}
	}
	return string(out)
}

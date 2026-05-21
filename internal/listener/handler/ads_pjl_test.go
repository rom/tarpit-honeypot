package handler

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestPJLInfoID(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 4096}
	resC := make(chan Result, 1)
	go func() { r, _ := (&pjl{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write([]byte("\x1b%-12345X@PJL INFO ID\r\n"))
	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	if !strings.Contains(string(buf[:n]), "HP LaserJet") {
		t.Errorf("PJL INFO ID response missing model: %q", string(buf[:n]))
	}
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "pjl-command") {
		t.Errorf("not flagged pjl-command: %v", r.Meta["anomalies"])
	}
}

func TestPJLRdymsgDefacement(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&pjl{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write([]byte("@PJL RDYMSG DISPLAY=\"HACKED\"\r\n"))
	time.Sleep(20 * time.Millisecond)
	_ = client.Close()
	r := <-resC
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "printer-rdymsg-set") {
		t.Errorf("RDYMSG defacement not flagged: %v", r.Meta["anomalies"])
	}
}

// runPJLSession drives the pjl handler with a full input then EOF, draining
// any believable responses it writes so the handler never blocks.
func runPJLSession(t *testing.T, input string) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 8192}
	resC := make(chan Result, 1)
	go func() { r, _ := (&pjl{}).Handle(context.Background(), server, cfg); resC <- r }()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	_, _ = client.Write([]byte(input))
	_ = client.Close()
	return <-resC
}

func pjlAnoms(r Result) []string {
	a, _ := r.Meta["anomalies"].([]string)
	return a
}

func TestPJLFilesystemTraversal(t *testing.T) {
	r := runPJLSession(t, "\x1b%-12345X@PJL FSDOWNLOAD FORMAT:BINARY SIZE=10 NAME=\"0:\\..\\..\\etc\\passwd\"\r\n")
	a := pjlAnoms(r)
	if !containsStr(a, "printer-filesystem-access") {
		t.Errorf("FS access not flagged: %v", a)
	}
	if !containsStr(a, "printer-path-traversal") {
		t.Errorf("path traversal not flagged: %v", a)
	}
}

func TestPJLFSInitFormat(t *testing.T) {
	r := runPJLSession(t, "@PJL FSINIT VOLUME=\"0:\"\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-filesystem-format") {
		t.Errorf("FSINIT (format) not flagged: %v", a)
	}
}

func TestPJLPasswordSet(t *testing.T) {
	r := runPJLSession(t, "@PJL DEFAULT PASSWORD=12345\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-password-set") {
		t.Errorf("password set not flagged: %v", a)
	}
}

func TestPJLCredentialRead(t *testing.T) {
	r := runPJLSession(t, "@PJL DINQUIRE PASSWORD\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-credential-access") {
		t.Errorf("password read not flagged: %v", a)
	}
}

func TestPJLInfoRecon(t *testing.T) {
	r := runPJLSession(t, "@PJL INFO VARIABLES\r\n@PJL INFO FILESYS\r\n@PJL INFO PAGECOUNT\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-info-query") {
		t.Errorf("INFO recon not flagged: %v", a)
	}
	cats, _ := r.Meta["pjl_info"].([]string)
	if !containsStr(cats, "VARIABLES") || !containsStr(cats, "FILESYS") {
		t.Errorf("INFO categories not recorded: %v", cats)
	}
}

func TestPJLJobPassword(t *testing.T) {
	r := runPJLSession(t, "@PJL JOB PASSWORD=4321 NAME=\"x\"\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-auth-attempt") {
		t.Errorf("job password not flagged auth-attempt: %v", a)
	}
	if r.Meta["pjl_password"] != "4321" {
		t.Errorf("password not captured: %v", r.Meta["pjl_password"])
	}
}

func TestPJLPostScriptExitserver(t *testing.T) {
	job := "%!PS-Adobe-3.0\nserverdict begin 0 exitserver\nstatusdict begin\n"
	r := runPJLSession(t, job)
	a := pjlAnoms(r)
	if !containsStr(a, "printer-job-received") {
		t.Errorf("raw job not flagged: %v", a)
	}
	if !containsStr(a, "printer-postscript-exitserver") {
		t.Errorf("PostScript exitserver not flagged: %v", a)
	}
}

func TestPJLPostScriptFileOp(t *testing.T) {
	job := "%!PS-Adobe-3.0\n(0:/etc/passwd) (r) file\n(junk) deletefile\n"
	r := runPJLSession(t, job)
	if a := pjlAnoms(r); !containsStr(a, "printer-postscript-fileop") {
		t.Errorf("PostScript file op not flagged: %v", a)
	}
}

func TestPJLEnterLanguage(t *testing.T) {
	r := runPJLSession(t, "@PJL ENTER LANGUAGE=POSTSCRIPT\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-language-switch") {
		t.Errorf("language switch not flagged: %v", a)
	}
	if r.Meta["pjl_language"] != "POSTSCRIPT" {
		t.Errorf("language not captured: %v", r.Meta["pjl_language"])
	}
}

func TestPJLServiceMode(t *testing.T) {
	r := runPJLSession(t, "@PJL DEFAULT SERVICEMODE=1\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-servicemode") {
		t.Errorf("service mode not flagged: %v", a)
	}
}

func TestPJLFirmwareUpgrade(t *testing.T) {
	r := runPJLSession(t, "@PJL UPGRADE SIZE=1024\r\n")
	if a := pjlAnoms(r); !containsStr(a, "printer-firmware-upload") {
		t.Errorf("firmware upgrade not flagged: %v", a)
	}
}

func TestPJLFSDirListDeception(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second, ReadBytes: 8192}
	resC := make(chan Result, 1)
	go func() { r, _ := (&pjl{}).Handle(context.Background(), server, cfg); resC <- r }()
	_, _ = client.Write([]byte("@PJL FSDIRLIST NAME=\"0:\\\" ENTRY=1\r\n"))
	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	if !strings.Contains(string(buf[:n]), "TYPE=DIR") {
		t.Errorf("FSDIRLIST decoy listing missing: %q", string(buf[:n]))
	}
	if a := pjlAnoms(r); !containsStr(a, "printer-filesystem-access") {
		t.Errorf("FSDIRLIST not flagged: %v", a)
	}
}

func TestPJLZebraZPLJob(t *testing.T) {
	// A Zebra label-printer job (ZPL) on the raw port — config-saving
	// control commands must be flagged.
	r := runPJLSession(t, "^XA^JUS^FO50,50^FDhi^FS^XZ\n~JA\n")
	a := pjlAnoms(r)
	if !containsStr(a, "printer-zpl-job") {
		t.Errorf("ZPL job not flagged: %v", a)
	}
	if !containsStr(a, "printer-zpl-config") {
		t.Errorf("ZPL config/destructive command not flagged: %v", a)
	}
}

func TestADSReadDeviceInfo(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&ads{}).Handle(context.Background(), server, cfg); resC <- r }()

	ams := make([]byte, 32)
	// target/source AmsNetId+port left zero except a recognizable target.
	copy(ams[0:6], []byte{192, 168, 0, 1, 1, 1})
	binary.LittleEndian.PutUint16(ams[16:18], adsReadDeviceInfo)
	binary.LittleEndian.PutUint16(ams[18:20], 0x0004) // ADS command
	binary.LittleEndian.PutUint32(ams[28:32], 1)      // invokeId
	frame := make([]byte, 6+len(ams))
	binary.LittleEndian.PutUint32(frame[2:6], uint32(len(ams)))
	copy(frame[6:], ams)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}

	hdr := make([]byte, 6)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	plen := binary.LittleEndian.Uint32(hdr[2:6])
	resp := make([]byte, plen)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	r := <-resC
	if binary.LittleEndian.Uint16(resp[16:18]) != adsReadDeviceInfo {
		t.Errorf("response cmdId wrong: %x", resp[16:18])
	}
	if resp[18]&0x01 == 0 {
		t.Errorf("response flag bit not set: %x", resp[18:20])
	}
	if !strings.Contains(string(resp[32:]), "TwinCAT") {
		t.Errorf("device info missing TwinCAT: % x", resp[32:])
	}
	if r.Meta["ads_command"] != "ReadDeviceInfo" {
		t.Errorf("ads_command = %v", r.Meta["ads_command"])
	}
	if anoms, _ := r.Meta["anomalies"].([]string); !containsStr(anoms, "ics-ads-probe") {
		t.Errorf("not flagged ics-ads-probe: %v", r.Meta["anomalies"])
	}
}

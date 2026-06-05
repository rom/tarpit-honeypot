package handler

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// FTP upload capture + analysis shared by the `ftp` and `ftp_files` handlers.
// A STOR/STOU/APPE pushes an attacker-supplied file onto the decoy; we read a
// bounded copy, checksum it, flag its type / threat traits / drop context, and
// surface the bytes as res.Payload so the sensor's payload pipeline runs full
// classification + the YARA engine + persistence over the captured file.

// readUploadBytes drains up to capN bytes of an FTP data connection (an upload),
// with a short read deadline so a stalled client can't hold the worker.
func readUploadBytes(dc net.Conn, capN int) []byte {
	if capN <= 0 {
		capN = 64 << 10
	}
	_ = dc.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < capN {
		n, err := dc.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(buf) > capN {
		buf = buf[:capN]
	}
	return buf
}

// ftpAnalyzeUpload records checksums and file-type / threat / drop-context
// anomalies for an uploaded file. It is intentionally lightweight (magic bytes
// + a bounded content scan) — deep classification + YARA matching happen in the
// sensor's payload pipeline once the bytes are surfaced as res.Payload.
func ftpAnalyzeUpload(res *Result, path string, buf []byte) {
	if len(buf) == 0 {
		return
	}
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	m := md5.Sum(buf)
	s1 := sha1.Sum(buf)
	s2 := sha256.Sum256(buf)
	res.Meta["ftp_upload_md5"] = hex.EncodeToString(m[:])
	res.Meta["ftp_upload_sha1"] = hex.EncodeToString(s1[:])
	res.Meta["ftp_upload_sha256"] = hex.EncodeToString(s2[:])

	// File-type from magic bytes — an executable / archive / script dropped onto
	// an FTP server is malware staging, not a normal file transfer.
	switch {
	case len(buf) >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F':
		flagAnomaly(res, "ftp-elf-upload")
		flagAnomaly(res, "ftp-executable-upload")
	case len(buf) >= 2 && buf[0] == 'M' && buf[1] == 'Z':
		flagAnomaly(res, "ftp-pe-upload")
		flagAnomaly(res, "ftp-executable-upload")
	case len(buf) >= 4 && ftpIsMachO(buf):
		flagAnomaly(res, "ftp-macho-upload")
		flagAnomaly(res, "ftp-executable-upload")
	case len(buf) >= 4 && buf[0] == 'P' && buf[1] == 'K' && buf[2] == 0x03 && buf[3] == 0x04:
		flagAnomaly(res, "ftp-archive-upload")
	case len(buf) >= 2 && buf[0] == '#' && buf[1] == '!':
		flagAnomaly(res, "ftp-script-upload")
	}

	// Content scan (bounded): shell-dropper one-liners, web shells, private keys.
	n := len(buf)
	if n > 8192 {
		n = 8192
	}
	head := buf[:n]
	low := bytes.ToLower(head)
	if ftpHasKeyMaterial(head) {
		flagAnomaly(res, "ftp-keymaterial-upload")
	}
	if ftpLooksDropper(low) {
		flagAnomaly(res, "ftp-script-dropper-upload")
		flagAnomaly(res, "ftp-script-upload")
	}
	if ftpLooksWebshell(low) {
		flagAnomaly(res, "ftp-webshell-upload")
	}

	// Drop into a classic anonymous-writable path (/pub, /incoming, /upload, …)
	// is the canonical anon-FTP malware-staging pattern.
	if ftpAnonWritablePath(path) {
		flagAnomaly(res, "ftp-anon-writable-drop")
	}
}

func ftpIsMachO(b []byte) bool {
	be := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	switch be {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE:
		return true
	}
	return false
}

// ftpHasKeyMaterial reports whether the bytes look like uploaded private-key /
// SSH key material (a PEM private key, an OpenSSH/PuTTY key, or an authorized
// public-key dump) — a high-signal accidental/credential-staging upload.
func ftpHasKeyMaterial(b []byte) bool {
	for _, m := range [][]byte{
		[]byte("PRIVATE KEY-----"),
		[]byte("BEGIN OPENSSH PRIVATE KEY"),
		[]byte("PuTTY-User-Key-File"),
	} {
		if bytes.Contains(b, m) {
			return true
		}
	}
	return bytes.HasPrefix(b, []byte("ssh-rsa ")) ||
		bytes.HasPrefix(b, []byte("ssh-ed25519 ")) ||
		bytes.HasPrefix(b, []byte("ecdsa-sha2-"))
}

// ftpLooksDropper matches a download-and-execute shell dropper in (lowercased)
// uploaded bytes.
func ftpLooksDropper(low []byte) bool {
	fetch := bytes.Contains(low, []byte("wget ")) || bytes.Contains(low, []byte("curl ")) ||
		bytes.Contains(low, []byte("tftp ")) || bytes.Contains(low, []byte("/dev/tcp/"))
	exec := bytes.Contains(low, []byte("chmod +x")) || bytes.Contains(low, []byte("chmod 777")) ||
		bytes.Contains(low, []byte("/bin/sh")) || bytes.Contains(low, []byte("/tmp/"))
	return fetch && exec
}

// ftpLooksWebshell matches common PHP/JSP/ASP web-shell command primitives.
func ftpLooksWebshell(low []byte) bool {
	for _, m := range [][]byte{
		[]byte("<?php"), []byte("eval($_"), []byte("eval(request"), []byte("system($_"),
		[]byte("shell_exec"), []byte("passthru("), []byte("runtime.getruntime().exec"),
		[]byte("<%eval"), []byte("<%execute"), []byte("processbuilder"),
	} {
		if bytes.Contains(low, m) {
			// Require a PHP/JSP/ASP shape to avoid matching benign mentions.
			if bytes.Contains(low, []byte("<?php")) || bytes.Contains(low, []byte("<%")) ||
				bytes.Contains(low, []byte("getruntime")) || bytes.Contains(low, []byte("processbuilder")) {
				return true
			}
		}
	}
	return false
}

// ftpAnonWritablePath reports whether an upload path is a classic
// anonymous-writable FTP directory where dropped files are public-by-default.
func ftpAnonWritablePath(p string) bool {
	p = strings.ToLower(p)
	for _, d := range []string{"/pub", "/incoming", "/upload", "/uploads", "/tmp", "/var/ftp", "/srv/ftp", "/home/ftp"} {
		if p == d || strings.HasPrefix(p, d+"/") || strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// Package fakefiles provides believable decoy file listings + content
// that file-serving handlers (ftp_files, future http directory
// listing, smb, tftp) present to attackers. The files don't exist on
// disk — names, sizes, mtimes, and a small synthesized body are
// generated deterministically per deployment so two sensors show
// different-but-stable trees.
//
// Some entries are deliberate canary bait: a download of
// `backup/credentials.txt` or `id_rsa` is a far stronger signal than
// a directory listing, so handlers flag those retrievals as the
// `honeyfile-download` anomaly (ATT&CK T1083 File and Directory
// Discovery + T1552.001 Credentials in Files).
package fakefiles

import (
	"fmt"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

// File is one decoy file entry.
type File struct {
	Name    string
	Size    int64
	ModTime time.Time
	// Bait marks files whose retrieval is a high-signal event (creds,
	// keys, backups, config dumps). Handlers flag downloads of these.
	Bait bool
	// body is the synthesized content served on retrieval. Generated
	// lazily so a 200 MB "backup.tar.gz" doesn't sit in memory.
	body func() []byte
}

// Body returns the synthesized file content, capped at maxBytes so a
// handler never streams an unbounded decoy.
func (f File) Body(maxBytes int) []byte {
	if f.body == nil {
		return nil
	}
	b := f.body()
	if maxBytes > 0 && len(b) > maxBytes {
		return b[:maxBytes]
	}
	return b
}

// Set is a named, deterministically-generated collection of decoy
// files for one deployment.
type Set struct {
	files []File
}

// Default builds the standard decoy tree for the given identity. The
// mtimes + sizes are derived from the deployment seed so they're
// stable per sensor but differ across deployments.
func Default(id *identity.Identity) *Set {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var seedShift int64
	if id != nil {
		seedShift = int64(id.Uint32("fakefiles-mtime")) % (86400 * 600)
	}
	mt := func(daysAgo int) time.Time {
		return base.Add(time.Duration(daysAgo)*24*time.Hour - time.Duration(seedShift)*time.Second)
	}
	sz := func(label string, min, span int64) int64 {
		if id == nil {
			return min + span/2
		}
		return min + int64(id.Uint32("fakefiles-size-"+label))%span
	}

	files := []File{
		{Name: "README.txt", Size: sz("readme", 200, 800), ModTime: mt(120), body: func() []byte {
			return []byte("Internal file server. Authorized personnel only.\r\nContact: it-ops@example.internal\r\n")
		}},
		{Name: "backup", Size: 4096, ModTime: mt(30)},          // directory
		{Name: "documents", Size: 4096, ModTime: mt(45)},       // directory
		{Name: "incoming", Size: 4096, ModTime: mt(2)},         // directory
		{Name: "database_dump.sql", Size: sz("sql", 1 << 20, 8 << 20), ModTime: mt(7), Bait: true, body: func() []byte {
			return []byte("-- MySQL dump 10.13\n-- Host: db01    Database: prod\n-- ------------------------------------------------------\nCREATE TABLE `users` (`id` int, `email` varchar(255), `pwhash` varchar(60));\n-- (truncated)\n")
		}},
		{Name: "id_rsa", Size: 2602, ModTime: mt(200), Bait: true, body: func() []byte {
			// A syntactically-shaped but non-functional decoy key.
			return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
				"DECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOYDECOY\n" +
				"-----END OPENSSH PRIVATE KEY-----\n")
		}},
		{Name: "credentials.txt", Size: sz("creds", 400, 2000), ModTime: mt(15), Bait: true, body: func() []byte {
			return []byte("# service account list (rotate quarterly)\r\nsvc-backup:Backup#2024!\r\nsvc-monitor:M0nit0r123\r\nadmin:see-keepass\r\n")
		}},
		{Name: "config.bak", Size: sz("config", 2000, 6000), ModTime: mt(60), Bait: true, body: func() []byte {
			return []byte("hostname core-sw-01\r\nenable secret 5 $1$decoy$abcdefghijklmnop.\r\nsnmp-server community public RO\r\n")
		}},
	}
	return &Set{files: files}
}

// List returns the directory entries sorted by name (directories +
// files mixed, like a real `ls`). dir is the requested path relative
// to the root; only the top level + a couple of canned subdirs exist.
func (s *Set) List(dir string) []File {
	switch normalizeDir(dir) {
	case "", "/", ".":
		out := append([]File(nil), s.files...)
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	case "backup", "/backup":
		return []File{
			{Name: "..", Size: 4096, ModTime: s.files[0].ModTime},
			{Name: "db-2024-05-18.tar.gz", Size: 48 << 20, ModTime: s.files[0].ModTime, Bait: true, body: func() []byte {
				return []byte("\x1f\x8b\x08\x00decoy-gzip-header")
			}},
			{Name: "etc-backup.tar.gz", Size: 12 << 20, ModTime: s.files[0].ModTime, Bait: true, body: func() []byte {
				return []byte("\x1f\x8b\x08\x00decoy-gzip-header")
			}},
		}
	case "documents", "/documents":
		return []File{
			{Name: "..", Size: 4096, ModTime: s.files[0].ModTime},
			{Name: "network-diagram.vsdx", Size: 240 << 10, ModTime: s.files[0].ModTime},
			{Name: "passwords.xlsx", Size: 18 << 10, ModTime: s.files[0].ModTime, Bait: true, body: func() []byte {
				return []byte("PK\x03\x04decoy-xlsx")
			}},
		}
	case "incoming", "/incoming":
		return []File{{Name: "..", Size: 4096, ModTime: s.files[0].ModTime}}
	}
	return nil
}

// Lookup returns the File for an exact name in a directory (used by the
// retrieval path), and whether it was found + is a regular file.
func (s *Set) Lookup(dir, name string) (File, bool) {
	for _, f := range s.List(dir) {
		if f.Name == name {
			return f, f.body != nil
		}
	}
	return File{}, false
}

func normalizeDir(d string) string {
	for len(d) > 1 && d[len(d)-1] == '/' {
		d = d[:len(d)-1]
	}
	return d
}

// FormatUnixListing renders a `File` as an `ls -l`-style line for FTP
// LIST. Directories show a leading 'd'; bait files are not visually
// distinguished (that would tip off the attacker).
func FormatUnixListing(f File) string {
	perm := "-rw-r--r--"
	if f.body == nil && f.Size == 4096 {
		perm = "drwxr-xr-x"
	}
	return fmt.Sprintf("%s    1 ftp      ftp      %10d %s %s",
		perm, f.Size, f.ModTime.Format("Jan 02 15:04"), f.Name)
}

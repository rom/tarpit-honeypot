package shell

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Per-attacker overlay persistence. Each source IP gets one JSON file under
// <data_dir>/shell-fs/, loaded at the start of an interactive session and saved
// at the end — so the filesystem the attacker mutated (dropped payloads, created
// dirs, edited files) is still there when they reconnect, and the operator keeps
// the dropper names + URLs across sessions. Bounded: the directory is pruned to
// a file ceiling so a spray of source IPs can't fill the disk.

const (
	vfsDirName  = "shell-fs"
	vfsMaxFiles = 4000 // distinct attacker filesystems retained
)

// LoadFS returns the persisted overlay for srcIP, or a fresh one. dir is the
// sensor data dir; an empty dir (or any error) yields an in-memory-only FS, so
// the shell still works, just without cross-session persistence.
func LoadFS(dir, srcIP, home string) *FS {
	fs := NewFS(home)
	if dir == "" || srcIP == "" {
		return fs
	}
	p := vfsPath(dir, srcIP)
	b, err := os.ReadFile(p)
	if err != nil {
		return fs
	}
	var loaded FS
	if json.Unmarshal(b, &loaded) != nil {
		return fs
	}
	loaded.normalize()
	if home != "" && loaded.Home == "" {
		loaded.Home = home
	}
	return &loaded
}

// SaveFS persists fs for srcIP. No-op when dir/srcIP are empty or the overlay is
// empty (nothing the attacker changed → nothing worth a file).
func SaveFS(dir, srcIP string, fs *FS) error {
	if dir == "" || srcIP == "" || fs == nil {
		return nil
	}
	if len(fs.Nodes) == 0 && len(fs.Deleted) == 0 && len(fs.Downloads) == 0 {
		return nil
	}
	base := filepath.Join(dir, vfsDirName)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(fs)
	if err != nil {
		return err
	}
	p := vfsPath(dir, srcIP)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	pruneVFSDir(base, vfsMaxFiles)
	return nil
}

// vfsPath is the per-IP overlay file path (IP sanitized for a filename).
func vfsPath(dir, srcIP string) string {
	return filepath.Join(dir, vfsDirName, sanitizeIP(srcIP)+".json")
}

func sanitizeIP(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r == '.' || r == ':':
			b.WriteByte('_')
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 80 {
		out = out[:80]
	}
	if out == "" {
		out = "unknown"
	}
	return out
}

// pruneVFSDir keeps at most max overlay files, deleting the oldest by mtime.
func pruneVFSDir(base string, max int) {
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) <= max {
		return
	}
	type fi struct {
		name string
		mod  int64
	}
	files := make([]fi, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{e.Name(), info.ModTime().UnixNano()})
	}
	if len(files) <= max {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })
	for _, f := range files[:len(files)-max] {
		_ = os.Remove(filepath.Join(base, f.name))
	}
}

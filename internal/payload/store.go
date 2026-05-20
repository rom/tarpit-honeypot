package payload

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Store persists harvested artifacts to <dir> with an oldest-first total
// size cap. Filenames are <sha256>.<ext> so duplicate drops dedup
// automatically. Safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	dir      string
	maxBytes int   // per-artifact cap
	maxTotal int64 // directory cap
}

// NewStore returns a payload store rooted at dir. maxBytes <= 0 defaults
// to 1 MiB; maxTotalMB <= 0 defaults to 256 MB. mkdir failures are
// returned so the caller can disable harvesting cleanly.
func NewStore(dir string, maxBytes, maxTotalMB int) (*Store, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if maxTotalMB <= 0 {
		maxTotalMB = 256
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Store{dir: dir, maxBytes: maxBytes, maxTotal: int64(maxTotalMB) << 20}, nil
}

// Persist writes the artifact bytes (truncated to maxBytes) and returns
// the on-disk path. Already-present hashes are not rewritten. Enforces
// the directory cap by deleting the oldest files first.
func (s *Store) Persist(a Artifact) (string, error) {
	if s == nil || len(a.Bytes) == 0 {
		return "", nil
	}
	b := a.Bytes
	if len(b) > s.maxBytes {
		b = b[:s.maxBytes]
	}
	name := a.SHA256 + extFor(a.Kind)
	path := filepath.Join(s.dir, name)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(path); err == nil {
		return path, nil // dedup: identical artifact already stored
	}
	if err := os.WriteFile(path, b, 0o640); err != nil {
		return "", err
	}
	s.enforceCap()
	return path, nil
}

// enforceCap deletes oldest files until the directory is under maxTotal.
// Caller holds s.mu.
func (s *Store) enforceCap() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		size int64
		mod  int64
	}
	var files []fi
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{filepath.Join(s.dir, e.Name()), info.Size(), info.ModTime().UnixNano()})
		total += info.Size()
	}
	if total <= s.maxTotal {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })
	for _, f := range files {
		if total <= s.maxTotal {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
}

func extFor(kind string) string {
	switch kind {
	case KindELF:
		return ".elf"
	case KindPE:
		return ".exe"
	case KindMachO:
		return ".macho"
	case KindArchive:
		return ".zip"
	case KindScript:
		return ".sh"
	case KindShellcode:
		return ".bin"
	default:
		return ".dat"
	}
}

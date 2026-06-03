package docs

import (
	"io/fs"
	"strings"
	"testing"
)

// The embedded docs FS must actually carry the Markdown guides the web UI
// serves (a //go:embed that matches nothing silently ships an empty FS).
func TestEmbeddedDocsPresent(t *testing.T) {
	var mds []string
	err := fs.WalkDir(FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			mds = append(mds, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mds) == 0 {
		t.Fatal("no .md files embedded in docs.FS")
	}
	// config.md is a core guide the UI links to — make sure it's there + non-empty.
	b, err := FS.ReadFile("config.md")
	if err != nil {
		t.Fatalf("config.md not embedded: %v", err)
	}
	if len(b) < 100 {
		t.Errorf("config.md suspiciously small (%d bytes)", len(b))
	}
}

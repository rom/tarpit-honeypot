package fakefiles

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

func TestDefaultListingHasBaitFiles(t *testing.T) {
	s := Default(identity.New("seed-1"))
	root := s.List("/")
	if len(root) == 0 {
		t.Fatal("root listing is empty")
	}
	baitNames := map[string]bool{}
	for _, f := range root {
		if f.Bait {
			baitNames[f.Name] = true
		}
	}
	for _, want := range []string{"id_rsa", "credentials.txt", "config.bak", "database_dump.sql"} {
		if !baitNames[want] {
			t.Errorf("expected bait file %q in root listing", want)
		}
	}
}

func TestDeterministicPerDeployment(t *testing.T) {
	a := Default(identity.New("seed-A")).List("/")
	b := Default(identity.New("seed-B")).List("/")
	// Same file set, but at least one size should differ between
	// deployments (mtimes/sizes are seed-derived).
	differ := false
	for i := range a {
		if i < len(b) && a[i].Name == b[i].Name && a[i].Size != b[i].Size {
			differ = true
		}
	}
	if !differ {
		t.Errorf("two deployments produced identical file sizes; expected divergence")
	}
	// Same deployment is stable.
	a2 := Default(identity.New("seed-A")).List("/")
	for i := range a {
		if a[i].Size != a2[i].Size {
			t.Errorf("same deployment produced different sizes across calls")
		}
	}
}

func TestLookupBaitBody(t *testing.T) {
	s := Default(identity.New("seed-1"))
	f, ok := s.Lookup("/", "id_rsa")
	if !ok {
		t.Fatal("id_rsa not found / not a regular file")
	}
	if !f.Bait {
		t.Errorf("id_rsa should be a bait file")
	}
	body := f.Body(4096)
	if !strings.Contains(string(body), "PRIVATE KEY") {
		t.Errorf("id_rsa body does not look like a key: %q", body)
	}
}

func TestSubdirListing(t *testing.T) {
	s := Default(identity.New("seed-1"))
	backup := s.List("backup")
	if len(backup) == 0 {
		t.Fatal("backup subdir empty")
	}
	foundTar := false
	for _, f := range backup {
		if strings.HasSuffix(f.Name, ".tar.gz") {
			foundTar = true
		}
	}
	if !foundTar {
		t.Errorf("backup subdir should contain a .tar.gz")
	}
}

func TestBodyCap(t *testing.T) {
	s := Default(identity.New("seed-1"))
	f, _ := s.Lookup("/", "database_dump.sql")
	capped := f.Body(10)
	if len(capped) > 10 {
		t.Errorf("Body(10) returned %d bytes", len(capped))
	}
}

func TestUnixListingFormat(t *testing.T) {
	s := Default(identity.New("seed-1"))
	for _, f := range s.List("/") {
		line := FormatUnixListing(f)
		if !strings.Contains(line, f.Name) {
			t.Errorf("listing line missing name: %q", line)
		}
		// Directories (Size==4096, no body) should show 'd' prefix.
		if f.Name == "backup" && !strings.HasPrefix(line, "d") {
			t.Errorf("directory %q not shown as dir: %q", f.Name, line)
		}
	}
}

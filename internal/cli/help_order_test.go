package cli

import (
	"io"
	"os"
	"sort"
	"strings"
	"testing"
)

// `--help` must list subcommands in alphabetical order.
func TestHelpListsSubcommandsAlphabetically(t *testing.T) {
	old := os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wp
	_ = Dispatch([]string{"--help"})
	_ = wp.Close()
	os.Stderr = old
	out, _ := io.ReadAll(rp)

	var names []string
	inBlock := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "subcommands:") {
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		if strings.TrimSpace(line) == "" {
			break // end of the subcommand block
		}
		if !strings.HasPrefix(line, "  ") {
			break
		}
		names = append(names, strings.Fields(line)[0])
	}
	if len(names) < 10 {
		t.Fatalf("expected the full subcommand list, parsed only %d: %v", len(names), names)
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for i := range names {
		if names[i] != sorted[i] {
			t.Fatalf("subcommands not alphabetical at %d: got %v", i, names)
		}
	}
	// Spot-check a couple are present.
	have := strings.Join(names, " ")
	for _, w := range []string{"analyze", "run", "version", "validate-config"} {
		if !strings.Contains(have, w) {
			t.Errorf("missing subcommand %q", w)
		}
	}
}

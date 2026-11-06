package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rom/tarpit-honeypot/internal/lure"
)

// cmdGenLures writes believable, structurally-correct secret/credential decoy
// files (fake ~/.aws/credentials, id_rsa, .env, kubeconfig, service-account
// JSON, …) so an operator can seed honeypot loot — fake home dirs, served
// downloads, decoy mounts, agent bait. Attackers and agentic tooling grep for
// exactly these filenames because they convert straight to access. Every file's
// headline value is a canary: if it reappears in a captured auth attempt it
// proves the loot was taken and acted on.
func cmdGenLures(args []string) error {
	fs := flag.NewFlagSet("gen-lures", flag.ContinueOnError)
	dir := fs.String("dir", "./lures", "output directory for the decoy files")
	seed := fs.String("seed", "", "deterministic seed (stable decoys per deployment); random if empty")
	kind := fs.String("kind", "all", "lure kind, or 'all'")
	list := fs.Bool("list", false, "list the supported lure kinds and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		fmt.Println("supported lure kinds:")
		for _, k := range lure.Kinds() {
			fmt.Printf("  %s\n", k)
		}
		return nil
	}

	s := *seed
	if s == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		s = hex.EncodeToString(b)
		fmt.Printf("seed: %s  (pass --seed %s to reproduce these exact decoys)\n", s, s)
	}

	var lures []lure.Lure
	if *kind == "all" {
		lures = lure.All(s)
	} else {
		l, err := lure.Generate(*kind, s)
		if err != nil {
			return err
		}
		lures = []lure.Lure{l}
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	fmt.Printf("%-20s %-22s %s\n", "KIND", "FILE", "CANARY (track this value)")
	for _, l := range lures {
		// Guard the filename to the output dir (no traversal from a kind's name).
		name := filepath.Base(l.Filename)
		p := filepath.Join(*dir, name)
		if err := os.WriteFile(p, l.Content, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		fmt.Printf("%-20s %-22s %s\n", l.Kind, name, clipCanary(l.Canary))
	}
	fmt.Printf("\n%d credential lure file(s) written to %s\n", len(lures), *dir)
	fmt.Println("Place them in honeypot loot (fake home dirs / served downloads / decoy mounts) and")
	fmt.Println("register the canary values with your SIEM so a stolen secret reappearing fires an alert.")
	return nil
}

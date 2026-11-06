package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/walletdecoy"
)

// cmdGenWalletDecoys writes believable, structurally-correct cryptocurrency
// wallet decoy files to a directory so an operator can seed honeypot loot (fake
// home dirs, served downloads, decoy mounts). Every value a file exposes
// (address / key / mnemonic) is a canary: if it later reappears in captured
// traffic it proves the loot was taken.
func cmdGenWalletDecoys(args []string) error {
	fs := flag.NewFlagSet("gen-wallet-decoys", flag.ContinueOnError)
	dir := fs.String("dir", "./wallet-decoys", "output directory for the decoy files")
	seed := fs.String("seed", "", "deterministic seed (stable decoys per deployment); random if empty")
	kind := fs.String("kind", "all", "wallet kind, or 'all'")
	list := fs.Bool("list", false, "list the supported wallet kinds and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		fmt.Println("supported wallet kinds:")
		for _, k := range walletdecoy.Kinds() {
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

	var wallets []walletdecoy.Wallet
	if *kind == "all" {
		wallets = walletdecoy.All(s)
	} else {
		w, err := walletdecoy.Generate(*kind, s)
		if err != nil {
			return err
		}
		wallets = []walletdecoy.Wallet{w}
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	fmt.Printf("%-18s %-34s %s\n", "KIND", "FILE", "CANARY (track this value)")
	for _, w := range wallets {
		// Guard the filename to the output dir (no traversal from a kind's name).
		name := filepath.Base(w.Filename)
		p := filepath.Join(*dir, name)
		if err := os.WriteFile(p, w.Content, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		fmt.Printf("%-18s %-34s %s\n", w.Kind, name, clipCanary(w.Canary))
	}
	fmt.Printf("\n%d decoy wallet file(s) written to %s\n", len(wallets), *dir)
	fmt.Println("Place them in honeypot loot (fake home dirs / served downloads) and register the")
	fmt.Println("canary values with your SIEM so an exfiltrated key reappearing fires an alert.")
	return nil
}

func clipCanary(s string) string {
	if len(s) > 44 {
		return s[:41] + "..."
	}
	return strings.TrimSpace(s)
}

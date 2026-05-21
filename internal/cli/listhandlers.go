package cli

import (
	"flag"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdListHandlers prints the protocol handlers the sensor ships, split by
// transport. These are exactly the values accepted in a listener's
// `handler:` field — the list is sourced from the same whitelist the
// config validator enforces, so it can never drift out of sync.
func cmdListHandlers(args []string) error {
	fs := flag.NewFlagSet("list-handlers", flag.ContinueOnError)
	proto := fs.String("proto", "", "limit to one transport: tcp | udp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *proto {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("--proto must be tcp or udp, got %q", *proto)
	}

	tcp := config.TCPHandlerNames()
	udp := config.UDPHandlerNames()
	if *proto == "" || *proto == "tcp" {
		fmt.Printf("tcp handlers (%d):\n", len(tcp))
		printColumns(tcp)
	}
	if *proto == "" {
		fmt.Println()
	}
	if *proto == "" || *proto == "udp" {
		fmt.Printf("udp handlers (%d):\n", len(udp))
		printColumns(udp)
	}
	return nil
}

// printColumns prints names in 4 aligned columns for compact scanning.
func printColumns(names []string) {
	const cols = 4
	for i, n := range names {
		fmt.Printf("  %-18s", n)
		if (i+1)%cols == 0 {
			fmt.Println()
		}
	}
	if len(names)%cols != 0 {
		fmt.Println()
	}
}

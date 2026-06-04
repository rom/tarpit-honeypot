package cli

import (
	"flag"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/archeservice"
)

// cmdListArcheservices prints the built-in service roles and the
// (port/proto/handler) set each one stands up. Use a role in an
// `archeservices:` config entry together with an `archetype:` so the
// expanded listeners answer with the right software identity. Read-only,
// no config or network needed.
func cmdListArcheservices(args []string) error {
	fs := flag.NewFlagSet("list-archeservices", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// `list-archeservices <role>` → just that role's detail.
	names := archeservice.Names()
	if r := fs.Arg(0); r != "" {
		svcs, ok := archeservice.Lookup(r)
		if !ok {
			return fmt.Errorf("unknown role %q (run `tarpit-honeypot list-archeservices`)", r)
		}
		names = []string{r}
		printArcheservice(r, svcs)
		return nil
	}
	for i, n := range names {
		svcs, _ := archeservice.Lookup(n)
		printArcheservice(n, svcs)
		if i < len(names)-1 {
			fmt.Println()
		}
	}
	fmt.Printf("\n%d role(s). Pair one with an archetype in an archeservices: config entry.\n", len(names))
	return nil
}

func printArcheservice(name string, svcs []archeservice.Service) {
	fmt.Printf("%s\n", name)
	fmt.Printf("  %-4s %s\n", "cpe:", archeservice.CPE(name))
	for _, s := range svcs {
		note := ""
		if s.Note != "" {
			note = "  # " + s.Note
		}
		fmt.Printf("  %-4s :%-6d %s%s\n", s.Proto, s.Port, s.Handler, note)
	}
}

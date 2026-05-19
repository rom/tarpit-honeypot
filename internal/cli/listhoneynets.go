package cli

import (
	"flag"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

// cmdListHoneynets prints the configured honeynet topology in a human-
// readable form: one network header per honeynet, indented hosts with
// their services. Validates the config at load time so the operator
// catches mistakes before deploying.
func cmdListHoneynets(args []string) error {
	fs := flag.NewFlagSet("list-honeynets", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if len(cfg.Honeynets) == 0 {
		fmt.Println("(no honeynets configured)")
		return nil
	}
	// Build a topology so we can show the per-host derived identity
	// alongside each entry. We use a throwaway in-memory identity here
	// (deployment_id from the config) so we don't touch the data_dir.
	id := identity.New(cfg.Sensor.DeploymentID)
	jit := jitter.New(0, 0)
	arch := archetype.Lookup(cfg.Sensor.Archetype)
	topo, err := honeynet.Build(cfg.Honeynets, id, jit, cfg.Sensor.DataDir, cfg.URLCanaries, cfg.Sensor.TLSRotate.Days, arch)
	if err != nil {
		return err
	}
	for _, n := range topo.Networks() {
		fmt.Printf("# %s  cidr=%s gateway=%s dns=%s domain=%s\n",
			n.ID, n.CIDR, n.Gateway, n.DNS, n.Domain)
		for _, h := range topo.HostsInNetwork(n.ID) {
			fmt.Printf("  %s  mac=%s  hostname=%-24s os=%-8s identity=%s\n",
				h.IP, h.MACString(), h.Hostname, h.OS, h.Identity.Seed())
			for _, s := range h.Services {
				fmt.Printf("    :%d  handler=%s\n", s.Port, s.Handler)
			}
		}
	}
	return nil
}

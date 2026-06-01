package blocklist

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// nftRunner is the production Runner: it shells out to the `nft` binary.
// Linux + nft + CAP_NET_ADMIN are required; elsewhere Run returns a clear
// error so the caller logs and continues (the sensor still observes — it just
// can't enforce blocks).
type nftRunner struct{}

func (nftRunner) Run(ctx context.Context, stdin string, args ...string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("blocklist: nftables blocking is only supported on linux")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("blocklist: nft not found on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, nft, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("blocklist: nft %s failed: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

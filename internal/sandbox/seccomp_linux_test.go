//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// childSkip is the exit code a subprocess uses to signal "this kernel /
// container can't apply the confinement" so the parent skips instead of
// failing.
const childSkip = 42

func TestBuildSeccompProgramJumpsLandOnDeny(t *testing.T) {
	blocked := []int{unix.SYS_EXECVE, unix.SYS_PTRACE, unix.SYS_MOUNT}
	prog := buildSeccompProgram(0xC000003E /* x86_64 */, blocked)
	denyIdx := len(prog) - 1
	allowIdx := denyIdx - 1

	// Arch check at index 1: jf must land on deny.
	if got := 1 + 1 + int(prog[1].Jf); got != denyIdx {
		t.Errorf("arch-mismatch jump lands at %d; want deny %d", got, denyIdx)
	}
	// Each blocked syscall jeq (indices 3..) jt must land on deny.
	for i := range blocked {
		idx := 3 + i
		if got := idx + 1 + int(prog[idx].Jt); got != denyIdx {
			t.Errorf("blocked[%d] jump lands at %d; want deny %d", i, got, denyIdx)
		}
	}
	if prog[allowIdx].K != uint32(unix.SECCOMP_RET_ALLOW) {
		t.Errorf("allow instr K = %#x; want SECCOMP_RET_ALLOW", prog[allowIdx].K)
	}
	if prog[denyIdx].K&uint32(unix.SECCOMP_RET_ERRNO) == 0 {
		t.Errorf("deny instr K = %#x; want SECCOMP_RET_ERRNO bits", prog[denyIdx].K)
	}
}

func TestAuditArchKnown(t *testing.T) {
	if _, ok := auditArch(); !ok {
		t.Skip("seccomp test arch not in the supported set")
	}
}

// TestSeccompBlocksExecve installs the real filter in a subprocess and
// confirms execve is denied with EPERM (the headline guarantee: a parser
// 0-day can't spawn a shell).
func TestSeccompBlocksExecve(t *testing.T) {
	if os.Getenv("SANDBOX_SECCOMP_CHILD") == "1" {
		if err := applySeccomp(); err != nil {
			os.Exit(childSkip)
		}
		err := unix.Exec(os.Args[0], []string{"x"}, os.Environ())
		// Exec only returns on failure; we want EPERM from seccomp.
		if errors.Is(err, unix.EPERM) {
			os.Exit(0)
		}
		os.Exit(4)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompBlocksExecve")
	cmd.Env = append(os.Environ(), "SANDBOX_SECCOMP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return // child exited 0: execve was blocked with EPERM
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == childSkip {
		t.Skip("seccomp not applicable in this environment")
	}
	t.Fatalf("seccomp child failed: %v\n%s", err, out)
}

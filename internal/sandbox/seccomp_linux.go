//go:build linux

package sandbox

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// applySeccomp installs a seccomp-bpf filter that DENIES (EPERM) a small
// set of syscalls the honeypot never legitimately makes. A denylist
// (default-allow) is deliberate: it cannot crash the Go runtime on an
// unforeseen libc path the way a tight allowlist can, while still
// neutralizing the things that matter most for a target host — spawning
// a shell, debugging another process, loading a kernel module, mounting
// a filesystem, or rebooting the box. The filter is a one-way ratchet
// installed after PR_SET_NO_NEW_PRIVS so it works without privilege.
func applySeccomp() error {
	arch, ok := auditArch()
	if !ok {
		return fmt.Errorf("seccomp: unsupported GOARCH %q", runtime.GOARCH)
	}
	filter := buildSeccompProgram(arch, blockedSyscalls())

	// Required for an unprivileged process to install a filter.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER), 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return fmt.Errorf("seccomp: SECCOMP_SET_MODE_FILTER: %w", errno)
	}
	return nil
}

// buildSeccompProgram assembles the classic BPF denylist program. The
// layout is:
//
//	[0]        load seccomp_data.arch (offset 4)
//	[1]        if arch != expected -> deny (32-bit bypass guard)
//	[2]        load seccomp_data.nr  (offset 0)
//	[3..3+n-1] if nr == blocked[i]   -> deny
//	[n+3]      return ALLOW
//	[n+4]      return ERRNO(EPERM)   (deny)
func buildSeccompProgram(arch uint32, blocked []int) []unix.SockFilter {
	const (
		offNR   = 0
		offArch = 4
	)
	denyK := uint32(unix.SECCOMP_RET_ERRNO) | (uint32(unix.EPERM) & 0x0000ffff)
	n := len(blocked)
	denyIdx := n + 4
	filter := make([]unix.SockFilter, 0, denyIdx+1)

	filter = append(filter, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch})
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch,
		Jt: 0, Jf: uint8(denyIdx - 1 - 1),
	})
	filter = append(filter, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offNR})
	for i, nr := range blocked {
		idx := 3 + i
		filter = append(filter, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(nr),
			Jt: uint8(denyIdx - 1 - idx), Jf: 0,
		})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ALLOW)})
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: denyK})
	return filter
}

// auditArch maps the build GOARCH to the AUDIT_ARCH_* token the filter
// pins against. unix.SYS_* numbers are already the correct values for
// the target arch (the unix package is built per-GOARCH).
func auditArch() (uint32, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return uint32(unix.AUDIT_ARCH_X86_64), true
	case "arm64":
		return uint32(unix.AUDIT_ARCH_AARCH64), true
	case "arm":
		return uint32(unix.AUDIT_ARCH_ARM), true
	case "386":
		return uint32(unix.AUDIT_ARCH_I386), true
	}
	return 0, false
}

// blockedSyscalls is the denylist: things a connection-level honeypot
// never does, but an attacker who lands code execution very much wants.
// Notably NOT blocked: socket/bind/setsockopt (listeners + AF_PACKET
// responders), clone/clone3 (Go threads), setresuid/setgid (privdrop),
// inotify/fanotify (file canaries), open/read/write (handlers).
func blockedSyscalls() []int {
	return []int{
		unix.SYS_EXECVE,            // spawn a program / shell
		unix.SYS_EXECVEAT,          // spawn a program (fd-relative)
		unix.SYS_PTRACE,            // debug / inject into other processes
		unix.SYS_PROCESS_VM_READV,  // read another process's memory
		unix.SYS_PROCESS_VM_WRITEV, // write another process's memory
		unix.SYS_KEXEC_LOAD,        // load a replacement kernel
		unix.SYS_INIT_MODULE,       // load a kernel module
		unix.SYS_FINIT_MODULE,      // load a kernel module (fd)
		unix.SYS_DELETE_MODULE,     // unload a kernel module
		unix.SYS_MOUNT,             // mount a filesystem
		unix.SYS_UMOUNT2,           // unmount
		unix.SYS_PIVOT_ROOT,        // change root
		unix.SYS_CHROOT,            // change root
		unix.SYS_SETNS,             // join a namespace
		unix.SYS_UNSHARE,           // create a namespace
		unix.SYS_REBOOT,            // reboot / power off
		unix.SYS_SWAPON,            // enable swap
		unix.SYS_SWAPOFF,           // disable swap
		unix.SYS_BPF,               // load eBPF programs
		unix.SYS_PERF_EVENT_OPEN,   // perf / tracing
	}
}

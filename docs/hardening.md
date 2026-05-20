# Hardening & self-confinement

The sensor is, by design, an exposed target. It is built to be a *safe*
target through defense-in-depth: hostile input is bounds-checked and
output sanitized in code, UDP handlers never amplify, and the process can
be confined by several composable, independent layers. Turn on as many as
your platform supports.

| Layer | Where | Enforced by | Platform |
|---|---|---|---|
| Privilege drop | `sensor.drop_user` / `drop_group` | the sensor (`setresuid`) | Linux + macOS |
| seccomp syscall filter | `sensor.sandbox.seccomp` | kernel (in-process) | Linux |
| Landlock FS restriction | `sensor.sandbox.landlock` | kernel (in-process) | Linux 5.13+ |
| AppArmor profile | `packaging/apparmor/` | host LSM | Linux (AppArmor) |
| SELinux policy module | `packaging/selinux/` | host LSM | Linux (SELinux) |
| systemd sandboxing | `packaging/systemd/` | systemd/kernel | Linux + systemd |

The in-process layers (seccomp + Landlock) and the host-LSM layers
(AppArmor / SELinux) express the *same intent* — read config, write only
the data dir, talk to the network, never spawn a process — so use
whichever your distro enforces, or both.

## Privilege drop

Bind privileged ports + open AF_PACKET sockets with
`CAP_NET_BIND_SERVICE` + `CAP_NET_RAW`, then drop to an unprivileged
user. The sensor refuses to keep running as uid 0.

```yaml
sensor:
  drop_user: tarpit
  drop_group: tarpit
```

Grant the caps without starting as root via systemd
`AmbientCapabilities` (see the shipped unit) or Linux file capabilities
(`setcap cap_net_bind_service,cap_net_raw+ep`).

## In-process sandbox (`sensor.sandbox`)

Applied once, after privileged setup and privilege drop. It is a one-way
ratchet that only removes capability. Best-effort: an unsupported kernel
logs a warning and the sensor keeps running.

```yaml
sensor:
  sandbox:
    seccomp: true          # deny shell-spawn / module-load / debug syscalls
    landlock: true         # read-only FS except data_dir
    # read_paths: ["/"]    # default: read everything
    # write_paths: []      # extra writable roots beyond data_dir
```

**seccomp** installs a seccomp-bpf *denylist* (default-allow, returns
`EPERM`) for the syscalls a connection honeypot never makes:
`execve`/`execveat`, `ptrace`, `process_vm_readv/writev`,
`init_module`/`finit_module`/`delete_module`, `mount`/`umount2`,
`kexec_load`, `pivot_root`/`chroot`, `setns`/`unshare`, `reboot`,
`swapon`/`swapoff`, `bpf`, `perf_event_open`. A denylist is deliberate:
it cannot crash the Go runtime on an unforeseen path the way a tight
allowlist can. The filter is installed with `SECCOMP_FILTER_FLAG_TSYNC`,
so it covers **every thread** of the process — delivering the headline
guarantee that **even a parser 0-day cannot spawn a shell or tamper with
the kernel.**

**Landlock** (Linux 5.13+) restricts the filesystem to read-only
everywhere and writable only under `data_dir` (plus any `write_paths`).
**Caveat:** unlike seccomp, Landlock has no TSYNC flag — `restrict_self`
applies to the calling thread and threads created after it, so OS threads
the Go runtime had already started are not retroactively confined, and a
goroutine scheduled onto one can still write outside `data_dir`. Treat
Landlock here as a best-effort layer; for kernel-enforced **full-process**
filesystem confinement use the AppArmor / SELinux profiles or the systemd
unit below. The access mask adapts to the kernel's Landlock ABI version.

Confirm what actually applied:

```
journalctl -u tarpit-honeypot | grep sandbox
# sandbox: seccomp syscall filter active
# sandbox: landlock filesystem restriction active  data_dir=/var/lib/tarpit-honeypot
```

## AppArmor

```
sudo cp packaging/apparmor/usr.local.bin.tarpit-honeypot /etc/apparmor.d/
sudo apparmor_parser -r -W /etc/apparmor.d/usr.local.bin.tarpit-honeypot
sudo aa-complain /usr/local/bin/tarpit-honeypot   # observe first
sudo aa-enforce  /usr/local/bin/tarpit-honeypot   # then enforce
```

The profile allows config reads, data/log rw, networking (incl.
AF_PACKET), and privilege drop, and explicitly denies executing any
shell/interpreter, `mount`, and `ptrace`. Start in complain mode to catch
site-specific paths (e.g. a non-default `data_dir` or `--log-file`), then
enforce.

## SELinux

```
cd packaging/selinux
make            # builds tarpit_honeypot.pp (needs selinux-policy-devel)
sudo make install
```

Defines a `tarpit_honeypot_t` domain that may bind any TCP/UDP port, open
raw/packet sockets, manage its data + log dirs, read its config, resolve
DNS, and drop privileges — and nothing else. Adjust the binary path in
`tarpit_honeypot.fc` if you install outside `/usr/local/bin`, then
`restorecon`.

## systemd

The shipped unit (`packaging/systemd/tarpit-honeypot.service`) adds
`NoNewPrivileges=true`, `ProtectSystem=strict` with an explicit
`ReadWritePaths`, `ProtectHome`, `PrivateTmp/Devices`,
`ProtectKernelTunables/Modules`, `RestrictNamespaces`, `LockPersonality`,
and a `CapabilityBoundingSet` of just `CAP_NET_BIND_SERVICE CAP_NET_RAW`.
This complements `sensor.sandbox`: systemd confines from outside the
process at start, the sandbox confines from inside after privilege drop.

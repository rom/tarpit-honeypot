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

**Turn-key:** `scripts/install.sh` applies all of this at once — it detects the
distribution (Debian/Ubuntu/Alma/Rocky/Fedora/CentOS/RHEL/SUSE/Arch), creates an
unprivileged `honey:honeypot` service account, installs the binary with the
right file capabilities, deploys the config with privilege-drop + seccomp +
Landlock, installs the matching host-LSM policy and a hardened systemd unit, and
wires the enrichment + Let's Encrypt timers. See
[`scripts/README.md`](../scripts/README.md). The sections below document each
layer for manual / custom setups.

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

## Egress containment

A honeypot must never be usable as an SSRF pivot, open relay, reflector, or
exfil channel — but its own telemetry has to leave the box (sink/forward/intel
endpoints). Two layers cooperate:

- **In-process allowlist** (`egress.enabled`): every outbound dial inside the
  sensor goes through a `DialContext` that consults the configured allowlist
  (hosts, `host:port`s, CIDRs). Anything else is refused and reported as an
  `egress:denied` event. Forward / intel-feed URLs are auto-allowlisted; for
  MISP / webhooks / SMTP / syslog destinations, add the URL to `sensor.egress.allow`.
- **OS-level backstop** (`egress.enforce`): an nftables `OUTPUT` chain scoped to
  the sensor's UID (`meta skuid`) drops anything outside the allowlist, so even
  a library that bypasses the in-process guard can't pivot. Requires Linux,
  `nft`, and `CAP_NET_ADMIN` at install (before privilege drop).

Sharp edges worth knowing:

- The HTTP client built by the egress package **deliberately ignores
  `HTTP(S)_PROXY` env vars** — under `Proxy: nil`. With Go's default
  `ProxyFromEnvironment`, a stray proxy var would route every dial through the
  proxy address, and the in-process allowlist would only see the proxy's
  `host:port`, not the real destination. If you need a forward proxy, dial it
  explicitly through a sink-specific URL (and allowlist it).
- Hostname allowlist entries are checked **by name** at dial time — the actual
  TCP connect goes to whatever your resolver returns. A DNS hijack can redirect
  a name to an attacker-controlled IP. The nftables backstop (IP-based) defends
  against this; prefer **IP/CIDR allowlist entries** for high-value destinations.
- Allowlist values are operator-trusted. Port and host strings are validated
  before they reach the generated nft script, so a malformed entry can't inject
  rules — but writing the config remains a trusted operation. Treat
  `sensor.egress.allow` like any other sensitive config.

A blocked dial logs as `egress:denied` and surfaces in the **errors** UI tab.

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

**Verify the daemon is actually confined.** The domain transition only fires
when the binary carries the `tarpit_honeypot_exec_t` label, so after install
check:

```
ps -eZ | grep tarpit-honeypot      # want tarpit_honeypot_t, NOT unconfined_service_t
ls -Z /usr/local/bin/tarpit-honeypot   # want ...:tarpit_honeypot_exec_t:s0
```

If `ps` shows `unconfined_service_t`, the binary is mislabeled — almost always
because a stray local file-context entry (e.g. `semanage fcontext -a -t bin_t`)
is overriding the module's `.fc` (a local entry outranks a module entry). Clear
it and relabel:

```
sudo semanage fcontext -d /usr/local/bin/tarpit-honeypot   # drop any local override
sudo restorecon -Fv /usr/local/bin/tarpit-honeypot
sudo systemctl restart tarpit-honeypot
```

`scripts/install.sh` does this automatically and now verifies the resulting
label, warning loudly if the daemon would run unconfined. (Earlier installs
that left a `bin_t` override behind are fixed simply by re-running it.)

**`NoNewPrivileges=yes` vs the domain transition (the other reason it stays
`unconfined_service_t`).** Even with the binary correctly labeled, the kernel
refuses the automatic `init_t → tarpit_honeypot_t` transition under
`no_new_privs` unless the policy grants the `process2:nnp_transition`
permission. The policy now calls `init_nnp_daemon_domain(...)` for exactly this,
and the systemd unit also pins the domain explicitly with
`SELinuxContext=-system_u:system_r:tarpit_honeypot_t:s0` (the `-` makes it
non-fatal when SELinux is off / the module isn't loaded). If you're on an older
selinux-policy without `init_nnp_daemon_domain`, the `make` will fail to build —
either upgrade selinux-policy-devel, or drop `NoNewPrivileges` from the unit.
After `systemctl daemon-reload && systemctl restart tarpit-honeypot`, confirm
with `ps -eZ | grep tarpit-honeypot` → it should read `tarpit_honeypot_t`.

The policy now wraps the `init_nnp_daemon_domain` call in an m4 `ifdef`, so the
module still **builds** on older selinux-policy that lacks the interface — and
`scripts/install.sh` detects that case and writes the unit with
`NoNewPrivileges=no` (warning you), since on those releases keeping it on would
block the transition and leave the daemon unconfined (SELinux confinement is the
stronger control for an internet-facing honeypot, so we prefer it).

**Just run the checker.** `sudo scripts/selinux-verify.sh` walks the whole chain
— enforcing mode → module loaded → binary label → the *running* process domain →
recent AVC denials — and prints the exact fix for the first thing that's wrong.
It's read-only and is installed to `/usr/local/share/tarpit-honeypot/scripts/`.

## systemd

The shipped unit (`packaging/systemd/tarpit-honeypot.service`) adds
`NoNewPrivileges=true`, `ProtectSystem=strict` with an explicit
`ReadWritePaths`, `ProtectHome`, `PrivateTmp/Devices`,
`ProtectKernelTunables/Modules`, `RestrictNamespaces`, `LockPersonality`,
and a `CapabilityBoundingSet` of just `CAP_NET_BIND_SERVICE CAP_NET_RAW`.
This complements `sensor.sandbox`: systemd confines from outside the
process at start, the sandbox confines from inside after privilege drop.

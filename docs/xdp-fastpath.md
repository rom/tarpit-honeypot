# Fast-path DoS resistance (userspace shaper + optional eBPF/XDP)

A honeypot is a magnet for connection floods and reflection/scan storms. The
**fast path** is an L3/L4 admission gate that sheds abusive sources *early* —
before a connection is allowed to spend a handler goroutine, buffers, or an
event-bus slot — so the sensor stays responsive under load and never becomes
the amplifier/victim.

It has two tiers behind one package (`internal/fastpath`):

| Tier | Where | Needs | Status |
|---|---|---|---|
| **Userspace shaper** (default) | Go, at `Accept()` | nothing (any OS, no privileges) | **shipped + tested** |
| **In-kernel eBPF/XDP** (opt-in) | NIC driver RX hook | Linux, `-tags tarpit_xdp`, a compiled BPF object, `CAP_BPF`/`CAP_NET_ADMIN` | **design + build-tagged scaffold** |

## Tier 1 — userspace shaper (default, on by opt-in)

A per-source **token bucket**: each source IP gets a bucket of depth
`burst = max(pps, 20)` refilled at `max_source_pps` tokens/second. A new
connection charges one token; a source with an empty bucket is **shed** — the
connection is closed immediately at accept and a low-severity `fastpath:shed`
event is emitted (non-blocking, so a flood can't wedge the accept loop). A hard
**drop-set** (wire it to the risk blocker / blocklist feed) refuses listed
sources in O(1). The source table is LRU-bounded (`MaxSources`, default 65536)
so a spoofed-source flood can't drive the gate's own memory up.

Enable it per TCP listener:

```yaml
listeners:
  - id: web
    proto: tcp
    bind: 0.0.0.0:80
    handler: http
    max_source_pps: 25        # sustained new-conns/sec per source IP; 0 = off
    max_concurrent: 500       # the existing global accept cap still applies
```

`max_source_pps` complements `max_concurrent`: the former bounds a *single*
source, the latter bounds the *total*. The shaper runs before the concurrency
semaphore, so a noisy source is shed without consuming a slot.

## Tier 2 — in-kernel eBPF/XDP (opt-in, Linux)

For line-rate resistance (floods large enough that even accept-and-close costs
too much), an XDP program attached at the driver RX hook drops abusive packets
*before* they reach the socket layer:

```
          ┌────────────── Go (userspace) ──────────────┐
NIC ─RX─▶ XDP program ─▶ (XDP_PASS) ─▶ socket ─▶ Accept ─▶ shaper ─▶ handler
             │  │                                   ▲
   XDP_DROP ◀┘  └── per-source token-bucket map     │ mirrors drop-set
             ▲                                       │  + reads counters
   drop map ─┘◀──────────────────────────────────────┘
```

- a `BPF_MAP_TYPE_LRU_HASH` **drop map** keyed by source IP → `XDP_DROP` (the
  hard blocklist, mirrored from the userspace drop-set);
- a second LRU_HASH holding the **per-source token bucket** (same refill math as
  Tier 1) → `XDP_DROP` when empty;
- a `PERCPU_ARRAY` of per-verdict **counters** the Go side reads for `Stats()`.

The Go integration lives in `internal/fastpath/xdp_linux.go`, compiled **only**
with `-tags tarpit_xdp` on Linux. The default build (`xdp_default.go`) never
references a kernel, a BPF toolchain, `CAP_BPF`, or a NIC, so `go build ./...`
and the honeypot always have the working userspace tier.

> **Honest status.** The repository ships the architecture, the Go interface
> (`AttachXDP`, `Available`, `Close`, `Shaper.SetBlocklist`), and the
> build-tagged skeleton — **not** a compiled `xdp_fastpath.o` or a bundled
> loader, and the kernel program has not been validated in CI (it needs a
> privileged kernel + NIC that the build/test environment doesn't have). A
> build that opts into `tarpit_xdp` must supply the compiled object + loader
> (e.g. via `cilium/ebpf`); until then `AttachXDP` returns a clear error and the
> sensor keeps using the userspace shaper. The map layout and refill math above
> are the contract to implement against.

## Why not just rely on the OS?

`SO_REUSEPORT`, conntrack and firewall rate-limits help, but the honeypot wants
the *decision* (which source, which verdict, with a `fastpath:shed` event) in
its own telemetry and tied to its risk/blocklist state. The shaper gives that
on every platform today; XDP moves the same decision into the kernel for the
highest-volume deployments.

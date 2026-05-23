# The userspace TCP stack (`internal/tcpstack`)

This document describes the userspace TCP/IPv4 engine that lets honeynet
virtual hosts terminate TCP — complete a handshake, answer one
request/response, and look like the intended operating system to a port
and OS scanner — **without the operator binding a real socket (or running
`ip addr add`) for every virtual host IP**, and while capturing the
malformed / illegal packets a scanner sprays.

It is the counterpart to the L3 responder in `internal/tunnet`: ICMP echo
stays at L3 in `tunnet`; everything TCP flows through `tcpstack`.

- **Code:** `internal/tcpstack/` (pure, OS-agnostic, fully unit-tested).
- **Wiring:** `internal/tunnet/tunnet_linux.go` (TUN I/O) +
  `internal/sensor/tundecoy.go` (per-host decoy build + event emit).
- **Config:** [`honeynets[].tun`](config.md#honeynets--artificial-networks-of-virtual-hosts).
- **Attribution:** [`attribution.md`](attribution.md) §1 (ATT&CK) and §3
  (the TCP/IP-stack CVE class).

---

## 1. Why a userspace stack

A honeynet wants virtual hosts that a scanner believes are real machines.
Three problems stand between "the sensor has one socket" and that illusion:

1. **Reachability without plumbing.** Making 250 virtual IPs answer TCP the
   normal way means 250 `ip addr add` (or iptables DNAT) rules and a real
   listener per service. That doesn't scale and leaks the deception (every
   host has byte-identical kernel behavior).
2. **OS fingerprint consistency.** `nmap -O` and p0f don't read banners —
   they read the *shape* of the TCP/IP handshake: the initial TTL, the
   advertised window, the MSS, whether window-scaling / SACK / timestamps
   are present, and **the exact order and NOP-padding of the TCP options**.
   If the SYN-ACK comes from the host kernel, every virtual host
   fingerprints as the sensor's real OS — not as the Windows DC or the
   Siemens PLC it claims to be.
3. **Capturing the weird stuff.** Stealth scans (NULL/FIN/Xmas), crafted
   illegal packets (bad checksums, SYN+FIN, lying data-offsets), IP
   fragmentation evasion, and the classic LAND DoS never reach a normal
   socket — the kernel silently drops or RSTs them. A honeypot wants to
   *record* them.

`tcpstack` solves all three: it synthesizes a SYN-ACK shaped to the host's
archetype, runs a minimal per-flow state machine to complete the handshake
and answer a single request, and classifies + reports every malformed
packet instead of letting the kernel eat it.

### Scope — it is a *decoy* stack, not a general one

Deliberately simplified. The engine handles **in-order data only** and does
**no** retransmission, congestion control, out-of-order reassembly, PMTU
discovery, or multi-request keep-alive. A lost segment just makes the
scanner retry as a fresh flow. This is sufficient to fool `nmap -sV` / `-O`
and p0f and to harvest a first request/response; deep multi-segment
protocol interaction (full login flows, file transfers, interactive
shells) still wants a real socket bound behind `ip addr add` / NAT.

IPv6 reconnaissance stays in the `tunnet` L3 responder (ICMPv6 echo); the
userspace stack is IPv4/TCP only.

---

## 2. Package layout

| File | Responsibility |
|---|---|
| `fingerprint.go` | `OSProfile` (the per-OS SYN-ACK shape), the canonical `profiles` table, `ProfileFor(family)`, and `buildOptions` (serialize the TCP options in the profile's exact order, NOP-padded to 4 bytes). |
| `packet.go` | `Segment` (a parsed IPv4+TCP packet), `ParseV4`, the IPv4 + TCP checksum routines, and `buildV4` (the single outbound-packet primitive). |
| `malformed.go` | `Classify(*Segment) []string` and `IsMalformed` — turn an illegal/corrupt packet into stable marker strings. |
| `stack.go` | `Stack` — the per-flow state machine, the open/closed + responder callbacks, idle-flow GC, and cumulative `Stats`. |

Everything is pure Go with no dependency on `tunnet`, `event`, or the OS,
so the whole engine is exercised with synthetic packets in `_test.go`
(the live TUN can't run in CI). `tunnet` is the only caller that does I/O.

---

## 3. Fingerprint profiles

`OSProfile` carries exactly the fields a SYN-ACK fingerprinter keys on:

```go
type OSProfile struct {
    Name   string
    TTL    uint8  // initial IP TTL
    Window uint16 // advertised TCP window
    MSS    uint16 // maximum segment size option (0 = omit)
    WScale uint8  // window-scale shift; emitted only when HasWScale
    DF     bool   // IP Don't-Fragment bit
    HasWScale, SACKPerm, HasTS bool
    Order  []byte // the option layout (kinds) — reproduces vendor ordering + NOP padding
}
```

Four canonical profiles approximate the real stacks closely enough to fool
signature matching:

| Profile | TTL | Window | MSS | WScale | SACK | TS | DF | Option order |
|---|---:|---:|---:|---:|:-:|:-:|:-:|---|
| `linux` | 64 | 64240 | 1460 | 7 | ✓ | ✓ | ✓ | MSS, SACK, TS, NOP, WScale |
| `windows` | 128 | 65535 | 1460 | 8 | ✓ | — | ✓ | MSS, NOP, WScale, NOP, NOP, SACK |
| `bsd` | 64 | 65535 | 1460 | 6 | ✓ | ✓ | ✓ | MSS, NOP, WScale, SACK, TS |
| `ot` | 255 | 4096 | 1460 | — | — | — | — | MSS |

The **option order** is the strongest signal — Linux, Windows, and BSD lay
the same options out differently and pad with NOPs in different places, and
`buildOptions` reproduces that byte-for-byte. When the client's SYN carried
a timestamp, the SYN-ACK echoes it in TSecr.

### `ProfileFor(family)` — archetype → profile

The host's archetype `Family` (see [`archetypes.md`](archetypes.md)) selects
the profile:

| Family | Profile |
|---|---|
| `windows` | `windows` |
| `bsd`, `freebsd`, `openbsd`, `netbsd`, `darwin`, `macos`, `pfsense` | `bsd` |
| `ot`, `ics`, `moxa`, `siemens`, `cisco`, `hirschmann`, `westermo`, `phoenix`, `schneider`, `omron`, `mitsubishi`, `abb`, `beckhoff`, `honeywell`, `wago`, `advantech`, `teltonika` | `ot` |
| everything else (`debian`, `ubuntu`, `rhel`, `arch`, `mikrotik`, …) | `linux` |

> MikroTik RouterOS and pfSense are mapped by OS lineage, not vendor:
> RouterOS is Linux-based (full options, TTL 64) and pfSense is
> FreeBSD-based — so they get the `linux` and `bsd` profiles respectively,
> not the OT "network gear" profile.

### TTL consistency across ICMP, RST and SYN-ACK

The sensor overrides `OSProfile.TTL` with the archetype's `ICMPTTL()` so a
host with a custom TTL gets the *same* TTL on its ICMP echo replies (from
`tunnet`), its closed-port RSTs, and its open-port SYN-ACKs. A scanner that
pings, hits a closed port, and hits an open port therefore sees one
coherent OS — there is no tell where ICMP says "Linux" but the SYN-ACK says
something else.

---

## 4. The connection state machine

One `Stack` serves every virtual host on a TUN. It keeps a flow table keyed
by the 4-tuple `(srcIP, srcPort, dstIP, dstPort)`; each flow is a tiny
control block:

```
            SYN (to an open port)
   (no flow) ───────────────────────────►  SYN_RCVD
                 emit SYN-ACK (fingerprint-shaped, ISN chosen)

   SYN_RCVD ──── ACK (handshake done) ───►  ESTABLISHED
                 if server-first port: send banner

ESTABLISHED ── client data (in order) ──►  send reply + FIN ─► FIN_WAIT
                 emit honeynet:tcp_request, answer once, then close

ESTABLISHED ──────── client FIN ─────────►  ack + our FIN ──► FIN_WAIT
   FIN_WAIT ──────── client ACK ─────────►  (flow deleted)
   (any state) ───────── RST ────────────►  (flow deleted)
```

Sequence-number bookkeeping follows real TCP: the client's SYN and our
SYN-ACK each consume one sequence number, as does each side's FIN; data
advances the sequence by its length. The SYN-ACK's ISN is random
(`crypto/rand`) per flow — predictable ISNs are themselves a fingerprint —
and is held constant so a SYN retransmit re-sends an identical SYN-ACK
(idempotent), never a second handshake.

### Server-first vs client-first services

- **Client-first** (HTTP, most): no banner; the decoy waits for the request
  and answers it.
- **Server-first** (SSH, FTP, SMTP, Telnet): a banner is pushed
  immediately after the handshake completes; a subsequent request is then
  answered once.

Both come from the per-host `Responder` (see §6). The decoy answers **one**
request then sends FIN — enough for a service-version probe, not a full
session.

### Closed ports and stray segments

A SYN (or any non-RST segment) to a port that isn't open gets a RFC-793
RST — exactly what a real host does — stamped with the host's TTL so a
closed-port probe fingerprints consistently. An empty decoy map therefore
reproduces the **legacy "every port closed" L3 behavior** automatically.

### Bounding state

A 30-second idle reaper (`Sweep`, driven by a ticker in `tunnet.Run`) drops
half-open and lingering flows, so a SYN flood with spoofed source ports
can't grow the flow table without bound. Cumulative counters (handshakes,
requests, malformed, resets, live flows) are exposed via `Stats()` and
logged when the adapter shuts down.

---

## 5. Malformed / illegal packet capture

`Classify` inspects every inbound segment and returns stable markers for
the shapes a honeypot wants on record. A well-formed ordinary segment
returns none.

| Marker | Meaning | Reply policy |
|---|---|---|
| `ip-bad-header-len` | IHL field smaller than 20 or past the buffer | drop |
| `ip-bad-checksum` | IPv4 header checksum mismatch | drop |
| `ip-fragmented` | MF bit or non-zero fragment offset (we never reassemble) | drop |
| `tcp-truncated` | fewer than 20 bytes of TCP header present | drop |
| `tcp-bad-dataoffset` | data-offset lies about the header length | drop |
| `tcp-bad-checksum` | TCP checksum mismatch | drop |
| `tcp-null` | no flags set (NULL scan) | closed → RST, open → drop |
| `tcp-fin-scan` | lone FIN (FIN scan) | closed → RST, open → drop |
| `tcp-xmas` | FIN+PSH+URG (Xmas scan) | closed → RST, open → drop |
| `tcp-syn-fin` | SYN and FIN both set (illegal) | closed → RST, open → drop |
| `tcp-syn-rst` | SYN and RST both set (illegal) | drop |
| `tcp-data-in-syn` | payload bytes in a SYN | closed → RST, open → drop |
| `tcp-land` | **source IP == destination IP** (LAND attack) | always drop |

**Reply policy.** Two principles keep the decoy believable and safe:

- *Structurally corrupt* packets (bad checksum, truncation, fragments) are
  **dropped silently**, exactly like a real stack — answering corrupt input
  would itself be a fingerprint.
- *Stealth-scan flag combinations* with otherwise-valid framing follow real
  host behavior: a **closed** port RSTs them (so `nmap` classifies the port
  correctly), an **open** port ignores them (so `nmap` reports
  `open|filtered`).
- A **LAND** packet (source == destination) is always dropped — replying
  would send the packet to ourselves, which *is* the attack.

`Augment` unions each marker's ATT&CK technique onto the event, so a
`honeynet:tcp_malformed` event carries precise attribution (see §7).

---

## 6. Per-host decoy configuration

There is **no new config** — the decoy is built from each honeynet host's
existing `archetype:`/`os:` and `services:` (`internal/sensor/tundecoy.go`,
`buildTUNDecoys`):

- **Open ports** = the set of `services[].port`.
- **OS fingerprint** = `ProfileFor(archetype.Family)` with its TTL set to
  the archetype's `ICMPTTL()`.
- **Banners / replies** are derived per service:
  - `ssh` → `SSH-2.0-…\r\n` (archetype SSH banner)
  - `ftp` → `220 …\r\n`
  - `smtp` → `220 <host> ESMTP <product>\r\n`
  - `telnet` → archetype telnet/login banner
  - `http` → a minimal `HTTP/1.1 200` with the archetype `Server:` header + body
  - `https` → accept-then-silence (the stack does not terminate TLS, but the
    port still fingerprints as open)
  - an explicit `services[].banner` overrides the archetype default
  - a host with no services still gets a profile entry (no open ports) so
    its closed-port RSTs carry the right TTL.

A single honeynet can therefore mix OS shapes — a `debian-12` web box next
to a `windows`/`active-directory` DC next to a `siemens` PLC — each
fingerprinting as itself.

---

## 7. Events & attribution

`tunnet` hands the stack's events to the sensor, which publishes them on the
bus (where enrichment, ATT&CK/D3FEND tagging, correlation and routing
apply, same as any other event). The malformed markers are placed in
`Anomalies` so the **`protocol_violation`** correlator (distinct-anomaly
threshold) aggregates a fuzzing/scan run from one source.

| rule_id | When | Severity | ATT&CK | Notes |
|---|---|---|---|---|
| `honeynet:tcp_connect` | a SYN to an open port was answered | low | T1046 (discovery) | one per new flow |
| `honeynet:tcp_request` | client payload captured | low | T1046, T1595 | payload base64 in `payload_b64` |
| `honeynet:tcp_malformed` | an illegal/corrupt packet | medium | T1046, T1595.001 (+ per-marker via `Anomalies`) | raw packet captured in `payload_b64` |
| `honeynet:tcp_land` | a LAND packet (src==dst) | high | T1499 (impact) | `meta.cve = CVE-1999-0016` |

Every event carries `meta.honeynet`, the source/dest endpoints, and the
matched markers in `Anomalies`. The per-marker ATT&CK mappings live in
`internal/mitre` (`anomalyTags`), with a `tcp-*` / `ip-*` prefix fallback
for any future marker; see [`attribution.md`](attribution.md) §1c/§1d.

### The TCP/IP-stack CVE class

The CVE catalog (`internal/cve`, `Service: "tcp"`) carries the classic
TCP/IP-stack attacks this layer is positioned to recognize. LAND is
detected live; the fragment-class entries pair with `ip-fragmented`; the
rest document the stack-fingerprint surface a scanner probes. They ride the
packet layer rather than an L7 handler, so they are advisory in the
signature sense but carry full ATT&CK + CWE/EPSS.

| CVE | Name | ATT&CK | Tie-in |
|---|---|---|---|
| CVE-1999-0016 | LAND (src==dst DoS) | T1499 | detected live → `tcp-land`, `meta.cve` |
| CVE-1999-0015 | Teardrop (overlapping fragments) | T1499 | `ip-fragmented` |
| CVE-2018-5391 | FragmentSmack (IP-fragment DoS) | T1499 | `ip-fragmented` |
| CVE-2004-0230 | TCP RST/SYN in-window DoS | T1499 | advisory |
| CVE-2008-4609 | sockstress (state exhaustion) | T1499 | flow table is bounded by the idle reaper |
| CVE-2016-5696 | Linux off-path TCP injection | T1499 | advisory |
| CVE-2019-11477 | SACK Panic | T1499 | advisory |
| CVE-2020-11896 | Ripple20 (Treck TCP/IP RCE) | T1190 | the OT/IoT device class the honeynet emulates |

Inspect both tables from the CLI:

```bash
tarpit-honeypot list-techniques --kind anomaly | grep -E 'tcp-|ip-'
tarpit-honeypot list-techniques --kind rule    | grep honeynet:tcp
tarpit-honeypot list-cves | grep ' tcp '
```

---

## 8. Worked example

A `debian-12` host at `10.99.0.10` exposes `services: [{port: 80, handler: http}]`,
routed through the honeynet TUN. A scanner runs `nmap -sV 10.99.0.10`:

1. `SYN → 10.99.0.10:80`. The stack creates a flow, picks a random ISN, and
   replies `SYN-ACK` with **TTL 64, window 64240, MSS 1460, SACK,
   timestamp (echoing the client's), NOP, window-scale 7** in Linux option
   order. `nmap -O` reads "Linux". → `honeynet:tcp_connect`.
2. `ACK` completes the handshake → ESTABLISHED. No banner (HTTP is
   client-first).
3. `GET / HTTP/1.0` → the stack captures it (`honeynet:tcp_request`,
   payload recorded) and answers `HTTP/1.1 200 OK` with
   `Server: Apache/2.4.62 (Debian)`, then sends FIN. `nmap -sV` records
   "Apache httpd 2.4.62 (Debian)".
4. The scanner ACKs the FIN; the flow is reaped.

If the same scanner sprays a Xmas scan at `10.99.0.81` (closed), the stack
RSTs it and emits `honeynet:tcp_malformed` with `Anomalies: [tcp-xmas]`
(T1046/T1595.001). A spoofed `10.99.0.10 → 10.99.0.10:80` SYN is dropped and
raises `honeynet:tcp_land` (T1499, CVE-1999-0016).

---

## 9. Testing

The engine is exercised entirely with synthetic packets (the live TUN is
Linux-only and can't run in CI):

- `packet_test.go` — parse/build round-trips, checksum verification, option
  parsing.
- `fingerprint_test.go` — `ProfileFor` family mapping and the exact option
  byte layout per profile.
- `malformed_test.go` — every classifier marker, including LAND.
- `stack_test.go` — full handshake + request/response + close, SYN-ACK
  fingerprint fields, banner timing, closed-port RST, malformed drop/RST
  policy, LAND drop, SYN-retransmit idempotency, idle GC.
- `tunnet_linux_test.go` — the `newStack` wiring (empty map → RST-only).

```bash
go test ./internal/tcpstack/ ./internal/tunnet/
GOOS=linux go build ./internal/tunnet/   # the I/O layer is Linux-only
```

---

## 10. Limitations & non-goals

- In-order data only; no retransmission, congestion control, out-of-order
  reassembly, or PMTU discovery.
- One request/response per flow (a service-version probe, not a session).
- IPv4 only; IPv6 reconnaissance is ICMPv6 echo in `tunnet`.
- No TLS termination — `https` ports complete the TCP handshake and stay
  silent (still "open" to a port scan).
- The four fingerprint profiles approximate real stacks; they are tuned to
  pass `nmap -O` / p0f signature matching, not to be byte-identical to a
  specific kernel build.

For full multi-segment protocol interaction, bind a real-socket listener and
route the virtual host's traffic to it (NAT / `ip addr add`); the userspace
stack and real listeners coexist on the same honeynet.

---

## See also

- [`config.md`](config.md) — `honeynets[].tun` and `hosts[].services`.
- [`attribution.md`](attribution.md) — ATT&CK §1, D3FEND §2, CVE §3.
- [`design.md`](design.md) — where the stack sits in the deception layer.
- [`archetypes.md`](archetypes.md) — the archetype families that select a
  profile and supply the banners.

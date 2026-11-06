# Operator scripts

Helper scripts for deploying, hardening, and feeding a tarpit-honeypot sensor.
All are plain `bash` (no extra deps beyond the tools they install).

| Script | Run where | What it does |
|---|---|---|
| `install.sh` | sensor (root) | Distro-aware **hardened install**: creates the `honey:honeypot` service account, builds + installs the binary to `/usr/local/bin` (owned by that account), grants file capabilities and sets the setuid/setgid bits so even a manual launch drops to `honey:honeypot` (guarded — it refuses unless the binary is owned by that unprivileged account, so it can never produce a setuid-root file), lays out `/etc` + `/var/lib` + `/var/log`, deploys the config with privilege-drop + seccomp + Landlock, installs the host LSM policy (SELinux or AppArmor), and installs a hardened systemd unit + the enrichment timer. |
| `add-instance.sh` | sensor (root) | After `install.sh`, provisions **one extra instance per server IP** — its own config (`/etc/tarpit-honeypot/instances/<name>.yaml`), database, deployment identity + certs, and loopback UI port, all driven by the `tarpit-honeypot@<name>` systemd template. `--listen-ip` binds the instance to that address; `--ui-port` picks the console port (auto-assigned otherwise). When you point it at a custom `--data-root`, it also emits the matching systemd `ReadWritePaths` drop-in and SELinux file-context so the hardened sandbox still starts. |
| `letsencrypt-cert.sh` | sensor (root) | Obtains a **Let's Encrypt** TLS cert for the management **UI** (asks for domain + hostname), installs a renewal deploy-hook that drops a sensor-readable copy and reloads the service, and points the config at it. |
| `fetch-enrichment.sh` | anywhere with internet | Downloads the enrichment databases (GeoIP/ASN, Tor exits, reputation lists, IEEE OUI). Air-gapped: writes a transferable bundle. Same-host: `--install` fetches **and** installs in one step. |
| `install-enrichment.sh` | sensor | Installs a fetched bundle into the live config's paths (read from `list-paths`) and reloads. |
| `update-enrichment.sh` | sensor (root) | One-shot **fetch+install+reload** wrapper for cron / systemd timers (locked, logged). |
| `fetch-kev.sh` | anywhere with internet | Downloads the CISA **Known Exploited Vulnerabilities (KEV)** catalog for the offline / air-gapped case; transfer the JSON and point the sensor at it with `kev.file`. Complements the built-in live `kev:` auto-sync and powers `tarpit-honeypot kev-gap`. |
| `selinux-verify.sh` | sensor (root) | **Read-only** SELinux containment check: walks enforcing mode → policy module loaded → binary label → the *running* process domain → recent AVC denials, and prints the exact fix for the first thing that's wrong. Exit 0 = the daemon is confined in `tarpit_honeypot_t`. |
| `open-firewall.sh` | sensor (root) | Reads a config and **opens the host firewall** for every decoy `listeners:` port (both flow + block YAML), then reloads. Auto-detects firewalld / ufw / iptables. Scope the rules to a NIC or destination IP with `--interface` / `--ip` (or it asks interactively); `--dry-run` previews. Leaves the loopback management UI port closed by design. |
| `wireguard-setup.sh` | sensor (root) | Installs **WireGuard** and configures an encrypted tunnel from the sensor to your SOC / management hub so the console and alert traffic leave the box over the link instead of the public internet. Generates the sensor keypair (the private key never leaves the host), writes `/etc/wireguard/wg0.conf`, opens the UDP port only when the hub dials in, and brings up `wg-quick@wg0`. Auto-picks **spoke** (sensor dials out through NAT) or **listener** (hub dials in) from `--endpoint`, then prints this sensor's public key and a ready-to-paste `[Peer]` block for the other side. `--dry-run` previews. |

## Quick start (single hardened box)

```bash
# 1. Install hardened, as a service (detects debian/ubuntu/alma/rocky/fedora/…)
sudo scripts/install.sh -c configs/tarpit-honeypot.example-CENTOS-SERVER.yaml

# 2. Real TLS for the web UI (prompts for domain + hostname)
sudo scripts/letsencrypt-cert.sh

# 3. Pull enrichment now; the daily timer keeps it fresh
sudo scripts/update-enrichment.sh

# 4. Go
sudo systemctl start tarpit-honeypot
```

## Enrichment on a schedule

The same-host path is `fetch-enrichment.sh --install` (it skips the archive +
transfer). `update-enrichment.sh` wraps it for unattended use:

* **systemd** — `install.sh` installs and enables `tarpit-enrichment.timer`
  (daily) and ships `tarpit-cert-renew.timer` (enabled by `letsencrypt-cert.sh`).
* **cron** — `17 4 * * *  /usr/local/share/tarpit-honeypot/scripts/update-enrichment.sh`

Set `MAXMIND_LICENSE_KEY` (env or in `tarpit-enrichment.service`) to use MaxMind
GeoLite2 instead of the no-key DB-IP lite databases.

## Air-gapped enrichment

```bash
# on an internet host:
scripts/fetch-enrichment.sh /tmp/enr            # writes /tmp/enr + /tmp/enr.tar.gz
scp /tmp/enr.tar.gz* sensor:/tmp/
# on the sensor:
sudo scripts/install-enrichment.sh /tmp/enr.tar.gz -c /etc/tarpit-honeypot/config.yaml
```

## WireGuard management tunnel

`wireguard-setup.sh` puts the sensor's **console and alert traffic** on an
encrypted WireGuard link to your SOC, so the loopback-bound management UI and
outbound notifications never cross the public internet in the clear. The
deceptive listeners stay exposed on the public interface — only your
side-channel moves into the tunnel.

It configures **one** of two topologies, chosen by whether you pass `--endpoint`:

* **spoke** (`--endpoint hub:51820`) — the sensor *dials* the hub and holds the
  path open with `PersistentKeepalive`. No inbound port is opened; this is the
  right choice for sensors behind NAT / firewalls (the common fleet case).
* **listener** (no `--endpoint`) — the hub *dials* the sensor. The script binds
  `ListenPort`, opens that UDP port in the host firewall (firewalld / ufw /
  iptables, auto-detected), and reports the address the hub should use as its
  `Endpoint`.

```bash
# On the sensor (spoke): dial the SOC hub. Supply the hub's public key if you
# already have it; otherwise the script writes a placeholder and prints how to
# finish once the hub hands its key back.
sudo scripts/wireguard-setup.sh \
    --endpoint soc.example.com:51820 \
    --tunnel-ip 10.8.0.2/24 --hub-ip 10.8.0.1 \
    --hub-pubkey <HUB_PUBLIC_KEY>
```

**What to do on the other side (the hub).** The script prints this verbatim with
the real values filled in; in summary:

1. Generate the hub's own keypair — `wg genkey | tee hub.key | wg pubkey > hub.pub`.
   Private keys never leave their host; you exchange only **public** keys.
2. Add the sensor as a `[Peer]` on the hub using the sensor's printed public key,
   `AllowedIPs = <sensor-tunnel-ip>/32`, the shared `PresharedKey` (if used), and
   — in *listener* mode — `Endpoint = <sensor-public-ip>:51820`.
3. Give the sensor the hub's public key (`--hub-pubkey`, or edit `wg0.conf`) and
   bring both ends up: `systemctl enable --now wg-quick@wg0`.
4. Reload the hub without flapping peers: `wg syncconf wg0 <(wg-quick strip wg0)`.

Then bind the UI to the tunnel address (`ui.bind: 10.8.0.2:8088`) and reach the
console from the SOC over the encrypted link. A pre-shared key is added by default
for an extra symmetric secret; transport the printed hub snippet over a secure
channel (SSH / age / password manager), since it carries that secret.

## Notes

* The Let's Encrypt cert is for the **management UI only**. The deceptive
  `https` *service* listeners intentionally keep archetype-shaped self-signed
  certs — a real cert there would tie the decoy to your identity.
* `install.sh` standalone-mode cert issuance briefly stops the sensor to free
  port 80 for the ACME HTTP-01 challenge; use `letsencrypt-cert.sh --method dns`
  for zero-downtime issuance if you have a DNS plugin.
* See [`docs/hardening.md`](../docs/hardening.md) for the layer-by-layer detail.

# Operator scripts

Helper scripts for deploying, hardening, and feeding a tarpit-honeypot sensor.
All are plain `bash` (no extra deps beyond the tools they install).

| Script | Run where | What it does |
|---|---|---|
| `install.sh` | sensor (root) | Distro-aware **hardened install**: creates the `honey:honeypot` service account, builds + installs the binary to `/usr/local/bin` (owned by that account), grants file capabilities and sets the setuid/setgid bits so even a manual launch drops to `honey:honeypot` (guarded — it refuses unless the binary is owned by that unprivileged account, so it can never produce a setuid-root file), lays out `/etc` + `/var/lib` + `/var/log`, deploys the config with privilege-drop + seccomp + Landlock, installs the host LSM policy (SELinux or AppArmor), and installs a hardened systemd unit + the enrichment timer. |
| `letsencrypt-cert.sh` | sensor (root) | Obtains a **Let's Encrypt** TLS cert for the management **UI** (asks for domain + hostname), installs a renewal deploy-hook that drops a sensor-readable copy and reloads the service, and points the config at it. |
| `fetch-enrichment.sh` | anywhere with internet | Downloads the enrichment databases (GeoIP/ASN, Tor exits, reputation lists, IEEE OUI). Air-gapped: writes a transferable bundle. Same-host: `--install` fetches **and** installs in one step. |
| `install-enrichment.sh` | sensor | Installs a fetched bundle into the live config's paths (read from `list-paths`) and reloads. |
| `update-enrichment.sh` | sensor (root) | One-shot **fetch+install+reload** wrapper for cron / systemd timers (locked, logged). |

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

## Notes

* The Let's Encrypt cert is for the **management UI only**. The deceptive
  `https` *service* listeners intentionally keep archetype-shaped self-signed
  certs — a real cert there would tie the decoy to your identity.
* `install.sh` standalone-mode cert issuance briefly stops the sensor to free
  port 80 for the ACME HTTP-01 challenge; use `letsencrypt-cert.sh --method dns`
  for zero-downtime issuance if you have a DNS plugin.
* See [`docs/hardening.md`](../docs/hardening.md) for the layer-by-layer detail.

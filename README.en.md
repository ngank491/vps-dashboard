# vps-dashboard (vpsmon)

**English** · [Tiếng Việt](README.md)

A small dashboard for watching a Linux VPS: resources, services, connections, **port-scanning bots and proxy password-guessing bots**, with a button to block an IP right from the page.

- **One Python file**, standard library only (Python ≥ 3.6): no pip, Docker or database server.
- **Lightweight**: about 16–20 MB of RAM and a SQLite database of a few MB. Old data is deleted automatically.
- Scan traffic is captured with **NFLOG**, so nothing is written to the journal or syslog and system logs stay small.
- **Two languages in the UI**: English and Tiếng Việt, switched with the **VI | EN** buttons (follows the browser language by default and remembers your choice).
- Runs well on **CentOS 7** (Python 3.6, systemd 219, kernel 3.10) and newer firewalld-based distros.

## Features

| Section | What it shows |
|---|---|
| Alerts | Stopped services, HTTPS certificates close to expiry, full disk/RAM/swap, high CPU load, network drive offline |
| Resources | CPU, RAM, swap, disk, network speed, 24-hour / 7-day charts |
| Services | Status, uptime, CPU, RAM and listening ports of each service; ports are marked as **open to the Internet**, local only, or Tailscale only |
| Connections | Who is using the proxy, WireGuard peers (last handshake, traffic), Tailscale devices (direct or relayed) |
| Attacks | Hourly/daily chart, most scanned ports, top scanning IPs, IPs guessing the proxy password, recent events |
| Country | Flag and country name next to every IP (DB-IP Lite, looked up on the machine, IPs never leave it) |
| IP blocking | **Block / Unblock** buttons → firewalld zone `drop` (runtime + permanent) |

## Requirements

- Linux with **systemd** and **python3 ≥ 3.6**
- **firewalld** running (needed for scan capture and IP blocking; everything else works without it)
- Optional: the [gost v3](https://github.com/go-gost/gost) proxy (auth-failure logs), WireGuard (`wg`), Tailscale, Caddy

## Install

```bash
git clone https://github.com/ngank491/vps-dashboard.git
cd vps-dashboard
sudo ./install.sh
```

The script will:
1. copy the program to `/opt/vpsmon`,
2. create the config `/etc/vpsmon/vpsmon.env` if it does not exist yet (the network interface is detected automatically),
3. add 4 NFLOG rules to firewalld (IPv4/IPv6 × TCP/UDP). They **only record packets; they do not block or open any port**,
4. install and start the `vpsmon` service (listening on `127.0.0.1:8790`).

Run `sudo ./install.sh` again to update the code, or after changing firewall-related settings in the env file. Installer messages are in Vietnamese when `LANG` starts with `vi`, otherwise in English.

## Configuration

Edit `/etc/vpsmon/vpsmon.env`, then run `sudo systemctl restart vpsmon`. The most important settings (see [vpsmon.env.example](vpsmon.env.example) for all of them):

| Variable | Meaning |
|---|---|
| `VPSMON_TCP_IGNORE`, `VPSMON_UDP_IGNORE` | Legitimate public service ports that are not counted as scans (e.g. `80,443`) |
| `VPSMON_PROXY_PORTS` | Proxy ports to watch, e.g. `21080:SOCKS5,23128:HTTP` |
| `VPSMON_PROXY_UNIT` | systemd unit of the gost proxy (leave empty if you don't use one) |
| `VPSMON_SERVICES` | Main services shown at the top of the table |
| `VPSMON_OWN_IPS` | **The VPS's public IP when it sits behind NAT** (Oracle, AWS, GCP…), so the Block button never blocks the VPS itself |
| `VPSMON_NAS_PATH` | Network drive mount point to monitor (optional) |
| `VPSMON_GEOIP` | `1` = show countries (downloads ~8 MB, refreshed monthly), `0` = off |

To name a WireGuard peer, add a comment line right above its `[Peer]` section in `/etc/wireguard/wg0.conf`, e.g. `# Laptop`.

## Accessing it safely

The dashboard **listens on localhost only and has no login**. Do not expose it directly to the Internet. Use one of these:

- **SSH tunnel**: `ssh -L 8790:127.0.0.1:8790 user@vps`, then open <http://localhost:8790/>
- **Caddy restricted to Tailscale**: see [examples/Caddyfile](examples/Caddyfile), giving `https://<machine>.<tailnet>.ts.net/monitor/`

## Security

- The service runs as root but keeps only these capabilities: `CAP_NET_ADMIN` (NFLOG, `wg`), `CAP_DAC_READ_SEARCH` (reading certificates) and `CAP_SYS_PTRACE` (only to read `/proc/PID/fd` and map ports to services). It also uses `ProtectSystem=full`, `ProtectHome`, `NoNewPrivileges` and an 80 MB memory limit.
- WireGuard private keys are never sent to the page.
- The block API (`POST /api/block`):
  - only accepts JSON with a custom `X-Vpsmon: 1` header and an `Origin` matching the host, so other websites cannot send block commands on your behalf (CSRF),
  - blocks **single IPs** only, after validating the format,
  - **refuses** the VPS's own IPs, private/Tailscale/special ranges, and the network IPs of your Tailscale/WireGuard devices (remembered automatically, e.g. your home IP),
  - adds the block to firewalld runtime and permanent config **without** `--reload`. Every action is logged to `journalctl -u vpsmon`.

## Uninstall

```bash
sudo ./uninstall.sh           # keep data and config
sudo ./uninstall.sh --purge   # also delete data and config
```

Blocked IPs stay in firewalld's `drop` zone.

## Limitations

- Only packets that actually reach the VPS are seen. If the provider filters them first (e.g. an Oracle Security List), they are not counted.
- Captured packets are rate-limited to 200 per second to survive floods, so counts during heavy attacks are underestimates.
- The country is where the IP range is registered (usually where a rented server sits), not where the person running the bot is.
- Proxy auth-failure logs currently support the JSON log format of gost v3.

## License

MIT. See [LICENSE](LICENSE).

Country data: [IP Geolocation by DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (downloaded at run time, not included in the repo).

# proxy-router

Selective tunnel router with per-provider failover, powered by [sing-box](https://sing-box.sagernet.org/).
Spiritual successor to `tools/opencode-zen-vpn` (retired).

## What it does

Runs a local mixed HTTP/SOCKS proxy at `127.0.0.1:2080` and routes only
matching domains/IPs through a WireGuard tunnel — everything else goes direct.
Routes can point at different tunnel providers (e.g. `opencode.ai -> proton`,
`roblox.com -> cloudflare`), and each provider keeps a pool of profiles that
rotate on demand (rate limits, server death) while the listener stays up
(config is hot-reloaded via SIGHUP, no restart).

On macOS the system proxy can be switched on/off (`up`/`down`) so the rest of
the system also uses the selective proxy.

Core CLI runs on macOS, Linux, and Windows. The macOS-only bits (`up`/`down`
and the launchd keep-alive) are guarded and print a clear message elsewhere.

## Requirements

- Python 3.10+ (stdlib only — no pip install)
- sing-box — bundled in the release archives (`bin/sing-box`), or available on
  `PATH`, or pointed at via `SING_BOX` env var

## Install

MacOS / Linux:

```sh
tar xzf proxy-router-<version>-<os>.tar.gz
cd proxy-router
./install.sh          # installs to ~/.local/share/proxy-router, links `proxy-router` on PATH
```

Windows (PowerShell):

```powershell
Expand-Archive proxy-router-<version>-windows-amd64.zip
cd proxy-router
powershell -ExecutionPolicy Bypass -File install.ps1
```

Then set up your first provider (see [Provider setup](#provider-setup)) and
start:

```sh
proxy-router init            # writes router.json from router.example.json
proxy-router ensure          # start engine if the listener is down (idempotent)
```

## Layout

```
router.py                    engine + CLI (single file, stdlib only)
router.example.json          config template (port, providers, cooldowns, route table)
install.sh / install.ps1     installers
bin/sing-box(.exe)           bundled engine binary (release archives only)
examples/keepalive.sh        re-arms the engine if the listener dies
examples/com.proxy-router.keepalive.plist.template   launchd agent loading keepalive
examples/hermes-opencode.sh  bounded model-run wrapper with automatic rotation
tests/                       unit tests (unittest, no deps)
providers/<provider>/        WireGuard configs, one file per profile (chmod 600)
state/                       active profile + cooldown markers (gitignored)
sing-box.json / .pid / .log  runtime state (gitignored)
```

## Usage

```sh
./router.py ensure                # start engine if the listener is down (idempotent)
./router.py start / stop / status
./router.py routes               # list route table
./router.py vpn on               # full TUN mode: route everything via the engines' rules
./router.py vpn off              # stop the TUN, back to proxy mode
./router.py vpn status           # show current mode and liveness
./router.py add --domain example.com --provider proton [--id my-route]
./router.py add --ip 1.2.3.0/24 --provider proton [--id my-route]
./router.py remove <id>
./router.py rotate <provider>    # switch to next cooled-down profile, hot reload
./router.py provider-count proton # rotation candidates (retry budget)
./router.py init                 # write a fresh router.json
./router.py up                   # enable macOS system proxy (also ensures engine)
./router.py down                 # disable macOS system proxy only (engine keeps running)
```

Every state-changing command takes an exclusive lock, so concurrent calls
are safe; read-only commands (`status`, `routes`, `provider-count`, `vpn
status`, `init`) do not.

## VPN (TUN) mode

`vpn on` switches the engine from a local mixed proxy (`127.0.0.1:2080`) to a
system TUN interface. sing-box `auto_route` then captures **all** traffic at
the IP layer — including apps that ignore system proxy settings — while the
same route rules still decide which domains go through which provider and
everything else exits `direct`. `vpn off` returns to proxy mode; `ensure`,
`reload`, `add`/`remove` and `rotate` all respect whatever mode is active.

Platform notes:

- **Linux**: needs root for the TUN device + route table (iproute2)
  (`sudo proxy-router vpn on`).
- **Windows**: needs an elevated shell and `wintun.dll` next to
  `sing-box.exe` (drop it from the official Wintun release).
- **macOS**: needs root to create the `utun` interface
  (`sudo proxy-router vpn on`). This is NOT a System Settings VPN provider
  entry — that would require a signed NetworkExtension app. It is a TUN
  interface managed from the terminal.

TUN options live under `"vpn"` in `router.json`:
`address` (CIDR list), `mtu`, `stack` (`system`, default | `gvisor`).

## Provider setup

Each profile is a sing-box-compatible WireGuard config dropped into
`providers/<provider>/` as `<name>.conf`. The provider name (e.g. `proton`)
becomes the sing-box endpoint tag.

Proton VPN: export a WireGuard config for each server from the app/account
page and drop the files in. Cloudflare WARP: generate a config with `wgcf`
(`wgcf account` then `wgcf generate`) and save it as
`providers/cloudflare/warp.conf`, then add `"cloudflare": {}` to `router.json`.

### Config reference (`router.json`)

```json
{
  "port": 2080,
  "providers": {
    "proton":     { "cooldown_seconds": 60 },
    "cloudflare": { "cooldown_seconds": 60 }
  },
  "routes": [
    { "id": "opencode", "domains": ["opencode.ai"], "provider": "proton" },
    { "id": "roblox",   "domains": ["roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com"], "provider": "cloudflare" }
  ]
}
```

- Route domains and IP CIDRs select which traffic enters a tunnel; everything
  else matches `direct` (unmatched) traffic.
- Every active provider injects one DNS server taken from its WireGuard
  profile's `[Interface] DNS` (fallback `1.1.1.1`) and routed through the
  tunnel — matching domains resolve there.
- A provider with no profiles is skipped entirely; its routes stay inert until
  a profile appears.

Notes on claims vs reality:

- The provider `"dns"` key in `router.json` is **not read** — DNS comes from
  each profile's `[Interface] DNS` line.
- Profile files are **not** chmod'd 600 (only state files and the generated
  `sing-box.json` are); the install dir is chmod 700 instead.
- `router.py init` refuses to overwrite an existing `router.json` unless you
  pass `--force`; the installer never overwrites it either.

## Self-healing

On macOS: install the launchd agent to re-arm a crashed engine every 15s:

```sh
./install.sh
examples/install-launchd.sh     # writes the plist with your paths and bootstraps
launchctl bootout gui/$(id -u)/com.proxy-router.keepalive   # remove
```

Linux/Windows: run `examples/keepalive.sh` under a supervisor of your choice
(systemd service / Task Scheduler / tmux).

## Hermes integration

Point `hermes` at the proxy (`http://127.0.0.1:2080` via
`https_proxy`/`http_proxy`). `examples/hermes-opencode.sh` wraps model runs:
on rate-limit/transient-http/transport failures it rotates the provider pool
once per profile and retries the exact same command after 15s
(`OPENCODE_RETRY_DELAY_SECONDS` to override, `OPENCODE_MAX_ATTEMPTS` to cap,
`OPENCODE_PROVIDER` to change the pool).

## Troubleshooting

- `FATAL start service: bind: address already in use` — another sing-box owns
  the port; stop it first, then `./proxy-router start`.
- Route changes don't apply — `reload`/`add`/`remove` SIGHUP the running
  process; a stale pid file with a dead listener needs a `start`.
- macOS system proxy toggles use the active network service (the default
  route's hardware port), so Wi-Fi won't be missed when on Ethernet.

## Development

```sh
python3 -m unittest discover tests
```

## License

[MIT](LICENSE)
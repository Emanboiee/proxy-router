# proxy-router

Selective tunnel router with per-provider failover, powered by [sing-box](https://sing-box.sagernet.org/).
Spiritual successor to `tools/opencode-zen-vpn` (retired).

## What it does

Runs a local mixed HTTP/SOCKS proxy at `127.0.0.1:2080` and routes only
matching domains/IPs through a WireGuard tunnel — everything else goes direct.
Routes can point at different tunnel providers (e.g. `roblox.com ->
cloudflare` and `opencode.ai -> proton`), and each provider keeps a pool of
profiles that rotate on demand (rate limits, server death) while the listener
stays up (config is hot-reloaded via SIGHUP, no restart). The default template
keeps the route table conservative; `proxy-router setup --preset` applies the
validated Proton/WARP presets explicitly.

On the current deployment, OpenCode Zen uses the Proton pool and Roblox uses
Cloudflare WARP. Direct egress remains the fallback when all tunnel exits are
unhealthy.

Core CLI runs on macOS, Linux, and Windows. The macOS-only bits (`up`/`down`
and the launchd keep-alive) are guarded and print a clear message elsewhere.

## Requirements

- Python 3.10+ (stdlib only — no pip install)
- sing-box **1.12.0 or newer** — bundled in the release archives
  (`bin/sing-box`), or available on `PATH`, or pointed at via `SING_BOX` env
  var. Older binaries are rejected up front: the generated config relies on
  the 1.12+ dialer `domain_resolver`, route `default_domain_resolver` and the
  `hijack-dns` rule action.

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

Then initialize the config and use the setup TUI/guide path:

```sh
proxy-router init
proxy-router setup --guide all
proxy-router setup --import-proton ~/Downloads/protonvpn-*.conf
proxy-router setup --import-warp ~/Downloads/wgcf-profile.conf  # optional
proxy-router setup --preset
proxy-router setup --check
proxy-router ensure
```

`proxy-router setup` with no flags opens the custom terminal wizard. It never
enables TUN mode or starts monitoring unless you explicitly choose those
operations.

## Layout

```
router.py                    engine + CLI (single file, stdlib only)
setup_tui.py                 custom terminal setup wizard + safe imports
monitor.py                   opt-in latency/ping/speed monitor worker
router.example.json          config template (port, providers, cooldowns, route table)
guides/proton-vpn-free.md    Proton VPN Free WireGuard guide
guides/cloudflare-warp.md    Cloudflare WARP/wgcf guide
install.sh / install.ps1     installers
bin/sing-box(.exe)           bundled engine binary (release archives only)
examples/keepalive.sh        re-arms the engine if the listener dies
examples/com.proxy-router.keepalive.plist.template   launchd agent loading keepalive
examples/hermes-opencode.sh  bounded model-run wrapper with automatic rotation
examples/proxy-manager.sh   bridge for the Hermes opencode-server-rotation plugin
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
./router.py setup                  # custom setup TUI
./router.py setup --guide all      # print Proton + WARP guides
./router.py setup --preset         # enable OpenCode->Proton and Roblox->WARP presets
./router.py setup --check          # validate imported profiles without networking
./router.py monitor status          # read monitor state; never probes
./router.py monitor check           # explicit one-shot ping/latency/speed sample
./router.py monitor on              # opt in to a detached sample worker (60s default)
./router.py monitor off             # stop the worker and remove active state
./router.py monitor logs            # show recent JSONL samples
./router.py init                 # write a fresh router.json (exists => refused; add --force)
./router.py up                   # enable macOS system proxy (also ensures engine)
./router.py down                 # disable macOS system proxy only (engine keeps running)
```

Every state-changing command takes an exclusive lock, so concurrent calls
are safe; read-only commands (`status`, `routes`, `provider-count`, `vpn
status`, `init`) do not.

`status` and `vpn status` report the same state (exit 0 = engine up and
matching the persisted mode; exit 1 = down, degraded, or unusable config), so
scripts and humans can rely on either one.

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

Two more knobs in `"vpn"` control address-family policy:

- `dns_strategy` — how domain *destinations* are resolved by the DNS module.
  Default `ipv4_only` (the tunnels carry only the IPv4 addresses assigned in
  each profile). Valid values: `ipv4_only`, `ipv6_only`, `ipv4_prefer`,
  `ipv6_prefer`.
- `prefer_ipv6_peers` — whether WireGuard *peer endpoints* that are domains
  resolve to an IPv6 address when one exists (default `true`; some networks
  drop the WARP IPv4 endpoint so the IPv6 one must be used). This is a
  separate scope from `dns_strategy`: endpoints are the tunnel servers,
  destinations are the sites you route.

## Provider setup

Each profile is a sing-box-compatible WireGuard config dropped into
`providers/<provider>/` as `<name>.conf`. The provider name (e.g. `proton`)
becomes the sing-box endpoint tag.

The easiest path is the setup wizard:

```sh
proxy-router setup                  # interactive terminal menu
proxy-router setup --guide proton   # print the bundled Proton guide
proxy-router setup --guide warp     # print the bundled WARP guide
proxy-router setup --import-proton ~/Downloads/*.conf
proxy-router setup --import-warp ~/Downloads/wgcf-profile.conf
proxy-router setup --preset          # idempotently adds both safe route presets
proxy-router setup --check
```

The full provider instructions live in
[`guides/proton-vpn-free.md`](guides/proton-vpn-free.md) and
[`guides/cloudflare-warp.md`](guides/cloudflare-warp.md). The importer validates
WireGuard structure, sanitizes filenames, and writes profiles as `0600`; it
never prints private keys. Proton's flaky private resolver `10.2.0.1` is
replaced by public DNS through the tunnel.

### Config reference (`router.json`)

```json
{
  "port": 2080,
  "providers": {
    "proton":     { "cooldown_seconds": 60 },
    "cloudflare": { "cooldown_seconds": 60 }
  },
  "routes": [
    { "id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton" },
    { "id": "roblox", "domains": ["roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com"], "provider": "cloudflare" }
  ]
}
```

`proxy-router setup --preset` adds the two routes above idempotently. Route
choice is configurable: the current validated deployment uses the Proton pool
for OpenCode Zen and Cloudflare WARP for Roblox, while unmatched traffic stays
direct. If every tunnel exit is unhealthy, direct OpenCode egress remains the
fallback; the router does not claim that a tunnel is healthy merely because a
profile parses.

- Route domains and IP CIDRs select which traffic enters a tunnel; everything
  else matches `direct` (unmatched) traffic.
- Every active provider injects one DNS server taken from its WireGuard
  profile's `[Interface] DNS` (fallback `1.1.1.1`) and routed through the
  tunnel — matching domains resolve there (strategy `ipv4_only` by default;
  see the `vpn.dns_strategy` option if your tunnels carry IPv6).
- A provider with no profiles is skipped entirely; its routes stay inert until
  a profile appears.

Notes on claims vs reality:

- The provider `"dns"` key in `router.json` is **not read** — DNS comes from
  each profile's `[Interface] DNS` line.
- The setup importer chmods imported profile files `600`; manually placed
  profiles must be secured by the operator. State files and generated
  `sing-box.json` are also protected.
- `router.py init` refuses to overwrite an existing `router.json` unless you
  pass `--force`; the installer never overwrites it either.

## Optional network monitoring

Monitoring is completely off by default. Normal proxy traffic does not start a
worker, timer, ping, HTTP request, or speed test. Use it only when you want a
snapshot or a background time series:

```sh
proxy-router monitor status     # state only; no network activity
proxy-router monitor check      # one explicit bounded sample
proxy-router monitor on         # detached worker, 60-second samples
proxy-router monitor logs       # bounded tail of JSONL samples
proxy-router monitor off        # stop worker and remove enabled state
```

Each sample records HTTP latency, ICMP ping where the platform provides it, and
bounded download/upload throughput. The worker state and samples live under
`state/monitor/` and are mode `0600`; `monitor on` is the only command that
starts recurring work. An optional `monitor` object in `router.json` can set
`interval_seconds`, `ping_hosts`, URLs, `max_bytes`, and timeouts. Speed checks
are intentionally bounded and use a conservative 1 MB default.

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

The Hermes `opencode_server_rotation` plugin expects a rotation manager at
`tools/opencode-zen-vpn/proxy-manager.sh` (its `rotate` subcommand). That
directory was retired; ship `examples/proxy-manager.sh` to that exact path to
bridge the plugin onto this router's `rotate` command (which provider is
rotated is `OPENCODE_PROVIDER`, defaulting to `proton`). No plugin or Hermes
config changes are needed.

## Troubleshooting

- `proxy-router: command not found` in interactive shells — the installer
  links into `~/.local/bin`. If that isn't on your shell's PATH, add
  `export PATH="$HOME/.local/bin:$PATH"` to `~/.zshrc` (or equivalent) and
  open a fresh login shell.
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
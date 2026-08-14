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
proxy-router setup --bridge-install  # install the Hermes OpenCode rotation bridge
proxy-router setup --bridge-force-install  # overwrite an existing bridge file
proxy-router setup --bridge-check    # verify the installed bridge
proxy-router ensure
```

`proxy-router setup` with no flags opens the custom terminal wizard. It never
enables TUN mode or starts monitoring unless you explicitly choose those
operations. Menu item 9 installs/verifies the Hermes OpenCode auto-rotation
bridge (placed at `$OPENCODE_ZEN_VPN_ROOT/proxy-manager.sh`).

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
./router.py rotate <provider>    # switch to next healthy profile, hot reload
./router.py rotate <provider> --reason 503|429|timeout|1010  # mark CURRENT exit failed upstream, prefer a different one
./router.py rotate <provider> --force   # switch anyway, ignoring cooldowns and blocked exits
./router.py rotate <provider> --no-probe # skip the post-switch egress probe
./router.py provider-count proton # rotation candidates (retry budget)
./router.py egress probe [provider]  # probe current exit(s) through the tunnel, persist health
./router.py egress show [provider]   # print persisted egress records (JSON)
./router.py egress check [--provider <name>] [--json]  # read-only live check: exit 1 ONLY when an active exit is DEAD
./router.py egress sweep [provider] [--json]  # full-pool sweep: probe EVERY profile, end on the best alive exit
./router.py status --json         # machine-readable status for scripts/Hermes
./router.py setup                  # custom setup TUI
./router.py setup --guide all      # print Proton + WARP guides
./router.py setup --preset         # enable OpenCode->Proton and Roblox->WARP presets
./router.py setup --check          # validate imported profiles without networking
./router.py setup --bridge-install # install/verify the Hermes OpenCode rotation bridge
./router.py setup --bridge-check   # verify the installed bridge without writing
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
scripts and humans can rely on either one. `status --json` adds the active
profile, per-profile cooldowns and egress records, last rotation, and route
table as JSON (same exit code) so automation can make decisions without
parsing human text.

## Egress health & rotation smarts

Each provider exit tracks health under `state/egress/<provider>/<profile>.json`
(atomic, mode 0600): last probe latency, consecutive failures, and an optional
`blocked` marker. A probe is a small GET to the first domain the provider
routes, sent THROUGH `127.0.0.1:<port>` so it exercises the real tunnel
end-to-end (a URL matching no route would go out direct and measure the wrong
path).

Rotation is then egress-aware instead of blind round-robin:

- Profiles with a fresh OK probe are preferred, fastest latency first;
  unknown profiles come next; profiles with repeated failures (`fail_threshold`,
  default 2) rank last.
- Profiles with a `blocked` marker (Cloudflare 1010/403 egress-IP reputation
  blocks, recorded by `rotate --reason 1010` or the probe itself) are skipped
  until the marker expires (`egress.block_seconds`, default 1h) or you run
  `rotate --force`.
- `rotate --reason <what>` gives the CURRENT profile a longer cooldown
  (`egress.upstream_cooldown_seconds`, default 300s) plus a recorded reason, so
  503/429/timeout storms steer away from the exit that just failed upstream.
- After switching, the new exit is probed; if it does not come up cleanly the
  router restores the previous good profile (one bounded rollback step).
- `egress probe` refreshes health on demand without rotating.
- `egress sweep` [provider] probes EVERY profile of the pool through the
  running tunnel (not just the active exit), persisting per-profile health,
  cooldown, and blocked markers, then ends on the best alive profile - lowest
  latency first, unmeasured alive profiles ranking after measured ones. It
  hops through the pool in wrap order (one `rotate` per step, engine reloaded
  each hop) with a short settle wait after each switch, so the first-request
  flake of a fresh WireGuard handshake never false-marks an exit failed. When
  nothing is alive the tunnel stays on the current profile and exit code 1
  signals a provider with zero alive exits (`--json` names them under
  `dead`). A sweep reloads the engine only when a strictly better exit was
  found, so a healthy sweep is cheap.
- `egress check` is the read-only liveness view used by the keepalive self-heal
  loop: it probes the ACTIVE exit(s) through the running tunnel and classifies
  each one `alive` (HTTP response rode the tunnel), `degraded` (an HTTP status
  arrived but was not ok - e.g. a Cloudflare 1010/403 reputation block or 5xx,
  i.e. NOT a dead tunnel), or `dead` (transport-level failure, no HTTP status
  at all - the tunnel path itself is broken). A companion DNS probe records
  `dns_ok` in the egress record when determinable: `dead` with `dns_ok: false`
  means resolution through the tunnel failed, `dns_ok: true` means a later
  dial/read stage failed. Exit code is 1 only when an exit is `dead`, so
  automation never rotates on a reputation-block HTTP status.
- A `sing-box.json.last-good` snapshot (atomic, 0600) is written whenever a
  freshly built config validates AND the engine demonstrably comes up with it;
  if a later reload's config fails validation or the engine fails to come up,
  the router restores the last-good config and reloads/starts once - never
  looping, and failing with a clear message when no last-good exists or the
  restore itself fails.

Tunables live in `router.json` under `"egress"` (see `router.example.json`).

## Error policy table (`error_policy`)

What happens to a lane after an upstream failure is configurable per reason via
a top-level `"error_policy"` table in `router.json`. Each reason maps to an
action and a duration:

```json
"error_policy": {
  "default": { "action": "cooldown", "seconds": 300 },
  "429":     { "action": "exhaust", "seconds": 900 },
  "503":     { "action": "cooldown", "seconds": 120 },
  "timeout": { "action": "cooldown", "seconds": 60 },
  "tls":     { "action": "cooldown", "seconds": 300 },
  "connection": { "action": "cooldown", "seconds": 300 },
  "1010":    { "action": "block", "seconds": 3600 },
  "403":     { "action": "block", "seconds": 3600 }
}
```

Semantics:

- `cooldown` — normal cooldown (`mark_cooldown`): rotation skips the lane
  until the timer resets.
- `exhaust` — cooldown **plus** `exhausted: true`, `exhausted_at` and an
  ISO-8601 `exhausted_until` written into the profile's egress record, so
  `status --json` and external scripts see the lane is dead for this turn
  (e.g. a free-tier quota lane that should not be retried for 15 minutes).
- `block` — reputation block (`mark_blocked`): rotation skips the lane
  entirely until the marker expires or `rotate --force` clears it (used for
  Cloudflare 1010/403 egress-IP reputation blocks).

Merge precedence (smallest merge surface, no breaking config changes): a
per-provider `providers.<name>.error_policy` beats the global top-level
`error_policy`, which beats the built-in defaults above. Missing reasons fall
back to the effective `default` entry. A reason is matched loosely before
exact lookup: `cloudflare-1010` → `1010`, `HTTP 503` / `503` → `503`,
SSL/TLS errors → `tls`, timeouts → `timeout`, dial/connect/reset errors →
`connection`, anything else by its slugified text (so custom reason keys like
`"429"` overrides still work).

Where it is consumed:

- `rotate --reason <x>` — `_apply_upstream_failure` now applies the policy
  entry (seconds + action) for `<x>` instead of the flat
  `upstream_cooldown_seconds or max(...)` computation. 1010/403 text always
  blocks regardless of the table.
- `probe_profile` / `check_egress_live` — a transport/TLS death (no HTTP
  status) is cooled with the policy's `tls`/`connection` seconds (built-in
  300s, which is the merged TLS-cooldown rule). A degraded HTTP status
  (reputation block / 5xx) is never cooled.
- `status --json` — echoes the effective policy for every provider under the
  top-level `"error_policy"` key, and each profile's egress record carries
  `exhausted`/`exhausted_at`/`exhausted_until` when an exhaust policy has
  fired, so automation can read the exact reset time.

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
proxy-router setup                  # interactive terminal menu (item 9: Hermes rotation bridge)
proxy-router setup --guide proton   # print the bundled Proton guide
proxy-router setup --guide warp     # print the bundled WARP guide
proxy-router setup --import-proton ~/Downloads/*.conf
proxy-router setup --import-warp ~/Downloads/wgcf-profile.conf
proxy-router setup --preset          # idempotently adds both safe route presets
proxy-router setup --check
proxy-router setup --bridge-install  # install/verify the Hermes OpenCode rotation bridge
proxy-router setup --bridge-force-install  # overwrite an existing bridge file
proxy-router setup --bridge-check    # verify the bridge without writing
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

The keepalive waits `PROXY_KEEPALIVE_INTERVAL` (default 15s) between checks,
but while `ensure` keeps failing the wait grows exponentially (15, 30, 60, ...)
up to `PROXY_KEEPALIVE_MAX_BACKOFF` (default 300s), so a dead engine is not
hammered; one successful check resets the wait. `sing-box.log` is also rotated
to `sing-box.log.1` once it exceeds 10 MB (at engine start, when no engine
holds the log).

`ensure` only proves the process is alive, so the keepalive ALSO self-heals a
dead-but-listening tunnel (WireGuard handshake/route dead while the port still
accepts): every `PROXY_KEEPALIVE_PROBE_EVERY` successful ensures (default 4,
roughly 60s at the base interval) it runs `router.py egress check`, which
probes the ACTIVE exit through the tunnel. After
`PROXY_KEEPALIVE_DEAD_STRIKES` consecutive dead checks (default 2 - a single
transient blip never rotates) it runs `router.py rotate <provider> --reason
timeout` (respecting cooldown/block semantics, never `--force`); a successful
check resets the dead-counter. On start, the first successful ensure triggers
one boot self-test: a dead tunnel logs a loud warning and gets ONE early
rotation; a healthy tunnel logs `router: boot self-test ok`. Keepalive
rotations are capped at `PROXY_KEEPALIVE_MAX_ROTATIONS` (default 2) per
`PROXY_KEEPALIVE_STORM_WINDOW` seconds (default 600), so a genuinely broken
pool can never rotation-storm.

The dead-tunnel checks only ever probe the ACTIVE exit, so a pool could sit
on a stale-but-alive lane forever. Every `PROXY_KEEPALIVE_SWEEP_EVERY`
seconds (default 1800 = 30 min) the keepalive therefore runs a full-pool
`egress sweep` (see "Egress health & rotation smarts"): every profile of
every provider is probed through the tunnel and the pool ends on the best
alive exit, with health/cooldown/block markers persisted along the way.

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
- WARP tunnel dead on every probe while Proton works — your network may be
  dropping UDP `2408`; switch the profile's `Endpoint` to `4500` and reload
  (see [guides/cloudflare-warp.md](guides/cloudflare-warp.md) →
  Troubleshooting).

## Development

```sh
python3 -m unittest discover tests
```

## License

[MIT](LICENSE)
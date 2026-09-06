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

Providers are bring-your-own: drop WireGuard profiles under
`providers/<name>/` (see the guides) and reference the provider name from
routes. A provider may declare an ordered `fallback_providers` chain, so its
routed domains keep working when its pool goes dead; direct egress remains
the final fallback when all tunnel exits are unhealthy or the router is down.

Core CLI runs on macOS, Linux, and Windows. The macOS-only bits (`up`/`down`
and the launchd keep-alive) are guarded and print a clear message elsewhere.

## Requirements

- Python 3.10+. The core CLI (`router.py`, `setup_tui.py`, `monitor.py`,
  `route_watcher.py`) is stdlib-only — no `pip install` needed. The optional
  macOS menu-bar tray additionally needs **pystray + Pillow**
  (`python3 -m pip install pystray pillow`; see the Tray section below).
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

The installer creates `router.json` from `router.example.json` on first run
(once — reruns never clobber it), so there is nothing to initialize by hand.
`init` is only for creating a fresh config from a bare checkout, and it
refuses to overwrite an existing file unless you pass `--force`. After
installing, validate what shipped and bring the engine up:

```sh
proxy-router setup --check    # validate router.json + provider profiles (offline)
proxy-router ensure           # start the engine if the listener is down
```

Then add providers with the wizard:

```sh
proxy-router setup --guide all
proxy-router setup --import-proton ~/Downloads/protonvpn-*.conf
proxy-router setup --import-warp ~/Downloads/wgcf-profile.conf  # optional
proxy-router setup --preset            # apply the default preset
proxy-router setup --preset-list       # list built-in + custom presets
proxy-router setup --bridge-install    # install the Hermes OpenCode rotation bridge
proxy-router setup --bridge-check      # verify the installed bridge
proxy-router setup --check             # re-validate after importing
proxy-router ensure
```

The shipped `router.example.json` template is deliberately vendor-neutral:
generic providers `primary-vpn` / `fallback-vpn` (with a
`fallback_providers` chain) and a conservative route table. The validated,
provider-specific presets are applied explicitly by name via
`setup --preset <name>` — built-ins: `default` (OpenCode → Proton + Roblox →
WARP combo), `opencode`, `roblox`, `school-warp` (VPN-list routing plus DoH
DNS for filtered/captive networks). List them any time with
`proxy-router setup --preset-list`.

`proxy-router setup` with no flags opens the custom terminal wizard. It never
enables TUN mode or starts monitoring unless you explicitly choose those
operations. Menu item 8 installs/verifies the Hermes OpenCode auto-rotation
bridge (placed at `$OPENCODE_ZEN_VPN_ROOT/proxy-manager.sh`).

## Layout

```
router.py                    engine + CLI (single file, stdlib only)
setup_tui.py                 custom terminal setup wizard + safe imports
monitor.py                   opt-in latency/ping/speed monitor worker
route_watcher.py             standalone routed-connection watcher
proxy_tray.py                optional macOS/Windows tray (needs pystray + Pillow)
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
./router.py doctor                # read-only health audit: config, profiles, listener, egress summary
./router.py routes               # list route table
./router.py vpn on               # default selective TUN: configured routes tunnel, rest stays direct
./router.py vpn off              # stop the TUN, back to proxy mode
./router.py vpn restart          # stop + re-enter TUN through the installed helper
./router.py vpn status           # show current mode and liveness
./router.py vpn capture routes   # dump the TUN route rules sing-box is using
./router.py vpn capture ruleset  # dump the selective ruleset capture config
./router.py routing show         # effective routing mode + lists (JSON + human)
./router.py routing set --mode vpn-list        # switch routing mode (safe-list | vpn-list | default)
./router.py routing set --mode safe-list --default-provider proton
./router.py routing add --mode safe-list --domain example.com  # add a domain to a list
./router.py routing remove --mode vpn-list --domain example.com
./router.py elevate install      # one-time macOS admin prompt; install root-owned lifecycle helper
./router.py elevate uninstall    # stop engine and remove helper + exact sudoers policy
./router.py elevate status       # is the safe helper active for this user?
./router.py add --domain example.com --provider proton [--id my-route]
./router.py add --ip 1.2.3.0/24 --provider proton [--id my-route]
./router.py remove <id>
./router.py rotate <provider>    # switch to next healthy profile, hot reload
./router.py rotate <provider> --reason 503|429|timeout|1010  # mark CURRENT exit failed upstream, prefer a different one
./router.py rotate <provider> --force   # switch anyway, ignoring cooldowns and blocked exits
./router.py rotate <provider> --no-probe # skip the post-switch egress probe
./router.py rotate --if-due      # scheduled rotation: proxy mode only; TUN returns 3 to preserve live flows
./router.py rotate <provider> --to 01-NL-FREE-140  # switch to this exact exit profile (used by the tray's Provider picker)
./router.py response-event --host example.com --status 429 [--provider proton]
                                 # feed an observed upstream status into cooldown/error-policy handling
./router.py profile copy <path...> --provider proton
                                 # copy validated .conf file(s)/directory into a provider
./router.py watcher status       # routed-connection watcher state (JSON)
./router.py watcher on           # start the standalone watcher (config-driven critical domains)
./router.py watcher off          # stop it (exit 1 when nothing was running)
./router.py watcher logs         # tail recent watcher event lines
./router.py network-check        # auto-apply the preset mapped to the current Wi-Fi (run by the route watcher every 30s)
./router.py failover <provider> on [--to <fallback>]  # route the provider's domains through its configured fallback chain (first valid entry, or the named member)
./router.py failover <provider> off    # clear fallback and restore the provider's routes
./router.py failover <provider> status --json   # configured chain + active fallback
./router.py provider-count proton # rotation candidates (retry budget)
./router.py providers check [provider] [--json]  # offline validity preflight: which providers can carry traffic at all (exit 1 = some invalid)
./router.py with-proxy [--timeout-ms 300] [--force-proxy|--force-direct] -- <cmd...>
                                 # fail-open runner: exec <cmd> through the proxy when up, else direct
./router.py with-proxy --check   # health check: prints proxy URL + exit 0 when up, exit 1 when down
./router.py egress probe [provider]  # probe current exit(s) through the tunnel, persist health
./router.py egress show [provider]   # print persisted egress records (JSON)
./router.py egress check [--provider <name>] [--json]  # read-only live check: exit 1 ONLY when an active exit is DEAD
./router.py egress sweep [provider] [--json] [--allow-tun]  # full-pool sweep; --allow-tun acknowledges a TUN interruption
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

Set `vpn.network_auto: true` and a `vpn.network_presets` map (`"SSID": "preset-name"`) in
`router.json` to switch presets automatically when you join a known network — e.g.
`{"MySchoolWiFi": "school-warp", "MyHomeWiFi": "default"}`. The route watcher applies
the mapped preset and hot-reloads the engine within ~30s of a network change. Unknown
networks keep the current preset.

Every state-changing command takes an exclusive lock, so concurrent calls
are safe; read-only commands (`status`, `routes`, `provider-count`, `vpn
status`) do not. (`init` is NOT in that group: it writes `router.json`, and
it refuses to touch one that already exists unless you pass `--force`.)

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
  found, so a healthy sweep is cheap. In TUN mode this command requires
  `--allow-tun` because each profile hop reloads the shared engine.
- The launchd keepalive leaves `egress check` read-only in TUN mode: it skips
  scheduled rotation, dead-exit recovery, full-pool sweeps, and fallback
  changes because every provider shares one engine. Explicit `rotate`,
  `egress sweep`, and `failover` commands remain available for intentional
  operator-controlled interruptions.
- `egress check` is the read-only liveness view used by the keepalive self-heal
  loop: it probes the ACTIVE exit(s) through the running tunnel and classifies
  each one `alive` (HTTP response rode the tunnel), `degraded` (an HTTP status
  arrived but was not ok - e.g. a Cloudflare 1010/403 reputation block or 5xx,
  i.e. NOT a dead tunnel), or `dead` (connection-level failure, no HTTP status
  and no TLS handshake - the tunnel path itself is broken). A TLS-classed
  failure (SSL EOF / `SSL_ERROR_SYSCALL` / TLS alert) is also `degraded`: the
  TCP CONNECT rode the tunnel, so the path works and the upstream endpoint is
  throttling (Proton free tier routinely resets inner TLS ~1s in while real
  traffic still succeeds) - never a cooldown, never a rotation. A companion
  DNS probe records `dns_ok` in the egress record when determinable. DNS
  resolution rides the DIRECT path by design, so `dns_ok: false` means the
  direct DNS path failed (e.g. a flaky DoH endpoint on a filtered network) -
  the tunnel was never dialed and is reported `degraded`, never dead. A
  connection-level death with `dns_ok: true` means the dial/read stage through
  the tunnel itself failed (`dns_ok` stays `None` when resolution is
  inconclusive - both keep the dead verdict). Exit code is 1 only
  when an exit is `dead`, so automation never rotates on a reputation-block
  HTTP status, a throttle blip, or a DNS flake.
- A provider can declare an ordered fallback chain under `fallback_providers`
  (the deployment maps Proton to Cloudflare WARP). The value may be a single
  provider name or an **ordered list** forming a fallback chain, e.g.
  `"fallback_providers": ["cloudflare", "mullvad"]` — entries are validated at
  load (must name another configured provider, no self/duplicates) and the
  chain is walked in order, so the first entry with valid profiles wins. When
  rotation exhausts the primary pool, the wrapper, keepalive, or Hermes
  rotation bridge writes a private runtime marker and reloads once with the
  primary endpoint removed; matching routes and DNS then use the chosen
  fallback. `failover <name> on [--to <provider>]` activates the first valid
  chain entry (or a specific member); `failover <name> status --json` reports
  both `configured` (the full chain) and `active`. `egress check`/`sweep`
  report `fallback` instead of probing Proton through WARP. Clear it
  explicitly with `failover proton off` after Proton has been validated again.
- A `sing-box.json.last-good` snapshot (atomic, 0600) is written whenever a
  freshly built config validates AND the engine demonstrably comes up with it;
  if a later reload's config fails validation or the engine fails to come up,
  the router restores the last-good config and reloads/starts once - never
  looping, and failing with a clear message when no last-good exists or the
  restore itself fails.

The singular `"fallback_provider"` key still loads as a compatibility alias
for existing configs (a single name or list; both keys together are an
error). New configurations should use `"fallback_providers"`.

Tunables live in `router.json` under `"egress"` (see `router.example.json`).

When a provider serves multiple routes, set `providers.<name>.probe_route_id`
to the route that represents the real client path (for example,
`"opencode-zen"`). The router validates that the route exists, belongs to the
provider, and has a tunneled domain, then probes that route instead of silently
using the first route in the table. If the explicitly pinned route is no longer
eligible for tunneling, selection returns no probe rather than measuring an
unrelated target.

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
- `probe_profile` / `check_egress_live` — a connection-level death (no HTTP
  status, no TLS handshake) is cooled with the policy's `connection` seconds
  (built-in 300s) after `fail_threshold` (default 2) consecutive failures,
  and only when the DNS probe succeeded (`dns_ok: true`): a failed lookup on
  the direct DNS path (DNS is pinned direct by design) never proves the
  tunnel dead, so `dns_ok: false` reports `degraded` instead of dead.
  TLS-classed failures are never cooled either: they mean the TCP CONNECT
  rode the tunnel and the upstream endpoint is throttling, so the exit is
  reported `degraded` instead of dead. A degraded HTTP status (reputation
  block / 5xx) is never cooled. HTTP 429 is the one exception: a probe that
  rides the tunnel to the routed service and gets a 429 is direct evidence
  the exit's egress IP is rate-limited, so it applies the 429 error-policy
  entry (exhaust + cooldown by default) immediately — the exit stays
  `degraded` for the keepalive (never rotated on a throttle), but scheduled
  rotation and the sweep skip the lane until the reset. `rotate --reason
  tls|connection|...` still applies the table (e.g. the merged 300s TLS
  rule) when a failure is reported by real traffic.
- `status --json` — echoes the effective policy for every provider under the
  top-level `"error_policy"` key, and each profile's egress record carries
  `exhausted`/`exhausted_at`/`exhausted_until` when an exhaust policy has
  fired, so automation can read the exact reset time.

## VPN (TUN) mode

`vpn on` switches the engine from a local mixed proxy (`127.0.0.1:2080`) to a
system TUN interface. In the default `capture: routes` mode, proxy-router
resolves the configured tunneled route domains at build/reload time and gives
sing-box those destination IPs as a `route_address_set`; unmatched traffic
bypasses the TUN and remains direct. This is destination-IP selective, not
process-aware, and a DNS change needs `router.py reload` to refresh the set.
Explicit `capture: ruleset` still uses a static IP-CIDR ruleset (for example,
Roblox). `vpn off` returns to proxy mode; `ensure`, `reload`, `add`/`remove`
and `rotate` all respect whatever mode is active.

Platform notes:

- **Linux**: needs root for the TUN device + route table (iproute2)
  (`sudo proxy-router vpn on`).
- **Windows**: needs an elevated shell and `wintun.dll` next to
  `sing-box.exe` (drop it from the official Wintun release).
- **macOS**: needs root to create the `utun` interface. Run
  `proxy-router elevate install` once; the authenticated installer snapshots
  and hashes its source, installs a minimal root-owned lifecycle helper and a
  pinned official sing-box binary, validates an exact sudoers policy with
  `visudo`, then grants only five helper operations. The normal controller,
  tray, and keepalive stay unprivileged and silently request helper
  `start`/`stop`/`reload` as needed. Without a valid helper, root-required
  operations fail closed and tell you to install it; they never execute the
  user-writable checkout as root or pop repeated admin dialogs. This is NOT a System Settings VPN
  provider entry — that would require a signed NetworkExtension app. It is a
  TUN interface managed from the terminal.

TUN options live under `"vpn"` in `router.json`:
`address` (CIDR list), `mtu`, `stack` (`system`, default | `gvisor`).

`mtu` must fit the path to the WireGuard endpoint: if the physical network
itself is tunneled (e.g. a school/proxy filter with a reduced inner MTU),
the WireGuard packets fragment or get dropped, which reads as "TUN is
slow". Measure the endpoint path with `ping -D -s <size> <endpoint>` and
set `mtu` to `path_mtu - 80` (WireGuard overhead); 1280 is a safe
default. `selective`/`selective_provider` is an optional IP-CIDR capture
list from `rulesets/<name>.json` — only use it when you want TUN to
capture exactly one site; with it set, all other domains fall out to
direct and are NOT tunneled.

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
- `dns_transport` — transport for the generated `dns-<provider>` servers that
  resolve tunneled domains. Default `udp`. Set to `https` (DoH over TCP
  443 to 1.1.1.1) on networks that drop UDP 53 to external resolvers while
  allowing outbound TCP 443; the same IP literal is used as the server
  address with `server_port: 443`.

## One-time elevation (macOS)

`vpn` engine commands need root to create the `utun` interface. Install the
minimal lifecycle helper once:

```sh
./router.py elevate install    # one prompt; install/upgrade root-owned helper
./router.py elevate status     # exit 0 when the exact helper status op works
./router.py elevate uninstall  # stop engine; remove policy, helper, root state
```

The sudoers file never names the user checkout, `router.py`, a user-selected
Python, or a wildcard command. It contains one exact argv line for each
root-owned helper operation: `status`, `start`, `stop`, `reload`, and
`uninstall`, pinned to the installing UID and executed with `/usr/bin/python3
-I -S` through an empty environment. The helper accepts no extra arguments.

The controller still owns routing, rotation, config generation, and the route
watcher as the normal user. Before root sing-box sees a config, the helper
safe-opens the fixed generated file without following links, validates a
closed versioned schema (no file/command/plugin/controller fields), copies the
bytes into root-owned state, and checks them with the hash-pinned binary.
Helper code, binary, policy, PID, and config live under root-owned macOS paths;
modifying the checkout after installation cannot change executable root code.

Install/upgrade requires a fresh admin approval. A recognized legacy policy
that authorized mutable `router.py` is revoked before fallible v2 staging and
is never restored on migration failure. Unrecognized policy content aborts
without being overwritten. The privileged DYLD/user-site adversarial gate is
opt-in and requires admin approval; do not claim a deployment is verified
until that gate has run on the target Mac.

## Provider setup

Each profile is a sing-box-compatible WireGuard config dropped into
`providers/<provider>/` as `<name>.conf`. The provider name (e.g. `proton`)
becomes the sing-box endpoint tag.

The easiest path is the setup wizard:

```sh
proxy-router setup                  # interactive terminal menu (item 8: Hermes rotation bridge)
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

What actually ships — `router.example.json`, copied to `router.json` by the
installer (abridged):

```json
{
  "port": 2080,
  "providers": {
    "primary-vpn": {
      "directory": "providers/primary-vpn",
      "cooldown_seconds": 60,
      "fallback_providers": ["fallback-vpn"]
    },
    "fallback-vpn": { "directory": "providers/fallback-vpn", "cooldown_seconds": 60 }
  },
  "routes": [
    { "id": "opencode-zen", "domains": ["opencode.ai"], "provider": "primary-vpn" },
    { "id": "roblox", "domains": ["roblox.com", "rbxcdn.com"], "provider": "fallback-vpn" }
  ],
  "routing": { "mode": "vpn-list", "vpn_domains": [] },
  "rotation": { "interval_seconds": 7200, "jitter_seconds": 300 }
}
```

Rename the providers to whatever you use (`proton`, `cloudflare`, ...) and
point each `directory` at its profile folder, or let the presets do it:

```sh
proxy-router setup --preset          # apply the default combo preset
proxy-router setup --preset school-warp   # filtered networks: vpn-list + DoH
proxy-router setup --preset-list     # built-ins: default/opencode/roblox/school-warp
```

`setup --preset <name>` applies a NAMED bundle of routes plus an optional
routing-mode/DNS section idempotently. Route choice is configurable: the
current validated deployment uses the Proton pool for OpenCode Zen and
Cloudflare WARP for Roblox, while unmatched traffic stays direct. If every
tunnel exit is unhealthy, direct OpenCode egress remains the fallback; the
router does not claim that a tunnel is healthy merely because a profile
parses.

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

## Tray (menu bar / taskbar)

`proxy_tray.py` is an optional resident status icon: macOS menu-bar accessory
(no Dock icon) or Windows taskbar tray. It never mutates engine state itself —
every click shells out to `router.py`, so rotation ownership, cooldowns, and
keepalive semantics stay exactly where they are.

The tray needs two GUI dependencies beyond the stdlib-only core:

```sh
python3 -m pip install pystray pillow
python3 proxy_tray.py --selftest   # no GUI needed: validates CLI contract + dispatch
python3 proxy_tray.py              # run it in the foreground
```

macOS login autostart (launchd agent):

```sh
examples/install-tray.sh            # fills the plist template, bootstraps gui/$UID agent
examples/install-tray.sh --remove   # unload + remove ~/Library/LaunchAgents/com.proxy-router.tray.plist
```

Rerunning the installer is safe: with the same root it re-renders and
re-bootstraps (a real upgrade); with a different root it unloads the stale
job, keeps the old plist as `*.stale`, and prints the restore command. Logs go
to `~/Library/Logs/proxy-router/`.

Menu map:

- **Status header** (`● Connected` / `○ Disconnected` / `! Error`; a fresh
  install shows "No VPN set up yet" with a pointer at Setup).
- **Open Dashboard** — opens the full terminal wizard in a Terminal window
  (the bold default action).
- **Connect / Reconnect · Disconnect** — `router.py start` / `stop`.
  Disconnect writes the manual-off marker, so the keepalive will NOT
  resurrect the engine until you connect again.
- **Switch VPN server** — rotate to the next healthy exit of the active pool.
- **Provider** — pick an exact exit profile per provider (runs
  `rotate <provider> --to <profile>`); hard-blocked/exhausted exits are
  greyed out.
- **Full tunnel (WARP): on/off** — TUN-mode toggle. On macOS this pops the
  standard administrator dialog: creating the `utun` interface needs root via
  the installed lifecycle helper (see One-time elevation).
- **Routing mode** — safe-list (home) / vpn-list (school) / default.
- **Setup** — provider guides and native file-picker `.conf` import
  (no terminal needed).
- **Presets** — built-in presets plus custom ones from `presets/*.json`,
  active one checked.
- **Quit** — stops the engine AND exits the tray (Tailscale/WARP-style):
  quitting deliberately takes the VPN down, and Quit waits (bounded) for any
  in-flight action before stopping. Use Disconnect if you want the VPN off
  but the tray to stay resident.

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

Fallback is part of the same self-heal loop. When a dead pool refuses to
rotate, `rotate_dead` activates the provider's configured fallback
(`failover <provider> on --reason timeout`) instead of giving up, so routed
domains keep working through the fallback tunnel. While a fallback is active,
`egress check`/`sweep` report `fallback` and never probe the primary pool.
On the full-pool sweep cadence (`PROXY_KEEPALIVE_SWEEP_EVERY`, default 1800s)
the keepalive therefore attempts ONE restore per fallback-parked provider:
it clears the marker (`failover off`), probes the primary live through the
tunnel, keeps the fallback cleared when the primary answers, and re-activates
the fallback when the primary is still dead. The sweep cadence throttles the
restore, so a genuinely dead primary never causes a failover off/on storm.

## Scheduled rotation

By default the router only rotates reactively (dead tunnel, upstream
429/503/...). With a `rotation` block in `router.json` the keepalive loop also
rotates proactively on a fixed cadence, so the active exit's egress IP churns
before upstream rate limits accumulate:

```json
"rotation": { "interval_seconds": 7200, "jitter_seconds": 300 }
```

- `interval_seconds` — rotate every N seconds (0 or absent = off; default
  config enables 7200 = 2h).
- `jitter_seconds` — spread the next rotation by ±jitter/2 around the exact
  interval (default 300), so the switch doesn't tick in lockstep with other
  clients on the same provider.
- Every healthy keepalive tick runs `router.py rotate --if-due`; it reads
  `state/<provider>.rotation` and only acts once the interval has elapsed
  (exit 0 = rotated, 3 = not due). It is skipped automatically while the
  engine is down or `manual-off` is set.
- A provider with no rotation record yet is seeded as "rotated now", so a
  fresh install waits a full interval before the first switch.
- Scheduled switches reuse the normal `rotate` path: verify-then-switch with
  rollback, per-provider cooldowns, and storm-guarded by nothing extra — the
  cadence itself is the guard. The current exit is NOT marked as an upstream
  failure (a scheduled switch is a preference, not a failure signal).
- `router.py status --json` reports `rotation.interval_seconds`,
  `rotation.jitter_seconds`, and `rotation.next_at` (earliest upcoming switch).

Manual rotation still works as before; scheduled rotation never forces past a
blocked/cooldown profile.

## Fail-open proxy runner

Apps pointed at `127.0.0.1:<port>` (hermes, curl, a cron job, ...) break when
the engine is down. `with-proxy` wraps any command with a health check: when
the listener answers it runs the command with `http_proxy`/`https_proxy` (and
uppercase variants) set, otherwise it strips those vars and runs DIRECT — the
engine is never started, so `manual-off` stays honored:

```sh
./router.py with-proxy -- hermes model@opencode "..."   # proxy when up, direct otherwise
./router.py with-proxy --check                          # prints http://127.0.0.1:2080, exit 0 when up
./router.py with-proxy --force-proxy -- cmd...          # refuse (exit 4) instead of running direct
./router.py with-proxy --force-direct -- cmd...         # always direct, skip the probe
```

Flags: `--timeout-ms` (probe timeout, default 300). The child replaces the
wrapper via exec, so exit codes and signals pass through untouched. `--check`
is what scripts should use for one-shot health checks (exit 0/1, prints the
URL only when up).

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

The wrapper is fail-open: it pre-flights with `router.py with-proxy --check`
and only sets the proxy env while the listener is up. When the router is
stopped or disabled, hermes runs DIRECT (no rotation, no engine resurrection)
so it keeps working without the tunnel — useful when the Proton egress is
rate-limited and you just want opencode to work. Rotation on failure resumes
automatically once the proxy is back up.

The Hermes `opencode-server-rotation` plugin looks for
`$OPENCODE_ZEN_VPN_ROOT/proxy-manager.sh` (its `rotate` subcommand). Set
`OPENCODE_ZEN_VPN_ROOT` to one canonical per-user directory for both Hermes
and this install, for example `~/.local/share/opencode-zen-vpn`, then place
`examples/proxy-manager.sh` there with `router.py setup --bridge-install`.
Do not rely on the plugin's retired historical default path; the bridge check
must report the same root that the plugin process receives.

Contract: `OPENCODE_PROVIDER`, when set, is the explicit provider to rotate.
When absent, `proxy-manager.sh` infers the egress from the router's live
config/status (`router.py status --json`): the `opencode.ai` route's provider
(or its active fallback — mirroring `router.py response-event`), or the sole
configured provider on single-provider routers. Ambiguity (no route and
multiple providers) fails closed with exit 2 instead of guessing. Set
`OPENCODE_PROVIDER` to force a specific provider; otherwise ensure
`PROXY_ROUTER_ROOT`/`PROXY_ROUTER_BIN` lets the bridge locate `router.py`.

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
# Windows gaming: Steam, Roblox and Reddit

The `gaming` preset uses a full TUN through the `cloudflare` WireGuard pool.
It includes Steam store/community/download hosts, Roblox and Reddit. Game
servers can use changing IP addresses and UDP without a hostname, so all
unmatched internet traffic also uses the VPN while this profile is active.
Existing explicit provider routes remain in place. Tailscale bypass stays on;
automatic Wi-Fi preset switching is paused to avoid changing profiles mid-game.
The TUN MTU is 1280 to leave room for VPN encapsulation on constrained paths.
IPv4 and IPv6 enter the tunnel, and Windows full capture enables strict routing
and port-53 DNS hijacking to prevent multihomed DNS queries bypassing it.

Requirements: Python 3.10+, sing-box 1.12+, an elevated PowerShell, a usable
WireGuard profile, and the matching-architecture `wintun.dll` beside
`%LOCALAPPDATA%\proxy-router\bin\sing-box.exe`. Obtain Wintun from
https://www.wintun.net/ and use the `amd64` DLL for the Windows x64 bundle.
The official WARP desktop app's TCP-only SOCKS mode cannot carry game UDP.

## Update and activate

Close the dashboard/tray and stop the engine before replacing program files.
Back up the installed directory, including `router.json` and `providers`.
Extract a current Windows bundle and run `install.ps1 -SetPath`; the installer
preserves the existing configuration and provider files. Do not install the
old v0.2.1 release expecting this preset to be present.

In an elevated PowerShell using your usual Windows account:

```powershell
$router = "$env:LOCALAPPDATA\proxy-router\bin\proxy-router.cmd"
& $router setup --import-warp "$HOME\Downloads\wgcf-profile.conf"
& $router setup --preset gaming
& $router setup --check
& $router vpn on
& $router doctor --network
```

If you already imported a WARP WireGuard profile, skip the import. Applying
the preset only saves configuration; `vpn on` activates the tunnel. For an
existing Proton pool with a different provider ID, save a custom preset in
`%LOCALAPPDATA%\proxy-router\presets\Gaming.json` using the same preset structure,
but set every route's `provider` and `routing.default_provider` to that pool's
ID. Apply it with `setup --preset Gaming`. Do not rename a Proton pool to WARP.

## Verify and recover

Fully quit and reopen Steam and Roblox after enabling the tunnel. Check Steam
store, sign-in and a download; join a Roblox experience and inspect in-game ping;
open Reddit in a browser. A successful web probe does not prove gameplay works.
The current `doctor --network` direct-path probe is unavailable on Windows
and can report `direct_probe_skipped` even with a working tunnel. Check the
sites and a public exit-IP service from the PC; the exit should be the VPN's.
If latency is high, compare a nearby Singapore WireGuard exit; a VPN cannot
guarantee lower ping or access to every experience/account region.

`vpn off` returns to application proxy mode; `stop` stops the engine entirely.
Restore your saved `router.json` before reconnecting to return to your earlier
routing settings. This profile does not implement a system-wide kill switch.

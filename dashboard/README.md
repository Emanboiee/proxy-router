# Proxy router dashboard

Local-first dashboard prototype for the existing proxy-router engine. It is a
real interactive UI with persisted browser-local profiles, routing rules,
provider health simulations, recovery settings, appearance themes, diagnostics,
and preview states. The live Python controller is intentionally behind the
planned API boundary, so exercising this dashboard never changes a real route.

```sh
cd dashboard
npm ci
npm run dev             # browser at http://127.0.0.1:1420
npm run tauri dev       # native window with tray behavior
npm test                # Playwright + axe checks
```

Requires Node supported by Vite 7, Rust, and Tauri 2 platform prerequisites.
The existing tray action opens the release binary when it exists at
`dashboard/src-tauri/target/release/proxy-router-dashboard` (with `.exe` on
Windows), and otherwise keeps the terminal dashboard fallback. Closing the
native window hides it into the menu-bar tray; **Open Dashboard** focuses the
same instance and **Quit Proxy Router** exits the shell. The router helper stays
separate until the signed integration pass.

Profiles (including routing presets, fallback behavior, and optional subdomain
detection), provider/server selection, WireGuard/custom/SOCKS5 connections,
Tailscale exit-node entries, close-to-tray, Wi-Fi-loss disconnect, auto-switch
thresholds, and appearance settings are all available from the sidebar. A
profile can add its own connection from the GUI: choose a WireGuard-compatible
`.conf` file, choose a custom provider type for an imported provider file, enter
a local SOCKS5 gateway, or select a Tailscale exit node. The prototype validates
the endpoint and stores only redacted connection metadata in browser storage;
the signed helper still owns secure installation of provider files. The About
page exports redacted local diagnostics; profile cards export/import JSON through
the same local controller model.

The design, state matrix, runtime map, and Python API contract are in
`../docs/plans/2026-09-08-dashboard-astra.md`. No credentials belong in this
directory.

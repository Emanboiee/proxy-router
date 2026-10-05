# Proxy Router dashboard

The dashboard runs in two modes. `npm run dev` opens a browser preview backed
by demo state in browser storage; it cannot call the router engine. The desktop
app (`npm run tauri dev`) connects live status, configuration,
network-detection, routing, preset, and route controls to `router.py` through
the allowlisted Tauri commands in `src-tauri/src/controller.rs`.

```sh
cd dashboard
npm ci
npm run dev             # browser preview at http://127.0.0.1:1420
npm run tauri dev       # native window with tray behavior
npm test                # Playwright + axe checks
```

The desktop shell invokes the Python controller from `~/proxy-router` with
`/opt/anaconda3/bin/python3` by default. Set `PROXY_ROUTER_ROOT` and
`PROXY_ROUTER_PYTHON` to target another checkout or interpreter. Starting the
app reads status but does not connect automatically. Explicit actions such as
Connect, Disconnect, preset changes, route changes, and network mappings call
the real controller and can change live routing state. The tray closes the
window to the menu bar; **Open Dashboard** shows the same instance and
**Quit Proxy Router** exits the shell.

The live Profiles, Connectivity, and Settings pages show engine configuration
and wire their supported controls to `router.py`. Profile/provider editing and
other preview-only controls remain browser-local until they have a live engine
command; they do not imply that a provider or profile was installed. The
dashboard returns a shaped configuration view: private provider paths,
SOCKS5 credentials, and unrecognized `router.json` fields are not sent to the
webview. Provider credentials and WireGuard keys belong in the engine's local
configuration or provider files, never in this directory or source control.

Requires Node supported by Vite 7, Rust, and Tauri 2 platform prerequisites.
The design, state matrix, runtime map, and Python API contract are in
`../docs/plans/2026-09-08-dashboard-astra.md`.

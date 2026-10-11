# Windows dashboard

The desktop app uses the same profiles and provider inventory as macOS. It discovers
the engine installed by install.ps1 under %LOCALAPPDATA%/proxy-router, or uses
PROXY_ROUTER_ROOT when explicitly set. An existing %USERPROFILE%/proxy-router
checkout is also supported.

## Setup

1. Install Python 3.10 or newer and put python.exe on PATH.
2. Run the repository's install.ps1 in PowerShell to install the routing engine.
3. Install the dashboard using the Windows NSIS installer from a release or CI artifact.
4. Import your own WireGuard configurations or add a SOCKS5 connection in Profiles.

The dashboard installer contains the desktop app, not Python, VPN credentials, or
the routing engine. WebView2 is required; the Tauri installer handles its bootstrap.
Keep the engine and dashboard versions aligned. Windows TUN capture requires
wintun.dll and administrator privileges; application proxy mode does not provide
transparent capture of apps that ignore system proxy settings.

## Build and validation

Run npm ci, npm run build, and npm test in dashboard, then
cargo test --locked --manifest-path src-tauri/Cargo.toml.
Build the installer with npm run tauri -- build --bundles nsis.
The platform-specific Tauri configuration is applied automatically on Windows.

Pull requests build and test on windows-latest, including native controller
tests and an NSIS artifact check. Tagged releases include a versioned Windows
dashboard ZIP and SHA-256 checksum. Build verification does not replace testing
real tunnels and system proxy behavior on a Windows machine.

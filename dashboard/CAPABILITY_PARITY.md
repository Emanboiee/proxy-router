# Dashboard capability parity

The polished application uses `main.ts` and the existing controller commands.
`dashboard-polish.ts` rearranges existing controls after rendering. It does not
create a second router, network watcher, or command execution path.

| Capability | Location in polished UI | Controller path / verification |
| --- | --- | --- |
| Connect, disconnect, reconnect; live status and tray | Home | `run_router_action`, `get_live_status`, `cached_live_status`; engine-controls tests |
| Saved profile discovery, apply, create, edit, duplicate, import/export, delete | Profiles; More disclosure | Existing dashboard profile commands; engine-controls and features tests |
| Domain rules, subdomain detection, direct/full/selective routing, per-rule fallback and missing-provider preservation | Profile editor; Advanced routing | `save_dashboard_profile`, `apply_dashboard_profile`; mixed-preset and routing-rule tests |
| WireGuard configuration import, add configs to one provider, edit/delete provider | Providers detail pane | `save_dashboard_provider`, `delete_dashboard_provider`; provider GUI tests |
| WARP and SOCKS5 host/port, external/WARP/command startup | Add/Edit provider | Existing provider startup payload; WARP and generic-command tests verify saving does not connect or execute |
| Preferred server, explicit switch, installed-server search, remove/restore pool entries | Home View more; provider editor | Existing server preference/switch/management commands; 23-server and pool tests |
| Wi-Fi profile auto-switch, reveal/hide names, last-five network mappings, remove mapping | Connectivity | `get_network`, `reveal_network`, `set_network_auto`, `set_network_preset`, `remove_network_preset`; network-controls tests |
| Network-loss disconnect/reconnect, manual-off preservation | Connectivity | Existing network guard and `set_network_disconnect`; network-controls tests |
| Routing mode and current engine/rotation/keepalive settings | Settings | Existing `get_config`, `get_routing`, `set_routing_mode` paths |
| Scheme, full color palette, layout, density, contrast, motion, custom themes, content width | Appearance | Existing local theme persistence plus validated local custom themes; features and polished-parity tests |
| Dashboard action logs and export | Home; Settings diagnostics | Existing dashboard log export; About navigation redirects to Settings |

## Verification boundaries

- Browser-only preview uses sample profiles. Desktop mode uses Tauri controller
  reads and never falls back to sample network/settings controls on a read failure.
- Automated desktop tests simulate Tauri IPC and assert command payloads and
  outcomes. They do not simulate an actual Wi-Fi transition or establish a VPN.
- Existing network watcher, privileged helper, tray lifecycle, and provider
  startup implementations are unchanged by this UI work.
- Traffic counters and engine-log streaming were not available in the old
  dashboard. The new Home labels its activity as dashboard actions; it does not
  fabricate live throughput or request counts.
- The installed macOS application is not replaced by this source/build change.

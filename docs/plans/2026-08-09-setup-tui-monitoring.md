# Setup TUI and Opt-In Network Monitoring Implementation Plan

> **For Hermes:** Implement and verify this plan in the proxy-router repository.

**Goal:** Make proxy-router easy to install and configure for Proton VPN Free and Cloudflare WARP, while adding a monitoring service that consumes no resources unless explicitly enabled.

**Architecture:** Keep the existing stdlib-only router engine and CLI. Add a small setup wizard module that owns import/guide/preset operations, and a separate monitor module with one-shot checks plus an explicitly started background worker. The TUI invokes existing router commands rather than duplicating sing-box lifecycle logic.

**Tech Stack:** Python 3.10+ standard library, ANSI terminal UI with line-input fallback, JSONL monitor samples, existing unittest suite.

---

### Task 1: Add provider setup guides

**Files:**
- Create: `guides/proton-vpn-free.md`
- Create: `guides/cloudflare-warp.md`
- Modify: `README.md`

Document official Proton WireGuard export, free-server selection, permissions, and WARP options (official client versus `wgcf` profile generation). Never ask users to paste private keys into chat or commit them.

### Task 2: Add setup import/preset helpers

**Files:**
- Create: `setup_tui.py`
- Test: `tests/test_setup_tui.py`

Implement pure helpers to validate/copy `.conf` files into `providers/proton` or `providers/cloudflare`, set mode `0600`, preserve existing config, and apply safe route presets for `opencode.ai -> proton` and Roblox domains -> `cloudflare`.

### Task 3: Add the terminal setup wizard

**Files:**
- Modify: `router.py`
- Modify: `setup_tui.py`
- Test: `tests/test_setup_tui.py`

Add `proxy-router setup` with a custom ANSI menu and non-interactive `setup --guide`, `setup --check`, and import options. The wizard must work without third-party packages, show the two guides, import profiles by path, apply presets, and start/reload through the router CLI.

### Task 4: Add opt-in monitoring

**Files:**
- Create: `monitor.py`
- Modify: `router.py`
- Test: `tests/test_monitor.py`

Add `monitor check`, `monitor on`, `monitor off`, `monitor status`, and `monitor logs`. Measure HTTP latency, ICMP ping where available, and bounded download/upload throughput. `monitor on` starts a detached worker; `monitor off` stops it; no worker, probes, or timers run while disabled. Store only redacted JSONL measurements under runtime state.

### Task 5: Documentation and verification

**Files:**
- Modify: `README.md`
- Modify: `router.example.json`

Document setup commands, route presets, monitoring lifecycle, output paths, and the fact that OpenCode Zen is currently routed through the validated Proton pool. Run the complete unittest suite, CLI smoke tests, config validation, and one real OpenCode request after deployment.

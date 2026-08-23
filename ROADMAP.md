# Roadmap

Parking lot for tracked-but-not-scheduled work. Items move to issues when
someone picks them up. Full specs and evidence live in the linked PR/issue
threads.

## Product

- **Vendor-neutral setup wizard** (from #34): generalize `setup_tui.py`'s
  proton/warp-hardwired import flows to `--import <name>` for any provider,
  keeping proton/warp as convenience presets. The BYO cleanup (#30) covered
  config and paths; the wizard is the last vendor-coupled surface.
- **Fallback settings view in the TUI** (from #32): settings entry for
  provider fallback chains — view chains, set/clear via a two-stage prompt,
  plus a line-mode writer. Test spec preserved in #31's description.

## Engine / networking

- **In-flight flow resets on switch are inherent**: graceful switching (SIGHUP
  reload) keeps the process, TUN interface, routes, and listener sockets
  alive, but flows bound to the old WireGuard endpoint cannot migrate — same
  behavior as commercial VPN clients on server switch. Use
  `vpn.exclude_cidr` to pin must-never-blip destinations outside the engine.
- **Scheduled-rotation etiquette**: stagger rotation and sweep windows so
  they never collide; consider a pre-switch drain notice in status output.

## Superseded stacks

- **PR #27 (`feat/proton-warp-fallback`)**: response-event plumbing, profile
  copy, fallback ergonomics, and keepalive fallback handling landed on
  `main` via #31/#35/#37. Unique remainder: the response-aware mitm sidecar
  (`examples/response_aware_mitm.py`, `examples/response-aware.sh`) and its
  tests — extract as a standalone opt-in PR if wanted. The "bad Proton
  exits" premise was a measurement artifact (#26 findings).
- **Issue #18 (redesign)**: delivered — transparent TUN capture with mixed
  listener lane, in-place graceful switching, `with-proxy` fail-open runner,
  and keepalive self-heal. Follow-ups live in the items above.

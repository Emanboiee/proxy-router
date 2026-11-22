# Design: issue #66 S1 slice — pure DNS/route resolution helpers

Settled with `architect` before code. Start: main 90c3f00. Branch: refactor/issue66-s1.

## Shape selection
Full S1 (build_singbox_config, 363 lines, 8 globals, 10 helper calls) is too wide
for one safe PR. `architect` says pick the smallest well-understood seam.

AST analysis found three helpers that read NO module globals and call only
builtins/stdlib — no dependency seam needed:
- `_capture_domain_name` (8 lines, string methods only)
- `_bounded_getaddrinfo` (18 lines, socket/threading only)
- `_vpn_list_intersection` (18 lines, string methods only)

`_dns_error_markers` was excluded: although it reads no globals, it calls
`egress.dns_error_markers`, which would drag the egress leaf into singbox.py's
imports — a seam we do not need for this slice. It stays in router.py.

These are cohesive: DNS failure classification, domain extraction, bounded DNS
resolution, and VPN-domain set intersection — all part of singbox route/domain
resolution. Move them into the existing `singbox.py` leaf, which already holds
`parse_endpoint`/`dns_server_for`, and re-export by name from router.py so all
call sites (including `model_relay.py`'s `router._vpn_list_intersection`) and
tests are unchanged.

Rejected: moving `_route_capture_cidrs` (needs `_effective_vpn_domains`,
`_effective_route_provider`, `_bounded_getaddrinfo` — a real seam) or
`_macos_dns_snapshot` (platform domain, not singbox). Those stay for later.

## Data shape
No new types. Signatures unchanged; only the module that defines them moves.
router re-exports all three under their original private names.

## Verification gate
- full pytest suite green
- cap ratcheted down (router.py loses ~48 def lines, gains 1 import)
- singbox.py remains stdlib-only / no upward import (architecture guard)
- runtime identity check: router._name is singbox._name for all three

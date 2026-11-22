# Design: issue #66 next step — move `_public_dns_error` into config_schema

Settled with `architect` before code. Start: main c2292c3. Loop branch: refactor/issue66-next-step.

## Shape selection

C2 (whole load_config validation move, ~210 lines) and S1 (build_singbox_config
+ 10 helpers) were both considered as the unit. Both have wide seams:

- C2: load_config reads 7 globals and calls 7 helpers, three of which mutate
  globals (`_load_error_policy`, `_load_rotation_settings`,
  `_load_egress_settings`). Moving the whole body in one PR needs a context
  object carrying mutators + root + regex — large and risky.
- S1: build_singbox_config reads 8 globals and calls 10 internal helpers
  (`_dns_entry`, `_effective_vpn_domains`, `_route_capture_cidrs`, ...). Needs
  a context object with 10 callables. Large.

`architect` says pick the smallest well-understood seam and do not do both in
one PR. A third option, a cohesive sub-unit of C2, is smaller and cleaner:

### Picked: move the pure `_public_dns_error` validator into config_schema
- Pure: only `ipaddress` and `re`, no module globals, no writes.
- 22 lines, two call sites (`router.py:660`, `router.py:3094`) inside router.
- `config_schema.py` is already a `LEAF_MODULES` member, so the direction guard
  covers it; it already owns defaults + `migrate` + three validators.

Shape A (rejected): keep it in router and instead move a bigger block. Wider
seam, more test churn, violates "smallest change evidence justifies".
Shape B (picked): move the pure validator to config_schema, re-export from
router under the same private name so both call sites and any tests are
unchanged. This is one verifiable unit with zero behavior change.

## Data shape
No new type. Function signature stays `_public_dns_error(value) -> str | None`.
config_schema gains `public_dns_error(value) -> str | None` with the identical
body and exact error strings. router re-exports it as `_public_dns_error`.

## Verification gate
- full pytest suite green
- cap ratcheted down only if router.py shrinks (moving 22 lines out, adding a
  1-line import, should drop router.py from 8283 to ~8262)
- config_schema still has no upward import (architecture guard)
- a direct probe confirms exact error strings on representative inputs

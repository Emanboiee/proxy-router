# Design: issue #66 E1-replacement slice — move _normalize_reason

Settled with `architect` before code. Start: main 2053fae. Branch: refactor/issue66-e1.

## Shape selection — why not a real engine.py slice this round
Full E1 (engine.py: engine_start/stop/reload, PID identity, lock, SIGHUP,
privileged helper) is wide and lifecycle-touching. AST analysis of every
engine-named function showed they ALL carry module globals or caches:
- engine_start/switch/reload: 5-10 globals each, 20-30 internal callees
- _expected_engine_argv: module-level caches `_expected_engine_argv_cache/source`
- _pid_matches/_find_our_engine_pids/_terminate_pid: call `_expected_engine_argv`,
  `_command_is_our_engine`, `resolve_sing_box`
- engine_alive: reads PID_FILE, helpers, sys

There is no seam-free engine cluster left. `architect`: do not force an
abstraction that adds indirection without removing branches or invalid states.
Moving engine functions now needs a dependency-seam context object (a contested
design), not a cheap mechanical PR. Deferred to a dedicated E1 design.

## Picked: smallest cohesive pure validation slice
Remaining pure (no globals, builtins/re only) functions were enumerated. The
one with an unambiguous single home is `_normalize_reason` (17 lines, maps a
failure reason to an error-policy key using only `re`/builtins). It belongs in
`config_schema.py`, which already owns error-policy validation
(`parse_error_policy`, DEFAULT_ERROR_POLICY). Its only callees are in router.py
(`policy_action`, `_load_error_policy`), both re-exported by name so callers and
tests are unchanged.

Rejected alternatives (no clean home or wrong domain): `_routing_print`
(CLI output), `_rejected_change_after_restore` (recovery/state), `_safe_source_bytes`
(privileged installer), `_active_autodetected_domains` (autodetect),
`_parse_networksetup_proxy`/`_parse_scutil_proxy` (platform/macos, P1 domain).

This is deliberately small; further router.py shrinkage needs the E1/C2 seam
design, not more one-function moves.

## Verification gate
- full pytest suite green
- cap ratcheted down (router.py -17 def lines + 1 import)
- config_schema stays upward-import-free
- re-export identity: router._normalize_reason is config_schema.normalize_reason
- exact behavior on reason inputs (HTTP codes, tls/connection/timeout, unknown, empty)

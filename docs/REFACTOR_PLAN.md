# REFACTOR PLAN: decompose router.py and centralize the runtime schema

Issue: #66 (P2 maintainability) · Status: DESIGN ONLY — no code has moved.
Author: lane F, proxy-router-six-lanes-20260823 (nonce PR6L-0823)

## Problem

`router.py` is ~5.5k lines with 192 functions and a 350-line `main()`. It owns
configuration/schema, WireGuard parsing, sing-box generation, engine lifecycle,
PID identity, health probes, cooldown/rotation/fallback state, routing modes,
macOS system proxy, sudoers/elevation, watcher integration, and CLI parsing —
connected through broad module-level mutable state (`_providers`, `_routes`,
`_port`, `_vpn`, `_routing`, `_egress_settings`, `_error_policy`, `_rotation`).
Security/lifecycle logic is duplicated in `proxy_tray.py`. This makes focused
review difficult and lets docs/defaults/tests drift across independent sources.

This document proposes the target module boundaries, the migration order, and
the risks — it intentionally contains **no code moves**.

## Target module boundaries

Dependency direction is strictly downward; nothing imports upward.

```
config.py      (new, leaf)
  One canonical definition of the runtime schema:
    - router.json schema: providers entries, routes, vpn, routing,
      egress settings, error_policy, rotation settings
    - defaults in ONE place (DEFAULT_EGRESS_SETTINGS,
      DEFAULT_ROTATION_SETTINGS, DEFAULT_ENDPOINT_MTU, ...)
    - validation functions extracted verbatim from load_config()
      (_routing_error, _parse_error_policy, fallback-chain checks)
    - schema VERSION + migration path for future changes
    - load()/save() returning an immutable validated snapshot instead of
      mutating module globals
singbox.py     (depends on config)
  build_singbox_config(), parse_wireguard(), parse_endpoint(),
  resolve_host(), dns_server_for(), dns strategy/transport helpers,
  config-drift comparison (_config_drifted), last-good rollback payload
engine.py      (depends on config, singbox)
  Process lifecycle only: start/stop/reload/ensure, readiness polling,
  PID identity, lock file, SIGHUP reload path, privileged-helper invocation
state.py       (leaf)
  Atomic writes, ownership hand-back, active markers, cooldowns,
  blocked/exhausted markers, egress health records, rotation records,
  mode/manual-off/reload-override markers, invariants (marker <-> record)
egress.py      (depends on config, state)
  probe_egress / probe_profile / check_egress_live / egress_dns_probe,
  transport-reason classification, ranking (_egress_rank),
  cooldown/fallback POLICY decisions (mark_cooldown stays in state.py as I/O;
  the *decision* of when to apply lives here)
platform/macos.py  (depends on config, state)
  system_proxy_on/off, networksetup/scutil wrappers, launchd agent checks,
  sudoers + privileged helper client (single source; tray calls into this)
providers_check.py (depends on config, state)   ← new in this PR (#51)
  The offline validity preflight (providers check). Small, self-contained,
  first proof that the seams work.
cli.py         (depends on everything above)
  argparse surface + main(); each subcommand becomes a thin call into one
  service API function. No business logic.
proxy_tray.py  (depends on cli-facing service API)
  Drops its duplicated elevation/PID interpretation; reads status via the
  same service API objects the CLI uses (issue #66 acceptance criterion).
router.py      (transitional shim, then deleted)
  Re-exports every public name from its new home so `import router`
  keeps working during migration.
```

## Runtime schema centralization

Today the schema lives implicitly in `load_config()` (~130 lines of inline
validation) plus scattered defaults. The plan:

1. Define dataclasses (or TypedDicts + guard constructors) per section:
   `ProviderEntry`, `Route`, `VpnSettings`, `RoutingSettings`,
   `EgressSettings`, `ErrorPolicy`, `RotationSettings`.
2. `config.load(path) -> Config` parses + validates once, raising
   `ConfigError` with the exact messages load_config emits today (tests pin
   these messages; they must not change).
3. `Config` is immutable; consumers receive it explicitly (constructor or
   parameter) instead of reading module globals. During migration router.py's
   globals become views over one `Config` instance.
4. Add `SCHEMA_VERSION`; `load()` runs registered migrations so old
   router.json files keep working (first version = current behavior, no-op).
5. Writers (`routing set/add/remove`, presets, init) go through
   `config.save(Config)` which serializes canonically and writes atomically
   (reusing the existing tmp+rename writer).

## Migration order (each step lands separately, suite green)

1. **state.py** — extract pure-I/O marker/record helpers with zero behavior
   change. Lowest risk; no policy moves; unblocks everything else.
2. **config.py** — move validation + defaults; introduce the immutable
   `Config` object behind the existing global-state facade. Router.py keeps
   its public function signatures.
3. **providers_check.py** — move the new preflight (already isolated by this
   PR); validates the extraction pattern on fresh code.
4. **egress.py** — move probes/classification/ranking; keep decision hooks
   where callers are today until step 6.
5. **singbox.py** — move generation/parsing/drift logic (largest pure
   transformation block).
6. **engine.py** — move lifecycle; this is where PID/readiness/lock identity
   consolidates and tray duplication gets deleted.
7. **platform/macos.py** — move system-proxy/sudoers/launchd; tray switches to
   the shared client here.
8. **cli.py** — thin-ify main(); delete the router.py shim once no importer
   references remain.

Each step adds a lightweight import-graph check (no upward imports, module
size caps) so regressions fail CI immediately.

## Risk notes

- **Behavior drift in validation**: tests currently pin exact failure strings
  from load_config; config.py must reuse them verbatim. Guard: run the full
  regression files unchanged after step 2.
- **Module-global mutation**: dozens of call sites read `_providers` etc. mid-
  function. Mechanical `global` removal in one pass would be unreviewable;
  hence the facade approach (globals become properties over `Config`) with
  per-module cutover afterwards.
- **Elevation/root paths**: engine.py + platform/macos.py touch sudoers and
  the root-owned helper. These moves must not reorder any subprocess/env
  handling; test_elevation.py and test_privileged_helper.py must stay green
  untouched.
- **Import cycles**: egress↔state and singbox↔config temptations exist; the
  dependency rule above plus the CI import-graph check is the guardrail.
- **Tray parity**: proxy_tray.py duplicates PID interpretation; deleting it
  before the service API exists would break tray UX — hence tray cutover is
  late (step 7), behind stable API objects.
- **Windows/Linux CLI paths**: several commands gate on `sys.platform ==
  "darwin"`; moving those gates into platform/macos.py requires care that the
  non-macOS error text (pinned in tests) survives.

## Acceptance criteria mapping (issue #66)

- Behavior-preserving, reviewable steps → migration order above (one PR per
  step, full suite green each time).
- One canonical schema definition + migration path → `Runtime schema
  centralization` section.
- Tray stops duplicating elevation/PID logic → step 7.
- No new import-time global mutation; DI for unsafe ops → immutable `Config`
  + explicit state/controller parameters.
- Size/dependency-direction enforcement → lightweight CI check added in step 1.

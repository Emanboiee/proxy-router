# Design: issue #66 C1 — immutable Config snapshot

Settled with `architect` before code. Start: main e6b3175.

## Two shapes considered

### Shape A — Config owns all state; globals become read-only views (REJECTED)
A frozen `Config` owns every section. `router.py`'s module globals become property
views; all writes reroute through `config.save()` producing a new Config.

Evidence against it as one unit: AST analysis found 16 mutation sites across 8
globals (`_providers`, `_routes`, `_vpn`, `_routing`, `_autodetect`,
`_egress_settings`, `_rotation`, `_proxy_bypass_domains`), including in-place
writes `_vpn["network_presets"]=`, `_routes[:]=`, `_vpn.clear()/.update()`.
Tests monkeypatch `router._providers`, `router._routing`, `router._rotation`
directly. Read-only views would break all of that. This is the whole C1+C2+CLI1
scope, not a single reviewable, green-at-each-step unit.

### Shape B — Config is the validated load snapshot (PICKED)
A frozen `Config` dataclass in `config_schema.py` owns the *validated* config
sections with one canonical type definition. `load_config()` builds it once from
validated data and seeds the existing globals from its fields. The globals remain
the mutable runtime table that CLI commands and presets legitimately update.

- One owner per piece of state *at the config boundary*: the parsed Config is
  the single validated snapshot.
- Each task has one way: schema shape and deep-copy invariants live in
  `config_schema.Config`; runtime mutation stays in router globals.
- Callers know least: every public signature is unchanged; tests keep
  monkeypatching globals.
- Verifiable as one unit with a real invariant test (two Configs cannot share
  mutable state).

Deferred, not lost: converting globals to true views (Shape A) stays the target
for C2/CLI1, once the 16 mutation sites can be migrated behind `save()` in their
own reviewed units.

## Data shape

`Config` frozen dataclass, fields:
`port:int, providers:dict, routes:list, vpn:dict, routing:dict,
autodetect:dict, egress_settings:dict, rotation:dict, error_policy:dict,
proxy_bypass_domains:list`.

- `Config.from_loaded(...)` classmethod deep-copies each section, so two
  instances never share mutable state (the invariant the plan asks to test).
- `to_dict()` returns a fresh deep copy as the `save()` contract foundation.
  Writers still use router's `_atomic_write` today; C2 will route them through
  this.

router.py: `load_config()` builds `_config = Config.from_loaded(...)` after all
existing validation and seeds globals from it. `_config` is the load-time
snapshot; nothing treats it as live truth.

## Verification gate
- full pytest suite green
- new Config tests: immutability + no shared mutable state + to_dict isolation
- cap ratcheted down only if router.py shrinks; unchanged otherwise (the cap
  may only decrease)

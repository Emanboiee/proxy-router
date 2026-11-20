# Plan: issue #184 remaining halves (bounded engine-log retention + first-frame timing origin)

Goal (from issue #184 acceptance):
- "Log retention remains bounded and logging failure does not create a retry storm."
- "Rendering timing uses a deterministic test and a documented clock origin."

Scope: ONLY these two items. Do not touch other 11 issues. Do not close #184 (other items/columns remain).

## Evidence gathered (current main = 0931bff)

Stale progress comment (Nov 6, PR #255) claims "retention-policy reporting half remains" and "first-frame timing origin". Verified what actually exists now:
- `tests/test_log_retention_reporting.py` (4 tests) and `tests/test_lifecycle_events_184.py` (5) already on main; all pass (9 passed).
- `rotate_log_if_needed()` / `trim_live_log_if_needed()` already print `router: log retention failed (...)` on their try/except paths.
- `preview_rendered` already prints `preview_first_frame_ms` from a `LaunchTime(Instant)` managed at `main()` entry.

Two genuine defects remain, both reproduced/inspected:

### Defect A (item 2) - root cause
`router.py:3985` does `archive.unlink(missing_ok=True)` OUTSIDE the try/except in `rotate_log_if_needed()`.
- Repro: monkeypatch `Path.unlink` to raise `OSError(EACCES)` on the archive -> `PermissionError` escapes `rotate_log_if_needed()` -> would abort `engine_start()`. Measured: "RESULT: RAISED PermissionError ... live log still present: True".
- `stat()` failure is silently swallowed by bare `except OSError: return`, so a retention failure on the size-check path gives no report.
- Acceptance requires: bounded retention + explicit failure reporting + no retry storm. A retention error must never break `engine_start`, and must be reported once (no storm).

### Defect B (item 4) - root cause
`dashboard/src-tauri/src/main.rs:745` seeds `LaunchTime(Instant::now())` at `main()` process entry, so `preview_rendered` at 84-85 measures elapsed *process lifetime*, not the first rendered frame. Issue says "Ensure first-frame latency measures the actual frame interval rather than elapsed process lifetime, with explicit timing origin." No deterministic test and no documented origin exist.

## Design (architect: one owner per clock; pure timing math)

### A. Retention guard
- Move every fallible retention operation (stat, unlink, rename, chmod) inside a single try/except OSError that reports once via a shared helper `report_log_retention_failure(stage, exc) -> None` at module level.
- Keep the two entry points `rotate_log_if_needed()` and `trim_live_log_if_needed()` (public-ish; tests call them). `rotate_log_if_needed()` returns bool success? No - keep `None` to preserve callers; report via stderr side effect only. No exception escapes.
- `trim_live_log_if_needed()` becomes called ONLY from an explicit maintenance call site (never from read-only status - #236 invariant preserved), but expose an explicit CLI action `trim-log`? Out of scope (UI surface). Instead: call it at end of `rotate_log_if_needed()`? No - the live inode is not held during engine_start, so trim is unnecessary there. Keep trim as explicit helper; document via docstring that it is for a live engine's held fd and call it from `engine_start`'s log-open path when an engine already holds the log? That reintroduces #236 risk. Decision: leave trim unreferenced in prod but well-documented; the bounded path that runs is rotation at engine_start. Acceptance "retention remains bounded" is satisfied by rotation (engine_start rotates the log before opening it every start). Trim remains available for explicit use, preserved by test.
- No retry storm: each call reports at most once per failure stage; no loops added.

### B. First-frame timing origin
- Replace `LaunchTime` with `FirstFrameProbe` owned by Rust: `started: Option<Instant>` and `documented origin` in a doc comment.
- Origin = `main.rs` `setup()` closure completion is the earliest meaningful "app ready" moment; but the true first frame is when the frontend reports `preview_rendered`. Design: frontend sends `performance.now()`-based timestamp of the frame (deterministic under test via an injected value) and Rust measures interval from a documented origin.
- Simplest robust design that satisfies "actual frame interval + documented origin + deterministic test": pure helper `frame_interval_ms(origin_ns: u128, frame_ns: u128) -> u128` in Rust (saturating_sub), with unit tests. Origin is the documented process-start instant (`Instant` at main entry) BUT the issue says that's wrong - it wants frame interval, not process lifetime. So origin must be a meaningful frame-anchor.

Reconsider: The real fix is to measure between two frames, not from process start. Change frontend `reportPreviewFrame` to capture the RAF timestamp (`performance.now()` at the first animation frame) and pass it; Rust stores the first reported frame time as the origin, and on the next `preview_rendered` reports the delta. That measures an actual frame interval. But main.ts calls `requestAnimationFrame(reportPreviewFrame)` once - a single frame. A single frame has no interval.

Better: anchor origin at navigation complete (the `navigate(false)` + `render()`), and report the frame's own timestamp from RAF. Use two deterministic events:
  1. `preview_navigation_done` invoked right after `navigate(false); render()` in main.ts, capturing `performance.now()` at that point as origin on the Rust side (or store in JS and pass both).
  2. `preview_rendered` invoked from the first `requestAnimationFrame` callback with its `performance.now()` timestamp.

Rust computes `frame - origin` via pure helper. Documented clock origin: `performance.now()` (monotonic, time-origin-anchored) captured at the two frontend events; Rust is a passive recorder. Deterministic test: unit-test the pure `frame_interval_ms` helper with fixed values incl. reversal (saturating to 0). This satisfies "actual frame interval rather than elapsed process lifetime" - the interval is from render-complete to first painted frame, not process start.

Keep payload backward-compatible: `reportPreviewFrame()` still callable with no args (optional timestamp). Command `preview_rendered` accepts `Option<f64>` timestamp.

- Update dashboard/src/main.ts: `navigate(false); const navDone = performance.now(); invoke('preview_navigation_done', { atMs: navDone }); requestAnimationFrame((t) => reportPreviewFrame(t));`
- controller.ts: add `reportNavigationDone(atMs)`, change `reportPreviewFrame(atMs?)`.
- Rust: state `FrameTiming { origin_ns: Option<u128> }`, commands `preview_navigation_done(at_ms: f64, state)` and `preview_rendered(at_ms: Option<f64>, state)`; pure `frame_interval_ms(origin_ms: f64, frame_ms: f64) -> f64` (saturating). Keep `preview_first_frame_ms=` eprintln for continuity but now it's the real interval.
- Document clock origin in code comment: "Clock origin = performance.now() at navigation/render completion (frontend, monotonic). Interval = first RAF timestamp - origin."
- Keep `LaunchTime` removed; no `manage(LaunchTime(...))`.

## TDD sequence (red then green, real before/after)

Commit 1 (red): tests only
- Python: `tests/test_log_retention_reporting.py` add `test_rotate_log_unlink_failure_is_reported_not_raised` (repro above) and `test_rotate_log_stat_failure_is_reported` - both assert no exception + stderr contains "log retention failed"; these FAIL on current code (unescaped exception / silent).
- Rust: add `#[test]` for `frame_interval_ms`: origin 100.0, frame 118.5 -> 18.5; reversed -> 0.0; NaN -> 0.0. Also a test asserting `FrameTiming` origin set then interval computed from two timestamps. These FAIL to compile (functions don't exist) = red.
- Run: python pytest (2 fail), cargo test (compile fail). Capture verbatim.

Commit 2 (green): implementations
- router.py: add `_report_log_retention_failure(stage, exc)`; wrap stat/unlink/rename/chmod in single try/except; change signatures minimally.
- Rust main.rs: add FrameTiming + pure helper + commands + main.ts/controller.ts changes; update invoke handler list.
- Run: python pytest all retention/lifecycle/batch2/status (pass), cargo test (39+ pass), full python suite (1560+).

## Verification
- `python3 -m pytest tests/test_log_retention_reporting.py tests/test_lifecycle_events_184.py tests/test_batch2_regressions.py tests/test_status_readonly_log_236.py -q`
- `python3 -m pytest tests/ -q` (full)
- `python3 -m py_compile router.py state.py`
- `cargo test` with writable CARGO_HOME=/tmp/pr-cargo-home-issue184, proxy unset
- `cd dashboard && npm test` if playwright browsers available; otherwise `npm run build` (tsc) to verify TS compiles.
- PR check via gh with proxy unset; do NOT close #184.

## Boundaries / safety
- No live engine, no service restart, no proxy start. Work in isolated worktree on disk.
- No secrets in new logs (stage names + errno only).
- Do not touch other issues or the frozen archive.
- After merge, main advances; do not restart proxy-router.

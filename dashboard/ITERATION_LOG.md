# Dashboard UI v2 — iteration log

Goal: port the frozen prototype's strongest screen (side-nav shell + focused Overview)
into the real Tauri dashboard, then iterate with a strict council. Source-only.

State file — re-read at every seam. Worktree: feat/dashboard-ui-v2 (off origin/main).

## Baseline (verified)
- `npx playwright test` — 66 passed.
- `npx tsc --noEmit` — clean.
- env: unset HTTP(S)_PROXY for gh/probes; proxy is 127.0.0.1:2080 (protected).

## Frozen prototype — READ ONLY
- Entry: /Users/kyson/proxy-router/dashboard-ui/dashboard/polished.html
- Best: .../redesign-polished/{base.css,components.css,app.js,views.js,pages.js,data.js}
- Strongest screen: persistent 248px side rail (brand, icon+label nav, connection
  status card at bottom) + topbar with eyebrow breadcrumb / title / profile picker
  + a calm centered connection Overview + "View more" disclosure + Activity list.
- Never edit /Users/kyson/proxy-router (110 dirty files).

## Iteration 1 — side-nav shell + Overview (IN PROGRESS)
- Scope: new `sidebar` layout preset (persistent side nav with icon+label links,
  breadcrumb titlebar, bottom connection-status card) + lighter Overview spacing.
  Reuse existing rail/nav/links/ids/actions; no new behavior or routes.
- Compatibility: keep `vertical`/`horizontal` presets and all tests. Default layout
  stays `horizontal` in this iteration to avoid churning native-window sizing tests;
  council may pick "make sidebar default" as a follow-up.
- Red test: tests/sidebar-shell.spec.ts
- RED evidence (verbatim, `npx playwright test tests/sidebar-shell.spec.ts`):
  `3 failed` — all `locator.click: Test timeout of 30000ms exceeded. waiting for getByRole('button', { name: /^Sidebar/ })` at `tests/sidebar-shell.spec.ts:11:54`. Sidebar preset does not exist yet.
- GREEN evidence (verbatim, `npx playwright test tests/sidebar-shell.spec.ts`):
  `3 passed (6.8s)`.
- Full suite: `69 passed (1.7m)` (updated features.spec.ts layout-button count
  2→3 to account for the new preset — legit test maintenance).
- `npx tsc --noEmit`: clean.
- Visual check: /tmp/sidebar-home2.png — persistent side nav, icon+label links,
  bottom status card, Overview breadcrumb/title, focused connection hero.
- Diff: controller.ts (LayoutPreset + sidebar validation), main.ts (layout
  button + topbar view-breadcrumb/view-title + render text), window-layout.ts
  (sidebar size), style.css (sidebar preset), tests/sidebar-shell.spec.ts,
  tests/features.spec.ts (count 2→3).

### Council R1 (2 seats, opencode/hy4-flash-free, read-only)
- Seat A (ap-reviewer): **PASS**, no P0/P1. P2s: topbar heading leaks into all
  presets; third Sidebar layout button wraps alone in the 2-col preset grid.
  Highest-value next improvement: make sidebar the default first-run layout.
  Base problem noted: default `horizontal` flattens the rail, so the prototype's
  strongest screen was never the first-run view.
- Seat B (ap-implementer): **FAIL** — proven P1. Measured at 1440×900:
  horizontal/vertical topbar 100.19px (base ~56px) because `.view-heading` was
  inserted unconditionally (main.ts:69,633-635) but styled only for
  `:root[data-layout="sidebar"]` (style.css:781-783). P2s: duplicate SR page
  name (sr-only #page-label + #view-title both "Home"); weak differentiation
  (rail already clamps to 15.5rem, so sidebar width == vertical). Wiring/
  polish-CSS conflict checks passed. Next improvement: port prototype's topbar
  profile picker wired to real active-profile state.

### P1 fix — scope breadcrumb/title to sidebar (red-first)
- Red test: tests/topbar-regression.spec.ts (2 tests: horizontal + vertical
  single-line topbar). RED evidence (verbatim, `npx playwright test
  tests/topbar-regression.spec.ts`): `2 failed`, each `Expected: < 72,
  Received: 100.1875`, matching seat B measurement exactly.
- Fix: main.ts:69 — `.view-heading` gets `aria-hidden="true"`, `#page-label`
  restored as the visible label (removed `sr-only`). style.css:781-783 —
  `.view-heading { display: none }` by default; only `:root[data-layout=sidebar]`
  shows it and visually hides #page-label.
- GREEN evidence (verbatim, `npx playwright test tests/topbar-regression.spec.ts
  tests/sidebar-shell.spec.ts`): `5 passed (8.3s)`.
- Full suite after fix: `71 passed (1.8m)` (/tmp/full-iter1c.log).
  `npx tsc --noEmit`: clean (TSC_EXIT=0).
### Council R2 (both seats re-review the P1 fix)
- Seat A (ap-reviewer): **FAIL** — desktop P1 fixed (own run `5 passed (7.6s)`),
  but same P1 survives below 651px: both corrective rules were inside the
  `@media(min-width:651px)` block, so mobile still stacks OVERVIEW/Home + a
  second visible Home. Axe clean, aria-hidden/SR-name verified OK.
- Seat B (ap-implementer): **FAIL** — same mobile P1, measured 390×844 default
  topbar **84.19px** vs base **49px**. Desktop fixed (65px). SR duplicate name
  resolved (`ariaSnapshot` = `- banner: Home Local prototype`). Next pick:
  topbar profile picker.
- Both seats' single next pick: port the prototype's topbar profile picker
  wired to real active-profile controller state.

### Mobile P1 fix (red-first)
- Root cause: `.view-heading { display:none }` and the `#page-label` clip were
  inside the `@media(min-width:651px)` sidebar block.
- Fix: moved `.view-heading { display:none }` to a global rule next to `.topbar`
  (style.css:59); removed it from the media query; sidebar override stays in
  the media query; extended tests/topbar-regression.spec.ts with a mobile case
  (390×844 default layout).
- GREEN (verbatim, `npx playwright test tests/topbar-regression.spec.ts
  tests/sidebar-shell.spec.ts`): `6 passed (6.7s)`.
- Full suite after fix: `72 passed (1.3m)` (/tmp/full-iter1d.log).
  `npx tsc --noEmit`: clean (TSC_EXIT=0).
### Council R3 — CLEAN, iteration 1 DONE
- Seat A (ap-reviewer): **PASS**, no findings. Own rerun `6 passed (7.0s)`,
  tsc clean (first run was a dev-server startup race, infra flake). Axe clean.
- Seat B (ap-implementer): **PASS**, no P0/P1. Re-measured 390×844: horizontal,
  vertical, sidebar-mobile topbars all **49px** (was 84.19px; base 49px).
  `ariaSnapshot` = `- banner: Home Local prototype` (one name). Mobile Axe 0.
  Desktop: horiz/vert 65px heading hidden; sidebar 108.98px with breadcrumb/
  title, #page-label clipped, banner exposed once.
- Council total: R1 (A PASS / B FAIL-P1), R2 (A FAIL-P1 / B FAIL-P1),
  R3 (A PASS / B PASS). Two P1 rounds fixed, final clean.
- Next pick (iteration 2): port the prototype's topbar profile picker wired to
  real active-profile controller state (both seats agree, both rounds).

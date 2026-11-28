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

---

## NEW TASK (replaces rejected iteration 1) — Signal Console port

User rejection: "ngl the UI is not looking better i was talking about the completely new UI find it somewhere". Real target supplied at `/Users/kyson/botkrie/state/ui-run/` (entry `work/ui/redesign.html`, assets `work/ui/redesign/`, notes REDESIGN.md / COUNCIL-UI.md / RESULT.md). The earlier `sidebar` preset work is DONE and PR #337 — do not touch it further.

### Iteration C1 — console layout preset: shell + Overview (implementation done)
- Scope: NEW opt-in `console` layout preset porting the Signal Console identity:
  lime-on-ink (#000/#fff, --console-accent #d4ff62), faint schematic grid, DM Sans
  font stack, 250px side rail with PR breadcrumb header, power ring, throughput
  sparkline, top routed sites with lime bars, timestamped activity log + SAMPLE DATA
  footer. Reuses real `#nav`, real `data-action=connect/disconnect`, existing ids.
  Default remains `horizontal`; other presets/pages untouched via CSS scoping.
- RED (verbatim /tmp/console-red.log): `npx playwright test tests/console-shell.spec.ts`
  → `3 failed`, each `locator.click: Test timeout of 30000ms exceeded. waiting for getByRole('button', { name: /^Console/ })` at `console-shell.spec.ts:13:54`.
- GREEN (verbatim /tmp/console-green.log): `3 passed (4.8s)`.
- First full run 74 passed/1 failed: new `.console-crumb` was visible in default layout
  at mobile width, inflating topbar to 87px (topbar-regression expects <72). Fix:
  global `.console-crumb{display:none}` in style.css next to `.view-heading`.
- Final full suite (verbatim /tmp/console-full2.log): `75 passed (1.4m)`.
  `npx tsc --noEmit` clean (TSC_EXIT=0).
- Visual /tmp/console-overview.png: black canvas, lime ring, PR crumb, PR-badged
  header, hero "Disconnected", sites bars + activity — matches UI-R4-OVERVIEW target.
- Diff: controller.ts (2), window-layout.ts (1), main.ts (7 + big consoleHomePage fn),
  style.css (2), features.spec.ts (1, count 3→4); NEW console.css (~230 lines) and
  NEW tests/console-shell.spec.ts (3 tests). Council: PENDING (2 rounds x 2 seats).
- Next picks: port the remaining prototype pages (Routes/Providers/Network/Settings)
  into console identity; rename nav labels to match prototype; profile picker in header.

### Iteration C1 council gate
- R1 seat A (ap-implementer replacement; first ap-reviewer seat returned INVALID-DISPATCH
  on its own Autoprompt-marker contract, did no review): FAIL — P1 Console+light scheme
  produced 100+ Axe contrast violations (light tokens on forced-black canvas).
  P2 half-ported UI off Overview; P3 drift from R4 target (156px ring, H1, PR crumb).
- R1 seat B: PASS — no P0/P1; verified real connect/disconnect, persistence, no CSS
  leak, Axe clean in dark. P2 partial fidelity/sample marking; P3 DM Sans not loaded,
  grid hidden under main.
- P1 fix (red-first): new test 'console stays readable when the light scheme is
  selected' loops all six pages with Axe under data-scheme=light. RED /tmp/console-light-red.log
  (`1 failed`, e.g. fg #595e77 on #070707 ratio 3.15). Root cause: dashboard-polish.ts
  applyDashboardPalette() sets inline --muted from scheme alone — beats all CSS.
  Fix: that function now treats data-layout="console" as dark; console.css remaps tokens
  incl. `html[data-layout="console"][data-scheme="light"]:has(.polished-preview)`.
  GREEN /tmp/console-light-green3.log `4 passed (8.3s)`; full `76 passed (1.4m)`; tsc 0.
- R2 seat A (ses_ddcf7b841ffe4vZoOv3qPq5Ets): **PASS**, no P0/P1. Independently
  re-ran targeted `4 passed (8.8s)`, full `76 passed (1.4m)`, tsc 0; P1 light-scheme
  contrast resolved at head, other layouts unchanged. P2 carried: only Overview ported.
  P3 carried: ring 156px vs ~84px target, H1/PR crumb/footer identity drift, scheme
  picker still offers Light while console forces dark. Next pick: port remaining pages.
- R2 seat B (ses_ddcf81f77ffeSDYwcz8teAu5k0): **PASS**, no P0/P1. Independent run
  `4 passed (7.9s)`, tsc 0. Verified fix root cause in dashboard-polish.ts:58-60 +
  applyTheme/sync ordering; also probed reverse path (Light first → Console), 5/5
  Axe-clean across six pages. One earlier transient contrast hit did not reproduce.
  P2 carried: Overview-only skin, other pages/rail labels unchanged, no header
  profile picker; only Activity marked SAMPLE DATA. P3 carried: DM Sans declared
  not loaded; grid hidden under main. Next pick: port Routes + relabel rail.
- C1 council complete: R1 (A FAIL-P1 / B PASS) → R2 (A PASS / B PASS), P1 fixed
  red-first. Committed/pushed as d87f457 on PR #337 (ready for review, NOT merged).

### Iteration C2 — console Routes screen + prototype rail labels
- Scope (reversible): relabel the rail ONLY under `data-layout=console` to
  Overview / Routes / Providers / Network / Settings (Appearance stays reachable
  so the preset can be exited). Hrefs/ids unchanged; other layouts keep old labels.
  Port the prototype's Routes screen: segmented routing-mode control, domain add
  form, domain list with Remove, LOCAL PROFILE footer (no false per-app claim).
- Real actions (after council P0/P1 fix): in Tauri the Routes screen reads
  `engineConfig.routes`, Add calls real `routeAddAction()` (add_route invoke) and
  Remove calls `routeRemoveAction(id)` (remove_route invoke), with footer
  "ENGINE ROUTES · FROM ROUTER.JSON". In browser preview it uses browser-safe
  `controller.setProvider/addDomain/removeDomain` with a LOCAL PROFILE footer.
  Routing-mode keeps `data-action=routing-mode` and `aria-pressed` from real state.
- RED (verbatim /tmp/c2-red.log): `4 failed`. (1) `expect(locator).toHaveAttribute(expected) failed — Locator: locator('#nav').getByRole('link', { name: 'Overview', exact: true }) — Expected: "#home" — Timeout: 5000ms — Error: element(s) not found` at console-routes.spec.ts:26:69; (2)(3)(4) `Test timeout of 30000ms exceeded. Error: locator.click: Test timeout of 30000ms exceeded. Call log: - waiting for locator('#nav').getByRole('link', { name: 'Routes', exact: true })` at :36/:58/:75.
- GREEN (verbatim /tmp/c2-green-final.log): `8 passed (12.8s)` — 4 new Routes tests + 4 C1 shell tests.
- Full suite (verbatim /tmp/c2-full.log): `80 passed (1.6m)`. `npx tsc --noEmit`: clean (TSC_EXIT=0) after two type fixes (String(mode), non-null dataset.domain).
- Visual /tmp/c2-routes.png: black canvas, PR breadcrumb "Proxy Router / Routes",
  h1 Routes, mode segmented control, input + provider combobox + lime Add route,
  3 domain rows with Remove, LOCAL PROFILE footer — matches UI-R5-ROUTES structure.
- Diff: main.ts (nav label spans, consoleNavLabel helper, consoleRoutesPage fn,
  render label/crumb/dispatch, 2 click actions), console.css (segmented/add-form/
  custom-select/responsive styles), console-shell.spec.ts (console labels), NEW
  tests/console-routes.spec.ts (4 tests). Council: PENDING (2 rounds x 2 seats).
- Next picks if clean: port Providers and Network into console identity; header
  profile picker; load DM Sans; reveal schematic grid under main.

### Iteration C2 council gate
- R1 seat A (ses_ddcdbbe7cffe1B4gOAINXGKVjF): **FAIL**. Confirmed rail relabel is
  console-scoped, non-console labels restore, CSS fully scoped, aria-pressed real,
  browser add/remove persists; own run `8 passed (13.5s)`, tsc 0. P0: shipped Tauri
  Add/Remove only mutated LocalController localStorage, and Tauri sync() does not
  copy profiles back (main.ts:115-117), so rows never updated while the toast
  claimed success — silent no-op. P1: provider selector decorative; add handler
  read only #route-domain (main.ts:1150-1153). P2: console.css:118 hides
  #prototype-badge; footer hardcoded 'SELECTIVE ROUTING' for every mode. P3: no
  Axe/mobile test on Routes. Next pick: Tauri-aware helper + wire provider.
- R1 seat B (ses_ddcdbbe75ffe0BR4R6nlSvdEHt): **FAIL**. Same dead provider picker
  (P1). P2: no form semantics / Enter-to-submit (prototype uses form#add-route).
  P3: no empty state; document.title/#page-label/#view-title still say 'Profiles'
  on console Routes; cosmetic drift. Confirmed 4+4 tests pass, Axe 0, mobile clean.
  Next pick: wire #route-provider into add or remove the picker.
- P0/P1 fix (red-first): NEW tests/console-routes-desktop.spec.ts simulates Tauri
  via addInitScript + __TAURI_INTERNALS__.invoke mock (get_config/get_live_status/
  get_routing/get_dashboard_state/add_route/remove_route). RED /tmp/c2-p0-red.log
  `1 failed` — `expect(locator).toContainText(expected) failed — Locator:
  locator('.console-foot') — Expected substring: "ENGINE ROUTES" — Received string:
  "LOCAL PROFILE · SELECTIVE ROUTING"` at console-routes-desktop.spec.ts:58:47.
  Fix: consoleRoutesPage() now branches on isTauri() — engine routes/ids + provider
  note in Tauri, preview domains otherwise; add is a real `<form>` submit wired to
  consoleRouteAdd() which calls routeAddAction() in Tauri and setProvider+addDomain
  in preview; Remove uses routeRemoveAction(id) in Tauri; empty state added.
  GREEN /tmp/c2-p0-green.log `1 passed (3.5s)`; full /tmp/c2-full-fixed.log
  `81 passed (1.5m)`; `npx tsc --noEmit` TSC_EXIT=0.
- R2 seat A (ses_ddcdbbe7cffe1B4gOAINXGKVjF): **PASS**, no P0/P1. Own run
  `9 passed (14.0s)`, TSC_EXIT=0; full `81 passed (1.5m)`. Verified P0/P1 fixed
  at source: isTauri branch (main.ts:354-355), engine routes (362-369),
  console-route-remove → routeRemoveAction → remove_route (1177,1462-1470),
  form submit → consoleRouteAdd → routeAddAction → add_route (383,396,1286,
  1447-1459); refreshStatus → refreshEngineData → refreshEngineConfig (884,
  902-904) repaints rows; Rust commands persist router.json (main.rs:494-500,
  625-670). Test asserts actual add_route/remove_route payloads incl. provider
  proton and id r2. P2 carried: browser preview setProvider reassigns whole
  active profile; #prototype-badge hidden in console; footer hardcodes
  SELECTIVE ROUTING. P3 carried: no Axe/mobile run on Routes screen.
  Next pick: per-domain provider in browser preview (or hide picker in preview).
- R2 seat B (ses_ddcdbbe75ffe0BR4R6nlSvdEHt): **PASS**, no P0/P1. Independent
  `1 passed (3.4s)` desktop mock test (add_route provider proton, remove_route id
  r2), `8 passed (11.2s)` browser specs, Axe 0 on Routes/all console pages incl.
  light scheme + mobile, tsc exit 0. Confirmed real form submit (main.ts:383,1286)
  and empty state (371). P3 carried: provider options show raw ids instead of
  friendly names (358-361); document.title still 'Profiles' on console Routes
  (755,757,759); preview provider choice reassigns whole profile (395-399);
  cosmetic drift. Next pick: map provider ids to friendly display names while
  keeping ids as option values.
- C2 council complete: R1 (A FAIL-P0/P1 / B FAIL-P1) → P0/P1 fixed red-first →
  R2 (A PASS / B PASS). Committed/pushed as 60147fd on PR #337 (ready for review,
  NOT merged).

### Iteration C3 — remove spaced captions and mono subtitles
- User request: "remove these goddamn font and not needed subtitles." The flagged
  element was the widely-tracked uppercase "CONNECT" caption under the power ring.
  Reversible scope choice: remove `.power-caption` (Overview) and both
  `.console-status-line` mono subtitles (Overview + Routes); keep honesty footers
  (SAMPLE DATA / ENGINE ROUTES) but restyle them from letter-spaced mono to plain
  sans. The power button keeps its accessible aria-label (Connect/Disconnect).
- RED (verbatim /tmp/c3-red2.log): `1 failed` — `expect(locator).toHaveCount(expected) failed — Locator: locator('.power-caption') — Expected: 0 — Received: 1 — Timeout: 5000ms` at console-clean.spec.ts:22:48. Earlier weaker RED /tmp/c3-red.log failed on footer letterSpacing (Expected "normal", Received "0.8704px").
- GREEN (verbatim /tmp/c3-green.log): `1 passed (5.1s)` — new tests/console-clean.spec.ts checks caption/subtitle counts are 0, the Connect button is still usable (Connect→Connected), footers are plain sans with letter-spacing normal and keep SAMPLE DATA, Axe [] on Overview + Routes.
- Full suite (verbatim /tmp/c3-full.log): `82 passed (2.0m)`. `npx tsc --noEmit`: TSC_EXIT=0.
- Visual: /tmp/c3-overview.png and /tmp/c3-routes.png — no CONNECT caption, no mono subtitle, honesty footers still present in plain sans.
- Diff: main.ts (removed profile/provider/modeNote locals + subtitle + caption markup in both pages), console.css (removed `.console-status-line` and `.power-caption` rules, restyled `.console-foot`), NEW tests/console-clean.spec.ts.
### Iteration C3 council gate — CLEAN
- R1 seat A (ses_ddcbaa358ffeqyDblaGreoMrRh): **PASS**. Live DOM `.power-caption`=0 and `.console-status-line`=0 on Overview+Routes, no orphan CSS; native button aria-label Connect/pressed=false, focus+Enter → Connected/Disconnect/pressed=true, Axe []; footers SAMPLE DATA / LOCAL PROFILE · SELECTIVE ROUTING / ENGINE ROUTES · FROM ROUTER.JSON intact; computed fontFamily DM Sans Variable, letterSpacing normal. Own runs `1 passed (6.9s)`, full `82 passed (2.0m)`, tsc 0. P3: Overview loses at-a-glance provider/mode; test gap on Disconnect aria-label flip.
- R1 seat B (ses_ddcbaa353ffeEK373Fe2rKH4FB): **PASS**. Ring state still explicit via title + rail status, mode on Routes segmented control, Axe clean, mobile covered; P3 next pick plain-sans power glyph inside ring.
- R2 seat A: **PASS** — no drift (same 3 files, 17+/12-, hunks byte-identical), focused rerun `1 passed (5.8s)`, tsc 0; no new P0/P1. R2 seat B: **PASS** — no drift at HEAD 60147fd, live GREEN `1 passed (5.4s)` (/tmp/c3-r2-green.log), tsc 0; Axe [] on both pages, focus/mobile/footers intact.
- C3 council complete: R1 (A PASS / B PASS) → R2 (A PASS / B PASS), zero P0/P1. Committed/pushed as dfac161 on PR #337 (ready for review, NOT merged).

### Iteration C4 — one font family across the console
- User request: "make sure the font is fully consistent." Scope choice: every visible
  text element under `data-layout=console` resolves to the DM Sans Variable stack;
  no second (mono) family. Keep tabular numerals on `.mono` via font-variant-numeric.
- Leak sources: console.css `--console-mono` (SF Mono stack) consumed by `.crumb-badge`,
  `.mono`, `.list .fav`, `.event-log time`; base rules style.css:247 `.route-list
  .route-domains` and style.css:651 `.diag-raw pre`.
- RED (verbatim /tmp/c4-red.log): `1 failed` — "Overview still uses a mono font:"
  16 offenders (`span.crumb-badge`, 6× `span.fav`, 6× `span.hits mono`, 5× `time.`)
  all `"SF Mono", SFMono-Regular, "JetBrains Mono", Consolas, "Liberation Mono",
  Menlo, monospace`; `Expected -1 + Received +18` at console-font.spec.ts:34:73.
- GREEN (verbatim /tmp/c4-green2.log): `1 passed (6.3s)` — new tests/console-font.spec.ts
  walks all six console pages and asserts zero visible elements compute a mono family.
- Full suite (verbatim /tmp/c4-full.log): `83 passed (2.1m)`. `npx tsc --noEmit`: TSC_EXIT=0.
- Diff: console.css (--console-mono redefined to the sans stack + scoped overrides for
  `.route-domains`, `.diag-raw pre`, `.mono`), NEW tests/console-font.spec.ts. No markup changes.
- Council R1 seat A (ses_ddcac4080ffexL2HFrcUAFDIYU): **FAIL** — P1 bare `<pre>`/`<code>` in the desktop WARP provider form (main.ts:531) still computes `monospace` under console; the scoped override patched only `.diag-raw pre`, which has no matching markup (dead selector). R1 seat B: PASS (all six pages one DM Sans family, Axe [], tabular-nums intact).
- P1 fix (red-first): second test in console-font.spec.ts injects `<div class="font-probe"><pre><code>warp-cli connect</code></pre></div>` under console and asserts every family starts with `"DM Sans Variable"` and has no /mono/i. RED /tmp/c4-p1-red.log `1 failed` (`"DM Sans Variable", ... | monospace | monospace`, `Received: false` at console-font.spec.ts:52:119). Fix: console.css overrides now target `:root[data-layout="console"]` `.route-list .route-domains, .mono, pre, code, kbd, samp` with `font-family: var(--console-mono); font-variant-numeric: tabular-nums;`.
- GREEN /tmp/c4-p1-green.log `2 passed (4.4s)`. Full /tmp/c4-full-final.log `84 passed (2.0m)`. `npx tsc --noEmit` TSC_EXIT=0.
- Council R2: seat A (ses_ddcac4080ffexL2HFrcUAFDIYU) **PASS** — console.css:16-23 confirms `pre/code/kbd/samp` + `.route-domains/.mono` scoped to the sans stack; live probe of WARP-style pre/code and kbd/samp all compute `"DM Sans Variable", …`, `white-space: pre` intact, zero mono on all six pages, non-console `pre` still `monospace` (no leak), `.hits.mono` tabular-nums; rerun `2 passed (4.7s)`, tsc 0. Seat B (ses_ddcac407dffe1onllPtg769rYr) **PASS** — real Tauri-mocked desktop WARP dialog verified `<pre>` 14px/400 and `<code>` 12px/400 on DM Sans, document mono=[] incl. pseudo-elements, Axe dialog []; focused `7 passed (13.2s)`, full `84 passed (2.0m)`, tsc 0; diff exact (ITERATION_LOG.md, console.css, new console-font.spec.ts). P3 carried: WARP shell commands now proportional; probe-injection test instead of real-dialog test; `.event-log time` lacks tabular-nums.
- C4 council complete: R1 (A FAIL-P1 / B PASS) → P1 fixed red-first → R2 (A PASS / B PASS). Ready to commit + push; do not merge without CI + clean council.


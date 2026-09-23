# Proxy-router post-merge audit — Neuro's verification pass on the 5.6-sol report

Sol agent produced /tmp/proxy_router_postmerge_audit.md (6 findings). I verified each against source. Corrections below.

## Verified findings (real, actionable)

1. **BLOCKER (verified)** — sudoers/interpreter mismatch in NEW installer code:
   - Live sudoers (this Mac) grants `/opt/anaconda3/bin/python3 /Users/kyson/proxy-router/router.py ...`
   - But `privileged_installer.py` hardcodes `SYSTEM_PYTHON=/usr/bin/python3` and sudoers line `/usr/bin/python3 -I -S <helper>`; `router.py:4989 PRIVILEGED_PYTHON="/usr/bin/python3"`.
   - Any freshly installed helper/plist from these scripts will request elevation under an interpreter path NOT in sudoers → silent denial (exit 1, no stderr). Existing deployed setup works only because its plist PATH puts /opt/anaconda3/bin first.
   - Fix direction: privileged_installer should render the sudoers line for the SAME interpreter that runs router.py (`sys.executable` at install time), or explicitly pin /opt/anaconda3/bin/python3 with a guard.

2. **HIGH (mechanism verified)** — engine_start writes last-good ONLY when `not use_existing_config`; the SIGHUP-restart fallback path therefore never snapshots. Combined with finding "restore paths > snapshot paths", a later failure can restore stale last-good. Real but lower urgency: last-good staleness ≠ breakage.

3. **HIGH→DOWNGRADED to MED (design-as-documented)** — rotate() hard-blocks while fallback active; no --force. Docstring documents the contract and `failover off` is the explicit clear path. The keepalive interaction (dead primary + active fallback → strikes reset, no rotation) deserves an integration test but is intentional safety behavior per skill: "rotating a primary while its fallback marker is active either remains blocked or explicitly clears fallback first". Keep as watch-item.

4. **MED (verified)** — tray mutation worker `self._mutation_gate.acquire()` blocks forever, BUT all mutation fns are subprocess calls with `timeout=COMMAND_TIMEOUT=20`, so a hang requires a stuck subprocess kill path. Quit drain uses MUTATION_DRAIN_TIMEOUT=25s then proceeds. Residual risk small; adding acquire timeout would be cheap hardening.

## Refuted findings

- **Finding 6 (providers_check stale globals): FALSE POSITIVE.** main() dispatches through a global `rc = load_config()` (router.py:5539) BEFORE providers_check runs — `_providers` is always fresh at CLI entry. Proven live: with PROXY_ROUTER_ROOT pointed at a temp root, `providers check` correctly read the temp config and reported `proton: INVALID (0 profiles)`.

## Cross-PR hunt results (agent's, spot-checked)

- (a) #89 atomic writer vs keepalive regen: serialized via _EngineLock flock; TOCTOU window noted between _config_drifted() rebuild (outside lock) and reload write — minor.
- (b) #64 import exclusivity vs #91 tray lock: different resources, no deadlock.
- (c) #76 vs sudoers identity: CONFIRMED as finding 1 above.
- (d) #92 install vs #91 quit-drain: sequenced OK (install bootouts agents first).
- (e) #86 DNS dedupe vs health ordering/cooldown drops: independent stages, no interference.

## Test evidence

- pytest tests/: 747 passed, exit 0
- py_compile all modules: exit 0
- proxy_tray.py --selftest: SELFTEST DONE, exit 0

## Recommended actions

1. Fix privileged_installer.py + router.py PRIVILEGED_PYTHON to derive interpreter from sys.executable (or pin /opt/anaconda3/bin/python3 consistently). Add test asserting rendered sudoers interpreter == running interpreter path.
2. Add write_last_good() after successful engine_start(recover=False) restart-fallback in engine_reload.
3. Integration test: rotate-while-fallback-active → expect blocked rc + explicit message; failover off → rotate succeeds.

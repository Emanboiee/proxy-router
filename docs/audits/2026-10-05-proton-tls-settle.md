# Proton TLS settling: corrected audit and PR history

## Result

The corrected October 5, 2026 audit authenticated all 23 primary Proton
WireGuard profiles. **22/23 passed HTTPS**, followed by three successful fresh
requests per passing profile (66 confirmations). Twenty profiles recovered
after an initial TLS failure. Successful settling took 2.4–16.1 seconds.

`22-SG-FREE-15` authenticated but failed all 24 HTTPS attempts in the configured
60-second window. It had returned verified HTTP 200 twice in an earlier test
of the same tunnel. Its application path is intermittent; the exact upstream
cause was not isolated. Neither TLS EOF nor a WireGuard handshake proves
usable HTTPS, and neither establishes that credentials expired.

This measures routed HTTPS availability, not free-model quota or guaranteed
24/7 availability. The remaining failure must stay a failure until an actual
HTTPS probe succeeds.

## What was fixed before?

| PR | Prior change | Relationship to this audit |
| --- | --- | --- |
| [#35](https://github.com/Emanboiee/proxy-router/pull/35) | Settle-aware probing and service-appropriate probe targets | Already documented early TLS failures recovering after 8–20 seconds; its earlier audit found 26 usable exits. |
| [#37](https://github.com/Emanboiee/proxy-router/pull/37) | Curl probes and transport-blip retry | Improved probe transport and steady-state retry. |
| [#79](https://github.com/Emanboiee/proxy-router/pull/79) | Poll the settle window instead of sleeping through it | Returns when readiness is observed; the configured maximum is not a fixed sleep. |
| [#118](https://github.com/Emanboiee/proxy-router/pull/118) | Target-scoped TLS strikes and quarantine | Separates repeated TLS failures from connection/DNS failure policy and defers TLS quarantine during settling. |
| [#188](https://github.com/Emanboiee/proxy-router/pull/188) | Reject TLS failures as usable egress | Prevents false healthy sweep, fallback, and TUN-readiness results; preserves probe error evidence. |

The basic warmup behavior was therefore already fixed. The follow-up addresses
remaining settle-policy gaps: premature connection cooldown, probe I/O budget,
HTTP outcomes incorrectly spending transport warmup time, and a misleading
"retrying once after" log message. It does not claim to repair the upstream
Singapore path.

## Reproduction method

1. Treat the 23 primary profiles as one account. Park that account's production
   tunnel before creating a diagnostic tunnel. Leave the secondary provider
   connected only because it belongs to a separate account.
2. Test primary profiles serially, one diagnostic tunnel at a time. Use isolated
   engine ports, health records, and cooldown state.
3. Confirm WireGuard authentication separately from application readiness.
4. Run the real `_probe_with_settle` function against the routed OpenCode models
   HTTPS endpoint, with the configured 60-second maximum. Record initial
   failures, attempts, and elapsed time.
5. For each successful profile, make three additional fresh HTTPS requests.
6. Restore production configuration byte-for-byte and verify the active primary
   path. Both `proton` and `proton2` were restored; production passed settling
   and all three subsequent requests. Tailscale remained running without an
   exit node.

The initial quick scan destroyed fresh tunnels after immediate probes, before
their settle window. Its claim that 22 profiles were persistently unusable was
incorrect. The correction is recorded on
[PR #188](https://github.com/Emanboiee/proxy-router/pull/188#issuecomment-5994070341)
and [issue #177](https://github.com/Emanboiee/proxy-router/issues/177#issuecomment-5994071024).
Issue #177 remains broader than these TLS fixes and is not closed by this audit.

## Evidence retained locally

The diagnostic artifacts are not committed because they contain operational
profile details. The measured results above are drawn from:

- `test-results/warmed-pool-audit-20261005.json` and its readable `.md` report.
- `test-results/wg-handshake-diagnosis-20261005.json`.
- `test-results/warmed-pool-final-verification-20261005.json`.

No diagnostic health result was used to clear production model-quota markers.

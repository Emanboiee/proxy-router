# Changelog

All notable changes to proxy-router are documented here. Versions follow
`vMAJOR.MINOR.PATCH`; the released tag is the source of truth for what ships.

## Unreleased

Status: audited `main`, green test suite, awaiting the next tag. This entry
**supersedes v0.2.1**, which predates the August 2026 audit by roughly 55
commits (~16k added lines) and no longer represents the product.

### Fixed / hardened since v0.2.1 (audit 2026-08 wave)

Security and identity:

- Stop passwordless sudo from trusting mutable code; delegate only exact,
  allow-listed root lifecycle operations to an installed root-owned helper
  (#71, audit #56).
- Pin one interpreter across launchd, keepalive, and elevation so launchd
  never resolves a different python3 than the elevation policy authorized
  (#74, audit #57).
- Route every config writer through atomic tmp+rename so interrupted writes
  cannot leave truncated JSON (#89).
- Close readiness and process-identity race windows around engine start/stop
  (#75, audit #62).
- Make manual-off quiescent and watcher shutdown synchronous; the watcher no
  longer resurrects an engine the user explicitly turned off (#77, audit #61).

Reliability and latency:
- Poll instead of sleeping through rotation settle windows; stop paths wait
  on real engine exit rather than a blind sleep (#79, #80).
- Give tun-mode reloads a realistic readiness budget and skip no-op ensure
  drift rebuilds when no config input changed (#82, #83).
- Probe egress providers concurrently in check cycles and rotate the provider
  that actually serves the failing host (#85, #81).
- Deduplicate identical DNS resolvers in the generated config (#86); make
  DoH conditional on the school-warp preset (#78).
- Apply presets with a hot reload instead of reporting done while old exits
  kept serving (#84).
- Bound TUI router commands with timeouts so a stuck CLI cannot freeze the
  dashboard (#88); open the dashboard via fire-and-forget so a slow terminal
  cannot freeze the tray (#90).
- `providers check` preflight (#51): offline, read-only validity audit of
  every configured provider (missing/empty profile directories, unparseable
  `.conf` files, all exits cooled down, bad per-provider entries), with
  `--json`, a valid/total summary, and exit 1 when any lane can't carry
  traffic — so "only 10/27 working" is diagnosable without probe traffic.
  `docs/REFACTOR_PLAN.md` proposes the router.py decomposition for #66
  (design only).

Installer and release (this change):

- Transactional installs: staged release directory, smoke test, atomic
  switch, one-command rollback (`install.sh --rollback`).
- Custom prefixes derived from the installed script; XML-escaped plist
  rendering; stale loaded jobs detected and migrated reversibly.
- Release downloads verify upstream sing-box checksums; exactly-one-binary
  assertion per artifact; clean-install CLI smoke tests; publishing gated on
  the full pytest suite for the tagged SHA; actions pinned to commit SHAs.

## v0.2.1

Historical release. Superseded by the entries above; see the repository
history between `v0.2.1` and the next tag for the complete diff.

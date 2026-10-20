# Windows release smoke — implementation report (issue #67)

Branch: `fix/windows-release-smoke-20261021` (base `9d13c9f`, previous commit `ed1d079`).
This round implements the parent review's concrete fixes and adds a safe
pull-request Windows CI job. **No GitHub interaction was performed**: nothing
pushed, no release dispatched, no publish path touched, no dashboard/live work.

## 1. Review fixes

### 1.1 `Assert-PrivateAcl` could never pass in CI (`.github/scripts/windows-release-smoke.ps1`)

The function asserted `AreAccessRulesProtected == true` unconditionally.
Generated child files (`sing-box.json`, provider profiles) are created *inside*
the protected install root, so their DACL is inherited and therefore
**unprotected** — CI would have failed on every clean install, and the real
inherited state was never actually asserted.

Now, split by `-ExpectInherited`:

| Entry | Assertion |
|---|---|
| install root, `providers\`, `router.json` (explicit, locked by `install.ps1`) | `AreAccessRulesProtected == true`, **no** leftover inherited ACEs, allowed SIDs only |
| generated `sing-box.json`, `providers\smoke\profile.conf` (`-ExpectInherited`) | `AreAccessRulesProtected == false` (must keep inheriting), every Allow ACE `IsInherited == true`, allowed SIDs only |

Both branches still require the installing user + `S-1-5-18` allow ACEs and
reject any SID outside `{current user, SYSTEM, Administrators}`.

### 1.2 `.cmd` launcher returned parse-time exit codes (`install.ps1`)

The generated `bin\proxy-router.cmd` used `exit /b %ERRORLEVEL%` **inside
parenthesised blocks**. cmd expands `%ERRORLEVEL%` when it *parses* a `( ... )`
block, so the `py` branch (the branch real users hit first) returned the value
from before the block — usually `0` — and every `router.py` failure looked
healthy.

* Replaced all occurrences with bare `exit /b` (no argument preserves the
  current code at run time). The smoke script's own fresh-shell wrapper got the
  same treatment for consistency.
* The structural contract is enforced by `tests/windows_ast_contract.ps1`
  (parses both scripts with the real PowerShell AST): no `%ERRORLEVEL%` anywhere
  in the embedded launcher, no `exit /b` with an argument, at least two bare
  `exit /b` lines (one per branch).

### 1.3 Meaningful nonzero-exit propagation tests (real `cmd.exe`, Windows CI only)

Static/macro pytest is not runtime proof (and must not be presented as such),
so the proof lives in the smoke script, which only runs on a Windows runner:

1. `proxy-router.cmd --no-such-flag` → must exit **2** (argparse) through the
   launcher as installed.
2. Forced **py branch**: a `wscript`-hosted `py.vbs` stub that passes the
   launcher's `py -3 -c "import sys"` probe and forwards to `python` → the
   parenthesised branch runs `router.py`, hits argparse, and its bare `exit /b`
   must hand **2** back.
3. Forced **python fallback**: a stub whose probe fails → the launcher falls
   through to the top-level branch → must also return **2**.

Design notes: a `.cmd` stub would *chain* (running one batch script from
another without `call` terminates the caller — see
<https://ss64.com/nt/start.html>), so the stub is a `.vbs` PATHEXT entry, which
cmd waits for and returns from. Each stub writes an `invoked.marker` file, and
the smoke asserts the marker exists — a branch cannot pass the exit-code
assertion without having actually been executed. If `wscript.exe` is missing
the forced checks are skipped with a visible warning (the natural run still
proves propagation on the branch the host actually takes).

### 1.4 Safe PR-triggered Windows CI (no release, no publish)

The release workflow runs on tags/`workflow_dispatch` only, and dispatching it
**publishes** a release — it can never validate a PR, and it must not learn a
`pull_request` trigger.

Chosen approach (the review's preferred one, minimal and structurally safe):

* **`.github/scripts/assemble-release-bundle.sh`** — the release job's six
  inline assembly steps (engine download + issue-#63 checksum verification,
  extract, single-binary arch/version assert, runtime file manifest, examples,
  archive) extracted verbatim into one helper. `release.yml`'s build matrix now
  calls it for all four targets, and so does the PR job — one manifest, no
  drift possible. The `publish` job and every other release job are untouched.
* **`.github/workflows/windows-smoke.yml`** — new workflow, `on: pull_request`
  only, `permissions: contents: read`, one `windows-latest` job:
  assemble via the shared helper (`windows-amd64 zip`, ref = PR sha) →
  `setup-python` → run `windows-release-smoke.ps1` against the exact zip. It
  contains no artifact upload, no release action, no write permission: it is
  structurally incapable of publishing anything (unlike guarding `release.yml`
  jobs with `if:` conditions, where one missed guard would push a release).

The alternative (adding `pull_request` to `release.yml` with per-job guards)
was rejected for exactly that footgun.

## 2. Tests added/updated

* `tests/windows_ast_contract.ps1` — PowerShell AST contract for
  `install.ps1` + smoke script (§1.1/§1.2 structure, propagation probes present
  in the embedded cmd here-strings). Run by
  `tests/test_windows_install.py::test_powershell_scripts_satisfy_ast_contract`
  under any working `pwsh` (PATH, `PWSH=` env, or a probed `/tmp/pwsh*/pwsh`);
  skips only when no pwsh exists at all.
* `tests/test_windows_install.py` — static guards for the launcher exit
  contract and the smoke propagation probes; contracts for
  `windows-smoke.yml` (pull_request-only, `contents: read`, no publish
  machinery, calls helper + smoke script); release/PR shared-assembly test
  asserting `release.yml` still has **no** `pull_request` trigger and its
  `publish` job only exists under tag/dispatch triggers.
* `tests/test_release_bundle.py` — manifest assertions now read the shared
  helper (and assert `release.yml` calls it instead of carrying an inline copy
  list).

## 3. Verification performed — exact scope

Run on this machine (macOS, Python 3.12.9):

| Command | Result |
|---|---|
| `python3 -m pytest tests/test_windows_install.py tests/test_release_bundle.py tests/test_ci_contract.py -q` | **20 passed** |
| `python3 -m pytest tests -q` (full suite) | **1254 passed, 5 warnings** (129 s) |
| `/tmp/pwsh75/pwsh -NoProfile -NonInteractive -File tests/windows_ast_contract.ps1 <root>` | **AST contract ok** (PowerShell 7.5.3; `/tmp/pwsh-tool/pwsh` was probed and skipped — needs .NET 8, host has 9) |
| AST contract vs **pre-fix** `install.ps1` | **fails** as intended (`%ERRORLEVEL%` detected) |
| AST contract vs **pre-fix** smoke script with fixed `install.ps1` | **fails** as intended (inherited entries not asserted unprotected) |
| `bash -n .github/scripts/assemble-release-bundle.sh` | ok |
| `python3 router.py --no-such-flag; echo $?` | `2` (the code the smoke expects) |

**Native Windows was NOT run here.** Not verified locally: `cmd.exe` batch
semantics at runtime, the `py.vbs` stubs, `Get-Acl`/`Set-Acl` behaviour, and
the assembly helper's real execution (it downloads sing-box from GitHub).
Those are exactly what the new `windows-smoke` PR job proves on every PR.

## 4. What must pass before leaving Draft

Check **`windows-smoke / assemble + clean-install smoke`** on the PR:

1. helper assembles `proxy-router-<sha>-windows-amd64.zip` (engine checksum
   step runs; windows asset has no recorded digest in `sing-box-release.json`,
   so it warns and skips — identical to release behaviour today);
2. install into throwaway `LOCALAPPDATA` exits 0;
3. explicit DACLs protected (root/providers/`router.json`), generated files
   inherited+unprotected;
4. `--help`, `status --json` JSON contract, read-only checks;
5. all three exit-propagation runs report **2**, with both branch markers.

Issue **#67 stays open**: this smoke never starts the engine, so TUN mode
(wintun/hardware), runtime ACLs on engine-written state, and hardware limits
remain unproven — they are not fixable in CI on hosted runners.

## 5. Deliberate non-actions

* No `workflow_dispatch` of `release`, no publish, no push, no `gh` usage.
* `release.yml` publish path byte-identical apart from the build job calling
  the shared assembly helper.
* No paths filter on `windows-smoke.yml`: a filtered list would be a second
  manifest to keep in sync — the exact drift the helper exists to remove.
* Dashboard/live work untouched.

"""Static Windows install contracts that run on every CI host."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / ".github/scripts/windows-release-smoke.ps1"
AST_CONTRACT = ROOT / "tests/windows_ast_contract.ps1"
ASSEMBLY_HELPER = ".github/scripts/assemble-release-bundle.sh"


def test_powershell_installer_handles_release_layout_and_native_launchers():
    script = (ROOT / "install.ps1").read_text(encoding="utf-8")

    assert "Test-Path -LiteralPath $SourceDirectory -PathType Container" in script
    assert "proxy-router.cmd" in script
    assert "proxy-router.ps1" in script
    assert "proxy-router-keepalive.ps1" in script
    # The launchers only trust the py launcher after proving it can run Python 3.
    assert 'py -3 -c "import sys"' in script
    assert "Task Scheduler" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "examples/keepalive.sh" not in script


def test_windows_installer_checks_wintun_and_hardens_private_state():
    script = (ROOT / "install.ps1").read_text(encoding="utf-8")

    assert "$Wintun = Join-Path $Bin 'wintun.dll'" in script
    assert "wintun.dll is not bundled" in script
    assert "Set-PrivateAcl" in script
    assert "S-1-5-18" in script  # SYSTEM
    assert "S-1-5-32-544" in script  # Administrators
    assert "sing-box.json.last-good" in script


def test_router_import_and_uid_checks_are_windows_safe():
    source = (ROOT / "router.py").read_text(encoding="utf-8")

    assert "except ImportError:  # Windows has no POSIX account database module." in source
    assert "def _effective_uid()" in source
    assert "os.geteuid()" not in source
    assert "the privileged macOS helper is unavailable on Windows" in source


def test_router_helper_status_probe_stops_before_posix_uid_on_windows():
    """`status --json` reaches _sudoers_installed on every platform.

    _helper_command uses os.getuid(), which does not exist on Windows, so the
    probe must return before building that argv or a clean install tracebacks.
    """
    source = (ROOT / "router.py").read_text(encoding="utf-8")
    probe = source.index("def _probe_helper_status")
    guard = source.index('if os.name == "nt":', probe)
    helper_call = source.index("_helper_command(", probe)
    assert guard < helper_call


def _release_workflow() -> dict:
    return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))


def test_release_workflow_runs_a_windows_clean_install_smoke_step():
    """Issue #67 criterion 6: the published zip must be installed and used.

    The unix smoke step already expands and runs its archive; Windows only
    assembled and zipped it, so a broken install.ps1 shipped green.
    """
    build_steps = _release_workflow()["jobs"]["build"]["steps"]
    smoke = next(
        step for step in build_steps
        if step.get("name") == "Clean-install smoke test (windows)"
    )

    assert smoke["if"] == "runner.os == 'Windows'"
    assert smoke["shell"] == "pwsh"
    assert "windows-release-smoke.ps1" in smoke["run"]
    assert "-Archive" in smoke["run"]
    python_step = next(
        step for step in build_steps
        if step.get("name") == "Set up Python for the Windows smoke test"
    )
    assert python_step["if"] == "runner.os == 'Windows'"
    assert python_step["uses"].startswith("actions/setup-python@")


def test_windows_smoke_installs_with_bundle_script_and_uses_real_launchers():
    script = SMOKE.read_text(encoding="utf-8")

    # The installer comes from the extracted bundle, into a throwaway root.
    assert "install.ps1" in script
    assert "LOCALAPPDATA" in script
    assert "-SetPath" not in script, "smoke must not touch the user PATH"
    assert "Get-Acl" in script
    assert "AreAccessRulesProtected" in script
    assert "sing-box.json" in script
    assert "providers" in script

    # Installed launchers, invoked from a fresh shell, produce real output.
    assert "proxy-router.cmd" in script
    assert "proxy-router.ps1" in script
    assert "'--help'" in script
    assert "'status', '--json'" in script
    assert "ConvertFrom-Json" in script
    assert 'system_proxy.status -eq \'skipped\'' in script

    # Read-only with respect to engine, TUN, and system proxy state.
    for forbidden in ("vpn on", "vpn off", "system_proxy_on", "networksetup"):
        assert forbidden not in script, f"smoke must not run {forbidden!r}"


def test_readme_windows_keepalive_guidance_is_not_contradictory():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Linux/Windows: run `examples/keepalive.sh`" not in readme
    assert "Windows: use the native `bin\\proxy-router-keepalive.ps1` supervisor" in readme
    assert "Linux: run `examples/keepalive.sh`" in readme


def test_cmd_launcher_propagates_runtime_exit_codes():
    """`exit /b %ERRORLEVEL%` inside a parenthesised block is parsed, not run.

    cmd expands %ERRORLEVEL% when it reads a `( ... )` block, so the generated
    launcher returned whatever the code was before the block -- usually 0 --
    and every router.py failure shipped green.
    """
    script = (ROOT / "install.ps1").read_text(encoding="utf-8")
    smoke = SMOKE.read_text(encoding="utf-8")

    assert "exit /b %ERRORLEVEL%" not in script
    assert "exit /b %ERRORLEVEL%" not in smoke
    # Bare `exit /b` (no argument) preserves the current code at run time.
    assert script.count("exit /b") >= 2
    assert 'exit /b\n' in script or 'exit /b\r\n' in script


def test_windows_smoke_probes_nonzero_exit_propagation_on_both_branches():
    """Meaningful propagation proof = real cmd.exe on Windows CI, not statics.

    The smoke runs the installed launcher with an unknown flag (argparse exit
    2) three ways: naturally, through a py stub that passes the launcher's
    probe (the parenthesised branch), and through a stub that fails it (the
    python fallback branch). Each must hand exit 2 back to the caller.
    """
    smoke = SMOKE.read_text(encoding="utf-8")

    assert "'--no-such-flag'" in smoke
    assert "wscript.exe" in smoke, "branch forcing needs a wscript-hosted py stub"
    assert "py.vbs" in smoke
    assert "exit propagation ok" in smoke
    # The stub must prove it ran: a branch can only pass if cmd really
    # resolved `py` through PATHEXT to the stub (marker written on invocation).
    assert "invoked.marker" in smoke
    # A .cmd stub would chain (control never returns to the launcher); the
    # stub must be a non-batch PATHEXT entry.
    assert "py.cmd" not in smoke


def _find_pwsh():
    """pwsh for the AST contract: $PWSH, PATH, or a downloaded local build.

    Candidates are probed (some downloaded builds refuse to start without
    their pinned .NET runtime), first working one wins.
    """
    candidates = []
    if from_env := os.environ.get("PWSH"):
        candidates.append(from_env)
    if on_path := shutil.which("pwsh"):
        candidates.append(on_path)
    candidates.extend(sorted(str(path) for path in Path("/tmp").glob("pwsh*/pwsh")))
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if not (Path(candidate).is_file() and os.access(candidate, os.X_OK)):
            continue
        try:
            probe = subprocess.run(
                [candidate, "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


PWSH = _find_pwsh()


@pytest.mark.skipif(PWSH is None, reason="no pwsh available (set PWSH to a local build)")
def test_powershell_scripts_satisfy_ast_contract():
    """Parse install.ps1 and the smoke script with the real PowerShell AST.

    String asserts cannot see which text lives inside the embedded cmd
    launcher here-string; the AST contract checks the launcher's exit lines and
    the DACL branch structure directly. Needs a real pwsh (CI images ship one;
    `PWSH=/path/to/pwsh` selects a local build).
    """
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(AST_CONTRACT), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"AST contract failed:\n{result.stdout}\n{result.stderr}"
    )


def _workflow_text(name: str) -> str:
    return (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")


def test_pull_request_windows_smoke_workflow_cannot_publish():
    """The PR Windows job is structurally incapable of writing a release.

    release.yml (tags + workflow_dispatch) publishes on dispatch, so it must
    never learn a pull_request trigger; the PR job lives in its own workflow
    with read-only contents permission.
    """
    text = _workflow_text("windows-smoke.yml")
    workflow = yaml.safe_load(text)

    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request"}
    assert workflow["permissions"] == {"contents": "read"}
    # Checked on the parsed trigger, not on prose: no dispatch, no tags, and
    # nothing in the file can write (publish) anything.
    assert "workflow_dispatch" not in triggers
    assert "push" not in triggers
    for forbidden in (
        "contents: write",
        "action-gh-release",
        "upload-artifact",
        "git push",
        "set-output",
    ):
        assert forbidden not in text, f"PR smoke workflow must not contain {forbidden!r}"

    assert set(workflow["jobs"]) == {"windows-installer-smoke"}
    job = workflow["jobs"]["windows-installer-smoke"]
    assert job["runs-on"] == "windows-latest"
    steps = job["steps"]
    assemble = next(step for step in steps if step.get("name", "").startswith("Assemble"))
    assert ASSEMBLY_HELPER in assemble["run"]
    assert "windows-amd64" in assemble["run"]
    smoke = next(
        step for step in steps
        if step.get("name", "").startswith("Clean-install smoke")
    )
    assert smoke["shell"] == "pwsh"
    assert "windows-release-smoke.ps1" in smoke["run"]
    assert "-Archive" in smoke["run"]


def test_release_and_pr_windows_smoke_share_one_bundle_assembly():
    """One manifest, two workflows: no drift between shipped and smoked bytes."""
    release = _workflow_text("release.yml")
    pr_smoke = _workflow_text("windows-smoke.yml")
    release_workflow = yaml.safe_load(release)

    assert ASSEMBLY_HELPER in release
    assert ASSEMBLY_HELPER in pr_smoke
    # Release publishing stays tag/dispatch only -- pull requests cannot reach
    # the publish job through release.yml at all.
    release_triggers = release_workflow.get("on", release_workflow.get(True))
    assert "pull_request" not in release_triggers
    assert set(release_triggers) == {"push", "workflow_dispatch"}
    assert "publish" in release_workflow["jobs"]


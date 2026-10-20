"""Static Windows install contracts that run on every CI host."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / ".github/scripts/windows-release-smoke.ps1"


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


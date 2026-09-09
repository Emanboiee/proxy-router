"""Static Windows install contracts that run on every CI host."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_powershell_installer_handles_release_layout_and_native_launchers():
    script = (ROOT / "install.ps1").read_text(encoding="utf-8")

    assert "Test-Path -LiteralPath $SourceDirectory -PathType Container" in script
    assert "proxy-router.cmd" in script
    assert "proxy-router.ps1" in script
    assert "proxy-router-keepalive.ps1" in script
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

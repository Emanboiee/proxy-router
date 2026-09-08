"""Docs-vs-CLI reconciliation tests for issue #65.

Pins the contract between the shipped CLI surface (router.py), the
installers' post-install guidance, and the documentation, so the docs
cannot silently drift again:

- top-level help lists every command, including `doctor`;
- nested `setup|monitor|watcher --help` documents real actions/flags
  instead of opaque REMAINDER catch-alls;
- README mentions every top-level command;
- install.sh / install.ps1 never tell users to run `init` after the
  installer already created router.json;
- ROADMAP carries no landed work as a future item.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _top_level_help_text() -> str:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "router.py"), "--help"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    return proc.stdout


def test_top_level_help_lists_every_command():
    text = _top_level_help_text()
    for cmd in ("ensure", "start", "stop", "status", "doctor", "reload",
                "autodetect", "routes", "up", "down", "routing", "egress", "vpn",
                "setup", "monitor", "watcher", "add", "remove", "rotate",
                "response-event", "with-proxy", "failover", "network-status",
                "network-disconnect", "network-reconnect", "provider-count",
                "profile", "elevate"):
        assert cmd in text.split("positional arguments:")[-1], (
            f"top-level help is missing `{cmd}`"
        )


def test_doctor_documented_as_read_only_in_help():
    text = _top_level_help_text()
    m = re.search(r"doctor\s+(.*)", text)
    assert m, "doctor missing from top-level help"
    assert "read-only" in m.group(1)


def _nested_help_via_subprocess(cmd: str) -> str:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "router.py"), cmd, "--help"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_nested_setup_help_documents_real_flags():
    text = _nested_help_via_subprocess("setup")
    for flag in ("--guide", "--check", "--import-proton", "--import-warp",
                 "--preset-list", "--preset-add", "--bridge-install"):
        assert flag in text, f"setup --help is missing {flag}"
    assert "setup_args" not in text


def test_nested_monitor_help_documents_real_actions():
    text = _nested_help_via_subprocess("monitor")
    for action in ("check", "on", "off", "status", "logs"):
        assert action in text, f"monitor --help is missing `{action}`"
    assert "monitor_args" not in text
    for flag in ("--interval", "--lines"):
        assert flag in text, f"monitor --help is missing {flag}"


def test_nested_watcher_help_documents_real_actions():
    text = _nested_help_via_subprocess("watcher")
    for action in ("status", "on", "off", "logs"):
        assert action in text, f"watcher --help is missing `{action}`"
    assert "watcher_args" not in text


def test_delegated_invalid_choice_rejected_at_router_level(tmp_path, monkeypatch):
    """`monitor bogus` must fail at the router parser, not inside monitor.py."""
    sys.path.insert(0, str(ROOT))
    from tests.test_router_regressions import load_router

    router = load_router(tmp_path)
    monkeypatch.setattr(router, "_needs_elevation", lambda args: False)
    monkeypatch.setattr(sys, "argv", ["router.py", "monitor", "bogus"])
    with pytest.raises(SystemExit) as excinfo:
        router.main()
    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Docs reconciliation: README must mention every shipped command.
# ---------------------------------------------------------------------------

def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("cmd", [
    "ensure", "start", "stop", "status", "doctor", "reload", "autodetect", "routes",
    "routing", "egress", "vpn", "setup", "monitor", "watcher", "add",
    "remove", "rotate", "response-event", "with-proxy", "failover",
    "provider-count", "profile", "elevate", "network-check", "network-status",
    "network-disconnect", "network-reconnect",
])
def test_readme_mentions_every_top_level_command(cmd):
    assert re.search(rf"(?<![\w-]){re.escape(cmd)}(?![\w-])", _readme()), (
        f"README.md does not document the `{cmd}` command"
    )


def test_readme_no_longer_claims_stdlib_only():
    readme = _readme()
    assert "stdlib only — no pip install" not in readme
    assert "stdlib only" not in readme.lower().replace(
        "router.py                    engine + cli (single file, stdlib only)", "")
    # The tray section must state the GUI dependency explicitly.
    assert "pystray" in readme and "pillow" in readme.lower()


def test_readme_has_tray_section():
    readme = _readme()
    assert re.search(r"^## .*[Tt]ray", readme, re.MULTILINE), \
        "README.md has no tray section"


def test_readme_init_not_listed_as_read_only():
    readme = _readme()
    # init writes router.json; it must not appear among read-only commands.
    readonly_m = re.search(r"read-only commands \(([^)]*)\)", readme)
    if readonly_m:
        listed = readonly_m.group(1)
        assert "init" not in re.split(r"[,\s]+", listed)


def test_readme_canonical_fallback_key_is_plural():
    readme = _readme()
    # Canonical key appears...
    assert '"fallback_providers"' in readme
    # ...and the singular form only ever appears as a labelled compat alias.
    for line in readme.splitlines():
        if '"fallback_provider"' in line and '"fallback_providers"' not in line:
            lowered = line.lower()
            assert "compat" in lowered or "alias" in lowered or "legacy" in lowered, (
                f"singular fallback_provider documented without compat note: {line!r}"
            )


def test_readme_presets_are_generic_template_plus_named_presets():
    readme = _readme()
    for name in ("opencode", "roblox", "school-warp"):
        assert name in readme, f"README preset story missing built-in preset `{name}`"
    assert "primary-vpn" in readme, \
        "shipped generic template providers undocumented"


# ---------------------------------------------------------------------------
# Installer banners must match the installer's own behavior: it already
# created router.json from the example, so post-install steps must NOT be
# `init`.
# ---------------------------------------------------------------------------

def _installer(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_install_sh_banner_does_not_suggest_init():
    script = _installer("install.sh")
    banner_start = script.index("proxy-router installed to:")
    banner = script[banner_start:]
    assert "proxy-router init" not in banner
    assert "proxy-router setup --check" in banner
    assert "proxy-router ensure" in banner


def test_install_ps1_banner_does_not_suggest_init():
    script = _installer("install.ps1")
    banner_start = script.index("proxy-router installed to")
    banner = script[banner_start:]
    assert "init" not in banner
    assert "ensure" in banner


# ---------------------------------------------------------------------------
# ROADMAP hygiene: landed work must not linger under future items.
# ---------------------------------------------------------------------------

def test_roadmap_has_no_landed_drift_watchdog_item():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    assert "drift watchdog" not in roadmap.lower(), \
        "_config_drifted ensure-rebuild landed (#82/#83); remove the future item"


def test_roadmap_has_no_landed_route_watcher_redesign_item():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    assert "route_watcher config-driven redesign" not in roadmap, \
        "critical_domains reads router.json on main; remove the future item"

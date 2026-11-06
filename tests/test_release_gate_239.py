"""#239: the Unix release gate must fail when bundled assets are broken.

Mirrors release.yml's clean-install smoke (status payload, routes, and the
non-empty asset assertions) against a real install, injecting one broken
asset at a time. A correct archive passes; each injection fails.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _stage(tmp_path: Path) -> Path:
    dist = tmp_path / "bundle"
    dist.mkdir(parents=True)
    install_text = (REPO / "install.sh").read_text()
    names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*\.(?:py|json|md|mjs|sh|ps1|txt)",
                           install_text))
    for name in sorted(names):
        src = REPO / name
        if src.is_file():
            shutil.copy2(src, dist / name)
    for extra in ("README.md", "LICENSE", "router.example.json", "install.sh",
                  "VERSION", "sing-box-release.json", "sing-box-windows.json",
                  "setup_tui.py", "monitor.py", "route_watcher.py", "proxy_tray.py",
                  "privileged_helper.py", "privileged_installer.py"):
        src = REPO / extra
        if src.is_file():
            shutil.copy2(src, dist / extra)
    shutil.copytree(REPO / "guides", dist / "guides")
    shutil.copytree(REPO / "rulesets", dist / "rulesets")
    shutil.copytree(REPO / "examples", dist / "examples")
    (dist / "bin").mkdir(exist_ok=True)
    return dist


def _install(bundle: Path, prefix: Path, tag: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(bundle / "install.sh")],
        env=dict(os.environ, PROXY_ROUTER_RELEASE=tag,
                 PROXY_ROUTER_DIR=str(prefix), HOME=str(prefix)),
        capture_output=True, text=True, timeout=120,
    )


def _smoke(prefix: Path) -> tuple[int, str, str]:
    """Mirror release.yml's gate: status payload + routes + non-empty assets."""
    env = {k: v for k, v in os.environ.items() if k != "PROXY_ROUTER_ROOT"}
    env.update({"HOME": str(prefix)})
    cli = prefix / "current" / "router.py"
    status = subprocess.run([sys.executable, str(cli), "status", "--json"],
                            env=env, capture_output=True, text=True, timeout=60)
    check = subprocess.run(
        [sys.executable, "-c",
         'import json,sys,os; d=json.load(sys.stdin); '
         'c=json.load(open(os.path.join(os.environ["PROXY_ROUTER_DIR"],"router.json"))); '
         'assert d.get("up") is False, d; '
         'assert d.get("port")==c.get("port",2080), d; '
         'assert d.get("mode") in ("proxy","tun"), d; '
         'assert d.get("error") is None, d; '
         'assert "down (unusable config" not in str(d), d'],
        input=status.stdout, env={**env, "PROXY_ROUTER_DIR": str(prefix)},
        capture_output=True, text=True, timeout=60)
    routes = subprocess.run([sys.executable, str(cli), "routes"],
                            env=env, capture_output=True, text=True, timeout=60)
    assets = subprocess.run(
        ["bash", "-c",
         'set -e; p="$1"; '
         '[ -f "$p/router.json" ]; '
         '[ -d "$p/rulesets" ] && [ -n "$(ls -A "$p/rulesets")" ]; '
         '[ -d "$p/guides" ] && [ -n "$(ls -A "$p/guides")" ]; '
         '[ -d "$p/current/guides" ] && [ -n "$(ls -A "$p/current/guides")" ]',
         "gate", str(prefix)],
        capture_output=True, text=True, timeout=60)
    failures = []
    if check.returncode != 0: failures.append(check.stderr)
    if routes.returncode != 0: failures.append(routes.stderr)
    if assets.returncode != 0: failures.append("bundled asset assertion failed: " + assets.stderr)
    return ((0 if not failures else 1), "\n".join(failures), status.stdout)


def test_correct_bundle_passes_the_gate(tmp_path):
    prefix = tmp_path / "prefix"
    assert _install(_stage(tmp_path / "s"), prefix, "v1").returncode == 0
    rc, err, _out = _smoke(prefix)
    assert rc == 0, err


def test_missing_ruleset_fails_the_gate(tmp_path):
    bundle = _stage(tmp_path / "s")
    shutil.rmtree(bundle / "rulesets")
    prefix = tmp_path / "prefix"
    assert _install(bundle, prefix, "v1").returncode == 0
    rc, err, _out = _smoke(prefix)
    assert rc == 1, "a missing rulesets/ tree must fail the gate"


def test_empty_ruleset_fails_the_gate(tmp_path):
    bundle = _stage(tmp_path / "s")
    for item in (bundle / "rulesets").iterdir():
        item.unlink()
    prefix = tmp_path / "prefix"
    assert _install(bundle, prefix, "v1").returncode == 0
    rc, err, _out = _smoke(prefix)
    assert rc == 1, "an empty rulesets/ tree must be detectable"


def test_missing_guides_fails_the_gate(tmp_path):
    bundle = _stage(tmp_path / "s")
    shutil.rmtree(bundle / "guides")
    prefix = tmp_path / "prefix"
    assert _install(bundle, prefix, "v1").returncode == 0
    rc, err, _out = _smoke(prefix)
    assert rc == 1, "a missing guides/ tree must fail the gate"


def test_corrupt_router_json_fails_the_gate(tmp_path):
    prefix = tmp_path / "prefix"
    assert _install(_stage(tmp_path / "s"), prefix, "v1").returncode == 0
    (prefix / "router.json").write_text("{not json")
    rc, err, out = _smoke(prefix)
    assert rc == 1, "an unusable config must fail the gate (the old smoke passed on this)"
    assert "unusable config" in out or err

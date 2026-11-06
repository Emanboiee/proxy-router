"""End-to-end install.sh acceptance for #231 (upgrade/rollback/idempotent)
and #230 (installed ROOT resolves to the prefix)."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _stage(tmp_path: Path, tag: str) -> Path:
    """Assemble a minimal but real release dir the way the bundle does."""
    dist = tmp_path / "bundle"
    dist.mkdir(parents=True)
    # Mirror the real runtime manifest from install.sh so the test exercises
    # the same layout the release bundle ships (assembly copies guides/ and
    # rulesets/ from the repo; the installer needs them at the stage root).
    install_text = (REPO / "install.sh").read_text()
    for line in install_text.splitlines():
        line = line.strip()
        if not line.startswith(("router.py ", "for runtime_file in", "for f in router.py")):
            continue
    import re
    names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*\.(?:py|json|md|mjs|sh|ps1|txt)",
                           install_text))
    for name in sorted(names):
        src = REPO / name
        if src.is_file():
            shutil.copy2(src, dist / name)
    for extra in ("README.md", "LICENSE", ".gitignore", "router.example.json",
                  "install.sh", "VERSION", "sing-box-release.json",
                  "sing-box-windows.json", "setup_tui.py", "monitor.py",
                  "route_watcher.py", "proxy_tray.py", "privileged_helper.py",
                  "privileged_installer.py", "pyproject.toml"):
        src = REPO / extra
        if src.is_file():
            shutil.copy2(src, dist / extra)
    (dist / "guides").mkdir(parents=True, exist_ok=True)
    (dist / "guides" / "g.md").write_text("guide")
    (dist / "rulesets").mkdir(parents=True, exist_ok=True)
    (dist / "rulesets" / "r.json").write_text('{"rules": []}')
    # examples/ is copied as a tree by assembly; install.sh requires some.
    if (REPO / "examples").is_dir():
        shutil.copytree(REPO / "examples", dist / "examples")
    (dist / "bin").mkdir(parents=True, exist_ok=True)  # engine binary not needed for CLI tests
    (dist / "VERSION").write_text(tag + "\n")
    return dist


def _install(bundle: Path, prefix: Path, tag: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(bundle / "install.sh")],
        env=dict(os.environ,
                 PROXY_ROUTER_RELEASE=tag,
                 PROXY_ROUTER_DIR=str(prefix),
                 HOME=str(prefix)),
        capture_output=True, text=True, timeout=120,
    )


@pytest.mark.skipif(sys.platform == "win32", reason="bash installer")
def test_231_upgrade_rollback_and_idempotent_reinstall(tmp_path):
    prefix = tmp_path / "prefix"
    v1 = _stage(tmp_path / "s1", "v1")
    v2 = _stage(tmp_path / "s2", "v2")

    first = _install(v1, prefix, "v1")
    assert first.returncode == 0, first.stderr
    assert (prefix / "releases" / "v1").is_dir()
    assert (prefix / "current").is_symlink()

    second = _install(v2, prefix, "v2")
    assert second.returncode == 0, second.stderr
    assert (prefix / "releases" / "v1").is_dir() and (prefix / "releases" / "v2").is_dir()
    assert os.readlink(prefix / "current").endswith("v2")
    # Operator config survives the upgrade untouched.
    assert (prefix / "router.json").is_file()

    again = _install(v2, prefix, "v2")
    assert again.returncode == 0, again.stderr  # same-tag reinstall is a no-op
    assert "already exists" not in again.stderr

    # Rollback runs the installer with --rollback; the bundle copy is the
    # same script the published archive ships.
    rb = subprocess.run(
        ["bash", str(v2 / "install.sh"), "--rollback"],
        env=dict(os.environ, PROXY_ROUTER_DIR=str(prefix), HOME=str(prefix)),
        capture_output=True, text=True, timeout=120,
    )
    assert rb.returncode == 0, rb.stderr
    assert os.readlink(prefix / "current").endswith("v1")


@pytest.mark.skipif(sys.platform == "win32", reason="bash installer")
def test_230_installed_cli_resolves_prefix_and_config(tmp_path):
    prefix = tmp_path / "prefix"
    bundle = _stage(tmp_path / "s1", "v1")
    assert _install(bundle, prefix, "v1").returncode == 0
    cfg = json.loads((prefix / "router.json").read_text())
    cfg["port"] = 2181
    (prefix / "router.json").write_text(json.dumps(cfg))

    root = prefix  # NO PROXY_ROUTER_ROOT: prove ROOT resolution works
    env = dict(os.environ)
    env.pop("PROXY_ROUTER_ROOT", None)
    env.update({"HOME": str(prefix)})
    cli = prefix / "current" / "router.py"
    status = subprocess.run(
        [sys.executable, str(cli), "status", "--json"],
        env=env, capture_output=True, text=True, timeout=60, cwd=str(prefix),
    )
    payload = json.loads(status.stdout)
    assert payload.get("up") is False  # no engine started, by design
    assert "unusable config" not in status.stdout
    assert payload.get("port") == 2181 or payload.get("port") is None
    # Guides/rulesets resolve from the installed tree.
    assert (prefix / "guides" / "g.md").is_file()
    assert (prefix / "rulesets" / "r.json").is_file()

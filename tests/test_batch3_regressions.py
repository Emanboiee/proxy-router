"""Focused regressions for the release/install audit batch (#230, #232, #238)."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[1]


def _runtime_root_fn():
    import config_schema
    return config_schema.runtime_root


def test_installed_layout_resolves_prefix_root(tmp_path):
    """#230: current -> releases/<tag> must not make ROOT the release dir."""
    prefix = tmp_path / "prefix"
    release = prefix / "releases" / "v1.2.3"
    release.mkdir(parents=True)
    (prefix / "router.json").write_text("{}")
    (prefix / "current").symlink_to("releases/v1.2.3", target_is_directory=True)
    resolved = (prefix / "current" / "router.py").resolve().parent
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("PROXY_ROUTER_ROOT", None)
        assert _runtime_root_fn()(resolved).resolve() == prefix.resolve()


def test_dev_checkout_keeps_source_root(tmp_path):
    src = tmp_path / "checkout"
    src.mkdir()
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("PROXY_ROUTER_ROOT", None)
        assert _runtime_root_fn()(src) == src


def test_env_override_wins(tmp_path):
    override = tmp_path / "explicit"
    override.mkdir()
    with mock.patch.dict(os.environ, {"PROXY_ROUTER_ROOT": str(override)}):
        assert _runtime_root_fn()(tmp_path) == override.resolve()


def test_manifest_has_all_four_target_digests():
    """#232: every published asset must have a pinned sha256."""
    doc = json.loads((REPO / "sing-box-release.json").read_text())
    assert doc["architectures"]["arm64"]["sha256"]
    assert doc["architectures"]["x86_64"]["sha256"]
    assert doc["platforms"]["linux"]["architectures"]["x86_64"]["sha256"]
    assert json.loads((REPO / "sing-box-windows.json").read_text())["sha256"]


def test_assembly_fails_closed_and_rejects_version_override():
    """#232: no 'skipping verification' path, and dispatch version is gated."""
    text = (REPO / ".github/scripts/assemble-release-bundle.sh").read_text()
    assert "skipping verification" not in text
    assert "verification failed for" in text
    assert 'doc["release"]["version"]' in text
    assert "linux-amd64-glibc" in text and "windows-amd64" in text
    assert "sing-box-windows.json" in text


def test_release_smoke_asserts_installed_behavior():
    """#239: valid JSON alone no longer passes the Unix clean-install gate."""
    text = (REPO / ".github/workflows/release.yml").read_text()
    # A fresh install has up=false -> status --json exits 1 by design. The
    # smoke must tolerate that while still asserting the payload.
    assert "status --json 2>/dev/null || true" in text
    assert "down (unusable config" in text
    assert 'd.get("port")' in text
    assert "routes --json" not in text
    assert "routes >/dev/null" in text


def test_keepalive_reads_config_in_one_call():
    """#238: startup must not spawn one interpreter per key."""
    text = (REPO / "examples/keepalive.sh").read_text()
    assert "load_all_settings || true" in text
    assert "_KEEPALIVE_SETTINGS_MTIME" in text
    # The cache must be populated in the PARENT shell, not inside cached_setting
    # (which runs in a $(...) subshell, losing the assignments).
    assert "load_all_settings() || { printf" not in text
    assert text.count("load_all_settings || true") == 2  # startup + tick
    assert 'cached_setting "$@"' in text
    assert text.count('(data.get("keepalive")') == 0


def test_keepalive_cache_persists_across_command_substitutions(tmp_path):
    """#238: one Python spawn for many reads, not one per $(...) subshell."""
    import textwrap
    script = (REPO / "examples/keepalive.sh").read_text()
    start = script.index("# #238: read every keepalive")
    end = script.index('case "$ENABLED" in')
    (tmp_path / "fns.sh").write_text(script[start:end])
    (tmp_path / "router.json").write_text('{"keepalive":{"interval":7}}')
    wrapper = tmp_path / "pywrap"
    wrapper.write_text('#!/bin/bash\necho x >> "$COUNTER"\nexec python3 "$@"\n')
    wrapper.chmod(0o755)
    counter = tmp_path / "count"
    probe = textwrap.dedent('''
        source "$1/fns.sh"
        for k in interval max_backoff probe_every dead_strikes storm_window sweep_every; do
          config_setting "$k" 15 >/dev/null
        done
        printf '%s' "$(config_setting interval 15)"
    ''')
    env = dict(os.environ, ROOT=str(tmp_path), PROXY_ROUTER_PYTHON=str(wrapper),
               COUNTER=str(counter))
    out = subprocess.run(["bash", "-c", probe, "--", str(tmp_path)],
                         capture_output=True, text=True, env=env, check=True)
    assert out.stdout.strip() == "7"
    assert len(counter.read_text().splitlines()) == 1, "one interpreter expected"

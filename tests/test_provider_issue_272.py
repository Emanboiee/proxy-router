"""Behavioral regression tests for issue #272.

The provider CLI is a user-facing control surface, and ``upstream_required``
must keep a dead local SOCKS5 lane out of the generated routing set.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _help(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "router.py"), *args, "--help"],
        capture_output=True, text=True,
    )


def test_provider_help_lists_all_actions():
    result = _help(["provider"])
    assert result.returncode == 0, result.stderr
    for action in ("activate", "deactivate", "upstream"):
        assert action in result.stdout


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _router(tmp_path):
    from tests.test_router_regressions import load_router

    return load_router(tmp_path)


@pytest.mark.enable_socket
def test_upstream_required_excludes_unreachable_socks5(tmp_path):
    router = _router(tmp_path)
    port = _unused_loopback_port()
    router._providers = {
        "p": {
            "socks5": {"host": "127.0.0.1", "port": port},
            "upstream_required": True,
        }
    }

    assert router.active_proxy_providers() == {}


@pytest.mark.enable_socket
def test_dead_upstream_without_requirement_stays_optional(tmp_path):
    router = _router(tmp_path)
    port = _unused_loopback_port()
    router._providers = {
        "p": {"socks5": {"host": "127.0.0.1", "port": port}}
    }

    assert router.active_proxy_providers() == {"p": ("127.0.0.1", port)}

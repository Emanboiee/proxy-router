"""#285: human `status --fast` must thread `--fast` into the report.

`status --json --fast` already skips the sudo/launchd elevation probes, but the
human-readable status path ignored `--fast` and still paid that cost. Pin the
wiring so a poller using the plain CLI gets the same fast path as the JSON one.
"""
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_router(tmp_path):
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("proxy_router_285", ROOT / "router.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    module.CONFIG_FILE = tmp_path / "router.json"
    module.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    module.LAST_GOOD_FILE = tmp_path / "sing-box.json.last-good"
    module.PID_FILE = tmp_path / "sing-box.pid"
    module.LOG_FILE = tmp_path / "sing-box.log"
    module.LOCK_FILE = tmp_path / "state" / "engine.lock"
    module.MODE_FILE = tmp_path / "state" / "mode"
    module.MANUAL_OFF_FILE = tmp_path / "state" / "manual-off"
    module.SYSTEM_PROXY_STATE_FILE = tmp_path / "state" / "system-proxy.json"
    module.NETWORK_DIAGNOSTIC_FILE = tmp_path / "state" / "network-diagnostic.json"
    return module


def _drive(router, monkeypatch, argv):
    captured = {}

    def fake_report(*, fast=False):
        captured["fast"] = fast
        return 0, "status ok"

    monkeypatch.setattr(router, "_status_report", fake_report)
    monkeypatch.setattr(router, "resolve_sing_box", lambda: "/usr/bin/sing-box")
    monkeypatch.setattr(router, "_legacy_launch_agents", lambda: [])
    monkeypatch.setattr(router, "load_config", lambda: 0)
    monkeypatch.setattr(router.sys, "argv", argv)
    rc = router.main()
    return rc, captured


def test_human_status_fast_threads_fast_flag(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    rc, captured = _drive(router, monkeypatch, ["router.py", "status", "--fast"])
    assert rc == 0
    assert captured["fast"] is True, "human `status --fast` ignored --fast"


def test_human_status_without_fast_keeps_full_path(tmp_path, monkeypatch):
    router = load_router(tmp_path)
    rc, captured = _drive(router, monkeypatch, ["router.py", "status"])
    assert rc == 0
    assert captured["fast"] is False, "plain `status` must keep the full check"


def test_fast_tun_fails_closed_on_unverified_running_mode(tmp_path, monkeypatch):
    """#340 P1: fast status must never claim up(tun) without the privileged
    check that proves the RUNNING engine is actually tun mode. A proxy-mode
    engine left running after a failed tun switch has mode file + generated
    config flipped to tun, so local signals alone cannot be trusted.
    """
    router = load_router(tmp_path)
    monkeypatch.setattr(router.sys, "platform", "darwin")
    monkeypatch.setattr(router, "_effective_uid", lambda: 501)
    monkeypatch.setattr(router, "_pid_matches", lambda pid: True)
    monkeypatch.setattr(router.os, "kill", lambda pid, sig: None)

    probes = []

    def fake_probe():
        probes.append(1)
        # Helper reports the RUNNING engine is proxy mode (failed tun switch).
        return {"installed": True, "running": True, "mode": "proxy"}

    monkeypatch.setattr(router, "_probe_helper_status", fake_probe)

    router.MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    router.MODE_FILE.write_text("tun")
    router.PID_FILE.write_text("4242")
    router.SING_BOX_CONFIG.write_text(
        '{"inbounds": [{"type": "tun"}]}')

    rc, line = router._status_report(fast=True)
    assert rc == 1, "fast tun status must fail closed, not report up"
    assert "unverified" in line.lower(), f"expected uncertainty in state line, got {line!r}"
    assert probes == [], "fast status must not probe the privileged helper"

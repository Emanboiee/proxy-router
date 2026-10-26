"""Batch discovery compares effective routing and never reloads per source."""
import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import autodetect_refresh

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def controller(tmp_path):
    desired = {"route": {"rules": []}, "dns": {"rules": []}, "outbounds": [{"private_key": "SECRET"}]}
    saved = tmp_path / "sing-box.json"
    saved.write_text(json.dumps(desired))
    router = SimpleNamespace(
        _autodetect={"enabled": True, "sources": {"a": {}, "b": {}}},
        SING_BOX_CONFIG=saved, MANUAL_OFF_FILE=tmp_path / "manual-off",
        engine_reload=Mock(return_value=0), engine_alive=Mock(return_value=True),
        _automatic_proxy_mode=Mock(return_value=True), fail=Mock(return_value=1),
        build_singbox_config=Mock(side_effect=lambda: (copy.deepcopy(desired), {})))
    calls = []

    def scan(source, *, reload, quiet):
        assert reload is False and quiet is True
        router.engine_reload.assert_not_called()
        calls.append(source)
        desired["route"]["rules"].append({"domain": [source + ".test"], "outbound": "vpn"})
        return 0

    router.autodetect_source = Mock(side_effect=scan)
    return router, desired, calls


def test_two_changed_sources_reload_only_after_the_batch(controller):
    router, _, calls = controller
    assert autodetect_refresh.refresh(router, quiet=True) == 0
    assert calls == ["a", "b"]
    router.engine_reload.assert_called_once_with()


def test_no_change_or_private_outbound_difference_does_not_reload(controller, capsys):
    router, desired, _ = controller
    router.autodetect_source.side_effect = None
    router.autodetect_source.return_value = 0
    desired["outbounds"][0]["private_key"] = "NEW-SECRET"
    assert autodetect_refresh.refresh(router) == 0
    router.engine_reload.assert_not_called()
    output = capsys.readouterr().out
    assert '"changed": false' in output
    assert "SECRET" not in output


def test_unapplied_prior_discovery_is_not_lost_on_next_scan(controller):
    router, desired, _ = controller
    desired["route"]["final"] = "vpn"
    router.autodetect_source.side_effect = None
    router.autodetect_source.return_value = 0
    assert autodetect_refresh.refresh(router, quiet=True) == 0
    router.engine_reload.assert_called_once()


@pytest.mark.parametrize("failure", [1, OSError("disk full")])
def test_partial_scan_still_commits_one_reload_and_reports_failure(controller, failure):
    router, desired, _ = controller

    def scan(source, **kwargs):
        if source == "b":
            if isinstance(failure, Exception):
                raise failure
            return failure
        desired["route"]["final"] = "vpn"
        return 0

    router.autodetect_source.side_effect = scan
    assert autodetect_refresh.refresh(router, quiet=True) == 1
    router.engine_reload.assert_called_once()


@pytest.mark.parametrize("guard", ["manual_off", "stopped", "tun_or_unknown", "no_reload"])
def test_background_scan_never_starts_or_mutates_an_unavailable_engine(controller, guard):
    router, _, _ = controller
    if guard == "manual_off":
        router.MANUAL_OFF_FILE.touch()
    elif guard == "stopped":
        router.engine_alive.return_value = False
    elif guard == "tun_or_unknown":
        router._automatic_proxy_mode.return_value = False
    assert autodetect_refresh.refresh(router, reload=guard != "no_reload", quiet=True) == 0
    router.engine_reload.assert_not_called()


def test_dns_dependency_change_also_reloads_once(controller):
    router, desired, _ = controller
    router.autodetect_source.side_effect = None
    router.autodetect_source.return_value = 0
    desired["dns"]["rules"] = [{"domain": ["api.test"], "server": "remote"}]
    assert autodetect_refresh.refresh(router, quiet=True) == 0
    router.engine_reload.assert_called_once()


def test_failed_reload_is_reported_without_a_second_attempt(controller):
    router, _, _ = controller
    router.engine_reload.return_value = 1
    assert autodetect_refresh.refresh(router, quiet=True) == 1
    router.engine_reload.assert_called_once()


@pytest.mark.parametrize("content", ["[]", "not-json", '{"dns":null}'])
def test_malformed_old_generated_state_does_not_crash_comparison(controller, content):
    router, _, _ = controller
    router.SING_BOX_CONFIG.write_text(content)
    assert autodetect_refresh.refresh(router, quiet=True) == 0
    router.engine_reload.assert_called_once()


def test_empty_or_disabled_sources_do_no_engine_work(controller):
    router, _, _ = controller
    router._autodetect["sources"] = {}
    assert autodetect_refresh.refresh(router, quiet=True) == 0
    router._autodetect["enabled"] = False
    assert autodetect_refresh.refresh(router, quiet=True) == 0
    router.autodetect_source.assert_not_called()
    router.build_singbox_config.assert_not_called()
    router.engine_reload.assert_not_called()


def test_cli_and_keepalive_use_the_batch_entry_point():
    result = subprocess.run([sys.executable, str(ROOT / "router.py"), "autodetect", "--help"],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert "--all" in result.stdout
    script = (ROOT / "examples/keepalive.sh").read_text()
    assert "controller autodetect --all --quiet" in script
    assert 'controller autodetect "$source"' not in script

"""#233: config changes must be one validated transaction."""
import json
import os
from pathlib import Path
from unittest import mock

import pytest
import state

from tests.test_router_regressions import load_router


def _config(tag="NEW"):
    return {"tag": tag, "endpoints": [{"type": "wireguard"}]}


def test_publish_validated_leaves_live_untouched_on_rejection(tmp_path):
    live = tmp_path / "sing-box.json"
    live.write_text("STALE-ON-DISK")
    seen = []

    def reject(path):
        seen.append(Path(path).read_text())
        return False

    assert state.publish_validated(live, json.dumps(_config()), reject) is False
    assert live.read_text() == "STALE-ON-DISK"
    assert seen and "NEW" in seen[0]  # validated the CANDIDATE, not live
    assert not list(tmp_path.glob("*.candidate"))


def test_publish_validated_publishes_only_after_validation(tmp_path):
    live = tmp_path / "sing-box.json"
    live.write_text("OLD")
    order = []

    def accept(path):
        order.append(("validate", live.read_text()))
        return True

    assert state.publish_validated(live, json.dumps(_config()), accept) is True
    assert order == [("validate", "OLD")]
    assert json.loads(live.read_text())["tag"] == "NEW"
    assert not list(tmp_path.glob("*.candidate"))


def test_enospc_does_not_truncate_live_config(tmp_path):
    live = tmp_path / "sing-box.json"
    live.write_text("ORIGINAL")
    with mock.patch.object(state.os, "replace", side_effect=OSError(28, "ENOSPC")):
        with pytest.raises(OSError):
            state.publish_validated(live, json.dumps(_config()), lambda p: True)
    assert live.read_text() == "ORIGINAL"
    assert not list(tmp_path.glob("*.candidate"))


def test_egress_less_config_is_rejected_without_touching_disk(tmp_path):
    r = load_router(tmp_path)
    r.SING_BOX_CONFIG.write_text("STALE")
    r.validate_config = mock.Mock(return_value=True)
    assert r.publish_sing_box({"tag": "EGRESSLESS"}) is False
    assert r.SING_BOX_CONFIG.read_text() == "STALE"


def test_failed_validation_does_not_publish(tmp_path):
    r = load_router(tmp_path)
    r.SING_BOX_CONFIG.write_text("ORIGINAL")
    r.validate_config = mock.Mock(return_value=False)
    assert r.publish_sing_box(_config()) is False
    assert r.SING_BOX_CONFIG.read_text() == "ORIGINAL"


def test_successful_publish_calls_validate_with_candidate_path(tmp_path):
    r = load_router(tmp_path)
    r.SING_BOX_CONFIG.write_text("ORIGINAL")
    paths = []

    def validate(path=None):
        paths.append(Path(path) if path else None)
        return True

    r.validate_config = validate
    assert r.publish_sing_box(_config("FRESH")) is True
    assert json.loads(r.SING_BOX_CONFIG.read_text())["tag"] == "FRESH"
    assert paths and paths[0].name.endswith(".candidate")
    assert not paths[0].exists()  # cleaned up after publish


def test_vpn_on_preflight_failure_leaves_config_untouched(tmp_path, monkeypatch):
    """#233 acceptance: a vpn_on TUN pre-flight failure must leave
    sing-box.json byte-identical to the original proxy config."""
    r = load_router(tmp_path)
    r.SING_BOX_CONFIG.write_text("ORIGINAL-PROXY-CONFIG")
    r.set_mode = lambda mode: None
    r.current_mode = lambda: "proxy"
    r.vpn_note = lambda: None
    r.build_singbox_config = lambda: ({"endpoints": [{"type": "wireguard"}]}, {"proton": Path("p")})
    r.validate_config = lambda path=None: False  # candidate rejected
    monkeypatch.setattr("sys.platform", "linux")
    assert r.vpn_on() != 0
    assert r.SING_BOX_CONFIG.read_text() == "ORIGINAL-PROXY-CONFIG"
    assert not list(tmp_path.glob("*.candidate"))

from __future__ import annotations

import builtins
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_setup_tui():
    name = "setup_tui_under_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "setup_tui.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_line_wizard_can_create_custom_preset(tmp_path):
    """The pipe/line fallback must expose the custom-preset path too.

    The fullscreen TUI already had this flow, but the line wizard only let
    users apply presets; ``setup> s`` gave no way to create one.
    """
    module = load_setup_tui()
    answers = iter(["new", "banana", "proton", "opencode.ai,roblox.com"])
    with patch.object(builtins, "input", side_effect=lambda _prompt: next(answers)):
        rc = module._cmd_preset_prompt(tmp_path)

    assert rc == 0
    preset = json.loads((tmp_path / "presets" / "banana.json").read_text())
    assert preset["routes"] == [{
        "id": "banana",
        "domains": ["opencode.ai", "roblox.com"],
        "provider": "proton",
    }]
    assert preset["routing"] == {
        "mode": "vpn-list",
        "vpn_domains": ["opencode.ai", "roblox.com"],
    }


def _stale_home_root(tmp_path, checked_at, ok=True):
    provider_dir = tmp_path / "providers" / "proton"
    provider_dir.mkdir(parents=True)
    for stem in ("a", "b"):
        (provider_dir / f"{stem}.conf").write_text("profile")
    (tmp_path / "router.json").write_text(json.dumps({
        "providers": {"proton": {"directory": "providers/proton"}},
        "egress": {"ok_window": 86400},
    }))
    if checked_at is not None:
        state_dir = tmp_path / "state" / "egress" / "proton"
        state_dir.mkdir(parents=True)
        for stem in ("a", "b"):
            (state_dir / f"{stem}.json").write_text(json.dumps({
                "checked_at": checked_at, "ok": ok,
            }))
    return tmp_path


def test_stale_probe_data_renders_age_not_zero_healthy(tmp_path):
    """33h-old verdicts must read as stale data, not 'everything is dead'."""
    import time
    module = load_setup_tui()
    root = _stale_home_root(tmp_path, time.time() - 33 * 3600)
    joined = "\n".join(module.render_frame(module.TuiState(root=root)))
    assert "0/2 fresh" in joined
    assert "probed 1d ago" in joined
    assert "[6] to refresh" in joined
    assert "0/2 healthy" not in joined


def test_never_probed_renders_never_probed(tmp_path):
    module = load_setup_tui()
    root = _stale_home_root(tmp_path, None)
    joined = "\n".join(module.render_frame(module.TuiState(root=root)))
    assert "never probed" in joined
    assert "0/2 healthy" not in joined


def test_fresh_probes_keep_healthy_count(tmp_path):
    import time
    module = load_setup_tui()
    root = _stale_home_root(tmp_path, time.time())
    joined = "\n".join(module.render_frame(module.TuiState(root=root)))
    assert "2/2 healthy" in joined
    assert "fresh" not in joined

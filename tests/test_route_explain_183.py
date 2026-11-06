"""#183 item 3: hostname diagnostic attributes rule, provider, leaf, fallback."""
import json
from pathlib import Path
from unittest import mock

import status_snapshot

from tests.test_router_regressions import load_router


def _controller(tmp_path):
    r = load_router(tmp_path)
    conf = tmp_path / "proton.conf"
    conf.write_text("x")
    r._providers = {"warp": {"fallback_providers": ["proton"]}, "proton": {}}
    r._routes = [{"id": "school", "domains": ["discord.com"], "provider": "warp"}]
    r._routing = {"mode": "safe-list", "direct_domains": [], "default_provider": "warp"}
    r._vpn = {}
    # The diagnostic is about rule attribution, not exit health: give warp a
    # usable profile so route_provider()'s availability check passes.
    r._usable_profile = lambda name, preferred=None: conf if name == "warp" else None
    return r


def test_explain_configured_rule(tmp_path, capsys):
    r = _controller(tmp_path)
    r._effective_route_provider = lambda name: name
    rc = status_snapshot.explain_host(
        {k: getattr(r, k) for k in dir(r) if not k.startswith("__")}, "discord.com")
    out = capsys.readouterr().out
    assert rc == 0
    assert "provider 'warp'" in out
    assert "configured rule 'discord.com'" in out
    assert "route 'school'" in out


def test_explain_learned_rule_is_labeled(tmp_path, capsys):
    r = _controller(tmp_path)
    r._effective_route_provider = lambda name: name
    r._autodetect = {"enabled": True}
    r._autodetected_domains_by_route = lambda: {"school": ["cdn.example.net"]}
    namespace = {k: getattr(r, k) for k in dir(r) if not k.startswith("__")}
    rc = status_snapshot.explain_host(namespace, "cdn.example.net")
    out = capsys.readouterr().out
    assert rc == 0
    assert "learned rule 'cdn.example.net'" in out


def test_explain_reports_fallback_leaf(tmp_path, capsys):
    r = _controller(tmp_path)
    proton_conf = tmp_path / "proton.conf"
    r._usable_profile = lambda name, preferred=None: (
        proton_conf if name in ("warp", "proton") else None)
    r._effective_route_provider = lambda name: "proton"  # warp parked on proton
    rc = status_snapshot.explain_host(
        {k: getattr(r, k) for k in dir(r) if not k.startswith("__")}, "discord.com")
    out = capsys.readouterr().out
    assert "leaf proton (fallback applied)" in out


def test_explain_direct_fallback_caveat(tmp_path, capsys):
    r = _controller(tmp_path)
    r._effective_route_provider = lambda name: "direct"
    rc = status_snapshot.explain_host(
        {k: getattr(r, k) for k in dir(r) if not k.startswith("__")}, "discord.com")
    out = capsys.readouterr().out
    assert "leaf direct" in out
    assert "may not reach a locally blocked destination" in out


def test_explain_unmatched_host_uses_default(tmp_path, capsys):
    r = _controller(tmp_path)
    rc = status_snapshot.explain_host(
        {k: getattr(r, k) for k in dir(r) if not k.startswith("__")}, "unrelated.example")
    out = capsys.readouterr().out
    assert "no explicit rule" in out  # routing default, not a route match


def test_explain_direct_when_nothing_available(tmp_path, capsys):
    """No available provider -> direct, with the honest caveat."""
    r = _controller(tmp_path)
    r._usable_profile = lambda name, preferred=None: None
    rc = status_snapshot.explain_host(
        {k: getattr(r, k) for k in dir(r) if not k.startswith("__")}, "discord.com")
    out = capsys.readouterr().out
    assert "direct" in out and "no route matched" in out

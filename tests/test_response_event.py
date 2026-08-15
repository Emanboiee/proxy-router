from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_router(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("router_response_event_test", ROOT / "router.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.ROOT = tmp_path
    module.CONFIG_FILE = tmp_path / "router.json"
    module.LOCK_FILE = tmp_path / "state" / "engine.lock"
    module._providers = {"proton": {}, "cloudflare": {}}
    module._routes = [{"id": "opencode", "domains": ["opencode.ai"], "provider": "proton"}]
    module._routing = {"mode": "vpn-list", "vpn_domains": ["opencode.ai"]}
    return module


def test_response_event_ignores_non_429_and_unrouted_hosts(tmp_path):
    router = load_router(tmp_path)
    calls = []
    router.rotate = lambda *args, **kwargs: calls.append((args, kwargs)) or 0

    assert router.response_event("opencode.ai", 500) == 0
    assert router.response_event("not-opencode.ai", 429) == 1
    assert calls == []


def test_response_event_rotates_once_and_suppresses_duplicate(tmp_path):
    router = load_router(tmp_path)
    calls = []
    router.rotate = lambda *args, **kwargs: calls.append((args, kwargs)) or 0

    assert router.response_event("api.opencode.ai", 429, dedupe_seconds=60) == 0
    assert router.response_event("api.opencode.ai", 429, dedupe_seconds=60) == 0
    assert calls == [(("proton",), {"reason": "429"})]
    marker = json.loads((tmp_path / "state" / "response-events" / "proton.json").read_text())
    assert marker["status"] == 429
    assert marker["host"] == "api.opencode.ai"


def test_response_event_activates_fallback_after_primary_failure(tmp_path):
    router = load_router(tmp_path)
    calls = []
    router.rotate = lambda *args, **kwargs: calls.append(("rotate", args, kwargs)) or 1
    router.activate_fallback = lambda *args, **kwargs: calls.append(("fallback", args, kwargs)) or 0

    assert router.response_event("opencode.ai", 429, dedupe_seconds=0) == 0
    assert calls == [
        ("rotate", ("proton",), {"reason": "429"}),
        ("fallback", ("proton",), {"reason": "429"}),
    ]


def test_response_event_targets_active_fallback_provider(tmp_path):
    router = load_router(tmp_path)
    router._providers["proton"] = {"fallback_providers": ["cloudflare"]}
    marker = tmp_path / "state" / "fallback" / "proton.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(json.dumps({"provider": "cloudflare"}))
    calls = []
    router.rotate = lambda *args, **kwargs: calls.append((args, kwargs)) or 0

    assert router.response_event("opencode.ai", 429, dedupe_seconds=0) == 0
    assert calls == [(("cloudflare",), {"reason": "429"})]

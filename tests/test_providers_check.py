"""Focused regression tests for `router.py providers check` (issue #51).

The preflight must answer, offline and read-only, which configured providers
can actually carry traffic — separate from the live `egress check` health
view — so the "only 10/27 working" failure mode becomes visible without any
probe traffic.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_router(tmp_path):
    sys.path.insert(0, str(ROOT))
    import importlib.util

    spec = importlib.util.spec_from_file_location("proxy_router_under_test_pcheck", ROOT / "router.py")
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
    return module


VALID_CONF = """[Interface]
Address = 10.2.0.2/32
PrivateKey = aaaabbbbccccdddd
DNS = 10.2.0.1

[Peer]
PublicKey = xbbzzww
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
"""


def make_provider(root: Path, name: str, *, profiles: int = 1, conf: str = VALID_CONF,
                  empty_dir: bool = False) -> None:
    directory = root / "providers" / name
    directory.mkdir(parents=True, exist_ok=True)
    if not empty_dir:
        for i in range(profiles):
            (directory / f"{name}-{i}.conf").write_text(conf)


def cool_profile(router_module, name: str, stem: str, seconds: int = 9999) -> None:
    """Write a cooldown marker directly (no rotation machinery involved)."""
    marker = router_module.ROOT / "state" / "cooldowns" / name / f"{stem}.until"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(int(time.time()) + seconds))


def configure(router_module, providers: dict) -> None:
    router_module._providers = providers
    router_module._routes = []
    router_module._routing = {}
    router_module._vpn = {}
    router_module._port = 2080


def test_valid_provider_reports_ok(tmp_path, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "proton")
    configure(router, {"proton": {}})

    rc = router.providers_check(as_json=True)

    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["total"] == 1 and out["valid"] == 1 and out["invalid"] == 0
    entry = out["results"]["proton"] if isinstance(out["results"], dict) else out["results"][0]
    assert entry["valid"] is True
    assert entry["issues"] == []
    assert entry["profiles"] == 1


def test_missing_directory_flags_invalid(tmp_path, capsys):
    router = load_router(tmp_path)
    configure(router, {"ghost": {"directory": "providers/ghost"}})

    rc = router.providers_check(as_json=True)

    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["invalid"] == 1
    entry = out["results"]["ghost"] if isinstance(out["results"], dict) else out["results"][0]
    assert entry["valid"] is False
    assert any("missing profile directory" in issue for issue in entry["issues"])


def test_empty_directory_flags_invalid(tmp_path, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "hollow", empty_dir=True)
    configure(router, {"hollow": {}})

    rc = router.providers_check()

    captured = capsys.readouterr()
    assert rc == 1
    assert "no .conf profiles" in captured.out
    assert "INVALID" in captured.out


def test_unparseable_profiles_are_named_and_all_bad_invalidates(tmp_path, capsys):
    router = load_router(tmp_path)
    directory = tmp_path / "providers" / "proton"
    directory.mkdir(parents=True)
    (directory / "good.conf").write_text(VALID_CONF)
    (directory / "broken.conf").write_text("[Interface]\nAddress = 10.2.0.2/32\n")  # no Peer section
    configure(router, {"proton": {}})

    rc_partial = router.providers_check("proton", as_json=True)
    out = json.loads(capsys.readouterr().out)
    assert rc_partial == 0  # one parseable lane remains
    entry = out["results"]["proton"] if isinstance(out["results"], dict) else out["results"][0]
    assert entry["valid"] is True
    assert entry["bad_profiles"] == ["broken"]
    assert any("unparseable profile(s): broken" in issue for issue in entry["issues"])

    (directory / "good.conf").unlink()
    rc_all_bad = router.providers_check("proton", as_json=True)
    out = json.loads(capsys.readouterr().out)
    assert rc_all_bad == 1
    entry = out["results"]["proton"] if isinstance(out["results"], dict) else out["results"][0]
    assert entry["valid"] is False
    assert any("no parseable profiles remain" in issue for issue in entry["issues"])


def test_all_profiles_cooled_down_flags_invalid(tmp_path, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "proton", profiles=2)
    cool_profile(router, "proton", "proton-0")
    cool_profile(router, "proton", "proton-1")
    configure(router, {"proton": {}})

    rc = router.providers_check(as_json=True)

    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    entry = out["results"]["proton"] if isinstance(out["results"], dict) else out["results"][0]
    assert entry["valid"] is False
    assert sorted(entry["cooled_down"]) == ["proton-0", "proton-1"]
    assert any("every remaining profile is cooled down" in issue for issue in entry["issues"])
    # A single live lane keeps the provider valid even with one cooled exit.
    (tmp_path / "state" / "cooldowns" / "proton" / "proton-1.until").unlink()
    assert router.providers_check() == 0


def test_unknown_provider_fails_fast_exit_2(tmp_path, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "proton")
    configure(router, {"proton": {}})

    rc = router.providers_check("warp")

    captured = capsys.readouterr()
    assert rc == 2
    assert "unknown provider 'warp'" in captured.err
    assert captured.out == ""


def test_summary_counts_mixed_pool_and_stderr_names_invalid(tmp_path, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "healthy-a")
    make_provider(tmp_path, "healthy-b")
    make_provider(tmp_path, "deadpool", empty_dir=True)
    configure(router, {"healthy-a": {}, "deadpool": {}, "healthy-b": {}})

    rc = router.providers_check()

    captured = capsys.readouterr()
    assert rc == 1
    assert "providers check: 2/3 valid" in captured.out
    assert "healthy-a: ok" in captured.out and "healthy-b: ok" in captured.out
    assert "deadpool: INVALID" in captured.out
    assert "invalid: deadpool" in captured.err


def test_static_entry_issues_surface_without_invalidating(tmp_path, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "proton")
    configure(router, {"proton": {"cooldown_seconds": "soon", "probe_url": "http://insecure.example"}})

    rc = router.providers_check(as_json=True)

    out = json.loads(capsys.readouterr().out)
    assert rc == 0  # the lane itself can carry traffic; these are advisories
    entry = out["results"]["proton"] if isinstance(out["results"], dict) else out["results"][0]
    assert entry["valid"] is True
    assert any("cooldown_seconds" in issue for issue in entry["issues"])
    assert any("probe_url" in issue for issue in entry["issues"])


def test_main_dispatch_providers_check_json(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    make_provider(tmp_path, "proton")
    config = {
        "port": 2080,
        "providers": {"proton": {}},
        "routes": [],
    }
    router.CONFIG_FILE.write_text(json.dumps(config))

    monkeypatch.setattr(sys, "argv", ["router.py", "providers", "check", "--json"])
    rc = router.main()

    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["total"] == 1 and out["valid"] == 1


def test_main_dispatch_reports_broken_pool_via_exit_code(tmp_path, monkeypatch, capsys):
    router = load_router(tmp_path)
    config = {
        "port": 2080,
        "providers": {"ghost": {"directory": "providers/ghost"}},
        "routes": [],
    }
    router.CONFIG_FILE.write_text(json.dumps(config))

    monkeypatch.setattr(sys, "argv", ["router.py", "providers", "check"])
    rc = router.main()

    captured = capsys.readouterr()
    assert rc == 1
    assert "ghost: INVALID" in captured.out

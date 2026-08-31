from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANAGER = ROOT / "examples" / "proxy-manager.sh"


def _make_fake_router(tmp: Path, status: dict) -> None:
    status_path = tmp / "status.json"
    log_path = tmp / "router.log"
    status_path.write_text(json.dumps(status))
    log_path.write_text("")
    router = tmp / "router.py"
    router.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, pathlib, os, json\n"
        "tmp = pathlib.Path(os.environ.get('FAKE_TMP','/tmp'))\n"
        "status_path = tmp / 'status.json'\n"
        "log_path = tmp / 'router.log'\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['status','--json']:\n"
        "    print(status_path.read_text())\n"
        "    raise SystemExit(0)\n"
        "if args and args[0]=='rotate':\n"
        "    log_path.write_text(' '.join(['rotate']+args[1:]))\n"
        "    raise SystemExit(0)\n"
        "if args and args[0]=='failover':\n"
        "    log_path.write_text(' '.join(['failover']+args[1:]))\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n"
    )
    router.chmod(0o755)


def _run_manager(tmp: Path, *args: str, env_overrides: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PROXY_ROUTER_ROOT"] = str(tmp)
    env["FAKE_TMP"] = str(tmp)
    if env_overrides:
        env.update(env_overrides)
        # allow test to explicitly unset OPENCODE_PROVIDER by setting to None
        for k, v in list(env_overrides.items()):
            if v is None and k in env:
                del env[k]
    return subprocess.run(
        [str(MANAGER), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def test_infer_via_opencode_route():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make_fake_router(tmp, {
            "providers": {"proton": {}, "cloudflare": {}},
            "routes": [
                {"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"},
                {"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"},
            ],
        })
        proc = _run_manager(tmp, "rotate", "429", env_overrides={"OPENCODE_PROVIDER": None})
        assert proc.returncode == 0, proc.stderr
        assert (tmp / "router.log").read_text() == "rotate proton --reason 429"


def test_infer_effective_fallback():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make_fake_router(tmp, {
            "providers": {"proton": {"fallback": {"active": "cloudflare"}}, "cloudflare": {}},
            "routes": [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}],
        })
        proc = _run_manager(tmp, "rotate", "429", env_overrides={"OPENCODE_PROVIDER": None})
        assert proc.returncode == 0, proc.stderr
        assert (tmp / "router.log").read_text() == "rotate cloudflare --reason 429"


def test_single_provider_generic_fallback():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make_fake_router(tmp, {"providers": {"myvpn": {}}, "routes": []})
        proc = _run_manager(tmp, "rotate", "429", env_overrides={"OPENCODE_PROVIDER": None})
        assert proc.returncode == 0, proc.stderr
        assert (tmp / "router.log").read_text() == "rotate myvpn --reason 429"


def test_fail_closed_ambiguous_multi_provider():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make_fake_router(tmp, {
            "providers": {"proton": {}, "cloudflare": {}},
            "routes": [{"id": "roblox", "domains": ["roblox.com"], "provider": "cloudflare"}],
        })
        proc = _run_manager(tmp, "rotate", "429", env_overrides={"OPENCODE_PROVIDER": None})
        assert proc.returncode == 2
        assert "cannot infer provider" in proc.stderr


def test_explicit_override_preserved():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make_fake_router(tmp, {
            "providers": {"proton": {}, "cloudflare": {}},
            "routes": [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}],
        })
        proc = _run_manager(tmp, "rotate", "429", env_overrides={"OPENCODE_PROVIDER": "cloudflare"})
        assert proc.returncode == 0, proc.stderr
        assert (tmp / "router.log").read_text() == "rotate cloudflare --reason 429"


def test_unsupported_reason_rejected_even_when_inferred():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make_fake_router(tmp, {
            "providers": {"proton": {}},
            "routes": [{"id": "opencode-zen", "domains": ["opencode.ai"], "provider": "proton"}],
        })
        proc = _run_manager(tmp, "rotate", "999", env_overrides={"OPENCODE_PROVIDER": None})
        assert proc.returncode == 2
        assert "unsupported rotation reason" in proc.stderr

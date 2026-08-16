from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_proxy_manager_activates_fallback_when_rotation_fails(tmp_path):
    examples = tmp_path / "examples"
    examples.mkdir()
    script = examples / "proxy-manager.sh"
    shutil.copy2(ROOT / "examples" / "proxy-manager.sh", script)
    script.chmod(0o755)

    marker = tmp_path / "fallback-called"
    router = examples / "router.py"
    router.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "if sys.argv[1] == 'rotate':\n"
        "    raise SystemExit(1)\n"
        "if sys.argv[1] == 'failover':\n"
        f"    pathlib.Path({str(marker)!r}).write_text(' '.join(sys.argv[1:]))\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(2)\n"
    )
    router.chmod(0o755)

    env = dict(os.environ)
    env.update({"PROXY_ROUTER_ROOT": str(tmp_path), "OPENCODE_PROVIDER": "proton"})
    result = subprocess.run(
        [str(script), "rotate", "tls"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "failover proton on --reason tls"

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_tls_eof_activates_fallback_and_retries(tmp_path):
    script = tmp_path / "hermes-opencode.sh"
    shutil.copy2(ROOT / "hermes-opencode.sh", script)
    script.chmod(0o755)

    state = tmp_path / "calls"
    router = tmp_path / "router.py"
    router.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        f"state = pathlib.Path({str(state)!r})\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['with-proxy', '--check']:\n"
        "    print('http://127.0.0.1:62080')\n"
        "elif args[:1] == ['provider-count']:\n"
        "    print('1')\n"
        "elif args[:1] == ['rotate']:\n"
        "    raise SystemExit(1)\n"
        "elif args[:1] == ['failover']:\n"
        "    state.with_suffix('.fallback').write_text('cloudflare')\n"
        "    print('fallback active')\n"
        "else:\n"
        "    raise SystemExit(2)\n"
    )
    router.chmod(0o755)

    hermes = tmp_path / "fake-hermes.py"
    hermes.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib\n"
        f"state = pathlib.Path({str(state)!r})\n"
        "count = int(state.read_text()) if state.exists() else 0\n"
        "state.write_text(str(count + 1))\n"
        "if count == 0:\n"
        "    print('SSL_ERROR_SYSCALL: unexpected EOF while reading')\n"
        "    raise SystemExit(1)\n"
        "print('success')\n"
    )
    hermes.chmod(0o755)

    env = dict(os.environ)
    env.update({
        "HERMES_BIN": str(hermes),
        "OPENCODE_MAX_ATTEMPTS": "2",
        "OPENCODE_RETRY_DELAY_SECONDS": "0",
        "TMPDIR": str(tmp_path),
    })
    result = subprocess.run(
        [str(script), "--version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "success" in result.stdout
    assert state.read_text() == "2"
    assert (tmp_path / "calls.fallback").read_text() == "cloudflare"

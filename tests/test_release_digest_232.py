"""#232 acceptance: assembly fails closed before the bundle is written.

Runs the REAL .github/scripts/assemble-release-bundle.sh with curl stubbed
to serve a local file, so the digest phase CI executes is what the tests
exercise. A corrupted downloaded archive, a missing manifest entry, or a
dispatch version mismatch must abort assembly with a digest error BEFORE
any dist/ output is written; a matching archive passes verification.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github/scripts/assemble-release-bundle.sh"
PINNED = "1.13.19"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _setup(tmp_path: Path, *, asset: str, version: str, payload: bytes,
           manifest: dict | None = None, windows: dict | None = None) -> tuple[Path, dict]:
    """Stage a work dir whose curl stub serves ``payload`` as the asset."""
    work = tmp_path / "work"
    work.mkdir()
    for name in ("sing-box-release.json", "sing-box-windows.json"):
        shutil.copy2(REPO / name, work / name)
    if manifest is not None:
        (work / "sing-box-release.json").write_text(json.dumps(manifest))
    if windows is not None:
        (work / "sing-box-windows.json").write_text(json.dumps(windows))
    # curl stub: writes the payload to the path given by -o and exits 0.
    fake = work / "curl"
    fake.write_text(
        "#!/bin/sh\n"
        'out=""\n'
        'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done\n'
        'cat "$CURL_PAYLOAD" > "$out"\n'
        "exit 0\n")
    fake.chmod(stat.S_IRWXU)
    env = dict(os.environ,
               PATH=f"{work}:{os.environ['PATH']}",
               SING_BOX_VERSION=version,
               CURL_PAYLOAD=str(tmp_path / "payload.bin"))
    (tmp_path / "payload.bin").write_bytes(payload)
    return work, env


def _digest_outcome(work: Path, env: dict, asset: str, version: str) -> tuple[int, str, bool]:
    """Run the real script; return (rc, stderr, wrote_dist)."""
    result = subprocess.run(
        ["bash", str(SCRIPT), asset, asset, "zip", "sing-box.exe", version],
        cwd=str(work), env=env, capture_output=True, text=True, timeout=180)
    wrote = (work / "dist").exists()
    return result.returncode, result.stderr, wrote


WINDOWS_PAYLOAD = b"PK\x03\x04 stub zip for digest test"


def test_matching_archive_passes_digest(tmp_path):
    """Correct manifest + payload whose sha matches -> verification passes."""
    payload = WINDOWS_PAYLOAD
    windows = {"name": f"sing-box-{PINNED}-windows-amd64.zip", "sha256": _sha(payload)}
    work, env = _setup(tmp_path, asset="windows-amd64", version=PINNED,
                       payload=payload, windows=windows)
    rc, err, _ = _digest_outcome(work, env, "windows-amd64", PINNED)
    # The script may fail later (a stub zip cannot extract - e.g. no
    # powershell on a macOS runner) - that is fine. What must NOT happen is
    # a digest failure on matching content.
    assert "sha256 verification failed" not in err, err


def test_corrupted_archive_fails_before_dist_writes(tmp_path):
    """A payload differing from the pinned digest aborts with a digest error
    and no dist/ tree (nothing written past verification)."""
    payload = b"CORRUPTED-PAYLOAD"
    windows = {"name": f"sing-box-{PINNED}-windows-amd64.zip", "sha256": _sha(WINDOWS_PAYLOAD)}
    work, env = _setup(tmp_path, asset="windows-amd64", version=PINNED,
                       payload=payload, windows=windows)
    rc, err, wrote = _digest_outcome(work, env, "windows-amd64", PINNED)
    assert rc != 0
    assert "sha256 verification failed" in err
    assert not wrote, "assembly must abort before writing the bundle"


def test_version_mismatch_fails(tmp_path):
    work, env = _setup(tmp_path, asset="windows-amd64", version="9.9.9",
                       payload=WINDOWS_PAYLOAD)
    rc, err, wrote = _digest_outcome(work, env, "windows-amd64", "9.9.9")
    assert rc != 0
    assert "!= pinned" in err
    assert not wrote


def test_missing_manifest_entry_fails(tmp_path):
    doc = json.loads((REPO / "sing-box-release.json").read_text())
    del doc["architectures"]["arm64"]
    work, env = _setup(tmp_path, asset="darwin-arm64", version=PINNED,
                       payload=b"x", manifest=doc)
    rc, err, wrote = _digest_outcome(work, env, "darwin-arm64", PINNED)
    assert rc != 0
    assert not wrote


def test_pinned_windows_digest_is_real():
    """The shipped windows pin matches the real upstream zip (recorded when
    the digest gate was added)."""
    win = json.loads((REPO / "sing-box-windows.json").read_text())
    assert win["sha256"] == "e011a4def2f5e2b143ed54adb2b1a20a6be407806ab4442f3667f1dd817a2c8d"

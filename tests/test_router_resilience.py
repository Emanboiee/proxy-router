"""F2 cooldown atomicity tests (also placeholder for F1/F3 if appended)."""
import os
import stat
import tempfile
import threading
from pathlib import Path
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]

def load_router(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("router_f2", ROOT / "router.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    mod.ROOT = tmp_path
    mod.CONFIG_FILE = tmp_path / "router.json"
    mod.SING_BOX_CONFIG = tmp_path / "sing-box.json"
    mod.LAST_GOOD_FILE = tmp_path / "sing-box.json.last-good"
    mod.PID_FILE = tmp_path / "sing-box.pid"
    mod.LOG_FILE = tmp_path / "sing-box.log"
    mod.LOCK_FILE = tmp_path / "state" / "engine.lock"
    mod.MODE_FILE = tmp_path / "state" / "mode"
    return mod

def test_f2_atomic_concurrent_writes(tmp_path):
    router = load_router(tmp_path)
    profile = Path("warp.conf")
    # 2x50 concurrent mark_cooldown must never produce 20-digit interleaving
    def worker():
        for _ in range(50):
            router.mark_cooldown("cloudflare", profile, 600)
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    p = tmp_path / "state" / "cooldowns" / "cloudflare" / "warp.until"
    assert p.is_file()
    text = p.read_text().strip()
    # must be numeric and 10 digits (epoch), not 20-digit corruption
    assert text.isdigit(), f"non-numeric: {text!r}"
    assert len(text) == 10, f"expected 10-digit epoch, got {len(text)}: {text!r}"
    assert text != "17877143351787714345"
    # wc -c == len+1 (newline)
    raw = p.read_bytes()
    assert raw.endswith(b"\n")
    assert len(raw) == len(text) + 1

def test_f2_atomic_temp_cleanup(tmp_path):
    router = load_router(tmp_path)
    profile = Path("warp.conf")
    for _ in range(20):
        router.mark_cooldown("cloudflare", profile, 600)
    # no *.until.tmp leaked
    leaked = list((tmp_path / "state" / "cooldowns").rglob("*.tmp"))
    assert leaked == [], f"leaked tmp files: {leaked}"
    leaked2 = list((tmp_path / "state" / "cooldowns").rglob("*.until.tmp"))
    assert leaked2 == []

def test_f2_mode_0600(tmp_path):
    router = load_router(tmp_path)
    profile = Path("warp.conf")
    router.mark_cooldown("cloudflare", profile, 600)
    p = tmp_path / "state" / "cooldowns" / "cloudflare" / "warp.until"
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, f"mode {oct(mode)} != 0o600"

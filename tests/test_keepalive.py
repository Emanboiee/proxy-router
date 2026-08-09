"""Integration test for examples/keepalive.sh exponential backoff.

Runs the real script against a fake router.py and a fake sleep (both on PATH)
so the loop is fast and deterministic: ensure fails on the 3rd and 4th calls,
so the waits must grow 2 -> 4 -> 8 (capped by MAX_BACKOFF) and then recover
back to the base interval once ensure succeeds again.
"""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KEEPALIVE_SRC = REPO / "examples" / "keepalive.sh"

FAKE_ROUTER = """#!/usr/bin/env bash
count_file="${FAKE_ROUTER_COUNT:-}"
count=$(cat "$count_file" 2>/dev/null || echo 0)
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
# fail on exactly the 3rd and 4th ensure calls
if [ "$count" -ge 3 ] && [ "$count" -le 4 ]; then
  exit 1
fi
exit 0
"""

FAKE_SLEEP = """#!/usr/bin/env bash
printf '%s\n' "$1" >> "${SLEEP_LOG:-/dev/null}"
"""


class KeepaliveBackoffTests(unittest.TestCase):
    def test_backoff_grows_then_recovers_and_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            sleep_bin = root / "bin" / "sleep"
            sleep_bin.write_text(FAKE_SLEEP)
            sleep_bin.chmod(0o755)
            router_bin = root / "router.py"
            router_bin.write_text(FAKE_ROUTER)
            router_bin.chmod(0o755)
            target = root / "keepalive.sh"
            target.write_text(KEEPALIVE_SRC.read_text())
            target.chmod(0o755)
            sleep_log = root / "sleeps.log"
            count_file = root / "count"

            env = dict(os.environ)
            env["PATH"] = f"{root / 'bin'}:" + env["PATH"]
            env["PROXY_KEEPALIVE_INTERVAL"] = "2"
            env["PROXY_KEEPALIVE_MAX_BACKOFF"] = "8"
            env["SLEEP_LOG"] = str(sleep_log)
            env["FAKE_ROUTER_COUNT"] = str(count_file)

            proc = subprocess.Popen([str(target)], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.time() + 20
                while time.time() < deadline:
                    if sleep_log.is_file() and len(sleep_log.read_text().split()) >= 8:
                        break
                    time.sleep(0.05)
                durations = [int(x) for x in sleep_log.read_text().split()] if sleep_log.is_file() else []
                self.assertGreaterEqual(len(durations), 8, f"loop made too few waits: {durations}")
                # the 3rd/4th ensure calls fail -> waits 4 then 8 (cap)
                self.assertIn(4, durations)
                self.assertIn(8, durations)
                # healthy cadence (2) after recovery
                self.assertIn(2, durations)
                self.assertLessEqual(max(durations), 8, "backoff must respect MAX_BACKOFF")
                # recovery: a base-interval wait must follow the last capped wait
                last_cap = max(i for i, d in enumerate(durations) if d == 8)
                self.assertTrue(any(d == 2 for d in durations[last_cap + 1:]),
                                f"no recovery after cap: {durations}")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    unittest.main()

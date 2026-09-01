"""Integration tests for examples/install-launchd.sh (issue #57).

Runs the real installer against a fake launchctl on PATH plus a fake HOME, so
no real launchd agent is touched. Verifies:

- the exact pinned interpreter is rendered into the plist env
  (PROXY_ROUTER_PYTHON) so launchd never resolves python3 via an ambient
  PATH that differs from the elevation-authorized identity,
- the installer fails loudly when no interpreter can be resolved,
- legacy agents (com.hermes.proxy-router) are detected and reported with
  explicit migration steps instead of being silently deleted.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_SRC = REPO / "examples" / "install-launchd.sh"
TEMPLATE_SRC = REPO / "examples" / "com.proxy-router.keepalive.plist.template"

FAKE_LAUNCHCTL = r"""#!/usr/bin/env bash
printf 'launchctl %s\n' "$*" >> "${LAUNCHCTL_LOG:-/dev/null}"
exit 0
"""


class InstallLaunchdHarness:
    def __init__(self, *, pinned_python="", legacy_agent=False):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name) / "home"
        self.home.mkdir()
        (self.home / "Library" / "LaunchAgents").mkdir(parents=True)
        self.root = Path(self._tmp.name) / "prefix"
        self.root.mkdir(parents=True)
        # New install-launchd.sh validates that the prefix actually contains
        # router.py before trusting it; stage a marker so positive-path tests
        # exercise a well-formed root.
        (self.root / "router.py").write_text("# test stub\n")
        (self.root / "examples").mkdir(parents=True)
        (self.root / "examples" / "com.proxy-router.keepalive.plist.template").write_text(
            TEMPLATE_SRC.read_text()
        )
        self.launchctl_log = Path(self._tmp.name) / "launchctl.log"
        if legacy_agent:
            (self.home / "Library" / "LaunchAgents"
             / "com.hermes.proxy-router.plist").write_text(
                "<plist><dict><key>Label</key><string>com.hermes.proxy-router</string></dict></plist>"
            )
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        env["PROXY_ROUTER_DIR"] = str(self.root)
        if pinned_python:
            env["PROXY_ROUTER_PYTHON"] = pinned_python
        # insert fake launchctl before the real one
        fake_bin = Path(self._tmp.name) / "bin"
        fake_bin.mkdir()
        launchctl = fake_bin / "launchctl"
        launchctl.write_text(FAKE_LAUNCHCTL)
        launchctl.chmod(0o755)
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        env["LAUNCHCTL_LOG"] = str(self.launchctl_log)
        self.env = env

    def run(self, *args):
        return subprocess.run(
            ["/bin/bash", str(INSTALL_SRC), *args],
            env=self.env, capture_output=True, text=True, timeout=30,
        )

    @property
    def plist(self):
        return self.home / "Library" / "LaunchAgents" / "com.proxy-router.keepalive.plist"

    def close(self):
        self._tmp.cleanup()


class InstallLaunchdTests(unittest.TestCase):
    def test_renders_exact_pinned_python_into_plist(self):
        pinned = sys.executable
        h = InstallLaunchdHarness(pinned_python=pinned)
        try:
            result = h.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.returncode, 0)
            plist = h.plist.read_text()
            # env pin: keepalive.sh uses this exact interpreter
            self.assertIn(f"<key>PROXY_ROUTER_PYTHON</key>", plist)
            self.assertIn(f"<string>{pinned}</string>", plist)
            # the legacy placeholder must be gone (no unrendered @PYTHON@)
            self.assertNotIn("@PYTHON@", plist)
            self.assertIn("interpreter:" + pinned, result.stdout)
        finally:
            h.close()

    def test_no_interpreter_fails_loudly(self):
        h = InstallLaunchdHarness()
        try:
            env = dict(h.env)
            env.pop("PROXY_ROUTER_PYTHON", None)
            # PATH with no python3 anywhere -> installer must fail loudly
            env["PATH"] = "/nonexistent"
            result = subprocess.run(
                ["/bin/bash", str(INSTALL_SRC)],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no executable python3", result.stderr)
            self.assertFalse(h.plist.exists())
        finally:
            h.close()

    def test_legacy_agent_detected_and_not_deleted(self):
        h = InstallLaunchdHarness(pinned_python="/usr/bin/python3",
                                  legacy_agent=True)
        try:
            result = h.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("legacy agent found", result.stderr)
            self.assertIn("com.hermes.proxy-router", result.stderr)
            self.assertIn("migrate with", result.stderr)
            legacy = h.home / "Library" / "LaunchAgents" / "com.hermes.proxy-router.plist"
            self.assertTrue(legacy.exists(),
                            "installer must not delete legacy agents")
        finally:
            h.close()

    @unittest.skipUnless(sys.platform == "darwin", "macOS plutil")
    def test_plist_passes_plutil_lint(self):
        h = InstallLaunchdHarness(pinned_python="/usr/bin/python3")
        try:
            result = h.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            lint = subprocess.run(
                ["plutil", "-lint", str(h.plist)],
                capture_output=True, text=True,
            )
            self.assertEqual(lint.returncode, 0, lint.stderr)
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
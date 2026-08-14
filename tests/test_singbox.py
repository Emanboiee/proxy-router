"""Unit tests for the sing-box discovery / missing-binary messaging."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import router


class MissingMessageTests(unittest.TestCase):
    def test_message_lists_candidates_version_and_download_url(self):
        msg = router._sing_box_missing_message()
        self.assertIn("sing-box not found", msg)
        self.assertIn("env SING_BOX=", msg)
        self.assertIn(str(router.ROOT / "bin" / "sing-box"), msg)
        self.assertIn("1.12.0", msg)  # MIN_SING_BOX_VERSION
        self.assertIn("https://github.com/SagerNet/sing-box/releases", msg)

    def test_darwin_message_includes_homebrew_candidates(self):
        with mock.patch.object(router.sys, "platform", "darwin"), \
             mock.patch.object(router.os, "name", "posix"):
            msg = router._sing_box_missing_message()
            self.assertIn("/opt/homebrew/bin/sing-box", msg)
            self.assertIn("/usr/local/bin/sing-box", msg)

    def test_windows_message_uses_exe_name_and_skips_homebrew(self):
        with mock.patch.object(router.sys, "platform", "win32"), \
             mock.patch.object(router.os, "name", "nt"):
            msg = router._sing_box_missing_message()
            self.assertIn("sing-box.exe", msg)
            self.assertNotIn("homebrew", msg.lower())

    def test_unset_env_shows_unset_marker(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            msg = router._sing_box_missing_message()
        self.assertIn("env SING_BOX=(unset)", msg)

    def test_set_env_shows_missing_marker_without_echoing_value(self):
        with mock.patch.dict(os.environ, {"SING_BOX": "/secret/path/sing-box"}):
            msg = router._sing_box_missing_message()
        self.assertIn("env SING_BOX (set, missing)", msg)
        self.assertNotIn("/secret/path/sing-box", msg)


if __name__ == "__main__":
    unittest.main()
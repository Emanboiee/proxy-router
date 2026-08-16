"""Release bundle smoke checks for the files the installers need at runtime."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseBundleSourceTests(unittest.TestCase):
    def test_runtime_modules_and_data_are_in_source_tree(self):
        for relative in (
            "router.py",
            "setup_tui.py",
            "monitor.py",
            "route_watcher.py",
            "proxy_tray.py",
            "guides/proton-vpn-free.md",
            "guides/cloudflare-warp.md",
            "rulesets/roblox.json",
            "examples/proxy-manager.sh",
            "examples/keepalive.sh",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_release_workflow_copies_runtime_modules_and_data(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        for name in ("setup_tui.py", "monitor.py", "route_watcher.py", "proxy_tray.py"):
            self.assertIn(name, workflow)
        self.assertIn("cp -R guides rulesets dist/proxy-router/", workflow)
        self.assertIn("cp -R examples/. dist/proxy-router/examples/", workflow)

    def test_installers_copy_runtime_modules(self):
        shell = (ROOT / "install.sh").read_text()
        powershell = (ROOT / "install.ps1").read_text()
        for name in ("setup_tui.py", "monitor.py", "route_watcher.py", "proxy_tray.py"):
            self.assertIn(name, shell)
            self.assertIn(name, powershell)
        for name in ("guides", "rulesets"):
            self.assertIn(name, shell)
            self.assertIn(name, powershell)


if __name__ == "__main__":
    unittest.main()

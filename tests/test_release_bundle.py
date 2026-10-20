"""Release bundle smoke checks for the files the installers need at runtime."""

import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]

# The runtime file manifest lives in the assembly helper shared by the release
# workflow (tags/dispatch) and the pull request Windows smoke workflow, so
# both ship the identical bundle.
ASSEMBLY_HELPER = ROOT / ".github/scripts/assemble-release-bundle.sh"

# macOS-only privileged lifecycle files: shipped in shell/release artifacts, and
# deliberately not listed by the Windows installer.
_MACOS_ONLY_MODULES = {"privileged_helper", "privileged_installer"}


class ReleaseBundleSourceTests(unittest.TestCase):
    def test_runtime_modules_and_data_are_in_source_tree(self):
        for relative in (
            "router.py",
            "setup_tui.py",
            "monitor.py",
            "route_watcher.py",
            "proxy_tray.py",
            "worker_lock.py",
            "guides/proton-vpn-free.md",
            "guides/cloudflare-warp.md",
            "rulesets/roblox.json",
            "examples/proxy-manager.sh",
            "examples/keepalive.sh",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_release_workflow_copies_runtime_modules_and_data(self):
        helper = ASSEMBLY_HELPER.read_text()
        for name in ("setup_tui.py", "monitor.py", "route_watcher.py", "proxy_tray.py"):
            self.assertIn(name, helper)
        self.assertIn("cp -R guides rulesets dist/proxy-router/", helper)
        self.assertIn("cp -R examples/. dist/proxy-router/examples/", helper)

        # The release job must actually ship THAT manifest: its assembly step
        # is a call to the shared helper, not an inline copy list.
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn(".github/scripts/assemble-release-bundle.sh", workflow)
        self.assertNotIn("cp -R guides rulesets", workflow)

    def test_installers_copy_runtime_modules(self):
        shell = (ROOT / "install.sh").read_text()
        powershell = (ROOT / "install.ps1").read_text()
        for name in ("setup_tui.py", "monitor.py", "route_watcher.py", "proxy_tray.py"):
            self.assertIn(name, shell)
            self.assertIn(name, powershell)
        for name in ("privileged_helper.py", "privileged_installer.py", "sing-box-release.json"):
            self.assertIn(name, shell)
        for name in ("guides", "rulesets"):
            self.assertIn(name, shell)
            self.assertIn(name, powershell)


    def test_every_locally_imported_module_is_listed_by_every_manifest(self):
        """Derive the runtime module set from the code, not a hand-kept list.

        A split-out module that only one manifest copies breaks the other
        platform at import time (audit F01/F03). Deriving the set means a
        future extraction fails this test instead of shipping broken.
        """
        modules: set[str] = set()
        for source in (
            "router.py", "setup_tui.py", "monitor.py", "route_watcher.py",
            "proxy_tray.py", "privileged_helper.py",
        ):
            text = (ROOT / source).read_text()
            names = set(re.findall(r"^\s*import (\w+)", text, re.M))
            names |= set(re.findall(r"^\s*from (\w+) import", text, re.M))
            modules |= {n for n in names if (ROOT / f"{n}.py").is_file()}
        self.assertIn("worker_lock", modules, "derivation found no local modules")

        manifests = {
            "install.sh": (ROOT / "install.sh").read_text(),
            "install.ps1": (ROOT / "install.ps1").read_text(),
            "assemble-release-bundle.sh": ASSEMBLY_HELPER.read_text(),
        }
        for name in sorted(modules):
            skip_windows = name in _MACOS_ONLY_MODULES
            for label, text in manifests.items():
                if label == "install.ps1" and skip_windows:
                    continue
                self.assertIn(f"{name}.py", text, f"{name}.py missing from {label}")


if __name__ == "__main__":
    unittest.main()

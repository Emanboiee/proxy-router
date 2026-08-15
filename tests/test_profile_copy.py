import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROUTER = REPO / "router.py"


VALID_CONF = """[Interface]
Address = 10.2.0.2/32
PrivateKey = test-private-key
DNS = 10.2.0.1
[Peer]
PublicKey = test-public-key
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""


class ProfileCopyCliTests(unittest.TestCase):
    def test_copy_validates_sanitizes_and_uses_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "providers" / "proton").mkdir(parents=True)
            (root / "router.json").write_text(json.dumps({
                "port": 2080,
                "providers": {"proton": {"directory": "providers/proton"}},
                "routes": [],
                "vpn": {"capture": "ruleset"},
            }))
            source = root / "friend server.conf"
            source.write_text(VALID_CONF)
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = str(root)
            result = subprocess.run(
                [sys.executable, str(ROUTER), "profile", "copy", str(source), "--provider", "proton"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("test-private-key", result.stdout + result.stderr)
            copied = list((root / "providers" / "proton").glob("*.conf"))
            self.assertEqual(len(copied), 1)
            self.assertNotIn(" ", copied[0].name)
            self.assertEqual(stat.S_IMODE(copied[0].stat().st_mode), 0o600)

    def test_unknown_provider_fails_without_copying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "providers" / "proton").mkdir(parents=True)
            (root / "router.json").write_text(json.dumps({
                "port": 2080,
                "providers": {"proton": {"directory": "providers/proton"}},
                "routes": [],
                "vpn": {"capture": "ruleset"},
            }))
            source = root / "friend.conf"
            source.write_text(VALID_CONF)
            env = dict(os.environ)
            env["PROXY_ROUTER_ROOT"] = str(root)
            result = subprocess.run(
                [sys.executable, str(ROUTER), "profile", "copy", str(source), "--provider", "warp"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list((root / "providers" / "proton").glob("*.conf")), [])


if __name__ == "__main__":
    unittest.main()

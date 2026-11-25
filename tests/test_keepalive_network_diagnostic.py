"""Keepalive must refresh the dashboard network diagnostic on a bounded cadence.

Issue #177: the tray consumes a cached network diagnostic whose max age is
300s. If keepalive never refreshes it, the icon goes stale every 5 minutes
even while the proxy is healthy. The refresh must be:
  - on its own cadence shorter than the 300s diagnostic max age;
  - read-only (doctor --network, not network-check which switches presets);
  - bounded (never more than once per tick).
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KEEPALIVE = (REPO / "examples" / "keepalive.sh").read_text(encoding="utf-8")


class NetworkDiagnosticRefreshTests(unittest.TestCase):
    def test_diagnostic_cadence_is_under_max_age(self):
        m = re.search(
            r'NETWORK_DIAGNOSTIC_EVERY="\$\{PROXY_KEEPALIVE_NETWORK_DIAGNOSTIC_EVERY:-\$\(config_setting network_diagnostic_every (\d+)\)\}"',
            KEEPALIVE,
        )
        self.assertIsNotNone(m, "no bounded NETWORK_DIAGNOSTIC_EVERY cadence")
        self.assertLess(int(m.group(1)), 300, "cadence must be under the 300s diagnostic max age")

    def test_refresh_uses_read_only_doctor(self):
        self.assertIn("controller doctor --network", KEEPALIVE,
                      "refresh must use read-only doctor --network")
        self.assertNotIn("controller network-check", KEEPALIVE,
                         "network-check switches presets; must not be used for refresh")

    def test_refresh_is_cadence_gated(self):
        self.assertIn("last_diagnostic", KEEPALIVE, "no last_diagnostic tracker")
        self.assertIn("last_diagnostic=", KEEPALIVE, "last_diagnostic never initialized/updated")
        self.assertRegex(KEEPALIVE, r'last_diagnostic.*NETWORK_DIAGNOSTIC_EVERY|NETWORK_DIAGNOSTIC_EVERY.*last_diagnostic',
                         "refresh not gated by cadence")


if __name__ == "__main__":
    unittest.main()

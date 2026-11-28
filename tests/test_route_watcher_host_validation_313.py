"""#313: probe_target must not interpolate an attacker-controlled host into a URL."""
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace

import route_watcher as w


VALID_HOSTS = (
    "opencode.ai",
    "ok.example.com",
    "8.8.8.8",
    "[2001:4860:4860::8888]",
)

INJECTION_HOSTS = (
    "user@evil.example",
    "evil.example/path?x=1",
    "evil.example#frag",
    "evil.example:443",
    "bad host",
    "evil.example%0d%0aX",
    "@evil.example",
    "evil.example\\@x",
)


class ProbeHostValidationTests(unittest.TestCase):
    def _capture(self, calls):
        def fake_runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="200", stderr="")

        return fake_runner

    def test_valid_hosts_still_dial(self):
        for host in VALID_HOSTS:
            with self.subTest(host=host):
                calls = []
                result = w.probe_target(Path("/tmp"), host, runner=self._capture(calls))
                self.assertEqual(len(calls), 1, f"{host} must still dial")
                url = calls[0][-1]
                self.assertTrue(url.startswith("https://"), url)
                self.assertFalse(result["transport_failure"])

    def test_injection_hosts_never_dial(self):
        for host in INJECTION_HOSTS:
            with self.subTest(host=host):
                calls = []
                result = w.probe_target(Path("/tmp"), host, runner=self._capture(calls))
                self.assertEqual(calls, [], f"{host} must not reach curl")
                self.assertFalse(result["ok"])
                # Must not look like a transport failure: that would trigger rotation.
                self.assertFalse(result["transport_failure"])
                self.assertFalse(result["underlay_signal"])


if __name__ == "__main__":
    unittest.main()

"""F11: one normalized schema for fallback aliases, route matchers, and
non-object configs."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load(name: str):
    modname = f"f11_{name}"
    spec = importlib.util.spec_from_file_location(modname, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


class _RouterCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.router = _load("router")
        self.router.ROOT = self.root
        self.router.CONFIG_FILE = self.root / "router.json"

    def write_config(self, payload):
        self.router.CONFIG_FILE.write_text(json.dumps(payload))

    def load_with_error(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            rc = self.router.load_config()
        return rc, buffer.getvalue()

    @staticmethod
    def base(**entries):
        return {"port": 2080, "providers": entries, "routes": []}


class FallbackEncodingCycleTests(_RouterCase):
    def test_cycle_via_plural_key_string_is_rejected(self):
        self.write_config(self.base(
            a={"directory": "providers/a", "fallback_providers": "b"},
            b={"directory": "providers/b", "fallback_providers": "a"},
        ))
        rc, err = self.load_with_error()
        self.assertNotEqual(rc, 0, err)
        self.assertIn("cycle", err)

    def test_cycle_via_legacy_key_list_is_rejected(self):
        self.write_config(self.base(
            a={"directory": "providers/a", "fallback_provider": ["b"]},
            b={"directory": "providers/b", "fallback_provider": ["a"]},
        ))
        rc, err = self.load_with_error()
        self.assertNotEqual(rc, 0, err)
        self.assertIn("cycle", err)

    def test_cycle_across_mixed_encodings_is_rejected(self):
        self.write_config(self.base(
            a={"directory": "providers/a", "fallback_provider": "b"},
            b={"directory": "providers/b", "fallback_providers": ["a"]},
        ))
        rc, err = self.load_with_error()
        self.assertNotEqual(rc, 0, err)
        self.assertIn("cycle", err)

    def test_acyclic_chain_still_loads(self):
        self.write_config(self.base(
            a={"directory": "providers/a", "fallback_providers": "b"},
            b={"directory": "providers/b"},
        ))
        rc, err = self.load_with_error()
        self.assertEqual(rc, 0, err)


class RouteMatcherTests(_RouterCase):
    def test_route_without_matcher_is_rejected(self):
        payload = self.base(a={"directory": "providers/a"})
        payload["routes"] = [{"id": "empty", "provider": "a"}]
        self.write_config(payload)
        rc, err = self.load_with_error()
        self.assertNotEqual(rc, 0, err)
        self.assertIn("needs domains or ip_cidr", err)

    def test_ip_only_route_still_loads(self):
        payload = self.base(a={"directory": "providers/a"})
        payload["routes"] = [{"id": "cidr", "provider": "a", "ip_cidr": ["1.2.3.0/24"]}]
        self.write_config(payload)
        rc, err = self.load_with_error()
        self.assertEqual(rc, 0, err)


class NonObjectConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        (self.root / "router.json").write_text("[]")

    def test_setup_check_reports_non_object_config(self):
        setup = _load("setup_tui")
        result = setup.check(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(
            any("must be an object" in issue for issue in result["issues"]), result
        )

    def test_watcher_rejects_non_object_config_for_router_port(self):
        watcher = _load("route_watcher")
        with self.assertRaisesRegex(
            watcher.RouterConfigError, "top level must be an object"
        ):
            watcher.router_port(self.root)

    def test_watcher_rejects_non_object_config_for_critical_domains(self):
        watcher = _load("route_watcher")
        with self.assertRaisesRegex(
            watcher.RouterConfigError, "top level must be an object"
        ):
            watcher.critical_domains(self.root)

    def test_watcher_defaults_when_router_config_is_missing(self):
        (self.root / "router.json").unlink()
        watcher = _load("route_watcher")
        self.assertEqual(watcher.router_port(self.root), watcher.DEFAULT_ROUTER_PORT)
        self.assertEqual(
            watcher.critical_domains(self.root), watcher.DEFAULT_CRITICAL_DOMAINS
        )


if __name__ == "__main__":
    unittest.main()

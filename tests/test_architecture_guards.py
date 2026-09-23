"""F16 guardrails for the router.py decomposition.

``docs/REFACTOR_PLAN.md`` requires a lightweight check so extraction cannot
regress silently: extracted leaves must keep importing downward only, and the
monolith may only shrink. The size cap ratchets down as each step lands; it is
not a style rule, it is the tripwire that stops router.py from growing back.
"""
from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LEAF_MODULES = (
    "state.py",
    "egress.py",
    "config_schema.py",
    "domain_autodetect.py",
    "worker_lock.py",
    "providers_check.py",
    "net_safety.py",
)
TOP_LEVEL_MODULES = (
    "router",
    "monitor",
    "route_watcher",
    "setup_tui",
    "proxy_tray",
    "privileged_helper",
    "privileged_installer",
)
ROUTER_LINE_CAP = 8400


def _imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".", 1)[0])
            elif node.level:
                names.update(alias.name.split(".", 1)[0] for alias in node.names)
    return names


class DependencyDirectionTests(unittest.TestCase):
    def test_import_parser_handles_multiple_dotted_and_relative_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "leaf.py"
            source.write_text(
                "import os, router.submodule\n"
                "from router.submodule import value\n"
                "from . import monitor as monitor_alias\n",
                encoding="utf-8",
            )

            self.assertEqual(_imported_names(source), {"os", "router", "monitor"})

    def test_leaf_modules_never_import_upward(self):
        for leaf in LEAF_MODULES:
            imported = _imported_names(ROOT / leaf)
            upward = sorted(set(TOP_LEVEL_MODULES) & imported)
            self.assertEqual(upward, [], f"{leaf} imports upward: {upward}")

    def test_router_imports_the_extracted_leaves(self):
        imported = _imported_names(ROOT / "router.py")
        for leaf in ("domain_autodetect", "egress", "state", "config_schema"):
            self.assertIn(leaf, imported, f"router.py must import {leaf}")


class MonolithGrowthTests(unittest.TestCase):
    def test_router_line_count_does_not_grow(self):
        lines = len((ROOT / "router.py").read_text().splitlines())
        self.assertLessEqual(
            lines,
            ROUTER_LINE_CAP,
            f"router.py is {lines} lines (cap {ROUTER_LINE_CAP}); extract a module "
            "per docs/REFACTOR_PLAN.md instead of growing the monolith",
        )


if __name__ == "__main__":
    unittest.main()

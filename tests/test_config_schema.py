"""Contract tests for the first issue #66 schema extraction step."""

from pathlib import Path

import config_schema


ROOT = Path(__file__).resolve().parents[1]


def test_schema_leaf_has_no_controller_or_platform_dependency():
    source = (ROOT / "config_schema.py").read_text(encoding="utf-8")
    assert "import router" not in source
    assert "import proxy_tray" not in source
    assert "import subprocess" not in source


def test_migration_is_copying_and_sets_current_version():
    original = {"port": 2080, "providers": {"proton": {}}, "schema_version": 0}
    migrated = config_schema.migrate(original)

    assert migrated["schema_version"] == config_schema.SCHEMA_VERSION == 1
    assert original["schema_version"] == 0
    assert migrated is not original
    migrated["providers"]["proton"]["new"] = True
    assert "new" not in original["providers"]["proton"]


def test_migration_rejects_unknown_versions():
    try:
        config_schema.migrate({"schema_version": 99})
    except ValueError as exc:
        assert "unsupported config schema version" in str(exc)
    else:
        raise AssertionError("unknown schema versions must fail closed")


def test_router_status_exposes_schema_version_without_redefining_defaults():
    router_source = (ROOT / "router.py").read_text(encoding="utf-8")
    assert "from config_schema import" in router_source
    assert '"schema_version": SCHEMA_VERSION' in router_source
    assert "DEFAULT_EGRESS_SETTINGS = {" not in router_source

"""Offline provider validity helpers (leaf module).

First extraction from router.py per docs/REFACTOR_PLAN.md step 3. This module
must stay a leaf: it may not import router, monitor, or any other top-level
module. tests/test_architecture_guards.py enforces that direction.
"""
from __future__ import annotations


def provider_config_errors(name: str, entry: dict) -> list[str]:
    """Static config errors for one provider entry (offline, no probing).

    ``load_config`` already enforces the schema-wide rules (types, fallback
    references, directory containment); this re-checks only what a single
    provider entry controls, so the report can name the offending provider
    instead of failing the whole load.
    """
    errors: list[str] = []
    cooldown = entry.get("cooldown_seconds")
    if cooldown is not None and not isinstance(cooldown, int):
        try:
            int(cooldown)
        except (TypeError, ValueError):
            errors.append(f"cooldown_seconds must be an integer (got {cooldown!r})")
    probe_url = entry.get("probe_url")
    if probe_url is not None and not (isinstance(probe_url, str) and probe_url.startswith("https://")):
        errors.append("probe_url must be an https:// URL when set")
    return errors

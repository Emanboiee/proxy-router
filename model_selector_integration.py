"""Router-side adapter for the optional model selector.

Keeps validation and config emission out of router.py while preserving the
existing provider endpoints, proxy listener, and ordinary route rules.
"""
from __future__ import annotations

from pathlib import Path

import model_selector


def enabled(vpn: dict, providers: dict, port: int) -> bool:
    """True when a valid model selector section is configured."""
    return model_selector.settings(vpn, providers, port) is not None


def load_error(vpn: dict, providers: dict, port: int) -> str | None:
    """Config-load error for malformed selector settings, else None."""
    try:
        model_selector.settings(vpn, providers, port)
    except ValueError as exc:
        return str(exc)
    return None


def guard_mode(vpn: dict, providers: dict, port: int, mode: str) -> None:
    """The selector is proxy mode only; raise before any config is built."""
    if enabled(vpn, providers, port) and mode != "proxy":
        raise ValueError("model selector is proxy mode only")


def integrate(config: dict, vpn: dict, providers: dict, port: int,
              root: Path, mode: str) -> None:
    """Add the selector outbound/control API to a proxy-mode config."""
    options = model_selector.settings(vpn, providers, port)
    if not options:
        return
    if mode != "proxy":
        raise ValueError("model selector is proxy mode only")
    credential = model_selector.secret(root / "state" / "model-selector.secret")
    model_selector.apply(config, options, credential)

#!/usr/bin/env python3
"""Setup wizard for proxy-router: guides, profile imports, route presets, checks.

Stdlib only. Owns the non-engine half of ``proxy-router setup``:

- ``guide_text``      - bundled provider guides (Proton VPN Free, Cloudflare WARP)
- ``import_profiles`` - validates/dedupes/copies WireGuard ``.conf`` files
- ``apply_presets``   - idempotent safe route presets (opencode.ai, Roblox)
- ``check``           - reports provider profile availability (no network)
- ``bridge``          - installs/verifies the Hermes OpenCode auto-rotation
  bridge (``proxy-manager.sh``) at the path the Hermes plugin expects
- ``main`` / ``wizard`` - non-interactive CLI flags and a full-screen TUI
  (alternate screen, arrow-key navigation; plain line menu when not a TTY)

This module never starts sing-box, enables TUN, or touches networking on its
own. The only engine lifecycle call (menu item 8) shells out to the existing
``router.py ensure`` command, and only when the user explicitly selects it.
"""
from __future__ import annotations

import argparse
import configparser
import contextlib
import copy
import dataclasses
import glob
import io
import json
import os
import signal
import time
import re
import select
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

_PRESET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

# Resource-aware keepalive profiles. Explicit CLI overrides can tune any of
# these values without making users hand-edit JSON or environment variables.
_AUTOCHECK_PRESETS = {
    "off": {
        "enabled": False,
        "interval": 15,
        "max_backoff": 300,
        "probe_every": 4,
        "dead_strikes": 2,
        "storm_window": 600,
        "max_rotations": 2,
        "sweep_every": 1800,
    },
    "light": {
        "enabled": True,
        "interval": 30,
        "max_backoff": 600,
        "probe_every": 12,
        "dead_strikes": 3,
        "storm_window": 1800,
        "max_rotations": 1,
        "sweep_every": 7200,
    },
    "balanced": {
        "enabled": True,
        "interval": 15,
        "max_backoff": 300,
        "probe_every": 4,
        "dead_strikes": 2,
        "storm_window": 600,
        "max_rotations": 2,
        "sweep_every": 1800,
    },
    "aggressive": {
        "enabled": True,
        "interval": 10,
        "max_backoff": 180,
        "probe_every": 1,
        "dead_strikes": 1,
        "storm_window": 300,
        "max_rotations": 3,
        "sweep_every": 900,
    },
}
_AUTOCHECK_NUMERIC = tuple(key for key in _AUTOCHECK_PRESETS["balanced"] if key != "enabled")

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX platforms
    termios = None
    tty = None

_HAVE_TERMIOS = termios is not None and tty is not None

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()
# A bare TuiState is also used by pure renderer callers and tests. It must not
# silently inspect the checkout's live PID/config; the wizard always injects its
# real root through _initial_state(root).
_UNBOUND_ROOT = Path(tempfile.gettempdir()) / f"proxy-router-unbound-{os.getpid()}"

# Default Hermes config path for the bridge check (resolved via env at call
# time so tests can override; defaults to this module-level value).
_HERMES_CONFIG_DEFAULT = "~/.hermes/config.yaml"

# Guides live next to this module in the checkout/installed prefix. They are
# resolved from the module location (not ROOT) because the test harness
# relocates ROOT per-suite while the bundled guides are fixed files.
_GUIDES = {
    "proton": "proton-vpn-free.md",
    "warp": "cloudflare-warp.md",
}

# Idempotent safe presets: only ever added when their route id is absent,
# never merged into or replacing unrelated routes/providers.
_PRESET_ROUTES = {
    "opencode-zen": {
        "id": "opencode-zen",
        "domains": ["opencode.ai"],
        "provider": "proton",
    },
    "roblox": {
        "id": "roblox",
        "domains": ["roblox.com", "rbxcdn.com", "robloxlabs.com", "rblx.com"],
        "provider": "cloudflare",
    },
    "school": {
        "id": "school",
        "domains": [
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "twitch.tv",
            "facebook.com",
            "fbcdn.net",
            "instagram.com",
            "cdninstagram.com",
            "youtube.com",
            "googlevideo.com",
            "ytimg.com",
            "x.com",
            "twitter.com",
            "twimg.com",
            "t.co",
            "cdn.sstatic.net",
            # Wayground/Quizizz requires these first-party and challenge hosts;
            # apex entries cover all subdomains through domain-suffix matching.
            "wayground.com",
            "quizizz.com",
            "joinmyquiz.com",
            "quizizz.app.link",
            "challenges.cloudflare.com",
            "pro.ip-api.com",
        ],
        "provider": "cloudflare",
    },
}

# Built-in preset definitions: name -> {"routes": [..], "routing": {...}}.
# A preset is a NAMED bundle of routes (domains -> provider) plus an optional
# routing-mode section, applied by name with `setup --preset <name>`. Users
# add their own with `setup --preset-add NAME --provider P --domain ...`.
_BUILTIN_PRESETS: dict = {
    "opencode": {
        "routes": [_PRESET_ROUTES["opencode-zen"]],
        "routing": {"mode": "default"},
    },
    "roblox": {
        "routes": [_PRESET_ROUTES["roblox"]],
        "routing": {"mode": "default"},
    },
    "default": {  # the classic combo: opencode via proton + roblox via warp
        "routes": [_PRESET_ROUTES["opencode-zen"], _PRESET_ROUTES["roblox"]],
        "routing": {"mode": "default"},
        # Unfiltered home/default networks: plain UDP 53 DNS (fast path).
        "vpn": {"dns_transport": "udp"},
    },
    "school-warp": {
        "routes": [_PRESET_ROUTES["school"]],
        "routing": {"mode": "vpn-list",
                    "vpn_domains": list(_PRESET_ROUTES["school"]["domains"])},
        # Filtered school/captive networks drop UDP 53; tunnel DNS must ride
        # DoH there. Applying any other built-in preset restores UDP.
        "vpn": {"dns_transport": "https"},
    },
}

ANSI = sys.stdout.isatty() and sys.stdin.isatty() and os.environ.get("NO_COLOR") is None


class _Ansi:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"
    MAGENTA = "\x1b[35m"
    REVERSE = "\x1b[7m"
    # 256-color: true orange/purple (brand-ish, readable on light+dark).
    PURPLE = "\x1b[38;5;141m"
    ORANGE = "\x1b[38;5;208m"


def _style(text: str, *codes: str) -> str:
    return "".join(codes) + text + _Ansi.RESET if ANSI else text


_PROVIDER_RE = re.compile(r"\b(proton|cloudflare|warp)\b", re.IGNORECASE)


def _tint_provider(text: str) -> str:
    """Color provider names: Proton/WARP = purple, Cloudflare = orange.

    Applies AFTER width fitting so ANSI bytes never affect layout math.
    No-op when ANSI is disabled (NO_COLOR / non-TTY).
    """
    if not ANSI:
        return text

    def _repl(match: re.Match) -> str:
        word = match.group(0)
        color = _Ansi.PURPLE if word.lower() in ("proton", "warp") else _Ansi.ORANGE
        return color + word + _Ansi.RESET

    return _PROVIDER_RE.sub(_repl, text)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _valid_endpoint(endpoint: str) -> bool:
    """Basic host:port endpoint shape (bracketed IPv6 allowed, no DNS lookups)."""
    endpoint = endpoint.strip()
    if not endpoint:
        return False
    if endpoint.startswith("["):
        return re.fullmatch(r"\[[0-9a-fA-F:.%]+\]:\d+", endpoint) is not None
    host, sep, port = endpoint.rpartition(":")
    return bool(sep) and bool(host) and port.isdigit()


def inspect_profile(conf_path: Path) -> tuple[bool, str]:
    """Validate the minimum WireGuard structure of a ``.conf`` file.

    Returns (ok, reason). Checks ``[Interface]`` Address/PrivateKey,
    ``[Peer]`` PublicKey/Endpoint/AllowedIPs, and a parseable Endpoint -
    the same surface the engine's parser needs. Never returns file contents.
    """
    try:
        # Read at the os level (not builtins.open) so validation keeps
        # working when tests or hardening inject failures into the text-open
        # layer; the exclusive copy below is where write-side errors surface.
        fd = os.open(str(conf_path), os.O_RDONLY)
        try:
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)
        raw = b"".join(chunks)
    except OSError as exc:
        return False, f"cannot read file: {exc}"
    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(raw.decode("utf-8", "replace"))
    except configparser.Error as exc:
        return False, f"not a parseable config: {exc}"
    if not parser.sections():
        return False, "unreadable file"
    if not parser.has_section("Interface"):
        return False, "missing [Interface] section"
    interface = parser["Interface"]
    for key in ("Address", "PrivateKey"):
        if not str(interface.get(key, "")).strip():
            return False, f"missing Interface.{key}"
    if not parser.has_section("Peer"):
        return False, "missing [Peer] section"
    peer = parser["Peer"]
    for key in ("PublicKey", "Endpoint", "AllowedIPs"):
        if not str(peer.get(key, "")).strip():
            return False, f"missing Peer.{key}"
    if not _valid_endpoint(str(peer["Endpoint"])):
        return False, "bad Peer.Endpoint (expected host:port or [v6]:port)"
    return True, "ok"


def validate_profile(conf_path: Path) -> bool:
    """Default single-file validator: True for a structurally valid profile."""
    ok, _ = inspect_profile(conf_path)
    return ok


# Roaming default (seconds): a WireGuard client that goes quiet behind
# NAT/school Wi-Fi never re-advertises its address after a roam, so the
# server keeps sending to the dead endpoint until user traffic flows.
# A 25s persistent keepalive (empty packet only when idle, ~0.3 MB/day)
# keeps the UDP mapping alive and announces the new endpoint within one
# interval. Stamped at import so every stored profile roams; an explicit
# per-profile value is always respected.
_ROAM_KEEPALIVE_DEFAULT = 25


def _stamp_roam_keepalive(text: str) -> str:
    """Insert ``PersistentKeepalive`` into ``[Peer]`` when the profile omits it.

    Returns the text unchanged when any keepalive entry (any case) is
    already present or no ``[Peer]`` section exists. Text-level edit on
    purpose: the rest of the file (keys, order, comments) is preserved
    byte-for-byte. Callers must never print the return value (key material).
    """
    lines = text.split("\n")
    try:
        peer_at = next(
            i for i, line in enumerate(lines) if line.strip() == "[Peer]"
        )
    except StopIteration:
        return text
    section_end = next(
        (i for i in range(peer_at + 1, len(lines))
         if lines[i].strip().startswith("[") and lines[i].strip().endswith("]")),
        len(lines),
    )
    if any(
        line.strip().lower().startswith("persistentkeepalive")
        for line in lines[peer_at + 1:section_end]
    ):
        return text
    lines.insert(peer_at + 1, f"PersistentKeepalive = {_ROAM_KEEPALIVE_DEFAULT}")
    return "\n".join(lines)


def sanitize_name(name: str) -> str:
    """Lowercase, safe filename preserving a trailing ``.conf`` extension."""
    name = name.strip()
    stem = name[:-5] if name.lower().endswith(".conf") else name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem)
    stem = stem.strip("._-").lower()
    if not stem:
        stem = "profile"
    return stem + ".conf"


def _unique_target(destination: Path, name: str) -> Path:
    """Pick an unused destination path for ``name``.

    A name that already exists is never reused — and if the existing entry
    is a symlink (an attacker-planted one), the import refuses loudly with
    ``copy failed`` instead of silently writing a ``-2`` sibling next to it:
    a planted symlink at the target means someone is racing the importer,
    and that must be surfaced, not routed around.
    """
    target = destination / name
    if not target.exists():
        return target
    if target.is_symlink():
        raise OSError(f"refusing symlink planted at import target: {target}")
    stem = name[:-5] if name.lower().endswith(".conf") else Path(name).stem
    for index in range(2, 10_000):
        candidate = destination / f"{stem}-{index}.conf"
        if not candidate.exists():
            return candidate
    raise OSError(f"could not find a unique destination name for {name}")


def _open_conf_exclusive(target: Path) -> int:
    """Open ``target`` as a new private file, refusing any symlink game.

    Issue #64: the old check-then-copy flow (``copyfile`` + chmod afterwards)
    let an attacker-writable destination install a symlink between the check
    and the copy, and created the key material world-readable before 0600 was
    applied. This opens with O_CREAT|O_EXCL|O_NOFOLLOW and mode 0600 up front,
    so the file either lands as a fresh private regular file or not at all.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(str(target), flags, 0o600)


def _is_within(child: Path, parent: Path) -> bool:
    """True when resolved ``child`` stays under resolved ``parent``."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def import_profiles(source, destination, validator=None) -> dict:
    """Copy valid WireGuard ``.conf`` profiles from ``source`` into ``destination``.

    ``source`` is a single ``.conf`` file or a directory of ``.conf`` files.
    Each profile is validated, given a sanitized, collision-free name, and
    written atomically: a fresh O_CREAT|O_EXCL|O_NOFOLLOW fd at mode 0600
    (never following symlinks), bytes copied through it with the roaming
    keepalive default stamped when absent, then fsync + close —
    matching the tmp+replace discipline PR #89 gave the config writers.
    Nothing about the contents is printed.

    Returns::

        {"imported": n, "rejected": n, "files": [names],
         "rejected_files": [{"name": ..., "reason": ...}]}
    """
    source = Path(source)
    destination = Path(destination)
    if source.is_dir():
        candidates = sorted(
            p for p in source.iterdir() if p.is_file() and p.suffix.lower() == ".conf"
        )
    else:
        candidates = [source]
    destination.mkdir(parents=True, exist_ok=True)

    files: list[str] = []
    rejected_files: list[dict] = []
    dest_root = destination.resolve()
    for candidate in candidates:
        name = candidate.name
        if not candidate.is_file():
            rejected_files.append({"name": name, "reason": "no such file"})
            continue
        if validator is None or validator is validate_profile:
            ok, reason = inspect_profile(candidate)
        else:
            try:
                ok = bool(validator(candidate))
            except Exception as exc:  # noqa: BLE001 - a broken custom validator
                ok, reason = False, f"validator error: {exc}"
            else:
                reason = "" if ok else "rejected by custom validator"
        if not ok:
            rejected_files.append({"name": name, "reason": reason or "invalid WireGuard profile"})
            continue
        try:
            target = _unique_target(destination, sanitize_name(name))
            fd = _open_conf_exclusive(target)
        except OSError as exc:
            rejected_files.append({"name": name, "reason": f"copy failed: {exc}"})
            continue
        # The exclusive open already guarantees target is a fresh regular
        # file; resolve it anyway so a hostile destination layout can never
        # move key material outside the provider root.
        if not _is_within(target.resolve(), dest_root):
            os.close(fd)
            target.unlink(missing_ok=True)
            rejected_files.append({"name": name, "reason": "target escaped provider root"})
            continue
        try:
            with os.fdopen(fd, "wb") as out:
                with open(candidate, "rb") as src_handle:
                    raw = src_handle.read()
                try:
                    out.write(_stamp_roam_keepalive(raw.decode("utf-8")).encode("utf-8"))
                except UnicodeDecodeError:
                    out.write(raw)
                out.flush()
                os.fsync(out.fileno())
        except OSError as exc:
            # Leave no partial key material behind on a failed copy.
            target.unlink(missing_ok=True)
            rejected_files.append({"name": name, "reason": f"copy failed: {exc}"})
            continue
        os.chmod(target, 0o600)
        files.append(target.name)

    return {
        "imported": len(files),
        "rejected": len(rejected_files),
        "files": files,
        "rejected_files": rejected_files,
    }


def configure_autocheck(config_path, preset: str | None = None, **overrides) -> dict:
    """Persist resource-aware keepalive settings without starting the engine.

    ``preset`` is one of ``off``, ``light``, ``balanced``, or ``aggressive``.
    Numeric overrides are validated and merged on top, making this suitable
    for both a low-power laptop and a machine that can afford frequent pool
    sweeps. Existing unrelated router settings are preserved.
    """
    config_path = Path(config_path)
    if config_path.is_file():
        data = json.loads(config_path.read_text())
    else:
        data = _default_config()
    current = data.get("keepalive")
    if not isinstance(current, dict):
        current = {}
    selected = preset or current.get("preset") or "balanced"
    if selected not in _AUTOCHECK_PRESETS:
        raise ValueError(f"unknown autocheck profile '{selected}'")
    settings = dict(_AUTOCHECK_PRESETS[selected])
    if preset is None:
        for key, value in current.items():
            if key in settings:
                settings[key] = value
    for key in _AUTOCHECK_NUMERIC:
        value = overrides.get(key)
        if value is None:
            continue
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"autocheck {key} must be an integer") from exc
        if value < 1:
            raise ValueError(f"autocheck {key} must be at least 1")
        settings[key] = value
    settings["preset"] = selected
    data["keepalive"] = settings
    _atomic_write_config(config_path, data)
    return settings


# ---------------------------------------------------------------------------
# guides
# ---------------------------------------------------------------------------

def guide_text(provider: str) -> str:
    """Return the bundled markdown guide; ``all`` combines them; unknown -> ""."""
    if provider == "all":
        return "\n\n".join(part for part in (guide_text("proton"), guide_text("warp")) if part)
    if provider not in _GUIDES:
        return ""
    try:
        return (Path(__file__).resolve().parent / "guides" / _GUIDES[provider]).read_text()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------

def _atomic_write_config(path: Path, data: dict) -> None:
    """Write a router.json-shaped dict atomically (tmp + os.replace).

    Every config writer must go through this: a crash or full disk mid-write
    of the plain write_text path left a truncated router.json, and the next
    ensure/rotate then failed to parse it — the proxy stayed down until the
    file was fixed by hand.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False,
                                     encoding="utf-8") as tmp:
        json.dump(data, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def _default_config() -> dict:
    example = Path(__file__).resolve().parent / "router.example.json"
    if example.is_file():
        return json.loads(example.read_text())
    return {
        "port": 2080,
        "providers": {},
        "routes": [],
        "vpn": {"address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system"},
    }


def apply_presets(config_path, opencode=True, warp_roblox=True) -> dict:
    """Add the safe route presets to ``router.json`` (idempotent, lossless).

    Adds providers ``proton``/``cloudflare`` and routes ``opencode-zen``
    (opencode.ai -> proton) and ``roblox`` (Roblox domains -> cloudflare) when
    missing, leaving every other key, provider, route, and value untouched.
    Returns ``{"added": [route ids created this call]}``.
    """
    config_path = Path(config_path)
    if config_path.is_file():
        data = json.loads(config_path.read_text())
    else:
        data = _default_config()
    providers = data.setdefault("providers", {})
    routes = data.setdefault("routes", [])

    added: list[str] = []
    if opencode:
        proton_config = providers.setdefault("proton", {})
        proton_config.setdefault("directory", "providers/proton")
        proton_config.setdefault("cooldown_seconds", 60)
        if warp_roblox or "cloudflare" in providers:
            if "fallback_providers" not in proton_config and "fallback_provider" not in proton_config:
                proton_config["fallback_providers"] = ["cloudflare"]
        if not any(r.get("id") == "opencode-zen" for r in routes):
            routes.append(dict(_PRESET_ROUTES["opencode-zen"]))
            added.append("opencode-zen")
    if warp_roblox:
        providers.setdefault(
            "cloudflare", {"directory": "providers/cloudflare", "cooldown_seconds": 60}
        )
        if not any(r.get("id") == "roblox" for r in routes):
            routes.append(dict(_PRESET_ROUTES["roblox"]))
            added.append("roblox")
    _atomic_write_config(config_path, data)
    return {"added": added}


def configure_fallback(config_path, primary: str, candidates: list[str] | str) -> dict:
    """Set an ordered fallback chain without starting or reloading the engine.

    ``candidates`` may be a list or a comma-separated CLI value. The legacy
    singular ``fallback_provider`` key is removed when a new chain is saved,
    making the migration explicit while preserving every unrelated setting.
    An empty candidate list clears the chain.
    """
    config_path = Path(config_path)
    if config_path.is_file():
        data = json.loads(config_path.read_text())
    else:
        data = _default_config()
    providers = data.setdefault("providers", {})
    if primary not in providers:
        raise ValueError(f"unknown primary provider '{primary}'")
    if isinstance(candidates, str):
        candidates = [item.strip() for item in candidates.split(",") if item.strip()]
    if not isinstance(candidates, list) or any(not isinstance(item, str) for item in candidates):
        raise ValueError("fallback candidates must be a comma-separated provider list")
    if len(set(candidates)) != len(candidates):
        raise ValueError("fallback candidates must not contain duplicates")
    if primary in candidates:
        raise ValueError("a provider cannot fall back to itself")
    unknown = [item for item in candidates if item not in providers]
    if unknown:
        raise ValueError(f"unknown fallback provider(s): {', '.join(unknown)}")
    entry = providers[primary]
    entry.pop("fallback_provider", None)
    if candidates:
        entry["fallback_providers"] = candidates
    else:
        entry.pop("fallback_providers", None)
    _atomic_write_config(config_path, data)
    return {"provider": primary, "fallback_providers": candidates}


def configure_transparent(config_path, enabled: bool = True) -> dict:
    """Select route-based TUN capture without starting or reloading the engine."""
    config_path = Path(config_path)
    if config_path.is_file():
        data = json.loads(config_path.read_text())
    else:
        data = _default_config()
    vpn = data.setdefault("vpn", {})
    if not isinstance(vpn, dict):
        raise ValueError("vpn configuration must be an object")
    capture = "routes" if enabled else "ruleset"
    vpn["capture"] = capture
    _atomic_write_config(config_path, data)
    return {"capture": capture}


def custom_preset_path(root: Path, name: str) -> Path:
    """Path of the custom preset file for ``name`` under ``root/presets/``.

    Preset names are validated like provider names (letters/digits/._-), so a
    name can never escape the presets directory.
    """
    if not _PRESET_NAME.fullmatch(name):
        raise ValueError(
            f"invalid preset name '{name}' (use letters, digits, '.', '_', '-'; max 64)"
        )
    return root / "presets" / f"{name}.json"


def preset_names(root: Path) -> list[str]:
    """All available preset names: built-ins first, then custom files."""
    names = sorted(_BUILTIN_PRESETS)
    try:
        custom_dir = root / "presets"
        if custom_dir.is_dir():
            names += sorted(p.stem for p in custom_dir.glob("*.json"))
    except OSError:
        pass
    result: list[str] = []
    for name in names:
        if name not in result:
            result.append(name)
    return result


def load_preset(root: Path, name: str) -> dict:
    """Load a preset definition (built-in or custom) as
    ``{"routes": [...], "routing": {...}, "providers": {...}}``."""
    if name in _BUILTIN_PRESETS:
        return dict(_BUILTIN_PRESETS[name])
    path = custom_preset_path(root, name)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"preset '{name}' is not loadable: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"preset '{name}' must be a JSON object")
    return data


def apply_preset_by_name(root: Path, name: str) -> dict:
    """Apply the preset ``name`` to ``root/router.json`` (idempotent, lossless).

    Adds the preset's routes/providers and merges its ``routing`` section
    (mode switch when the preset defines one; a ``default`` routing is left
    untouched). Never starts the engine.
    Returns ``{"added": [...], "mode": ..., "preset": name}``.
    """
    config_path = root / "router.json"
    if config_path.is_file():
        data = json.loads(config_path.read_text())
    else:
        data = _default_config()
    preset = load_preset(root, name)
    providers = data.setdefault("providers", {})
    routes = data.setdefault("routes", [])
    for provider in preset.get("providers", {}):
        providers.setdefault(provider, dict(preset["providers"][provider]))
    added: list[str] = []
    for route in preset.get("routes", []):
        if route.get("provider") and route["provider"] not in providers:
            provider_config = {
                "directory": f"providers/{route['provider']}",
                "cooldown_seconds": 60,
            }
            providers.setdefault(route["provider"], provider_config)
        if not any(r.get("id") == route.get("id") for r in routes):
            routes.append(dict(route))
            added.append(str(route.get("id")))
    # Same normalization apply_presets uses: a Proton pool paired with a
    # Cloudflare pool declares it as the fallback chain (first application
    # only; an explicitly configured chain is never overwritten).
    proton_config = providers.get("proton")
    if isinstance(proton_config, dict) and "cloudflare" in providers:
        if "fallback_providers" not in proton_config and "fallback_provider" not in proton_config:
            proton_config["fallback_providers"] = ["cloudflare"]
    routing = preset.get("routing") or {}
    mode = routing.get("mode", "default")
    if mode != "default":
        data["routing"] = data.get("routing") or {}
        data["routing"].update({k: v for k, v in routing.items() if v is not None})
        # never clobber an explicitly-set default_provider with None
        if routing.get("default_provider"):
            data["routing"]["default_provider"] = routing["default_provider"]
    vpn = preset.get("vpn") or {}
    if vpn:
        # Preset-declared VPN knobs (e.g. dns_transport for filtered
        # networks) merge into the live config; a preset without a "vpn"
        # section leaves the operator's current settings untouched.
        data["vpn"] = data.get("vpn") or {}
        data["vpn"].update(vpn)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    # record the applied preset so `status` (and the tray) can show it
    data["preset"] = name
    _atomic_write_config(config_path, data)
    return {"added": added, "mode": mode, "preset": name}


def add_custom_preset(root: Path, name: str, provider: str, domains: list[str],
                      mode: str = "vpn-list", default_provider: str | None = None) -> Path:
    """Create a custom named preset file under ``root/presets/``.

    Custom presets are the "make it yours" path: pick a name, a provider
    (proton, cloudflare, or any configured exit), and the domains that ride
    it. The remaining routing mode defaults to vpn-list (only these domains
    tunneled) — the configurable inverse of safe-list.
    """
    domain_list = [d for d in domains if d]
    if not domain_list:
        raise ValueError("preset needs at least one domain")
    routing: dict = {"mode": mode}
    if mode == "vpn-list":
        routing["vpn_domains"] = domain_list
    elif mode == "safe-list":
        routing["direct_domains"] = domain_list
        if default_provider:
            routing["default_provider"] = default_provider
    elif mode == "default":
        routing = {"mode": "default"}
    preset = {
        "routes": [{"id": name, "domains": domain_list, "provider": provider}],
        "routing": routing,
    }
    path = custom_preset_path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_config(path, preset)
    os.chmod(path, 0o600)
    return path


# ---------------------------------------------------------------------------
# non-interactive commands
# ---------------------------------------------------------------------------

def check(root) -> dict:
    """Report provider profile availability from ``root/router.json``.

    Network-free: every configured provider needs at least one valid
    ``*.conf`` profile in its directory. Returns ``{"ok": bool, "issues": []}``.
    """
    root = Path(root)
    config_file = root / "router.json"
    if not config_file.is_file():
        return {"ok": False, "issues": [f"missing {config_file}"]}
    try:
        data = json.loads(config_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "issues": [f"bad {config_file.name}: {exc}"]}
    providers = data.get("providers") or {}
    if not providers:
        return {"ok": False, "issues": ["no providers configured in router.json"]}
    issues: list[str] = []
    for name, entry in providers.items():
        directory = root / (entry or {}).get("directory", f"providers/{name}")
        if not directory.is_dir():
            issues.append(f"provider '{name}': missing directory {directory}")
            continue
        if not any(validate_profile(p) for p in directory.glob("*.conf")):
            issues.append(f"provider '{name}': no valid .conf profile in {directory}")
    return {"ok": not issues, "issues": issues}


def _expand_paths(paths) -> list[Path]:
    """Expand ~ and glob patterns into a de-duplicated list of paths."""
    expanded: list[Path] = []
    seen: set[str] = set()
    for raw in paths:
        raw = os.path.expanduser(raw)
        if any(ch in raw for ch in "*?["):
            matches = sorted(glob.glob(raw))
            candidates = matches or [raw]
        else:
            candidates = [raw]
        for candidate in candidates:
            key = os.path.abspath(candidate)
            if key not in seen:
                seen.add(key)
                expanded.append(Path(candidate))
    return expanded


def _merge_results(results: list[dict]) -> dict:
    return {
        "imported": sum(r["imported"] for r in results),
        "rejected": sum(r["rejected"] for r in results),
        "files": [f for r in results for f in r["files"]],
        "rejected_files": [f for r in results for f in r["rejected_files"]],
    }


def _cmd_guide(provider: str) -> int:
    text = guide_text(provider)
    if not text:
        print(f"setup: no guide available for '{provider}'", file=sys.stderr)
        return 1
    print(_style(f"--- {_tint_provider(provider)} setup guide ---", _Ansi.BOLD, _Ansi.CYAN))
    print(text)
    return 0


def _cmd_check(root: Path) -> int:
    result = check(root)
    if result["ok"]:
        print(_style("setup: ok - every provider has at least one valid profile", _Ansi.GREEN))
        return 0
    for issue in result["issues"]:
        print(_style(f"setup: {issue}", _Ansi.RED), file=sys.stderr)
    print(_style("setup: check failed", _Ansi.RED), file=sys.stderr)
    return 1


def _cmd_import(root: Path, provider: str, paths) -> int:
    destination = root / "providers" / provider
    sources = _expand_paths(paths) or [Path(paths[0])]
    merged = _merge_results([import_profiles(src, destination) for src in sources])
    if merged["imported"]:
        print(_style(
            f"setup: imported {merged['imported']} profile(s) into providers/{provider}",
            _Ansi.GREEN,
        ))
        for name in merged["files"]:
            print(_style(f"  + {name}", _Ansi.DIM))
    for entry in merged["rejected_files"]:
        print(_style(f"  - {entry['name']}: {entry['reason']}", _Ansi.YELLOW))
    if merged["rejected"]:
        print(_style(f"setup: rejected {merged['rejected']} file(s)", _Ansi.YELLOW))
    return 0 if merged["imported"] else 1


def _cmd_autocheck(root: Path, preset: str | None, overrides: dict) -> int:
    try:
        settings = configure_autocheck(root / "router.json", preset, **overrides)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(_style(f"setup: autocheck configuration failed: {exc}", _Ansi.RED), file=sys.stderr)
        return 1
    state = "enabled" if settings["enabled"] else "disabled"
    print(_style(f"setup: autocheck {state} ({settings['preset']})", _Ansi.GREEN))
    print(
        "setup: interval={interval}s, probe_every={probe_every}, sweep_every={sweep_every}s, "
        "dead_strikes={dead_strikes}, max_rotations={max_rotations}".format(**settings)
    )
    print("setup: run `setup --keepalive-install` to load/reload the launchd supervisor.")
    return 0


def _cmd_preset(root: Path) -> int:
    config_path = root / "router.json"
    try:
        result = apply_presets(config_path)
    except (json.JSONDecodeError, OSError) as exc:
        print(_style(f"setup: preset failed: {exc}", _Ansi.RED), file=sys.stderr)
        return 1
    if result["added"]:
        print(_style(_tint_provider("setup: added route preset(s): " + ", ".join(result["added"])), _Ansi.GREEN))
    else:
        print(_style(_tint_provider("setup: route presets already applied (nothing to add)"), _Ansi.GREEN))
    print(f"setup: wrote {config_path}")
    return 0


def _cmd_preset_prompt(root: Path) -> int:
    """Line-menu flow: pick a preset by name (built-in or custom) and apply it,
    or create a new custom preset interactively."""
    names = preset_names(root)
    if not names:
        print(_style("  no presets available", _Ansi.RED), file=sys.stderr)
        return 1
    print(_style("  available presets: " + ", ".join(names), _Ansi.BOLD))
    print(_style("  create a new one with:  new", _Ansi.BOLD))
    name = input("  preset name (empty cancels, 'new' creates): ").strip().lower()
    if not name:
        return 1
    if name == "new":
        return _cmd_preset_create_prompt(root)
    if name not in names:
        print(_style(f"  unknown preset '{name}' — use one of: {', '.join(names)}", _Ansi.RED), file=sys.stderr)
        return 1
    try:
        result = apply_preset_by_name(root, name)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(_style(f"  preset apply failed: {exc}", _Ansi.RED), file=sys.stderr)
        return 1
    label = f"preset '{result['preset']}' applied — routing={result['mode']}"
    if result["added"]:
        label += f", added route(s): {', '.join(result['added'])}"
    else:
        label += " (already present, nothing added)"
    print(_style(_tint_provider(label), _Ansi.GREEN))
    print("  run menu item 8 (`ensure`) to apply; engine untouched for now.")
    return 0


def _cmd_preset_create_prompt(root: Path) -> int:
    """Line-menu create flow: name -> provider -> comma-separated domains.
    Writes the preset file only; the engine is never started here."""
    try:
        name = input("  new preset name (empty cancels): ").strip().lower()
        if not name:
            return 1
        try:
            custom_preset_path(root, name)  # validates the name
        except ValueError as exc:
            print(_style(f"  {exc}", _Ansi.RED), file=sys.stderr)
            return 1
        if name in preset_names(root):
            print(_style(f"  preset '{name}' already exists — pick another name", _Ansi.RED), file=sys.stderr)
            return 1
        provider = input("  provider for this preset (proton / cloudflare / other): ").strip()
        if not provider:
            print(_style("  provider cannot be empty", _Ansi.RED), file=sys.stderr)
            return 1
        domain_text = input("  domains to tunnel, comma-separated (e.g. opencode.ai,roblox.com): ").strip()
        if not domain_text:
            print(_style("  at least one domain is required", _Ansi.RED), file=sys.stderr)
            return 1
        path = add_custom_preset(root, name, provider,
                                 [d.strip() for d in domain_text.split(",") if d.strip()])
    except (EOFError, KeyboardInterrupt):
        print()
        return 130
    except (ValueError, OSError) as exc:
        print(_style(f"  preset create failed: {exc}", _Ansi.RED), file=sys.stderr)
        return 1
    print(_style(f"  custom preset '{name}' written to {path.relative_to(root or Path('.'))} (not applied)", _Ansi.GREEN))
    print("  apply it now with 's', or from the tray: Presets → your name")
    return 0


# ---------------------------------------------------------------------------
# Hermes OpenCode auto-rotation bridge
# ---------------------------------------------------------------------------

def bridge_root() -> Path:
    """Machine-level VPN root that the Hermes rotation plugin expects.

    ``OPENCODE_ZEN_VPN_ROOT`` env override, else a generic per-user default
    (the installer prefix convention). ``expanduser`` so ``~`` prefixes work
    in the env value.
    """
    return Path(
        os.environ.get(
            "OPENCODE_ZEN_VPN_ROOT",
            os.path.join(os.path.expanduser("~"), ".local", "share", "opencode-zen-vpn"),
        )
    ).expanduser()


def _hermes_config_path() -> Path:
    """Hermes config path, resolved from env at call time (default module global)."""
    return Path(os.environ.get("HERMES_CONFIG", _HERMES_CONFIG_DEFAULT)).expanduser()


def _hermes_plugin_enabled() -> bool:
    """Best-effort: is ``opencode-server-rotation`` listed under a plugins: block?

    Read-only and never fatal: an unreadable/missing config reports not
    enabled. A simple scan of parsed lines keeps this dependency-free.
    """
    try:
        lines = _hermes_config_path().read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return False
    section = ""
    for line in lines:
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
        if section == "plugins" and "opencode-server-rotation" in line:
            return True
    return False


def _cmd_bridge_check(root: Path | None = None) -> int:
    """Verify the Hermes rotation bridge; no side effects, one line per check.

    ``root`` is accepted for CLI symmetry but placement always comes from
    ``OPENCODE_ZEN_VPN_ROOT`` (this is a machine-level Hermes integration,
    not a repo file). The Hermes plugin-enabled line is informational only
    and does not affect the exit code.
    """
    manager = bridge_root() / "proxy-manager.sh"
    ok = True

    if manager.is_file():
        print(_style(f"bridge: manager present ({manager})", _Ansi.GREEN))
    else:
        print(_style(f"bridge: manager missing ({manager})", _Ansi.RED))
        ok = False

    if os.access(manager, os.X_OK):
        print(_style("bridge: executable", _Ansi.GREEN))
    else:
        print(_style("bridge: not executable", _Ansi.RED))
        ok = False

    if manager.is_file():
        try:
            result = subprocess.run(["bash", "-n", str(manager)], capture_output=True, text=True)
        except OSError as exc:
            print(_style(f"bridge: syntax check skipped (bash unavailable: {exc})", _Ansi.YELLOW))
        else:
            if result.returncode == 0:
                print(_style("bridge: syntax ok", _Ansi.GREEN))
            else:
                print(_style(f"bridge: syntax error: {result.stderr.strip() or result.stdout.strip()}", _Ansi.RED))
                ok = False
    else:
        print(_style("bridge: syntax check skipped (manager missing)", _Ansi.YELLOW))

    vpn_root = bridge_root()
    if os.environ.get("OPENCODE_ZEN_VPN_ROOT"):
        print(f"bridge: vpn root {vpn_root} (env OPENCODE_ZEN_VPN_ROOT)")
    else:
        print(f"bridge: vpn root {vpn_root} (default)")

    if _hermes_plugin_enabled():
        print(_style("bridge: hermes plugin enabled (opencode-server-rotation)", _Ansi.GREEN))
    else:
        print(_style("bridge: hermes plugin NOT enabled (add plugins: - opencode-server-rotation)", _Ansi.YELLOW))
    return 0 if ok else 1


def _cmd_bridge_install(root: Path, force: bool = False) -> int:
    """Install the Hermes OpenCode auto-rotation bridge and validate it.

    Copies ``examples/proxy-manager.sh`` to ``OPENCODE_ZEN_VPN_ROOT/
    proxy-manager.sh`` (a machine-level Hermes integration, not a repo
    config file), chmod 0755, then runs ``bash -n`` and removes the file
    on failure. Idempotent when content is already identical; refuses to
    overwrite a differing existing file unless ``force`` is set.
    """
    source = Path(__file__).resolve().parent / "examples" / "proxy-manager.sh"
    target_dir = bridge_root()
    target = target_dir / "proxy-manager.sh"

    try:
        payload = source.read_bytes()
    except OSError as exc:
        print(f"bridge: cannot read source {source}: {exc}", file=sys.stderr)
        return 1

    if target.is_file():
        try:
            if target.read_bytes() == payload:
                print(_style(f"bridge: already up to date ({target})", _Ansi.GREEN))
                return 0
        except OSError as exc:
            if not force:
                print(_style(f"bridge: existing {target} not readable ({exc})", _Ansi.RED), file=sys.stderr)
                return 1
        if not force:
            print(
                _style(
                    f"bridge: refusing to overwrite existing {target} "
                    "(use --bridge-force-install)",
                    _Ansi.YELLOW,
                ),
                file=sys.stderr,
            )
            return 1
    elif target.exists():
        if not force:
            print(_style(f"bridge: refusing to replace non-file path {target}", _Ansi.YELLOW), file=sys.stderr)
            return 1

    created_dir = not target_dir.is_dir()
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        if created_dir:
            os.chmod(target_dir, 0o700)
        shutil.copy2(source, target)
        os.chmod(target, 0o755)
    except OSError as exc:
        print(f"bridge: install failed: {exc}", file=sys.stderr)
        return 1

    try:
        result = subprocess.run(["bash", "-n", str(target)], capture_output=True, text=True)
    except OSError as exc:
        print(f"bridge: bash unavailable after install ({exc})", file=sys.stderr)
        return 1
    if result.returncode != 0:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        print(
            f"bridge: syntax check failed, removed {target}: "
            f"{result.stderr.strip() or result.stdout.strip()}",
            file=sys.stderr,
        )
        return 1
    print(_style(f"bridge: installed -> {target}", _Ansi.GREEN))
    return 0


def _cmd_keepalive_install(root: Path, remove: bool = False) -> int:
    """Install or remove the macOS launchd supervisor for unattended support."""
    script = root / "examples" / "install-launchd.sh"
    if not script.is_file():
        print(f"keepalive: installer missing: {script}", file=sys.stderr)
        return 1
    env = dict(os.environ)
    env["PROXY_ROUTER_DIR"] = str(root)
    command = ["bash", str(script)] + (["--remove"] if remove else [])
    try:
        result = subprocess.run(command, env=env, cwd=root)
    except OSError as exc:
        print(f"keepalive: installer failed: {exc}", file=sys.stderr)
        return 1
    return result.returncode


def _router_command(root: Path, *args: str, timeout: float = 120.0) -> int:
    """Run the existing router CLI against ``root`` (never enabled implicitly).

    A timeout keeps a hung router.py (stuck lock, dead upstream probe) from
    freezing the TUI key loop indefinitely; long-running mutations
    (rotate/sweep with settle windows) pass an explicit larger budget.
    Process-group timeout: when the deadline fires the router and any
    child sing-box keepalive are terminated together (start_new_session +
    killpg) so the TUI does not leave a detached engine behind.
    """
    script = Path(__file__).resolve().parent / "router.py"
    env = dict(os.environ, PROXY_ROUTER_ROOT=str(root))
    cmd = [sys.executable, str(script), *args]
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            print(f"setup: {' '.join(args)} timed out after {timeout:.0f}s "
                  "(still running in the background? check `router.py status`)",
                  file=sys.stderr)
            return 1
        # router.py writes diagnostics to stdout/stderr; surface them so the
        # TUI caller can see failures inline (mirrors old subprocess.run echo).
        if stdout:
            print(stdout, end="")
        if stderr:
            print(stderr, end="", file=sys.stderr)
        return proc.returncode if proc.returncode is not None else 1
    except OSError as exc:
        print(f"setup: could not run {script}: {exc}", file=sys.stderr)
        return 1


def _read_vpn_mode(root: Path) -> str:
    """Read the persisted TUN mode (state/mode, 'proxy' | 'tun') read-only."""
    try:
        mode = (Path(root) / "state" / "mode").read_text().strip()
    except OSError:
        mode = ""
    return mode if mode in ("proxy", "tun") else "proxy"


def _read_routing_state(root: Path) -> dict:
    """Read-only view of the persisted routing section (no mutation, no
    subprocess): the TUI renders from this; every change goes through the
    ``router.py routing`` CLI writer below."""
    try:
        data = json.loads((Path(root) / "router.json").read_text())
        routing = data.get("routing") or {}
        if not isinstance(routing, dict):
            routing = {}
    except (OSError, json.JSONDecodeError):
        routing = {}
    return {
        "mode": routing.get("mode", "default"),
        "direct_domains": list(routing.get("direct_domains", []) or []),
        "vpn_domains": list(routing.get("vpn_domains", []) or []),
        "default_provider": routing.get("default_provider"),
    }


def _routing_lines(root: Path) -> list[str]:
    state = _read_routing_state(root)
    direct = ", ".join(state["direct_domains"]) or "(none)"
    vpn = ", ".join(state["vpn_domains"]) or "(none)"
    return [
        f"mode: {state['mode']}",
        f"direct_domains: {direct}",
        f"vpn_domains: {vpn}",
        f"default_provider: {state['default_provider'] or '(none)'}",
    ]


def _read_rotation_state(root: Path) -> dict:
    """Read-only view of the persisted rotation block (no mutation, no
    subprocess): the TUI renders from this; every change goes through
    ``_cmd_rotation_set`` below."""
    try:
        data = json.loads((Path(root) / "router.json").read_text())
        rotation = data.get("rotation") or {}
        if not isinstance(rotation, dict):
            rotation = {}
    except (OSError, json.JSONDecodeError):
        rotation = {}
    return {
        "interval_seconds": rotation.get("interval_seconds", 0),
        "jitter_seconds": rotation.get("jitter_seconds", 300),
        "policy": rotation.get("policy", "latency"),
    }


def _rotation_lines(root: Path) -> list[str]:
    state = _read_rotation_state(root)
    policy_hint = ("autoroute" if state["policy"] == "least-recent" else "fastest exit wins")
    return [
        f"interval_seconds: {state['interval_seconds']}",
        f"jitter_seconds: {state['jitter_seconds']}",
        f"policy: {state['policy']} ({policy_hint})",
    ]


def _cmd_rotation_set(root: Path, key: str, value: str) -> None:
    """Write one rotation setting into router.json atomically (0600)."""
    if key not in ("interval_seconds", "jitter_seconds", "policy"):
        raise ValueError(f"unknown rotation setting '{key}'")
    path = Path(root) / "router.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"router.json unreadable ({exc})") from exc
    if key == "policy":
        if value not in ("latency", "least-recent"):
            raise ValueError("policy must be 'latency' or 'least-recent'")
        parsed = value
    else:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be an integer") from exc
        if parsed < 0:
            raise ValueError(f"{key} must be >= 0")
    rotation = dict(data.get("rotation") or {})
    rotation[key] = parsed
    data["rotation"] = rotation
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False,
                                     encoding="utf-8") as tmp:
        json.dump(data, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def _cmd_routing(root: Path) -> None:
    """Line-menu flow for routing modes. Every mutation shells out to the
    existing ``router.py routing`` CLI - one config writer, never a second
    mutation path - and the engine is never started or reloaded here."""
    while True:
        _router_command(root, "routing", "show")
        print(_style("  [1] set vpn-list   [2] set safe-list   [3] add direct   [4] remove direct"
                     "   [5] add vpn   [6] remove vpn   [b] back", _Ansi.BOLD))
        try:
            choice = input(_style("routing> ", _Ansi.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("b", "back", "q"):
            return
        if choice == "1":
            _router_command(root, "routing", "set", "--mode", "vpn-list")
        elif choice == "2":
            provider = input("  default provider (empty keeps the current one): ").strip()
            args = ["routing", "set", "--mode", "safe-list"]
            if provider:
                args += ["--default-provider", provider]
            _router_command(root, "routing", *args)
        elif choice == "3":
            domain = input("  domain to go DIRECT: ").strip()
            if domain:
                _router_command(root, "routing", "add", "--mode", "safe-list", "--domain", domain)
        elif choice == "4":
            domain = input("  domain to remove from the direct list: ").strip()
            if domain:
                _router_command(root, "routing", "remove", "--mode", "safe-list", "--domain", domain)
        elif choice == "5":
            domain = input("  domain to TUNNEL: ").strip()
            if domain:
                _router_command(root, "routing", "add", "--mode", "vpn-list", "--domain", domain)
        elif choice == "6":
            domain = input("  domain to remove from the vpn list: ").strip()
            if domain:
                _router_command(root, "routing", "remove", "--mode", "vpn-list", "--domain", domain)
        else:
            print(f"  unknown choice '{choice}'")


# ---------------------------------------------------------------------------
# interactive wizard
# ---------------------------------------------------------------------------

_BANNER = """
  proxy-router setup wizard
  -------------------------
  Control center: engine, providers, TUN, rotation, presets and health.
  The engine is only started when you explicitly pick item 1.
"""

_MENU = [
    ("1", "Start proxy-router (engine + tray autostart)"),
    ("2", "Stop proxy-router"),
    ("3", "Add a VPN provider (step-by-step wizard)"),
    ("4", "Settings: TUN mode, rotation & autoroute"),
    ("5", "Presets: browse / apply / create (built-in + custom)"),
    ("6", "Check provider health"),
    ("7", "Routing modes (show / switch / add-remove domain)"),
    ("8", "Install / verify the OpenCode bridge (Hermes rotation gateway)"),
    ("r", "Routing modes (show / switch / add-remove domain)"),
    ("s", "Presets: apply by name / create custom (built-in + custom)"),
    ("q", "Quit"),
]


def _print_menu() -> None:
    print(_style(_BANNER, _Ansi.CYAN))
    for key, label in _MENU:
        print(f"  {_style(key, _Ansi.BOLD)}  {_tint_provider(label)}")
    print()


def _prompt_import(root: Path, provider: str) -> None:
    label = "Proton VPN" if provider == "proton" else "Cloudflare WARP"
    try:
        answer = input(f"  path to .conf file or directory ({_tint_provider(label)}): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not answer:
        return
    _cmd_import(root, provider, [answer])


def _line_provider_wizard(root: Path) -> None:
    """Line-mode add-a-VPN-provider flow: pick provider, show guide, import."""
    while True:
        print(_style("  [1] Proton VPN   [2] Cloudflare WARP   [b] back", _Ansi.BOLD))
        try:
            choice = input(_style("provider> ", _Ansi.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("b", "back", "q"):
            return
        if choice == "1":
            _cmd_guide("proton")
            _prompt_import(root, "proton")
            return
        if choice == "2":
            _cmd_guide("warp")
            _prompt_import(root, "cloudflare")
            return
        print(f"  unknown choice '{choice}'")


def _line_rotation(root: Path) -> None:
    """Line-mode rotation & autoroute settings (writes go through the CLI)."""
    while True:
        state = _read_rotation_state(root)
        print(_style(f"  interval_seconds: {state['interval_seconds']}  "
                     f"jitter_seconds: {state['jitter_seconds']}  policy: {state['policy']}", _Ansi.DIM))
        print(_style("  [1] interval   [2] jitter   [3] policy toggle   [b] back", _Ansi.BOLD))
        try:
            choice = input(_style("rotation> ", _Ansi.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("b", "back", "q"):
            return
        if choice == "1":
            value = input("  interval_seconds (0 = off): ").strip()
            if value:
                try:
                    _cmd_rotation_set(root, "interval_seconds", value)
                    print(_style(f"  rotation interval_seconds = {value}", _Ansi.GREEN))
                except ValueError as exc:
                    print(_style(f"  {exc}", _Ansi.RED))
        elif choice == "2":
            value = input("  jitter_seconds: ").strip()
            if value:
                try:
                    _cmd_rotation_set(root, "jitter_seconds", value)
                    print(_style(f"  rotation jitter_seconds = {value}", _Ansi.GREEN))
                except ValueError as exc:
                    print(_style(f"  {exc}", _Ansi.RED))
        elif choice == "3":
            new_policy = "least-recent" if state["policy"] == "latency" else "latency"
            _cmd_rotation_set(root, "policy", new_policy)
            print(_style(f"  rotation policy = {new_policy}", _Ansi.GREEN))
        else:
            print(f"  unknown choice '{choice}'")


def _line_settings(root: Path) -> None:
    """Line-mode settings: TUN mode toggle and rotation sub-flows."""
    while True:
        print(_style(f"  vpn mode: {_read_vpn_mode(root)}", _Ansi.DIM))
        print(_style("  [1] TUN mode toggle   [2] rotation & autoroute   [b] back", _Ansi.BOLD))
        try:
            choice = input(_style("settings> ", _Ansi.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("b", "back", "q"):
            return
        if choice == "1":
            target = "off" if _read_vpn_mode(root) == "tun" else "on"
            print(_style(f"  toggling TUN mode (vpn {target})...", _Ansi.YELLOW))
            rc = _router_command(root, "vpn", target)
            if rc == 0:
                print(_style(f"  TUN mode {target}", _Ansi.GREEN))
            else:
                print(_style("  vpn toggle failed (see router output above)", _Ansi.RED))
        elif choice == "2":
            _line_rotation(root)
        else:
            print(f"  unknown choice '{choice}'")


def _line_wizard(root: Path) -> int:
    """Line-based fallback: used whenever either stream is not a real TTY."""
    while True:
        _print_menu()
        try:
            choice = input(_style("setup> ", _Ansi.BOLD)).strip().lower()
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            return 130
        if choice in ("q", "quit"):
            return 0
        if choice == "1":
            print(_style("  starting proxy-router (start)...", _Ansi.YELLOW))
            # Explicit start is the reconnect contract: router.py clears the
            # manual-off marker and asks the canonical launchd tray to run.
            rc = _router_command(root, "start")
            if rc == 0:
                print(_style("  engine up (canonical tray autostart)", _Ansi.GREEN))
            else:
                print(_style("  engine failed to start (see router output above)", _Ansi.RED))
        elif choice == "2":
            print(_style("  stopping proxy-router...", _Ansi.YELLOW))
            rc = _router_command(root, "stop")
            if rc == 0:
                print(_style("  engine stopped", _Ansi.GREEN))
            else:
                print(_style("  engine stop failed (see router output above)", _Ansi.RED))
        elif choice == "3":
            _line_provider_wizard(root)
        elif choice == "4":
            _line_settings(root)
        elif choice in ("5", "s"):
            _cmd_preset_prompt(root)
        elif choice == "6":
            _cmd_check(root)
        elif choice in ("7", "r"):
            _cmd_routing(root)
        elif choice == "8":
            _cmd_bridge_install(root)
        else:
            print(f"  unknown choice '{choice}' (enter a number or 'q')")


# ---------------------------------------------------------------------------
# full-screen TUI: state, pure key handling and frame rendering
# ---------------------------------------------------------------------------

# TUI menu keeps the same actions plus Quit (digit 0; q/Q/ESC also quit).
# Home dashboard destinations. Screens are one key away; the dashboard
# itself summarizes the whole deployment (engine, mode, exits, pool health).
TUI_MENU = [
    ("1", "Servers: browse pools, pick exits, rotate"),
    ("2", "Routing: modes, domains, presets"),
    ("3", "Fallbacks: chains, on/off/status"),
    ("4", "Add a VPN provider (step-by-step wizard)"),
    ("5", "Settings: engine, TUN mode, rotation & autoroute"),
    ("6", "Check provider health"),
    ("e", "Start proxy-router (engine + tray autostart)"),
    ("x", "Stop proxy-router"),
    ("b", "Install / verify the OpenCode bridge (Hermes rotation gateway)"),
    ("r", "Routing: modes, domains, presets"),
    ("0", "Quit"),
]
TUI_MENU_INDEX = {key: index for index, (key, _) in enumerate(TUI_MENU)}

UP = "\x1b[A"
DOWN = "\x1b[B"
ESC = "\x1b"
ENTER = "\r"
BACKSPACE = "\x7f"
LEFT = "\x1b[D"
RIGHT = "\x1b[C"

_ANSI_ESC_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Remove ANSI SGR sequences so captured action output stays box-safe."""
    return _ANSI_ESC_RE.sub("", text)


@dataclasses.dataclass
class TuiState:
    """Pure TUI state; view is one of "home" | "servers" | "fallbacks" |
    "settings" | "guide" | "import" | "routing" | "routing_prompt" |
    "provider" | "rotation". """

    view: str = "home"
    cursor: int = 0
    guide_provider: str = "proton"
    guide_lines: list = dataclasses.field(default_factory=list)
    guide_scroll: int = 0
    import_provider: str = "proton"
    import_text: str = ""
    servers_provider: str = ""    # "" = first configured provider
    servers_cursor: int = 0
    fallbacks_provider: int = 0
    routing_lines: list = dataclasses.field(default_factory=list)
    routing_prompt_label: str = ""
    routing_prompt_text: str = ""
    routing_prompt_args: tuple = ()
    preset_browser: bool = False          # routing view showing presets (s), not routing actions
    preset_step: int = 0                  # 0=name, 1=provider, 2=domains
    preset_name: str = ""
    preset_provider: str = ""
    prompt_return_view: str = ""          # routing_prompt ESC/Enter lands here when set
    provider_wizard_import: bool = False  # guide view came from the provider wizard (offers i=import)
    status: str = ""
    status_ok: bool = True
    action: tuple | None = None  # recorded machine action for the wizard loop
    quit: bool = False
    cols: int = 80
    rows: int = 24
    root: Path = dataclasses.field(default_factory=lambda: _UNBOUND_ROOT)


def _initial_state(root: Path | None = None) -> TuiState:
    size = shutil.get_terminal_size((80, 24))
    state = TuiState(cols=max(size.columns, 40), rows=max(size.lines, 18))
    if root is not None:
        state.root = Path(root).resolve()
    return state


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def _fit_ansi(text: str, width: int) -> str:
    """_fit for strings that may carry ANSI styling: pad/clip by the
    VISIBLE width so colors never break column alignment."""
    plain = _ANSI_RE.sub("", text)
    if len(plain) > width:
        if width <= 1:
            return plain[:width]
        return plain[: width - 1] + "\u2026"
    return text + " " * (width - len(plain))


class _Theme:
    """Hermes-style presentation tokens: one accent, quiet chrome, state
    colors reused across every dashboard screen."""

    ACCENT = _Ansi.CYAN
    MUTED = _Ansi.ORANGE  # reuse the existing dim tone for hints/footers
    OK = "\x1b[32m"
    WARN = "\x1b[33m"
    ERR = "\x1b[31m"
    BOLD = _Ansi.BOLD
    RESET = _Ansi.RESET


def _fit(text: str, width: int) -> str:
    """Truncate/pad ``text`` to exactly ``width`` columns."""
    if len(text) > width:
        if width <= 1:
            return text[:width]
        return text[: width - 1] + "\u2026"  # horizontal ellipsis
    return text + " " * (width - len(text))


def _wrap_guide(text: str, width: int) -> list[str]:
    """Split guide markdown into screen lines wrapped to ``width``."""
    width = max(width, 10)
    lines: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            lines.append("")
        else:
            lines.extend(textwrap.wrap(line, width) or [""])
    return lines


def _render_chrome(title: str, body: list[str], state: TuiState, footer: str,
                   cursor_line: int | None = None,
                   chips: list[tuple[str, str]] | None = None) -> list[str]:
    """Bordered frame with scroll windowing, shared by the dashboard screens."""
    inner = max(state.cols - 2, 30)
    reserved = 7  # top, title, separator, separator, footer, bottom + margin
    visible = max(1, state.rows - reserved)
    window: list[str] = []
    if len(body) > visible:
        anchor = len(body) - 1 if cursor_line is None else max(0, min(cursor_line, len(body) - 1))
        half = visible // 2
        start = max(0, min(anchor - half, len(body) - visible))
        window = body[start:start + visible]
    else:
        window = body[:visible]
    if len(body) > visible:
        first = body.index(window[0]) + 1
        footer = f"{footer}  ·  lines {first}-{first + len(window) - 1}/{len(body)}"
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    header = _style(f" {title} ", _Theme.BOLD, _Theme.ACCENT)
    if chips:
        chip_text = " ".join(_style(text, _Theme.BOLD, color) for text, color in chips)
        pad = inner - _visible_len(header) - _visible_len(chip_text) - 1
        header = header + " " * max(1, pad) + chip_text
    lines.append("\u2502" + _fit_ansi(header, inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for line in window:
        lines.append("\u2502" + _fit_ansi(line, inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    lines.append("\u2502" + _style(_fit(footer, inner), _Theme.MUTED) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _tui_config(root: Path) -> dict:
    try:
        return json.loads((root / "router.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _tui_providers(root: Path) -> list[str]:
    providers = _tui_config(root).get("providers") or {}
    return [name for name in providers if isinstance(providers[name], dict)]


def _tui_active(root: Path, provider: str) -> str:
    try:
        return (root / "state" / f"{provider}.active").read_text().strip()
    except OSError:
        return ""


def _tui_process_argv(pid: int) -> list[str] | None:
    """Read one process's argument vector without shell-style reconstruction.

    macOS exposes original argv through KERN_PROCARGS2; errors return None.
    """
    if sys.platform != "darwin":
        return None
    try:
        import ctypes
        import struct

        libc = ctypes.CDLL(None, use_errno=True)
        sysctl = libc.sysctl
        sysctl.restype = ctypes.c_int
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t(0)
        if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            return None
        if not 4 < size.value <= 65536:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            return None
        payload = bytes(buffer.raw[:size.value])
        argc = struct.unpack_from("i", payload)[0]
        if argc < 1 or argc > 256:
            return None
        values = payload[4:].split(b"\\0")
        if len(values) < argc + 1:
            return None
        return [value.decode("utf-8", "surrogateescape") for value in values[:argc + 1]]
    except (AttributeError, OSError, UnicodeError, ValueError, struct.error):
        return None


def _tui_argv_matches_config(argv: list[str], config: Path) -> bool:
    if not argv or not Path(argv[0]).name.startswith("sing-box"):
        return False
    if "run" not in argv:
        return False
    for index, arg in enumerate(argv[:-1]):
        if arg in ("-c", "--config"):
            try:
                if Path(argv[index + 1]).resolve() == config:
                    return True
            except (OSError, RuntimeError):
                pass
    return False


def _tui_engine_up(root: Path) -> bool:
    """Prove PID belongs to sing-box running this checkout's config."""
    root = Path(root)
    try:
        pid = int((root / "sing-box.pid").read_text().strip())
        if pid <= 0:
            return False
    except (OSError, ValueError, UnicodeError):
        return False
    config = (root / "sing-box.json").resolve()
    argv = _tui_process_argv(pid)
    return argv is not None and _tui_argv_matches_config(argv, config)


def _tui_generated_mode(root: Path) -> str | None:
    """Return the mode represented by a generated sing-box config."""
    try:
        data = json.loads((Path(root) / "sing-box.json").read_text())
        inbounds = data.get("inbounds")
        if not isinstance(inbounds, list):
            return "unknown"
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return "unknown"
    return "tun" if any(
        isinstance(item, dict) and item.get("type") == "tun"
        for item in inbounds
    ) else "proxy"


def _tui_engine_state(root: Path) -> tuple[bool, str | None]:
    """Return (verified_up, verified_mode); stale PID state is unknown."""
    root = Path(root)
    pid_file = root / "sing-box.pid"
    if not pid_file.is_file():
        return False, None
    if not _tui_engine_up(root):
        return False, "unknown"
    return True, _tui_generated_mode(root)


def _tui_fallback_chain(provider: str, entry: dict) -> list[str]:
    raw = entry.get("fallback_providers")
    if raw is None:
        raw = entry.get("fallback_provider")
    if raw is None:
        return []
    return raw if isinstance(raw, list) else [raw]


def _tui_profiles(root: Path, provider: str) -> list[tuple[str, str]]:
    """(stem, marker) per profile: "ok" | "dead" | "cooling" | "".
    Reads the same state files the router writes; never spawns a probe."""
    config = _tui_config(root)
    directory = (config.get("providers") or {}).get(provider, {}).get("directory", f"providers/{provider}")
    confs = sorted((root / directory).glob("*.conf"))
    active = _tui_active(root, provider)
    now = time.time()
    rows: list[tuple[str, str]] = []
    for conf in confs:
        record = {}
        try:
            record = json.loads((root / "state" / "egress" / provider / f"{conf.stem}.json").read_text())
        except (OSError, json.JSONDecodeError):
            pass
        cooling = False
        try:
            until = int((root / "state" / "cooldowns" / provider / f"{conf.stem}.until").read_text().strip())
            cooling = until > now
        except (OSError, ValueError):
            pass
        # Records carry no signal forever: a probe verdict older than the
        # egress ok-window was typically written under long-gone network
        # conditions (or an era of dishonest probes) — render it as unprobed.
        try:
            window = int((config.get("egress") or {}).get("ok_window", 86400))
        except (TypeError, ValueError):
            window = 86400
        checked_at = record.get("checked_at")
        fresh = isinstance(checked_at, (int, float)) and now - float(checked_at) < window
        if record.get("blocked"):
            marker = "blocked"
        elif cooling:
            marker = "cooling"
        elif fresh and record.get("ok") is True:
            marker = "ok"
        elif fresh and record.get("ok") is False:
            marker = "dead"
        else:
            marker = ""
        if conf.stem == active:
            marker = {
                "blocked": "active-blocked",
                "cooling": "active-cooling",
                "ok": "active",
                "dead": "active-dead",
                "": "active-unknown",
            }[marker]
        rows.append((conf.stem, marker))
    return rows


def _tui_egress_age(root: Path, provider: str) -> float | None:
    """Seconds since the newest egress probe verdict; None if never probed."""
    newest: float | None = None
    try:
        records = sorted((Path(root) / "state" / "egress" / provider).glob("*.json"))
    except OSError:
        return None
    for record in records:
        try:
            checked = json.loads(record.read_text()).get("checked_at")
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(checked, (int, float)) and (newest is None or checked > newest):
            newest = float(checked)
    if newest is None:
        return None
    return max(0.0, time.time() - newest)


def _format_probe_age(age: float | None) -> str:
    if age is None:
        return "never probed"
    if age < 90:
        return "probed just now"
    if age < 3600:
        return f"probed {int(age // 60)}m ago"
    if age < 86400:
        return f"probed {int(age // 3600)}h ago"
    return f"probed {int(age // 86400)}d ago"


def _render_home(state: TuiState) -> list[str]:
    root = state.root
    config = _tui_config(root)
    desired_mode = _read_vpn_mode(root)
    engine_up, engine_mode = _tui_engine_state(root)
    if engine_up and engine_mode in {"proxy", "tun"}:
        engine = "UP"
        mode_chip = (engine_mode, _Theme.ACCENT)
    elif engine_up:
        engine = "UP (mode unknown)"
        mode_chip = ("mode unverified", _Theme.WARN)
    elif engine_mode == "unknown":
        engine = "unknown"
        mode_chip = ("mode unverified", _Theme.WARN)
    else:
        engine = "down"
        mode_chip = (f"configured {desired_mode}", _Theme.MUTED)
    engine_chip = (("\u25cf UP", _Theme.OK) if engine == "UP"
                   else ("\u26a0 unknown", _Theme.WARN) if engine == "unknown"
                   else ("\u25cb down", _Theme.MUTED))
    body: list[str] = [""]
    for provider in _tui_providers(root):
        entry = (config.get("providers") or {}).get(provider, {})
        profiles = _tui_profiles(root, provider)
        active = _tui_active(root, provider) or "-"
        active_marker = next((marker for stem, marker in profiles if stem == active), "")
        active_display = active
        if active_marker and active_marker != "active":
            active_display = f"{active} ({active_marker})"
        healthy = sum(1 for _stem, marker in profiles if marker in ("ok", "active"))
        stale = sum(1 for _stem, marker in profiles if marker in ("", "active-unknown"))
        chain = _tui_fallback_chain(provider, entry)
        chain_text = " -> ".join(chain) if chain else "-"
        stale_hint: str | None = None
        if healthy == 0 and stale:
            # No fresh verdicts: say the data is old, not that everything is dead.
            stale_hint = _format_probe_age(_tui_egress_age(root, provider))
            health = _style(f"0/{len(profiles)} fresh", _Theme.WARN)
        else:
            health = _style(f"{healthy}/{len(profiles)} healthy", _Theme.OK if healthy else _Theme.ERR)
        body.append(f" {_tint_provider(provider)}: exit {active_display} | {health} | fallback {chain_text}")
        if stale_hint is not None:
            body.append(f"   {_style('probe data ' + stale_hint + ' · [6] to refresh', _Theme.MUTED)}")
    status_height = len(body)
    body.append("")
    for index, (key, label) in enumerate(TUI_MENU):
        cursor = ">" if index == state.cursor % len(TUI_MENU) else " "
        body.append(f" {cursor} [{key}] {label}")
    return _render_chrome("proxy-router", body, state, "j/k move · enter select · h home · q quit",
                          cursor_line=status_height + state.cursor % len(TUI_MENU),
                          chips=[engine_chip, mode_chip])


def _render_servers(state: TuiState) -> list[str]:
    providers = _tui_providers(state.root)
    if not providers:
        return _render_chrome("servers", [" no providers configured - add one first (4)"],
                              state, "esc home")
    provider = state.servers_provider if state.servers_provider in providers else providers[0]
    state.servers_provider = provider
    profiles = _tui_profiles(state.root, provider)
    glyph_color = {"active": _Theme.OK, "ok": _Theme.OK, "dead": _Theme.ERR,
                   "cooling": _Theme.MUTED, "blocked": _Theme.WARN,
                   "active-dead": _Theme.ERR, "active-cooling": _Theme.MUTED,
                   "active-blocked": _Theme.WARN, "active-unknown": _Theme.MUTED,
                   "": _Theme.MUTED}
    glyphs = {"active": "\u25cf", "ok": "\u25cf", "dead": "\u2715", "cooling": "\u25cb", "blocked": "\u26a0",
              "active-dead": "\u2715", "active-cooling": "\u25cb",
              "active-blocked": "\u26a0", "active-unknown": "\u25cf", "": "\u00b7"}
    labels = {"active": "active", "ok": "ok", "dead": "dead", "cooling": "cooling", "blocked": "blocked",
              "active-dead": "active · dead", "active-cooling": "active · cooling",
              "active-blocked": "active · blocked", "active-unknown": "active · unprobed",
              "": "unprobed"}
    body = [f" {provider}  ({providers.index(provider) + 1}/{len(providers)})", ""]
    if not profiles:
        body.append(" no profiles imported for this provider")
    for index, (stem, marker) in enumerate(profiles):
        cursor = ">" if index == state.cursor % max(1, len(profiles)) else " "
        glyph = _style(glyphs.get(marker, "\u00b7"), glyph_color.get(marker, _Theme.MUTED))
        body.append(f" {cursor} {glyph} {stem}  {labels.get(marker, '')}")
    return _render_chrome("servers", body, state,
                          "h/l provider · j/k exit · r rotate · enter set active · esc home",
                          chips=[(_tint_provider(provider), _Theme.BOLD)])


def _render_fallbacks(state: TuiState) -> list[str]:
    providers = _tui_providers(state.root)
    if not providers:
        return _render_chrome("fallbacks", [" no providers configured"], state, "esc home")
    index = state.fallbacks_provider % len(providers)
    provider = providers[index]
    entry = (_tui_config(state.root).get("providers") or {}).get(provider, {})
    chain = _tui_fallback_chain(provider, entry)
    active = ""
    try:
        marker = json.loads((state.root / "state" / "fallback" / f"{provider}.json").read_text())
        active = marker.get("provider", "")
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    body = [
        f" provider: {provider}  ({index + 1}/{len(providers)})",
        "",
        f" chain:  {' -> '.join(chain) if chain else '(none configured)'}",
        f" active: {_style(active or 'none', _Theme.OK if active else _Theme.MUTED)}",
    ]
    return _render_chrome("fallbacks", body, state, "h/l provider · 1 failover on · 2 failover off · esc home",
                          chips=[(_tint_provider(provider), _Theme.BOLD)])


def _render_menu(state: TuiState) -> list[str]:
    inner = max(state.cols - 2, 30)
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    header = _style(_fit(" proxy-router setup ", inner), _Ansi.BOLD, _Ansi.CYAN)
    lines.append("\u2502" + header + "\u2502")
    lines.append("\u2502" + _fit(" Guides \u00b7 imports \u00b7 presets \u00b7 health checks ", inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    # Scroll window keeps the cursor row visible; fixed overhead is 9 rows.
    total = len(TUI_MENU)
    visible = max(state.rows - 9, 1)
    scroll = min(max(state.cursor - visible + 1, 0), max(total - visible, 0))
    for index in range(visible):
        item_index = scroll + index
        if item_index >= total:
            break
        key, label = TUI_MENU[item_index]
        right = f" {key} "
        prefix = f"  {key}  "
        fitted = _fit(prefix + label, inner - len(right))
        label_plain = fitted[len(prefix):]
        label_tint = _tint_provider(label_plain)
        if item_index == state.cursor:
            row = "\u2502" + prefix + label_tint + right + "\u2502"
            lines.append(_style(row, _Ansi.REVERSE))
        else:
            lines.append("\u2502" + _style(prefix, _Ansi.CYAN) + label_tint + right + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    status_lines = [ln for ln in state.status.splitlines() if ln.strip()] or ["Ready \u2014 pick an item."]
    for ln in status_lines[-2:]:
        plain = _strip_ansi(ln)
        if plain.strip() == "Ready \u2014 pick an item.":
            styled = _style(_fit(" " + plain, inner), _Ansi.DIM)
        elif state.status_ok:
            styled = _style(_fit(" " + plain, inner), _Ansi.GREEN)
        else:
            styled = _style(_fit(" " + plain, inner), _Ansi.RED)
        lines.append("\u2502" + styled + "\u2502")
    if total > visible:
        hint = " \u2191\u2193 navigate \u00b7 Enter select \u00b7 q/ESC quit \u00b7 item {}-{}/{} ".format(
            scroll + 1, min(scroll + visible, total), total)
    else:
        hint = " \u2191\u2193 navigate \u00b7 Enter select \u00b7 q/ESC quit "
    lines.append("\u2502" + _style(_fit(hint, inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_guide(state: TuiState) -> list[str]:
    inner = max(state.cols - 2, 30)
    titles = {
        "proton": "Show Proton VPN guide",
        "warp": "Show Cloudflare WARP guide",
        "all": "Show both guides",
    }
    title = titles.get(state.guide_provider, "Guide")
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    title_fit = _fit(f" {title} ", inner)
    lines.append("\u2502" + _style(_tint_provider(title_fit), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    visible = max(state.rows - 5, 1)
    scroll = min(state.guide_scroll, max(0, len(state.guide_lines) - visible))
    for index in range(visible):
        src = state.guide_lines[scroll + index] if scroll + index < len(state.guide_lines) else ""
        lines.append("\u2502" + _fit(src, inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    total = len(state.guide_lines)
    shown = min(scroll + 1, total) if total else 0
    hint = " line {}/{} \u00b7 \u2191\u2193 scroll \u00b7 i import \u00b7 q back ".format(shown, total) \
        if state.provider_wizard_import else " line {}/{} \u00b7 \u2191\u2193 scroll \u00b7 q back ".format(shown, total)
    lines.append("\u2502" + _style(_fit(hint, inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_import(state: TuiState) -> list[str]:
    inner = max(state.cols - 2, 30)
    title = (
        "Import Proton VPN profiles"
        if state.import_provider == "proton"
        else "Import Cloudflare WARP profiles"
    )
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    title_fit = _fit(f" {title} ", inner)
    lines.append("\u2502" + _style(_tint_provider(title_fit), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    path_display = state.import_text or "no path yet"
    lines.append("\u2502" + _fit(" path: " + path_display, inner) + "\u2502")
    lines.append("\u2502" + _style(_fit(" Enter submits \u00b7 ESC cancels \u00b7 backspace edits ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


_ROUTING_ACTIONS = [
    ("1", "switch to vpn-list (only listed domains tunneled)"),
    ("2", "switch to safe-list (everything else via default_provider)"),
    ("3", "add domain to the direct list"),
    ("4", "remove domain from the direct list"),
    ("5", "add domain to the vpn list"),
    ("6", "remove domain from the vpn list"),
    ("7", "apply a preset by name (built-in or custom)"),
]
_PRESET_ACTIONS = [
    ("1", "apply a preset by name (built-in or custom)"),
    ("2", "create a new preset (name, provider, domain)"),
]
_PRESET_PROMPT_LABEL = "preset name to apply (built-in or custom):"
_ROTATION_ACTIONS = [
    ("1", "interval_seconds (0 = off)"),
    ("2", "jitter_seconds (default 300)"),
    ("3", "policy: latency <-> least-recent (autoroute)"),
]
_SETTINGS_ACTIONS = [
    ("1", "TUN mode toggle (proxy <-> full tunnel)"),
    ("2", "rotation & autoroute settings"),
]
_PROVIDER_WIZARD_STEPS = [
    ("1", "Proton VPN (step-by-step guide)"),
    ("2", "Cloudflare WARP (step-by-step guide)"),
]
_PRESET_CREATE_LABELS = [
    "new preset name (e.g. banana):",
    "provider for the preset (proton / cloudflare):",
    "domain(s) to route (comma-separated, e.g. opencode.ai):",
]


def _render_routing(state: TuiState) -> list[str]:
    """Routing-modes view (r) or presets browser (s). Rendered read-only;
    every change is executed by the wizard loop through the router CLI
    (routing) or add_custom_preset (preset create)."""
    inner = max(state.cols - 2, 30)
    if state.preset_browser:
        title = " presets "
        lines = ["\u250c" + "\u2500" * inner + "\u2510"]
        lines.append("\u2502" + _style(_fit(title, inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
        lines.append("\u251c" + "\u2500" * inner + "\u2524")
        for ln in state.routing_lines:
            lines.append("\u2502" + _fit(" " + ln, inner) + "\u2502")
        lines.append("\u251c" + "\u2500" * inner + "\u2524")
        for key, label in _PRESET_ACTIONS:
            lines.append("\u2502" + _style(_fit(f"  {key}  {label}", inner), _Ansi.CYAN) + "\u2502")
        lines.append("\u251c" + "\u2500" * inner + "\u2524")
        lines.append("\u2502" + _style(_fit(" 1-2 change \u00b7 ESC back ", inner), _Ansi.DIM) + "\u2502")
        lines.append("\u2514" + "\u2500" * inner + "\u2518")
        return lines
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(" routing modes ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for ln in state.routing_lines:
        lines.append("\u2502" + _fit(" " + ln, inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for key, label in _ROUTING_ACTIONS:
        lines.append("\u2502" + _style(_fit(f"  {key}  {label}", inner), _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    lines.append("\u2502" + _style(_fit(" 1-7 change \u00b7 writes go through the router CLI \u00b7 ESC back ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_routing_prompt(state: TuiState) -> list[str]:
    """Single-field text input for routing mutations (domain/provider)."""
    inner = max(state.cols - 2, 30)
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(" routing input ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    lines.append("\u2502" + _fit(" " + (state.routing_prompt_label or "input:"), inner) + "\u2502")
    display = state.routing_prompt_text or "no input yet"
    lines.append("\u2502" + _fit(" input: " + display, inner) + "\u2502")
    lines.append("\u2502" + _style(_fit(" Enter submits \u00b7 ESC cancels \u00b7 backspace edits ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_provider(state: TuiState) -> list[str]:
    """Add-a-VPN-provider wizard step: pick which provider to set up."""
    inner = max(state.cols - 2, 30)
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(" add a vpn provider ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for key, label in _PROVIDER_WIZARD_STEPS:
        lines.append("\u2502" + _style(_fit(f"  {key}  {label}", inner), _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    lines.append("\u2502" + _style(_fit(" 1-2 pick a provider \u00b7 ESC back ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_rotation(state: TuiState) -> list[str]:
    """Rotation & autoroute settings view: read-only lines, every change
    flows through the ``('rotation_set', ...)`` action to ``_cmd_rotation_set``."""
    inner = max(state.cols - 2, 30)
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(" rotation & autoroute ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for ln in _rotation_lines(state.root):
        lines.append("\u2502" + _fit(" " + ln, inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for key, label in _ROTATION_ACTIONS:
        lines.append("\u2502" + _style(_fit(f"  {key}  {label}", inner), _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    lines.append("\u2502" + _style(_fit(" 1-3 change \u00b7 writes router.json \u00b7 ESC back ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def _render_settings(state: TuiState) -> list[str]:
    """Settings view: one entry point for TUN mode and rotation settings."""
    inner = max(state.cols - 2, 30)
    lines = ["\u250c" + "\u2500" * inner + "\u2510"]
    lines.append("\u2502" + _style(_fit(" settings ", inner), _Ansi.BOLD, _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    vpn = _read_vpn_mode(state.root)
    lines.append("\u2502" + _fit(f" vpn mode: {vpn} (proxy mode or full TUN capture)", inner) + "\u2502")
    rot = _read_rotation_state(state.root)
    lines.append("\u2502" + _fit(f" rotation: interval {rot['interval_seconds']}s \u00b7 "
                                 f"jitter {rot['jitter_seconds']}s \u00b7 policy {rot['policy']}", inner) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    for key, label in _SETTINGS_ACTIONS:
        lines.append("\u2502" + _style(_fit(f"  {key}  {label}", inner), _Ansi.CYAN) + "\u2502")
    lines.append("\u251c" + "\u2500" * inner + "\u2524")
    lines.append("\u2502" + _style(_fit(" 1-2 change \u00b7 ESC back ", inner), _Ansi.DIM) + "\u2502")
    lines.append("\u2514" + "\u2500" * inner + "\u2518")
    return lines


def render_frame(state: TuiState) -> list[str]:
    """Build the full frame (header, body, footer) as a list of screen lines."""
    if state.view == "home":
        return _render_home(state)
    if state.view == "servers":
        return _render_servers(state)
    if state.view == "fallbacks":
        return _render_fallbacks(state)
    if state.view == "guide":
        return _render_guide(state)
    if state.view == "import":
        return _render_import(state)
    if state.view == "routing":
        return _render_routing(state)
    if state.view == "routing_prompt":
        return _render_routing_prompt(state)
    if state.view == "provider":
        return _render_provider(state)
    if state.view == "rotation":
        return _render_rotation(state)
    if state.view == "settings":
        return _render_settings(state)
    return _render_menu(state)


def _open_guide(state: TuiState, provider: str) -> None:
    text = guide_text(provider)
    if not text:
        state.status = f"no {provider} guide available"
        state.status_ok = False
        return
    state.view = "guide"
    state.guide_provider = provider
    state.guide_lines = _wrap_guide(text, max(state.cols - 4, 20))
    state.guide_scroll = 0


def _select_item(state: TuiState, index: int) -> TuiState:
    """Enter/digit selection: switch view or record a machine action."""
    key, _ = TUI_MENU[index]
    if key == "0":
        state.quit = True
    elif key == "1":
        state.view = "servers"
        state.servers_provider = ""
        state.servers_cursor = 0
    elif key in ("2", "r"):
        state.view = "routing"
        state.preset_browser = False
        state.routing_lines = _routing_lines(state.root) or ["routing modes"]
        state.routing_prompt_text = ""
    elif key == "3":
        state.view = "fallbacks"
    elif key == "4":
        state.view = "provider"
    elif key == "5":
        state.view = "settings"
    elif key == "e":
        state.action = ("engine_start",)
    elif key == "x":
        state.action = ("engine_stop",)
    elif key == "b":
        state.action = ("bridge_install",)
    elif key == "6":
        state.action = ("check",)
    elif key == "s":
        # Preset browser: renders read-only, mutation flows through
        # state.action like routing changes.
        state.view = "routing"
        state.preset_browser = True
        try:
            names = preset_names(state.root)
            state.routing_lines = ["presets: " + (", ".join(names) if names else "(none)")]
        except OSError:
            state.routing_lines = ["presets: (unreadable)"]
        state.routing_prompt_text = ""
    return state


def apply_key(state: TuiState, key: str) -> TuiState:
    """Advance the TUI by one key event; returns a new state.

    Pure with respect to the terminal: never writes to the screen and never
    runs machine actions directly. Imports/presets/check/engine record
    ``state.action`` for the wizard loop to execute through the existing
    ``_cmd_*`` helpers, keeping business logic identical to today.
    """
    state = copy.copy(state)
    state.action = None

    if key in ("h", "H") and state.view not in ("home", "routing_prompt", "import"):
        # one-key return to the dashboard from anywhere
        state.view = "home"
        return state

    if state.view == "home":
        if key in (UP, "k", "K"):
            state.cursor = (state.cursor - 1) % len(TUI_MENU)
        elif key in (DOWN, "j", "J"):
            state.cursor = (state.cursor + 1) % len(TUI_MENU)
        elif key in ("q", "Q", ESC, "\x03", "\x04"):
            state.quit = True
        elif key in (ENTER, "\n"):
            return _select_item(state, state.cursor)
        elif key in TUI_MENU_INDEX:
            state.cursor = TUI_MENU_INDEX[key]
            return _select_item(state, state.cursor)
        return state

    if state.view == "servers":
        providers = _tui_providers(state.root)
        if not providers:
            if key in (ESC, "q", "Q"):
                state.view = "home"
            return state
        if not state.servers_provider or state.servers_provider not in providers:
            state.servers_provider = providers[0]
        profiles = _tui_profiles(state.root, state.servers_provider)
        if key in (ESC, "q", "Q"):
            state.view = "home"
        elif key in ("h", "H") or key == LEFT:
            index = providers.index(state.servers_provider)
            state.servers_provider = providers[(index - 1) % len(providers)]
            state.servers_cursor = 0
        elif key in ("l", "L") or key == RIGHT:
            index = providers.index(state.servers_provider)
            state.servers_provider = providers[(index + 1) % len(providers)]
            state.servers_cursor = 0
        elif key in (UP, "k", "K") and profiles:
            state.servers_cursor = (state.servers_cursor - 1) % len(profiles)
        elif key in (DOWN, "j", "J") and profiles:
            state.servers_cursor = (state.servers_cursor + 1) % len(profiles)
        elif key in ("r", "R"):
            state.action = ("rotate_provider", state.servers_provider)
        elif key in (ENTER, "\n") and profiles:
            stem, _state = profiles[state.servers_cursor]
            state.action = ("rotate_to", state.servers_provider, stem)
        return state

    if state.view == "fallbacks":
        providers = _tui_providers(state.root)
        if key in (ESC, "q", "Q"):
            state.view = "home"
        elif providers and key in ("h", "H", LEFT):
            state.fallbacks_provider = (state.fallbacks_provider - 1) % len(providers)
        elif providers and key in ("l", "L", RIGHT):
            state.fallbacks_provider = (state.fallbacks_provider + 1) % len(providers)
        elif providers and key in ("1",):
            state.action = ("failover_on", providers[state.fallbacks_provider % len(providers)])
        elif providers and key in ("2",):
            state.action = ("failover_off", providers[state.fallbacks_provider % len(providers)])
        return state

    if state.view == "guide":
        if key in ("q", "Q", ESC, ENTER, "\n"):
            state.view = "provider" if state.provider_wizard_import else "home"
        elif key in ("i", "I") and state.provider_wizard_import:
            # Offer one-click jump to profile import for the wizard's provider.
            state.view = "import"
            state.import_provider = "cloudflare" if state.guide_provider == "warp" else "proton"
            state.import_text = ""
        elif key in (UP, "k", "K"):
            state.guide_scroll = max(0, state.guide_scroll - 1)
        elif key in (DOWN, "j", "J"):
            visible = max(1, state.rows - 5)
            max_scroll = max(0, len(state.guide_lines) - visible)
            state.guide_scroll = min(state.guide_scroll + 1, max_scroll)
        return state

    if state.view == "provider":
        if key in (ESC, "q", "Q"):
            state.view = "home"
        elif key == "1":
            _open_guide(state, "proton")
            state.provider_wizard_import = True
        elif key == "2":
            _open_guide(state, "warp")
            state.provider_wizard_import = True
        return state

    if state.view == "settings":
        if key in (ESC, "q", "Q"):
            state.view = "home"
        elif key == "1":
            state.action = ("vpn_toggle",)
        elif key == "2":
            state.view = "rotation"
        return state

    if state.view == "rotation":
        if key in (ESC, "q", "Q"):
            state.view = "settings"
        elif key in ("1", "2"):
            setting = "interval_seconds" if key == "1" else "jitter_seconds"
            state.view = "routing_prompt"
            state.prompt_return_view = "rotation"
            state.routing_prompt_label = f"{setting} (0 = off for interval):"
            state.routing_prompt_args = ("rotation_set", setting, "{TEXT}")
        elif key == "3":
            # policy toggle: latency <-> least-recent (autoroute)
            current = _read_rotation_state(state.root)["policy"]
            state.action = ("rotation_set", "policy",
                            "least-recent" if current == "latency" else "latency")
        return state

    if state.view == "import":
        if key == ESC:
            state.view = "provider" if state.provider_wizard_import else "home"
        elif key in (ENTER, "\n"):
            path = state.import_text.strip()
            state.view = "home"
            if not path:
                state.status = "import cancelled: empty path"
                state.status_ok = False
            else:
                state.action = ("import", state.import_provider, path)
        elif key in (BACKSPACE, "\x08"):
            state.import_text = state.import_text[:-1]
        elif key and len(key) == 1 and ord(key) >= 32:
            if len(state.import_text) < max(state.cols * 4, 256):
                state.import_text += key
        return state

    if state.view == "routing":
        if key in (ESC, "q", "Q"):
            state.view = "home"
        elif state.preset_browser:
            if key == "1":
                state.view = "routing_prompt"
                state.routing_prompt_label = _PRESET_PROMPT_LABEL
                state.routing_prompt_args = ("preset_by_name", "{TEXT}")
            elif key == "2":
                state.view = "routing_prompt"
                state.preset_step = 0
                state.preset_name = state.preset_provider = ""
                state.routing_prompt_label = _PRESET_CREATE_LABELS[0]
            return state
        elif key == "1":
            state.action = ("routing", "set", "--mode", "vpn-list")
        elif key == "2":
            if _read_routing_state(state.root).get("default_provider"):
                state.action = ("routing", "set", "--mode", "safe-list")
            else:
                state.view = "routing_prompt"
                state.routing_prompt_label = "default provider for safe-list (e.g. proton):"
                state.routing_prompt_args = ("routing", "set", "--mode", "safe-list",
                                             "--default-provider", "{TEXT}")
        elif key == "3":
            state.view = "routing_prompt"
            state.routing_prompt_label = "domain to go DIRECT (safe-list):"
            state.routing_prompt_args = ("routing", "add", "--mode", "safe-list", "--domain", "{TEXT}")
        elif key == "4":
            state.view = "routing_prompt"
            state.routing_prompt_label = "domain to remove from the DIRECT list (safe-list):"
            state.routing_prompt_args = ("routing", "remove", "--mode", "safe-list", "--domain", "{TEXT}")
        elif key == "5":
            state.view = "routing_prompt"
            state.routing_prompt_label = "domain to TUNNEL (vpn-list):"
            state.routing_prompt_args = ("routing", "add", "--mode", "vpn-list", "--domain", "{TEXT}")
        elif key == "6":
            state.view = "routing_prompt"
            state.routing_prompt_label = "domain to remove from the VPN list (vpn-list):"
            state.routing_prompt_args = ("routing", "remove", "--mode", "vpn-list", "--domain", "{TEXT}")
        elif key == "7":
            state.view = "routing_prompt"
            state.routing_prompt_label = _PRESET_PROMPT_LABEL
            state.routing_prompt_args = ("preset_by_name", "{TEXT}")
        return state

    if state.view == "routing_prompt":
        if key == ESC:
            state.view = state.prompt_return_view or ("routing" if state.preset_browser else "home")
            state.preset_step = 0
            state.prompt_return_view = ""
        elif key in (ENTER, "\n"):
            text = state.routing_prompt_text.strip()
            if state.preset_browser and state.preset_step < 2:
                # create-preset flow: name (0) -> provider (1) -> domains (2)
                if not text:
                    state.status = "preset create cancelled: empty input"
                    state.status_ok = False
                elif state.preset_step == 0:
                    state.preset_name = text
                    state.preset_step = 1
                    state.routing_prompt_label = _PRESET_CREATE_LABELS[1]
                elif state.preset_step == 1:
                    state.preset_provider = text
                    state.preset_step = 2
                    state.routing_prompt_label = _PRESET_CREATE_LABELS[2]
                state.routing_prompt_text = ""
            elif state.preset_browser and state.preset_step == 2:
                # final create-flow step: domains -> fire preset_create action
                state.view = "routing"
                state.preset_step = 0
                if not text:
                    state.status = "preset create cancelled: empty domain"
                    state.status_ok = False
                else:
                    state.action = ("preset_create", state.preset_name,
                                    state.preset_provider, text)
            else:
                state.view = state.prompt_return_view or ("routing" if state.preset_browser else "home")
                state.prompt_return_view = ""
                if not text:
                    state.status = "routing change cancelled: empty input"
                    state.status_ok = False
                else:
                    state.action = tuple(text if part == "{TEXT}" else part for part in state.routing_prompt_args)
        elif key in (BACKSPACE, "\x08"):
            state.routing_prompt_text = state.routing_prompt_text[:-1]
        elif key and len(key) == 1 and ord(key) >= 32:
            if len(state.routing_prompt_text) < max(state.cols * 4, 256):
                state.routing_prompt_text += key
        return state

    # menu view
    if key in (UP, "k", "K"):
        state.cursor = (state.cursor - 1) % len(TUI_MENU)
    elif key in (DOWN, "j", "J"):
        state.cursor = (state.cursor + 1) % len(TUI_MENU)
    elif key in ("q", "Q", ESC, "\x03", "\x04"):
        state.quit = True
    elif key in (ENTER, "\n"):
        return _select_item(state, state.cursor)
    elif key in TUI_MENU_INDEX:
        state.cursor = TUI_MENU_INDEX[key]
        return _select_item(state, state.cursor)
    return state


@contextlib.contextmanager
def _capture_output():
    """Capture parent prints and child-process fd output into one buffer."""
    buf = io.StringIO()
    saved_out = saved_err = None
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        saved_out, saved_err = os.dup(1), os.dup(2)
        with tempfile.TemporaryFile() as tmp:
            os.dup2(tmp.fileno(), 1)
            os.dup2(tmp.fileno(), 2)
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                yield buf
            tmp.seek(0)
            buf.write(tmp.read().decode("utf-8", errors="replace"))
    finally:
        if saved_out is not None:
            os.dup2(saved_out, 1)
            os.close(saved_out)
        if saved_err is not None:
            os.dup2(saved_err, 2)
            os.close(saved_err)


def _execute_action(action: tuple, root: Path) -> tuple[str, int]:
    """Run a recorded action through the existing helpers, capturing output.

    Exactly the same helpers and call shapes as the non-interactive CLI and
    the line wizard use; the screen simply stays up and the result lands in
    the status area instead of the terminal scrollback.
    """
    kind = action[0]
    with _capture_output() as buf:
        if kind == "import":
            rc = _cmd_import(root, action[1], [action[2]])
        elif kind == "preset":
            rc = _cmd_preset(root)
        elif kind == "preset_by_name":
            try:
                result = apply_preset_by_name(root, action[1])
                buf.write(f"preset '{result['preset']}' applied — routing={result['mode']}"
                          + (f"; added {', '.join(result['added'])}" if result["added"] else "; nothing to add"))
                rc = 0
            except (ValueError, json.JSONDecodeError, OSError) as exc:
                buf.write(f"preset apply failed: {exc}")
                rc = 1
        elif kind == "preset_create":
            # write the preset file only; the engine is never started here
            try:
                _, name, provider, domain_text = action
                domains = [d.strip() for d in domain_text.split(",") if d.strip()]
                path = add_custom_preset(root, name, provider, domains)
                buf.write(f"custom preset '{name}' written to {path.relative_to(root or Path('.'))} (not applied)")
                rc = 0
            except (ValueError, OSError) as exc:
                buf.write(f"preset create failed: {exc}")
                rc = 1
        elif kind == "check":
            rc = _cmd_check(root)
        elif kind == "engine_start":
            # Do not use ensure here: it intentionally respects manual-off.
            # The backend's explicit start clears that marker and owns the
            # canonical launchd tray kickstart, so the TUI must not Popen a
            # second unmanaged tray process.
            rc = _router_command(root, "start")
            if rc == 0:
                buf.write("engine up (canonical launchd tray autostart)")
            else:
                buf.write("engine failed to start (see output above)")
        elif kind == "engine_stop":
            rc = _router_command(root, "stop")
            if rc == 0:
                buf.write("engine stopped")
            else:
                buf.write("engine stop failed (see output above)")
        elif kind == "vpn_toggle":
            engine_up, engine_mode = _tui_engine_state(root)
            if engine_mode == "unknown" or (engine_up and engine_mode not in {"proxy", "tun"}):
                buf.write("vpn toggle failed: running mode is unverified")
                rc = 1
            else:
                target = "off" if engine_up and engine_mode == "tun" else "on"
                rc = _router_command(root, "vpn", target)
                if rc == 0:
                    buf.write("TUN mode on (all traffic via engine rules)" if target == "on"
                              else "TUN mode off (proxy mode)")
                else:
                    buf.write("vpn toggle failed (see output above)")
        elif kind == "rotation_set":
            try:
                _cmd_rotation_set(root, action[1], action[2])
                buf.write(f"rotation {action[1]} = {action[2]}")
                rc = 0
            except ValueError as exc:
                buf.write(str(exc))
                rc = 1
        elif kind == "rotate_provider":
            # rotation includes probe + settle window + possible rollback
            rc = _router_command(root, "rotate", action[1], timeout=180.0)
            if rc == 0:
                buf.write(f"rotated {action[1]} (in place; settle retry applies)")
            else:
                buf.write(f"rotation {action[1]} failed (see output above)")
        elif kind == "rotate_to":
            rc = _router_command(root, "rotate", action[1], "--to", action[2],
                                 timeout=180.0)
            if rc == 0:
                buf.write(f"set {action[1]} exit -> {action[2]}")
            else:
                buf.write(f"setting {action[1]} exit failed (see output above)")
        elif kind == "failover_on":
            rc = _router_command(root, "failover", action[1], "on")
            if rc == 0:
                buf.write(f"failover {action[1]} on (first valid chain member)")
            else:
                buf.write(f"failover {action[1]} on failed (see output above)")
        elif kind == "failover_off":
            rc = _router_command(root, "failover", action[1], "off")
            if rc == 0:
                buf.write(f"failover {action[1]} off (primary restored)")
            else:
                buf.write(f"failover {action[1]} off failed (see output above)")
        elif kind == "bridge_install":
            rc = _cmd_bridge_install(root)
        elif kind == "routing":
            # One writer: the `router.py routing` CLI. Never starts the engine -
            # the output tells the operator to run ensure/reload separately.
            rc = _router_command(root, "routing", *action[1:])
            if rc == 0:
                buf.write("routing config saved (engine NOT reloaded - run 'router.py ensure' to apply)")
            else:
                buf.write("routing change failed (see router output above)")
        else:  # pragma: no cover - defensive
            rc = 0
    return _strip_ansi(buf.getvalue()).strip(), rc


def _paint(state: TuiState) -> None:
    """Paint one full frame: home + lines + home, single write burst."""
    out = sys.stdout
    frame = render_frame(state)
    if len(frame) < state.rows:
        frame = frame + [""] * (state.rows - len(frame))
    out.write("\x1b[H")
    out.write("\r\n".join(frame))
    out.write("\x1b[H")
    if state.view == "import":
        row = 4  # 1-based line of the " path: " input row (frame index 3)
        col = min(1 + len(" path: ") + len(state.import_text), state.cols - 1)
        out.write(f"\x1b[{row};{col}H\x1b[?25h")
    else:
        out.write("\x1b[?25l")
    out.flush()


def _read_key(timeout: float = 0.05) -> str:
    """Read one key event from raw stdin; resolves ESC-prefixed sequences."""
    fd = sys.stdin.fileno()

    def _read1() -> str:
        try:
            data = os.read(fd, 1)
        except OSError:
            return ""
        if not data:
            return "\x04"  # EOF behaves like quit
        return data.decode("utf-8", errors="replace")

    ch = _read1()
    if ch != ESC:
        return ch
    # ESC: possibly the start of an arrow/function sequence; peek for more.
    try:
        ready, _, _ = select.select([fd], [], [], timeout)
    except (OSError, ValueError):
        ready = []
    if not ready:
        return ESC
    seq = _read1()
    if seq in ("[", "O"):
        try:
            ready, _, _ = select.select([fd], [], [], timeout)
        except (OSError, ValueError):
            ready = []
        if ready:
            seq += _read1()
    return ESC + seq


def _tui_wizard(root: Path) -> int:
    """Full-screen alternate-screen wizard (both streams must be TTYs)."""
    state = _initial_state(root)
    fd = sys.stdin.fileno()
    try:
        saved = termios.tcgetattr(fd)
    except (termios.error, OSError, ValueError):
        saved = None
    interrupted = False
    try:
        try:
            tty.setraw(fd)
        except Exception:
            return _line_wizard(root)
        sys.stdout.write("\x1b[?1049h\x1b[?25l\x1b[2J")
        sys.stdout.flush()
        while not state.quit:
            _paint(state)
            key = _read_key()
            state = apply_key(state, key)
            if state.action is not None:
                text, rc = _execute_action(state.action, root)
                state.action = None
                state.view = "home"
                state.status = text or ("command finished" if rc == 0 else "command failed")
                state.status_ok = rc == 0
    except KeyboardInterrupt:
        interrupted = True
    finally:
        # Always restore the terminal, even on errors or Ctrl-C.
        try:
            sys.stdout.write("\x1b[?25h\x1b[?1049l\n\n")
            sys.stdout.flush()
        except Exception:
            pass
        if saved is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            except Exception:
                pass
    return 130 if interrupted else 0


def wizard(root=None) -> int:
    """Interactive setup: full-screen TUI on a real TTY, line fallback otherwise.

    Falls back to the plain line menu when stdin or stdout is not a TTY
    (pipes, CI, tests) or when POSIX raw mode (termios/tty) is unavailable.
    """
    root = Path(root) if root is not None else ROOT
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return _line_wizard(root)
    if not _HAVE_TERMIOS:
        return _line_wizard(root)
    return _tui_wizard(root)


def main(argv=None, root=None) -> int:
    """CLI entry point: non-interactive flags, or the wizard when run bare.

    ``root`` is the repository root to operate on (tests and the router CLI
    pass it explicitly); it redirects every path this module resolves.
    """
    global ROOT
    if root is not None:
        ROOT = Path(root).resolve()
    if argv and argv[0] == "setup":
        argv = argv[1:]

    parser = argparse.ArgumentParser(
        prog="proxy-router setup",
        description="setup wizard: guides, profile import, presets, health check",
    )
    parser.add_argument("--guide", choices=["proton", "warp", "all"], metavar="PROVIDER",
                        help="print a setup guide (proton, warp, or all)")
    parser.add_argument("--check", action="store_true",
                        help="verify router.json and provider profiles")
    parser.add_argument("--import-proton", nargs="+", metavar="PATH",
                        help="import WireGuard .conf file(s)/directory into providers/proton")
    parser.add_argument("--import-warp", nargs="+", metavar="PATH",
                        help="import WireGuard .conf file(s)/directory into providers/cloudflare")
    parser.add_argument("--autocheck", choices=sorted(_AUTOCHECK_PRESETS), metavar="PROFILE",
                        help="configure automatic health checks (off, light, balanced, aggressive)")
    for key in _AUTOCHECK_NUMERIC:
        parser.add_argument(f"--autocheck-{key.replace('_', '-')}", type=int, metavar="N",
                            help=f"override autocheck {key}")
    parser.add_argument("--fallback", metavar="PRIMARY",
                        help="set a primary provider's ordered fallback chain")
    parser.add_argument("--fallback-to", metavar="PROVIDER,...",
                        help="comma-separated fallback providers for --fallback; empty clears it")
    parser.add_argument("--fallback-clear", metavar="PRIMARY",
                        help="clear a provider's fallback chain")
    parser.add_argument("--transparent", action="store_true",
                        help="configure route-based TUN capture for configured domains")
    parser.add_argument("--transparent-off", action="store_true",
                        help="restore the existing selective ruleset TUN capture")
    parser.add_argument("--keepalive-install", action="store_true",
                        help="install the macOS launchd 24/7 supervisor")
    parser.add_argument("--keepalive-remove", action="store_true",
                        help="remove the macOS launchd 24/7 supervisor")
    parser.add_argument("--preset", metavar="NAME", nargs="?",
                        const="default",
                        help="apply a preset by name (built-in or custom; bare --preset applies 'default')")
    parser.add_argument("--preset-list", action="store_true",
                        help="list available presets (built-in and custom)")
    parser.add_argument("--preset-add", metavar="NAME",
                        help="create a custom preset file under presets/")
    parser.add_argument("--provider", metavar="PROVIDER",
                        help="provider for --preset-add (e.g. proton, cloudflare)")
    parser.add_argument("--domain", action="append", default=[], metavar="DOMAIN",
                        help="domain for --preset-add (repeatable)")
    parser.add_argument("--preset-route-mode", choices=["vpn-list", "safe-list", "default"],
                        default="vpn-list",
                        help="routing mode for --preset-add (default vpn-list)")
    parser.add_argument("--preset-default-provider", metavar="PROVIDER",
                        help="default_provider for --preset-add safe-list mode")
    parser.add_argument("--bridge-install", action="store_true",
                        help="install the Hermes OpenCode auto-rotation bridge")
    parser.add_argument("--bridge-force-install", action="store_true",
                        help="install the bridge, overwriting an existing file")
    parser.add_argument("--bridge-check", action="store_true",
                        help="verify the installed OpenCode auto-rotation bridge")
    args = parser.parse_args(argv)

    rc = 0
    if args.guide:
        rc = max(rc, _cmd_guide(args.guide))
    if args.check:
        rc = max(rc, _cmd_check(ROOT))
    if args.import_proton:
        rc = max(rc, _cmd_import(ROOT, "proton", args.import_proton))
    if args.import_warp:
        rc = max(rc, _cmd_import(ROOT, "cloudflare", args.import_warp))
    autocheck_overrides = {
        key: getattr(args, f"autocheck_{key}")
        for key in _AUTOCHECK_NUMERIC
        if getattr(args, f"autocheck_{key}") is not None
    }
    if args.autocheck or autocheck_overrides:
        rc = max(rc, _cmd_autocheck(ROOT, args.autocheck, autocheck_overrides))
    if args.fallback or args.fallback_clear:
        try:
            if args.fallback and args.fallback_clear:
                raise ValueError("choose --fallback or --fallback-clear, not both")
            if args.fallback_clear and args.fallback_to is not None:
                raise ValueError("--fallback-clear cannot be combined with --fallback-to")
            primary = args.fallback or args.fallback_clear
            candidates = [] if args.fallback_clear else args.fallback_to
            if args.fallback and args.fallback_to is None:
                raise ValueError("--fallback needs --fallback-to PROVIDER,... (empty clears it)")
            result = configure_fallback(ROOT / "router.json", primary, candidates or [])
            chain = " -> ".join(result["fallback_providers"]) or "(none)"
            print(_style(f"setup: fallback chain {primary} -> {chain}", _Ansi.GREEN))
            print("setup: run `proxy-router reload` to apply (or `ensure` if stopped); the engine was not restarted.")
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            print(_style(f"setup: fallback configuration failed: {exc}", _Ansi.RED), file=sys.stderr)
            rc = max(rc, 1)
    if args.transparent or args.transparent_off:
        try:
            if args.transparent and args.transparent_off:
                raise ValueError("choose --transparent or --transparent-off, not both")
            result = configure_transparent(ROOT / "router.json", enabled=args.transparent)
            print(_style(f"setup: TUN capture = {result['capture']}", _Ansi.GREEN))
            print("setup: run `proxy-router vpn on` (or `reload` if TUN is already active); the engine was not restarted.")
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            print(_style(f"setup: transparent mode configuration failed: {exc}", _Ansi.RED), file=sys.stderr)
            rc = max(rc, 1)
    if args.keepalive_install or args.keepalive_remove:
        if args.keepalive_install and args.keepalive_remove:
            print("setup: choose --keepalive-install or --keepalive-remove, not both", file=sys.stderr)
            rc = max(rc, 1)
        else:
            rc = max(rc, _cmd_keepalive_install(ROOT, remove=args.keepalive_remove))
    if args.preset:
        try:
            result = apply_preset_by_name(ROOT, args.preset)
            label = f"setup: preset '{result['preset']}' applied — routing={result['mode']}"
            if result["added"]:
                label += f", added route(s): {', '.join(result['added'])}"
            else:
                label += " (already present, nothing added)"
            print(_style(_tint_provider(label), _Ansi.GREEN))
            print("setup: run `proxy-router reload` to apply (or `ensure` if stopped); the engine was not restarted.")
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            print(_style(f"setup: preset apply failed: {exc}", _Ansi.RED), file=sys.stderr)
            rc = max(rc, 1)
    if args.preset_list:
        print("setup: available presets:")
        for name in preset_names(ROOT):
            source = "built-in" if name in _BUILTIN_PRESETS else "custom"
            print(f"  {name:16s} ({source})")
    if args.preset_add:
        try:
            if not args.provider:
                raise ValueError("--preset-add needs --provider (e.g. proton, cloudflare)")
            path = add_custom_preset(ROOT, args.preset_add, args.provider, args.domain,
                                     mode=args.preset_route_mode,
                                     default_provider=args.preset_default_provider)
            print(_style(f"setup: custom preset '{args.preset_add}' written to {path}", _Ansi.GREEN))
            print("setup: apply it with `setup --preset <name>`, or from the TUI preset menu.")
        except ValueError as exc:
            print(_style(f"setup: {exc}", _Ansi.RED), file=sys.stderr)
            rc = max(rc, 1)
    if args.bridge_install:
        rc = max(rc, _cmd_bridge_install(ROOT))
    if args.bridge_force_install:
        rc = max(rc, _cmd_bridge_install(ROOT, force=True))
    if args.bridge_check:
        rc = max(rc, _cmd_bridge_check(ROOT))
    if not (args.guide or args.check or args.import_proton or args.import_warp
            or args.autocheck or autocheck_overrides or args.fallback
            or args.fallback_clear or args.transparent or args.transparent_off
            or args.keepalive_install or args.keepalive_remove
            or args.preset or args.bridge_install
            or args.bridge_force_install or args.bridge_check):
        rc = wizard(ROOT)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

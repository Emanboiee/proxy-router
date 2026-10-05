"""Safe persistence and config bridge for the native dashboard.

Only profile metadata and non-secret provider labels live in the dashboard
store. WireGuard credentials stay in mode-0600 provider files and are never
returned to the webview.
"""
from __future__ import annotations

import base64
import binascii
import configparser
import contextlib
import copy
import importlib.util
import io
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


STORE_NAME = "dashboard_profiles.json"
_PROVIDER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ROUTE_MODES = {"selective", "direct", "full"}
_FALLBACKS = {"direct", "retry", "block"}
_PROVIDER_KINDS = {"wireguard", "custom"}


class DashboardError(ValueError):
    """An invalid dashboard request that is safe to show inline."""


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_config(root: Path) -> dict[str, Any]:
    path = root / "router.json"
    if not path.exists():
        return {"port": 2080, "providers": {}, "routes": [], "vpn": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DashboardError(f"Could not read router.json: {exc}") from exc
    if not isinstance(value, dict):
        raise DashboardError("router.json must contain an object")
    providers = value.setdefault("providers", {})
    routes = value.setdefault("routes", [])
    if not isinstance(providers, dict) or not isinstance(routes, list):
        raise DashboardError("router.json has invalid provider or route data")
    return value


def _read_store(root: Path) -> dict[str, Any]:
    path = root / "state" / STORE_NAME
    if not path.exists():
        return {"profiles": [], "active_profile_id": None, "providers": {}, "profiles_initialized": False}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DashboardError(f"Could not read saved dashboard data: {exc}") from exc
    if not isinstance(value, dict):
        raise DashboardError("Saved dashboard data is invalid")
    if not isinstance(value.get("profiles", []), list) or not isinstance(value.get("providers", {}), dict):
        raise DashboardError("Saved dashboard profiles or providers are invalid")
    if any(not isinstance(profile, dict) for profile in value.get("profiles", [])):
        raise DashboardError("Saved dashboard profile data is invalid")
    if value.get("active_profile_id") is not None and not isinstance(value.get("active_profile_id"), str):
        raise DashboardError("Saved active profile is invalid")
    if not isinstance(value.get("profiles_initialized", False), bool):
        raise DashboardError("Saved dashboard profile state is invalid")
    value.setdefault("profiles", [])
    value.setdefault("providers", {})
    value.setdefault("active_profile_id", None)
    value.setdefault("profiles_initialized", False)
    return value


def _save_store(root: Path, store: dict[str, Any]) -> None:
    _atomic_json(root / "state" / STORE_NAME, store)


def _validate_config(root: Path, config: dict[str, Any]) -> None:
    """Use the controller's validator in an isolated module, before publishing."""
    spec = importlib.util.spec_from_file_location(
        "_dashboard_candidate_router", Path(__file__).with_name("router.py")
    )
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    with tempfile.TemporaryDirectory(prefix="proxy-router-config-") as directory:
        path = Path(directory) / "router.json"
        candidate = copy.deepcopy(config)
        # An empty dashboard is a supported disconnected setup. Validate its
        # remaining fields with a temporary provider; never publish that entry.
        if not candidate.get("providers"):
            candidate["providers"] = {"dashboard-validation": {"directory": "providers/dashboard-validation"}}
        _atomic_json(path, candidate)
        controller.ROOT = root
        controller.CONFIG_FILE = path
        with contextlib.redirect_stderr(io.StringIO()):
            valid = controller.load_config() == 0
    if not valid:
        raise DashboardError("The updated configuration is invalid; existing settings were preserved")


def _publish_files(files: dict[Path, bytes]) -> None:
    """Stage every write and rollback file before changing any live file."""
    staged: dict[Path, str] = {}
    backups: dict[Path, str | None] = {}
    published: list[Path] = []
    def stage(path: Path, content: bytes) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        staged_paths.append(temporary)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        return temporary
    staged_paths: list[str] = []
    try:
        for path, content in files.items():
            backups[path] = stage(path, path.read_bytes()) if path.exists() else None
            staged[path] = stage(path, content)
        for path, temporary in staged.items():
            os.replace(temporary, path)
            published.append(path)
    except OSError:
        for path in reversed(published):
            backup = backups[path]
            if backup is None:
                path.unlink(missing_ok=True)
            else:
                os.replace(backup, path)
        raise
    finally:
        for temporary in staged_paths:
            Path(temporary).unlink(missing_ok=True)


def _publish_config_store(root: Path, config: dict, store: dict, extra: dict | None = None) -> None:
    _validate_config(root, config)
    files = dict(extra or {})
    for path, value in ((root / "router.json", config), (root / "state" / STORE_NAME, store)):
        files[path] = (json.dumps(value, indent=2) + "\n").encode()
    _publish_files(files)


def _route_snapshot(config: dict) -> dict:
    return {
        "routes": copy.deepcopy(config.get("routes", [])),
        "routing": copy.deepcopy(config.get("routing")),
    }


def _text(value: Any, field: str, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise DashboardError(f"{field} must be text")
    cleaned = value.strip()
    if required and not cleaned:
        raise DashboardError(f"Give this {field.lower()} a name")
    if len(cleaned) > limit or any(ord(character) < 32 for character in cleaned):
        raise DashboardError(f"{field} must be at most {limit} characters")
    return cleaned


def _new_id(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-._") or "item"
    return f"{base[:48]}-{uuid.uuid4().hex[:6]}"


def _profile_data(value: Any, providers: dict[str, Any], old: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError("Profile data is invalid")
    name = _text(value.get("name"), "Profile name", 48, required=True)
    description = _text(value.get("description", ""), "Description", 120)
    provider_id = _text(value.get("providerId", ""), "Connection", 64)
    route_mode = value.get("routeMode", "selective")
    fallback = value.get("fallback", "direct")
    if not isinstance(route_mode, str) or route_mode not in _ROUTE_MODES:
        raise DashboardError("Choose a routing mode")
    if not isinstance(fallback, str) or fallback not in _FALLBACKS:
        raise DashboardError("Choose a fallback behavior")
    # A direct profile has no provider route that needs retry or block fallback.
    if route_mode == "direct":
        fallback = "direct"
    if provider_id and not _PROVIDER_ID.fullmatch(provider_id):
        raise DashboardError("Choose a valid connection")
    if route_mode != "direct" and provider_id not in providers:
        raise DashboardError("Choose a connection that is already in Providers")
    fallback_id = _text(value.get("fallbackProviderId", ""), "Fallback connection", 64)
    if fallback_id and not _PROVIDER_ID.fullmatch(fallback_id):
        raise DashboardError("Choose a valid fallback connection")
    if fallback == "retry":
        if not fallback_id or fallback_id not in providers:
            raise DashboardError("Choose a second connection for retry fallback")
        if fallback_id == provider_id:
            raise DashboardError("Fallback must use a different connection")
    else:
        fallback_id = ""
    raw_domains = value.get("domains", [])
    if not isinstance(raw_domains, list):
        raise DashboardError("Enter one domain per line")
    domains: list[str] = []
    for raw in raw_domains:
        domain = _text(raw, "Domain", 253).lower().rstrip(".")
        if not domain:
            continue
        if len(domain) > 253 or not all(_DOMAIN_LABEL.fullmatch(label) for label in domain.split(".")):
            raise DashboardError(f"“{domain}” is not a valid domain name")
        if domain not in domains:
            domains.append(domain)
    if route_mode == "selective" and not domains:
        raise DashboardError("Add at least one domain for selective routing")
    auto_subdomains = value.get("autoSubdomains", False)
    if not isinstance(auto_subdomains, bool):
        raise DashboardError("Subdomain detection must be on or off")
    profile_id = (old or {}).get("id") or value.get("id")
    if profile_id is not None:
        profile_id = _text(profile_id, "Profile ID", 64, required=True)
        if not _PROVIDER_ID.fullmatch(profile_id):
            raise DashboardError("Profile ID is invalid")
    return {
        "id": profile_id or _new_id(name),
        "name": name,
        "description": description,
        "providerId": provider_id,
        "fallbackProviderId": fallback_id,
        "routeMode": route_mode,
        "domains": domains,
        "autoSubdomains": auto_subdomains,
        "fallback": fallback,
        "updatedAt": int(time.time() * 1000),
    }


def _wireguard_summary(path: Path) -> tuple[str, str]:
    if path.suffix.lower() != ".conf":
        raise DashboardError("Choose a WireGuard .conf file")
    try:
        if path.stat().st_size > 128 * 1024:
            raise DashboardError("WireGuard config must be under 128 KB")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise DashboardError("Could not read the selected WireGuard file") from exc
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(raw)
        interface, peer = parser["Interface"], parser["Peer"]
        private_key = interface.get("PrivateKey", "").strip()
        public_key = peer.get("PublicKey", "").strip()
        endpoint = peer.get("Endpoint", "").strip()
        allowed_ips = peer.get("AllowedIPs", "").strip()
    except (KeyError, configparser.Error) as exc:
        raise DashboardError("WireGuard config needs [Interface] and [Peer] sections") from exc
    if not private_key or not public_key or not allowed_ips:
        raise DashboardError("WireGuard config needs PrivateKey, PublicKey, and AllowedIPs")
    try:
        keys = [private_key, public_key]
        if peer.get("PresharedKey", "").strip():
            keys.append(peer["PresharedKey"].strip())
        if any(len(base64.b64decode(key, validate=True)) != 32 for key in keys):
            raise ValueError("invalid key length")
        for address in interface.get("Address", "").split(","):
            ipaddress.ip_interface(address.strip())
        for network in allowed_ips.split(","):
            ipaddress.ip_network(network.strip(), strict=False)
    except (ValueError, binascii.Error) as exc:
        raise DashboardError("WireGuard config contains an invalid key or IP address") from exc
    if not re.fullmatch(r"(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}", endpoint):
        raise DashboardError("WireGuard Endpoint must be a host and port")
    port = int(endpoint.rsplit(":", 1)[-1])
    if not 1 <= port <= 65535:
        raise DashboardError("WireGuard Endpoint port must be between 1 and 65535")
    return endpoint, raw


def _provider_rows(root: Path, config: dict[str, Any], store: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = store.get("providers", {})
    result = []
    for provider_id, spec in sorted(config.get("providers", {}).items()):
        if not isinstance(provider_id, str) or not _PROVIDER_ID.fullmatch(provider_id) or not isinstance(spec, dict):
            continue
        saved = metadata.get(provider_id, {}) if isinstance(metadata, dict) else {}
        if not isinstance(saved, dict):
            saved = {}
        directory = spec.get("directory", f"providers/{provider_id}")
        files: list[Path] = []
        if isinstance(directory, str):
            provider_path = (root / directory).resolve()
            try:
                provider_path.relative_to(root.resolve())
                files = sorted(provider_path.glob("*.conf"))
            except ValueError:
                files = []
        kind = saved.get("kind") or ("wireguard" if spec.get("directory") else "custom")
        endpoint = str(saved.get("endpoint") or (files[0].stem if files else "Configured connection"))
        result.append({
            "id": provider_id,
            "name": str(saved.get("name") or provider_id),
            "kind": kind if kind in _PROVIDER_KINDS else "custom",
            "status": "offline",
            "latency": None,
            "server": endpoint,
            "servers": [endpoint],
            "connection": {"kind": "wireguard", "fileName": files[0].name if files else "", "endpoint": endpoint},
            "managed": bool(saved.get("managed", False)),
        })
    return result


def _inferred_profile(config: dict[str, Any], providers: dict[str, Any]) -> dict[str, Any] | None:
    if not providers:
        return None
    routes = config.get("routes", [])
    first = next((route for route in routes if isinstance(route, dict)), {})
    provider_id = str(first.get("provider") or next(iter(providers)))
    if provider_id not in providers:
        provider_id = next(iter(providers))
    routing = config.get("routing", {})
    mode = routing.get("mode") if isinstance(routing, dict) else "default"
    route_mode = "full" if mode == "safe-list" else "direct" if not routes and mode != "safe-list" else "selective"
    domains = [domain for route in routes if isinstance(route, dict) for domain in route.get("domains", []) if isinstance(domain, str)]
    chain = providers.get(provider_id, {}).get("fallback_providers", [])
    fallback_id = chain[0] if isinstance(chain, list) and chain else ""
    return {
        "id": "current-setup", "name": "Current setup", "description": "Imported from the router’s current routes.",
        "providerId": provider_id, "fallbackProviderId": fallback_id if fallback_id in providers else "",
        "routeMode": route_mode, "domains": list(dict.fromkeys(domains)), "autoSubdomains": True,
        "fallback": "retry" if fallback_id in providers else "direct", "updatedAt": 0,
    }


def state(root: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    config = _read_config(root)
    store = _read_store(root)
    providers = _provider_rows(root, config, store)
    profiles = [{key: value for key, value in item.items() if key != "_route_snapshot"}
                for item in store["profiles"] if isinstance(item, dict)]
    if not profiles and not store.get("profiles_initialized", False):
        inferred = _inferred_profile(config, config["providers"])
        if inferred:
            profiles = [inferred]
    active_id = store.get("active_profile_id")
    if active_id is not None and not isinstance(active_id, str):
        raise DashboardError("Saved active profile is invalid")
    if active_id not in {profile.get("id") for profile in profiles}:
        active_id = profiles[0]["id"] if profiles and not store.get("profiles_initialized", False) else None
    return {"profiles": profiles, "providers": providers, "activeProfileId": active_id}


def save_profile(root: Path, value: Any, profile_id: str | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    if profile_id is not None and (not isinstance(profile_id, str) or not _PROVIDER_ID.fullmatch(profile_id)):
        raise DashboardError("Profile ID is invalid")
    config = _read_config(root)
    store = _read_store(root)
    profiles = store["profiles"]
    old = next((item for item in profiles if isinstance(item, dict) and item.get("id") == profile_id), None) if profile_id else None
    if profile_id and old is None:
        inferred = _inferred_profile(config, config["providers"])
        if inferred and inferred["id"] == profile_id:
            old = inferred
        else:
            raise DashboardError("That profile no longer exists. Refresh and try again.")
    profile = _profile_data(value, config["providers"], old)
    snapshot = (old or {}).get("_route_snapshot")
    if old and old.get("id") == "current-setup" and snapshot is None:
        snapshot = _route_snapshot(config)
    if snapshot is not None:
        fields = ("providerId", "fallbackProviderId", "routeMode", "domains", "autoSubdomains", "fallback")
        changed = any(profile.get(field) != old.get(field) for field in fields)
        if changed and len(snapshot["routes"]) > 1:
            raise DashboardError("Current setup has multiple route rules. Create a new profile to replace them.")
        if not changed:
            profile["_route_snapshot"] = snapshot
    if old:
        profiles[:] = [profile if item.get("id") == profile_id else item for item in profiles]
        if not any(item.get("id") == profile_id for item in profiles):
            profiles.append(profile)
    else:
        profiles.append(profile)
    store["profiles"] = profiles
    store["profiles_initialized"] = True
    _save_store(root, store)
    return state(root)


def delete_profile(root: Path, profile_id: str) -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(profile_id, str) or not _PROVIDER_ID.fullmatch(profile_id):
        raise DashboardError("Profile ID is invalid")
    store = _read_store(root)
    profiles = store["profiles"]
    config = _read_config(root)
    visible_profiles = list(profiles)
    if not visible_profiles and not store.get("profiles_initialized", False):
        inferred = _inferred_profile(config, config["providers"])
        if inferred:
            visible_profiles = [inferred]
    exists = any(item.get("id") == profile_id for item in profiles if isinstance(item, dict))
    if not exists:
        if not any(item.get("id") == profile_id for item in visible_profiles):
            raise DashboardError("That profile no longer exists")
    active_id = store.get("active_profile_id")
    visible_ids = {item.get("id") for item in visible_profiles if isinstance(item.get("id"), str)}
    if active_id not in visible_ids:
        active_id = visible_profiles[0].get("id") if visible_profiles else None
    deleting_active = active_id == profile_id
    store["profiles"] = [item for item in profiles if item.get("id") != profile_id]
    store["profiles_initialized"] = True
    remaining_ids = {item.get("id") for item in store["profiles"] if isinstance(item.get("id"), str)}
    if deleting_active or store.get("active_profile_id") not in remaining_ids:
        store["active_profile_id"] = store["profiles"][0]["id"] if store["profiles"] else None
    if deleting_active and store["active_profile_id"]:
        next_profile = next(item for item in store["profiles"] if item["id"] == store["active_profile_id"])
        _apply_profile_config(config, next_profile)
    elif deleting_active:
        config["routes"] = []
        config["routing"] = {"mode": "default"}
    _publish_config_store(root, config, store)
    return state(root)


def _apply_profile_config(config: dict, profile: dict) -> dict:
    clean = dict(profile) if "_route_snapshot" in profile else _profile_data(profile, config["providers"], profile)
    provider_id = clean["providerId"]
    if clean["routeMode"] != "direct" and provider_id not in config["providers"]:
        raise DashboardError("This profile’s connection is missing")
    if "_route_snapshot" in clean:
        snapshot = clean["_route_snapshot"]
        config["routes"] = copy.deepcopy(snapshot["routes"])
        if snapshot["routing"] is None:
            config.pop("routing", None)
        else:
            config["routing"] = copy.deepcopy(snapshot["routing"])
        return clean
    spec = config["providers"].get(provider_id)
    if isinstance(spec, dict) and clean["routeMode"] != "direct":
        spec.pop("fallback_providers", None)
        spec.pop("fallback_provider", None)
        if clean["fallback"] == "retry":
            spec["fallback_providers"] = [clean["fallbackProviderId"]]
    if clean["routeMode"] == "selective":
        config.pop("routing", None)
        config["routes"] = [{
            "id": clean["id"], "domains": clean["domains"], "provider": provider_id,
            "auto_subdomains": clean["autoSubdomains"],
            "on_unavailable": "block" if clean["fallback"] == "block" else "direct",
        }]
    elif clean["routeMode"] == "full":
        config["routes"] = []
        config["routing"] = {"mode": "safe-list", "default_provider": provider_id, "direct_domains": []}
    else:
        config["routes"] = []
        config["routing"] = {"mode": "default"}
    return clean


def apply_profile(root: Path, profile_id: str) -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(profile_id, str) or not _PROVIDER_ID.fullmatch(profile_id):
        raise DashboardError("Profile ID is invalid")
    config = _read_config(root)
    store = _read_store(root)
    profiles = store["profiles"]
    profile = next((item for item in profiles if isinstance(item, dict) and item.get("id") == profile_id), None)
    if profile is None:
        profile = _inferred_profile(config, config["providers"])
        if profile:
            profile["_route_snapshot"] = _route_snapshot(config)
    if not profile or profile.get("id") != profile_id:
        raise DashboardError("That profile no longer exists")
    clean = _apply_profile_config(config, profile)
    store["active_profile_id"] = clean["id"]
    if not any(item.get("id") == clean["id"] for item in profiles if isinstance(item, dict)):
        profiles.append(clean)
    store["profiles"] = profiles
    _publish_config_store(root, config, store)
    return state(root)


def save_provider(root: Path, value: Any, provider_id: str | None = None, source_path: str | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(value, dict):
        raise DashboardError("Connection data is invalid")
    name = _text(value.get("name"), "Connection name", 48, required=True)
    kind = value.get("kind", "custom")
    if not isinstance(kind, str) or kind not in _PROVIDER_KINDS:
        raise DashboardError("Choose WireGuard or Custom VPN")
    if provider_id is not None and (not isinstance(provider_id, str) or not _PROVIDER_ID.fullmatch(provider_id)):
        raise DashboardError("Connection ID is invalid")
    config = _read_config(root)
    store = _read_store(root)
    if any(
        provider["id"] != provider_id and provider["name"].casefold() == name.casefold()
        for provider in _provider_rows(root, config, store)
    ):
        raise DashboardError("A connection with that name already exists")
    if provider_id:
        if provider_id not in config["providers"]:
            raise DashboardError("That connection no longer exists")
        identifier = provider_id
    else:
        identifier = _new_id(name)
    pending_files: dict[Path, bytes] = {}
    if source_path:
        source = Path(source_path).expanduser().resolve()
        endpoint, raw = _wireguard_summary(source)
        relative = Path("providers") / identifier
        destination_dir = root / relative
        destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination_dir, 0o700)
        destination = destination_dir / "wireguard.conf"
        pending_files[destination] = raw.encode()
        spec = config["providers"].get(identifier, {})
        if not isinstance(spec, dict):
            spec = {}
        spec.pop("socks5", None)
        spec["directory"] = str(relative)
        config["providers"][identifier] = spec
        saved = {"name": name, "kind": kind, "endpoint": endpoint, "managed": True}
    else:
        if not provider_id:
            raise DashboardError("Choose a WireGuard configuration file")
        saved = store["providers"].get(identifier, {})
        saved = dict(saved) if isinstance(saved, dict) else {}
        endpoint = str(saved.get("endpoint") or identifier)
        saved.update({"name": name, "kind": kind})
    store["providers"][identifier] = saved
    _publish_config_store(root, config, store, pending_files)
    return state(root)


def delete_provider(root: Path, provider_id: str) -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(provider_id, str) or not _PROVIDER_ID.fullmatch(provider_id):
        raise DashboardError("Connection ID is invalid")
    config = _read_config(root)
    store = _read_store(root)
    if provider_id not in config["providers"]:
        raise DashboardError("That connection no longer exists")
    profiles = [item for item in store["profiles"] if isinstance(item, dict)]
    if any(item.get("providerId") == provider_id or item.get("fallbackProviderId") == provider_id for item in profiles):
        raise DashboardError("This connection is used by a saved profile. Update or delete that profile first.")
    routes = config.get("routes", [])
    if any(isinstance(route, dict) and route.get("provider") == provider_id for route in routes):
        raise DashboardError("This connection is used by a route. Apply another profile first.")
    routing = config.get("routing", {})
    if isinstance(routing, dict) and routing.get("default_provider") == provider_id:
        raise DashboardError("This connection is the routing default. Apply another profile first.")
    if any(
        isinstance(spec, dict) and (
            spec.get("fallback_provider") == provider_id
            or provider_id in (spec.get("fallback_providers") if isinstance(spec.get("fallback_providers"), list) else [])
        )
        for name, spec in config["providers"].items() if name != provider_id
    ):
        raise DashboardError("Another connection uses this as its fallback")
    saved = store["providers"].pop(provider_id, {})
    spec = config["providers"].pop(provider_id)
    _publish_config_store(root, config, store)
    if isinstance(saved, dict) and saved.get("managed") and isinstance(spec, dict):
        directory = spec.get("directory", f"providers/{provider_id}")
        if isinstance(directory, str):
            target = (root / directory).resolve()
            managed_root = (root / "providers").resolve()
            try:
                target.relative_to(managed_root)
                if target.name == provider_id:
                    shutil.rmtree(target, ignore_errors=True)
            except ValueError:
                pass
    return state(root)


def run_cli(root: Path, args) -> int:
    try:
        if args.dashboard_action == "state":
            value = state(root)
        elif args.dashboard_action == "profile-save":
            value = save_profile(
                root, json.loads(args.json), args.id,
            )
        elif args.dashboard_action == "profile-delete":
            value = delete_profile(root, args.id)
        elif args.dashboard_action == "profile-apply":
            value = apply_profile(root, args.id)
        elif args.dashboard_action == "provider-save":
            value = save_provider(
                root, json.loads(args.json), args.id, args.path,
            )
        elif args.dashboard_action == "provider-delete":
            value = delete_provider(root, args.id)
        else:
            raise DashboardError("unsupported dashboard operation")
    except (DashboardError, json.JSONDecodeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(value, separators=(",", ":")))
    return 0

"""Built-in network safety and private five-network history.

Link loss and SSID visibility are separate: redacted identities never become
mapping keys, and an unavailable probe never disconnects a working engine.
"""

from __future__ import annotations
import json
import hashlib
import re
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import worker_lock

REDACTED = {"<redacted>", "<hidden>", "(null)"}


def valid_ssid(value):
    return (
        isinstance(value, str)
        and bool(value)
        and value.lower() not in REDACTED
        and len(value) <= 255
        and not any(ord(c) < 32 for c in value)
    )


def read_json(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def write_bytes(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, value):
    write_bytes(path, json.dumps(value).encode("utf-8"))


def remember(root, ssid, now=None):
    path = Path(root) / "state" / "recent-networks.json"
    with worker_lock.exclusive(path.with_suffix(".lock")):
        rows = read_json(path).get("networks", [])
        if not isinstance(rows, list):
            rows = []
        rows = [r for r in rows if isinstance(r, dict) and valid_ssid(r.get("ssid"))]
        if valid_ssid(ssid):
            rows = [
                {"ssid": ssid, "last_seen": int(time.time() if now is None else now)}
            ] + [r for r in rows if r["ssid"] != ssid]
            write_json(path, {"networks": rows[:5]})
        return rows[:5]


def preferences(root):
    return read_json(Path(root) / "state" / "network-preferences.json")


def disconnect_enabled(root):
    return preferences(root).get("disconnect_on_loss", True) is not False


def set_disconnect(root, enabled):
    path = Path(root) / "state" / "network-preferences.json"
    with worker_lock.exclusive(path.with_suffix(".lock")):
        value = preferences(root)
        value["disconnect_on_loss"] = bool(enabled)
        write_json(path, value)


def probe(root, runner=None, platform=None):
    runner = runner or subprocess.run
    platform = platform or sys.platform
    result = {
        "connected": True,
        "ssid": None,
        "supported": False,
        "checked_at": int(time.time()),
        "identity": "unavailable",
    }
    try:
        if platform == "darwin":
            names = runner(
                ["networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            interfaces = []
            lines = names.stdout.splitlines()
            for i, line in enumerate(lines):
                if ("Wi-Fi" in line or "AirPort" in line) and i + 1 < len(lines):
                    interfaces.append(lines[i + 1].partition(":")[2].strip())
            if names.returncode or not interfaces:
                return result
            successful = False
            for iface in interfaces:
                out = runner(
                    ["ipconfig", "getsummary", iface],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if out.returncode:
                    link = runner(
                        ["ifconfig", iface], capture_output=True, text=True, timeout=5
                    )
                    if link.returncode == 0 and "status: inactive" in link.stdout:
                        successful = True
                    elif link.returncode == 0 and "status: active" in link.stdout:
                        result.update(connected=True, supported=True)
                        return result
                    continue
                successful = True
                # Private connection token, not an SSID guess. DHCP transaction
                # and gateway identity change when roaming, including networks
                # that happen to use the same private address range.
                fields = re.findall(
                    r"^\s*(?:ConnectionID|LeaseStartTime|Security)\s*:\s*(.+)$|"
                    r"^(?:xid|chaddr) = (.+)$|"
                    r"^\s*source link-address option.*?:\s*(.+)$",
                    out.stdout, re.MULTILINE,
                )
                if fields:
                    token = json.dumps([iface, fields], sort_keys=True).encode()
                    result["connection_token"] = hashlib.sha256(token).hexdigest()
                for line in out.stdout.splitlines():
                    if line.strip().startswith("SSID :") or line.strip().startswith(
                        "SSID:"
                    ):
                        ssid = line.partition(":")[2].strip()
                        if ssid:
                            result.update(
                                connected=True,
                                supported=True,
                                ssid=ssid if valid_ssid(ssid) else None,
                                identity=(
                                    "available" if valid_ssid(ssid) else "permission"
                                ),
                            )
                            return result
            if successful:
                result.update(connected=False, supported=True, identity="disconnected")
        elif platform == "win32":
            # PowerShell avoids localized netsh labels; physical adapters only.
            out = runner(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetAdapter -Physical | Select-Object Status | ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                rows = json.loads(out.stdout)
                rows = rows if isinstance(rows, list) else [rows]
                if rows:
                    result.update(
                        connected=any(r.get("Status") == "Up" for r in rows),
                        supported=True,
                    )
            wifi = runner(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if wifi.returncode == 0:
                for line in wifi.stdout.splitlines():
                    key, _, value = line.strip().partition(":")
                    if key.strip() == "SSID" and valid_ssid(value.strip()):
                        result.update(ssid=value.strip(), identity="available")
                        break
        elif platform.startswith("linux"):
            out = runner(
                ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                rows = [r.split(":") for r in out.stdout.splitlines()]
                physical = [
                    r for r in rows if len(r) == 3 and r[1] in ("wifi", "ethernet")
                ]
                if physical:
                    result.update(
                        connected=any(r[2] == "connected" for r in physical),
                        supported=True,
                    )
            wifi = runner(
                ["iwgetid", "--raw"], capture_output=True, text=True, timeout=5
            )
            if wifi.returncode == 0 and valid_ssid(wifi.stdout.strip()):
                result.update(ssid=wifi.stdout.strip(), identity="available")
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return result


def native_ssid():
    """CoreWLAN uses the responsible app's location authorization, never prompts."""
    if sys.platform != "darwin":
        return None
    try:
        import ctypes

        ctypes.CDLL("/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN")
        objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]
        send = objc.objc_msgSend
        send.restype = ctypes.c_void_p
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        def message(obj, selector):
            return send(obj, objc.sel_registerName(selector))

        pool = message(objc.objc_getClass(b"NSAutoreleasePool"), b"new")
        try:
            client = message(objc.objc_getClass(b"CWWiFiClient"), b"sharedWiFiClient")
            interface = message(client, b"interface")
            name = message(interface, b"ssid")
            pointer = message(name, b"UTF8String")
            ssid = ctypes.string_at(pointer).decode("utf-8") if pointer else None
            return ssid if valid_ssid(ssid) else None
        finally:
            message(pool, b"drain")
    except (OSError, UnicodeError):
        return None


def observe(root, ssid):
    """Bridge an authorized dashboard reading to the unprivileged worker."""
    if not valid_ssid(ssid):
        return False
    status = probe(root)
    token = status.get("connection_token")
    if not status.get("supported") or not status.get("connected") or not token:
        return False
    write_json(Path(root) / "state" / "native-network.json", {
        "ssid": ssid, "connection_token": token, "checked_at": int(time.time()),
    })
    remember(root, ssid)
    return True


def observed_ssid(root, status):
    if not status.get("supported") or not status.get("connected"):
        return None
    observation = read_json(Path(root) / "state" / "native-network.json")
    checked = observation.get("checked_at")
    if not isinstance(checked, (int, float)) or not 0 <= time.time() - checked <= 30:
        return None
    token = status.get("connection_token")
    if not token or token != observation.get("connection_token"):
        return None
    ssid = observation.get("ssid")
    return ssid if valid_ssid(ssid) else None


def view(root, status):
    if status.get("connected") and sys.platform == "darwin":
        ssid = native_ssid() or observed_ssid(root, status)
        if ssid:
            status = dict(status, ssid=ssid, identity="available")
    ssid = status.get("ssid")
    return dict(
        status,
        recent=remember(root, ssid if status.get("connected") else None),
        disconnect_on_loss=disconnect_enabled(root),
    )


def profile_error(root, name):
    if not isinstance(name, str) or not name.startswith("profile:"):
        return None
    import dashboard_profile_manager as manager

    try:
        if any(p.get("id") == name[8:] for p in manager.state(Path(root))["profiles"]):
            return None
    except (OSError, ValueError, manager.DashboardError):
        pass
    return "That saved profile no longer exists"


def apply_mapping(router, root, reload_engine=True):
    root = Path(root)
    now = int(time.time())
    if (root / "state" / "manual-off").exists():
        return {"applied": False, "reason": "manually disconnected", "checked_at": now}
    mapped = router.preset_for_current_network()
    if not mapped:
        return {"applied": False, "reason": "no network mapping", "checked_at": now}
    config_path = root / "router.json"
    original_config = config_path.read_bytes()
    previous_config = json.loads(original_config)
    import dashboard_profile_manager as manager

    store_path = root / "state" / manager.STORE_NAME
    original_store = store_path.read_bytes() if store_path.exists() else None
    is_profile = mapped.startswith("profile:")
    if is_profile:
        current = manager.state(root).get("activeProfileId")
        already = current == mapped[8:]
    else:
        already = previous_config.get("preset") == mapped
    if already:
        return {
            "applied": False,
            "reason": "already active",
            "preset": mapped,
            "checked_at": now,
        }
    was_running = router.engine_alive() if reload_engine else False

    def restore():
        write_bytes(config_path, original_config)
        if is_profile:
            if original_store is None:
                store_path.unlink(missing_ok=True)
            else:
                write_bytes(store_path, original_store)
        router.load_config()

    try:
        if is_profile:
            if error := profile_error(root, mapped):
                return {"applied": False, "error": error, "reload_rc": 1}
            manager.apply_profile(root, mapped[8:])
            result = {}
        else:
            from setup_tui import apply_preset_by_name

            result = apply_preset_by_name(root, mapped)
        # Reload must read the new route table, not pre-apply globals.
        rc = router.load_config()
        if rc == 0 and was_running and not (root / "state" / "manual-off").exists():
            rc = (
                router._elevated_reload()
                if router._engine_runs_as_root()
                else router.engine_reload()
            )
        if rc:
            restore()
            return {
                "applied": False,
                "preset": mapped,
                "reload_rc": rc,
                "checked_at": now,
            }
    except (Exception, SystemExit):
        restore()
        raise
    write_json(
        root / "state" / "network-preset.json",
        {"ssid": router.current_ssid(), "preset": mapped, "applied_at": now},
    )
    return {
        "applied": True,
        **result,
        "preset": mapped,
        "reload_rc": 0,
        "checked_at": now,
    }


class Guard:
    def __init__(self):
        self.losses = 0
        self.returns = 0
        self.pending_disconnect = False

    def completed(self, action, rc):
        if action == "network-disconnect":
            self.pending_disconnect = rc != 0

    def action(self, status, *, enabled, manual_off, network_off):
        if manual_off or not status.get("supported"):
            self.losses = self.returns = 0
            self.pending_disconnect = False
            return None
        if status.get("connected"):
            self.pending_disconnect = False
            self.losses = 0
            self.returns += 1
            return "network-reconnect" if network_off and self.returns >= 2 else None
        self.returns = 0
        self.losses += 1
        return (
            "network-disconnect"
            if enabled
            and self.losses >= 2
            and (not network_off or self.pending_disconnect)
            else None
        )


def start(root):
    root = Path(root)
    path = root / "state" / "network-guard.lock"
    # Probe the lifetime lock before spawning; children also claim it to
    # close the race between simultaneous Connect commands.
    try:
        with worker_lock.exclusive(path, timeout=0.01):
            pass
    except TimeoutError:
        return
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--worker", str(root)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def worker(root):
    root = Path(root)
    try:
        with worker_lock.exclusive(root / "state" / "network-guard.lock", timeout=0.1):
            guard = Guard()
            last_check = 0
            while not (root / "state" / "manual-off").exists():
                status = view(root, probe(root))
                action = guard.action(
                    status,
                    enabled=disconnect_enabled(root),
                    manual_off=False,
                    network_off=(root / "state" / "network-off").exists(),
                )
                try:
                    if action:
                        if action == "network-reconnect":
                            subprocess.run(
                                [
                                    sys.executable,
                                    str(root / "router.py"),
                                    "network-check",
                                ],
                                timeout=45,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                        completed = subprocess.run(
                            [sys.executable, str(root / "router.py"), action],
                            timeout=45,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        guard.completed(action, completed.returncode)
                        write_json(
                            root / "state" / "network-guard.json",
                            {
                                "action": action,
                                "returncode": completed.returncode,
                                "checked_at": int(time.time()),
                            },
                        )
                    elif status.get("connected") and time.monotonic() - last_check > 15:
                        checked = subprocess.run(
                            [sys.executable, str(root / "router.py"), "network-check"],
                            timeout=45, capture_output=True, text=True,
                        )
                        try:
                            result = json.loads(getattr(checked, "stdout", ""))
                        except (ValueError, TypeError):
                            result = {"error": "network-check returned no result"}
                        write_json(root / "state" / "network-auto.json", {
                            "result": result, "returncode": checked.returncode,
                            "checked_at": int(time.time()),
                        })
                        last_check = time.monotonic()
                except (OSError, subprocess.SubprocessError):
                    guard.completed(action, 1)
                    write_json(
                        root / "state" / "network-guard.json",
                        {
                            "action": action,
                            "returncode": 1,
                            "checked_at": int(time.time()),
                        },
                    )
                time.sleep(5)
    except TimeoutError:
        return


if __name__ == "__main__":
    worker(Path(sys.argv[2]))

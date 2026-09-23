#!/usr/bin/env python3
"""Opt-in network monitor for proxy-router.

The monitor is deliberately separate from the routing engine. Nothing here runs
unless the user invokes ``monitor check`` or starts the detached worker with
``monitor on``. Samples are bounded JSONL records under ``state/monitor``.
"""
from __future__ import annotations

import argparse
import collections
import functools
import http.client
import ipaddress
import json
import os
import platform
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import net_safety
import worker_lock

ROOT = Path(os.environ.get("PROXY_ROUTER_ROOT") or Path(__file__).resolve().parent).resolve()
DEFAULT_INTERVAL = 60
DEFAULT_HTTP_URL = "https://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"
DEFAULT_PING_HOSTS = ("1.1.1.1", "8.8.8.8")
DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_TIMEOUT = 10
MAX_LOG_LINES = 100
# Rotate the samples file once it grows past either bound (F11): the worker
# appends a line every interval, so without a cap samples.jsonl grows forever.
MAX_SAMPLE_LINES = 10_000
MAX_SAMPLE_BYTES = 5_000_000
DEFAULT_HEADERS = {
    "User-Agent": "proxy-router-monitor/1.0",
    "Accept": "*/*",
}

# --- Issue #64: validated monitor targets -----------------------------------
# Trust model: router.json's monitor URLs point at public internet endpoints
# (default: Cloudflare) and are NOT a place where secrets live, but they must
# never aim the worker at infrastructure. Loopback, private, link-local and
# known cloud-metadata ranges are therefore rejected unless the operator sets
# PROXY_ROUTER_ALLOW_PRIVATE_TARGETS=1 (the explicit opt-in). Validation is
# re-run against the *resolved* addresses right before connecting, which also
# closes the DNS-rebinding window (config-time check passes on a public name,
# resolution later returns 127.0.0.1 / 169.254.169.254).
PRIVATE_TARGET_BYPASS_ENV = net_safety.PRIVATE_TARGET_BYPASS_ENV
_METADATA_HOSTNAMES = net_safety.METADATA_HOSTNAMES
_METADATA_ADDRESSES = net_safety.METADATA_ADDRESSES


def _addr_is_private(addr: str) -> bool:
    """True for loopback / private / link-local / reserved / multicast IPs."""
    return net_safety.addr_is_private(addr)


def target_violation(url: str, *, resolved_addresses=None) -> str | None:
    """Return why ``url`` is an unsafe monitor target, or None when allowed.

    Checks scheme (http/https only — no file://, ftp://, ...), credentials,
    literal private/metadata hosts, and — when ``resolved_addresses`` is given
    — every address the name actually resolves to, so a rebinding DNS answer
    cannot slip a probe to loopback/LAN/metadata after config validation.
    """
    if os.environ.get(PRIVATE_TARGET_BYPASS_ENV, "").strip().lower() in {"1", "true", "yes"}:
        if isinstance(url, str):
            try:
                parsed = urlsplit(url)
                if parsed.scheme in ("http", "https") and parsed.hostname:
                    return None
            except ValueError:
                pass
        return "scheme must be http/https with a hostname"
    if not isinstance(url, str):
        return "target must be a string URL"
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "unparseable URL"
    if parsed.scheme not in ("http", "https"):
        return f"scheme {parsed.scheme!r} must be http/https"
    host = parsed.hostname
    if not host:
        return "missing hostname"
    if parsed.username is not None or parsed.password is not None:
        return "credentials in URL are not allowed"
    bare = host.rstrip(".").lower()
    if bare in _METADATA_HOSTNAMES:
        return f"{bare} is a metadata endpoint"
    if bare == "localhost" or bare.endswith(".localhost") or bare.endswith(".local"):
        # Names that can only ever mean this machine / the LAN segment.
        return f"{bare} is a private/loopback/metadata target"
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        if _addr_is_private(bare):
            return f"{bare} is a private/loopback/metadata target"
    for addr in resolved_addresses or ():
        if str(addr).strip("[]").lower() in _METADATA_ADDRESSES:
            return "resolved to a metadata endpoint"
        if _addr_is_private(str(addr).strip("[]")):
            return f"resolved to private/loopback address {addr}"
    return None


def resolve_target_addresses(url: str) -> list[str]:
    """Best-effort DNS resolution for connection-time target validation."""
    return net_safety.resolve_target_addresses(url)


def _reject_unsafe_url(url: str) -> str | None:
    """Config-time violation for ``url``, else None. No DNS here."""
    return target_violation(url)


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirect hops that fail the monitor target policy."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        violation = target_violation(
            newurl, resolved_addresses=resolve_target_addresses(newurl)
        )
        if violation is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validated_connection_addresses(url: str) -> tuple[str, ...]:
    """Resolve and validate once; the returned IPs are the only dial targets."""
    violation = target_violation(url)
    if violation is not None:
        raise urllib.error.URLError(f"unsafe monitor target: {violation}")

    addresses = tuple(resolve_target_addresses(url))
    if not addresses:
        raise urllib.error.URLError("monitor target did not resolve to an address")
    violation = target_violation(url, resolved_addresses=addresses)
    if violation is not None:
        raise urllib.error.URLError(f"unsafe monitor target: {violation}")
    return addresses


class _PinnedConnectMixin:
    """Dial only validated numeric IPs while retaining the URL hostname."""

    def __init__(self, host, *args, pinned_addresses, **kwargs):
        self._pinned_addresses = tuple(pinned_addresses)
        super().__init__(host, *args, **kwargs)
        # HTTPConnection stores socket.create_connection on the instance, so
        # replace that attribute after its initializer returns.
        self._create_connection = self._create_pinned_connection

    def _create_pinned_connection(self, address, timeout=None, source_address=None):
        host, port = address
        if host != self.host:
            raise OSError("monitor connection host changed after validation")

        last_error = None
        for pinned_address in self._pinned_addresses:
            try:
                return socket.create_connection(
                    (pinned_address, port), timeout, source_address
                )
            except OSError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise OSError("monitor connection has no validated addresses")


class _PinnedHTTPConnection(_PinnedConnectMixin, http.client.HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectMixin, http.client.HTTPSConnection):
    pass


def _pinned_connection_factory(url: str, connection_type):
    addresses = _validated_connection_addresses(url)
    return functools.partial(connection_type, pinned_addresses=addresses)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        connection = _pinned_connection_factory(req.full_url, _PinnedHTTPConnection)
        return self.do_open(connection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        connection = _pinned_connection_factory(req.full_url, _PinnedHTTPSConnection)
        return self.do_open(
            connection,
            req,
            context=getattr(self, "_context", None),
        )


# A proxy would resolve the destination outside this process, bypassing pinning.
_SAFE_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _ValidatedRedirectHandler,
    _PinnedHTTPHandler,
    _PinnedHTTPSHandler,
)


def _safe_urlopen(url, timeout=None):
    """Default monitor transport: validate and pin every request and redirect."""
    return _SAFE_OPENER.open(url, timeout=timeout)


def _uses_urllib_transport(opener) -> bool:
    """True for built-in transports that accept urllib Request objects."""
    return opener is _safe_urlopen or opener is urllib.request.urlopen


def validate_ping_host(host: str) -> str | None:
    """Return why ``host`` is unsafe to append to a ping argv, else None.

    Conservative allow-list: IPv4/IPv6 literals (bracketed or bare) or
    hostnames made only of letters/digits/dots/hyphens/colons — no whitespace,
    no shell metacharacters and, critically, no leading hyphen, so option
    injection like ``-c 1`` or ``-i 0.001`` is impossible. Length capped at
    253 per hostname limits.
    """
    text = str(host)
    if not text or len(text) > 253:
        return "host empty or over 253 characters"
    if text.startswith("-"):
        return "leading hyphen looks like a ping option injection"
    if text.isdigit():
        # Bare numbers ("3", "8080") are never valid hosts; they read as
        # injected argv values and must not survive settings sanitization.
        return "bare number is not a host"
    allowed = ".:-[]0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if any(ch not in allowed for ch in text):
        return "host has characters outside [.:-] alphanumerics"
    return None


def _open_request(opener, request, timeout: float):
    """Route urllib transports through DNS-pinned connections."""
    transport = _safe_urlopen if _uses_urllib_transport(opener) else opener
    return transport(request, timeout=timeout)


def _open(opener, url: str, timeout: float):
    """Use browser-like headers for urllib transports; keep injected openers simple."""
    if _uses_urllib_transport(opener):
        request = urllib.request.Request(url, headers=DEFAULT_HEADERS)
        return _open_request(opener, request, timeout)
    return opener(url, timeout=timeout)


def monitor_dir(root: Path | None = None) -> Path:
    return (Path(root) if root is not None else ROOT) / "state" / "monitor"


def pid_file(root: Path | None = None) -> Path:
    return monitor_dir(root) / "pid"


def enabled_file(root: Path | None = None) -> Path:
    return monitor_dir(root) / "enabled"


def samples_file(root: Path | None = None) -> Path:
    return monitor_dir(root) / "samples.jsonl"


def _error(message: str, **extra) -> dict:
    result = {"error": message}
    result.update(extra)
    return result


def _network_error(exc: Exception, url: str, **extra) -> dict:
    """Keep exception details useful without persisting a credential-bearing URL."""
    url_text = str(url)
    message = str(exc).replace(url_text, "[REDACTED_URL]")
    message = re.sub(r"https?://[^\s'\"]+", "[REDACTED_URL]", message)
    return _error(f"{type(exc).__name__}: {message}", **extra)


def _close(response) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        close()


def parse_ping_output(text: str) -> dict:
    """Parse macOS/Linux or Windows ping output without assuming locale details."""
    match = re.search(
        r"(?:min/avg/max/(?:stddev|mdev)|Minimum\s*=)\s*=?\s*"
        r"([0-9.]+)[/\s]+([0-9.]+)[/\s]+([0-9.]+)",
        text,
        re.IGNORECASE,
    )
    if match:
        return {
            "min_ms": float(match.group(1)),
            "avg_ms": float(match.group(2)),
            "max_ms": float(match.group(3)),
        }
    windows = re.search(
        r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
        text,
        re.IGNORECASE,
    )
    if windows:
        return {
            "min_ms": float(windows.group(1)),
            "avg_ms": float(windows.group(3)),
            "max_ms": float(windows.group(2)),
        }
    return {"min_ms": None, "avg_ms": None, "max_ms": None, "error": "ping result unavailable"}


def _safe_target(url: str) -> str:
    try:
        parsed = urlsplit(str(url))
        return parsed.hostname or "configured-target"
    except (TypeError, ValueError):
        return "configured-target"


def measure_http_latency(url: str = DEFAULT_HTTP_URL, *, opener=_safe_urlopen,
                         clock=time.monotonic, timeout: float = 5) -> dict:
    started = clock()
    response = None
    violation = target_violation(url)
    if violation is not None:
        return _network_error(ValueError(f"unsafe monitor target: {violation}"),
                              url, target=_safe_target(url))
    try:
        response = _open(opener, url, timeout)
        response.read(1)
        result = {
            "target": _safe_target(url),
            "status": int(getattr(response, "status", getattr(response, "code", 200))),
            "latency_ms": round((clock() - started) * 1000, 2),
        }
        return result
    except Exception as exc:  # network errors are data, not monitor crashes
        return _network_error(exc, url, target=_safe_target(url))
    finally:
        if response is not None:
            _close(response)


def _throughput(bytes_read: int, elapsed: float) -> float | None:
    if elapsed <= 0:
        return None
    return round(bytes_read * 8 / elapsed / 1_000_000, 3)


def measure_download(url: str = DEFAULT_DOWNLOAD_URL, *, max_bytes: int = DEFAULT_MAX_BYTES,
                     opener=_safe_urlopen, clock=time.monotonic,
                     timeout: float = DEFAULT_TIMEOUT) -> dict:
    max_bytes = max(1, int(max_bytes))
    started = clock()
    response = None
    total = 0
    violation = target_violation(url)
    if violation is not None:
        return _network_error(ValueError(f"unsafe monitor target: {violation}"), url, bytes=0)
    try:
        response = _open(opener, url, timeout)
        while total < max_bytes:
            chunk = response.read(min(64 * 1024, max_bytes - total))
            if not chunk:
                break
            total += len(chunk)
        elapsed = clock() - started
        return {"bytes": total, "mbps": _throughput(total, elapsed)}
    except Exception as exc:
        return _network_error(exc, url, bytes=total)
    finally:
        if response is not None:
            _close(response)


def measure_upload(url: str = DEFAULT_UPLOAD_URL, *, max_bytes: int = DEFAULT_MAX_BYTES,
                   opener=_safe_urlopen, clock=time.monotonic,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    max_bytes = max(1, int(max_bytes))
    payload = b"0" * max_bytes
    started = clock()
    response = None
    violation = target_violation(url)
    if violation is not None:
        return _network_error(ValueError(f"unsafe monitor target: {violation}"), url, bytes=max_bytes)
    try:
        request = urllib.request.Request(url, data=payload, headers=DEFAULT_HEADERS, method="POST")
        response = _open_request(opener, request, timeout)
        response.read(1)
        elapsed = clock() - started
        return {"bytes": max_bytes, "mbps": _throughput(max_bytes, elapsed),
                "status": int(getattr(response, "status", getattr(response, "code", 200)))}
    except Exception as exc:
        return _network_error(exc, url, bytes=max_bytes)
    finally:
        if response is not None:
            _close(response)


def measure_ping(host: str, *, command_runner=subprocess.run,
                 system: str | None = None, timeout: float = 8) -> dict:
    violation = validate_ping_host(host)
    if violation is not None:
        return _error(f"unsafe ping target: {violation}", host=host)
    system = system or platform.system()
    if system == "Windows":
        command = ["ping", "-n", "3", "-w", "2000", host]
    elif system == "Darwin":
        # macOS: -W is in milliseconds.
        command = ["ping", "-c", "3", "-W", "2000", host]
    else:
        # Linux: -W is in SECONDS; 2000 would be an ~33-minute dead wait (F9).
        command = ["ping", "-c", "3", "-W", "2", host]
    try:
        result = command_runner(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return _error("ping command unavailable", host=host)
    except Exception as exc:
        return _error(f"{type(exc).__name__}: {exc}", host=host)
    parsed = parse_ping_output((result.stdout or "") + "\n" + (result.stderr or ""))
    parsed["host"] = host
    if getattr(result, "returncode", 0) != 0 and parsed.get("avg_ms") is None:
        parsed.setdefault("error", "ping failed")
    return parsed


def _monitor_settings(root: Path) -> dict:
    settings = {
        "interval_seconds": DEFAULT_INTERVAL,
        "http_url": DEFAULT_HTTP_URL,
        "download_url": DEFAULT_DOWNLOAD_URL,
        "upload_url": DEFAULT_UPLOAD_URL,
        "ping_hosts": list(DEFAULT_PING_HOSTS),
        "max_bytes": DEFAULT_MAX_BYTES,
        "timeout_seconds": DEFAULT_TIMEOUT,
    }
    config = root / "router.json"
    try:
        data = json.loads(config.read_text())
        custom = data.get("monitor", {}) if isinstance(data, dict) else {}
        if isinstance(custom, dict):
            for key in settings:
                if key in custom:
                    settings[key] = custom[key]
    except (OSError, json.JSONDecodeError):
        pass
    for key in ("http_url", "download_url", "upload_url"):
        value = settings[key]
        try:
            parsed = urlsplit(value) if isinstance(value, str) else None
        except ValueError:
            parsed = None
        if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            settings[key] = {
                "http_url": DEFAULT_HTTP_URL,
                "download_url": DEFAULT_DOWNLOAD_URL,
                "upload_url": DEFAULT_UPLOAD_URL,
            }[key]
        else:
            # Issue #64: config-time target validation. A URL that aims the
            # worker at loopback/LAN/link-local/metadata (or a non-http
            # scheme smuggled past the check above) falls back to the safe
            # default instead of being probed.
            violation = _reject_unsafe_url(settings[key])
            if violation is not None:
                settings[key] = {
                    "http_url": DEFAULT_HTTP_URL,
                    "download_url": DEFAULT_DOWNLOAD_URL,
                    "upload_url": DEFAULT_UPLOAD_URL,
                }[key]
    try:
        settings["interval_seconds"] = max(5, int(settings["interval_seconds"]))
    except (TypeError, ValueError):
        settings["interval_seconds"] = DEFAULT_INTERVAL
    try:
        settings["max_bytes"] = min(max(1, int(settings["max_bytes"])), 10_000_000)
    except (TypeError, ValueError):
        settings["max_bytes"] = DEFAULT_MAX_BYTES
    try:
        settings["timeout_seconds"] = min(max(1, float(settings["timeout_seconds"])), 60)
    except (TypeError, ValueError):
        settings["timeout_seconds"] = DEFAULT_TIMEOUT
    hosts = settings["ping_hosts"]
    if not isinstance(hosts, (list, tuple)):
        hosts = DEFAULT_PING_HOSTS
    # Issue #64: keep only conservative DNS/IP values; anything option-like or
    # metacharacter-bearing is dropped rather than passed to the ping argv.
    settings["ping_hosts"] = [
        str(x) for x in hosts
        if str(x) and validate_ping_host(str(x)) is None
    ][:8]
    return settings


def collect_sample(root: Path | None = None, *, opener=_safe_urlopen,
                   command_runner=subprocess.run, clock=time.monotonic,
                   include_speed: bool = True) -> dict:
    """Collect one bounded sample; this function is only called by check/worker."""
    root = Path(root) if root is not None else ROOT
    settings = _monitor_settings(root)
    sample = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "http": measure_http_latency(settings["http_url"], opener=opener, clock=clock,
                                      timeout=settings["timeout_seconds"]),
        "ping": [measure_ping(host, command_runner=command_runner) for host in settings["ping_hosts"]],
    }
    if include_speed:
        sample["download"] = measure_download(
            settings["download_url"], max_bytes=settings["max_bytes"], opener=opener,
            clock=clock, timeout=settings["timeout_seconds"],
        )
        sample["upload"] = measure_upload(
            settings["upload_url"], max_bytes=settings["max_bytes"], opener=opener,
            clock=clock, timeout=settings["timeout_seconds"],
        )
    return sample


def _pid_matches(pid: int, root: Path) -> bool:
    """Confirm a PID belongs to this monitor worker before trusting/killing it."""
    if pid <= 0:
        return False
    root = Path(root).resolve()
    try:
        if os.name == "nt":
            command = [
                "powershell", "-NoProfile", "-Command",
                f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine",
            ]
        else:
            command = ["ps", "-p", str(pid), "-o", "command="]
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return False
    command_line = result.stdout or ""
    try:
        tokens = shlex.split(command_line)
    except ValueError:
        tokens = command_line.split()
    script_ok = any(Path(token).name == "monitor.py" for token in tokens)
    root_arg = None
    if "--root" in tokens:
        index = tokens.index("--root")
        if index + 1 < len(tokens):
            root_arg = tokens[index + 1]
    return (
        result.returncode == 0
        and script_ok
        and "--worker" in tokens
        and root_arg == str(root)
    )


def _pid_running(pid: int, root: Path | None = None) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return root is None or _pid_matches(pid, Path(root))



def _read_pid(root: Path) -> int | None:
    try:
        return int(pid_file(root).read_text().strip())
    except (OSError, ValueError):
        return None


def status(root: Path | None = None, *, pid_checker=None) -> dict:
    """Read state only; never performs network probes."""
    root = Path(root) if root is not None else ROOT
    pid = _read_pid(root)
    if pid_checker is None:
        running = bool(pid and _pid_running(pid, root))
    else:
        running = bool(pid and pid_checker(pid))
    return {
        "enabled": enabled_file(root).is_file(),
        "running": running,
        "pid": pid,
        "samples": samples_file(root).is_file(),
    }


def worker_command(root: Path, interval: int) -> list[str]:
    return [sys.executable, str(Path(__file__).resolve()), "--worker", "--root", str(root),
            "--interval", str(int(interval))]


def start(root: Path | None = None, *, interval: int | None = None) -> dict:
    root = Path(root) if root is not None else ROOT
    try:
        with worker_lock.exclusive(monitor_dir(root) / "start.lock"):
            return _start_locked(root, interval)
    except TimeoutError as exc:
        return {"started": False, "error": str(exc)}


def _start_locked(root: Path, interval: int | None) -> dict:
    current = status(root)
    if current["running"]:
        return {"started": False, "already_running": True, "pid": current["pid"]}
    interval = max(5, int(interval or _monitor_settings(root)["interval_seconds"]))
    directory = monitor_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    # Enable marker first: the child must never observe a missing marker and
    # exit during the parent/child spawn race.
    enabled_file(root).write_text("enabled\n")
    os.chmod(enabled_file(root), 0o600)
    command = worker_command(root, interval)
    try:
        proc = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError as exc:
        enabled_file(root).unlink(missing_ok=True)
        return {"started": False, "error": f"could not start monitor: {exc}"}
    pid_file(root).write_text(str(proc.pid))
    os.chmod(pid_file(root), 0o600)
    return {"started": True, "pid": proc.pid, "interval_seconds": interval}


STOP_CONFIRM_SECONDS = 3.0


def stop(root: Path | None = None) -> dict:
    root = Path(root) if root is not None else ROOT
    try:
        with worker_lock.exclusive(monitor_dir(root) / "start.lock"):
            return _stop_locked(root)
    except TimeoutError as exc:
        return {"stopped": False, "confirmed": False, "error": str(exc)}


def _stop_locked(root: Path) -> dict:
    pid = _read_pid(root)
    confirmed = True
    if pid and _pid_running(pid, root):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.monotonic() + STOP_CONFIRM_SECONDS
        while time.monotonic() < deadline and _pid_running(pid, root):
            time.sleep(0.1)
        confirmed = not _pid_running(pid, root)
    pid_file(root).unlink(missing_ok=True)
    enabled_file(root).unlink(missing_ok=True)
    return {"stopped": True, "confirmed": confirmed, "pid": pid}


def _rotate_samples_if_needed(path: Path) -> None:
    """Archive a too-large/too-long samples file to ``samples.jsonl.1``."""
    try:
        size = path.stat().st_size
        with path.open() as handle:
            lines = sum(1 for _ in handle)
    except OSError:
        return
    if size < MAX_SAMPLE_BYTES and lines < MAX_SAMPLE_LINES:
        return
    archive = path.with_suffix(path.suffix + ".1")
    archive.unlink(missing_ok=True)
    try:
        path.rename(archive)
    except OSError:
        pass


def append_sample(root: Path, sample: dict) -> None:
    path = samples_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_samples_if_needed(path)
    with path.open("a") as handle:
        handle.write(json.dumps(sample, separators=(",", ":")) + "\n")
    os.chmod(path, 0o600)


def worker(root: Path, interval: int) -> int:
    """Worker entrypoint. It exits naturally when monitor off removes enabled."""
    root = Path(root)
    enabled_file(root).parent.mkdir(parents=True, exist_ok=True)
    while enabled_file(root).is_file():
        try:
            append_sample(root, collect_sample(root))
        except Exception as exc:  # keep the worker alive but record no secrets
            append_sample(root, {"timestamp": datetime.now(timezone.utc).isoformat(),
                                 "error": f"{type(exc).__name__}: {exc}"})
        time.sleep(max(5, int(interval)))
    return 0


def tail_logs(root: Path | None = None, *, lines: int = 20) -> str:
    path = samples_file(Path(root) if root is not None else ROOT)
    if not path.is_file():
        return ""
    lines = min(max(1, int(lines)), MAX_LOG_LINES)
    with path.open() as handle:
        return "".join(collections.deque(handle, maxlen=lines))


def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv=None, root=None) -> int:
    global ROOT
    if root is not None:
        ROOT = Path(root).resolve()
    argv = list(argv or sys.argv[1:])
    if argv and argv[0] == "monitor":
        argv = argv[1:]
    parser = argparse.ArgumentParser(prog="proxy-router monitor")
    parser.add_argument("action", nargs="?", choices=["check", "on", "off", "status", "logs"])
    parser.add_argument("--root", default=None)
    parser.add_argument("--interval", type=int, default=None)
    parser.add_argument("--lines", type=int, default=20)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args(argv)
    target = Path(args.root).resolve() if args.root else ROOT
    if args.worker:
        return worker(target, args.interval or _monitor_settings(target)["interval_seconds"])
    if args.action == "check":
        _print_json(collect_sample(target))
        return 0
    if args.action == "on":
        _print_json(start(target, interval=args.interval))
        return 0
    if args.action == "off":
        _print_json(stop(target))
        return 0
    if args.action == "status":
        _print_json(status(target))
        return 0
    if args.action == "logs":
        text = tail_logs(target, lines=args.lines)
        print(text, end="" if text.endswith("\n") or not text else "\n")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

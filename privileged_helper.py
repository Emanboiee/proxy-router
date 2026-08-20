#!/usr/bin/python3
"""Minimal root-owned lifecycle helper for proxy-router on macOS.

The importable validation surface is shared by the unprivileged controller and
the installed root-owned copy. Privileged process/file operations are added in
small, separately tested slices below this boundary.
"""
from __future__ import annotations

import ipaddress
import hashlib
import io
import fcntl
import contextlib
import functools
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path


SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_RELEASE_BINARY_BYTES = 80 * 1024 * 1024
HELPER_OPERATIONS = frozenset({"status", "start", "stop", "reload", "uninstall"})
_LIFECYCLE_LOCKS: dict[str, threading.RLock] = {}
_LIFECYCLE_LOCKS_GUARD = threading.Lock()
_LIFECYCLE_LOCAL = threading.local()


class ValidationError(ValueError):
    """The user-generated helper request is outside the closed schema."""


def parse_helper_request(argv: list[str], pinned_uid: int) -> str:
    """Return the one exact authorized operation or reject before mutation."""
    if not isinstance(argv, list) or len(argv) != 2:
        raise ValidationError("helper needs exactly operation and pinned uid")
    operation, raw_uid = argv
    if operation not in HELPER_OPERATIONS:
        raise ValidationError("unknown helper operation")
    if not isinstance(raw_uid, str) or not raw_uid.isascii() or not raw_uid.isdecimal():
        raise ValidationError("helper uid must be decimal")
    if int(raw_uid) != pinned_uid:
        raise ValidationError("helper uid does not match installed owner")
    return operation


def sing_box_environment(state_directory: Path) -> dict[str, str]:
    """Return the complete environment for the privileged sing-box child."""
    return {
        "HOME": os.fspath(state_directory),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
    }


class SecurityError(RuntimeError):
    """A privileged filesystem/process trust invariant did not hold."""


@contextlib.contextmanager
def lifecycle_lock(metadata: "RuntimeMetadata"):
    """Serialize every helper lifecycle operation across threads/processes."""
    key = os.fspath(metadata.state_dir)
    with _LIFECYCLE_LOCKS_GUARD:
        thread_lock = _LIFECYCLE_LOCKS.setdefault(key, threading.RLock())
    with thread_lock:
        depths = getattr(_LIFECYCLE_LOCAL, "depths", {})
        depth = depths.get(key, 0)
        if depth:
            depths[key] = depth + 1
            _LIFECYCLE_LOCAL.depths = depths
            try:
                yield
            finally:
                depths[key] -= 1
            return
        verify_secure_chain(metadata.state_dir, owner_uid=metadata.root_uid, anchor=metadata.state_dir)
        directory_fd = os.open(
            metadata.state_dir,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        fd = None
        try:
            flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            fd = None
            created = False
            for _attempt in range(8):
                try:
                    fd = os.open("helper.lock", flags, dir_fd=directory_fd)
                    break
                except FileNotFoundError:
                    try:
                        fd = os.open(
                            "helper.lock",
                            flags | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=directory_fd,
                        )
                        created = True
                        break
                    except FileExistsError:
                        continue
            if fd is None:
                raise SecurityError("helper lifecycle lock creation did not stabilize")
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != metadata.root_uid
                or (not created and stat.S_IMODE(info.st_mode) != 0o600)
            ):
                raise SecurityError("helper lifecycle lock has unsafe type, links, owner, or mode")
            if created:
                if info.st_gid != metadata.root_gid:
                    os.fchown(fd, metadata.root_uid, metadata.root_gid)
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                os.fsync(directory_fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            depths[key] = 1
            _LIFECYCLE_LOCAL.depths = depths
            try:
                yield
            finally:
                depths.pop(key, None)
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory_fd)


def _serialized_lifecycle(runtime_position: int):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            runtime = args[runtime_position]
            with lifecycle_lock(runtime):
                return function(*args, **kwargs)
        return wrapped
    return decorate


def release_for_architecture(
    manifest_path: Path,
    architecture: str,
    *,
    owner_uid: int,
    anchor: Path,
) -> dict:
    """Load one exact reviewed sing-box release entry."""
    verify_secure_chain(manifest_path, owner_uid=owner_uid, anchor=anchor)
    try:
        value = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityError(f"cannot load sing-box release manifest: {exc}") from exc
    value = _exact_object(value, {"schema_version", "release", "architectures"}, set(), "manifest")
    if value["schema_version"] != 1:
        raise SecurityError("unsupported sing-box release manifest version")
    release = _exact_object(value["release"], {"version", "tag"}, set(), "manifest release")
    if not isinstance(release["version"], str) or release["tag"] != "v" + release["version"]:
        raise SecurityError("sing-box manifest release identity is invalid")
    architectures = value["architectures"]
    if not isinstance(architectures, dict) or set(architectures) != {"arm64", "x86_64"}:
        raise SecurityError("sing-box manifest architectures must be exactly arm64 and x86_64")
    if architecture not in architectures:
        raise SecurityError(f"unsupported macOS architecture: {architecture}")
    entry = _exact_object(
        architectures[architecture],
        {"name", "url", "size", "sha256", "archive_root"},
        set(),
        "manifest architecture",
    )
    expected_prefix = f"sing-box-{release['version']}-darwin-"
    if (
        not isinstance(entry["name"], str)
        or not entry["name"].startswith(expected_prefix)
        or not entry["name"].endswith(".tar.gz")
        or entry["archive_root"] != entry["name"][:-7]
        or entry["url"] != f"https://github.com/SagerNet/sing-box/releases/download/{release['tag']}/{entry['name']}"
        or isinstance(entry["size"], bool)
        or not isinstance(entry["size"], int)
        or not 1_000_000 <= entry["size"] <= 100_000_000
        or not isinstance(entry["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
    ):
        raise SecurityError("sing-box manifest architecture entry is invalid")
    return {"version": release["version"], "tag": release["tag"], **entry}


def verified_release_binary(archive_bytes: bytes, release: dict) -> bytes:
    """Verify one pinned official archive and return its sole binary bytes."""
    if not isinstance(archive_bytes, bytes) or len(archive_bytes) > MAX_RELEASE_ARCHIVE_BYTES:
        raise SecurityError("sing-box archive has an invalid size")
    if (
        not isinstance(release, dict)
        or set(release) < {"archive_root", "size", "sha256"}
        or release["size"] != len(archive_bytes)
        or not isinstance(release["sha256"], str)
        or hashlib.sha256(archive_bytes).hexdigest() != release["sha256"]
    ):
        raise SecurityError("sing-box archive size or digest mismatch")
    root = release["archive_root"]
    if not isinstance(root, str) or not root or "/" in root or root in {".", ".."}:
        raise SecurityError("sing-box archive root is invalid")
    expected = {root, f"{root}/LICENSE", f"{root}/sing-box"}
    seen = set()
    binary = None
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r|gz") as archive:
            for member in archive:
                canonical = member.name.rstrip("/") if member.isdir() else member.name
                if canonical not in expected or canonical in seen:
                    raise SecurityError(f"unexpected or duplicate sing-box archive member: {member.name}")
                seen.add(canonical)
                if canonical == root:
                    if not member.isdir():
                        raise SecurityError("sing-box archive root must be a directory")
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise SecurityError("sing-box archive payloads must be regular files")
                limit = MAX_RELEASE_BINARY_BYTES if canonical.endswith("/sing-box") else 2 * 1024 * 1024
                if member.size < 1 or member.size > limit:
                    raise SecurityError("sing-box archive member size is invalid")
                if canonical.endswith("/sing-box"):
                    source = archive.extractfile(member)
                    if source is None:
                        raise SecurityError("cannot read sing-box archive binary")
                    binary = source.read(limit + 1)
                    if len(binary) != member.size or len(binary) > limit:
                        raise SecurityError("sing-box archive binary length mismatch")
    except (tarfile.TarError, OSError) as exc:
        raise SecurityError(f"cannot parse sing-box archive: {exc}") from exc
    if seen != expected or binary is None:
        raise SecurityError("sing-box archive does not have the exact reviewed shape")
    return binary


@dataclass(frozen=True)
class InstallMetadata:
    uid: int
    gid: int
    user_root: Path
    user_root_device: int
    user_root_inode: int


@dataclass(frozen=True)
class RuntimeMetadata:
    uid: int
    gid: int
    root_uid: int
    root_gid: int
    bundle_dir: Path
    state_dir: Path
    binary_sha256: str

    @property
    def binary(self) -> Path:
        return self.bundle_dir / "sing-box"

    @property
    def config(self) -> Path:
        return self.state_dir / "sing-box.json"

    @property
    def candidate_config(self) -> Path:
        return self.state_dir / "sing-box.json.candidate"

    @property
    def pid_file(self) -> Path:
        return self.state_dir / "sing-box.pid"


def load_installed_runtime(
    uid: int,
    *,
    state_base: Path = Path("/private/var/db/proxy-router"),
    versions_dir: Path = Path("/Library/PrivilegedHelperTools/com.proxy-router/versions"),
    root_uid: int = 0,
    root_gid: int = 0,
) -> tuple[InstallMetadata, RuntimeMetadata]:
    """Load strict root-owned install metadata without importing installer code."""
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        raise SecurityError("installed helper uid is invalid")
    state_base = Path(os.path.abspath(state_base))
    versions_dir = Path(os.path.abspath(versions_dir))
    state_dir = state_base / str(uid)
    metadata_path = state_dir / "install.json"
    verify_secure_chain(metadata_path, owner_uid=root_uid, anchor=state_base.parent)
    fd = os.open(metadata_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != root_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 65536
        ):
            raise SecurityError("install metadata has unsafe type, owner, mode, links, or size")
        payload = os.read(fd, 65537)
    finally:
        os.close(fd)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError(f"install metadata is invalid JSON: {exc}") from exc
    expected = {
        "schema_version", "uid", "gid", "user_root", "user_root_device",
        "user_root_inode", "bundle_digest", "binary_sha256", "state_dir",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise SecurityError("install metadata schema mismatch")
    if value["uid"] != uid or isinstance(value["gid"], bool) or not isinstance(value["gid"], int):
        raise SecurityError("install metadata owner mismatch")
    if value["state_dir"] != str(state_dir):
        raise SecurityError("install metadata state path mismatch")
    for key in ("bundle_digest", "binary_sha256"):
        if not isinstance(value[key], str) or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None:
            raise SecurityError(f"install metadata {key} is invalid")
    user_root = Path(value["user_root"])
    if not user_root.is_absolute():
        raise SecurityError("install metadata user root must be absolute")
    bundle_dir = versions_dir / value["bundle_digest"]
    verify_secure_chain(bundle_dir, owner_uid=root_uid, anchor=versions_dir.parent)
    install = InstallMetadata(
        uid=uid,
        gid=value["gid"],
        user_root=user_root,
        user_root_device=value["user_root_device"],
        user_root_inode=value["user_root_inode"],
    )
    runtime = RuntimeMetadata(
        uid=uid,
        gid=value["gid"],
        root_uid=root_uid,
        root_gid=root_gid,
        bundle_dir=bundle_dir,
        state_dir=state_dir,
        binary_sha256=value["binary_sha256"],
    )
    verify_runtime_binary(runtime)
    return install, runtime


def verify_runtime_binary(metadata: RuntimeMetadata) -> None:
    """Hash the installed binary from one no-follow FD before privileged use."""
    verify_secure_chain(metadata.binary, owner_uid=metadata.root_uid, anchor=metadata.bundle_dir)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(metadata.binary, flags)
    except OSError as exc:
        raise SecurityError(f"cannot open installed sing-box safely: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != metadata.root_uid:
            raise SecurityError("installed sing-box type/owner is invalid")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if digest.hexdigest() != metadata.binary_sha256:
            raise SecurityError("installed sing-box digest mismatch")
    finally:
        os.close(fd)


def process_state(pid: int, metadata: RuntimeMetadata, *, runner=subprocess.run) -> str:
    """Return missing, match, or foreign for one root-state PID."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return "missing"
    verify_runtime_binary(metadata)
    try:
        result = runner(
            ["/bin/ps", "-p", str(pid), "-o", "uid=,command="],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "missing"
    output = (result.stdout or "").strip()
    if not output:
        return "missing"
    parts = output.split(None, 1)
    if (
        len(parts) == 2
        and parts[0] == str(metadata.root_uid)
        and parts[1] == f"{metadata.binary} run -c {metadata.config}"
    ):
        return "match"
    return "foreign"


def process_matches(pid: int, metadata: RuntimeMetadata, *, runner=subprocess.run) -> bool:
    """Compatibility predicate for callers that only need verified liveness."""
    return process_state(pid, metadata, runner=runner) == "match"


def _runtime_pid(metadata: RuntimeMetadata) -> int | None:
    verify_secure_chain(metadata.state_dir, owner_uid=metadata.root_uid, anchor=metadata.state_dir)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_fd = os.open(metadata.state_dir, directory_flags)
    try:
        try:
            fd = os.open("sing-box.pid", file_flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SecurityError(f"cannot open root PID state safely: {exc}") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != metadata.root_uid
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 32
            ):
                raise SecurityError("root PID state has unsafe type, owner, mode, or size")
            raw = os.read(fd, 33)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)
    try:
        pid = int(raw.strip())
    except ValueError as exc:
        raise SecurityError("root PID state is not an integer") from exc
    if pid <= 1:
        raise SecurityError("root PID state is outside the signalable range")
    return pid


def _read_runtime_config(metadata: RuntimeMetadata) -> dict:
    verify_secure_chain(metadata.config, owner_uid=metadata.root_uid, anchor=metadata.state_dir)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(metadata.config, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != metadata.root_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_CONFIG_BYTES
        ):
            raise SecurityError("runtime config has unsafe type, owner, mode, or size")
        payload = os.read(fd, MAX_CONFIG_BYTES + 1)
    finally:
        os.close(fd)
    if len(payload) > MAX_CONFIG_BYTES:
        raise SecurityError("runtime config exceeds the helper size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError(f"runtime config is invalid JSON: {exc}") from exc
    validate_config_envelope(make_config_envelope(value))
    return value


def engine_status(metadata: RuntimeMetadata, *, runner=subprocess.run) -> dict:
    """Report canonical root backend state without returning config secrets."""
    verify_runtime_binary(metadata)
    pid = _runtime_pid(metadata)
    running = bool(pid is not None and process_matches(pid, metadata, runner=runner))
    mode = None
    if metadata.config.is_file():
        config = _read_runtime_config(metadata)
        mode = "tun" if any(item.get("type") == "tun" for item in config["inbounds"]) else "proxy"
    return {
        "installed": True,
        "running": running,
        "pid": pid if running else None,
        "mode": mode,
        "schema_version": SCHEMA_VERSION,
        "binary_sha256": metadata.binary_sha256,
    }


def _remove_runtime_pid(metadata: RuntimeMetadata) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(metadata.state_dir, flags)
    try:
        try:
            os.unlink("sing-box.pid", dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def stop_engine(
    metadata: RuntimeMetadata,
    *,
    runner=subprocess.run,
    killer=os.kill,
    sleeper=time.sleep,
    monotonic=time.monotonic,
    timeout: float = 3.0,
) -> dict:
    """Stop only the exact trusted root engine and confirm terminal state."""
    pid = _runtime_pid(metadata)
    if pid is None:
        return {"stopped": True, "pid": None, "killed": False}
    state = process_state(pid, metadata, runner=runner)
    if state == "missing":
        _remove_runtime_pid(metadata)
        return {"stopped": True, "pid": pid, "killed": False, "stale": True}
    if state != "match":
        raise SecurityError("root PID state does not identify the installed engine")
    killer(pid, signal.SIGTERM)
    deadline = monotonic() + max(0.0, float(timeout))
    state = process_state(pid, metadata, runner=runner)
    while state == "match":
        now = monotonic()
        if now >= deadline:
            break
        sleeper(min(0.05, deadline - now))
        state = process_state(pid, metadata, runner=runner)
    if state == "foreign":
        raise SecurityError("engine PID was reused during TERM wait")
    killed = False
    if state == "match" and process_state(pid, metadata, runner=runner) == "match":
        # Identity is explicitly rechecked immediately before KILL.
        killer(pid, signal.SIGKILL)
        killed = True
        final_deadline = monotonic() + 1.0
        state = process_state(pid, metadata, runner=runner)
        while state == "match":
            now = monotonic()
            if now >= final_deadline:
                raise SecurityError("installed engine survived SIGKILL")
            sleeper(min(0.05, final_deadline - now))
            state = process_state(pid, metadata, runner=runner)
        if state == "foreign":
            raise SecurityError("engine PID was reused during KILL wait")
    _remove_runtime_pid(metadata)
    return {"stopped": True, "pid": pid, "killed": killed}


def terminate_spawned_engine(
    pid: int,
    metadata: RuntimeMetadata,
    *,
    runner=subprocess.run,
    killer=os.kill,
    sleeper=time.sleep,
    monotonic=time.monotonic,
) -> None:
    """Terminate a just-spawned engine before PID state exists."""
    state = process_state(pid, metadata, runner=runner)
    if state == "missing":
        return
    if state != "match":
        raise SecurityError("spawned PID no longer identifies the installed engine")
    killer(pid, signal.SIGTERM)
    deadline = monotonic() + 1.0
    state = process_state(pid, metadata, runner=runner)
    while state == "match" and monotonic() < deadline:
        sleeper(0.05)
        state = process_state(pid, metadata, runner=runner)
    if state == "foreign":
        raise SecurityError("spawned PID was reused during cleanup")
    if state == "match" and process_state(pid, metadata, runner=runner) == "match":
        killer(pid, signal.SIGKILL)


def _write_runtime_pid(metadata: RuntimeMetadata, pid: int) -> None:
    state_fd = os.open(
        metadata.state_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        atomic_root_write(
            state_fd,
            "sing-box.pid",
            f"{pid}\n".encode("ascii"),
            0o600,
            owner_uid=metadata.root_uid,
            owner_gid=metadata.root_gid,
        )
    finally:
        os.close(state_fd)


def _write_runtime_config(metadata: RuntimeMetadata, payload: bytes) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(metadata.state_dir, flags)
    try:
        atomic_root_write(
            directory_fd,
            "sing-box.json.candidate",
            payload,
            0o600,
            owner_uid=metadata.root_uid,
            owner_gid=metadata.root_gid,
        )
    finally:
        os.close(directory_fd)


def _remove_runtime_candidate(metadata: RuntimeMetadata) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(metadata.state_dir, flags)
    try:
        try:
            os.unlink("sing-box.json.candidate", dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _promote_runtime_candidate(metadata: RuntimeMetadata) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(metadata.state_dir, flags)
    try:
        candidate = os.stat("sing-box.json.candidate", dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(candidate.st_mode)
            or candidate.st_uid != metadata.root_uid
            or stat.S_IMODE(candidate.st_mode) != 0o600
        ):
            raise SecurityError("runtime config candidate has unsafe type, owner, or mode")
        try:
            current = os.stat("sing-box.json", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != metadata.root_uid
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise SecurityError("runtime config target has unsafe type, owner, or mode")
        os.rename(
            "sing-box.json.candidate",
            "sing-box.json",
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _open_user_log(metadata: InstallMetadata) -> int:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    log_flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    root_fd = os.open(metadata.user_root, directory_flags)
    try:
        root_info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != metadata.uid
            or root_info.st_dev != metadata.user_root_device
            or root_info.st_ino != metadata.user_root_inode
            or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SecurityError("pinned user root identity changed before log open")
        created = False
        try:
            fd = os.open("sing-box.log", log_flags, dir_fd=root_fd)
        except FileNotFoundError:
            try:
                fd = os.open(
                    "sing-box.log",
                    log_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=root_fd,
                )
                created = True
            except OSError as exc:
                raise SecurityError(f"cannot create user log safely: {exc}") from exc
        except OSError as exc:
            raise SecurityError(f"cannot open user log safely: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SecurityError("user log must be one unlinked regular inode")
            if created:
                if info.st_uid != os.geteuid():
                    raise SecurityError("new user log has an unexpected owner")
                os.fchown(fd, metadata.uid, metadata.gid)
                os.fchmod(fd, 0o600)
            elif (
                info.st_uid != metadata.uid
                or info.st_gid != metadata.gid
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise SecurityError("existing user log owner/mode is unsafe")
            current_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, current_flags & ~os.O_NONBLOCK)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(root_fd)


def _wait_started(pid: int, metadata: RuntimeMetadata) -> bool:
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if process_matches(pid, metadata):
            return True
        time.sleep(0.05)
    return False


def _stage_checked_config(install: InstallMetadata, runtime: RuntimeMetadata, checker) -> None:
    raw = read_user_config(install)
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"user sing-box config is not valid JSON: {exc}") from exc
    validate_config_envelope(make_config_envelope(config))
    canonical = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8")
    verify_secure_chain(runtime.state_dir, owner_uid=runtime.root_uid, anchor=runtime.state_dir)
    _write_runtime_config(runtime, canonical)
    verify_runtime_binary(runtime)
    try:
        check = checker(
            [str(runtime.binary), "check", "-c", str(runtime.candidate_config)],
            capture_output=True,
            text=True,
            timeout=20,
            cwd=str(runtime.state_dir),
            env=sing_box_environment(runtime.state_dir),
        )
        if check.returncode != 0:
            raise SecurityError("pinned sing-box rejected the validated config")
        _promote_runtime_candidate(runtime)
    except BaseException:
        _remove_runtime_candidate(runtime)
        raise


def start_engine(
    install: InstallMetadata,
    runtime: RuntimeMetadata,
    *,
    checker=subprocess.run,
    popen=subprocess.Popen,
    waiter=_wait_started,
    stopper=stop_engine,
    pid_writer=_write_runtime_pid,
    spawn_cleanup=terminate_spawned_engine,
) -> dict:
    """Validate/copy one config and launch only the pinned root-owned binary."""
    log_fd = _open_user_log(install)
    try:
        _stage_checked_config(install, runtime, checker)
        environment = sing_box_environment(runtime.state_dir)
        if _runtime_pid(runtime) is not None:
            stopper(runtime)
        verify_runtime_binary(runtime)
        try:
            process = popen(
                [str(runtime.binary), "run", "-c", str(runtime.config)],
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                cwd=str(runtime.state_dir),
                env=environment,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise SecurityError(f"cannot start pinned sing-box: {exc}") from exc
    finally:
        os.close(log_fd)
    try:
        pid_writer(runtime, process.pid)
    except BaseException:
        spawn_cleanup(process.pid, runtime)
        raise
    if not waiter(process.pid, runtime):
        stopper(runtime)
        raise SecurityError("pinned sing-box did not reach a verified running state")
    return {"started": True, "pid": process.pid}


def reload_engine(
    install: InstallMetadata,
    runtime: RuntimeMetadata,
    *,
    checker=subprocess.run,
    runner=subprocess.run,
    killer=os.kill,
    waiter=_wait_started,
    starter=start_engine,
) -> dict:
    """Install checked config and SIGHUP only the exact trusted engine."""
    _stage_checked_config(install, runtime, checker)
    pid = _runtime_pid(runtime)
    if pid is None:
        started = starter(install, runtime)
        return {"reloaded": False, "started": True, "pid": started["pid"]}
    if not process_matches(pid, runtime, runner=runner):
        raise SecurityError("root PID state does not identify the installed engine")
    killer(pid, signal.SIGHUP)
    if not waiter(pid, runtime):
        raise SecurityError("installed engine did not recover after SIGHUP")
    return {"reloaded": True, "pid": pid}


# Public lifecycle entrypoints own the cross-process lock. Their defaults bind
# the original unlocked functions above, so nested start→stop and reload→start
# stay inside the already-held lock instead of deadlocking on a second FD.
stop_engine = _serialized_lifecycle(0)(stop_engine)
engine_status = _serialized_lifecycle(0)(engine_status)
start_engine = _serialized_lifecycle(1)(start_engine)
reload_engine = _serialized_lifecycle(1)(reload_engine)


def read_user_config(metadata: InstallMetadata) -> bytes:
    """Read the pinned user's config once without following links or devices."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        root_fd = os.open(metadata.user_root, directory_flags)
    except OSError as exc:
        raise SecurityError(f"cannot open pinned user root: {exc}") from exc
    try:
        root_info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != metadata.uid
            or root_info.st_dev != metadata.user_root_device
            or root_info.st_ino != metadata.user_root_inode
            or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SecurityError("pinned user root identity or permissions changed")
        try:
            config_fd = os.open("sing-box.json", file_flags, dir_fd=root_fd)
        except OSError as exc:
            raise SecurityError(f"cannot open user config safely: {exc}") from exc
        try:
            info = os.fstat(config_fd)
            if not stat.S_ISREG(info.st_mode):
                raise SecurityError("user config must be a regular file")
            if info.st_uid != metadata.uid or stat.S_IMODE(info.st_mode) != 0o600:
                raise SecurityError("user config owner/mode must match pinned user and 0600")
            if info.st_size > MAX_CONFIG_BYTES:
                raise SecurityError("user config exceeds the helper size limit")
            chunks = []
            total = 0
            while True:
                chunk = os.read(config_fd, min(65536, MAX_CONFIG_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_CONFIG_BYTES:
                    raise SecurityError("user config exceeds the helper size limit")
            return b"".join(chunks)
        finally:
            os.close(config_fd)
    finally:
        os.close(root_fd)


def atomic_root_write(
    directory_fd: int,
    name: str,
    payload: bytes,
    mode: int,
    *,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> None:
    """Atomically replace one expected regular file inside a secure dir FD."""
    if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name:
        raise SecurityError("atomic write needs one plain filename")
    if not isinstance(payload, bytes):
        raise SecurityError("atomic write payload must be bytes")
    directory = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != owner_uid
        or directory.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise SecurityError("atomic write directory is not securely owned")
    try:
        existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise SecurityError(f"cannot inspect atomic write target: {exc}") from exc
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != owner_uid
        or stat.S_IMODE(existing.st_mode) != mode
    ):
        raise SecurityError("atomic write target has unexpected type, owner, or mode")
    temporary = f".{name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = None
    renamed = False
    try:
        fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        created = os.fstat(fd)
        if not stat.S_ISREG(created.st_mode):
            raise SecurityError("atomic write temporary is not regular")
        if created.st_uid != owner_uid or created.st_gid != owner_gid:
            os.fchown(fd, owner_uid, owner_gid)
        os.fchmod(fd, mode)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise SecurityError("atomic write made no progress")
            written += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.rename(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        renamed = True
        os.fsync(directory_fd)
    except OSError as exc:
        raise SecurityError(f"atomic write failed: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if not renamed:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass


def verify_secure_chain(path: Path, *, owner_uid: int = 0, anchor: Path = Path("/")) -> None:
    """Verify one lexical path chain without following any symlink.

    Every component from ``anchor`` through ``path`` must have the expected
    owner and must not be group/other writable. Ancestors must be directories;
    the leaf may be a regular file or directory.
    """
    anchor = Path(os.path.abspath(os.fspath(anchor)))
    path = Path(os.path.abspath(os.fspath(path)))
    try:
        relative = path.relative_to(anchor)
    except ValueError as exc:
        raise SecurityError(f"{path} is outside secure anchor {anchor}") from exc
    components = [anchor]
    current = anchor
    for part in relative.parts:
        if part in {"", ".", ".."}:
            raise SecurityError("secure path contains an invalid component")
        current = current / part
        components.append(current)
    for index, component in enumerate(components):
        try:
            info = os.lstat(component)
        except OSError as exc:
            raise SecurityError(f"cannot inspect secure path component {component}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SecurityError(f"secure path component is a symlink: {component}")
        if info.st_uid != owner_uid:
            raise SecurityError(f"secure path component has wrong owner: {component}")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SecurityError(f"secure path component is group/other writable: {component}")
        is_leaf = index == len(components) - 1
        if not is_leaf and not stat.S_ISDIR(info.st_mode):
            raise SecurityError(f"secure path ancestor is not a directory: {component}")
        if is_leaf and not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise SecurityError(f"secure path leaf has an unsafe type: {component}")


def _exact_object(value: object, required: set, optional: set, label: str) -> dict:
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
        raise ValidationError(f"{label} keys must match the generated schema")
    return value


def _string(value: object, label: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{label} must be a bounded string")
    return value


def _strings(value: object, label: str, *, maximum_items: int = 256) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum_items
        or any(not isinstance(item, str) or not item or len(item) > 1024 for item in value)
    ):
        raise ValidationError(f"{label} must be a bounded string list")
    return value


def _validate_inbounds(value: object) -> None:
    if not isinstance(value, list):
        raise ValidationError("inbounds must be a list")
    for inbound in value:
        if not isinstance(inbound, dict):
            raise ValidationError("unsupported inbound type")
        if inbound.get("type") == "tun":
            required = {"type", "tag", "address", "mtu", "stack", "strict_route", "auto_route"}
            optional = {"route_address_set", "route_exclude_address"}
            if not required <= set(inbound) or set(inbound) - required - optional:
                raise ValidationError("tun inbound keys must match the generated schema")
            mtu = inbound["mtu"]
            if (
                inbound["tag"] != "tun-in"
                or not isinstance(inbound["stack"], str)
                or inbound["stack"] not in {"system", "gvisor", "mixed"}
                or inbound["strict_route"] is not False
                or inbound["auto_route"] is not True
                or isinstance(mtu, bool)
                or not isinstance(mtu, int)
                or not 576 <= mtu <= 9000
            ):
                raise ValidationError("tun inbound has unsafe fixed values")
            addresses = inbound["address"]
            if not isinstance(addresses, list) or not addresses or len(addresses) > 16:
                raise ValidationError("tun inbound address must be a bounded CIDR list")
            try:
                for address in addresses:
                    if not isinstance(address, str):
                        raise ValueError
                    ipaddress.ip_interface(address)
                for address in inbound.get("route_exclude_address", []):
                    if not isinstance(address, str):
                        raise ValueError
                    ipaddress.ip_network(address, strict=False)
            except ValueError as exc:
                raise ValidationError("tun inbound contains an invalid CIDR") from exc
            route_sets = inbound.get("route_address_set", [])
            if not isinstance(route_sets, list) or any(
                not isinstance(tag, str) or not tag.startswith("ruleset-") or len(tag) > 80
                for tag in route_sets
            ):
                raise ValidationError("tun inbound route_address_set is invalid")
            continue
        if inbound.get("type") != "mixed":
            raise ValidationError("unsupported inbound type")
        if set(inbound) != {"type", "tag", "listen", "listen_port"}:
            raise ValidationError("mixed inbound keys must match exactly")
        port = inbound["listen_port"]
        if (
            inbound["tag"] != "local-proxy"
            or inbound["listen"] != "127.0.0.1"
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1024 <= port <= 65535
        ):
            raise ValidationError("mixed inbound must be a bounded loopback listener")


def _validate_endpoints(value: object) -> None:
    if not isinstance(value, list) or len(value) > 64:
        raise ValidationError("endpoints must be a bounded list")
    for endpoint in value:
        endpoint = _exact_object(
            endpoint,
            {"type", "tag", "address", "private_key", "peers", "domain_resolver"},
            {"mtu"},
            "endpoint",
        )
        if endpoint["type"] != "wireguard":
            raise ValidationError("endpoint type must be wireguard")
        _string(endpoint["tag"], "endpoint tag", maximum=64)
        _string(endpoint["private_key"], "endpoint private_key", maximum=256)
        _string(endpoint["domain_resolver"], "endpoint domain_resolver", maximum=80)
        addresses = _strings(endpoint["address"], "endpoint address", maximum_items=16)
        try:
            for address in addresses:
                ipaddress.ip_interface(address)
        except ValueError as exc:
            raise ValidationError("endpoint address contains an invalid CIDR") from exc
        mtu = endpoint.get("mtu", 1280)
        if isinstance(mtu, bool) or not isinstance(mtu, int) or not 576 <= mtu <= 9000:
            raise ValidationError("endpoint mtu is invalid")
        peers = endpoint["peers"]
        if not isinstance(peers, list) or not 1 <= len(peers) <= 8:
            raise ValidationError("endpoint peers must be a bounded non-empty list")
        for peer in peers:
            peer = _exact_object(
                peer,
                {"address", "port", "public_key", "allowed_ips"},
                {"pre_shared_key", "persistent_keepalive_interval"},
                "peer",
            )
            _string(peer["address"], "peer address", maximum=253)
            _string(peer["public_key"], "peer public_key", maximum=256)
            if "pre_shared_key" in peer:
                _string(peer["pre_shared_key"], "peer pre_shared_key", maximum=256)
            port = peer["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValidationError("peer port is invalid")
            keepalive = peer.get("persistent_keepalive_interval", 0)
            if isinstance(keepalive, bool) or not isinstance(keepalive, int) or not 0 <= keepalive <= 65535:
                raise ValidationError("peer persistent keepalive is invalid")
            allowed = _strings(peer["allowed_ips"], "peer allowed_ips", maximum_items=256)
            try:
                for network in allowed:
                    ipaddress.ip_network(network, strict=False)
            except ValueError as exc:
                raise ValidationError("peer allowed_ips contains an invalid CIDR") from exc


def _validate_outbounds(value: object) -> None:
    if not isinstance(value, list) or value != [{"type": "direct", "tag": "direct"}]:
        if isinstance(value, list) and value and isinstance(value[0], dict) and set(value[0]) != {"type", "tag"}:
            raise ValidationError("outbound keys must match the generated schema")
        raise ValidationError("outbounds must contain only the generated direct outbound")


def _validate_dns(value: object) -> None:
    dns = _exact_object(value, {"servers", "rules", "strategy"}, {"final"}, "dns")
    if not isinstance(dns["strategy"], str) or dns["strategy"] not in {
        "ipv4_only", "ipv6_only", "prefer_ipv4", "prefer_ipv6"
    }:
        raise ValidationError("dns strategy is invalid")
    servers = dns["servers"]
    if not isinstance(servers, list) or len(servers) > 65:
        raise ValidationError("dns servers must be a bounded list")
    for server in servers:
        if not isinstance(server, dict):
            raise ValidationError("dns server must be an object")
        kind = server.get("type")
        if kind == "local":
            server = _exact_object(server, {"type", "tag"}, set(), "dns server")
        elif kind == "udp":
            server = _exact_object(server, {"type", "tag", "server"}, set(), "dns server")
            _string(server["server"], "dns server address", maximum=253)
        elif kind == "https":
            server = _exact_object(server, {"type", "tag", "server", "server_port"}, set(), "dns server")
            _string(server["server"], "dns server address", maximum=253)
            if isinstance(server["server_port"], bool) or not isinstance(server["server_port"], int) or server["server_port"] != 443:
                raise ValidationError("https dns server port must be 443")
        else:
            raise ValidationError("dns server type is unsupported")
        _string(server["tag"], "dns server tag", maximum=80)
    rules = dns["rules"]
    if not isinstance(rules, list) or len(rules) > 512:
        raise ValidationError("dns rules must be a bounded list")
    for rule in rules:
        rule = _exact_object(rule, {"domain_suffix", "server"}, set(), "dns rule")
        _strings(rule["domain_suffix"], "dns rule domain_suffix")
        _string(rule["server"], "dns rule server", maximum=80)


def _validate_route_rule(rule: object) -> None:
    if not isinstance(rule, dict):
        raise ValidationError("route rule must be an object")
    keys = set(rule)
    if keys == {"action"} and rule["action"] == "sniff":
        return
    if keys == {"action", "protocol"} and rule == {"action": "hijack-dns", "protocol": "dns"}:
        return
    data_keys = keys - {"outbound"}
    if "outbound" not in rule or not data_keys or not data_keys <= {"domain", "domain_suffix", "ip_cidr", "rule_set"}:
        raise ValidationError("route rule keys must match the generated schema")
    _string(rule["outbound"], "route rule outbound", maximum=80)
    for key in data_keys:
        values = _strings(rule[key], f"route rule {key}")
        if key == "ip_cidr":
            try:
                for value in values:
                    ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValidationError("route rule ip_cidr is invalid") from exc


def _validate_route(value: object) -> None:
    route = _exact_object(
        value,
        {"auto_detect_interface", "default_domain_resolver", "rules", "rule_set", "final"},
        set(),
        "route",
    )
    if route["auto_detect_interface"] is not True:
        raise ValidationError("route auto_detect_interface must be true")
    _string(route["default_domain_resolver"], "route default resolver", maximum=80)
    _string(route["final"], "route final", maximum=80)
    rules = route["rules"]
    if not isinstance(rules, list) or len(rules) > 1024:
        raise ValidationError("route rules must be a bounded list")
    for rule in rules:
        _validate_route_rule(rule)
    rule_sets = route["rule_set"]
    if not isinstance(rule_sets, list) or len(rule_sets) > 64:
        raise ValidationError("route rule_set must be a bounded list")
    for rule_set in rule_sets:
        rule_set = _exact_object(rule_set, {"type", "tag", "rules"}, set(), "route rule_set")
        if rule_set["type"] != "inline":
            raise ValidationError("route rule_set must be inline")
        _string(rule_set["tag"], "route rule_set tag", maximum=80)
        inline = rule_set["rules"]
        if not isinstance(inline, list) or not 1 <= len(inline) <= 64:
            raise ValidationError("route rule_set rules must be bounded")
        for rule in inline:
            rule = _exact_object(rule, {"ip_cidr"}, set(), "route rule_set rule")
            values = _strings(rule["ip_cidr"], "route rule_set ip_cidr")
            try:
                for value in values:
                    ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValidationError("route rule_set ip_cidr is invalid") from exc


def make_config_envelope(config: dict) -> dict:
    """Wrap one generated sing-box config in the versioned helper protocol."""
    if not isinstance(config, dict):
        raise ValidationError("config must be an object")
    return {"schema_version": SCHEMA_VERSION, "config": config}


def validate_config_envelope(value: object) -> dict:
    """Validate the protocol envelope and return its config object."""
    if not isinstance(value, dict) or set(value) != {"schema_version", "config"}:
        raise ValidationError("envelope needs exactly schema_version and config")
    try:
        encoded_size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("envelope must contain JSON values") from exc
    if encoded_size > MAX_CONFIG_BYTES:
        raise ValidationError("config size exceeds the helper limit")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("helper schema version mismatch")
    config = value["config"]
    if not isinstance(config, dict):
        raise ValidationError("config must be an object")
    expected = {"log", "inbounds", "endpoints", "outbounds", "dns", "route"}
    if set(config) != expected:
        raise ValidationError("config keys must match the generated schema exactly")
    log = config["log"]
    if not isinstance(log, dict) or set(log) != {"level"}:
        raise ValidationError("log keys must be exactly level")
    if not isinstance(log["level"], str) or log["level"] not in {
        "trace", "debug", "info", "warn", "error", "fatal", "panic"
    }:
        raise ValidationError("unsupported log level")
    _validate_inbounds(config["inbounds"])
    _validate_endpoints(config["endpoints"])
    _validate_outbounds(config["outbounds"])
    _validate_dns(config["dns"])
    _validate_route(config["route"])
    return config


def _verify_owned_tree(base: Path, owner_uid: int) -> None:
    for directory, names, files in os.walk(base, topdown=True, followlinks=False):
        directory_path = Path(directory)
        info = os.lstat(directory_path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SecurityError(f"uninstall tree has insecure directory: {directory_path}")
        for name in names + files:
            path = directory_path / name
            child = os.lstat(path)
            if stat.S_ISLNK(child.st_mode):
                if path != base / "current" or child.st_uid != owner_uid:
                    raise SecurityError(f"uninstall tree has foreign symlink: {path}")
                continue
            if child.st_uid != owner_uid or child.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise SecurityError(f"uninstall tree has insecure owner/mode: {path}")
            if stat.S_ISREG(child.st_mode) and child.st_nlink != 1:
                raise SecurityError(f"uninstall tree has hardlinked file: {path}")
            if not (stat.S_ISREG(child.st_mode) or stat.S_ISDIR(child.st_mode)):
                raise SecurityError(f"uninstall tree has unsafe file type: {path}")


def uninstall_helper(
    install: InstallMetadata,
    runtime: RuntimeMetadata,
    *,
    helper_base: Path = Path("/Library/PrivilegedHelperTools/com.proxy-router"),
    sudoers_file: Path = Path("/private/etc/sudoers.d/91-proxy-router"),
    stopper=stop_engine,
    visudo=subprocess.run,
) -> dict:
    """Stop first, disable validated policy, tombstone and remove owned state."""
    helper_base = Path(helper_base)
    sudoers_file = Path(sudoers_file)
    _verify_owned_tree(helper_base, runtime.root_uid)
    policy_fd = os.open(sudoers_file, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        policy_info = os.fstat(policy_fd)
        if (
            not stat.S_ISREG(policy_info.st_mode)
            or policy_info.st_nlink != 1
            or policy_info.st_uid != runtime.root_uid
            or stat.S_IMODE(policy_info.st_mode) != 0o440
            or policy_info.st_size > 1024 * 1024
        ):
            raise SecurityError("managed sudoers policy has unsafe metadata")
        policy = os.read(policy_fd, 1024 * 1024 + 1)
    finally:
        os.close(policy_fd)
    text = policy.decode("utf-8")
    marker = "# Managed by proxy-router privileged helper v2; remove with `elevate uninstall`."
    command_lines = [line for line in text.splitlines() if "NOPASSWD:" in line]
    if (
        not text.startswith(marker + "\n")
        or len(command_lines) != 5
        or any("router.py" in line or not line.endswith(f" {install.uid}") for line in command_lines)
        or {line.rsplit(" ", 2)[-2] for line in command_lines}
        != {"status", "start", "stop", "reload", "uninstall"}
    ):
        raise SecurityError("managed sudoers policy content is foreign")
    _verify_owned_tree(runtime.state_dir, runtime.root_uid)
    stopper(runtime)
    policy_parent_fd = os.open(
        sudoers_file.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    policy_removed = False
    try:
        os.unlink(sudoers_file.name, dir_fd=policy_parent_fd)
        policy_removed = True
        os.fsync(policy_parent_fd)
        result = visudo(["/usr/sbin/visudo", "-c"], capture_output=True, text=True)
        if result.returncode != 0:
            atomic_root_write(
                policy_parent_fd,
                sudoers_file.name,
                policy,
                0o440,
                owner_uid=runtime.root_uid,
                owner_gid=runtime.root_gid,
            )
            policy_removed = False
            raise SecurityError("sudoers validation failed after helper policy removal")
    finally:
        os.close(policy_parent_fd)
    if not policy_removed:
        raise SecurityError("helper policy removal did not complete")
    token = secrets.token_hex(12)
    helper_tombstone = helper_base.with_name(f".{helper_base.name}.remove-{token}")
    state_tombstone = runtime.state_dir.with_name(f".{runtime.state_dir.name}.remove-{token}")
    helper_base.rename(helper_tombstone)
    runtime.state_dir.rename(state_tombstone)
    shutil.rmtree(helper_tombstone)
    shutil.rmtree(state_tombstone)
    return {"uninstalled": True}


def main(
    argv: list[str] | None = None,
    *,
    euid=os.geteuid,
    loader=load_installed_runtime,
    status_action=engine_status,
    start_action=start_engine,
    stop_action=stop_engine,
    reload_action=reload_engine,
    uninstall_action=uninstall_helper,
    output=print,
    error_output=None,
) -> int:
    """Dispatch exactly one installed root helper operation."""
    if error_output is None:
        error_output = lambda message: print(message, file=sys.stderr)
    args = list(sys.argv[1:] if argv is None else argv)
    if euid() != 0:
        error_output("proxy-router helper: root execution required")
        return 1
    if len(args) != 2 or not args[1].isascii() or not args[1].isdecimal():
        error_output("proxy-router helper: expected exactly operation and uid")
        return 2
    try:
        requested_uid = int(args[1])
        install, runtime = loader(requested_uid)
        operation = parse_helper_request(args, install.uid)
        if operation == "status":
            result = status_action(runtime)
        elif operation == "start":
            result = start_action(install, runtime)
        elif operation == "stop":
            result = stop_action(runtime)
        elif operation == "reload":
            result = reload_action(install, runtime)
        elif operation == "uninstall" and uninstall_action is not None:
            result = uninstall_action(install, runtime)
        else:
            raise SecurityError("uninstall is unavailable in this helper build")
        output(json.dumps(result, sort_keys=True))
        return 0
    except (ValidationError, SecurityError, OSError, ValueError) as exc:
        error_output(f"proxy-router helper: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

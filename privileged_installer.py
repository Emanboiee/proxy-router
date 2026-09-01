#!/usr/bin/python3
"""Authenticated installer for proxy-router's root-owned macOS/Linux helper."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


HELPER_OPERATIONS = ("status", "start", "stop", "reload", "uninstall")
SYSTEM_ENV = Path("/usr/bin/env")
SYSTEM_PYTHON = Path("/usr/bin/python3")
EXPECTED_HELPER = Path(
    "/Library/PrivilegedHelperTools/com.proxy-router/current/privileged_helper.py"
)
LINUX_EXPECTED_HELPER = Path(
    "/usr/local/libexec/proxy-router/current/privileged_helper.py"
)
SUPPORTED_HELPERS = frozenset({EXPECTED_HELPER, LINUX_EXPECTED_HELPER})
V2_MARKER = "# Managed by proxy-router privileged helper v2; remove with `elevate uninstall`."
V2_DEFAULTS = {
    "Defaults!/usr/bin/env env_reset",
    "Defaults!/usr/bin/env !setenv",
    "Defaults!/usr/bin/env !requiretty",
    'Defaults!/usr/bin/env env_delete += "DYLD_*"',
    'Defaults!/usr/bin/env env_delete += "LD_*"',
    'Defaults!/usr/bin/env env_delete += "PYTHON*"',
}


@dataclass(frozen=True)
class InstallLayout:
    helper_parent: Path = Path("/Library/PrivilegedHelperTools")
    helper_base: Path = Path("/Library/PrivilegedHelperTools/com.proxy-router")
    state_base: Path = Path("/private/var/db/proxy-router")
    sudoers_file: Path = Path("/private/etc/sudoers.d/91-proxy-router")

    @classmethod
    def for_platform(cls, platform_name: str | None = None) -> "InstallLayout":
        """Return the canonical immutable-helper paths for one OS family."""
        platform_name = sys.platform if platform_name is None else str(platform_name)
        if platform_name == "darwin":
            return cls()
        if platform_name.startswith("linux"):
            return cls(
                helper_parent=Path("/usr/local/libexec"),
                helper_base=Path("/usr/local/libexec/proxy-router"),
                state_base=Path("/var/lib/proxy-router"),
                sudoers_file=Path("/etc/sudoers.d/91-proxy-router"),
            )
        raise ValueError(f"unsupported privileged helper platform: {platform_name}")

    @property
    def helper_path(self) -> Path:
        """Canonical helper entrypoint inside the atomic current selector."""
        return self.helper_base / "current" / "privileged_helper.py"

    @property
    def system_python(self) -> Path:
        """System interpreter named by the exact sudoers command."""
        return SYSTEM_PYTHON


def render_sudoers(
    username: str,
    uid: int,
    helper_path: Path = EXPECTED_HELPER,
    *,
    system_python: Path = SYSTEM_PYTHON,
) -> str:
    """Render exact no-wildcard sudo commands for one helper path."""
    if not isinstance(username, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", username) is None:
        raise ValueError("unsafe sudoers username")
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        raise ValueError("unsafe sudoers uid")
    helper_path = Path(helper_path)
    system_python = Path(system_python)
    if helper_path not in SUPPORTED_HELPERS:
        raise ValueError("helper path must be a canonical root-owned location")
    if system_python != SYSTEM_PYTHON:
        raise ValueError("system python must be the canonical system interpreter")
    command_prefix = (
        "/usr/bin/env -i HOME=/var/empty "
        "PATH=/usr/bin\\:/bin\\:/usr/sbin\\:/sbin LANG=C "
        f"{system_python} -I -S {helper_path}"
    )
    lines = [
        V2_MARKER,
        "Defaults!/usr/bin/env env_reset",
        "Defaults!/usr/bin/env !setenv",
        "Defaults!/usr/bin/env !requiretty",
        'Defaults!/usr/bin/env env_delete += "DYLD_*"',
        'Defaults!/usr/bin/env env_delete += "LD_*"',
        'Defaults!/usr/bin/env env_delete += "PYTHON*"',
    ]
    for operation in HELPER_OPERATIONS:
        lines.append(
            f"{username} ALL=(root) NOPASSWD: {command_prefix} {operation} {uid}"
        )
    return "\n".join(lines) + "\n"


def classify_policy(
    content: str,
    legacy_python: str,
    legacy_router: str,
    *,
    helper_path: Path = EXPECTED_HELPER,
    system_python: Path = SYSTEM_PYTHON,
) -> str:
    """Classify only exact managed legacy/v2 policy; never guess foreign text."""
    helper_path = Path(helper_path)
    system_python = Path(system_python)
    if helper_path not in SUPPORTED_HELPERS or system_python != SYSTEM_PYTHON:
        raise ValueError("helper policy path must be canonical")
    if not content:
        return "absent"
    lines = content.strip().splitlines()
    if lines and lines[0] == V2_MARKER:
        defaults = {line for line in lines[1:] if line.startswith("Defaults!")}
        commands = [line for line in lines[1:] if "NOPASSWD:" in line]
        if defaults != V2_DEFAULTS or len(commands) != len(HELPER_OPERATIONS):
            return "foreign"
        pattern = re.compile(
            r"^(?P<user>[A-Za-z_][A-Za-z0-9_.-]*) ALL=\(root\) NOPASSWD: "
            r"/usr/bin/env -i HOME=/var/empty PATH=/usr/bin\\:/bin\\:/usr/sbin\\:/sbin LANG=C "
            + re.escape(os.fspath(system_python))
            + r" -I -S "
            + re.escape(os.fspath(helper_path))
            + r" (?P<operation>status|start|stop|reload|uninstall) (?P<uid>[1-9][0-9]*)$"
        )
        matches = [pattern.fullmatch(line) for line in commands]
        if any(match is None for match in matches):
            return "foreign"
        identities = {(match.group("user"), match.group("uid")) for match in matches if match}
        operations = {match.group("operation") for match in matches if match}
        other = [
            line for line in lines[1:]
            if not line.startswith("Defaults!") and "NOPASSWD:" not in line
        ]
        return (
            "v2"
            if len(identities) == 1 and operations == set(HELPER_OPERATIONS) and not other
            else "foreign"
        )
    legacy_marker = "# Managed by `proxy-router elevate install`; remove with `elevate uninstall`."
    if lines and lines[0] == legacy_marker:
        commands = lines[1:]
        prefix = f" NOPASSWD: {legacy_python} {legacy_router} "
        if commands and all(" ALL=(root)" in line and prefix in line for line in commands):
            return "legacy"
    return "foreign"


def _verify_directory(path: Path, owner_uid: int) -> None:
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError(f"insecure installer directory: {path}")


def _ensure_directory(path: Path, owner_uid: int, owner_gid: int) -> None:
    """Create one missing root-owned directory beneath a verified parent."""
    try:
        _verify_directory(path, owner_uid)
        return
    except FileNotFoundError:
        pass
    _verify_directory(path.parent, owner_uid)
    try:
        os.mkdir(path, 0o755)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError(f"insecure installer directory: {path}")
    if info.st_gid != owner_gid:
        os.chown(path, owner_uid, owner_gid)
    os.chmod(path, 0o755)


def _secure_child_directory(parent_fd: int, name: str, mode: int, owner_uid: int, owner_gid: int) -> int:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"insecure installer directory component: {name}")
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    if info.st_gid != owner_gid:
        os.fchown(fd, owner_uid, owner_gid)
    os.fchmod(fd, mode)
    return fd


def _write_new_file(directory_fd: int, name: str, payload: bytes, mode: int, owner_uid: int, owner_gid: int) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner_uid:
            raise RuntimeError(f"unsafe staged file: {name}")
        if info.st_gid != owner_gid:
            os.fchown(fd, owner_uid, owner_gid)
        os.fchmod(fd, mode)
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            count = os.write(fd, view[offset:])
            if count <= 0:
                raise RuntimeError(f"staged file write stalled: {name}")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def _locked_fchmod(parent_fd: int, name: str, mode: int) -> None:
    """chmod one entry by dir_fd without ever following a symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _verify_existing_version(
    versions_fd: int,
    bundle_digest: str,
    files: tuple,
    owner_uid: int,
) -> None:
    version_fd = os.open(
        bundle_digest,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=versions_fd,
    )
    try:
        directory = os.fstat(version_fd)
        if directory.st_uid != owner_uid or stat.S_IMODE(directory.st_mode) != 0o555:
            raise RuntimeError("existing bundle directory ownership/mode mismatch")
        expected = {name for name, _payload, _mode in files}
        if set(os.listdir(version_fd)) != expected:
            raise RuntimeError("existing bundle file set mismatch")
        for name, payload, mode in files:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=version_fd)
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != owner_uid
                    or stat.S_IMODE(info.st_mode) != mode
                ):
                    raise RuntimeError(f"existing bundle metadata mismatch: {name}")
                data = bytearray()
                while len(data) <= len(payload):
                    chunk = os.read(fd, min(65536, len(payload) + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if bytes(data) != payload:
                    raise RuntimeError(f"existing bundle content mismatch: {name}")
            finally:
                os.close(fd)
    finally:
        os.close(version_fd)


def stage_bundle(
    layout: InstallLayout,
    *,
    helper_bytes: bytes,
    installer_bytes: bytes,
    manifest_bytes: bytes,
    binary_bytes: bytes,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> dict:
    """Install one immutable content-addressed bundle and atomically select it."""
    _ensure_directory(layout.helper_parent, owner_uid, owner_gid)
    digest = hashlib.sha256()
    files = (
        ("privileged_helper.py", helper_bytes, 0o555),
        ("privileged_installer.py", installer_bytes, 0o555),
        ("sing-box-release.json", manifest_bytes, 0o444),
        ("sing-box", binary_bytes, 0o555),
    )
    for name, payload, mode in files:
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name.encode("utf-8"))
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    bundle_digest = digest.hexdigest()
    parent_fd = os.open(
        layout.helper_parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    base_fd = versions_fd = stage_fd = None
    stage_name = f".stage-{secrets.token_hex(12)}"
    temporary_link = None
    version_installed = False
    success = False
    try:
        base_fd = _secure_child_directory(parent_fd, layout.helper_base.name, 0o755, owner_uid, owner_gid)
        versions_fd = _secure_child_directory(base_fd, "versions", 0o755, owner_uid, owner_gid)
        try:
            os.stat(bundle_digest, dir_fd=versions_fd, follow_symlinks=False)
            existing_version = True
        except FileNotFoundError:
            existing_version = False
        if existing_version:
            _verify_existing_version(versions_fd, bundle_digest, files, owner_uid)
        else:
            stage_fd = _secure_child_directory(versions_fd, stage_name, 0o700, owner_uid, owner_gid)
            for name, payload, mode in files:
                _write_new_file(stage_fd, name, payload, mode, owner_uid, owner_gid)
            os.fsync(stage_fd)
            # Rename while the source is still writable; macOS refuses to
            # rename a read-only directory (EACCES) even onto a confirmed
            # spot, so the 0o555 immutability lands AFTER the atomic move.
            os.rename(stage_name, bundle_digest, src_dir_fd=versions_fd, dst_dir_fd=versions_fd)
            version_installed = True
            os.fsync(versions_fd)
            _locked_fchmod(versions_fd, bundle_digest, 0o555)
        temporary_link = f".current-{secrets.token_hex(12)}"
        os.symlink(f"versions/{bundle_digest}", temporary_link, dir_fd=base_fd)
        try:
            current = os.stat("current", dir_fd=base_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (not stat.S_ISLNK(current.st_mode) or current.st_uid != owner_uid):
            raise RuntimeError("existing current selector is foreign or insecure")
        os.rename(temporary_link, "current", src_dir_fd=base_fd, dst_dir_fd=base_fd)
        temporary_link = None
        os.fsync(base_fd)
        success = True
    finally:
        if not success:
            if temporary_link is not None and base_fd is not None:
                try:
                    os.unlink(temporary_link, dir_fd=base_fd)
                except FileNotFoundError:
                    pass
            cleanup_name = bundle_digest if version_installed else stage_name
            cleanup_fd = None
            if versions_fd is not None:
                try:
                    cleanup_fd = os.open(
                        cleanup_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=versions_fd,
                    )
                    os.fchmod(cleanup_fd, 0o700)
                    for child in os.listdir(cleanup_fd):
                        os.unlink(child, dir_fd=cleanup_fd)
                except FileNotFoundError:
                    pass
                finally:
                    if cleanup_fd is not None:
                        os.close(cleanup_fd)
                try:
                    os.rmdir(cleanup_name, dir_fd=versions_fd)
                except FileNotFoundError:
                    pass
        for fd in (stage_fd, versions_fd, base_fd, parent_fd):
            if fd is not None:
                os.close(fd)
    return {
        "bundle_digest": bundle_digest,
        "binary_sha256": hashlib.sha256(binary_bytes).hexdigest(),
    }


def _read_policy(layout: InstallLayout, owner_uid: int) -> tuple[str, int]:
    parent = layout.sudoers_file.parent
    _verify_directory(parent, owner_uid)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open(
                layout.sudoers_file.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return "", directory_fd
        info = os.fstat(fd)
        try:
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != owner_uid
                or stat.S_IMODE(info.st_mode) != 0o440
                or info.st_size > 1024 * 1024
            ):
                raise RuntimeError("managed sudoers policy has unsafe metadata")
            payload = os.read(fd, 1024 * 1024 + 1)
        finally:
            os.close(fd)
        return payload.decode("utf-8"), directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def install_policy(
    layout: InstallLayout,
    policy: str,
    *,
    owner_uid: int = 0,
    owner_gid: int = 0,
    runner=None,
) -> None:
    """Validate a private temp sudoers policy, then atomically install it."""
    if runner is None:
        import subprocess
        runner = subprocess.run
    parent = layout.sudoers_file.parent
    _verify_directory(parent, owner_uid)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    temporary = f".{layout.sudoers_file.name}.{secrets.token_hex(12)}.tmp"
    installed = False
    try:
        _write_new_file(
            directory_fd,
            temporary,
            policy.encode("utf-8"),
            0o440,
            owner_uid,
            owner_gid,
        )
        candidate = parent / temporary
        result = runner(
            ["/usr/sbin/visudo", "-c", "-f", str(candidate)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError("generated helper sudoers policy failed visudo validation")
        try:
            current = os.stat(layout.sudoers_file.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != owner_uid
            or stat.S_IMODE(current.st_mode) != 0o440
        ):
            raise RuntimeError("existing managed sudoers policy is insecure")
        os.rename(
            temporary,
            layout.sudoers_file.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        installed = True
        os.fsync(directory_fd)
    finally:
        if not installed:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def write_install_metadata(
    layout: InstallLayout,
    *,
    uid: int,
    gid: int,
    user_root: Path,
    user_root_device: int,
    user_root_inode: int,
    bundle_digest: str,
    binary_sha256: str,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> Path:
    """Atomically install canonical helper ownership/runtime metadata."""
    user_root = Path(user_root)
    user_info = os.lstat(user_root)
    if (
        not stat.S_ISDIR(user_info.st_mode)
        or stat.S_ISLNK(user_info.st_mode)
        or user_info.st_uid != uid
        or user_info.st_dev != user_root_device
        or user_info.st_ino != user_root_inode
        or user_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError("user root identity is unsafe or changed")
    if re.fullmatch(r"[0-9a-f]{64}", bundle_digest) is None or re.fullmatch(r"[0-9a-f]{64}", binary_sha256) is None:
        raise ValueError("metadata digests must be lowercase SHA-256")
    parent = layout.state_base.parent
    _verify_directory(parent, owner_uid)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    base_fd = user_fd = None
    try:
        base_fd = _secure_child_directory(parent_fd, layout.state_base.name, 0o755, owner_uid, owner_gid)
        user_fd = _secure_child_directory(base_fd, str(uid), 0o700, owner_uid, owner_gid)
        value = {
            "schema_version": 1,
            "uid": uid,
            "gid": gid,
            "user_root": str(user_root),
            "user_root_device": user_root_device,
            "user_root_inode": user_root_inode,
            "bundle_digest": bundle_digest,
            "binary_sha256": binary_sha256,
            "state_dir": str(layout.state_base / str(uid)),
        }
        payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        temporary = f".install.{secrets.token_hex(12)}.tmp"
        _write_new_file(user_fd, temporary, payload, 0o600, owner_uid, owner_gid)
        try:
            current = os.stat("install.json", dir_fd=user_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != owner_uid
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise RuntimeError("existing install metadata is insecure")
        os.rename(temporary, "install.json", src_dir_fd=user_fd, dst_dir_fd=user_fd)
        os.fsync(user_fd)
        return layout.state_base / str(uid) / "install.json"
    finally:
        for fd in (user_fd, base_fd, parent_fd):
            if fd is not None:
                os.close(fd)


def read_install_metadata(path: Path, *, owner_uid: int = 0, anchor: Path) -> dict:
    """Strictly read root-owned metadata without following path components."""
    path = Path(os.path.abspath(path))
    anchor = Path(os.path.abspath(anchor))
    relative = path.relative_to(anchor)
    current = anchor
    for index, part in enumerate(relative.parts):
        current = current / part
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != owner_uid:
            raise RuntimeError(f"insecure metadata path: {current}")
        if index < len(relative.parts) - 1:
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RuntimeError(f"insecure metadata directory: {current}")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("install metadata leaf is insecure")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if info.st_size > 65536:
            raise RuntimeError("install metadata is oversized")
        payload = os.read(fd, 65537)
    finally:
        os.close(fd)
    value = json.loads(payload.decode("utf-8"))
    expected = {
        "schema_version", "uid", "gid", "user_root", "user_root_device",
        "user_root_inode", "bundle_digest", "binary_sha256", "state_dir",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise RuntimeError("install metadata schema mismatch")
    if re.fullmatch(r"[0-9a-f]{64}", value["bundle_digest"]) is None or re.fullmatch(r"[0-9a-f]{64}", value["binary_sha256"]) is None:
        raise RuntimeError("install metadata digest is invalid")
    return value


def migrate_install(
    layout: InstallLayout,
    *,
    legacy_python: str,
    legacy_router: str,
    stop_legacy,
    stage,
    owner_uid: int = 0,
    helper_path: Path = EXPECTED_HELPER,
    system_python: Path = SYSTEM_PYTHON,
):
    """Revoke recognized legacy privilege before any fallible v2 staging."""
    content, directory_fd = _read_policy(layout, owner_uid)
    try:
        classification = classify_policy(
            content,
            legacy_python,
            legacy_router,
            helper_path=helper_path,
            system_python=system_python,
        )
        if classification == "foreign":
            raise RuntimeError("managed sudoers path contains foreign content")
        if classification == "legacy":
            stop_legacy()
            os.unlink(layout.sudoers_file.name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        return stage()
    finally:
        os.close(directory_fd)

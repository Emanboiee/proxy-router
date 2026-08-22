"""Security contracts for the root-owned macOS lifecycle helper."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import tarfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import privileged_helper as helper
import privileged_installer as installer


def _generated_config(mode: str, *, vpn: dict | None = None) -> dict:
    """Build a real controller config in a fresh module and disposable root."""
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    profile = root / "providers" / "proton" / "a.conf"
    profile.parent.mkdir(parents=True)
    profile.write_text(
        "[Interface]\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 10.0.0.2/32\n"
        "DNS = 1.1.1.1\n"
        "MTU = 1280\n"
        "\n[Peer]\n"
        "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n"
        "Endpoint = 1.1.1.1:51820\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n",
        encoding="utf-8",
    )
    (root / "state").mkdir()
    (root / "state" / "mode").write_text(mode, encoding="ascii")
    module_name = f"router_privileged_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(
        module_name, Path(__file__).resolve().parents[1] / "router.py"
    )
    assert spec and spec.loader
    router = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, {"PROXY_ROUTER_ROOT": str(root)}):
        spec.loader.exec_module(router)
    vpn_config = dict(vpn or {})
    setattr(router, "_providers", {"proton": {"directory": "providers/proton"}})
    setattr(router, "_routes", [{"id": "example", "domains": ["example.com"], "provider": "proton"}])
    setattr(router, "_port", 2080)
    setattr(router, "_vpn", vpn_config)
    setattr(router, "_routing", {})
    if vpn_config.get("selective"):
        ruleset = root / "rulesets" / f"{vpn_config['selective']}.json"
        ruleset.parent.mkdir()
        ruleset.write_text(json.dumps({"provider": "proton", "ip_cidr": ["203.0.113.0/24"]}))
    config, _active = router.build_singbox_config()
    temporary.cleanup()
    return config


class GeneratedSchemaTests(unittest.TestCase):
    @staticmethod
    def base_config():
        return {
            "log": {"level": "info"},
            "inbounds": [],
            "endpoints": [],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "dns": {"servers": [], "rules": [], "strategy": "prefer_ipv4"},
            "route": {
                "auto_detect_interface": True,
                "default_domain_resolver": "dns-local",
                "rules": [],
                "rule_set": [],
                "final": "direct",
            },
        }

    def test_valid_empty_shape_envelope_round_trips_for_first_schema_slice(self):
        config = self.base_config()

        envelope = helper.make_config_envelope(config)

        self.assertEqual(envelope["schema_version"], helper.SCHEMA_VERSION)
        self.assertEqual(helper.validate_config_envelope(envelope), config)

    def test_unknown_top_level_config_key_is_rejected(self):
        envelope = helper.make_config_envelope({
            "log": {"level": "info"},
            "inbounds": [],
            "endpoints": [],
            "outbounds": [],
            "dns": {},
            "route": {},
            "external_controller": "0.0.0.0:9090",
        })

        with self.assertRaisesRegex(helper.ValidationError, "config keys"):
            helper.validate_config_envelope(envelope)

    def test_log_output_path_is_rejected(self):
        config = self.base_config()
        config["log"]["output"] = "/private/etc/sudoers.d/pwn"

        with self.assertRaisesRegex(helper.ValidationError, "log keys"):
            helper.validate_config_envelope(helper.make_config_envelope(config))

    def test_mixed_inbound_must_be_exact_loopback_shape(self):
        config = self.base_config()
        config["inbounds"] = [{
            "type": "mixed",
            "tag": "local-proxy",
            "listen": "0.0.0.0",
            "listen_port": 2080,
        }]

        with self.assertRaisesRegex(helper.ValidationError, "mixed inbound"):
            helper.validate_config_envelope(helper.make_config_envelope(config))

    def test_real_generated_tun_config_is_accepted(self):
        config = _generated_config("tun")

        self.assertEqual(
            helper.validate_config_envelope(helper.make_config_envelope(config)),
            config,
        )

    def test_real_generated_proxy_config_with_optional_peer_fields_is_accepted(self):
        config = _generated_config("proxy")

        self.assertEqual(
            helper.validate_config_envelope(helper.make_config_envelope(config)),
            config,
        )

    def test_real_generated_https_dns_and_selective_tun_configs_are_accepted(self):
        https = _generated_config("proxy", vpn={"dns_transport": "https"})
        selective = _generated_config(
            "tun",
            vpn={"capture": "ruleset", "selective": "school", "selective_provider": "proton"},
        )

        helper.validate_config_envelope(helper.make_config_envelope(https))
        helper.validate_config_envelope(helper.make_config_envelope(selective))

    def test_unknown_nested_keys_are_rejected_in_every_config_section(self):
        cases = {
            "endpoint": lambda c: c["endpoints"][0].update(command="id"),
            "peer": lambda c: c["endpoints"][0]["peers"][0].update(path="/etc/shadow"),
            "outbound": lambda c: c["outbounds"][0].update(plugin="evil"),
            "dns": lambda c: c["dns"].update(cache_file="/etc/sudoers"),
            "dns server": lambda c: c["dns"]["servers"][0].update(path="/etc/passwd"),
            "dns rule": lambda c: c["dns"]["rules"][0].update(script="evil"),
            "route": lambda c: c["route"].update(external_controller="0.0.0.0:9090"),
            "route rule": lambda c: c["route"]["rules"][0].update(path="/etc/passwd"),
        }
        original = _generated_config("proxy")
        for label, mutate in cases.items():
            with self.subTest(label=label):
                config = copy.deepcopy(original)
                mutate(config)
                with self.assertRaisesRegex(helper.ValidationError, label):
                    helper.validate_config_envelope(helper.make_config_envelope(config))

    def test_aggregate_config_size_is_bounded(self):
        config = self.base_config()
        config["route"]["rules"] = [
            {"domain_suffix": ["a" * 1024] * 5, "outbound": "direct"}
            for _ in range(1024)
        ]

        with self.assertRaisesRegex(helper.ValidationError, "config size"):
            helper.validate_config_envelope(helper.make_config_envelope(config))

    def test_protocol_version_and_envelope_keys_fail_closed(self):
        config = self.base_config()
        wrong_version = {"schema_version": helper.SCHEMA_VERSION + 1, "config": config}
        extra_key = {"schema_version": helper.SCHEMA_VERSION, "config": config, "path": "/tmp/x"}

        with self.assertRaisesRegex(helper.ValidationError, "version mismatch"):
            helper.validate_config_envelope(wrong_version)
        with self.assertRaisesRegex(helper.ValidationError, "exactly"):
            helper.validate_config_envelope(extra_key)

    def test_membership_and_integer_fields_reject_type_confusion_cleanly(self):
        cases = []
        log = self.base_config()
        log["log"]["level"] = []
        cases.append(log)
        tun = _generated_config("tun")
        tun["inbounds"][0]["stack"] = []
        cases.append(tun)
        dns = self.base_config()
        dns["dns"]["strategy"] = []
        cases.append(dns)
        https = _generated_config("proxy", vpn={"dns_transport": "https"})
        https["dns"]["servers"][0]["server_port"] = 443.0
        cases.append(https)

        for config in cases:
            with self.subTest(config=config):
                with self.assertRaises(helper.ValidationError):
                    helper.validate_config_envelope(helper.make_config_envelope(config))


class FilesystemBoundaryTests(unittest.TestCase):
    def test_secure_chain_accepts_expected_owner_and_nonwritable_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            anchor = Path(temporary)
            anchor.chmod(0o700)
            directory = anchor / "bundle"
            directory.mkdir(mode=0o755)
            leaf = directory / "helper.py"
            leaf.write_text("pass\n", encoding="utf-8")
            leaf.chmod(0o555)

            helper.verify_secure_chain(leaf, owner_uid=os.getuid(), anchor=anchor)

    def test_secure_chain_rejects_symlink_writable_and_wrong_owner_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            anchor = Path(temporary)
            anchor.chmod(0o700)
            safe = anchor / "safe"
            safe.mkdir(mode=0o755)
            leaf = safe / "leaf"
            leaf.write_text("x", encoding="ascii")
            leaf.chmod(0o555)
            link = anchor / "link"
            link.symlink_to(safe, target_is_directory=True)

            with self.assertRaisesRegex(helper.SecurityError, "symlink"):
                helper.verify_secure_chain(link / "leaf", owner_uid=os.getuid(), anchor=anchor)
            safe.chmod(0o775)
            with self.assertRaisesRegex(helper.SecurityError, "writable"):
                helper.verify_secure_chain(leaf, owner_uid=os.getuid(), anchor=anchor)
            safe.chmod(0o755)
            with self.assertRaisesRegex(helper.SecurityError, "wrong owner"):
                helper.verify_secure_chain(leaf, owner_uid=os.getuid() + 1, anchor=anchor)

    def test_safe_config_read_uses_pinned_root_identity_and_single_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            payload = b'{"schema_version":1,"config":{}}'
            config = root / "sing-box.json"
            config.write_bytes(payload)
            config.chmod(0o600)
            identity = root.stat()
            metadata = helper.InstallMetadata(
                uid=os.getuid(),
                gid=os.getgid(),
                user_root=root,
                user_root_device=identity.st_dev,
                user_root_inode=identity.st_ino,
            )

            self.assertEqual(helper.read_user_config(metadata), payload)

    def test_safe_config_read_rejects_symlink_fifo_and_wrong_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            identity = root.stat()
            metadata = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            target = root / "target.json"
            target.write_text("{}", encoding="ascii")
            target.chmod(0o600)
            config = root / "sing-box.json"

            config.symlink_to(target)
            with self.assertRaises(helper.SecurityError):
                helper.read_user_config(metadata)
            config.unlink()
            os.mkfifo(config, 0o600)
            with self.assertRaisesRegex(helper.SecurityError, "regular file"):
                helper.read_user_config(metadata)
            config.unlink()
            config.write_text("{}", encoding="ascii")
            config.chmod(0o644)
            with self.assertRaisesRegex(helper.SecurityError, "0600"):
                helper.read_user_config(metadata)

    def test_safe_config_read_rejects_replaced_user_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "root"
            root.mkdir(mode=0o700)
            (root / "sing-box.json").write_text("{}", encoding="ascii")
            (root / "sing-box.json").chmod(0o600)
            identity = root.stat()
            metadata = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            root.rename(parent / "old-root")
            root.mkdir(mode=0o700)
            (root / "sing-box.json").write_text("{}", encoding="ascii")
            (root / "sing-box.json").chmod(0o600)

            with self.assertRaisesRegex(helper.SecurityError, "identity"):
                helper.read_user_config(metadata)

    def test_atomic_root_write_creates_exact_mode_file_without_temp_survivors(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, directory_fd)

            helper.atomic_root_write(
                directory_fd,
                "state.json",
                b'{"ok":true}\n',
                0o600,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

            target = directory / "state.json"
            self.assertEqual(target.read_bytes(), b'{"ok":true}\n')
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual([path.name for path in directory.iterdir()], ["state.json"])

    def test_atomic_root_write_rejects_insecure_directory_symlink_and_wrong_mode_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            target = directory / "state.json"
            target.symlink_to(directory / "elsewhere")
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, directory_fd)

            with self.assertRaisesRegex(helper.SecurityError, "target"):
                helper.atomic_root_write(
                    directory_fd, "state.json", b"x", 0o600,
                    owner_uid=os.getuid(), owner_gid=os.getgid(),
                )
            target.unlink()
            target.write_text("old", encoding="ascii")
            target.chmod(0o644)
            with self.assertRaisesRegex(helper.SecurityError, "target"):
                helper.atomic_root_write(
                    directory_fd, "state.json", b"x", 0o600,
                    owner_uid=os.getuid(), owner_gid=os.getgid(),
                )
            target.unlink()
            directory.chmod(0o777)
            with self.assertRaisesRegex(helper.SecurityError, "directory"):
                helper.atomic_root_write(
                    directory_fd, "state.json", b"x", 0o600,
                    owner_uid=os.getuid(), owner_gid=os.getgid(),
                )


class ReleaseArtifactTests(unittest.TestCase):
    @staticmethod
    def archive_bytes(*, binary_type=tarfile.REGTYPE, extra_name=None, duplicate=False):
        root = "sing-box-1.13.19-darwin-arm64"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            directory = tarfile.TarInfo(root + "/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            license_member = tarfile.TarInfo(root + "/LICENSE")
            license_member.size = 8
            archive.addfile(license_member, io.BytesIO(b"license\n"))
            for _ in range(2 if duplicate else 1):
                binary = tarfile.TarInfo(root + "/sing-box")
                binary.type = binary_type
                if binary_type == tarfile.REGTYPE:
                    payload = b"#!/bin/sh\nexit 0\n"
                    binary.size = len(payload)
                    archive.addfile(binary, io.BytesIO(payload))
                else:
                    binary.linkname = "/etc/passwd"
                    archive.addfile(binary)
            if extra_name:
                extra = tarfile.TarInfo(extra_name)
                extra.size = 1
                archive.addfile(extra, io.BytesIO(b"x"))
        return buffer.getvalue()

    def test_manifest_selects_exact_pinned_arm64_release(self):
        manifest = Path(__file__).resolve().parents[1] / "sing-box-release.json"

        release = helper.release_for_architecture(
            manifest,
            "arm64",
            owner_uid=os.getuid(),
            anchor=manifest.parent,
        )

        self.assertEqual(release["version"], "1.13.19")
        self.assertEqual(release["size"], 18765957)
        self.assertEqual(
            release["sha256"],
            "23bf191906f2dfc9f00e9f0092f274f3426ba9377327e903ff94e636b64d0997",
        )
        self.assertEqual(release["archive_root"], "sing-box-1.13.19-darwin-arm64")

    def test_manifest_loader_rejects_symlinked_trust_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            real = root / "real.json"
            real.write_text("{}", encoding="ascii")
            real.chmod(0o600)
            link = root / "manifest.json"
            link.symlink_to(real)

            with self.assertRaisesRegex(helper.SecurityError, "symlink"):
                helper.release_for_architecture(
                    link,
                    "arm64",
                    owner_uid=os.getuid(),
                    anchor=root,
                )

    def test_verified_archive_returns_exact_regular_binary(self):
        root = "sing-box-1.13.19-darwin-arm64"
        payload = self.archive_bytes()
        release = {
            "archive_root": root,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

        binary = helper.verified_release_binary(payload, release)

        self.assertEqual(binary, b"#!/bin/sh\nexit 0\n")

    def test_verified_archive_rejects_digest_and_unsafe_member_shapes(self):
        root = "sing-box-1.13.19-darwin-arm64"
        cases = [
            self.archive_bytes(binary_type=tarfile.SYMTYPE),
            self.archive_bytes(extra_name="../escape"),
            self.archive_bytes(extra_name=root + "/evil"),
            self.archive_bytes(duplicate=True),
        ]
        for payload in cases:
            release = {
                "archive_root": root,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            with self.subTest(payload=hashlib.sha256(payload).hexdigest()):
                with self.assertRaises(helper.SecurityError):
                    helper.verified_release_binary(payload, release)

        good = self.archive_bytes()
        with self.assertRaisesRegex(helper.SecurityError, "digest"):
            helper.verified_release_binary(
                good,
                {"archive_root": root, "size": len(good), "sha256": "0" * 64},
            )


class HelperLifecycleTests(unittest.TestCase):
    def runtime(self, root: Path):
        bundle = root / "bundle"
        state = root / "state"
        bundle.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        binary = bundle / "sing-box"
        binary.write_bytes(b"trusted-binary")
        binary.chmod(0o500)
        config = state / "sing-box.json"
        config.write_text("{}", encoding="ascii")
        config.chmod(0o600)
        return helper.RuntimeMetadata(
            uid=501,
            gid=20,
            root_uid=os.getuid(),
            root_gid=os.getgid(),
            bundle_dir=bundle,
            state_dir=state,
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        )

    def test_request_parser_accepts_only_one_known_operation_and_pinned_uid(self):
        self.assertEqual(helper.parse_helper_request(["status", "501"], 501), "status")
        for argv in (
            [],
            ["status"],
            ["status", "501", "extra"],
            ["install", "501"],
            ["status", "502"],
            ["status", "not-a-uid"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(helper.ValidationError):
                    helper.parse_helper_request(argv, 501)

    def test_sing_box_environment_is_an_exact_allowlist(self):
        hostile = {
            "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
            "DYLD_LIBRARY_PATH": "/tmp",
            "LD_PRELOAD": "/tmp/evil.so",
            "PYTHONPATH": "/tmp/evil",
            "HOME": "/Users/attacker",
            "PATH": "/tmp/bin",
            "TMPDIR": "/tmp/attacker",
        }
        with mock.patch.dict(os.environ, hostile, clear=True):
            environment = helper.sing_box_environment(Path("/private/var/db/proxy-router/501"))

        self.assertEqual(
            environment,
            {
                "HOME": "/private/var/db/proxy-router/501",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
            },
        )

    def test_process_identity_requires_exact_uid_binary_config_and_current_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            expected = f"{runtime.root_uid} {runtime.binary} run -c {runtime.config}\n"
            runner = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=expected))

            self.assertTrue(helper.process_matches(4242, runtime, runner=runner))
            runtime.binary.chmod(0o700)
            runtime.binary.write_bytes(b"replaced")
            runtime.binary.chmod(0o500)
            with self.assertRaisesRegex(helper.SecurityError, "digest"):
                helper.process_matches(4242, runtime, runner=runner)

    def test_process_identity_rejects_foreign_or_recycled_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            outputs = (
                f"{runtime.root_uid + 1} {runtime.binary} run -c {runtime.config}\n",
                f"{runtime.root_uid} /usr/bin/other run -c {runtime.config}\n",
                "",
            )
            for output in outputs:
                runner = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=output))
                self.assertFalse(helper.process_matches(4242, runtime, runner=runner))

    def test_stop_engine_terms_verified_process_waits_and_removes_pid_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            exact = f"{runtime.root_uid} {runtime.binary} run -c {runtime.config}\n"
            runner = mock.Mock(side_effect=[
                SimpleNamespace(returncode=0, stdout=exact),
                SimpleNamespace(returncode=1, stdout=""),
            ])
            killer = mock.Mock()

            result = helper.stop_engine(
                runtime,
                runner=runner,
                killer=killer,
                sleeper=lambda _seconds: None,
                timeout=0.1,
            )

            self.assertEqual(result, {"stopped": True, "pid": 4242, "killed": False})
            killer.assert_called_once_with(4242, signal.SIGTERM)
            self.assertFalse(runtime.pid_file.exists())

    def test_stop_engine_rechecks_identity_before_bounded_kill(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            exact = f"{runtime.root_uid} {runtime.binary} run -c {runtime.config}\n"
            outputs = [exact, exact, exact, exact, exact, ""]
            runner = mock.Mock(side_effect=[SimpleNamespace(returncode=0, stdout=v) for v in outputs])
            killer = mock.Mock()
            now = [0.0]

            result = helper.stop_engine(
                runtime,
                runner=runner,
                killer=killer,
                sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
                monotonic=lambda: now[0],
                timeout=0.1,
            )

            self.assertTrue(result["killed"])
            self.assertEqual(
                killer.call_args_list,
                [mock.call(4242, signal.SIGTERM), mock.call(4242, signal.SIGKILL)],
            )

    def test_stop_engine_never_signals_foreign_pid_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            runner = mock.Mock(return_value=SimpleNamespace(
                returncode=0,
                stdout=f"{runtime.root_uid} /usr/bin/foreign --serve\n",
            ))
            killer = mock.Mock()

            with self.assertRaisesRegex(helper.SecurityError, "does not identify"):
                helper.stop_engine(runtime, runner=runner, killer=killer)

            killer.assert_not_called()
            self.assertTrue(runtime.pid_file.exists())

    def test_stop_engine_cleans_dead_stale_pid_without_signaling(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            runner = mock.Mock(return_value=SimpleNamespace(returncode=1, stdout=""))
            killer = mock.Mock()

            result = helper.stop_engine(runtime, runner=runner, killer=killer)

            self.assertEqual(result, {"stopped": True, "pid": 4242, "killed": False, "stale": True})
            killer.assert_not_called()
            self.assertFalse(runtime.pid_file.exists())

    def test_start_engine_validates_copies_checks_and_spawns_only_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime(root)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            user_config = user_root / "sing-box.json"
            user_config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            user_config.chmod(0o600)
            identity = user_root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            checker = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            process = SimpleNamespace(pid=4242)
            popen = mock.Mock(return_value=process)
            waiter = mock.Mock(return_value=True)

            result = helper.start_engine(
                install,
                runtime,
                checker=checker,
                popen=popen,
                waiter=waiter,
            )

            self.assertEqual(result, {"started": True, "pid": 4242})
            self.assertEqual(json.loads(runtime.config.read_text()), _generated_config("tun"))
            checker.assert_called_once_with(
                [str(runtime.binary), "check", "-c", str(runtime.candidate_config)],
                capture_output=True,
                text=True,
                timeout=20,
                cwd=str(runtime.state_dir),
                env=helper.sing_box_environment(runtime.state_dir),
            )
            spawn = popen.call_args
            self.assertEqual(spawn.args[0], [str(runtime.binary), "run", "-c", str(runtime.config)])
            self.assertEqual(spawn.kwargs["cwd"], str(runtime.state_dir))
            self.assertEqual(spawn.kwargs["env"], helper.sing_box_environment(runtime.state_dir))
            self.assertTrue(spawn.kwargs["start_new_session"])
            self.assertEqual(runtime.pid_file.read_text(), "4242\n")
            waiter.assert_called_once_with(4242, runtime)

    def test_start_engine_readiness_failure_stops_spawned_engine(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime(root)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            user_config = user_root / "sing-box.json"
            user_config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            user_config.chmod(0o600)
            identity = user_root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            checker = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            popen = mock.Mock(return_value=SimpleNamespace(pid=4242))
            stopper = mock.Mock(return_value={"stopped": True, "pid": 4242, "killed": False})

            with self.assertRaisesRegex(helper.SecurityError, "verified running state"):
                helper.start_engine(
                    install,
                    runtime,
                    checker=checker,
                    popen=popen,
                    waiter=lambda _pid, _runtime: False,
                    stopper=stopper,
                )

            stopper.assert_called_once_with(runtime)

    def test_reload_engine_checks_new_config_and_signals_only_verified_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime(root)
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            user_config = user_root / "sing-box.json"
            user_config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            user_config.chmod(0o600)
            identity = user_root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            exact = f"{runtime.root_uid} {runtime.binary} run -c {runtime.config}\n"
            runner = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=exact))
            checker = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            killer = mock.Mock()
            waiter = mock.Mock(return_value=True)

            result = helper.reload_engine(
                install,
                runtime,
                checker=checker,
                runner=runner,
                killer=killer,
                waiter=waiter,
            )

            self.assertEqual(result, {"reloaded": True, "pid": 4242})
            killer.assert_called_once_with(4242, signal.SIGHUP)
            waiter.assert_called_once_with(4242, runtime)
            self.assertEqual(json.loads(runtime.config.read_text()), _generated_config("tun"))

    def test_failed_config_check_preserves_previous_root_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime(root)
            previous = runtime.config.read_bytes()
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            user_config = user_root / "sing-box.json"
            user_config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            user_config.chmod(0o600)
            identity = user_root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            checker = mock.Mock(return_value=SimpleNamespace(returncode=1, stdout="", stderr="bad"))
            popen = mock.Mock()

            with self.assertRaisesRegex(helper.SecurityError, "rejected"):
                helper.start_engine(install, runtime, checker=checker, popen=popen)

            self.assertEqual(runtime.config.read_bytes(), previous)
            self.assertFalse((runtime.state_dir / "sing-box.json.candidate").exists())
            popen.assert_not_called()

    def test_engine_status_reports_canonical_root_backend_without_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            runtime.config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            runtime.config.chmod(0o600)
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            exact = f"{runtime.root_uid} {runtime.binary} run -c {runtime.config}\n"
            runner = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=exact))

            status = helper.engine_status(runtime, runner=runner)

            self.assertEqual(status["running"], True)
            self.assertEqual(status["pid"], 4242)
            self.assertEqual(status["mode"], "tun")
            self.assertEqual(status["schema_version"], helper.SCHEMA_VERSION)
            self.assertNotIn("config", status)
            self.assertNotIn("private_key", json.dumps(status))

    def test_user_log_rejects_preexisting_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            target = root / "other-user-file"
            target.write_text("do not touch", encoding="ascii")
            target.chmod(0o600)
            os.link(target, root / "sing-box.log")
            identity = root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )

            with self.assertRaisesRegex(helper.SecurityError, "log"):
                helper._open_user_log(install)

            self.assertEqual(target.read_text(), "do not touch")

    def test_pid_state_write_failure_terminates_untracked_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime(root)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            config = user_root / "sing-box.json"
            config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            config.chmod(0o600)
            identity = user_root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            checker = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            popen = mock.Mock(return_value=SimpleNamespace(pid=4242))
            cleanup = mock.Mock()

            with self.assertRaisesRegex(helper.SecurityError, "pid write failed"):
                helper.start_engine(
                    install,
                    runtime,
                    checker=checker,
                    popen=popen,
                    pid_writer=mock.Mock(side_effect=helper.SecurityError("pid write failed")),
                    spawn_cleanup=cleanup,
                )

            cleanup.assert_called_once_with(4242, runtime)

    def test_invalid_user_log_fails_before_existing_engine_is_stopped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self.runtime(root)
            runtime.pid_file.write_text("4242\n", encoding="ascii")
            runtime.pid_file.chmod(0o600)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            config = user_root / "sing-box.json"
            config.write_text(json.dumps(_generated_config("tun")), encoding="utf-8")
            config.chmod(0o600)
            target = user_root / "other"
            target.write_text("x", encoding="ascii")
            target.chmod(0o600)
            os.link(target, user_root / "sing-box.log")
            identity = user_root.stat()
            install = helper.InstallMetadata(
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
            )
            checker = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            stopper = mock.Mock()

            with self.assertRaisesRegex(helper.SecurityError, "log"):
                helper.start_engine(install, runtime, checker=checker, stopper=stopper)

            stopper.assert_not_called()

    def test_lifecycle_lock_creates_one_secure_root_state_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))

            with helper.lifecycle_lock(runtime):
                lock = runtime.state_dir / "helper.lock"
                self.assertTrue(lock.is_file())
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
                self.assertEqual(lock.stat().st_nlink, 1)

    def test_lifecycle_lock_serializes_independent_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            script = (
                "import hashlib,sys,time; from pathlib import Path; import privileged_helper as h; "
                "b=Path(sys.argv[1]); s=Path(sys.argv[2]); "
                "m=h.RuntimeMetadata(uid=501,gid=20,root_uid=int(sys.argv[3]),root_gid=int(sys.argv[4]),"
                "bundle_dir=b,state_dir=s,binary_sha256=sys.argv[5]); "
                "\nwith h.lifecycle_lock(m): print(time.monotonic(),flush=True); time.sleep(float(sys.argv[6]))"
            )
            args = [
                str(runtime.bundle_dir), str(runtime.state_dir),
                str(runtime.root_uid), str(runtime.root_gid), runtime.binary_sha256,
            ]
            first = subprocess.Popen(
                [sys.executable, "-c", script, *args, "0.25"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            first_stdout = first.stdout
            self.assertIsNotNone(first_stdout)
            assert first_stdout is not None
            first_acquired = float(first_stdout.readline().strip())
            second = subprocess.Popen(
                [sys.executable, "-c", script, *args, "0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            second_out, second_err = second.communicate(timeout=2)
            _first_out, first_err = first.communicate(timeout=2)
            second_acquired = float(second_out.strip())

            self.assertEqual(first.returncode, 0, first_err)
            self.assertEqual(second.returncode, 0, second_err)
            self.assertGreaterEqual(second_acquired - first_acquired, 0.15)

    def test_lifecycle_lock_reopens_when_another_process_wins_creation_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            real_open = os.open
            lock_calls = [0]

            def racing_open(path, flags, *args, **kwargs):
                if path != "helper.lock":
                    return real_open(path, flags, *args, **kwargs)
                lock_calls[0] += 1
                if lock_calls[0] == 1:
                    raise FileNotFoundError(path)
                if lock_calls[0] == 2:
                    fd = real_open(path, flags, *args, **kwargs)
                    os.close(fd)
                    raise FileExistsError(path)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(helper.os, "open", side_effect=racing_open):
                with helper.lifecycle_lock(runtime):
                    pass

            self.assertGreaterEqual(lock_calls[0], 3)

    def test_root_metadata_loads_exact_install_and_runtime_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper_parent = root / "PrivilegedHelperTools"
            helper_parent.mkdir(mode=0o700)
            state_parent = root / "var-db"
            state_parent.mkdir(mode=0o700)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            layout = installer.InstallLayout(
                helper_parent=helper_parent,
                helper_base=helper_parent / "com.proxy-router",
                state_base=state_parent / "proxy-router",
                sudoers_file=root / "sudoers.d" / "91-proxy-router",
            )
            bundle = installer.stage_bundle(
                layout,
                helper_bytes=b"helper\n",
                installer_bytes=b"installer\n",
                manifest_bytes=b"{}\n",
                binary_bytes=b"trusted-sing-box",
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            identity = user_root.stat()
            installer.write_install_metadata(
                layout,
                uid=os.getuid(), gid=os.getgid(), user_root=user_root,
                user_root_device=identity.st_dev, user_root_inode=identity.st_ino,
                bundle_digest=bundle["bundle_digest"],
                binary_sha256=bundle["binary_sha256"],
                owner_uid=os.getuid(), owner_gid=os.getgid(),
            )

            install, runtime = helper.load_installed_runtime(
                os.getuid(),
                state_base=layout.state_base,
                versions_dir=layout.helper_base / "versions",
                root_uid=os.getuid(),
                root_gid=os.getgid(),
            )

            self.assertEqual(install.user_root, user_root)
            self.assertEqual(runtime.bundle_dir.name, bundle["bundle_digest"])
            self.assertEqual(runtime.state_dir, layout.state_base / str(os.getuid()))
            self.assertEqual(runtime.binary_sha256, bundle["binary_sha256"])

    def test_helper_main_requires_root_and_dispatches_exact_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime(Path(temporary))
            install = helper.InstallMetadata(
                uid=501,
                gid=20,
                user_root=Path(temporary),
                user_root_device=1,
                user_root_inode=2,
            )
            status = mock.Mock(return_value={
                "installed": True,
                "running": False,
                "pid": None,
                "mode": "tun",
                "schema_version": helper.SCHEMA_VERSION,
                "binary_sha256": runtime.binary_sha256,
            })
            output = []

            rc = helper.main(
                ["status", "501"],
                euid=lambda: 0,
                loader=lambda _uid: (install, runtime),
                status_action=status,
                output=output.append,
            )

            self.assertEqual(rc, 0)
            status.assert_called_once_with(runtime)
            self.assertEqual(json.loads(output[0])["mode"], "tun")
            denied = helper.main(
                ["status", "501"],
                euid=lambda: 501,
                loader=lambda _uid: (install, runtime),
                output=output.append,
            )
            self.assertEqual(denied, 1)

    def test_uninstall_stops_engine_then_removes_policy_bundle_and_root_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper_base = root / "helper"
            version = helper_base / "versions" / "v1"
            version.mkdir(parents=True, mode=0o700)
            binary = version / "sing-box"
            binary.write_bytes(b"trusted")
            binary.chmod(0o500)
            helper_file = version / "privileged_helper.py"
            helper_file.write_text("# helper\n", encoding="ascii")
            helper_file.chmod(0o500)
            (helper_base / "current").symlink_to(Path("versions") / "v1")
            state = root / "state" / "501"
            state.mkdir(parents=True, mode=0o700)
            runtime = helper.RuntimeMetadata(
                uid=501, gid=20, root_uid=os.getuid(), root_gid=os.getgid(),
                bundle_dir=version, state_dir=state,
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            )
            install = helper.InstallMetadata(
                uid=501, gid=20, user_root=root,
                user_root_device=root.stat().st_dev, user_root_inode=root.stat().st_ino,
            )
            sudoers_dir = root / "sudoers.d"
            sudoers_dir.mkdir(mode=0o700)
            sudoers = sudoers_dir / "91-proxy-router"
            sudoers.write_text(
                "# Managed by proxy-router privileged helper v2; remove with `elevate uninstall`.\n"
                + "\n".join(
                    f"alice ALL=(root) NOPASSWD: /usr/bin/python3 -I -S {helper_file} {op} 501"
                    for op in ("status", "start", "stop", "reload", "uninstall")
                )
                + "\n",
                encoding="utf-8",
            )
            sudoers.chmod(0o440)
            stopper = mock.Mock(return_value={"stopped": True, "pid": None, "killed": False})
            visudo = mock.Mock(return_value=SimpleNamespace(returncode=0))

            result = helper.uninstall_helper(
                install,
                runtime,
                helper_base=helper_base,
                sudoers_file=sudoers,
                stopper=stopper,
                visudo=visudo,
            )

            self.assertEqual(result, {"uninstalled": True})
            stopper.assert_called_once_with(runtime)
            self.assertFalse(sudoers.exists())
            self.assertFalse(helper_base.exists())
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()

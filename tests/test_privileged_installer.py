"""Installer and sudoers contracts for the root-owned helper bundle."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import privileged_installer as installer


class SudoersPolicyTests(unittest.TestCase):
    def test_policy_has_only_exact_helper_operations_and_passes_real_visudo(self):
        helper = Path("/Library/PrivilegedHelperTools/com.proxy-router/current/privileged_helper.py")

        policy = installer.render_sudoers("alice", 501, helper)

        command_lines = [line for line in policy.splitlines() if "NOPASSWD:" in line]
        self.assertEqual(len(command_lines), 5)
        for operation in ("status", "start", "stop", "reload", "uninstall"):
            matches = [line for line in command_lines if f" {operation} 501" in line]
            self.assertEqual(len(matches), 1, operation)
        self.assertNotIn("router.py", policy)
        self.assertNotIn(" SETENV:", policy)
        self.assertTrue(all("*" not in line for line in command_lines))
        self.assertIn("/usr/bin/python3 -I -S", policy)
        self.assertIn("!requiretty", policy)
        self.assertIn("!setenv", policy)

        if Path("/usr/sbin/visudo").is_file():
            with tempfile.NamedTemporaryFile("w", delete=False) as handle:
                handle.write(policy)
                path = Path(handle.name)
            self.addCleanup(path.unlink, missing_ok=True)
            result = subprocess.run(
                ["/usr/sbin/visudo", "-c", "-f", str(path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_linux_layout_uses_canonical_system_paths(self):
        layout = installer.InstallLayout.for_platform("linux")

        self.assertEqual(layout.helper_parent, Path("/usr/local/libexec"))
        self.assertEqual(layout.helper_base, Path("/usr/local/libexec/proxy-router"))
        self.assertEqual(layout.state_base, Path("/var/lib/proxy-router"))
        self.assertEqual(layout.sudoers_file, Path("/etc/sudoers.d/91-proxy-router"))
        self.assertEqual(
            layout.helper_path,
            Path("/usr/local/libexec/proxy-router/current/privileged_helper.py"),
        )

    def test_linux_policy_uses_only_the_canonical_linux_helper(self):
        helper_path = installer.LINUX_EXPECTED_HELPER
        policy = installer.render_sudoers("alice", 501, helper_path)

        self.assertIn(str(helper_path), policy)
        self.assertNotIn(str(installer.EXPECTED_HELPER), policy)
        self.assertEqual(
            installer.classify_policy(
                policy,
                "/opt/anaconda3/bin/python3",
                "/Users/alice/proxy-router/router.py",
                helper_path=helper_path,
            ),
            "v2",
        )

    def test_policy_classifier_distinguishes_legacy_v2_and_foreign_content(self):
        python = "/opt/anaconda3/bin/python3"
        router = "/Users/alice/proxy-router/router.py"
        legacy = (
            "# Managed by `proxy-router elevate install`; remove with `elevate uninstall`.\n"
            f"alice ALL=(root) NOPASSWD: {python} {router} start\n"
        )
        v2 = installer.render_sudoers("alice", 501, installer.EXPECTED_HELPER)
        foreign = "alice ALL=(root) NOPASSWD: /bin/sh\n"

        self.assertEqual(installer.classify_policy(legacy, python, router), "legacy")
        self.assertEqual(installer.classify_policy(v2, python, router), "v2")
        self.assertEqual(installer.classify_policy(foreign, python, router), "foreign")
        self.assertEqual(installer.classify_policy("", python, router), "absent")


class BundleInstallTests(unittest.TestCase):
    def test_stage_bundle_installs_immutable_version_and_atomic_current_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "PrivilegedHelperTools"
            parent.mkdir(mode=0o700)
            layout = installer.InstallLayout(
                helper_parent=parent,
                helper_base=parent / "com.proxy-router",
                state_base=Path(temporary) / "var-db",
                sudoers_file=Path(temporary) / "sudoers.d" / "91-proxy-router",
            )

            result = installer.stage_bundle(
                layout,
                helper_bytes=b"helper\n",
                installer_bytes=b"installer\n",
                manifest_bytes=b"{}\n",
                binary_bytes=b"trusted-sing-box",
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

            version = layout.helper_base / "versions" / result["bundle_digest"]
            self.assertEqual((layout.helper_base / "current").readlink(), Path("versions") / result["bundle_digest"])
            self.assertEqual((version / "privileged_helper.py").read_bytes(), b"helper\n")
            self.assertEqual((version / "privileged_installer.py").read_bytes(), b"installer\n")
            self.assertEqual((version / "sing-box-release.json").read_bytes(), b"{}\n")
            self.assertEqual((version / "sing-box").read_bytes(), b"trusted-sing-box")
            self.assertEqual(stat.S_IMODE(version.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((version / "sing-box").stat().st_mode), 0o555)

    def test_stage_failure_removes_all_partial_bundle_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "PrivilegedHelperTools"
            parent.mkdir(mode=0o700)
            layout = installer.InstallLayout(
                helper_parent=parent,
                helper_base=parent / "com.proxy-router",
                state_base=Path(temporary) / "var-db",
                sudoers_file=Path(temporary) / "sudoers.d" / "91-proxy-router",
            )
            real_write = installer._write_new_file
            calls = [0]

            def fail_second(*args, **kwargs):
                calls[0] += 1
                if calls[0] == 2:
                    raise OSError("injected write failure")
                return real_write(*args, **kwargs)

            with mock.patch.object(installer, "_write_new_file", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "injected"):
                    installer.stage_bundle(
                        layout,
                        helper_bytes=b"helper\n",
                        installer_bytes=b"installer\n",
                        manifest_bytes=b"{}\n",
                        binary_bytes=b"trusted-sing-box",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )

            versions = layout.helper_base / "versions"
            self.assertEqual(list(versions.iterdir()), [])
            self.assertFalse((layout.helper_base / "current").exists())

    def test_same_bundle_install_is_idempotent_and_does_not_duplicate_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "PrivilegedHelperTools"
            parent.mkdir(mode=0o700)
            layout = installer.InstallLayout(
                helper_parent=parent,
                helper_base=parent / "com.proxy-router",
                state_base=Path(temporary) / "var-db",
                sudoers_file=Path(temporary) / "sudoers.d" / "91-proxy-router",
            )
            kwargs = dict(
                helper_bytes=b"helper\n",
                installer_bytes=b"installer\n",
                manifest_bytes=b"{}\n",
                binary_bytes=b"trusted-sing-box",
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

            first = installer.stage_bundle(layout, **kwargs)
            second = installer.stage_bundle(layout, **kwargs)

            self.assertEqual(first, second)
            versions = list((layout.helper_base / "versions").iterdir())
            self.assertEqual([path.name for path in versions], [first["bundle_digest"]])


class MigrationTests(unittest.TestCase):
    def test_legacy_policy_is_revoked_before_stage_failure_and_never_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sudoers = root / "sudoers.d"
            sudoers.mkdir(mode=0o700)
            policy = sudoers / "91-proxy-router"
            legacy_python = "/opt/anaconda3/bin/python3"
            legacy_router = "/Users/alice/proxy-router/router.py"
            policy.write_text(
                "# Managed by `proxy-router elevate install`; remove with `elevate uninstall`.\n"
                f"alice ALL=(root) NOPASSWD: {legacy_python} {legacy_router} start\n",
                encoding="utf-8",
            )
            policy.chmod(0o440)
            layout = installer.InstallLayout(
                helper_parent=root,
                helper_base=root / "helper",
                state_base=root / "state",
                sudoers_file=policy,
            )

            def failing_stage():
                self.assertFalse(policy.exists())
                raise OSError("injected stage failure")

            with self.assertRaisesRegex(OSError, "injected"):
                installer.migrate_install(
                    layout,
                    legacy_python=legacy_python,
                    legacy_router=legacy_router,
                    stop_legacy=mock.Mock(),
                    stage=failing_stage,
                    owner_uid=os.getuid(),
                )

            self.assertFalse(policy.exists())

    def test_v2_policy_is_validated_then_atomically_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sudoers = root / "sudoers.d"
            sudoers.mkdir(mode=0o700)
            layout = installer.InstallLayout(
                helper_parent=root,
                helper_base=root / "helper",
                state_base=root / "state",
                sudoers_file=sudoers / "91-proxy-router",
            )
            policy = installer.render_sudoers("alice", 501, installer.EXPECTED_HELPER)

            def validate(command, **_kwargs):
                candidate = Path(command[-1])
                self.assertEqual(candidate.read_text(), policy)
                self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o440)
                return subprocess.CompletedProcess(command, 0, "", "")

            installer.install_policy(
                layout,
                policy,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                runner=validate,
            )

            self.assertEqual(layout.sudoers_file.read_text(), policy)
            self.assertEqual(stat.S_IMODE(layout.sudoers_file.stat().st_mode), 0o440)
            self.assertEqual([path.name for path in sudoers.iterdir()], ["91-proxy-router"])

    def test_install_metadata_is_root_owned_atomic_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_parent = root / "var-db"
            state_parent.mkdir(mode=0o700)
            user_root = root / "user"
            user_root.mkdir(mode=0o700)
            identity = user_root.stat()
            layout = installer.InstallLayout(
                helper_parent=root,
                helper_base=root / "helper",
                state_base=state_parent / "proxy-router",
                sudoers_file=root / "sudoers.d" / "91-proxy-router",
            )

            path = installer.write_install_metadata(
                layout,
                uid=os.getuid(),
                gid=os.getgid(),
                user_root=user_root,
                user_root_device=identity.st_dev,
                user_root_inode=identity.st_ino,
                bundle_digest="a" * 64,
                binary_sha256="b" * 64,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

            data = installer.read_install_metadata(path, owner_uid=os.getuid(), anchor=state_parent)
            self.assertEqual(data["uid"], os.getuid())
            self.assertEqual(data["user_root"], str(user_root))
            self.assertEqual(data["bundle_digest"], "a" * 64)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()

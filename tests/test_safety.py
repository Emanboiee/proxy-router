"""Focused tests for the fail-closed test safety layer (issue #58 Task 1)."""
import os
import signal
import subprocess
import sys

import pytest


class TestCommandClassification:
    def test_mutating_networksetup_is_blocked(self):
        from tests.safety import classify_command
        result = classify_command(["networksetup", "-setwebproxystate", "Wi-Fi", "off"])
        assert result.allowed is False

    def test_read_only_networksetup_is_allowed(self):
        from tests.safety import classify_command
        assert classify_command(["networksetup", "-listallnetworkservices"]).allowed is True
        assert classify_command(["networksetup", "-getwebproxy", "Wi-Fi"]).allowed is True

    @pytest.mark.parametrize("flag", [
        "-createnetworkservice",
        "-removenetworkservice",
        "-renamenetworkservice",
        "-adddnsservers",
        "-removednsservers",
        "-addsearchdomains",
        "-removesearchdomains",
        "-create6to4service",
    ])
    def test_non_set_networksetup_mutators_are_blocked(self, flag):
        from tests.safety import classify_command
        assert classify_command(["networksetup", flag, "Wi-Fi", "value"]).allowed is False

    def test_route_watcher_worker_is_blocked(self):
        from tests.safety import classify_command
        result = classify_command([
            sys.executable, "route_watcher.py", "--worker", "--root", "/tmp",
        ])
        assert result.allowed is False

    def test_disposable_popen_command_is_allowed(self):
        from tests.safety import classify_command
        assert classify_command(["sleep", "1"]).allowed is True

    @pytest.mark.parametrize("command", [
        "networksetup -setwebproxystate Wi-Fi off",
        "env networksetup -setwebproxystate Wi-Fi off",
        "nohup networksetup -setwebproxystate Wi-Fi off",
        "bash -c 'networksetup -setwebproxystate Wi-Fi off'",
        "bash -c 'bash -c \"networksetup -setwebproxystate Wi-Fi off\"'",
        "sh -c 'env networksetup -setwebproxystate Wi-Fi off'",
        "bash -c 'python3 route_watcher.py --worker --root /tmp'",
    ])
    def test_shell_and_nested_mutations_are_blocked(self, command):
        from tests.safety import classify_command
        assert classify_command(command).allowed is False


class TestChildRegistry:
    def test_guarded_popen_retains_proc_and_cleans_private_group(self, safety_nodeid):
        from tests.safety import get_session_registry
        registry = get_session_registry()
        proc = subprocess.Popen(["sleep", "300"], start_new_session=True)
        children = registry.children_for_test(safety_nodeid)
        assert [child.pid for child in children] == [proc.pid]
        child = children[0]
        assert child.proc is proc
        assert child.pgid == proc.pid
        assert registry.cleanup_child(child, timeout=3.0) is True
        assert registry.children_for_test(safety_nodeid) == []
        assert proc.poll() is not None

    def test_guarded_popen_without_private_group_uses_pid_cleanup(self, safety_nodeid):
        from tests.safety import get_session_registry
        registry = get_session_registry()
        proc = subprocess.Popen(["sleep", "300"])
        child = registry.children_for_test(safety_nodeid)[0]
        assert child.pgid == os.getpgrp()
        assert registry.cleanup_child(child, timeout=3.0) is True
        assert proc.poll() is not None

    def test_completed_subprocess_is_silently_unregistered_at_teardown(self):
        result = subprocess.run(
            [sys.executable, "-c", "pass"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # Intentionally leave the completed Popen registration for autouse
        # teardown. A false-positive leak makes this test error after its body.

    def test_protected_baseline_pid_is_refused_before_cleanup(self):
        from tests.safety import ChildRegistry
        registry = ChildRegistry()
        registry.register(
            pid=424242,
            pgid=424242,
            command=["protected"],
            test_id="protected",
        )
        child = registry.children_for_test("protected")[0]
        with pytest.raises(RuntimeError, match="protected baseline PID"):
            registry.cleanup_child(child, baseline_pids={424242})
        assert registry.is_registered(424242)
        registry.clear()


class TestProcessTree:
    def test_parser_and_diff_report_new_process(self):
        from tests.safety import parse_process_tree, process_tree_diff
        baseline = parse_process_tree("1 0 1 init\n2 1 1 pytest\n")
        current = parse_process_tree("1 0 1 init\n2 1 1 pytest\n3 2 3 sleep 10\n")
        diff = process_tree_diff(baseline, current)
        assert diff.new == {3}
        assert diff.removed == set()

    def test_find_new_descendants_follows_ancestry_only(self):
        from tests.safety import find_new_descendants
        tree = {
            10: {"pid": 10, "ppid": 1, "pgid": 10, "command": "pytest"},
            11: {"pid": 11, "ppid": 10, "pgid": 11, "command": "child"},
            12: {"pid": 12, "ppid": 11, "pgid": 11, "command": "grandchild"},
            99: {"pid": 99, "ppid": 1, "pgid": 99, "command": "ambient"},
        }
        assert find_new_descendants(10, tree, {10}) == {11, 12}
        assert 99 not in find_new_descendants(10, tree, {10})

    def test_baseline_descendant_is_not_new(self):
        from tests.safety import find_new_descendants
        tree = {
            10: {"pid": 10, "ppid": 1, "pgid": 10, "command": "pytest"},
            11: {"pid": 11, "ppid": 10, "pgid": 11, "command": "baseline child"},
        }
        assert find_new_descendants(10, tree, {10, 11}) == set()


class TestProxySnapshot:
    def test_diff_is_field_specific(self):
        from tests.safety import proxy_snapshot_diff
        baseline = {"http_enable": "0", "pac_enable": "0"}
        current = {"http_enable": "1", "pac_enable": "0"}
        assert proxy_snapshot_diff(baseline, current).changed == {"http_enable"}

    def test_scutil_proxy_normalization_keeps_only_stable_proxy_fields(self):
        from tests.safety import normalize_scutil_proxy
        output = """<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
  HTTPPort : 2080
  ProxyAutoConfigEnable : 0
  ProxyAutoDiscoveryEnable : 0
  ExceptionsList : <array> {
    0 : localhost
  }
}
"""
        assert normalize_scutil_proxy(output) == {
            "HTTPEnable": "1",
            "HTTPPort": "2080",
            "HTTPProxy": "127.0.0.1",
            "ProxyAutoConfigEnable": "0",
            "ProxyAutoDiscoveryEnable": "0",
        }

    def test_service_proxy_snapshot_is_namespaced_and_normalized(self):
        from tests.safety import normalize_service_proxy_outputs
        result = normalize_service_proxy_outputs({
            "web": "Enabled: Yes\nServer: 127.0.0.1\nPort: 2080\n",
            "secure": "Enabled: No\nServer: \nPort: 0\n",
            "pac": "URL: (null)\nEnabled: No\n",
            "discovery": "Auto Proxy Discovery: Off\n",
        })
        assert result["web.enabled"] == "yes"
        assert result["web.server"] == "127.0.0.1"
        assert result["secure.enabled"] == "no"
        assert result["pac.url"] == "(null)"
        assert result["discovery.auto_proxy_discovery"] == "off"

    def test_listener_owner_snapshot_is_baseline_aware(self):
        from tests.safety import normalize_lsof_listener_owners, compare_host_snapshots
        output = "p2429\ncsing-box\nf12\nn127.0.0.1:2080\n"
        owners = normalize_lsof_listener_owners(output)
        assert owners == ((2429, "sing-box", "127.0.0.1:2080"),)
        baseline = {"listener_2080": owners}
        assert compare_host_snapshots(baseline, baseline).status == "ok"

    def test_correlated_guard_attempt_is_attributed_failure(self):
        from tests.safety import compare_host_snapshots
        result = compare_host_snapshots(
            {"proxy": {"HTTPEnable": "0"}},
            {"proxy": {"HTTPEnable": "1"}},
            guard_attempts=["networksetup -setwebproxystate"],
        )
        assert result.status == "guard_violation"
        assert result.attributed is True

    def test_uncorrelated_ambient_change_is_environment_changed_locally(self):
        from tests.safety import compare_host_snapshots
        result = compare_host_snapshots(
            {"listener_2080": ((1, "old", "127.0.0.1:2080"),)},
            {"listener_2080": ((2, "new", "127.0.0.1:2080"),)},
            strict=False,
        )
        assert result.status == "environment_changed"
        assert result.attributed is False
        strict = compare_host_snapshots(
            {"listener_2080": (1,)}, {"listener_2080": (2,)}, strict=True,
        )
        assert strict.status == "failed"


class TestSignalValidation:
    def test_current_pytest_process_group_is_rejected(self):
        from tests.safety import validate_signal_target
        assert validate_signal_target(-os.getpgrp()).allowed is False

    def test_foreign_pid_is_rejected(self):
        from tests.safety import validate_signal_target
        assert validate_signal_target(1).allowed is False

    def test_registered_private_group_is_allowed(self):
        from tests.safety import ChildRegistry, validate_signal_target
        registry = ChildRegistry()
        registry.register(pid=99999, pgid=99999, command=["sleep"], test_id="fake")
        assert validate_signal_target(-99999, registry=registry).allowed is True


class TestInstalledGuards:
    @pytest.mark.safety_guard
    def test_forkpty_is_in_direct_spawn_guard_set(self):
        if not hasattr(os, "forkpty"):
            pytest.skip("os.forkpty unavailable")
        from tests import conftest as safety_conftest
        assert "forkpty" in safety_conftest._DIRECT_SPAWN_NAMES
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.forkpty()

    @pytest.mark.safety_guard
    def test_mutating_networksetup_is_blocked_before_execution(self):
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            subprocess.run(["networksetup", "-setwebproxystate", "Wi-Fi", "off"])

    @pytest.mark.safety_guard
    def test_route_watcher_worker_is_blocked_before_execution(self):
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            subprocess.Popen([
                sys.executable, "route_watcher.py", "--worker", "--root", "/tmp",
            ])

    @pytest.mark.safety_guard
    def test_current_group_and_foreign_signals_are_blocked(self):
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.killpg(os.getpgrp(), signal.SIGTERM)
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.kill(-os.getpgrp(), signal.SIGTERM)
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.kill(1, signal.SIGTERM)

    @pytest.mark.safety_guard
    def test_fork_is_blocked(self):
        if not hasattr(os, "fork"):
            pytest.skip("os.fork unavailable")
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.fork()

    @pytest.mark.safety_guard
    def test_harmless_posix_spawn_is_still_blocked(self):
        if not hasattr(os, "posix_spawn"):
            pytest.skip("os.posix_spawn unavailable")
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.posix_spawn("/bin/true", ["/bin/true"], os.environ.copy())

    @pytest.mark.safety_guard
    def test_harmless_spawnl_is_still_blocked(self):
        if not hasattr(os, "spawnl"):
            pytest.skip("os.spawnl unavailable")
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.spawnl(os.P_WAIT, "/bin/true", "true")

    @pytest.mark.safety_guard
    def test_os_system_is_blocked(self):
        with pytest.raises(RuntimeError, match="TEST SAFETY"):
            os.system("true")

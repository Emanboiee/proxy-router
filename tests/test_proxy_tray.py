"""Unit tests for proxy_tray.py (stdlib only, no GUI deps — the
module's pystray/PIL imports are guarded)."""
import importlib.util
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load_tray():
    if "proxy_tray" in sys.modules:
        return sys.modules["proxy_tray"]
    spec = importlib.util.spec_from_file_location(
        "proxy_tray", ROOT / "proxy_tray.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["proxy_tray"] = mod
    spec.loader.exec_module(mod)
    return mod


tray = _load_tray()


class RouterClientEngineOwnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.pid = Path(self.tmp.name) / "sing-box.pid"
        self.addCleanup(self.tmp.cleanup)

    def test_missing_pid_file_is_not_root(self):
        self.assertFalse(self.client._engine_runs_as_root())

    def test_pid_file_alone_does_not_prove_root(self):
        self.pid.write_text("4242")
        with mock.patch.object(tray.subprocess, "run", return_value=SimpleNamespace(
                returncode=1, stdout="")):
            self.assertFalse(self.client._engine_runs_as_root())

    def test_unreadable_pid_file_without_live_root_process_is_not_root(self):
        self.pid.write_text("4242")
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch("os.geteuid", return_value=501), \
             mock.patch.object(tray.Path, "read_text", side_effect=PermissionError), \
             mock.patch.object(tray.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout="")):
            self.assertFalse(self.client._engine_runs_as_root())

    def test_readable_root_pid_confirmed_by_live_exact_process(self):
        self.pid.write_text("4242")
        config = str(Path(self.tmp.name) / "sing-box.json")
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch("os.geteuid", return_value=501), \
             mock.patch.dict(tray.os.environ, {"SING_BOX": "/trusted/sing-box"}), \
             mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = SimpleNamespace(
                returncode=0,
                stdout=f"0 /trusted/sing-box run -c {config}\n",
            )
            self.assertTrue(self.client._engine_runs_as_root())
        self.assertEqual(run.call_args.args[0], ["ps", "-p", "4242", "-o", "uid=,command="])

    def test_never_root_outside_macos(self):
        self.pid.write_text("4242")
        with mock.patch.object(tray.sys, "platform", "linux"), \
             mock.patch("os.stat") as st:
            st.return_value.st_uid = 0
            with mock.patch("builtins.open", side_effect=PermissionError):
                self.assertFalse(self.client._engine_runs_as_root())


class RouterClientLifecycleDelegationTests(unittest.TestCase):
    """Lifecycle ownership belongs to router.py, not duplicated tray probes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.client._active_provider = "proton"
        self.addCleanup(self.tmp.cleanup)

    def test_lifecycle_commands_delegate_once_without_local_owner_probe(self):
        with mock.patch.object(self.client, "_engine_runs_as_root",
                               side_effect=AssertionError("tray must not decide owner")), \
             mock.patch.object(self.client, "_run", return_value=(0, "ok")) as run:
            self.assertEqual(self.client.start(), (0, "ok"))
            self.assertEqual(self.client.stop(), (0, "ok"))
            self.assertEqual(self.client.rotate(), (0, "ok"))
            self.assertEqual(
                self.client.rotate_to("proton", "06-SG-FREE-4", force=True),
                (0, "ok"),
            )
        self.assertEqual(
            [call.args for call in run.call_args_list],
            [
                ("start",),
                ("stop",),
                ("rotate", "proton"),
                ("rotate", "proton", "--to", "06-SG-FREE-4", "--force"),
            ],
        )


class HumanizeTests(unittest.TestCase):
    def test_untouched_engine_shortcut_unchanged(self):
        self.assertEqual(
            tray._humanize("engine is untouched"), "saved — Connect to apply")

    def test_empty_output_is_empty(self):
        self.assertEqual(tray._humanize(""), "")

    def test_long_unmapped_detail_cap_is_above_160(self):
        # The CLI's missing-binary message lists every candidate; the old
        # 160-char cap cut it into an unexplained "Connect: Failed" (#11).
        out = "router: could not start sing-box: " + "candidate-path " * 40
        detail = tray._humanize(out)
        self.assertGreater(len(detail), 160)  # old cap would cut at 160
        self.assertEqual(len(detail), tray._MAX_DETAIL)  # cap keeps the full detail

    def test_sing_box_not_found_maps_to_friendly_next_step(self):
        detail = tray._humanize(
            "router: sing-box not found (tried: env SING_BOX=(unset), ...)")
        self.assertIn("install sing-box 1.12+", detail)
        self.assertIn("github.com/SagerNet/sing-box/releases", detail)

    def test_system_proxy_echo_line_is_stripped(self):
        # macOS start/stop end with "system proxy disabled on 1 network
        # service(s)"; showing that after "Connect: done" reads like a
        # failure (issue #50).
        detail = tray._humanize(
            "router: engine started\nsystem proxy disabled on 1 network service(s)")
        self.assertEqual(detail, "")

    def test_system_proxy_enabled_echo_line_is_stripped(self):
        detail = tray._humanize(
            "system proxy enabled on 2 network service(s) -> 127.0.0.1:2080")
        self.assertEqual(detail, "")


class RunElevatedFallbackTests(unittest.TestCase):
    """Legacy-named wrapper now runs only the normal user controller."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _probe(self, returncode, stdout="", stderr=""):
        return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()

    def test_controller_failure_never_falls_back_to_osascript(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(1, stderr="a password is required")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (1, "a password is required"))
        self.assertEqual(run.call_args.args[0][0], self.client.python)
        self.assertEqual(run.call_count, 1)

    def test_controller_sudoers_message_is_returned_without_tray_fallback(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(1, stderr="alice is not in the sudoers file")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (1, "alice is not in the sudoers file"))
        self.assertEqual(run.call_args.args[0][0], self.client.python)

    def test_controller_command_failure_returns_unchanged(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(3, stderr="router: engine failed to start")
            rc, _out = self.client._run_elevated("stop")
        self.assertEqual(rc, 3)
        self.assertEqual(run.call_args.args[0][0], self.client.python)
        self.assertEqual(run.call_count, 1)

    def test_controller_success_returns_unchanged(self):
        with mock.patch.object(tray.subprocess, "run") as run:
            run.return_value = self._probe(0, stdout="stopped")
            rc, out = self.client._run_elevated("stop")
        self.assertEqual((rc, out), (0, "stopped"))
        self.assertEqual(run.call_args.args[0][0], self.client.python)
        self.assertEqual(run.call_count, 1)


class TransientProbePresentationTests(unittest.TestCase):
    def _status(self, record):
        return tray.RouterStatus(
            up=True,
            providers={
                "proton": {
                    "active": "06-SG-FREE-4",
                    "profiles": ["06-SG-FREE-4"],
                    "egress": {"06-SG-FREE-4": record},
                }
            },
        )

    def test_transport_probe_failure_is_quiet_but_stays_force_clickable(self):
        status = self._status({
            "ok": False,
            "status": None,
            "error": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING]>",
            "upstream_error": None,
            "blocked": False,
            "exhausted": False,
        })
        app = object.__new__(tray.TrayApp)
        self.assertEqual(status.profile_health("proton", "06-SG-FREE-4"), "")
        self.assertNotIn("▲", status.provider_label("proton"))
        self.assertTrue(app._exit_try_anyway(status, "proton", "06-SG-FREE-4"))

    def test_explicit_upstream_failure_stays_visible(self):
        status = self._status({
            "ok": True,
            "status": 200,
            "error": None,
            "upstream_error": "429",
            "blocked": False,
            "exhausted": True,
        })
        self.assertIn("▲", status.provider_label("proton"))
        self.assertIn("rate-limited", status.profile_health("proton", "06-SG-FREE-4"))


class MutationSerializationTests(unittest.TestCase):
    """Issue #60: tray mutations used to run on independent daemon threads.

    Two rapid clicks raced inside router.py, and an older completion or poll
    could overwrite newer status. These tests pin the contract: strict FIFO
    execution (no concurrency), newest-snapshot-wins publication, and a
    menu signature that covers every field the menu renders.
    """

    def _make_app(self):
        class FakeClient:
            def status(self):
                return tray.RouterStatus()
        app = tray.TrayApp(FakeClient(), None)
        return app

    def _wait_until(self, pred, timeout=2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.005)
        return pred()

    def test_overlapping_clicks_execute_serially_in_click_order(self):
        app = self._make_app()
        events = []
        lock = threading.Lock()

        def make_job(name, hold):
            def job():
                with lock:
                    running = getattr(app, "_concurrency_probe", 0)
                    app._concurrency_probe = running + 1
                    events.append(f"{name}:start")
                if hold:
                    time.sleep(0.15)  # long enough for the next click to land
                with lock:
                    app._concurrency_probe -= 1
                    events.append(f"{name}:done")
                return 0, "ok"
            return job

        # Click 1 starts a slow mutation; clicks 2..4 arrive while it runs.
        app._do(make_job("a", True), "a")
        app._do(make_job("b", False), "b")
        app._do(make_job("c", False), "c")
        app._do(make_job("d", False), "d")
        self.assertTrue(self._wait_until(
            lambda: len([e for e in events if e.endswith(":done")]) == 4))
        order = [e.split(":")[0] for e in events if e.endswith(":start")]
        dones = [e.split(":")[0] for e in events if e.endswith(":done")]
        self.assertEqual(order, ["a", "b", "c", "d"])
        self.assertEqual(dones, ["a", "b", "c", "d"])
        # No two bodies ever overlapped: the pump leaves no residual count.
        self.assertEqual(app._concurrency_probe, 0)

    def test_worker_exception_becomes_visible_failed_result(self):
        app = self._make_app()

        def boom():
            raise RuntimeError("kaboom")

        app._do(boom, "explode")
        self.assertTrue(self._wait_until(
            lambda: app.last_action_result
            and "failed" in app.last_action_result))
        self.assertIn("RuntimeError", app.last_action_result)

    def test_dashboard_update_failure_does_not_stick_mutation_active(self):
        app = self._make_app()

        def fail_publish(*_args):
            raise RuntimeError("dashboard closed")

        app._publish_status = fail_publish
        app._do(lambda: (0, "ok"), "connect")
        self.assertTrue(self._wait_until(lambda: not app._mutation_active))

    def test_stale_poll_cannot_overwrite_newer_post_action_snapshot(self):
        # Deliberately inverted completion driven through the REAL poll
        # loop: the poll claims its slot and fetches status BEFORE the
        # action finishes, then publishes AFTER the post-action snapshot
        # landed. The newer post-action snapshot must win.
        gate = threading.Event()

        class BlockingStatusClient:
            root = "/tmp"

            def __init__(self):
                self.calls = 0

            def status(self):
                self.calls += 1
                if self.calls == 1:
                    gate.wait(2)  # poll fetch stalls "mid-network"
                    return tray.RouterStatus(up=False)
                return tray.RouterStatus()

        client = BlockingStatusClient()
        app = tray.TrayApp(client, None)
        app._publish_status(tray.RouterStatus(), None)  # baseline
        poller = threading.Thread(target=self._guarded_poll(app), daemon=True)
        poller.start()
        deadline = time.time() + 2
        while client.calls < 1 and time.time() < deadline:
            time.sleep(0.005)
        time.sleep(0.05)  # ensure the poll is parked inside its fetch

        # The mutation finishes meanwhile and publishes its fresh snapshot,
        # exactly like _mutation_worker does (new epoch, newest-wins).
        with app.lock:
            app._status_epoch += 1
        app._publish_status(tray.RouterStatus(up=True),
                            app._status_epoch)
        app.quit_flag.set()  # end the loop after this in-flight iteration
        gate.set()  # release the stale fetch; its publish lands LAST

        poller.join(5)
        self.assertTrue(
            app.latest.up,
            "stale poll overwrote the post-action snapshot")

    @staticmethod
    def _guarded_poll(app):
        def run():
            try:
                app.poll_loop()
            except Exception:
                pass
        return run

    def test_signature_changes_when_preset_or_profile_lists_change(self):
        # These fields are rendered by build_menu but were unsigned before
        # issue #60: preset changes and provider profile lists went stale.
        base = tray.RouterStatus()
        app = self._make_app()

        with_preset = tray.RouterStatus(preset="school-warp")
        self.assertNotEqual(app._status_signature(base),
                            app._status_signature(with_preset))

        no_profiles = tray.RouterStatus()
        info = dict(no_profiles.providers)
        info["proton"] = {"active": None,
                          "profiles": ["01-NL"], "egress": {}}
        with_profiles = tray.RouterStatus(providers=info)
        self.assertNotEqual(app._status_signature(no_profiles),
                            app._status_signature(with_profiles))

        plain = tray.RouterStatus()
        marked = dict(plain.providers)
        marked["proton"] = {"active": None, "profiles": [],
                            "egress": {"nl": {"ok": False, "error": None,
                                              "latency_ms": None,
                                              "status": None,
                                              "upstream_error": None,
                                              "blocked": True}}}
        self.assertNotEqual(
            app._status_signature(plain),
            app._status_signature(tray.RouterStatus(providers=marked)))

    def test_publish_status_without_epoch_always_installs(self):
        # Error snapshots from poll failures carry no epoch; they install
        # unconditionally so a broken CLI still surfaces in the menu.
        app = self._make_app()
        app._publish_status(tray.RouterStatus(up=True), 3)
        err = tray.RouterStatus(error="status exit 7")
        app._publish_status(err, None)
        self.assertEqual(app.latest.error, "status exit 7")

    def test_menu_controls_disabled_while_mutation_active(self):
        release = threading.Event()

        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus()

        app = tray.TrayApp(RootedClient(), None)

        def job():
            release.wait(2)
            return 0, "ok"

        app.latest = tray.RouterStatus(up=True, providers={
            "proton": {"active": "nl", "profiles": ["nl"], "egress": {}}})
        app._mutation_active = True
        menu = app.build_menu()
        labels = {item.text: item.enabled for item in menu}
        connect = next(v for k, v in labels.items() if k in ("Connect", "Reconnect"))
        disconnect = next(v for k, v in labels.items() if k == "Disconnect")
        rotate = next(v for k, v in labels.items() if k == "Switch VPN server")
        quit_item = next(v for k, v in labels.items() if k == "Quit")
        self.assertFalse(connect)
        self.assertFalse(disconnect)
        self.assertFalse(rotate)
        self.assertTrue(quit_item, "Quit must stay clickable")
        release.set()


class QuitActionTests(unittest.TestCase):
    """Quit must stop the engine BEFORE leaving the tray (issue #52):
    a quitting tray that leaves the proxy-router engine running strands
    the user with a live tunnel they can no longer control."""

    def _make_app(self, client, drain_ok=None):
        app = tray.TrayApp(client, None)
        if drain_ok is not None:
            # Shrink the quit drain window so a stuck mutation cannot slow
            # the suite; production uses MUTATION_DRAIN_TIMEOUT.
            app._drain_timeout = drain_ok
        return app

    def test_quit_stops_engine_then_tray(self):
        calls = []
        tray_stopped = threading.Event()

        class FakeClient:
            def stop(self):
                calls.append("engine")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                calls.append("tray")
                tray_stopped.set()

        app = self._make_app(FakeClient(), 2)
        app.tray = FakeTray()
        app.action_quit()
        self.assertTrue(tray_stopped.wait(2))
        self.assertEqual(calls, ["engine", "tray"])
        self.assertTrue(app.quit_flag.is_set())

    def test_quit_keeps_tray_resident_when_engine_stop_fails(self):
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def stop(self):
                return 1, "engine not running"

        class FakeTray:
            def stop(self):
                tray_stopped.set()

        app = self._make_app(FakeClient(), 2)
        app.tray = FakeTray()
        app.action_quit()
        deadline = time.time() + 2
        while app._quit_pending and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(tray_stopped.is_set(), "failed Stop must not close the tray")
        self.assertFalse(app.quit_flag.is_set(), "failed Quit must reconcile quit state")
        self.assertIn("failed", app.last_action_result or "")

    def test_failed_quit_allows_a_later_disconnect_retry(self):
        calls = []
        results = iter([(1, "engine busy"), (0, "stopped")])
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def stop(self):
                calls.append("stop")
                return next(results)

            def status(self):
                return tray.RouterStatus(up=True)

        class FakeTray:
            def stop(self):
                tray_stopped.set()

        app = self._make_app(FakeClient(), 2)
        app.tray = FakeTray()
        app.action_quit()
        deadline = time.time() + 2
        while app._quit_pending and time.time() < deadline:
            time.sleep(0.01)
        app.action_disconnect()
        deadline = time.time() + 2
        while len(calls) < 2 and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(calls, ["stop", "stop"])
        self.assertFalse(tray_stopped.is_set(), "Disconnect must not close the tray")

    def test_quit_drain_timeout_does_not_stop_active_mutation(self):
        mutation_started = threading.Event()
        release_mutation = threading.Event()
        stop_calls = []
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def mutate(self):
                mutation_started.set()
                release_mutation.wait(2)
                return 0, "mutation complete"

            def status(self):
                return tray.RouterStatus(up=True)

            def stop(self):
                stop_calls.append("stop")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                tray_stopped.set()

        app = self._make_app(FakeClient(), 0.05)
        app.tray = FakeTray()
        app._do(app.client.mutate, "mutate")
        self.assertTrue(mutation_started.wait(2))
        app.action_quit()

        deadline = time.time() + 2
        while app._quit_pending and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(app._quit_pending)
        self.assertEqual(stop_calls, [], "Quit must not stop under an active mutation")
        self.assertFalse(tray_stopped.is_set(), "timed-out Quit must keep the tray resident")

        release_mutation.set()
        deadline = time.time() + 2
        while not app._mutation_idle() and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(app._mutation_idle())

    def test_quit_drains_in_flight_mutation_before_engine_stop(self):
        # Issue #60: quit used to race the per-click daemon threads. The
        # engine stop must land AFTER an already-running mutation finished.
        calls = []
        mutation_running = threading.Event()
        release_mutation = threading.Event()
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def mutate(self):
                calls.append("mutate-start")
                mutation_running.set()
                release_mutation.wait(2)
                calls.append("mutate-done")
                return 0, "ok"

            def status(self):
                return tray.RouterStatus(up=False)

            def stop(self):
                calls.append("engine-stop")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                calls.append("tray")
                tray_stopped.set()

        app = self._make_app(FakeClient(), 5)
        app.tray = FakeTray()
        app._do(app.client.mutate, "mutate")
        self.assertTrue(mutation_running.wait(2))
        app.action_quit()
        # Give quit's worker a beat to observe the in-flight mutation, then
        # let the mutation finish. Engine stop must come after "mutate-done"
        # and the tray must leave after the engine stopped.
        time.sleep(0.1)
        release_mutation.set()
        self.assertTrue(tray_stopped.wait(3))
        self.assertLess(calls.index("mutate-done"), calls.index("engine-stop"))
        self.assertLess(calls.index("engine-stop"), calls.index("tray"))

    def test_click_racing_quit_does_not_run_after_quit_completes(self):
        # Issue #52 hardening: a click that lands while quit is draining must
        # not resurrect the engine after quit finished stopping it. _do()
        # refuses new work once quit_flag is set, so a late Connect can only
        # queue if it won the race BEFORE quit set the flag; either way, no
        # mutation may execute after engine-stop/tray teardown.
        calls = []
        tray_stopped = threading.Event()
        release_mutation = threading.Event()

        class FakeClient:
            root = "/tmp"

            def mutate(self):
                calls.append("mutate-start")
                release_mutation.wait(2)
                calls.append("mutate-done")
                return 0, "ok"

            def status(self):
                return tray.RouterStatus(up=False)

            def stop(self):
                calls.append("engine-stop")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                calls.append("tray")
                tray_stopped.set()

        app = self._make_app(FakeClient(), 5)
        app.tray = FakeTray()
        app.action_quit()          # drain window opens
        self.assertTrue(app.quit_flag.is_set())
        app._do(app.client.mutate, "late connect")   # click during quit: refused
        # Give any (wrongly) queued job a beat to run on the pump.
        time.sleep(0.2)
        release_mutation.set()
        self.assertTrue(tray_stopped.wait(3))
        self.assertNotIn("mutate-start", calls)
        self.assertEqual(calls.index("engine-stop"), len(calls) - 1 - calls.count("tray"))
        self.assertLess(calls.index("engine-stop"), calls.index("tray"))

    def test_quit_after_mutation_finished_does_not_wait(self):
        # Once the pump is idle, quit stops the engine without any drain wait
        # (the idle condition is already true).
        calls = []
        tray_stopped = threading.Event()

        class FakeClient:
            root = "/tmp"

            def mutate(self):
                calls.append("mutate")
                return 0, "ok"

            def status(self):
                return tray.RouterStatus()

            def stop(self):
                calls.append("engine-stop")
                return 0, "stopped"

        class FakeTray:
            def stop(self):
                tray_stopped.set()

        app = self._make_app(FakeClient(), 5)
        app.tray = FakeTray()
        app._do(app.client.mutate, "mutate")
        deadline = time.time() + 2
        while not app._mutation_idle() and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(app._mutation_idle())
        app.action_quit()
        self.assertTrue(tray_stopped.wait(3))
        # mutate ran on the pump before quit; engine stop came after it.
        self.assertIn("mutate", calls)
        self.assertLess(calls.index("mutate"),
                        calls.index("engine-stop"))


class PermissionErrorMappingTests(unittest.TestCase):
    """Issue #76: the autostarted tray must turn permission jargon into a
    one-time fix instead of an unexplained 'Connect: failed'."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = tray.RouterClient(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _probe(self, returncode, stdout="", stderr=""):
        return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()

    def test_router_permission_message_maps_to_one_time_fix(self):
        out = tray._humanize(
            "router: VPN startup permission missing (sudo grant denied during "
            "'start'): run `router.py elevate install` once in a terminal "
            "(admin password), then Connect again")
        self.assertIn("permission", out.lower())
        self.assertIn("elevate install", out)

    def test_router_not_set_up_message_maps_to_fix(self):
        out = tray._humanize(
            "router: startup permission not set up yet: the automatic (launchd) "
            "app cannot control the VPN engine without it; run "
            "`router.py elevate install` once in a terminal (admin password), "
            "then Connect again")
        self.assertIn("Fix Startup Permissions", out)

    def test_raw_sudo_password_denial_maps_to_fix(self):
        out = tray._humanize(
            "privileged helper start failed: sudo: a password is required")
        self.assertIn("elevate install", out)
        self.assertNotIn("a password is required", out)

    def test_sudoers_denial_maps_to_fix(self):
        out = tray._humanize(
            "privileged helper stop failed: kyson is not in the sudoers file. "
            "This incident has been reported.")
        self.assertIn("elevate install", out)

    def test_is_permission_error_matches_all_markers(self):
        self.assertTrue(tray._is_permission_error(
            "connect: failed — router: VPN startup permission missing"))
        self.assertTrue(tray._is_permission_error(
            "connect: failed — startup permission not set up yet"))
        self.assertTrue(tray._is_permission_error(
            "switch server: failed — sudo: a password is required"))
        self.assertTrue(tray._is_permission_error(
            "stop: failed — alice is not in the sudoers file"))
        self.assertFalse(tray._is_permission_error(None))
        self.assertFalse(tray._is_permission_error(
            "connect: done"))
        self.assertFalse(tray._is_permission_error(
            "connect: failed — sing-box not found"))

    def test_menu_offers_repair_after_permission_failure(self):
        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus(up=True, providers={
                    "proton": {"active": "nl", "profiles": ["nl"], "egress": {}}})

        app = tray.TrayApp(RootedClient(), None)
        app.last_action_result = (
            "connect: failed — router: VPN startup permission missing "
            "(sudo grant denied during 'start')")
        labels = [item.text for item in app.build_menu()]
        self.assertTrue(
            any("Fix Startup Permissions" in label for label in labels),
            f"repair entry missing from menu: {labels}")

    def test_menu_has_no_repair_entry_on_normal_failure(self):
        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus(up=True, providers={
                    "proton": {"active": "nl", "profiles": ["nl"], "egress": {}}})

        app = tray.TrayApp(RootedClient(), None)
        app.last_action_result = "connect: failed — sing-box not found"
        labels = [item.text for item in app.build_menu()]
        self.assertFalse(any("Fix Startup Permissions" in label for label in labels))

    def test_setup_submenu_always_offers_the_repair(self):
        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus()

        app = tray.TrayApp(RootedClient(), None)

        def collect(menu):
            texts = []
            for item in menu:
                if item.__class__.__name__ != "MenuItem":
                    continue
                try:
                    submenu = item.submenu
                except Exception:
                    submenu = None
                texts.append(item.text)
            return texts

        # Walk the built tree via pystray's descriptors on the Setup item.
        setup_item = next(item for item in app.build_menu()
                          if getattr(item, "text", "") == "Setup")
        entries = []

        def walk(m):
            for sub in m:
                entries.append(sub.text)
                inner = getattr(sub, "submenu", None) or getattr(sub, "_Menu__menu", None)
                if inner is not None and not callable(inner):
                    walk(inner)

        walk(setup_item.submenu if hasattr(setup_item, "submenu") else setup_item[0])
        self.assertTrue(any("Fix Startup Permissions" in e for e in entries),
                        f"Setup submenu lacks repair entry: {entries}")

    def test_fix_permissions_action_launches_terminal_and_reports(self):
        app = tray.TrayApp(self.client, None)
        with mock.patch.object(tray, "_launch_terminal",
                               return_value=True) as launch:
            app.action_fix_permissions()
        launch.assert_called_once()
        args = launch.call_args
        self.assertEqual(args.args[0], Path(self.tmp.name))
        self.assertEqual(args.args[1], ["elevate", "install"])
        self.assertEqual(app.last_action_result,
                         "permission repair: follow the Terminal window")

    def test_fix_permissions_action_reports_missing_terminal(self):
        app = tray.TrayApp(self.client, None)
        with mock.patch.object(tray, "_launch_terminal", return_value=False):
            app.action_fix_permissions()
        self.assertEqual(app.last_action_result,
                         "permission repair: no terminal available")

    @unittest.skipUnless(sys.platform == "darwin", "macOS Terminal path")
    def test_fix_permissions_terminal_command_carries_elevate_install(self):
        (Path(self.tmp.name) / "setup_tui.py").write_text("# tui")
        calls = []
        with mock.patch.object(tray.subprocess, "Popen",
                               side_effect=lambda argv, **kw: calls.append(argv)):
            opened = tray._launch_terminal(Path(self.tmp.name), ["elevate", "install"])
        self.assertTrue(opened)
        joined = " ".join(calls[0])
        self.assertIn("elevate install", joined)
        self.assertIn("setup_tui.py", joined)

    def test_elevate_runs_router_cli_not_sudo_or_osascript(self):
        with mock.patch.object(self.client, "_run", return_value=(0, "ok")) as run, \
             mock.patch.object(tray.subprocess, "run") as subprocess_run:
            rc, _out = self.client.elevate()
        self.assertEqual(rc, 0)
        run.assert_called_once_with("elevate", "install")
        subprocess_run.assert_not_called()


class DashboardOpenerTests(unittest.TestCase):
    """Tray one-click: open the full TUI in a terminal window."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "setup_tui.py").write_text("# tui")

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_tui_fails_quietly(self):
        (self.root / "setup_tui.py").unlink()
        self.assertFalse(tray.open_dashboard(self.root))

    @unittest.skipUnless(sys.platform == "darwin", "macOS Terminal path")
    def test_macos_opens_terminal_with_tui(self):
        calls = []
        def fake_popen(argv, **kwargs):
            calls.append(argv)
            return mock.Mock()
        with mock.patch.object(tray.subprocess, "Popen", side_effect=fake_popen):
            self.assertTrue(tray.open_dashboard(self.root))
        self.assertEqual(calls[0][0], "osascript")
        self.assertIn("setup_tui.py", " ".join(calls[0]))

    def test_macos_terminal_failure_fails_quietly(self):
        with mock.patch.object(tray.sys, "platform", "darwin"), \
             mock.patch.object(tray.subprocess, "Popen",
                               side_effect=OSError("no Terminal")):
            self.assertFalse(tray.open_dashboard(self.root))


class DashboardActionTests(unittest.TestCase):
    """The tray callback owns root forwarding and visible outcome state."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.app = tray.TrayApp(tray.RouterClient(str(self.root)), None)

    def tearDown(self):
        self._tmp.cleanup()

    def test_callback_passes_client_root_and_records_success(self):
        roots = []
        with mock.patch.object(
            tray, "open_dashboard", side_effect=lambda root: roots.append(root) or True
        ):
            self.app.action_dashboard()
        self.assertEqual(roots, [str(self.root)])
        self.assertEqual(self.app.last_action_result, "dashboard opened")

    def test_callback_records_visible_failure_without_raising(self):
        with mock.patch.object(tray, "open_dashboard", return_value=False):
            self.app.action_dashboard()
        self.assertEqual(self.app.last_action_result, "dashboard: no terminal")

    def test_callback_rebuilds_attached_tray_menu(self):
        sentinel = object()
        self.app.tray = SimpleNamespace(menu=None)
        self.app._menu_sig = "old"
        with mock.patch.object(tray, "open_dashboard", return_value=True), \
             mock.patch.object(self.app, "build_menu", return_value=sentinel) as build:
            self.app.action_dashboard()
        self.assertIsNone(self.app._menu_sig)
        self.assertIs(self.app.tray.menu, sentinel)
        build.assert_called_once_with()


class PrivilegedHelperTrayTests(unittest.TestCase):
    def test_root_action_uses_normal_controller_and_never_sudo_or_osascript(self):
        client = tray.RouterClient("/tmp/proxy-router")
        with mock.patch.object(client, "_run", return_value=(0, "ok")) as run, \
             mock.patch.object(tray.subprocess, "run") as subprocess_run:
            result = client._run_elevated("vpn", "on")

        self.assertEqual(result, (0, "ok"))
        run.assert_called_once_with("vpn", "on")
        subprocess_run.assert_not_called()


class PresetApplyReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.client = tray.RouterClient(self.tmp.name)

    def test_reload_runs_router_reload_subcommand(self):
        with mock.patch.object(self.client, "_run", return_value=(0, "ok")) as run:
            rc, out = self.client.reload()
        self.assertEqual(rc, 0)
        run.assert_called_once_with("reload")

    def test_apply_preset_failure_skips_reload(self):
        # Drive the same closure action_apply_preset builds, without the
        # TrayApp worker machinery (locks/menu) that needs a full app.
        app = mock.Mock()
        app.client = self.client
        captured = {}
        def fake_do(fn, label):
            captured["rc"] = fn()
            captured["label"] = label
        with mock.patch.object(self.client, "_run",
                               side_effect=[(1, "boom"), (0, "reloaded")]) as run:
            bound = tray.TrayApp.action_apply_preset.__get__(app)
            real_do = tray.TrayApp._do.__get__(app)
            # replace _do on the instance for this call
            app._do = fake_do
            bound("school-warp")
        run.assert_called_once_with("setup", "--preset", "school-warp")
        self.assertEqual(captured["rc"], (1, "boom"))


class PresetMenuCallbackTests(unittest.TestCase):
    def test_preset_activation_keeps_captured_name_instead_of_icon(self):
        calls = []

        class FakeClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus(
                    up=True,
                    providers={"proton": {"active": "nl", "profiles": ["nl"], "egress": {}}},
                    preset="school-warp",
                )

            def setup_preset(self, name):
                calls.append(("setup", name))
                return 0, "preset applied"

            def reload(self):
                calls.append(("reload",))
                return 0, "reloaded"

        app = tray.TrayApp(FakeClient(), None)
        captured = {}

        def fake_do(fn, label):
            captured["label"] = label
            captured["result"] = fn()

        app._do = fake_do
        menu = app.build_menu()
        presets = next(item for item in menu if item.text == "Presets").submenu
        preset = next(item for item in presets if "school-warp" in item.text)
        preset(object())
        self.assertEqual(captured["label"], "preset school-warp")
        self.assertEqual(calls, [("setup", "school-warp"), ("reload",)])


class DashboardViewModelTests(unittest.TestCase):
    def test_disconnected_model_binds_primary_connect_and_route_health(self):
        status = tray.RouterStatus(
            up=False,
            routing_mode="safe-list",
            providers={
                "proton": {
                    "active": "01-NL",
                    "profiles": ["01-NL"],
                    "egress": {"01-NL": {"ok": True, "latency_ms": 42}},
                }
            },
        )
        model = tray.DashboardViewModel.from_status(status)
        self.assertEqual(model.title, "Disconnected")
        self.assertEqual(model.primary_action, "connect")
        self.assertEqual(model.primary_label, "Connect")
        self.assertEqual(model.mode_label, "Home")
        self.assertEqual(model.provider_summary, "Proton")
        self.assertEqual(model.route_health, "Healthy")
        self.assertEqual(model.port_label, "Not running")

    def test_connected_model_binds_disconnect_and_route_details(self):
        status = tray.RouterStatus(
            up=True,
            mode="proxy",
            port=2080,
            watcher=True,
            routing_mode="vpn-list",
            providers={
                "proton": {
                    "active": "01-NL",
                    "profiles": ["01-NL"],
                    "egress": {"01-NL": {"ok": True, "latency_ms": 18}},
                }
            },
        )
        model = tray.DashboardViewModel.from_status(status)
        self.assertEqual(model.title, "Connected")
        self.assertEqual(model.primary_action, "disconnect")
        self.assertEqual(model.mode_label, "School")
        self.assertEqual(model.port_label, "Proxy :2080")
        self.assertEqual(model.watcher_label, "Route watcher active")
        self.assertEqual(model.route_health, "Healthy")

    def test_error_model_renders_actionable_error_without_crashing(self):
        model = tray.DashboardViewModel.from_status(
            tray.RouterStatus(error="status exit 7"))
        self.assertEqual(model.title, "Router unavailable")
        self.assertIn("status exit 7", model.error)
        self.assertEqual(model.route_health, "Unavailable")

    def test_none_provider_entry_is_treated_as_unconfigured(self):
        model = tray.DashboardViewModel.from_status(
            tray.RouterStatus(providers={"proton": None}))
        self.assertEqual(model.provider_rows, ("Proton   no active server",))
        self.assertEqual(model.route_health, "Waiting")

    def test_none_egress_record_is_treated_as_waiting(self):
        model = tray.DashboardViewModel.from_status(
            tray.RouterStatus(providers={
                "proton": {"active": "01-NL", "egress": {"01-NL": None}},
            }))
        self.assertEqual(model.route_health, "Waiting")


class DashboardLifecycleTests(unittest.TestCase):
    class FakeWindow:
        def __init__(self):
            self.statuses = []
            self.actions = []
            self.shown = 0
            self.closed = 0

        def update_status(self, status):
            self.statuses.append(status)

        def update_action(self, action):
            self.actions.append(action)

        def show(self):
            self.shown += 1

        def close(self):
            self.closed += 1

    def test_show_reuses_and_focuses_one_window_then_closes_it(self):
        windows = []

        def factory(*_args):
            window = self.FakeWindow()
            windows.append(window)
            return window

        controller = tray.DashboardController(
            object(), object(), window_factory=factory)
        first = tray.RouterStatus(up=False)
        second = tray.RouterStatus(up=True)
        self.assertTrue(controller.show(first))
        self.assertTrue(controller.show(second))
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].shown, 2)
        self.assertEqual(windows[0].statuses, [first, second])
        controller.update_action("connect: working")
        self.assertEqual(windows[0].actions[-1], "connect: working")
        controller.close()
        self.assertEqual(windows[0].closed, 1)

    def test_missing_cocoa_factory_fails_closed(self):
        controller = tray.DashboardController(
            object(), object(), window_factory=lambda *_args: None)
        self.assertFalse(controller.show(tray.RouterStatus()))
        self.assertIsNone(controller.window)


class DashboardClickRoutingTests(unittest.TestCase):
    def test_left_click_opens_dashboard_and_right_click_opens_existing_menu(self):
        calls = []
        token = object()
        self.assertIsNone(tray._route_macos_click(
            "left", lambda: calls.append("dashboard"),
            lambda: calls.append("menu")))
        self.assertIsNone(tray._route_macos_click(
            "right", lambda: calls.append("dashboard"),
            lambda: calls.append("menu")))
        self.assertEqual(calls, ["dashboard", "menu"])
        self.assertIs(tray._route_macos_click(
            "other", lambda: None, lambda: None, event=token), token)

    def test_menu_creation_keeps_existing_right_click_actions(self):
        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus()

        app = tray.TrayApp(RootedClient(), None)
        labels = [item.text for item in app.build_menu()]
        for expected in ("Open Setup in Terminal", "Connect", "Disconnect",
                         "Routing mode", "Setup", "Presets", "Quit"):
            self.assertIn(expected, labels)


class DarwinStatusButtonTests(unittest.TestCase):
    """Verify the private pystray-Darwin adapter without opening a window."""

    class Event:
        def __init__(self, event_type, modifier_flags=0):
            self._event_type = event_type
            self._modifier_flags = modifier_flags

        def type(self):
            return self._event_type

        def modifierFlags(self):
            return self._modifier_flags

    def test_native_button_routes_left_to_dashboard_and_right_to_menu(self):
        if not tray._COCOA_AVAILABLE:
            self.skipTest("Cocoa unavailable")
        icon = object.__new__(tray._DarwinDashboardIcon)
        icon._visible = False
        icon._dashboard_callback = mock.Mock()
        icon._show_native_menu = mock.Mock()
        left = self.Event(tray.AppKit.NSLeftMouseUp)
        right = self.Event(tray.AppKit.NSRightMouseUp)

        icon._route_status_button_event(left)
        icon._route_status_button_event(right)

        icon._dashboard_callback.assert_called_once_with()
        icon._show_native_menu.assert_called_once_with(right)

    def test_control_click_opens_existing_menu(self):
        if not tray._COCOA_AVAILABLE:
            self.skipTest("Cocoa unavailable")
        control_mask = getattr(
            tray.AppKit, "NSEventModifierFlagControl",
            getattr(tray.AppKit, "NSControlKeyMask", 0),
        )
        if not control_mask:
            self.skipTest("Cocoa control modifier unavailable")
        event = self.Event(tray.AppKit.NSLeftMouseUp, control_mask)
        self.assertTrue(tray._is_right_click_event(event))

    def test_native_menu_rebuild_keeps_status_item_menu_unset(self):
        if not tray._COCOA_AVAILABLE:
            self.skipTest("Cocoa unavailable")
        icon = object.__new__(tray._DarwinDashboardIcon)
        icon._visible = False
        icon._menu_handle = None
        icon._native_menu = None
        icon._menu = object()
        icon._dashboard_delegate = object()
        button = SimpleNamespace(
            setTarget_=mock.Mock(),
            setAction_=mock.Mock(),
            sendActionOn_=mock.Mock(),
        )
        icon._status_item = SimpleNamespace(
            button=lambda: button, setMenu_=mock.Mock())
        native_menu = object()
        icon._create_menu = mock.Mock(return_value=native_menu)

        icon._update_menu()

        self.assertIs(icon._menu_handle[0], native_menu)
        self.assertEqual(icon._status_item.setMenu_.call_count, 2)
        icon._status_item.setMenu_.assert_called_with(None)


class DashboardTrayIntegrationTests(unittest.TestCase):
    def test_left_click_entry_uses_native_callback_but_menu_entry_stays_legacy(self):
        class RootedClient:
            root = "/tmp"

            def status(self):
                return tray.RouterStatus()

        app = tray.TrayApp(RootedClient(), None)
        app.dashboard = mock.Mock()
        with mock.patch.object(tray, "open_dashboard", return_value=True) as legacy:
            app.action_dashboard()
        legacy.assert_called_once_with("/tmp")

        app.dashboard.show.reset_mock()
        app._show_native_dashboard()
        app.dashboard.show.assert_called_once_with(app.latest)

    def test_dashboard_action_dispatch_reuses_existing_tray_methods(self):
        app = object.__new__(tray.TrayApp)
        app.action_connect = mock.Mock()
        app.action_disconnect = mock.Mock()
        app.action_rotate = mock.Mock()
        app.action_mode = mock.Mock()
        app.action_setup = mock.Mock()

        app._dispatch_dashboard_action("connect")
        app._dispatch_dashboard_action("disconnect")
        app._dispatch_dashboard_action("rotate")
        app._dispatch_dashboard_action("mode", "safe-list")
        app._dispatch_dashboard_action("setup")
        app._dispatch_dashboard_action("mode", "not-a-mode")

        app.action_connect.assert_called_once_with()
        app.action_disconnect.assert_called_once_with()
        app.action_rotate.assert_called_once_with()
        app.action_mode.assert_called_once_with("safe-list")
        app.action_setup.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

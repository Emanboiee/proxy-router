"""Proof that server switching works via selected config + real routed egress (#54)."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import router
from tests.test_router import _relocate

def _write_distinct_conf(path: Path, private_key: str, endpoint: str):
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        "Address = 10.2.0.2/32",
        "DNS = 1.1.1.1",
        "",
        "[Peer]",
        f"PublicKey = pub-{private_key[:8]}",
        f"Endpoint = {endpoint}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
    ]
    path.write_text("\n".join(lines) + "\n")

def _endpoint_private_keys(config: dict) -> dict:
    return {e["tag"]: e["private_key"] for e in config.get("endpoints", []) if e.get("type") == "wireguard"}

class SwitchProvenTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _relocate(router, self.root)
        (self.root / "providers" / "proton").mkdir(parents=True)
        _write_distinct_conf(self.root / "providers" / "proton" / "a.conf",
                             "aaaa0000111122223333444455556666bbbbccccddddeeeeffff00001111",
                             "1.1.1.1:51820")
        _write_distinct_conf(self.root / "providers" / "proton" / "b.conf",
                             "bbbb0000111122223333444455556666ccccddddeeeeffff00002222",
                             "2.2.2.2:51820")
        _write_distinct_conf(self.root / "providers" / "proton" / "c.conf",
                             "cccc0000111122223333444455556666ddddeeeeffff00003333aaaa",
                             "3.3.3.3:51820")
        self.root.joinpath("router.json").write_text(json.dumps({
            "port": 28191,
            "providers": {"proton": {"directory": "providers/proton", "cooldown_seconds": 60}},
            "routes": [{"id": "test", "domains": ["example.com"], "provider": "proton"}],
            "vpn": {"address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system"},
        }))
        router.load_config()
        router._egress_settings = {**router.DEFAULT_EGRESS_SETTINGS, "probe_settle_seconds": 0}
        self.p_listener = mock.patch.object(router, "listener_up", return_value=True)
        self.mock_listener = self.p_listener.start()
        self.p_alive = mock.patch.object(router, "engine_alive", return_value=True)
        self.p_alive.start()
        self.p_wait = mock.patch.object(router, "wait_engine", return_value=True)
        self.p_wait.start()
        self.p_probe = mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True}))
        self.mock_probe = self.p_probe.start()
        self.p_validate = mock.patch.object(router, "validate_config", return_value=True)
        self.p_validate.start()
        self.p_start = mock.patch.object(router, "engine_start", return_value=0)
        self.p_start.start()
        self.p_stop = mock.patch.object(router, "engine_stop", return_value=0)
        self.p_stop.start()
        self.p_matches = mock.patch.object(router, "_pid_matches", return_value=True)
        self.p_matches.start()
        (self.root / "sing-box.pid").write_text("12345")
        router.set_active("proton", self.root / "providers" / "proton" / "a.conf")
        cfg, _ = router.build_singbox_config()
        router.write_sing_box(cfg)
        router.write_last_good()

    def tearDown(self):
        self.p_matches.stop()
        self.p_stop.stop()
        self.p_start.stop()
        self.p_validate.stop()
        self.p_probe.stop()
        self.p_wait.stop()
        self.p_alive.stop()
        self.p_listener.stop()
        router._egress_settings = {}
        self._tmp.cleanup()

    def _sighup_patches(self):
        return [mock.patch.object(os, "kill", return_value=None),
                mock.patch.object(os, "geteuid", return_value=1000)]

    def test_rotate_to_switches_config_and_marker_and_status(self):
        self.assertEqual((self.root / "state" / "proton.active").read_text(), "a")
        cfg_before = json.loads((self.root / "sing-box.json").read_text())
        self.assertEqual(_endpoint_private_keys(cfg_before)["proton"],
                         "aaaa0000111122223333444455556666bbbbccccddddeeeeffff00001111")
        patches = self._sighup_patches()
        for p in patches: p.start()
        try:
            rc = router.rotate("proton", to="b")
        finally:
            for p in patches: p.stop()
        self.assertEqual(rc, 0)
        cfg_after = json.loads((self.root / "sing-box.json").read_text())
        self.assertEqual(_endpoint_private_keys(cfg_after)["proton"],
                         "bbbb0000111122223333444455556666ccccddddeeeeffff00002222")
        self.assertEqual((self.root / "state" / "proton.active").read_text(), "b")
        data = router.status_json()
        self.assertEqual(data["providers"]["proton"]["active"], "b")
        self.mock_probe.assert_called()

    def test_rotate_to_proves_real_routed_egress_not_just_marker(self):
        patches = self._sighup_patches()
        for p in patches: p.start()
        # Make _probe_with_settle fail (not just probe_profile, to avoid settle retry)
        with mock.patch.object(router, "_probe_with_settle", return_value=(False, {"ok": False, "error": "connection timeout"})):
            rc = router.rotate("proton", to="b")
        for p in patches: p.stop()
        self.assertEqual(rc, 1)
        self.assertEqual((self.root / "state" / "proton.active").read_text(), "a")
        cfg = json.loads((self.root / "sing-box.json").read_text())
        self.assertEqual(_endpoint_private_keys(cfg)["proton"],
                         "aaaa0000111122223333444455556666bbbbccccddddeeeeffff00001111")

    def test_sweep_leaves_best_alive_and_is_tun_aware(self):
        router.record_egress("proton", self.root / "providers" / "proton" / "a.conf", ok=True, latency_ms=200)
        router.record_egress("proton", self.root / "providers" / "proton" / "b.conf", ok=True, latency_ms=30)
        router.record_egress("proton", self.root / "providers" / "proton" / "c.conf", ok=True, latency_ms=150)
        with mock.patch.object(router, "_probe_with_settle", return_value=(True, {"ok": True, "latency_ms": 10})):
            patches = self._sighup_patches()
            for p in patches: p.start()
            try:
                rc = router.egress_sweep("proton")
            finally:
                for p in patches: p.stop()
        self.assertEqual(rc, 0)
        active = (self.root / "state" / "proton.active").read_text()
        self.assertIn(active, ["a", "b", "c"])
        cfg = json.loads((self.root / "sing-box.json").read_text())
        self.assertIn(cfg["endpoints"][0]["private_key"],
                      ["aaaa0000111122223333444455556666bbbbccccddddeeeeffff00001111",
                       "bbbb0000111122223333444455556666ccccddddeeeeffff00002222",
                       "cccc0000111122223333444455556666ddddeeeeffff00003333aaaa"])

    def test_sweep_tun_requires_allow_flag(self):
        router.set_mode("tun")
        cfg, _ = router.build_singbox_config()
        router.write_sing_box(cfg)
        rc = router.egress_sweep("proton", allow_tun=False)
        self.assertNotEqual(rc, 0)
        patches = self._sighup_patches()
        for p in patches: p.start()
        try:
            rc2 = router.egress_sweep("proton", allow_tun=True)
        finally:
            for p in patches: p.stop()
        self.assertEqual(rc2, 0)

    def test_rotate_tun_mode_still_probes_via_mixed_listener(self):
        router.set_mode("tun")
        cfg, _ = router.build_singbox_config()
        router.write_sing_box(cfg)
        with mock.patch.object(router, "listener_up", return_value=False), \
             mock.patch.object(router, "probe_profile", side_effect=AssertionError("must not probe")):
            patches = self._sighup_patches()
            for p in patches: p.start()
            try:
                rc = router.rotate("proton", to="b")
            finally:
                for p in patches: p.stop()
            self.assertEqual(rc, 0)
        with mock.patch.object(router, "listener_up", return_value=True), \
             mock.patch.object(router, "probe_profile", return_value=(True, {"ok": True})) as probe2:
            patches = self._sighup_patches()
            for p in patches: p.start()
            try:
                rc = router.rotate("proton", to="c")
            finally:
                for p in patches: p.stop()
            self.assertEqual(rc, 0)
            probe2.assert_called_once()

    def test_last_good_snapshot_after_restart_fallback(self):
        (self.root / "sing-box.pid").unlink(missing_ok=True)
        self.p_start.return_value = 0
        patches = self._sighup_patches()
        for p in patches: p.start()
        try:
            rc = router.engine_reload({"proton": self.root / "providers" / "proton" / "b.conf"})
        finally:
            for p in patches: p.stop()
        self.assertEqual(rc, 0)
        last = json.loads((self.root / "sing-box.json.last-good").read_text())
        self.assertEqual([e["private_key"] for e in last["endpoints"] if e["tag"] == "proton"][0],
                         "bbbb0000111122223333444455556666ccccddddeeeeffff00002222")

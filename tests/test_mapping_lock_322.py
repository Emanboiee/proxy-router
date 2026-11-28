"""#322: concurrent network mapping applies share one writer."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import dashboard_profile_manager as manager
import network_control as net
from tests.test_network_control import profile_fixture


def test_parallel_mapping_applies_do_not_overlap(tmp_path):
    router, _identifier = profile_fixture(tmp_path)
    real_apply = manager.apply_profile
    guard = threading.Lock()
    stats = {"active": 0, "peak": 0}

    def slow_apply(root, profile_id):
        with guard:
            stats["active"] += 1
            stats["peak"] = max(stats["peak"], stats["active"])
        deadline = time.monotonic() + 0.3
        while stats["active"] < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        try:
            return real_apply(root, profile_id)
        finally:
            with guard:
                stats["active"] -= 1

    with mock.patch.object(manager, "apply_profile", slow_apply):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda _worker: net.apply_mapping(router, tmp_path), range(2)
            ))

    assert stats["peak"] == 1
    assert sorted(result["applied"] for result in results) == [False, True]
    assert "already active" in [result.get("reason") for result in results]
    assert net.read_json(tmp_path / "router.json")["routes"]

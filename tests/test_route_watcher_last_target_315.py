"""#315: route_watcher's ``last_target`` must not accumulate stale hosts forever.

The dict is keyed by host and only ever grew: hosts seen under an earlier router
config stayed in memory after their domain was removed.  These tests pin the
invariant that entries are pruned back to the currently configured (active)
domain set, without evicting hosts that are still routed.
"""
import unittest

import route_watcher as w


class LastTargetEvictionTests(unittest.TestCase):
    def test_stale_targets_evicted_when_active_set_rotates(self):
        # Feed N targets under an old config, then rotate the active set away.
        last_target = {f"stale{i}.gone.example": 100.0 + i for i in range(64)}
        w._prune_last_targets(last_target, ("now-active.example",))
        self.assertEqual(last_target, {}, "stale hosts must be evicted after rotation")

    def test_bounded_to_active_set_and_keeps_subdomains(self):
        last_target = {f"stale{i}.gone.example": float(i) for i in range(64)}
        last_target["now-active.example"] = 200.0
        last_target["deep.now-active.example"] = 201.0

        w._prune_last_targets(last_target, ("now-active.example",))

        self.assertEqual(
            set(last_target),
            {"now-active.example", "deep.now-active.example"},
            "only hosts matching a configured domain survive",
        )
        self.assertLessEqual(len(last_target), 8, "last_target must stay bounded")

    def test_empty_active_set_clears_every_target(self):
        last_target = {"a.example": 1.0, "b.example": 2.0}
        w._prune_last_targets(last_target, ())
        self.assertEqual(last_target, {})

    def test_cap_evicts_oldest_active_subdomains(self):
        # Active subdomains all match the configured domain, so the domain
        # prune keeps them; the hard cap must still bound the set by recency.
        hosts = {f"h{i}.now-active.example": float(i) for i in range(64)}
        w._prune_last_targets(hosts, ("now-active.example",))
        self.assertLessEqual(len(hosts), w.LAST_TARGET_CAP)
        self.assertIn("h63.now-active.example", hosts, "newest host must survive")
        self.assertNotIn("h0.now-active.example", hosts, "oldest host must be evicted")


class ProbeBudgetTests(unittest.TestCase):
    def test_probe_budget_constant_is_bounded(self):
        self.assertGreaterEqual(w.PROBES_PER_TICK, 1)
        self.assertLess(w.PROBES_PER_TICK, 32,
                        "per-tick probe budget must stay small vs the 2s loop")


if __name__ == "__main__":
    unittest.main()

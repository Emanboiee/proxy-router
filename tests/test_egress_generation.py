"""#225: egress evidence bound to a config generation. A green record from
before a config/network change must not certify health after the change.
"""
import os
import time

import egress


def test_generation_is_file_identity(tmp_path):
    cfg = tmp_path / "sing-box.json"
    cfg.write_text("{}")
    g1 = egress.config_generation(cfg)
    assert g1 and len(g1) == 3
    cfg.write_text("changed content, same size")
    g2 = egress.config_generation(cfg)
    assert g2 != g1, "a config rewrite must change its generation"


def test_generation_missing_path_is_none(tmp_path):
    assert egress.config_generation(tmp_path / "missing.json") is None


def test_legacy_record_without_generation_stays_usable():
    rec = {"ok": True, "checked_at": int(time.time())}
    # No generation stamped -> legacy record, do not invalidate it.
    assert egress.usable_evidence(rec, int(time.time()), 86400, generation=["i", 1, 2])


def test_record_from_other_generation_is_not_usable():
    rec = {"ok": True, "checked_at": int(time.time()), "generation": ["old", 1, 2]}
    assert not egress.usable_evidence(rec, int(time.time()), 86400, generation=["new", 9, 9])


def test_malformed_generation_does_not_crash_status():
    """Council nit 2: a corrupted non-iterable generation must not crash status."""
    rec = {"ok": True, "checked_at": int(time.time()), "generation": 12345}
    # Must not raise; treat as unusable (cannot prove current generation).
    assert egress.usable_evidence(rec, int(time.time()), 86400, generation=["a", 1, 2]) is False


def test_missing_generation_stamp_is_not_pinned_as_legacy():
    """Council nit 1: a record stamped with None generation (config missing at
    probe time) must not become permanently 'legacy' once config appears."""
    rec = {"ok": True, "checked_at": int(time.time()), "generation": None}
    assert egress.usable_evidence(rec, int(time.time()), 86400, generation=["a", 1, 2]) is False


def test_degraded_detail_names_generation_mismatch():
    """Council nit 3: an old-generation record should say config changed,
    not 'probe failed'."""
    rec = {"ok": True, "checked_at": int(time.time()), "generation": ["old", 1, 2]}
    detail = egress.degraded_detail(rec, int(time.time()), 86400, generation=["new", 9, 9])
    assert "generation" in detail.lower() or "config" in detail.lower(), detail


def test_config_rewrite_marks_existing_evidence_stale(tmp_path, monkeypatch):
    """#225: a WARP/network/exit transition rewrites sing-box.json; a green
    record stamped with the old generation must then read degraded."""
    from tests.test_router_regressions import load_router
    r = load_router(tmp_path)
    cfg = tmp_path / "sing-box.json"
    cfg.write_text('{"outbounds":[{"tag":"cloudflare"}]}')
    monkeypatch.setattr(r, "SING_BOX_CONFIG", cfg)
    r._providers = {"cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
    r._routes = [{"id": "school", "provider": "cloudflare"}]
    r.active_fallback = lambda name: None
    # Record a green probe under the current generation.
    r.record_egress("cloudflare", r.proxy_profile_key("cloudflare"), ok=True, status=200)
    assert r._degraded_lanes() == []
    # A network exit change rewrites the generated config.
    cfg.write_text('{"outbounds":[{"tag":"cloudflare"},{"tag":"proton"}]}')
    lanes = r._degraded_lanes()
    assert lanes, "old-generation evidence must not certify the current config"


def test_record_from_current_generation_is_usable():
    rec = {"ok": True, "checked_at": int(time.time()), "generation": ["cur", 5, 6]}
    assert egress.usable_evidence(rec, int(time.time()), 86400, generation=["cur", 5, 6])

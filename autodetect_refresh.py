"""Batch dependency discovery before considering one shared-engine reload."""
from __future__ import annotations

import json


def routing_signature(config: dict) -> dict:
    """Compare generated routing, not timestamps or private outbound keys."""
    dns = config.get("dns")
    return {"route": config.get("route"),
            "dns_rules": dns.get("rules") if isinstance(dns, dict) else None}


def refresh(router, *, reload: bool = True, quiet: bool = False) -> int:
    """Refresh every source under the caller's controller lock; reload at most once."""
    if not router._autodetect.get("enabled"):
        return 0 if quiet else router.fail("autodetection is disabled")
    sources = sorted(router._autodetect.get("sources") or {})
    if not sources:
        return 0
    failed = []
    for source in sources:
        try:
            rc = router.autodetect_source(source, reload=False, quiet=True)
        except OSError:
            # Keep a source's previous atomic state; still consider discoveries
            # already committed by the other sources in this refresh.
            rc = 1
        if rc != 0:
            failed.append(source)
    desired, _ = router.build_singbox_config()
    try:
        saved = json.loads(router.SING_BOX_CONFIG.read_text())
        if not isinstance(saved, dict):
            saved = {}
    except (OSError, ValueError):
        saved = {}
    changed = routing_signature(saved) != routing_signature(desired)
    reload_rc = 0
    reloaded = False
    if changed and reload and not router.MANUAL_OFF_FILE.exists():
        if router.engine_alive() and router._automatic_proxy_mode():
            reload_rc = router.engine_reload()
            reloaded = reload_rc == 0
    if not quiet:
        print(json.dumps({"sources": sources, "failed_sources": failed,
                          "changed": changed, "reloaded": reloaded,
                          "reload_rc": reload_rc}, sort_keys=True))
    return 1 if failed or reload_rc != 0 else 0

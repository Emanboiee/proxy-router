import json
from pathlib import Path

import domain_autodetect
import router


def test_extract_related_hosts_is_suffix_bounded():
    document = '''
      <script src="https://static-cdn.jtvnw.net/assets/app.js"></script>
      <link href="//usher.ttvnw.net/api/channel.m3u8">
      <a href="https://www.twitch.tv/">home</a>
      <img src="https://not-twitch.tv/evil.png">
    '''

    assert domain_autodetect.extract_related_hosts(
        document, ["twitch.tv", "jtvnw.net", "ttvnw.net"]
    ) == ["static-cdn.jtvnw.net", "usher.ttvnw.net", "www.twitch.tv"]


def test_merge_state_refreshes_hosts_and_prunes_expired():
    state = {
        "domains": {
            "old.example": {"first_seen": 1, "last_seen": 1, "expires_at": 10},
            "kept.example": {"first_seen": 1, "last_seen": 2, "expires_at": 100},
        }
    }

    merged, changed = domain_autodetect.merge_state(
        state, ["new.example", "kept.example"], now=20, ttl_seconds=600
    )

    assert changed is True
    assert domain_autodetect.active_domains(merged, now=20) == [
        "kept.example", "new.example"
    ]
    assert merged["domains"]["kept.example"]["expires_at"] == 620


def test_build_config_includes_non_suffix_learned_hosts(tmp_path, monkeypatch):
    old = (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
           router._vpn, router._routing, router._autodetect, router._port)
    try:
        router.ROOT = Path(tmp_path)
        router.CONFIG_FILE = router.ROOT / "router.json"
        router._providers = {
            "cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}}
        }
        router._routes = [{
            "id": "school", "domains": ["twitch.tv"], "provider": "cloudflare"
        }]
        router._vpn = {}
        router._routing = {"mode": "default", "vpn_domains": []}
        router._autodetect = {
            "enabled": True,
            "sources": {"twitch": {"route_id": "school", "provider": "cloudflare"}},
        }
        router._port = 2080
        state_path = router.ROOT / "state" / "autodetect" / "twitch.json"
        state_path.parent.mkdir(parents=True)
        state_path.write_text(json.dumps({
            "route_id": "school", "provider": "cloudflare",
            "domains": {
                "static-cdn.jtvnw.net": {
                    "first_seen": 1, "last_seen": 2, "expires_at": 9999999999
                }
            }
        }))
        monkeypatch.setattr(router, "current_mode", lambda: "proxy")

        config, _ = router.build_singbox_config()

        assert {
            "outbound": "cloudflare",
            "domain_suffix": ["twitch.tv", "static-cdn.jtvnw.net"],
        } in config["route"]["rules"]
    finally:
        (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
         router._vpn, router._routing, router._autodetect, router._port) = old

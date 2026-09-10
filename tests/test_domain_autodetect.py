import json
from pathlib import Path

import domain_autodetect
import pytest
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


def test_extract_related_hosts_accepts_explicit_cross_origin_asset_root():
    document = '''
      <script src="https://cdn.prod.example.net/app.js"></script>
      <img src="https://untrusted.example.net/image.png">
    '''

    assert domain_autodetect.extract_related_hosts(
        document, ["wayground.com"], extra_roots=["cdn.prod.example.net"]
    ) == ["cdn.prod.example.net"]


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


def test_build_config_keeps_learned_hosts_when_provider_changes(tmp_path, monkeypatch):
    old = (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
           router._vpn, router._routing, router._autodetect, router._port)
    try:
        router.ROOT = Path(tmp_path)
        router.CONFIG_FILE = router.ROOT / "router.json"
        router._providers = {
            "proton": {"socks5": {"host": "127.0.0.1", "port": 2182}}
        }
        router._routes = [{
            "id": "school", "domains": ["twitch.tv"], "provider": "proton"
        }]
        router._vpn = {}
        router._routing = {"mode": "default", "vpn_domains": []}
        router._autodetect = {
            "enabled": True,
            "sources": {"twitch": {"route_id": "school", "provider": "proton"}},
        }
        router._port = 2080
        state_path = router.ROOT / "state" / "autodetect" / "twitch.json"
        state_path.parent.mkdir(parents=True)
        state_path.write_text(json.dumps({
            "route_id": "school", "provider": "cloudflare",
            "domains": {
                "video-weaver.example.ttvnw.net": {
                    "first_seen": 1, "last_seen": 2, "expires_at": 9999999999
                }
            }
        }))
        monkeypatch.setattr(router, "current_mode", lambda: "proxy")

        config, _ = router.build_singbox_config()

        assert {
            "outbound": "proton",
            "domain_suffix": ["twitch.tv", "video-weaver.example.ttvnw.net"],
        } in config["route"]["rules"]
    finally:
        (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
         router._vpn, router._routing, router._autodetect, router._port) = old


def test_build_config_routes_configured_autodetect_roots(tmp_path, monkeypatch):
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
            "sources": {
                "twitch": {
                    "route_id": "school",
                    "provider": "cloudflare",
                    "roots": ["twitch.tv", "jtvnw.net", "ttvnw.net"],
                    "extra_roots": ["cdn.example.net"],
                }
            },
        }
        router._port = 2080
        monkeypatch.setattr(router, "current_mode", lambda: "proxy")

        config, _ = router.build_singbox_config()

        assert {
            "outbound": "cloudflare",
            "domain_suffix": ["twitch.tv", "jtvnw.net", "ttvnw.net", "cdn.example.net"],
        } in config["route"]["rules"]
    finally:
        (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
         router._vpn, router._routing, router._autodetect, router._port) = old


def test_load_autodetect_generates_sources_for_unconfigured_routes():
    settings = router._load_autodetect(
        {"autodetect": {"enabled": True}},
        [
            {"id": "school", "domains": ["twitch.tv", "ttvnw.net"], "provider": "cloudflare"},
            {"id": "roblox", "domains": ["roblox.com", "rbxcdn.com"], "provider": "proton"},
        ],
        {"cloudflare": {}, "proton": {}},
    )

    assert set(settings["sources"]) == {"route-school", "route-roblox"}
    assert settings["sources"]["route-roblox"] == {
        "seed": "https://roblox.com/",
        "route_id": "roblox",
        "provider": "proton",
        "roots": ["rbxcdn.com", "roblox.com"],
        "ttl_seconds": 1800,
    }


def test_load_autodetect_explicit_source_covers_route():
    settings = router._load_autodetect(
        {
            "autodetect": {
                "enabled": True,
                "sources": {
                    "twitch": {
                        "seed": "https://www.twitch.tv/",
                        "route_id": "school",
                        "provider": "cloudflare",
                        "roots": ["twitch.tv", "ttvnw.net"],
                    }
                },
            }
        },
        [{"id": "school", "domains": ["twitch.tv"], "provider": "cloudflare"}],
        {"cloudflare": {}},
    )

    assert set(settings["sources"]) == {"twitch"}
    assert settings["auto_sources"] is True


def test_load_autodetect_preserves_explicit_extra_roots():
    settings = router._load_autodetect(
        {
            "autodetect": {
                "enabled": True,
                "auto_sources": False,
                "sources": {
                    "school": {
                        "seed": "https://wayground.com/",
                        "route_id": "school",
                        "provider": "cloudflare",
                        "roots": ["wayground.com"],
                        "extra_roots": [
                            "cdn.prod.website-files.com",
                            "CDN.PROD.WEBSITE-FILES.COM",
                        ],
                    }
                },
            }
        },
        [{"id": "school", "domains": ["wayground.com"], "provider": "cloudflare"}],
        {"cloudflare": {}},
    )

    assert settings["sources"]["school"]["extra_roots"] == [
        "cdn.prod.website-files.com"
    ]


def test_load_autodetect_rejects_invalid_extra_roots():
    with pytest.raises(ValueError, match="extra_roots"):
        router._load_autodetect(
            {
                "autodetect": {
                    "enabled": True,
                    "auto_sources": False,
                    "sources": {
                        "school": {
                            "seed": "https://wayground.com/",
                            "route_id": "school",
                            "provider": "cloudflare",
                            "roots": ["wayground.com"],
                            "extra_roots": ["not a host"],
                        }
                    },
                }
            },
            [{"id": "school", "domains": ["wayground.com"], "provider": "cloudflare"}],
            {"cloudflare": {}},
        )


def test_learned_hosts_outside_current_roots_are_pruned(tmp_path):
    old = (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
           router._vpn, router._routing, router._autodetect, router._port)
    try:
        router.ROOT = Path(tmp_path)
        router.CONFIG_FILE = router.ROOT / "router.json"
        router._autodetect = {
            "enabled": True,
            "sources": {
                "school": {
                    "route_id": "school",
                    "roots": ["wayground.com"],
                    "extra_roots": ["cdn.prod.example.net"],
                }
            },
        }
        state_path = router.ROOT / "state" / "autodetect" / "school.json"
        state_path.parent.mkdir(parents=True)
        state_path.write_text(json.dumps({
            "route_id": "school",
            "domains": {
                "cdn.prod.example.net": {"expires_at": 9999999999},
                "old.shared-cdn.net": {"expires_at": 9999999999},
            },
        }))

        assert router._autodetected_domains_by_route() == {
            "school": ["cdn.prod.example.net"]
        }
    finally:
        (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
         router._vpn, router._routing, router._autodetect, router._port) = old


def test_build_config_does_not_expand_roots_when_disabled(tmp_path, monkeypatch):
    old = (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
           router._vpn, router._routing, router._autodetect, router._port)
    try:
        router.ROOT = Path(tmp_path)
        router.CONFIG_FILE = router.ROOT / "router.json"
        router._providers = {"cloudflare": {"socks5": {"host": "127.0.0.1", "port": 2181}}}
        router._routes = [{"id": "school", "domains": ["twitch.tv"], "provider": "cloudflare"}]
        router._vpn = {}
        router._routing = {"mode": "default", "vpn_domains": []}
        router._autodetect = {
            "enabled": False,
            "sources": {
                "twitch": {
                    "route_id": "school",
                    "provider": "cloudflare",
                    "roots": ["twitch.tv", "ttvnw.net"],
                }
            },
        }
        router._port = 2080

        assert router._routes_with_autodetected_domains(router._routes) == router._routes
    finally:
        (router.ROOT, router.CONFIG_FILE, router._providers, router._routes,
         router._vpn, router._routing, router._autodetect, router._port) = old


def test_load_autodetect_skips_ip_only_route():
    settings = router._load_autodetect(
        {"autodetect": {"enabled": True}},
        [{"id": "ip-only", "domains": ["192.0.2.1"], "provider": "cloudflare"}],
        {"cloudflare": {}},
    )

    assert settings["sources"] == {}


def test_load_autodetect_does_not_materialize_sources_when_disabled():
    settings = router._load_autodetect(
        {"autodetect": {"enabled": False}},
        [{"id": "school", "domains": ["twitch.tv"], "provider": "cloudflare"}],
        {"cloudflare": {}},
    )

    assert settings["sources"] == {}


def test_load_autodetect_ignores_malformed_route_domains():
    settings = router._load_autodetect(
        {"autodetect": {"enabled": True}},
        [{"id": "school", "domains": None, "provider": "cloudflare"}],
        {"cloudflare": {}},
    )

    assert settings["sources"] == {}


def test_load_autodetect_rejects_generated_source_collision():
    with pytest.raises(ValueError, match="collides with generated route source"):
        router._load_autodetect(
            {
                "autodetect": {
                    "enabled": True,
                    "sources": {
                        "route-school": {
                            "seed": "https://other.example/",
                            "route_id": "other",
                            "provider": "cloudflare",
                            "roots": ["other.example"],
                        }
                    },
                }
            },
            [
                {"id": "school", "domains": ["school.example"], "provider": "cloudflare"},
                {"id": "other", "domains": ["other.example"], "provider": "cloudflare"},
            ],
            {"cloudflare": {}},
        )

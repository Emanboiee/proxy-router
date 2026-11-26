from tests.test_router_regressions import load_router


def test_supplemental_source_does_not_suppress_route_generated_source(tmp_path):
    router = load_router(tmp_path)
    routes = [{
        "id": "school",
        "domains": ["discord.com", "youtube.com"],
        "provider": "cloudflare",
    }]
    settings = router._load_autodetect({
        "autodetect": {
            "enabled": True,
            "auto_sources": True,
            "sources": {
                "youtube": {
                    "seed": "https://www.youtube.com/",
                    "route_id": "school",
                    "provider": "cloudflare",
                    "roots": ["youtube.com"],
                    "supplemental": True,
                }
            },
        }
    }, routes, {"cloudflare": {}})
    assert settings["sources"]["route-school"]["seed"] == "https://discord.com/"
    assert settings["sources"]["youtube"]["supplemental"] is True

"""Contract tests for the shared probe-target safety leaf."""

import net_safety


def test_addr_is_private_covers_loopback_private_linklocal_and_unspecified():
    assert net_safety.addr_is_private("127.0.0.1")
    assert net_safety.addr_is_private("10.0.0.5")
    assert net_safety.addr_is_private("192.168.1.1")
    assert net_safety.addr_is_private("169.254.1.1")
    assert net_safety.addr_is_private("::1")
    assert net_safety.addr_is_private("0.0.0.0")


def test_addr_is_private_allows_public_and_fails_closed_on_garbage():
    assert net_safety.addr_is_private("93.184.216.34") is False
    assert net_safety.addr_is_private("not-an-address") is True


def test_metadata_policy_is_a_single_source_of_truth():
    assert "169.254.169.254" in net_safety.METADATA_ADDRESSES
    assert "metadata.google.internal" in net_safety.METADATA_HOSTNAMES
    assert net_safety.PRIVATE_TARGET_BYPASS_ENV == "PROXY_ROUTER_ALLOW_PRIVATE_TARGETS"


def test_resolve_target_addresses_returns_every_deduped_address(monkeypatch):
    import socket

    def fake_getaddrinfo(host, port):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert net_safety.resolve_target_addresses("https://example.com/") == [
        "93.184.216.34",
        "93.184.216.35",
    ]


def test_resolve_target_addresses_is_best_effort(monkeypatch):
    import socket

    def boom(host, port):
        raise OSError("resolver down")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert net_safety.resolve_target_addresses("https://example.com/") == []
    assert net_safety.resolve_target_addresses("not a url") == []

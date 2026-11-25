"""Status must not report a working proxy listener as plainly 'down'.

F1/#177: never claim a foreign process is OUR healthy engine (rc stays 1),
but a listener that answers must be distinguishable from nothing listening.
"""
from unittest import mock

from tests.test_router_regressions import load_router


def test_foreign_listener_is_not_plain_down(tmp_path):
    r = load_router(tmp_path)
    with mock.patch.object(r, "listener_up", return_value=True), \
         mock.patch.object(r, "engine_alive", return_value=False):
        rc, line = r._status_report()
    assert rc == 1
    assert not line.startswith("down"), line
    assert "listener" in line.lower()
    assert "answering" in line.lower() or "active" in line.lower()


def test_no_listener_is_still_down(tmp_path):
    r = load_router(tmp_path)
    with mock.patch.object(r, "listener_up", return_value=False):
        rc, line = r._status_report()
    assert rc == 1
    assert line.startswith("down"), line


def test_foreign_listener_status_json_exposes_proxy_listener(tmp_path):
    r = load_router(tmp_path)
    with mock.patch.object(r, "_status_report",
                           return_value=(1, "proxy listener answering on 127.0.0.1:2080")):
        data = r.status_json()
    assert data["up"] is False
    assert data["proxy_listener"] is True


def test_no_listener_status_json_reports_proxy_listener_false(tmp_path):
    r = load_router(tmp_path)
    with mock.patch.object(r, "_status_report",
                           return_value=(1, "down (proxy mode)")):
        data = r.status_json()
    assert data["up"] is False
    assert data["proxy_listener"] is False


def test_up_status_json_reports_proxy_listener_true(tmp_path):
    r = load_router(tmp_path)
    with mock.patch.object(r, "_status_report",
                           return_value=(0, "up (proxy 127.0.0.1:2080)")):
        data = r.status_json()
    assert data["up"] is True
    assert data["proxy_listener"] is True

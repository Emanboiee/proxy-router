from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class _Log:
    def info(self, _message):
        pass

    def warn(self, _message):
        pass

    def error(self, _message):
        pass


def load_addon(monkeypatch):
    fake_ctx = types.SimpleNamespace(log=_Log())
    fake_http = types.SimpleNamespace()
    fake_mitmproxy = types.ModuleType("mitmproxy")
    fake_mitmproxy.ctx = fake_ctx
    fake_mitmproxy.http = fake_http
    monkeypatch.setitem(sys.modules, "mitmproxy", fake_mitmproxy)
    spec = importlib.util.spec_from_file_location(
        "response_aware_mitm_test", ROOT / "examples" / "response_aware_mitm.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_host_matching_does_not_accept_suffix_lookalikes(monkeypatch):
    addon = load_addon(monkeypatch)
    assert addon._host_matches("api.opencode.ai", "opencode.ai")
    assert addon._host_matches("opencode.ai.", "*.opencode.ai")
    assert not addon._host_matches("evilopencode.ai", "opencode.ai")


def test_429_is_rotated_and_replaced_with_one_retry(monkeypatch):
    addon = load_addon(monkeypatch)
    observer = addon.ResponseAwareOpenCode()

    class Request:
        host = "api.opencode.ai"

    class Response:
        status_code = 429

    replacement = object()
    flow = types.SimpleNamespace(request=Request(), response=Response(), metadata={})
    calls = []
    observer._rotate = lambda host, status: calls.append((host, status)) or True
    observer._retry_request = lambda _flow: replacement

    observer.response(flow)
    first_response = flow.response
    flow.response = Response()
    observer.response(flow)

    assert calls == [("api.opencode.ai", 429)]
    assert first_response is replacement
    assert flow.response.status_code == 429
    assert flow.metadata["response_aware_retried"] is True


def test_non_target_429_is_left_alone(monkeypatch):
    addon = load_addon(monkeypatch)
    observer = addon.ResponseAwareOpenCode()

    class Request:
        host = "example.com"

    class Response:
        status_code = 429

    flow = types.SimpleNamespace(request=Request(), response=Response(), metadata={})
    observer._rotate = lambda *_args: (_ for _ in ()).throw(AssertionError("must not rotate"))
    observer.response(flow)
    assert flow.response.status_code == 429
    assert flow.metadata == {}


def test_recent_event_log_keeps_one_bounded_backup(tmp_path, monkeypatch):
    addon = load_addon(monkeypatch)
    log_path = tmp_path / "response-aware.log"
    event_log = addon.RecentEventLog(log_path, max_bytes=220, backups=1)

    for index in range(8):
        event_log.write("429_detected", host="api.opencode.ai", status=429, attempt=index)

    assert log_path.exists()
    assert Path(str(log_path) + ".1").exists()
    assert not Path(str(log_path) + ".2").exists()
    assert log_path.stat().st_size <= 220
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert records
    assert all(record["event"] == "429_detected" for record in records)
    assert all("headers" not in record and "body" not in record for record in records)


def test_429_failure_is_written_to_recent_event_log(tmp_path, monkeypatch):
    addon = load_addon(monkeypatch)
    observer = addon.ResponseAwareOpenCode(log_file=tmp_path / "response-aware.log")

    class Request:
        host = "api.opencode.ai"
        method = "POST"

    class Response:
        status_code = 429

    flow = types.SimpleNamespace(request=Request(), response=Response(), metadata={})
    observer._rotate = lambda *_args: False
    observer.response(flow)

    records = [json.loads(line) for line in observer.log_file.read_text().splitlines()]
    assert [record["event"] for record in records] == ["429_detected", "rotation_failed"]
    assert records[0]["host"] == "api.opencode.ai"
    assert records[0]["method"] == "POST"

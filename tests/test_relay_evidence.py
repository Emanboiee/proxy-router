"""Failure evidence distinguishes request lanes without exposing request data."""
import http.client
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from model_relay import RelayEvidence
from tests.test_model_header_timeout import header_path  # noqa: F401
from tests.test_model_relay import relay_path  # noqa: F401

pytestmark = [pytest.mark.enable_socket, pytest.mark.allow_hosts(["127.0.0.1"])]


def health(relay):
    connection = http.client.HTTPConnection(*relay.server_address, timeout=2)
    connection.request("GET", "/health")
    response = connection.getresponse()
    assert response.status == 200
    result = json.loads(response.read())
    connection.close()
    return result


def test_header_stall_reports_safe_exit_phase_budget_and_attempt(header_path, caplog):
    request, delays, _, recovery, relay, *_ = header_path
    recovery.recover_transport.return_value = False
    delays.append((0.2, 0))
    assert request()[0] == 504
    failure = health(relay)["last_failure"]
    assert failure["failure_class"] == "upstream_header_timeout"
    assert failure["phase"] == "response_headers"
    assert failure["request_kind"] == "stream"
    assert failure["attempt"] == 1
    assert failure["quota_retries"] == failure["transport_retries"] == 0
    assert failure["elapsed_seconds"] >= 0.04
    assert 0 <= failure["remaining_seconds"] < relay.retry_window
    assert failure["exit"] == {"primary": "primary", "provider": "primary", "profile": "first"}
    assert failure["seconds_ago"] >= 0
    for sentinel in ("SECRET-PROMPT", "SECRET-TOKEN"):
        assert sentinel not in caplog.text
        assert sentinel not in json.dumps(health(relay))
    assert '"phase": "response_headers"' in caplog.text


def test_auxiliary_rejection_cannot_overwrite_chat_lane_evidence(relay_path, caplog):
    request, statuses, _, _, _ = relay_path
    statuses.extend([(400, b'{"error":{"message":"SECRET-UPSTREAM-BODY"}}')] * 2)
    assert request(kind="chat")[0] == 400
    assert request(stream=False, kind="auxiliary")[0] == 400
    evidence = health(request.relay)
    assert evidence["last_failure"]["request_kind"] == "auxiliary"
    assert evidence["failures_by_kind"]["chat"]["upstream_status"] == 400
    assert evidence["failures_by_kind"]["auxiliary"]["failure_class"] == "upstream_rejected"
    for sentinel in ("SECRET-UPSTREAM-BODY", "test-only", "unchanged"):
        assert sentinel not in caplog.text
        assert sentinel not in json.dumps(evidence)


def test_untagged_nonstream_and_stream_remain_distinct(relay_path):
    request, statuses, *_ = relay_path
    statuses.extend([400, 400])
    request(stream=False)
    request(stream=True, kind="DO-NOT-LOG-THIS-SESSION")
    evidence = health(request.relay)
    assert set(evidence["failures_by_kind"]) == {"nonstream", "stream"}
    assert "DO-NOT-LOG-THIS-SESSION" not in json.dumps(evidence)


def test_quota_failure_keeps_http_status_and_retry_counts(relay_path):
    request, statuses, _, recovery, _ = relay_path
    recovery.available = False
    statuses.append(429)
    assert request()[0] == 429
    failure = health(request.relay)["last_failure"]
    assert failure["failure_class"] == "quota_unavailable"
    assert failure["upstream_status"] == 429
    assert failure["attempt"] == 1
    assert failure["quota_retries"] == failure["transport_retries"] == 0


def test_evidence_rejects_raw_paths_and_snapshot_extras():
    assert RelayEvidence.exit_fields(("primary", "provider", "/private/SECRET")) is None
    assert RelayEvidence.exit_fields(("primary", "provider", "profile", "SESSION")) is None
    assert RelayEvidence.exit_fields(None) is None


def test_concurrent_failures_keep_a_bounded_coherent_snapshot():
    evidence = RelayEvidence()

    def record(number):
        kind = "stream" if number % 2 else "nonstream"
        evidence.failure(("primary", "provider", "profile"), request_kind=kind,
                         failure_class="transport_failed", phase="connect_or_response", attempt=number,
                         authorization="SECRET-TOKEN", prompt="SECRET-PROMPT")
        snapshot = evidence.view()
        assert snapshot["last_failure"]["attempt"] in range(40)
        assert len(snapshot["failures_by_kind"]) <= 2
        assert "SECRET" not in json.dumps(snapshot)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(record, range(40)))
    assert set(evidence.view()["failures_by_kind"]) == {"stream", "nonstream"}

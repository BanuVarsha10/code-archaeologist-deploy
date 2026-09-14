"""FastAPI-level smoke tests for the dashboard API surface. Attack Testing
is Live Mode only (Part C) — there is no non-streaming /api/attack-test/run
endpoint anymore (the frontend never called it; /run-stream is the only
Attack Testing entry point). Real hardware is mocked at the live_mode.py
boundary via live_fixtures.mock_live_hardware."""

import json

import pytest
from fastapi.testclient import TestClient

import dashboard_backend.main as main_module
from dashboard_backend.tests.live_fixtures import mock_live_hardware


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "EXPERIENCE_PATH", str(tmp_path / "api_test_experience.json"))
    from dashboard_backend.results_store import ResultsStore
    monkeypatch.setattr(main_module, "store", ResultsStore())
    # Isolated from the real, shared device_pool.json (device-pool task) —
    # without this, every API-level test would read/write the project's
    # actual persistent pool file instead of test-local state.
    from dashboard_backend.device_pool import DevicePool
    monkeypatch.setattr(main_module, "device_pool", DevicePool(tmp_path / "test_device_pool.json"))
    return TestClient(main_module.app)


def _run_one_device(client, ue_id, suci, attack_scenario="replay"):
    with mock_live_hardware(ue_id, suci):
        with client.stream(
            "POST", "/api/attack-test/run-stream",
            json={"attack_scenario": attack_scenario, "attack_mode": "same_for_all", "devices_this_run": 1},
        ) as resp:
            assert resp.status_code == 200
            events = [json.loads(line) for line in resp.iter_lines() if line]
    return events


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_live_run_isolates_failure_and_still_returns_200(client):
    with mock_live_hardware("imsi-999709999999999", "suci-x", fail_at="provision"):
        with client.stream(
            "POST", "/api/attack-test/run-stream",
            json={"attack_scenario": "replay", "attack_mode": "same_for_all", "devices_this_run": 1},
        ) as resp:
            assert resp.status_code == 200
            events = [json.loads(line) for line in resp.iter_lines() if line]

    device = next(e for e in events if e["type"] == "device_done")["device"]
    assert device["live_success"] is False
    assert "simulated provision failure" in device["failure_reason"]
    batch_done = events[-1]
    assert batch_done["summary"]["live_failures"] == 1


def test_devices_this_run_is_capped_at_max(client):
    resp = client.post(
        "/api/attack-test/run-stream",
        json={"attack_scenario": "replay", "attack_mode": "same_for_all", "devices_this_run": 21},
    )
    # Requesting above the cap is rejected by pydantic validation, not silently clamped.
    assert resp.status_code == 422


def test_invalid_subscriber_run_has_no_comparison(client):
    events = _run_one_device(client, "imsi-999709999999998", "suci-y", attack_scenario="invalid_subscriber")
    device = next(e for e in events if e["type"] == "device_done")["device"]
    assert device["comparison_result"] is None
    assert device["no_comparison_reason"]
    batch_done = events[-1]
    assert batch_done["summary"]["verdict_counts"].get("NO_COMPARISON") == 1


def test_get_run_by_id(client):
    events = _run_one_device(client, "imsi-999709999999997", "suci-z", attack_scenario="replay")
    run_id = events[-1]["run_id"]

    resp = client.get(f"/api/run/{run_id}")
    assert resp.status_code == 200
    assert resp.json()["run_id"] == run_id


def test_get_run_unknown_id_404(client):
    resp = client.get("/api/run/does-not-exist")
    assert resp.status_code == 404


def test_get_assessment_and_agent_trace_for_a_ue(client):
    events = _run_one_device(client, "imsi-999709999999996", "suci-w", attack_scenario="replay")
    ue_id = next(e for e in events if e["type"] == "device_done")["device"]["ue_id"]

    assessment_resp = client.get(f"/api/assessment/{ue_id}")
    assert assessment_resp.status_code == 200
    assert assessment_resp.json()["comparison_result"] is not None

    trace_resp = client.get(f"/api/agent-trace/{ue_id}")
    assert trace_resp.status_code == 200
    assert len(trace_resp.json()["decision_trace"]["candidate_scores"]) == 7


def test_get_assessment_unknown_ue_404(client):
    resp = client.get("/api/assessment/imsi-999799999999999")
    assert resp.status_code == 404

"""Tests for the Tier 2 read-only endpoints: Knowledge Base Viewer,
Experience Memory + Timeline, and the Manual Scenario Builder."""

import pytest
from fastapi.testclient import TestClient

import dashboard_backend.main as main_module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "EXPERIENCE_PATH", str(tmp_path / "tier2_experience.json"))
    from dashboard_backend.results_store import ResultsStore
    monkeypatch.setattr(main_module, "store", ResultsStore())
    return TestClient(main_module.app)


def test_knowledge_base_lists_all_seven_schemes(client):
    resp = client.get("/api/knowledge-base")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["schemes"]) == 7
    assert body["knowledge_version"]


def test_knowledge_base_compare_two_real_schemes(client):
    resp = client.get("/api/knowledge-base/compare", params={"a": "GS", "b": "ECIES"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scheme_a"]["short_name"] == "GS"
    assert body["scheme_b"]["short_name"] == "ECIES"


def test_knowledge_base_compare_unknown_scheme_404(client):
    resp = client.get("/api/knowledge-base/compare", params={"a": "GS", "b": "NOT_REAL"})
    assert resp.status_code == 404


def test_manual_scenario_run_produces_a_real_comparison(client):
    resp = client.post(
        "/api/manual-scenario/run",
        json={
            "threat_score": 0.9,
            "privacy_score": 0.2,
            "metadata_leakage": 0.8,
            "correlation_score": 0.7,
            "detection_confidence": 0.85,
            "attack_type": "flooding",
            "attack_severity": "MALICIOUS",
            "request_classification": "BLOCK",
        },
    )
    assert resp.status_code == 200
    device = resp.json()["device"]
    assert device["mode"] == "manual"
    assert device["comparison_result"] is not None
    assert device["comparison_result"]["overall_verdict"] in ("VALIDATED", "INCONCLUSIVE", "NO CHANGE")


def test_manual_scenario_uses_defaults_when_fields_omitted(client):
    resp = client.post("/api/manual-scenario/run", json={})
    assert resp.status_code == 200


def test_manual_scenario_stream_emits_real_stage_sequence(client):
    import json as _json

    with client.stream(
        "POST", "/api/manual-scenario/run-stream",
        json={"threat_score": 0.9, "attack_type": "flooding", "request_classification": "BLOCK"},
    ) as resp:
        assert resp.status_code == 200
        events = [_json.loads(line) for line in resp.iter_lines() if line]

    stages = [e["stage"] for e in events if e["type"] == "stage"]
    assert stages == ["registered", "attack_simulated", "consulting_agent", "assessment_done", "ranking_done"]
    assert events[-1]["type"] == "batch_done"
    assert len(events[-1]["identities"]) == 1


def test_manual_scenario_reuse_identity_pins_the_same_device(client):
    import json as _json

    with client.stream(
        "POST", "/api/manual-scenario/run-stream", json={"threat_score": 0.9},
    ) as resp:
        first_events = [_json.loads(line) for line in resp.iter_lines() if line]
    identity = first_events[-1]["identities"][0]

    with client.stream(
        "POST", "/api/manual-scenario/run-stream",
        json={"threat_score": 0.1, "reuse_identity": identity},
    ) as resp:
        second_events = [_json.loads(line) for line in resp.iter_lines() if line]

    assert second_events[-1]["identities"][0] == identity


def test_experience_stats_and_timeline_reflect_a_real_run(client):
    run_resp = client.post(
        "/api/manual-scenario/run",
        json={"threat_score": 0.9, "attack_type": "replay", "request_classification": "TAG"},
    )
    ue_id = run_resp.json()["device"]["ue_id"]

    stats_resp = client.get("/api/experience/stats")
    assert stats_resp.status_code == 200
    assert stats_resp.json()["total_ues"] >= 1

    ues_resp = client.get("/api/experience/ues")
    assert ue_id in ues_resp.json()["ue_ids"]

    timeline_resp = client.get(f"/api/experience/{ue_id}/timeline")
    assert timeline_resp.status_code == 200
    body = timeline_resp.json()
    assert body["ue_id"] == ue_id
    assert len(body["confidence_trend"]) >= 1


def test_experience_timeline_unknown_ue_404(client):
    resp = client.get("/api/experience/imsi-999799999999999/timeline")
    assert resp.status_code == 404

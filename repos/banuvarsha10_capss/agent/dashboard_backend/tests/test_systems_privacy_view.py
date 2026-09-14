"""Verifies SystemsPrivacyView produces real Systems+Privacy output without
ever touching CAPSSAgent or any experience store (Issue 1 fix)."""

import os

from tests.integration.subscriber_fixtures import mock_subscriber_database

from dashboard_backend.scenario_builder import build_scenario_requests
from dashboard_backend.systems_privacy_view import SystemsPrivacyView

UE_ID = "imsi-999700000008888"
SUCI = "suci-0-999-70-0000-0-0-0000008888"


def test_process_returns_report_privacy_context_and_validation_breakdown():
    requests = build_scenario_requests(UE_ID, SUCI, "duplicate_registration")
    view = SystemsPrivacyView()
    with mock_subscriber_database({UE_ID.replace("imsi-", "")}):
        report, privacy_result, context, validation_context, minimization_result = view.process(requests[0])

    assert report.ue_id == UE_ID
    assert "privacy_score" in privacy_result
    assert context.ue_id == UE_ID
    assert context.request_classification == report.decision
    assert validation_context.header_result.passed is True
    assert validation_context.parameter_result.passed is True

    # Real before/after field minimization (this task) — original value is
    # the real UE_ID, minimized value is a real pseudonym, never the same.
    assert minimization_result["ue_id"]["original"] == UE_ID
    assert minimization_result["ue_id"]["minimized"] == "UE_001"
    assert minimization_result["ue_id"]["minimized"] != UE_ID


def test_never_creates_any_experience_file_as_a_side_effect(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    requests = build_scenario_requests(UE_ID, SUCI, "flooding")
    view = SystemsPrivacyView()
    with mock_subscriber_database({UE_ID.replace("imsi-", "")}):
        for req in requests:
            view.process(req)

    # No file should have been created anywhere under the temp cwd.
    created_files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert created_files == []


def test_reused_instance_accumulates_per_ue_history():
    """Calling .process() repeatedly on the SAME instance must accumulate
    RegistrationHistory state (needed for duplicate/replay/flood detection
    across a scenario sequence) — a fresh instance per call would not."""
    requests = build_scenario_requests(UE_ID, SUCI, "duplicate_registration")
    view = SystemsPrivacyView()
    with mock_subscriber_database({UE_ID.replace("imsi-", "")}):
        report1, _, _, _, _ = view.process(requests[0])
        report2, _, _, _, _ = view.process(requests[1])

    assert report1.attack_type == "NONE"
    assert report2.attack_type == "DUPLICATE_REGISTRATION"

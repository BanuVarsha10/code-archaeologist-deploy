"""Verifies each scenario actually triggers its intended real
ClassificationResult.attack_type — not assumed from the threshold
constants alone, per the plan's Issue-1-adjacent verification requirement.
"""

import pytest

from tests.integration.subscriber_fixtures import mock_subscriber_database

from dashboard_backend.scenario_builder import build_scenario_requests
from dashboard_backend.systems_privacy_view import SystemsPrivacyView

UE_ID = "imsi-999700000009999"
SUCI = "suci-0-999-70-0000-0-0-0000009999"


def _run_sequence(scenario, known_ids):
    requests = build_scenario_requests(UE_ID, SUCI, scenario)
    view = SystemsPrivacyView()
    reports = []
    with mock_subscriber_database(known_ids):
        for req in requests:
            report, _privacy, _context, _validation_context, _minimization = view.process(req)
            reports.append(report)
    return requests, reports


def test_replay_triggers_real_replay_attack_type():
    _requests, reports = _run_sequence("replay", {UE_ID.replace("imsi-", "")})
    assert reports[0].attack_type == "NONE"
    assert reports[-1].attack_type == "REPLAY"


def test_duplicate_registration_triggers_real_duplicate_attack_type():
    _requests, reports = _run_sequence("duplicate_registration", {UE_ID.replace("imsi-", "")})
    assert reports[0].attack_type == "NONE"
    assert reports[-1].attack_type == "DUPLICATE_REGISTRATION"


def test_flooding_triggers_real_flood_attack_type():
    _requests, reports = _run_sequence("flooding", {UE_ID.replace("imsi-", "")})
    assert reports[0].attack_type == "NONE"
    assert reports[-1].attack_type == "REGISTRATION_FLOOD"
    assert reports[-1].decision == "BLOCK"


def test_invalid_subscriber_triggers_real_invalid_subscriber_attack_type():
    # Empty allow-list -> this identity is not a known subscriber.
    _requests, reports = _run_sequence("invalid_subscriber", set())
    assert reports[-1].attack_type == "INVALID_SUBSCRIBER"
    assert reports[-1].decision == "BLOCK"


def test_mixed_touches_more_than_one_detector_and_ends_on_a_real_attack():
    _requests, reports = _run_sequence("mixed", {UE_ID.replace("imsi-", "")})
    attack_types_seen = {r.attack_type for r in reports}
    assert reports[0].attack_type == "NONE"
    assert len(attack_types_seen) > 2  # NONE + at least two distinct attack types
    assert reports[-1].attack_type in ("REPLAY", "DUPLICATE_REGISTRATION")


def test_unknown_scenario_raises():
    with pytest.raises(ValueError):
        build_scenario_requests(UE_ID, SUCI, "not_a_real_scenario")

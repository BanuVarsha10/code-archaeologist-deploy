"""
tests/integration/test_systems_agent_integration.py

Rigorous integration testing of the real (unmodified) Systems module
against the real (unmodified) Agent module, through capss/integration/
systems_adapter.py only.

Covers: normal flow, duplicate detection, replay detection, registration
flooding, invalid subscriber, mixed traffic, interval boundary conditions,
multi-UE isolation, and defensive checks that Systems' own source files
are never modified by this integration work.
"""

import hashlib
import os
from datetime import datetime, timedelta

import pytest

from systems.pre_amf.models import RegistrationRequest
from capss.integration.systems_adapter import SystemsPipeline, attack_report_to_registration_context, _normalize_threat_score
from capss.agent.capss_agent import CAPSSAgent

from tests.integration.subscriber_fixtures import mock_subscriber_database

KNOWN_IMSI = "999700000000001"


def make_request(ue_id="imsi-999700000000001", suci="suci-0001", seconds_offset=0,
                  auth_result="Success", reg_status="Success", request_id="REQ0001"):
    return RegistrationRequest(
        request_id=request_id,
        timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(seconds=seconds_offset),
        ue_id=ue_id,
        suci=suci,
        event="Registration Request",
        authentication_result=auth_result,
        registration_status=reg_status,
        gnb_ip="127.0.0.1",
        dnn="internet",
        snssai="SST:1 SD:0x1",
        registration_type="INITIAL",
    )


@pytest.fixture
def agent(tmp_path):
    return CAPSSAgent(
        schemes_path="data/privacy_schemes.json",
        experience_path=str(tmp_path / "exp.json"),
    )


# ============================================================
# 1. Basic flow - first registration
# ============================================================

def test_first_registration_is_allow(agent):
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        request = make_request()
        report = pipeline.process(request)

        assert report.decision == "ALLOW"
        assert report.attack_type in ("NONE", None) or report.attack_type == "NONE"

        context = attack_report_to_registration_context(report, request)
        policy = agent.process_registration(context, verbose=False)
        assert policy.validation_result.is_valid


# ============================================================
# 2. Duplicate registration detection
# ============================================================

def test_duplicate_registration_detected_and_agent_reacts(agent):
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()

        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        report1 = pipeline.process(r1)
        ctx1 = attack_report_to_registration_context(report1, r1)
        policy1 = agent.process_registration(ctx1, verbose=False)

        r2 = make_request(seconds_offset=3, request_id="REQ0002")  # within DUPLICATE_INTERVAL (10s)
        report2 = pipeline.process(r2)

        assert report2.decision == "TAG"
        assert report2.attack_type == "DUPLICATE_REGISTRATION"

        ctx2 = attack_report_to_registration_context(report2, r2)
        policy2 = agent.process_registration(ctx2, verbose=False)
        assert policy2.validation_result.is_valid
        # Duplicate registration should favor tracking-resistant schemes
        assert policy2.selected_scheme in ("DP", "GS") or (
            policy2.hybrid_schemes and any(s in ("DP", "GS") for s in policy2.hybrid_schemes)
        )


# ============================================================
# 3. Replay detection (interval <= 2s, same SUCI)
# ============================================================

def test_replay_detected_within_replay_interval(agent):
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()

        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        pipeline.process(r1)

        r2 = make_request(seconds_offset=1, request_id="REQ0002")  # within REPLAY_INTERVAL (2s)
        report2 = pipeline.process(r2)

        assert report2.attack_type == "REPLAY"
        assert report2.decision == "TAG"


# ============================================================
# 4. Boundary conditions - exact interval thresholds
# ============================================================

def test_interval_exactly_at_replay_boundary(agent):
    """interval == REPLAY_INTERVAL (2s) - inclusive per detector's <= check."""
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        pipeline.process(r1)

        r2 = make_request(seconds_offset=2, request_id="REQ0002")
        report2 = pipeline.process(r2)
        assert report2.attack_type == "REPLAY"  # <=2s is replay, inclusive


def test_interval_just_past_replay_boundary_falls_to_duplicate(agent):
    """interval > REPLAY_INTERVAL but <= DUPLICATE_INTERVAL -> duplicate, not replay."""
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        pipeline.process(r1)

        r2 = make_request(seconds_offset=2.5, request_id="REQ0002")
        report2 = pipeline.process(r2)
        assert report2.attack_type == "DUPLICATE_REGISTRATION"


def test_interval_exactly_at_duplicate_boundary(agent):
    """interval == DUPLICATE_INTERVAL (10s) - inclusive."""
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        pipeline.process(r1)

        r2 = make_request(seconds_offset=10, request_id="REQ0002")
        report2 = pipeline.process(r2)
        assert report2.attack_type == "DUPLICATE_REGISTRATION"


def test_interval_past_duplicate_boundary_is_normal(agent):
    """interval > DUPLICATE_INTERVAL -> normal traffic, no false positive."""
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        pipeline.process(r1)

        r2 = make_request(seconds_offset=11, request_id="REQ0002")
        report2 = pipeline.process(r2)
        assert report2.attack_type == "NONE"
        assert report2.decision == "ALLOW"


# ============================================================
# 5. Invalid subscriber
# ============================================================

def test_invalid_subscriber_blocked_but_agent_still_recommends(agent):
    with mock_subscriber_database({KNOWN_IMSI}):  # unknown UE deliberately NOT in the known set
        pipeline = SystemsPipeline()
        request = make_request(ue_id="imsi-999799999999999", request_id="REQ0001")
        report = pipeline.process(request)

        assert report.decision == "BLOCK"
        assert report.attack_type == "INVALID_SUBSCRIBER"

        context = attack_report_to_registration_context(report, request)
        policy = agent.process_registration(context, verbose=False)
        # Agent must still produce a valid policy even for a BLOCKed request
        assert policy.validation_result.is_valid
        assert policy.selected_scheme


# ============================================================
# 6. Multi-UE isolation - histories must not cross-contaminate
# ============================================================

def test_multiple_ues_do_not_share_history(agent):
    with mock_subscriber_database({KNOWN_IMSI, "999700000000002"}):
        pipeline = SystemsPipeline()

        # UE-A registers twice, quickly (should trigger duplicate for UE-A only)
        a1 = make_request(ue_id="imsi-999700000000001", seconds_offset=0, request_id="A1")
        pipeline.process(a1)
        a2 = make_request(ue_id="imsi-999700000000001", seconds_offset=3, request_id="A2")
        report_a2 = pipeline.process(a2)
        assert report_a2.attack_type == "DUPLICATE_REGISTRATION"

        # UE-B's first-ever registration, same timestamp window - must NOT inherit UE-A's history
        b1 = make_request(ue_id="imsi-999700000000002", seconds_offset=3, request_id="B1")
        report_b1 = pipeline.process(b1)
        assert report_b1.decision == "ALLOW"
        assert report_b1.attack_type == "NONE"


# ============================================================
# 7. Mixed traffic sequence
# ============================================================

def test_mixed_traffic_sequence_all_produce_valid_policies(agent):
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        sequence = [
            make_request(seconds_offset=0, request_id="R1"),                          # normal
            make_request(seconds_offset=1, request_id="R2"),                          # replay
            make_request(seconds_offset=15, request_id="R3"),                         # normal (past window)
            make_request(ue_id="imsi-999799999999999", seconds_offset=16, request_id="R4"),  # invalid subscriber
        ]
        decisions = []
        for req in sequence:
            report = pipeline.process(req)
            context = attack_report_to_registration_context(report, req)
            policy = agent.process_registration(context, verbose=False)
            assert policy.validation_result.is_valid, f"Invalid policy for {req.request_id}: {policy.validation_result.errors}"
            decisions.append((report.decision, report.attack_type))

        assert decisions[0] == ("ALLOW", "NONE")
        assert decisions[1][1] == "REPLAY"
        assert decisions[3] == ("BLOCK", "INVALID_SUBSCRIBER")


# ============================================================
# 8. Threat score normalization
# ============================================================

def test_threat_score_normalization_in_range():
    assert _normalize_threat_score(0) == 0.0
    assert _normalize_threat_score(100) == 1.0
    assert _normalize_threat_score(50) == 0.5
    # Defensive clip even if Systems' own clamp were ever bypassed
    assert _normalize_threat_score(150) == 1.0
    assert _normalize_threat_score(-10) == 0.0


def test_real_threat_score_from_pipeline_is_valid_for_registrationcontext(agent):
    """
    Regression guard for the exact bug found during integration:
    Systems' risk_score is 0-100; RegistrationContext requires 0-1.
    This must never raise a pydantic ValidationError.
    """
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        r1 = make_request(seconds_offset=0, request_id="REQ0001")
        pipeline.process(r1)
        r2 = make_request(seconds_offset=3, request_id="REQ0002")  # triggers duplicate -> non-zero risk_score
        report2 = pipeline.process(r2)

        assert report2.risk_score > 0  # confirm this test actually exercises a non-trivial score
        context = attack_report_to_registration_context(report2, r2)  # must not raise
        assert 0.0 <= context.threat_score <= 1.0


# ============================================================
# 9. Systems' own source files must never be modified
# ============================================================

SYSTEMS_FILES_TO_GUARD = [
    "systems/pre_amf/validator.py",
    "systems/pre_amf/models.py",
    "systems/pre_amf/report.py",
    "systems/pre_amf/detectors/duplicate_detector.py",
    "systems/pre_amf/validators/subscriber_validator.py",
    "systems/threat_context/generator.py",
    "systems/threat_context/calculator.py",
]


def _hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def test_systems_files_are_never_written_by_integration_code():
    """
    Records a hash of each guarded Systems file before and after running
    the full test module's fixtures once more, confirming nothing in this
    integration layer wrote to Systems' own source.
    """
    before = {}
    for rel_path in SYSTEMS_FILES_TO_GUARD:
        assert os.path.exists(rel_path), f"Expected Systems file missing: {rel_path}"
        before[rel_path] = _hash_file(rel_path)

    # Exercise the pipeline once more to be sure nothing writes as a side effect
    with mock_subscriber_database({KNOWN_IMSI}):
        pipeline = SystemsPipeline()
        pipeline.process(make_request())

    for rel_path in SYSTEMS_FILES_TO_GUARD:
        after = _hash_file(rel_path)
        assert after == before[rel_path], f"Systems file was modified: {rel_path}"


# ============================================================
# 10. Subscriber mock cleans up after itself
# ============================================================

def test_mock_subscriber_database_restores_real_implementation_after_use():
    from systems.pre_amf.validators.subscriber_validator import SubscriberValidator
    original_exists = SubscriberValidator.subscriber_exists

    with mock_subscriber_database({KNOWN_IMSI}):
        assert SubscriberValidator.subscriber_exists is not original_exists

    assert SubscriberValidator.subscriber_exists is original_exists

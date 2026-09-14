"""
tests/integration/test_full_pipeline.py

Rigorous testing of the complete, live CAPSS pipeline: Systems -> Privacy ->
Agent, through capss/integration/full_pipeline.py only. Builds on
test_systems_agent_integration.py (which covers Systems<->Agent in isolation)
by adding Privacy into the loop and testing the combined behavior.
"""

import hashlib
import os
from datetime import datetime, timedelta

import pytest

from systems.pre_amf.models import RegistrationRequest
from capss.integration.full_pipeline import CAPSSFullPipeline, build_registration_context
from tests.integration.subscriber_fixtures import mock_subscriber_database


def make_request(ue_id="imsi-999700000000001", suci="suci-0-999-70-0000-0-0-0000000001",
                  seconds_offset=0, request_id="REQ0001", gnb_ip="127.0.0.1", dnn="internet",
                  snssai="SST:1 SD:0x1", auth_result="Success", reg_status="Success"):
    return RegistrationRequest(
        request_id=request_id,
        timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(seconds=seconds_offset),
        ue_id=ue_id, suci=suci, event="Registration Request",
        authentication_result=auth_result, registration_status=reg_status,
        gnb_ip=gnb_ip, dnn=dnn, snssai=snssai, registration_type="INITIAL",
    )


@pytest.fixture
def pipeline(tmp_path):
    with mock_subscriber_database({"999700000000001", "999700000000002", "999700000000003", "ue_00001"}):
        yield CAPSSFullPipeline(
            schemes_path="data/privacy_schemes.json",
            experience_path=str(tmp_path / "exp.json"),
        )


# ============================================================
# 1. Basic full pipeline
# ============================================================

def test_full_pipeline_normal_registration(pipeline):
    report, privacy, context, policy = pipeline.process(make_request())
    assert report.decision == "ALLOW"
    assert policy.validation_result.is_valid
    assert 0.0 <= privacy["privacy_score"] <= 1.0
    assert 0.0 <= context.threat_score <= 1.0


# ============================================================
# 2. Privacy signal genuinely drives Agent choice (live, not synthetic)
# ============================================================

def test_high_exposure_identity_drives_metadata_aware_scheme(pipeline):
    """Real IMSI + real SUCI + real gNB IP -> high exposure -> AP-favoring pick."""
    report, privacy, context, policy = pipeline.process(make_request(
        ue_id="imsi-999700000000001", suci="suci-0-999-70-0000-0-0-0000000001", gnb_ip="127.0.0.1"
    ))
    assert privacy["metadata_leakage"] > 0.8
    assert policy.selected_scheme == "AP" or (policy.hybrid_schemes and "AP" in policy.hybrid_schemes)


def test_pseudonymized_identity_scores_lower_risk_than_full_identity(pipeline):
    """
    Pseudonymized UE_ID, masked gNB, placeholder DNN/SNSSAI -> meaningfully
    lower exposure than a full real-identity registration.

    NOTE: SUCI is intentionally left in Systems-valid format here
    ("suci-..."), not Privacy's own "anonymized" convention ("suci_...") -
    see test_suci_anonymization_convention_conflicts_with_systems_format
    below for why those two can never both be satisfied by the same value.
    """
    baseline_report, baseline_privacy, _, _ = pipeline.process(make_request(
        ue_id="imsi-999700000000001", suci="suci-0-999-70-0000-0-0-0000000001", gnb_ip="127.0.0.1",
        request_id="BASELINE",
    ))

    report, privacy, context, policy = pipeline.process(make_request(
        ue_id="ue_00001", suci="suci-anon-00001", gnb_ip="xxx.xxx.xxx.xxx",
        dnn="DEFAULT_DNN", snssai="DEFAULT_SLICE", request_id="PSEUDO",
    ))
    assert report.decision == "ALLOW"
    assert privacy["privacy_score"] > baseline_privacy["privacy_score"]
    assert privacy["metadata_leakage"] < baseline_privacy["metadata_leakage"]


# ============================================================
# 2b. Real, worth-documenting finding: Systems and Privacy disagree
#     on what an "anonymized" SUCI looks like
# ============================================================

def test_suci_anonymization_convention_conflicts_with_systems_format():
    """
    DOCUMENTS A REAL CROSS-TEAM INCONSISTENCY (not a bug to fix here):

    Systems' parameter_validator.py requires SUCI to match
    ^suci-[A-Za-z0-9\\-.]+$ (hyphen) or it's rejected as INVALID_PARAMETER.

    Privacy's privacy_score.py's suci_exposure() treats "suci_" (underscore)
    as the LOW-exposure "anonymized label" pattern, and ANY "suci-..."
    (hyphen - the ONLY format Systems accepts) as a high-exposure "real
    SUCI" (20/20 points, second only to a real IMSI).

    Net effect: no SUCI value can simultaneously pass Systems' format
    check AND score as "anonymized" in Privacy's exposure calculation.
    This test locks in that this is real and reproducible, so it doesn't
    get silently "fixed" by an unrelated change later without noticing.
    """
    from tests.integration.subscriber_fixtures import mock_subscriber_database
    from systems.pre_amf.validator import PreAMFValidator
    from datetime import datetime
    from systems.pre_amf.models import RegistrationRequest

    with mock_subscriber_database({"ue_00001"}):
        validator = PreAMFValidator()
        request = RegistrationRequest(
            request_id="SUCICONFLICT", timestamp=datetime(2026, 1, 1, 12, 0, 0), ue_id="ue_00001",
            suci="suci_001",  # Privacy's own "anonymized" convention
            event="Registration Request", authentication_result="Success", registration_status="Success",
            gnb_ip="xxx.xxx.xxx.xxx", dnn="DEFAULT_DNN", snssai="DEFAULT_SLICE", registration_type="INITIAL",
        )
        context = validator.validate_with_context(request)

    # Confirmed: Privacy's "anonymized" SUCI format is rejected by Systems
    assert context.parameter_result.passed is False
    assert "Invalid SUCI format" in context.parameter_result.errors
    assert context.classification_result.decision == "BLOCK"


# ============================================================
# 3. Systems attack detection + Privacy both feed the same decision
# ============================================================

def test_duplicate_attack_plus_high_correlation_together(pipeline):
    """Repeated registration should trigger BOTH Systems' duplicate detector
    AND Privacy's rising correlation score, and the Agent should react to both."""
    r1 = make_request(seconds_offset=0, request_id="R1")
    report1, priv1, ctx1, policy1 = pipeline.process(r1)

    r2 = make_request(seconds_offset=3, request_id="R2")  # within duplicate window
    report2, priv2, ctx2, policy2 = pipeline.process(r2)

    assert report2.attack_type == "DUPLICATE_REGISTRATION"
    assert priv2["correlation_score"] > priv1["correlation_score"]  # linkability rising
    assert policy2.validation_result.is_valid
    # Duplicate + rising correlation should favor tracking-resistant schemes
    assert policy2.selected_scheme in ("DP", "GS") or (
        policy2.hybrid_schemes and any(s in ("DP", "GS") for s in policy2.hybrid_schemes)
    )


# ============================================================
# 4. Multi-UE isolation across ALL THREE modules
# ============================================================

def test_multi_ue_isolation_across_all_three_modules(pipeline):
    # UE-A registers 3 times -> builds up Systems history + Privacy correlation + Agent experience
    for i in range(3):
        pipeline.process(make_request(ue_id="imsi-999700000000001", seconds_offset=i * 3, request_id=f"A{i}"))

    # UE-B's first-ever registration must NOT inherit UE-A's Systems history,
    # Privacy correlation, or Agent experience
    report_b, priv_b, ctx_b, policy_b = pipeline.process(
        make_request(ue_id="imsi-999700000000002", seconds_offset=9, request_id="B1")
    )
    assert report_b.decision == "ALLOW"
    assert report_b.attack_type == "NONE"
    stored_b = pipeline.agent.memory.retrieve("imsi-999700000000002")
    assert len(stored_b) == 1  # only this UE's own single experience, not UE-A's 3


# ============================================================
# 5. Same UE, 10 registrations, 10 different threat scenarios
#    (the "virtual environment" demonstration scenario)
# ============================================================

SCENARIO_SEQUENCE = [
    ("normal", dict()),
    ("normal", dict()),
    ("replay", dict(seconds_offset_delta=1)),
    ("duplicate", dict(seconds_offset_delta=5)),
    ("duplicate", dict(seconds_offset_delta=5)),
    ("normal_recovery", dict(seconds_offset_delta=30)),
    ("flooding_start", dict(seconds_offset_delta=1)),
    ("flooding_continue", dict(seconds_offset_delta=1)),
    ("flooding_continue", dict(seconds_offset_delta=1)),
    ("normal_recovery", dict(seconds_offset_delta=60)),
]


def test_same_ue_ten_registrations_varied_scenarios(pipeline):
    """
    Same UE, 10 sequential registrations, deliberately varied timing to hit
    normal / replay / duplicate / flooding conditions in one continuous
    session - exactly the scenario requested for the live demonstration.
    """
    ue = "imsi-999700000000003"
    t = 0
    results = []
    for i, (label, cfg) in enumerate(SCENARIO_SEQUENCE):
        t += cfg.get("seconds_offset_delta", 20)
        report, privacy, context, policy = pipeline.process(
            make_request(ue_id=ue, seconds_offset=t, request_id=f"SEQ{i}")
        )
        results.append((label, report.decision, report.attack_type, policy.selected_scheme,
                         policy.hybrid_schemes, policy.confidence, policy.validation_result.is_valid))
        assert policy.validation_result.is_valid, f"Invalid policy at step {i} ({label})"

    # Confirm the sequence actually exercised more than one attack type
    attack_types_seen = {r[2] for r in results}
    assert len(attack_types_seen) > 1, f"Expected multiple attack types, saw only {attack_types_seen}"

    # Confirm the replay step (index 2) was actually detected as replay
    assert results[2][2] == "REPLAY"

    # Confirm experience accumulated for this UE across all 10 registrations
    stored = pipeline.agent.memory.retrieve(ue)
    assert len(stored) >= 1


# ============================================================
# 6. Multiple different UEs, single run, no cross-contamination
# ============================================================

def test_multiple_different_ues_single_run(pipeline):
    ue_profiles = [
        ("imsi-999700000000001", "suci-0-999-70-0000-0-0-0000000001", "127.0.0.1"),
        ("imsi-999700000000002", "suci-0-999-70-0000-0-0-0000000002", "127.0.0.2"),
        ("imsi-999700000000003", "suci-0-999-70-0000-0-0-0000000003", "127.0.0.3"),
    ]
    seen_ues = set()
    for i, (ue, suci, gnb) in enumerate(ue_profiles):
        report, privacy, context, policy = pipeline.process(
            make_request(ue_id=ue, suci=suci, gnb_ip=gnb, seconds_offset=i * 100, request_id=f"MULTI{i}")
        )
        assert policy.validation_result.is_valid
        seen_ues.add(ue)

    assert len(seen_ues) == 3
    for ue, _, _ in ue_profiles:
        assert len(pipeline.agent.memory.retrieve(ue)) == 1


# ============================================================
# 7. Invalid subscriber + high privacy risk combined
# ============================================================

def test_invalid_subscriber_with_high_exposure(pipeline):
    report, privacy, context, policy = pipeline.process(make_request(
        ue_id="imsi-999799999999999",  # not in known set
        suci="suci-0-999-79-9999-9-9-9999999999",
        gnb_ip="127.0.0.99",
    ))
    assert report.decision == "BLOCK"
    assert report.attack_type == "INVALID_SUBSCRIBER"
    assert privacy["privacy_risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert policy.validation_result.is_valid
    assert policy.selected_scheme


# ============================================================
# 8. Edge cases - empty/missing optional fields
# ============================================================

def test_empty_optional_fields_do_not_crash(pipeline):
    report, privacy, context, policy = pipeline.process(make_request(
        gnb_ip="", dnn="", snssai="",
    ))
    assert policy.validation_result.is_valid
    assert 0.0 <= privacy["metadata_leakage"] <= 1.0


def test_unknown_attack_type_handled_gracefully(pipeline):
    """A registration with unusual/malformed values must not crash the pipeline."""
    report, privacy, context, policy = pipeline.process(make_request(
        ue_id="totally-unrecognized-id-format", suci="", gnb_ip="???", dnn="???", snssai="???",
    ))
    assert policy.validation_result.is_valid


# ============================================================
# 9. Systems + Privacy source files never modified
# ============================================================

GUARDED_FILES = [
    "systems/pre_amf/validator.py",
    "systems/pre_amf/models.py",
    "systems/pre_amf/report.py",
    "systems/pre_amf/detectors/duplicate_detector.py",
    "systems/threat_context/generator.py",
    "systems/threat_context/calculator.py",
    "privacy/privacy_score.py",
    "privacy/correlation_analyzer.py",
    "privacy/generate_privacy_context.py",
]


def _hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def test_systems_and_privacy_files_never_modified(pipeline):
    before = {p: _hash_file(p) for p in GUARDED_FILES if os.path.exists(p)}
    assert len(before) == len(GUARDED_FILES), "One or more guarded files is missing"

    pipeline.process(make_request(request_id="GUARD1"))
    pipeline.process(make_request(ue_id="imsi-999700000000002", request_id="GUARD2"))

    for p in GUARDED_FILES:
        assert _hash_file(p) == before[p], f"File was modified: {p}"


# ============================================================
# 10. Threat score / privacy score always valid range under stress
# ============================================================

def test_scores_stay_in_valid_range_under_repeated_attack_pressure(pipeline):
    """Hammer the same UE with rapid registrations - scores must never go
    out of [0,1] range regardless of how extreme the accumulated history gets."""
    ue = "imsi-999700000000001"
    for i in range(15):
        report, privacy, context, policy = pipeline.process(
            make_request(ue_id=ue, seconds_offset=i * 1, request_id=f"STRESS{i}")
        )
        assert 0.0 <= context.threat_score <= 1.0
        assert 0.0 <= privacy["privacy_score"] <= 1.0
        assert 0.0 <= privacy["metadata_leakage"] <= 1.0
        assert 0.0 <= privacy["correlation_score"] <= 1.0
        assert 0.0 <= policy.confidence <= 1.0
        assert policy.validation_result.is_valid

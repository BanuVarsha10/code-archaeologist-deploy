import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError

from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import SchemeScore, DecisionTrace, Recommendation
from capss.schemas.policy import PrivacyPolicy, ValidationResult


def test_registration_context_valid():
    ctx = RegistrationContext(
        ue_id="UE-001",
        suci="suci-123",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow()
    )
    assert ctx.ue_id == "UE-001"
    assert ctx.privacy_score is None
    assert ctx.threat_score is None

def test_registration_context_invalid():
    with pytest.raises(ValidationError):
        RegistrationContext(
            ue_id="UE-001",
            suci="suci-123",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            # Missing timestamp
        )

def test_registration_context_optional_fields():
    ctx = RegistrationContext(
        ue_id="UE-001",
        suci="suci-123",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow(),
        privacy_score=0.8,
        threat_score=0.2
    )
    assert ctx.privacy_score == 0.8
    assert ctx.threat_score == 0.2

def test_requirement_profile_constraints():
    with pytest.raises(ValidationError):
        RequirementProfile(
            threat_level="high",
            privacy_requirement=1.5,  # Invalid, > 1.0
            tracking_risk=0.5,
            metadata_leakage_risk=0.5,
            correlation_risk=0.5,
            latency_requirement="low",
            resource_profile="moderate",
            network_confidence=0.8,
            context_completeness=1.0
        )
    
    prof = RequirementProfile(
        threat_level="high",
        privacy_requirement=1.0,
        tracking_risk=0.5,
        metadata_leakage_risk=0.5,
        correlation_risk=0.5,
        latency_requirement="low",
        resource_profile="moderate",
        network_confidence=0.8,
        context_completeness=1.0
    )
    assert prof.privacy_requirement == 1.0

def test_experience_creation():
    exp = Experience(
        ue_id="UE-001",
        context_snapshot={"test": "data"},
        requirement_profile={"req": "data"},
        selected_scheme="ECIES",
        selected_scheme_id="SCH-1",
        reason="Good fit",
        confidence=0.9
    )
    assert exp.experience_id is not None
    assert isinstance(exp.experience_id, str)
    assert exp.ue_id == "UE-001"
    
def test_privacy_scheme_helpers():
    scheme = PrivacyScheme(
        id="SCHEME-001",
        name="Test Scheme",
        short_name="TEST",
        description="A test scheme",
        category="Test",
        primary_privacy_goal="Testing",
        quantitative_metrics={"privacy_score": 4},
        cryptographic_characteristics={"quantum_resistant": True},
        security_metrics={"anonymous_authentication": True},
        hybrid_support={"compatible_with": ["OTHER"]}
    )
    assert scheme.get_metric("privacy_score") == 4
    assert scheme.get_metric("security_score", default=3) == 3
    assert scheme.is_quantum_resistant() is True
    assert scheme.supports_anonymous_auth() is True
    assert scheme.get_compatible_hybrids() == ["OTHER"]

def test_scheme_score_decision_trace_recommendation():
    score = SchemeScore(
        scheme_id="SCH-1",
        scheme_name="Test Scheme",
        short_name="TEST",
        final_score=0.85
    )
    trace = DecisionTrace(
        candidate_scores=[score],
        winner="TEST",
        winner_score=0.85
    )
    rec = Recommendation(
        primary_scheme="TEST",
        primary_scheme_id="SCH-1",
        primary_score=0.85,
        reason="Best match",
        confidence=0.9,
        risk_assessment="low",
        decision_trace=trace
    )
    assert rec.primary_scheme == "TEST"
    assert rec.decision_trace.winner == "TEST"
    assert len(rec.decision_trace.candidate_scores) == 1

def test_privacy_policy_validation_result():
    val = ValidationResult(is_valid=True, completeness_score=0.9)
    policy = PrivacyPolicy(
        selected_scheme="TEST",
        selected_scheme_id="SCH-1",
        reason="Matched requirements",
        confidence=0.85,
        validation_result=val
    )
    assert policy.selected_scheme == "TEST"
    assert policy.validation_result.is_valid is True
    policy.set_default_expiry(24)
    assert policy.expiry is not None
    assert policy.expiry > policy.timestamp

def test_model_serialization():
    ctx = RegistrationContext(
        ue_id="UE-001",
        suci="suci-123",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.utcnow()
    )
    data = ctx.model_dump(mode='json')
    assert isinstance(data, dict)
    assert data["ue_id"] == "UE-001"
    
    ctx2 = RegistrationContext.model_validate(data)
    assert ctx2.ue_id == ctx.ue_id
    assert ctx2.dnn == ctx.dnn

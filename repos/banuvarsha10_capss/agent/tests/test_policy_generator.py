"""Tests for PolicyGenerator and PolicyValidator."""

import pytest
from datetime import datetime, timezone

from capss.policy_generator.generator import PolicyGenerator
from capss.policy_generator.validator import PolicyValidator
from capss.schemas.context import RegistrationContext
from capss.schemas.recommendation import Recommendation, DecisionTrace, SchemeScore
from capss.schemas.policy import PrivacyPolicy
from capss.schemas.scheme import PrivacyScheme
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase

from unittest.mock import MagicMock


@pytest.fixture
def sample_context():
    return RegistrationContext(
        ue_id="UE-1",
        suci="suci-0-001-01-0000-0-0-0000000001",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_recommendation():
    trace = DecisionTrace(
        context_summary={"ue_id": "UE-1"},
        requirement_profile={"threat_level": "medium"},
        top_candidates=[],
        winner="ECIES",
        winner_score=0.85,
        processing_time_ms=5.2,
    )
    return Recommendation(
        primary_scheme="ECIES",
        primary_scheme_id="SCHEME-001",
        primary_score=0.85,
        alternative_scheme="ML-KEM",
        alternative_scheme_id="SCHEME-002",
        alternative_score=0.72,
        reason="ECIES selected due to highest overall fitness score",
        confidence=0.82,
        risk_assessment="low",
        metric_breakdown={"sfs": 0.85, "eas": 0.5, "pm": 0.7},
        decision_trace=trace,
        explanation={"why_selected": "Highest score"},
        knowledge_version="v1.0-schemes-8",
        reasoning_version="1.0",
    )


@pytest.fixture
def ecies_scheme():
    return PrivacyScheme(
        id="SCHEME-001",
        name="ECIES",
        short_name="ECIES",
        description="Standard 5G identity protection",
        category="Identity Protection",
        primary_privacy_goal="Identity confidentiality",
        quantitative_metrics={"privacy_score": 4, "security_score": 5},
        decision_support={
            "recommendation_profile": {"reasoning_profile": {}},
            "context_preferences": {},
        },
    )


# ------------------------------------------------------------------ PolicyGenerator


def test_policy_generator_produces_valid_policy(sample_context, sample_recommendation):
    generator = PolicyGenerator()
    policy = generator.generate(sample_recommendation, sample_context)

    assert isinstance(policy, PrivacyPolicy)
    assert policy.selected_scheme == "ECIES"
    assert policy.selected_scheme_id == "SCHEME-001"
    assert policy.confidence == 0.82
    assert policy.reason is not None
    assert policy.expiry is not None  # 24h expiry set
    assert policy.enforcement["apply_to_ue"] == "UE-1"
    assert policy.knowledge_version == "v1.0-schemes-8"
    assert policy.reasoning_version == "1.0"


def test_policy_generator_with_hybrid(sample_context):
    trace = DecisionTrace(
        context_summary={"ue_id": "UE-1"},
        requirement_profile={},
        top_candidates=[],
        processing_time_ms=3.0,
    )
    rec = Recommendation(
        primary_scheme="ECIES",
        primary_scheme_id="SCHEME-001",
        primary_score=0.85,
        hybrid_combination=["ECIES", "Adaptive Padding"],
        hybrid_benefit_score=0.18,
        hybrid_reason="Complementary coverage",
        reason="Hybrid recommended",
        confidence=0.80,
        risk_assessment="low",
        decision_trace=trace,
    )
    generator = PolicyGenerator()
    policy = generator.generate(rec, sample_context)

    assert policy.hybrid_schemes == ["ECIES", "Adaptive Padding"]
    assert policy.enforcement.get("hybrid_schemes") == ["ECIES", "Adaptive Padding"]


# ------------------------------------------------------------------ PolicyValidator


def test_policy_validator_validates_correct_scheme(ecies_scheme):
    kb = MagicMock(spec=SchemeKnowledgeBase)
    kb.get_by_short_name.return_value = ecies_scheme
    kb.get_scheme.return_value = ecies_scheme

    policy = PrivacyPolicy(
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="Test",
        confidence=0.85,
        risk_assessment="low",
    )

    validator = PolicyValidator()
    result = validator.validate(policy, kb)
    assert result.is_valid is True
    assert len(result.errors) == 0


def test_policy_validator_catches_missing_schemes():
    kb = MagicMock(spec=SchemeKnowledgeBase)
    kb.get_by_short_name.return_value = None
    kb.get_scheme.return_value = None

    policy = PrivacyPolicy(
        selected_scheme="UNKNOWN",
        selected_scheme_id="SCHEME-999",
        reason="Test",
        confidence=0.85,
        risk_assessment="low",
    )

    validator = PolicyValidator()
    result = validator.validate(policy, kb)
    assert result.is_valid is False
    assert any("not found" in e for e in result.errors)


def test_policy_validator_warns_low_confidence():
    kb = MagicMock(spec=SchemeKnowledgeBase)
    kb.get_by_short_name.return_value = MagicMock()

    policy = PrivacyPolicy(
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="Test",
        confidence=0.1,  # Very low
        risk_assessment="high",
    )

    validator = PolicyValidator()
    result = validator.validate(policy, kb)
    assert any("below minimum" in w for w in result.warnings)


def test_policy_validator_fallback_warning():
    kb = MagicMock(spec=SchemeKnowledgeBase)
    kb.get_by_short_name.return_value = MagicMock()

    policy = PrivacyPolicy(
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="Test",
        confidence=0.5,
        risk_assessment="high",
        is_fallback=True,
    )

    validator = PolicyValidator()
    result = validator.validate(policy, kb)
    assert any("fallback" in w.lower() for w in result.warnings)

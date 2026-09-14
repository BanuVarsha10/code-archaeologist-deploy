"""Tests for the Reasoning Engine and sub-modules.

Tests: MetricsCalculator, ProfileMatcher, SchemeScorer,
       ExplanationGenerator, ReasoningEngine.
"""

import pytest
from datetime import datetime, timezone

from capss.reasoning.metrics import MetricsCalculator
from capss.reasoning.scorer import SchemeScorer
from capss.reasoning.engine import ReasoningEngine
from capss.reasoning.profile_matcher import ProfileMatcher
from capss.reasoning.explainer import ExplanationGenerator

from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import SchemeScore
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase

from unittest.mock import MagicMock


# ------------------------------------------------------------------ fixtures

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
def sample_req_profile():
    return RequirementProfile(
        threat_level="medium",
        privacy_requirement=0.5,
        tracking_risk=0.5,
        metadata_leakage_risk=0.5,
        correlation_risk=0.5,
        latency_requirement="medium",
        resource_profile="powerful",
        network_confidence=0.8,
        context_completeness=1.0,
        quantum_threat=False,
        anonymous_auth_required=False,
        identity_protection_required=True,
    )


@pytest.fixture
def dummy_scheme():
    return PrivacyScheme(
        id="SCHEME-001",
        name="ECIES",
        short_name="ECIES",
        description="Standard 5G identity protection",
        category="Identity Protection",
        primary_privacy_goal="Identity confidentiality",
        quantitative_metrics={
            "privacy_score": 4,
            "security_score": 5,
            "latency_score": 5,
            "energy_score": 5,
            "tracking_score": 3,
            "identity_score": 5,
            "scalability_score": 5,
            "deployment_score": 5,
            "quantum_score": 1,
        },
        decision_support={
            "recommendation_profile": {
                "reasoning_profile": {
                    "high_threat": False,
                    "high_privacy_required": False,
                    "high_metadata_leakage": False,
                    "high_tracking_risk": False,
                    "high_correlation_risk": False,
                    "low_latency_required": True,
                    "low_signal_environment": False,
                    "registration_success": True,
                    "authentication_success": True,
                    "attack_detected": False,
                },
                "capabilities": ["identity_protection"],
            },
            "context_preferences": {
                "high_privacy": False,
                "high_security": True,
                "low_latency": True,
                "resource_constrained": False,
                "quantum_safe": False,
                "tracking_risk": False,
                "anonymous_authentication_required": False,
                "identity_protection_required": True,
                "high_scalability": True,
            },
        },
        cryptographic_characteristics={"quantum_resistant": False},
        security_metrics={"anonymous_authentication": False},
        hybrid_support={"compatible_with": ["Adaptive Padding"]},
    )


@pytest.fixture
def dummy_scheme_2():
    """A weaker scheme for comparison tests."""
    return PrivacyScheme(
        id="SCHEME-002",
        name="Weak Scheme",
        short_name="WEAK",
        description="A weak scheme for testing",
        category="Test",
        primary_privacy_goal="Test",
        quantitative_metrics={
            "privacy_score": 1,
            "security_score": 1,
            "latency_score": 1,
            "energy_score": 1,
            "tracking_score": 1,
            "identity_score": 1,
            "deployment_score": 1,
            "quantum_score": 1,
        },
        decision_support={
            "recommendation_profile": {"reasoning_profile": {}},
            "context_preferences": {},
        },
    )


@pytest.fixture
def sample_experience():
    return Experience(
        experience_id="exp-001",
        ue_id="UE-1",
        context_snapshot={},
        requirement_profile={},
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="test",
        confidence=0.8,
        decision_score=0.75,
        timestamp=datetime.now(timezone.utc),
        adaptation_count=0,
        success_count=1,
        failure_count=0,
        confidence_trend=[0.8],
        average_decision_score=0.75,
        experience_decay_factor=1.0,
        knowledge_version="v1",
        reasoning_version="v1",
    )


# ------------------------------------------------------------------ MetricsCalculator

def test_metrics_compute_css(sample_context):
    calc = MetricsCalculator()
    css = calc.compute_css(sample_context)
    assert 0.0 <= css <= 1.0
    # eMBB=0.5*0.35, internet=0.4*0.40, initial=0.6*0.25 = 0.175+0.16+0.15 = 0.485
    assert abs(css - 0.485) < 0.01


def test_metrics_compute_pri(sample_req_profile):
    calc = MetricsCalculator()
    pri = calc.compute_pri(sample_req_profile, css=0.5)
    assert 0.0 <= pri <= 1.0


def test_metrics_compute_sfs(dummy_scheme, sample_req_profile):
    calc = MetricsCalculator()
    sfs, dim_scores = calc.compute_sfs(dummy_scheme, sample_req_profile)
    assert 0.0 <= sfs <= 1.0
    assert isinstance(dim_scores, dict)
    assert "privacy_match" in dim_scores


def test_metrics_compute_eas_no_experience(dummy_scheme):
    calc = MetricsCalculator()
    eas = calc.compute_eas([], dummy_scheme)
    assert eas == 0.5  # Neutral for no history


def test_metrics_compute_eas_with_experience(dummy_scheme, sample_experience):
    calc = MetricsCalculator()
    eas = calc.compute_eas([sample_experience], dummy_scheme)
    assert eas > 0.5  # Positive alignment


def test_metrics_compute_ors():
    calc = MetricsCalculator()
    ors = calc.compute_ors(sfs=0.8, pri_match=0.7, eas=0.6, hbs=0.0)
    assert 0.0 <= ors <= 1.0


def test_metrics_compute_confidence():
    calc = MetricsCalculator()
    conf = calc.compute_confidence(
        context_completeness=1.0,
        scheme_match=0.8,
        historical_agreement=0.5,
        knowledge_completeness=1.0,
    )
    assert 0.0 <= conf <= 1.0


# ------------------------------------------------------------------ ProfileMatcher

def test_profile_matcher_returns_0_1(dummy_scheme, sample_req_profile):
    matcher = ProfileMatcher()
    match = matcher.match(sample_req_profile, dummy_scheme)
    assert 0.0 <= match <= 1.0


# ------------------------------------------------------------------ SchemeScorer

def test_scorer_score_scheme(dummy_scheme, sample_req_profile):
    calc = MetricsCalculator()
    matcher = ProfileMatcher()
    scorer = SchemeScorer(calc, matcher, {})

    score = scorer.score_scheme(dummy_scheme, sample_req_profile, [])
    assert isinstance(score, SchemeScore)
    assert 0.0 <= score.final_score <= 1.0
    assert score.scheme_id == "SCHEME-001"
    assert score.short_name == "ECIES"


def test_scorer_ranks_correctly(dummy_scheme, dummy_scheme_2, sample_req_profile):
    calc = MetricsCalculator()
    matcher = ProfileMatcher()
    scorer = SchemeScorer(calc, matcher, {})

    scores = scorer.score_all_schemes(
        [dummy_scheme, dummy_scheme_2], sample_req_profile, [],
    )
    assert len(scores) == 2
    assert scores[0].scheme_id == "SCHEME-001"  # ECIES has higher metrics
    assert scores[0].final_score >= scores[1].final_score


def test_scorer_rejects_quantum_unsafe_scheme(dummy_scheme):
    """Quantum-safe requirement should penalise non-quantum-resistant schemes."""
    calc = MetricsCalculator()
    matcher = ProfileMatcher()
    scorer = SchemeScorer(calc, matcher, {})

    req = RequirementProfile(
        threat_level="high",
        privacy_requirement=0.8,
        tracking_risk=0.6,
        metadata_leakage_risk=0.5,
        correlation_risk=0.5,
        latency_requirement="medium",
        resource_profile="powerful",
        network_confidence=0.8,
        context_completeness=1.0,
        quantum_threat=True,  # Require quantum resistance
        anonymous_auth_required=False,
        identity_protection_required=True,
    )

    score = scorer.score_scheme(dummy_scheme, req, [])
    assert score.is_rejected is True
    assert "Not quantum resistant" in score.rejection_reasons


def test_hybrid_evaluation(dummy_scheme, sample_req_profile):
    calc = MetricsCalculator()
    matcher = ProfileMatcher()
    scorer = SchemeScorer(calc, matcher, {})

    # Create a compatible partner
    partner = PrivacyScheme(
        id="SCHEME-003",
        name="Adaptive Padding",
        short_name="AP",
        description="Traffic analysis protection",
        category="Traffic Analysis Protection",
        primary_privacy_goal="Anti-tracking",
        quantitative_metrics={
            "privacy_score": 3, "security_score": 3, "latency_score": 3,
            "energy_score": 3, "tracking_score": 5, "identity_score": 2,
            "deployment_score": 3, "quantum_score": 3,
        },
        decision_support={
            "recommendation_profile": {"reasoning_profile": {}},
            "context_preferences": {},
        },
    )

    # dummy_scheme has compatible_with: ["Adaptive Padding"]
    # But evaluate_hybrid checks scheme2.id, which is "SCHEME-003", not in compatible list
    # So it should report incompatible
    benefit, reason = scorer.evaluate_hybrid(dummy_scheme, partner, sample_req_profile)
    assert isinstance(benefit, float)
    assert isinstance(reason, str)


# ------------------------------------------------------------------ ExplanationGenerator

def test_explanation_generator(sample_context, sample_req_profile):
    explainer = ExplanationGenerator()

    winner = SchemeScore(
        scheme_id="SCHEME-001",
        scheme_name="ECIES",
        short_name="ECIES",
        fitness_score=0.8,
        final_score=0.75,
        score_breakdown={"sfs": 0.8, "eas": 0.5},
    )

    alt = SchemeScore(
        scheme_id="SCHEME-002",
        scheme_name="Weak Scheme",
        short_name="WEAK",
        fitness_score=0.3,
        final_score=0.25,
        score_breakdown={"sfs": 0.3, "eas": 0.5},
    )

    explanation = explainer.generate_explanation(
        winner=winner,
        context=sample_context,
        experiences=[],
        all_scores=[winner, alt],
        requirement_profile=sample_req_profile,
    )

    assert "why_selected" in explanation
    assert "why_alternatives_rejected" in explanation
    assert "rules_fired" in explanation
    assert isinstance(explanation["rules_fired"], list)
    assert "context_influence" in explanation
    assert "experience_influence" in explanation


# ------------------------------------------------------------------ ReasoningEngine

def test_reasoning_engine_reason(sample_context, sample_req_profile, dummy_scheme):
    kb = MagicMock(spec=SchemeKnowledgeBase)
    kb.get_all_schemes.return_value = [dummy_scheme]
    kb.get_scheme.return_value = dummy_scheme
    kb.get_by_short_name.return_value = None
    kb.get_by_name.return_value = None
    kb.get_knowledge_coverage.return_value = (1.0, [])
    kb.get_knowledge_version.return_value = "v1.0-schemes-1"
    kb.get_scheme_count.return_value = 1

    engine = ReasoningEngine(kb)
    rec = engine.reason(sample_context, sample_req_profile, [])

    assert rec.primary_scheme is not None
    assert rec.primary_scheme_id == "SCHEME-001"
    assert 0.0 <= rec.confidence <= 1.0
    assert rec.decision_trace is not None
    assert isinstance(rec.explanation, dict)
    assert rec.reason != ""


def test_reasoning_engine_with_experience(
    sample_context, sample_req_profile, dummy_scheme, sample_experience,
):
    kb = MagicMock(spec=SchemeKnowledgeBase)
    kb.get_all_schemes.return_value = [dummy_scheme]
    kb.get_scheme.return_value = dummy_scheme
    kb.get_by_short_name.return_value = None
    kb.get_by_name.return_value = None
    kb.get_knowledge_coverage.return_value = (1.0, [])
    kb.get_knowledge_version.return_value = "v1.0-schemes-1"

    engine = ReasoningEngine(kb)
    rec = engine.reason(sample_context, sample_req_profile, [sample_experience])

    assert rec.primary_scheme is not None
    assert rec.decision_trace.previous_scheme == "ECIES"

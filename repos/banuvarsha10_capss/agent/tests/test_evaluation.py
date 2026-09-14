"""Tests for EvaluationMetrics."""

import pytest
from datetime import datetime, timezone, timedelta

from capss.evaluation.metrics import EvaluationMetrics
from capss.schemas.experience import Experience
from capss.schemas.recommendation import DecisionTrace


def _make_experience(scheme: str, confidence: float = 0.8, offset_min: int = 0) -> Experience:
    """Create a real Experience object for testing."""
    return Experience(
        experience_id=f"exp-{scheme}-{offset_min}",
        ue_id="UE-1",
        context_snapshot={},
        requirement_profile={},
        selected_scheme=scheme,
        selected_scheme_id=f"SCHEME-{scheme}",
        reason="test",
        confidence=confidence,
        decision_score=0.75,
        timestamp=datetime.now(timezone.utc) + timedelta(minutes=offset_min),
        adaptation_count=0,
        success_count=1,
        failure_count=0,
        confidence_trend=[confidence],
        average_decision_score=0.75,
        experience_decay_factor=1.0,
        knowledge_version="v1",
        reasoning_version="v1",
    )


def test_recommendation_stability():
    exps = [
        _make_experience("S1", offset_min=0),
        _make_experience("S1", offset_min=1),
        _make_experience("S2", offset_min=2),
    ]
    stability = EvaluationMetrics.recommendation_stability(exps)
    # Sorted by timestamp: S1, S1, S2 → pairs (S1,S1)=same, (S1,S2)=diff → 1/2 = 0.5
    assert stability == 0.5


def test_adaptation_rate():
    exps = [
        _make_experience("S1", offset_min=0),
        _make_experience("S1", offset_min=1),
        _make_experience("S2", offset_min=2),
    ]
    rate = EvaluationMetrics.adaptation_rate(exps)
    assert rate == 0.5  # 1 - 0.5


def test_average_confidence():
    exps = [
        _make_experience("S1", confidence=0.6),
        _make_experience("S1", confidence=0.8),
        _make_experience("S2", confidence=1.0),
    ]
    avg = EvaluationMetrics.average_confidence(exps)
    assert abs(avg - 0.8) < 0.01


def test_recommendation_diversity():
    exps = [
        _make_experience("S1", offset_min=0),
        _make_experience("S2", offset_min=1),
        _make_experience("S3", offset_min=2),
    ]
    # 3 unique schemes, each 1/3 → max entropy → diversity = 1.0
    diversity = EvaluationMetrics.recommendation_diversity(exps)
    assert diversity == 1.0


def test_recommendation_diversity_single_scheme():
    exps = [
        _make_experience("S1", offset_min=0),
        _make_experience("S1", offset_min=1),
        _make_experience("S1", offset_min=2),
    ]
    # All same scheme → entropy = 0 → diversity = 0.0
    diversity = EvaluationMetrics.recommendation_diversity(exps)
    assert diversity == 0.0


def test_hybrid_recommendation_rate():
    exp_no_hybrid = _make_experience("S1")
    exp_with_hybrid = _make_experience("S2")
    exp_with_hybrid.hybrid_combination = ["S2", "S3"]

    rate = EvaluationMetrics.hybrid_recommendation_rate([exp_no_hybrid, exp_with_hybrid])
    assert rate == 0.5  # 1 out of 2


def test_decision_latency_stats():
    traces = [
        DecisionTrace(processing_time_ms=5.0),
        DecisionTrace(processing_time_ms=10.0),
        DecisionTrace(processing_time_ms=15.0),
    ]
    stats = EvaluationMetrics.decision_latency_stats(traces)
    assert stats["min_ms"] == 5.0
    assert stats["max_ms"] == 15.0
    assert stats["avg_ms"] == 10.0


def test_confidence_trend_direction():
    # Increasing confidence
    exps_inc = [
        _make_experience("S1", confidence=0.5, offset_min=0),
        _make_experience("S1", confidence=0.6, offset_min=1),
        _make_experience("S1", confidence=0.7, offset_min=2),
        _make_experience("S1", confidence=0.9, offset_min=3),
    ]
    assert EvaluationMetrics.confidence_trend_direction(exps_inc) == "increasing"

    # Stable
    exps_stable = [
        _make_experience("S1", confidence=0.8, offset_min=0),
        _make_experience("S1", confidence=0.8, offset_min=1),
    ]
    assert EvaluationMetrics.confidence_trend_direction(exps_stable) == "stable"

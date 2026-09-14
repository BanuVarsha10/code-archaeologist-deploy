"""End-to-end tests for the CAPSS Agent pipeline.

Tests the full flow: Context → Analysis → Reasoning → Policy → Memory.
Uses mocked dependencies for the CAPSSAgent but ensures the pipeline
contracts are satisfied.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from capss.agent.capss_agent import CAPSSAgent
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.policy import PrivacyPolicy, ValidationResult
from capss.schemas.recommendation import Recommendation, DecisionTrace, SchemeScore
from capss.schemas.experience import Experience


def _create_ctx(ue_id, slice_type="eMBB", dnn="internet", reg_type="initial"):
    return RegistrationContext(
        ue_id=ue_id,
        suci=f"suci-0-001-01-0000-0-0-{ue_id}",
        registration_type=reg_type,
        slice_type=slice_type,
        dnn=dnn,
        timestamp=datetime.now(timezone.utc),
    )


def _make_mock_req_profile():
    return RequirementProfile(
        threat_level="medium",
        privacy_requirement=0.5,
        tracking_risk=0.4,
        metadata_leakage_risk=0.5,
        correlation_risk=0.3,
        latency_requirement="medium",
        resource_profile="powerful",
        network_confidence=0.8,
        context_completeness=0.8,
        quantum_threat=False,
        anonymous_auth_required=False,
        identity_protection_required=True,
    )


def _make_mock_recommendation():
    trace = DecisionTrace(
        context_summary={"ue_id": "UE-1"},
        requirement_profile={"threat_level": "medium"},
        top_candidates=[
            SchemeScore(
                scheme_id="SCHEME-001", scheme_name="ECIES",
                short_name="ECIES", final_score=0.85,
            ),
        ],
        winner="ECIES",
        winner_score=0.85,
        processing_time_ms=5.0,
    )
    return Recommendation(
        primary_scheme="ECIES",
        primary_scheme_id="SCHEME-001",
        primary_score=0.85,
        reason="Selected ECIES due to highest fitness",
        confidence=0.82,
        risk_assessment="low",
        metric_breakdown={"sfs": 0.85},
        decision_trace=trace,
        explanation={"why_selected": "Highest overall score"},
        knowledge_version="v1.0",
        reasoning_version="1.0",
    )


def _make_mock_policy():
    return PrivacyPolicy(
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="ECIES selected",
        confidence=0.82,
        risk_assessment="low",
    )


def _make_mock_experience():
    return Experience(
        experience_id="exp-001",
        ue_id="UE-1",
        context_snapshot={},
        requirement_profile={},
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="test",
        confidence=0.82,
        decision_score=0.85,
        timestamp=datetime.now(timezone.utc),
        adaptation_count=0,
        success_count=0,
        failure_count=0,
        confidence_trend=[0.82],
        average_decision_score=0.85,
        experience_decay_factor=1.0,
        knowledge_version="v1",
        reasoning_version="v1",
    )


@pytest.fixture
def mock_agent(tmp_path):
    """Create a CAPSSAgent with all internal modules mocked."""
    exp_path = tmp_path / "mock_agent_exp.json"
    with patch('capss.agent.capss_agent.SchemeKnowledgeBase') as MockKB, \
         patch('capss.agent.capss_agent.ExperienceMemory') as MockMemory, \
         patch('capss.agent.capss_agent.ContextAnalyzer') as MockAnalyzer, \
         patch('capss.agent.capss_agent.ReasoningEngine') as MockEngine, \
         patch('capss.agent.capss_agent.PolicyGenerator') as MockGen, \
         patch('capss.agent.capss_agent.PolicyValidator') as MockVal, \
         patch('capss.agent.capss_agent.MemoryUpdater') as MockUpdater:

        agent = CAPSSAgent("dummy_schemes.json", experience_path=str(exp_path))

        # Configure mocks with real Pydantic objects
        agent.analyzer.analyze.return_value = _make_mock_req_profile()
        agent.engine.reason.return_value = _make_mock_recommendation()
        agent.generator.generate.return_value = _make_mock_policy()
        agent.validator.validate.return_value = ValidationResult(is_valid=True)
        agent.updater.update.return_value = _make_mock_experience()
        agent.memory.retrieve.return_value = []
        agent.knowledge_base.get_scheme_count.return_value = 8

        yield agent


# ------------------------------------------------------------------ Tests

def test_single_registration(mock_agent):
    ctx = _create_ctx("UE-1")
    policy = mock_agent.process_registration(ctx, verbose=False)
    assert isinstance(policy, PrivacyPolicy)
    assert policy.selected_scheme == "ECIES"
    mock_agent.analyzer.analyze.assert_called_once()
    mock_agent.engine.reason.assert_called_once()
    mock_agent.generator.generate.assert_called_once()


def test_batch_processing(mock_agent):
    contexts = [_create_ctx(f"UE-{i}") for i in range(3)]
    policies = mock_agent.process_batch(contexts, verbose=False)
    assert len(policies) == 3
    assert mock_agent.engine.reason.call_count == 3


def test_adaptation_over_time(mock_agent):
    contexts = [_create_ctx("UE-1") for _ in range(5)]
    policies = mock_agent.process_batch(contexts, verbose=False)
    assert len(policies) == 5
    assert mock_agent.memory.store.call_count == 5


def test_different_contexts(mock_agent):
    ctx1 = _create_ctx("UE-1", slice_type="eMBB", dnn="internet")
    ctx2 = _create_ctx("UE-2", slice_type="URLLC", dnn="enterprise")
    ctx3 = _create_ctx("UE-3", slice_type="mMTC", dnn="iot")

    mock_agent.process_registration(ctx1, verbose=False)
    mock_agent.process_registration(ctx2, verbose=False)
    mock_agent.process_registration(ctx3, verbose=False)

    assert mock_agent.analyzer.analyze.call_count == 3


def test_experience_memory_persistence(mock_agent):
    ctx = _create_ctx("UE-1")
    mock_agent.process_registration(ctx, verbose=False)
    mock_agent.memory.store.assert_called_once()


def test_decision_trace_completeness(mock_agent):
    ctx = _create_ctx("UE-1")
    mock_agent.process_registration(ctx, verbose=False)
    assert len(mock_agent.decision_traces) == 1
    trace = mock_agent.decision_traces[0]
    assert trace.processing_time_ms > 0


def test_explanation_quality(mock_agent):
    ctx = _create_ctx("UE-1")
    mock_agent.process_registration(ctx, verbose=False)
    assert len(mock_agent.policies_generated) == 1


def test_agent_stats(mock_agent):
    contexts = [_create_ctx(f"UE-{i}") for i in range(3)]
    mock_agent.process_batch(contexts, verbose=False)
    stats = mock_agent.get_agent_stats()
    assert stats["total_registrations_processed"] == 3
    assert stats["total_policies_generated"] == 3


def test_verbose_output_does_not_crash(mock_agent, capsys):
    """Verify verbose output works without crashing."""
    ctx = _create_ctx("UE-1")
    mock_agent.process_registration(ctx, verbose=True)
    captured = capsys.readouterr()
    assert "CAPSS Agent" in captured.out
    assert "ECIES" in captured.out

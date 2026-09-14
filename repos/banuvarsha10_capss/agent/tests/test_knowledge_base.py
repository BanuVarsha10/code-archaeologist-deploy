import pytest
import os
import json
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.schemas.context import RequirementProfile

@pytest.fixture
def mock_schemes_file(tmp_path):
    data = [
        {
            "id": "SCH-1",
            "name": "Scheme 1",
            "short_name": "S1",
            "description": "desc",
            "category": "cat",
            "primary_privacy_goal": "goal",
            "quantitative_metrics": {"privacy_score": 5},
            "cryptographic_characteristics": {"quantum_resistant": True},
            "hybrid_support": {"compatible_with": ["SCH-2"]},
            "decision_support": {
                "recommendation_profile": {
                    "reasoning_profile": {"threat_level": "high", "privacy_requirement": 0.8}
                }
            }
        },
        {
            "id": "SCH-2",
            "name": "Scheme 2",
            "short_name": "S2",
            "description": "desc",
            "category": "cat",
            "primary_privacy_goal": "goal",
            "quantitative_metrics": {"privacy_score": 3},
            "cryptographic_characteristics": {"quantum_resistant": False},
            "hybrid_support": {"compatible_with": []},
            "decision_support": {
                "recommendation_profile": {
                    "reasoning_profile": {"threat_level": "low", "latency_requirement": "ultra_low"}
                }
            }
        }
    ]
    file_path = tmp_path / "schemes.json"
    file_path.write_text(json.dumps(data))
    return str(file_path)

def test_loading_schemes(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    assert kb.get_scheme_count() == 2

def test_get_scheme(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    assert kb.get_scheme("SCH-1").short_name == "S1"
    assert kb.get_by_name("Scheme 2").id == "SCH-2"
    assert kb.get_by_short_name("S1").id == "SCH-1"

def test_get_all_schemes(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    schemes = kb.get_all_schemes()
    assert len(schemes) == 2
    assert schemes[0].id == "SCH-1"

def test_filter_quantum_resistant(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    qr = kb.filter_quantum_resistant()
    assert len(qr) == 1
    assert qr[0].id == "SCH-1"

def test_get_compatible_hybrids(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    hybrids = kb.get_compatible_hybrids("SCH-1")
    assert len(hybrids) == 1
    assert hybrids[0].id == "SCH-2"
    
    assert kb.get_compatible_hybrids("SCH-2") == []

def test_get_knowledge_coverage(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    # create dummy requirement profile
    req = RequirementProfile(
        threat_level="high", privacy_requirement=1.0, tracking_risk=0.5,
        metadata_leakage_risk=0.5, correlation_risk=0.5, latency_requirement="low",
        resource_profile="moderate", network_confidence=0.8, context_completeness=1.0
    )
    coverage, missing = kb.get_knowledge_coverage(req)
    # The dimensions are ["threat_level", "privacy_requirement", "latency_requirement", "resource_profile"]
    # SCH-1 covers threat_level, privacy_requirement
    # SCH-2 covers threat_level, latency_requirement
    # Covered: threat_level, privacy_requirement, latency_requirement
    # Missing: resource_profile
    assert coverage == 3 / 4
    assert "resource_profile" in missing
    assert "threat_level" not in missing

def test_unknown_scheme_returns_none(mock_schemes_file):
    kb = SchemeKnowledgeBase(mock_schemes_file)
    assert kb.get_scheme("UNKNOWN") is None
    assert kb.get_by_name("UNKNOWN") is None
    assert kb.get_by_short_name("UNKNOWN") is None

"""Unit and integration tests for the CAPSS Cross-UE RAG subsystem."""

import os
import time
from datetime import datetime
import pytest
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.agent.rag.experience_schema import profile_to_feature_vector, experience_to_feature_vector
from capss.agent.rag.vector_store import VectorStore
from capss.agent.rag.embedding_generator import EmbeddingGenerator
from capss.agent.rag.retriever import ExperienceRetriever
from capss.agent.capss_agent import CAPSSAgent


def _make_req_profile(**kwargs) -> RequirementProfile:
    defaults = {
        "threat_level": "medium",
        "privacy_requirement": 0.5,
        "tracking_risk": 0.3,
        "metadata_leakage_risk": 0.3,
        "correlation_risk": 0.3,
        "latency_requirement": "medium",
        "resource_profile": "powerful",
        "network_confidence": 0.8,
        "context_completeness": 1.0,
    }
    defaults.update(kwargs)
    return RequirementProfile(**defaults)


def test_experience_schema_feature_vectors():
    profile = _make_req_profile(
        threat_level="high",
        privacy_requirement=0.8,
        tracking_risk=0.7,
        metadata_leakage_risk=0.6,
        correlation_risk=0.5,
    )
    context = RegistrationContext(
        ue_id="UE-TEST-01",
        suci="suci-01",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime(2026, 7, 20, 10, 0, 0),
        attack_type="DUPLICATE_REGISTRATION",
    )
    vec = profile_to_feature_vector(profile, context)
    assert len(vec) == 13
    assert all(0.0 <= x <= 1.0 for x in vec)

    exp = Experience(
        ue_id="UE-TEST-01",
        context_snapshot={"slice_type": "eMBB", "registration_type": "initial", "attack_type": "none"},
        requirement_profile={"threat_level": "high", "privacy_requirement": 0.8},
        selected_scheme="ECIES",
        selected_scheme_id="SCHEME-001",
        reason="test",
        confidence=0.85,
    )
    exp_vec = experience_to_feature_vector(exp)
    assert len(exp_vec) == 13
    assert all(0.0 <= x <= 1.0 for x in exp_vec)


def test_vector_store_operations(tmp_path):
    store = VectorStore()
    v1 = [1.0, 0.0, 0.0] + [0.0] * 10
    v2 = [0.9, 0.1, 0.0] + [0.0] * 10
    v3 = [0.0, 1.0, 0.0] + [0.0] * 10

    store.add("EXP-1", v1, {"ue_id": "UE-A"})
    store.add("EXP-2", v2, {"ue_id": "UE-B"})
    store.add("EXP-3", v3, {"ue_id": "UE-C"})

    res = store.query(v1, top_k=2)
    assert len(res) == 2
    assert res[0][0] == "EXP-1"
    assert res[1][0] == "EXP-2"

    # Filter out UE-A
    res_filtered = store.query(v1, top_k=2, filters={"exclude_ue_id": "UE-A"})
    assert res_filtered[0][0] == "EXP-2"

    # Persist and load
    save_path = tmp_path / "vec_store.json"
    store.persist(str(save_path))
    assert os.path.exists(save_path)

    store2 = VectorStore()
    store2.load(str(save_path))
    assert len(store2.ids) == 3


def test_cross_ue_retrieval_cold_start(tmp_path):
    """VERIFICATION CHECK 3: Cold-start UE-B comparison (Without RAG vs With RAG)."""
    # 1. Setup Agent A (Without cross-UE memory seeded)
    exp_path1 = tmp_path / "no_rag_exp.json"
    agent_no_rag = CAPSSAgent(schemes_path="data/privacy_schemes.json", experience_path=str(exp_path1))

    # 2. Setup Agent B (With 5 successful AP experiences seeded for UE-A)
    exp_path2 = tmp_path / "with_rag_exp.json"
    agent_with_rag = CAPSSAgent(schemes_path="data/privacy_schemes.json", experience_path=str(exp_path2))
    ap_scheme = agent_with_rag.knowledge_base.get_by_short_name("AP")

    for _ in range(5):
        exp = Experience(
            ue_id="UE-A",
            context_snapshot={"slice_type": "eMBB", "registration_type": "initial", "attack_type": "none"},
            requirement_profile={"threat_level": "medium", "privacy_requirement": 0.8, "metadata_leakage_risk": 0.9},
            selected_scheme="AP",
            selected_scheme_id=ap_scheme.id,
            reason="seed AP success",
            confidence=0.85,
            outcome="success",
            success_count=5,
            failure_count=0,
        )
        agent_with_rag.memory.store(exp)
        agent_with_rag.retriever.index_experience(exp)

    ctx_ue_b = RegistrationContext(
        ue_id="UE-B",
        suci="suci-b-01",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime(2026, 7, 20, 10, 0, 0),
        metadata_leakage=0.9,
    )

    # Process for UE-B without RAG
    policy_no_rag = agent_no_rag.process_registration(ctx_ue_b, verbose=False)
    rec_no_rag = agent_no_rag.recommendations[-1]
    eas_no_rag = rec_no_rag.decision_trace.candidate_scores[0].experience_alignment

    # Process for UE-B with RAG
    policy_with_rag = agent_with_rag.process_registration(ctx_ue_b, verbose=False)
    rec_with_rag = agent_with_rag.recommendations[-1]
    eas_with_rag = rec_with_rag.decision_trace.candidate_scores[0].experience_alignment
    exp_infl = rec_with_rag.explanation.get("experience_influence", "")

    print("\n" + "=" * 75)
    print("  VERIFICATION CHECK 3: COLD-START RETRIEVAL COMPARISON")
    print("=" * 75)
    print(f"  a) WITHOUT RAG (Old Behavior):")
    print(f"     Selected Scheme: {policy_no_rag.selected_scheme} | EAS: {eas_no_rag:.4f}")
    print(f"     Explanation:     {rec_no_rag.explanation.get('experience_influence')}")
    print(f"  b) WITH RAG (New Cross-UE Feature):")
    print(f"     Selected Scheme: {policy_with_rag.selected_scheme} | EAS: {eas_with_rag:.4f}")
    print(f"     Explanation:     {exp_infl}")
    print("=" * 75 + "\n")

    assert eas_no_rag == 0.5000  # Neutral baseline without RAG
    assert eas_with_rag > 0.5000  # Shifted higher by RAG cross-UE retrieval!
    assert "Cold start" in exp_infl or "cross-UE" in exp_infl


def test_cross_ue_retrieval_bypassed_when_sufficient_own_history(tmp_path):
    """VERIFICATION CHECK 4: Confirm cross-UE retrieval is skipped when UE has >= 3 experiences."""
    exp_path = tmp_path / "test_bypass_exp.json"
    agent = CAPSSAgent(schemes_path="data/privacy_schemes.json", experience_path=str(exp_path))
    ecies = agent.knowledge_base.get_by_short_name("ECIES")

    # Seed 3 experiences for UE-C (own history)
    for _ in range(3):
        exp = Experience(
            ue_id="UE-C",
            context_snapshot={},
            requirement_profile={},
            selected_scheme="ECIES",
            selected_scheme_id=ecies.id,
            reason="own history",
            confidence=0.8,
            outcome="success",
            success_count=3,
        )
        agent.memory.store(exp)
        agent.retriever.index_experience(exp)

    ctx = RegistrationContext(
        ue_id="UE-C",
        suci="suci-c-04",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime(2026, 7, 20, 10, 0, 0),
    )

    p = agent.process_registration(ctx, verbose=False)
    rec = agent.recommendations[-1]
    exp_infl = rec.explanation.get("experience_influence", "")

    print("\n[VERIFICATION 4] Cross-UE retrieval bypassed for UE with sufficient own history (>= 3)!")
    print(f"  Explanation: {exp_infl}")
    assert "3 previous experiences for UE-C" in exp_infl
    assert "cross-UE" not in exp_infl


def test_retrieval_performance_scaling():
    """VERIFICATION CHECK 5: Measure retrieve_similar() performance over 500 experiences."""
    retriever = ExperienceRetriever()

    # Index 500 experiences across 50 UEs
    for i in range(500):
        ue_id = f"UE-{i % 50}"
        exp = Experience(
            ue_id=ue_id,
            context_snapshot={"slice_type": "eMBB" if i % 2 == 0 else "URLLC", "registration_type": "initial"},
            requirement_profile={"privacy_requirement": (i % 10) / 10.0, "threat_level": "medium"},
            selected_scheme="ECIES" if i % 2 == 0 else "GS",
            selected_scheme_id="S1" if i % 2 == 0 else "S6",
            reason=f"scale test {i}",
            confidence=0.8,
        )
        retriever.index_experience(exp)

    req = _make_req_profile(threat_level="medium", privacy_requirement=0.5)

    start = time.perf_counter()
    matches = retriever.retrieve_similar(req, top_k=5, exclude_ue_id="UE-0")
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    print(f"\n[VERIFICATION 5] Retrieval time for 500 experiences: {elapsed_ms:.3f} ms")
    assert len(matches) == 5
    assert elapsed_ms < 50.0  # Well under 50ms performance target!

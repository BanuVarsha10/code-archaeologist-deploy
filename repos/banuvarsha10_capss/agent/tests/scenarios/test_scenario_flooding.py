"""Scenario 3: Flooding Attack Scenario Test.

Evaluates adaptive CAPSS against static baselines on DOS flooding attack conditions.
"""

import pytest
from datetime import datetime
from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.evaluation.benchmark import Benchmark


@pytest.fixture
def flooding_attack_contexts():
    """Create flooding attack contexts (BLOCK/TAG, flooding attack type)."""
    return [
        RegistrationContext(
            ue_id="UE-FLOOD-01",
            suci="suci-flood-01",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 10, 0, 0),
            request_classification="BLOCK",
            attack_type="flooding",
            attack_severity="critical",
            detection_confidence=0.96,
            threat_score=0.92,
            authentication_result="FAILED",
        ),
        RegistrationContext(
            ue_id="UE-FLOOD-02",
            suci="suci-flood-02",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 10, 0, 1),
            request_classification="BLOCK",
            attack_type="flooding",
            attack_severity="critical",
            detection_confidence=0.98,
            threat_score=0.95,
            authentication_result="FAILED",
        ),
        RegistrationContext(
            ue_id="UE-FLOOD-03",
            suci="suci-flood-03",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 10, 0, 2),
            request_classification="TAG",
            attack_type="flooding",
            attack_severity="high",
            detection_confidence=0.85,
            threat_score=0.80,
            authentication_result="FAILED",
        ),
    ]


def test_scenario_flooding(flooding_attack_contexts, tmp_path):
    exp_path = tmp_path / "test_flood_experience.json"
    agent = CAPSSAgent("data/privacy_schemes.json", experience_path=str(exp_path))
    benchmark = Benchmark(agent)

    res = benchmark.compare_against_all_static(flooding_attack_contexts)

    # Print comparison table
    print("\n" + "=" * 75)
    print("  SCENARIO EVALUATION: Flooding Attacks")
    print("=" * 75)
    print(f"{'Baseline':<12} | {'Adaptive Conf':<14} | {'Static Conf':<12} | {'Auth Success':<14} | {'Overhead (ms)':<14}")
    print("-" * 75)
    best_static_conf = 0.0
    for name, data in res.items():
        adap_c = data["adaptive"]["avg_confidence"]
        stat_c = data["static"]["avg_confidence"]
        auth_s = data["adaptive"]["authentication_success_rate"]
        over_h = data["adaptive"]["computational_overhead"]["mean_ms"]
        print(f"{name:<12} | {adap_c:<14.4f} | {stat_c:<12.4f} | {auth_s:<14.2f} | {over_h:<14.2f}")
        if stat_c > best_static_conf:
            best_static_conf = stat_c
    print("=" * 75 + "\n")

    sample_res = list(res.values())[0]
    adaptive_conf = sample_res["adaptive"]["avg_confidence"]

    assert adaptive_conf >= (best_static_conf - 0.20)

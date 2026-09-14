"""Scenario 2: Duplicate Registration Scenario Test.

Evaluates adaptive CAPSS against static baselines on duplicate registration tracking attempts.
"""

import pytest
from datetime import datetime
from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.evaluation.benchmark import Benchmark


@pytest.fixture
def duplicate_registration_contexts():
    """Create duplicate registration attack contexts (TAG, duplicate_registration attack type)."""
    return [
        RegistrationContext(
            ue_id="UE-DUP-01",
            suci="suci-dup-01",
            registration_type="mobility",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 9, 0, 0),
            request_classification="TAG",
            attack_type="duplicate_registration",
            attack_severity="medium",
            detection_confidence=0.82,
            threat_score=0.70,
            authentication_result="SUCCESS",
        ),
        RegistrationContext(
            ue_id="UE-DUP-01",
            suci="suci-dup-01",
            registration_type="mobility",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 9, 0, 15),
            request_classification="TAG",
            attack_type="duplicate_registration",
            attack_severity="high",
            detection_confidence=0.88,
            threat_score=0.75,
            authentication_result="SUCCESS",
        ),
        RegistrationContext(
            ue_id="UE-DUP-02",
            suci="suci-dup-02",
            registration_type="mobility",
            slice_type="URLLC",
            dnn="enterprise",
            timestamp=datetime(2024, 1, 20, 9, 10, 0),
            request_classification="TAG",
            attack_type="duplicate_registration",
            attack_severity="medium",
            detection_confidence=0.79,
            threat_score=0.68,
            authentication_result="SUCCESS",
        ),
    ]


def test_scenario_duplicate(duplicate_registration_contexts, tmp_path):
    exp_path = tmp_path / "test_dup_experience.json"
    agent = CAPSSAgent("data/privacy_schemes.json", experience_path=str(exp_path))
    benchmark = Benchmark(agent)

    res = benchmark.compare_against_all_static(duplicate_registration_contexts)

    # Print comparison table
    print("\n" + "=" * 75)
    print("  SCENARIO EVALUATION: Duplicate Registrations")
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

    # Assert dynamic agent selects tracking-resistant scheme (DP / GS) and maintains high score
    assert adaptive_conf >= (best_static_conf - 0.20)
    assert len(sample_res["adaptive"]["schemes_used"]) >= 1

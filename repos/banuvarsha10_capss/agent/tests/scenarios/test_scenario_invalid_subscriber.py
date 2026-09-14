"""Scenario 4: Invalid Subscriber Scenario Test.

Evaluates adaptive CAPSS against static baselines on invalid subscriber / identity spoofing attempts.
"""

import pytest
from datetime import datetime
from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.evaluation.benchmark import Benchmark


@pytest.fixture
def invalid_subscriber_contexts():
    """Create invalid subscriber attack contexts (BLOCK, invalid_subscriber attack type)."""
    return [
        RegistrationContext(
            ue_id="UE-INV-01",
            suci="suci-inv-01",
            registration_type="initial",
            slice_type="enterprise",
            dnn="enterprise",
            timestamp=datetime(2024, 1, 20, 11, 0, 0),
            request_classification="BLOCK",
            attack_type="invalid_subscriber",
            attack_severity="high",
            detection_confidence=0.91,
            threat_score=0.85,
            authentication_result="FAILED",
        ),
        RegistrationContext(
            ue_id="UE-INV-02",
            suci="suci-inv-02",
            registration_type="initial",
            slice_type="URLLC",
            dnn="ims",
            timestamp=datetime(2024, 1, 20, 11, 15, 0),
            request_classification="BLOCK",
            attack_type="invalid_subscriber",
            attack_severity="critical",
            detection_confidence=0.95,
            threat_score=0.90,
            authentication_result="FAILED",
        ),
        RegistrationContext(
            ue_id="UE-INV-03",
            suci="suci-inv-03",
            registration_type="emergency",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 11, 30, 0),
            request_classification="BLOCK",
            attack_type="invalid_subscriber",
            attack_severity="high",
            detection_confidence=0.89,
            threat_score=0.82,
            authentication_result="FAILED",
        ),
    ]


def test_scenario_invalid_subscriber(invalid_subscriber_contexts, tmp_path):
    exp_path = tmp_path / "test_inv_experience.json"
    agent = CAPSSAgent("data/privacy_schemes.json", experience_path=str(exp_path))
    benchmark = Benchmark(agent)

    res = benchmark.compare_against_all_static(invalid_subscriber_contexts)

    # Print comparison table
    print("\n" + "=" * 75)
    print("  SCENARIO EVALUATION: Invalid Subscriber")
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

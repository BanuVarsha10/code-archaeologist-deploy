"""Scenario 1: Normal Traffic Scenario Test.

Evaluates adaptive CAPSS against static baselines on legitimate registration traffic.
"""

import pytest
from datetime import datetime
from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.evaluation.benchmark import Benchmark


@pytest.fixture
def normal_traffic_contexts():
    """Create normal registration contexts (ALLOW, no attacks)."""
    return [
        RegistrationContext(
            ue_id="UE-NORM-01",
            suci="suci-norm-01",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 8, 0, 0),
            request_classification="ALLOW",
            attack_type="NONE",
            attack_severity="low",
            detection_confidence=0.02,
            threat_score=0.05,
            authentication_result="SUCCESS",
        ),
        RegistrationContext(
            ue_id="UE-NORM-02",
            suci="suci-norm-02",
            registration_type="initial",
            slice_type="URLLC",
            dnn="ims",
            timestamp=datetime(2024, 1, 20, 8, 15, 0),
            request_classification="ALLOW",
            attack_type="NONE",
            attack_severity="low",
            detection_confidence=0.01,
            threat_score=0.04,
            authentication_result="SUCCESS",
        ),
        RegistrationContext(
            ue_id="UE-NORM-03",
            suci="suci-norm-03",
            registration_type="periodic",
            slice_type="mMTC",
            dnn="iot",
            timestamp=datetime(2024, 1, 20, 8, 30, 0),
            request_classification="ALLOW",
            attack_type="NONE",
            attack_severity="low",
            detection_confidence=0.03,
            threat_score=0.06,
            authentication_result="SUCCESS",
        ),
    ]


def test_scenario_normal(normal_traffic_contexts, tmp_path):
    exp_path = tmp_path / "test_normal_experience.json"
    agent = CAPSSAgent("data/privacy_schemes.json", experience_path=str(exp_path))
    benchmark = Benchmark(agent)

    res = benchmark.compare_against_all_static(normal_traffic_contexts)

    # Print comparison table
    print("\n" + "=" * 75)
    print("  SCENARIO EVALUATION: Normal Traffic")
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

    # Assert dynamic agent confidence is >= best static baseline or acceptable margin
    sample_res = list(res.values())[0]
    adaptive_conf = sample_res["adaptive"]["avg_confidence"]
    assert adaptive_conf >= (best_static_conf - 0.20)
    assert sample_res["adaptive"]["authentication_success_rate"] == 1.0

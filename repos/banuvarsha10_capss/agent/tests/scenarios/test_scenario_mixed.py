"""Scenario 5: Mixed Traffic Conditions Scenario Test.

Evaluates adaptive CAPSS against static baselines under mixed realistic production traffic.
"""

import pytest
from datetime import datetime
from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.evaluation.benchmark import Benchmark


@pytest.fixture
def mixed_traffic_contexts():
    """Create mixed operational traffic contexts combining normal and attack scenarios."""
    return [
        # Normal 1
        RegistrationContext(
            ue_id="UE-MIX-01",
            suci="suci-mix-01",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 12, 0, 0),
            request_classification="ALLOW",
            attack_type="NONE",
            attack_severity="low",
            detection_confidence=0.02,
            threat_score=0.05,
            authentication_result="SUCCESS",
        ),
        # Replay Attack
        RegistrationContext(
            ue_id="UE-MIX-02",
            suci="suci-mix-02",
            registration_type="mobility",
            slice_type="URLLC",
            dnn="ims",
            timestamp=datetime(2024, 1, 20, 12, 5, 0),
            request_classification="TAG",
            attack_type="replay",
            attack_severity="medium",
            detection_confidence=0.75,
            threat_score=0.65,
            authentication_result="SUCCESS",
        ),
        # Flooding Attack
        RegistrationContext(
            ue_id="UE-MIX-03",
            suci="suci-mix-03",
            registration_type="initial",
            slice_type="eMBB",
            dnn="internet",
            timestamp=datetime(2024, 1, 20, 12, 10, 0),
            request_classification="BLOCK",
            attack_type="flooding",
            attack_severity="critical",
            detection_confidence=0.95,
            threat_score=0.92,
            authentication_result="FAILED",
        ),
        # Invalid Subscriber
        RegistrationContext(
            ue_id="UE-MIX-04",
            suci="suci-mix-04",
            registration_type="initial",
            slice_type="enterprise",
            dnn="enterprise",
            timestamp=datetime(2024, 1, 20, 12, 15, 0),
            request_classification="BLOCK",
            attack_type="invalid_subscriber",
            attack_severity="high",
            detection_confidence=0.91,
            threat_score=0.85,
            authentication_result="FAILED",
        ),
        # Normal 2 (mMTC)
        RegistrationContext(
            ue_id="UE-MIX-05",
            suci="suci-mix-05",
            registration_type="periodic",
            slice_type="mMTC",
            dnn="iot",
            timestamp=datetime(2024, 1, 20, 12, 20, 0),
            request_classification="ALLOW",
            attack_type="NONE",
            attack_severity="low",
            detection_confidence=0.01,
            threat_score=0.03,
            authentication_result="SUCCESS",
        ),
    ]


def test_scenario_mixed(mixed_traffic_contexts, tmp_path):
    exp_path = tmp_path / "test_mix_experience.json"
    agent = CAPSSAgent("data/privacy_schemes.json", experience_path=str(exp_path))
    benchmark = Benchmark(agent)

    res = benchmark.compare_against_all_static(mixed_traffic_contexts)

    # Print comparison table
    print("\n" + "=" * 75)
    print("  SCENARIO EVALUATION: Mixed Traffic Conditions")
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

    # Assert adaptive agent dynamically selects distinct schemes across mixed traffic
    assert len(sample_res["adaptive"]["schemes_used"]) >= 2
    assert adaptive_conf >= (best_static_conf - 0.20)

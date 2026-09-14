"""Test User Flow Script for CAPSS Adaptive Privacy System.

Simulates a 3-step user registration sequence:
  1. Normal registration → Baseline scheme (ECIES)
  2. Registration with Privacy Issue (Tracking Attack) → Adaptive scheme (GS / DP)
  3. Registration with Linkability & Multi-Vector Threat → Hybrid scheme (2 mechanisms together)
"""

import os
import sys

# Ensure project root is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from capss.agent.capss_agent import CAPSSAgent
from capss.schemas.context import RegistrationContext

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_test():
    agent = CAPSSAgent("data/privacy_schemes.json")
    agent.reset()

    print("\n" + "=" * 68)
    print("  CAPSS USER SCENARIO TEST: ADAPTATION & HYBRID SCHEMES")
    print("=" * 68)

    # ------------------------------------------------------------------
    # Step 1: Normal Registration
    # ------------------------------------------------------------------
    print("\n[STEP 1] User registers under normal conditions...")
    ctx1 = RegistrationContext(
        ue_id="imsi-user-01",
        suci="suci-0-999-70-0000000001",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.now(),
        request_classification="ALLOW",
        attack_type="NONE",
        authentication_result="SUCCESS",
    )
    policy1 = agent.process_registration(ctx1, verbose=True)

    # ------------------------------------------------------------------
    # Step 2: Privacy Issue Detected (Tracking / Duplicate Registration Attack)
    # ------------------------------------------------------------------
    print("\n[STEP 2] Next registration — Privacy Issue / Tracking Attack detected!")
    ctx2 = RegistrationContext(
        ue_id="imsi-user-01",
        suci="suci-0-999-70-0000000001",
        registration_type="mobility",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.now(),
        request_classification="TAG",
        attack_type="duplicate_registration",
        attack_severity="high",
        detection_confidence=0.88,
        threat_score=0.80,
        authentication_result="SUCCESS",
    )
    policy2 = agent.process_registration(ctx2, verbose=True)

    # ------------------------------------------------------------------
    # Step 3: Linkability / Multi-Vector Threat (Triggers 2 Mechanisms Together)
    # ------------------------------------------------------------------
    print("\n[STEP 3] Current registration — Linkability & Multi-Vector Threat detected!")
    ctx3 = RegistrationContext(
        ue_id="imsi-user-01",
        suci="suci-0-999-70-0000000001",
        registration_type="initial",
        slice_type="eMBB",
        dnn="internet",
        timestamp=datetime.now(),
        request_classification="TAG",
        attack_type="flooding",
        attack_severity="critical",
        correlation_score=0.90,
        metadata_leakage=0.85,
        threat_score=0.90,
        authentication_result="SUCCESS",
    )
    policy3 = agent.process_registration(ctx3, verbose=True)

    print("\n" + "=" * 68)
    print("  SUMMARY OF USER ADAPTATION TEST")
    print("=" * 68)
    print(f"  Step 1 (Normal):            Scheme → {policy1.selected_scheme}")
    print(f"  Step 2 (Privacy Issue):     Scheme → {policy2.selected_scheme}")
    print(f"  Step 3 (Linkability Risk): Scheme → {policy3.selected_scheme}")
    print(f"                             Hybrid → {policy3.hybrid_schemes} (2 mechanisms together!)")
    print("=" * 68 + "\n")


if __name__ == "__main__":
    run_test()

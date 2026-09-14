"""dashboard_backend/scenario_builder.py

TEST-FIXTURE HELPER — no longer used by production Attack Testing. Attack
Testing is Live Mode only now (Part C): real devices get their
RegistrationRequest sequence from live_mode.parse_amf_log_for_device()
(a real, parsed AMF log), not from this synthetic builder. Kept because
dashboard_backend/tests/test_systems_privacy_view.py still uses it as a
convenient way to build realistic request sequences without needing real
hardware — see also tests/live_fixtures.py, which builds equivalent
sequences directly via demo_for_mentor.make_request() for the Live Mode
orchestration tests.

Builds the ordered RegistrationRequest sequence for each dashboard attack
scenario, for ONE fresh UE. These are plain data objects — this module does
NOT touch Systems/Privacy/Agent itself; systems_privacy_view.py is what
actually runs them through the real, unmodified pipeline code.

Timing per scenario mirrors demo_for_mentor.py's own proven Scenario 1
recipe (systems/pre_amf/attack_rules.py thresholds: REPLAY_INTERVAL=2s,
DUPLICATE_INTERVAL=10s, MAX_REGISTRATIONS_PER_WINDOW=5 within a 30s
REGISTRATION_WINDOW) — verified empirically in
tests/test_scenario_builder.py by asserting the real resulting
ClassificationResult.attack_type for each case, not assumed from the
threshold constants alone.

"mixed" here has always genuinely been a duplicate-then-replay chain (see
below) — Live Mode's REAL "mixed" used to diverge from this and silently
alias duplicate_registration's timing instead (a real gap, found during the
Bug 2 diagnosis and fixed afterward: live_mode.py's _launch_pattern_for now
also chains a duplicate-timed pair into a replay-timed follow-up). Both
"mixed" implementations describe the same intent again as of that fix.

make_request() is imported directly from demo_for_mentor.py (import-safe:
guarded by `if __name__ == "__main__":`) rather than re-implemented, so the
RegistrationRequest shape stays identical to the project's own proven demo.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from systems.pre_amf.models import RegistrationRequest
from demo_for_mentor import make_request

SCENARIOS = (
    "replay",
    "duplicate_registration",
    "flooding",
    "invalid_subscriber",
    "mixed",
)


def build_scenario_requests(
    ue_id: str,
    suci: str,
    attack_scenario: str,
    base_time: datetime | None = None,
) -> List[RegistrationRequest]:
    """Returns the ordered request sequence for one UE under one scenario.

    The FIRST request is always a clean baseline (registration_count == 0
    for this UE beforehand). For every scenario except invalid_subscriber,
    the LAST request is the one whose resulting ClassificationResult shows
    the intended attack_type.
    """
    base_time = base_time or datetime(2026, 1, 1, 12, 0, 0)

    if attack_scenario not in SCENARIOS:
        raise ValueError(f"Unknown attack_scenario: {attack_scenario!r}")

    if attack_scenario == "replay":
        return [
            make_request(ue_id, suci, "R1", 0, base_time=base_time),
            make_request(ue_id, suci, "R2", 1, base_time=base_time),  # 1s <= REPLAY_INTERVAL(2s)
        ]

    if attack_scenario == "duplicate_registration":
        return [
            make_request(ue_id, suci, "D1", 0, base_time=base_time),
            make_request(ue_id, suci, "D2", 5, base_time=base_time),  # 5s <= DUPLICATE_INTERVAL(10s)
        ]

    if attack_scenario == "flooding":
        # 6 requests, 5s apart, all inside the 30s window: rate_monitor sees
        # 5 PRIOR timestamps (its own append happens after detect()) on the
        # 6th request, meeting MAX_REGISTRATIONS_PER_WINDOW(5) -> FLOOD.
        return [
            make_request(ue_id, suci, f"F{i+1}", i * 5, base_time=base_time)
            for i in range(6)
        ]

    if attack_scenario == "invalid_subscriber":
        # Single request only — see pipeline_service.py for why this
        # scenario has no before/after comparison (Issue 2 fix, Option B).
        return [
            make_request(ue_id, suci, "I1", 0, base_time=base_time),
        ]

    # mixed: baseline -> duplicate (5s) -> replay (1s later) — exercises
    # more than one detector across the sequence before landing on REPLAY.
    return [
        make_request(ue_id, suci, "M1", 0, base_time=base_time),
        make_request(ue_id, suci, "M2", 5, base_time=base_time),
        make_request(ue_id, suci, "M3", 6, base_time=base_time),
    ]

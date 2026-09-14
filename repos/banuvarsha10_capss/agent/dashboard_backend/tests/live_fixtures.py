"""dashboard_backend/tests/live_fixtures.py

Shared test-only helper for exercising the Live Mode 13-step flow
(pipeline_service.run_live_device) WITHOUT real hardware: mocks only
live_mode.py's real-hardware boundary (provision_subscriber /
run_baseline_registration / run_attack_registration /
run_stability_replay_registration / parse_amf_log_for_device) while every
real CAPSS layer underneath — SystemsPrivacyView, assess_adaptation,
CAPSSAgent, ReasoningEngine — runs for real, against realistic
RegistrationRequest timing built via demo_for_mentor.make_request (the
same helper scenario_builder.py already reuses for the same reason).

There is no real gNB/MongoDB/UERANSIM reachable from this test
environment — see live_mode.py's own module docstring for what WAS
verified against real hardware, and dashboard_backend/tests/test_live_mode.py
for this project's existing convention of mocking exactly this boundary.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import Optional
from unittest.mock import patch

from demo_for_mentor import make_request

from dashboard_backend import live_mode

# How many real nr-ue launches each scenario's real attack-timing pattern
# uses — must match live_mode._launch_pattern_for() exactly, since that is
# what run_attack_registration/run_stability_replay_registration call in
# production; these fixtures replicate its launch COUNT, not its sleeps
# (tests should not spend real wall-clock time on the sleep schedule).
ATTACK_LAUNCH_COUNTS = {"flooding": 6, "replay": 2, "duplicate_registration": 2, "mixed": 2}


class FakeAmfLog:
    """Simulates parse_amf_log_for_device()'s real cumulative-list
    behavior (every call re-parses the WHOLE log and returns everything
    seen so far) without touching a real log file."""

    def __init__(self, ue_id: str, suci: str, base_time: Optional[datetime] = None):
        self.ue_id = ue_id
        self.suci = suci
        self.base_time = base_time or datetime(2026, 1, 1, 12, 0, 0)
        self._requests: list = []
        self._offset = 0
        self._n = 0

    def add_launch(self) -> None:
        """Call once per real nr-ue launch under test — mirrors one more
        registration becoming visible in the real AMF log."""
        self._n += 1
        self._requests.append(
            make_request(self.ue_id, self.suci, f"R{self._n}", self._offset, base_time=self.base_time)
        )
        self._offset += 1

    def snapshot(self, *_args, **_kwargs) -> list:
        return list(self._requests)


@contextmanager
def mock_live_hardware(
    ue_id: str,
    suci: str,
    key_hex: str = "A" * 32,
    opc_hex: str = "B" * 32,
    fail_at: Optional[str] = None,
    fail_replay_number: Optional[int] = None,
):
    """Patches live_mode's real-hardware boundary so run_live_device() (and
    anything streaming it) exercises its REAL orchestration logic end to
    end, deterministically and instantly.

    fail_at: one of "provision" / "baseline" / "attack" — makes that step
        return success=False, exercising Part F step 13 failure isolation.
    fail_replay_number: 1 / 2 / 3 — makes that specific stability replay
        fail (Part H's mid-flow failure-isolation test).

    Yields (creds, log) — `log` exposes the accumulated fake requests if a
    test needs to assert on real launch counts.
    """
    creds = live_mode.LiveCredentials(imsi=ue_id, suci=suci, key_hex=key_hex, opc_hex=opc_hex)
    log = FakeAmfLog(ue_id, suci)

    def fake_provision(attack_scenario, creds_arg, is_returning, on_stage=None):
        if fail_at == "provision":
            return live_mode.ProvisionOutcome(
                creds=creds_arg, config_path=None, success=False, failure_reason="simulated provision failure",
            )
        return live_mode.ProvisionOutcome(
            creds=creds_arg, config_path="fake_config.yaml", success=True, failure_reason=None,
        )

    def fake_baseline(config_path, creds_, on_stage=None):
        if fail_at == "baseline":
            return live_mode.RegistrationEventOutcome(
                success=False, failure_reason="simulated baseline failure", launch_count=0,
            )
        log.add_launch()
        return live_mode.RegistrationEventOutcome(success=True, failure_reason=None, launch_count=1)

    def fake_attack(config_path, creds_, attack_scenario, is_returning=False, on_stage=None):
        if fail_at == "attack":
            return live_mode.RegistrationEventOutcome(
                success=False, failure_reason="simulated attack failure", launch_count=0,
            )
        count = ATTACK_LAUNCH_COUNTS.get(attack_scenario, 1)
        for _ in range(count):
            log.add_launch()
        return live_mode.RegistrationEventOutcome(success=True, failure_reason=None, launch_count=count)

    def fake_replay(config_path, creds_, attack_scenario, replay_number, is_returning=False, on_stage=None):
        if fail_replay_number == replay_number:
            return live_mode.RegistrationEventOutcome(
                success=False, failure_reason=f"simulated replay {replay_number} failure", launch_count=0,
            )
        count = ATTACK_LAUNCH_COUNTS.get(attack_scenario, 1)
        for _ in range(count):
            log.add_launch()
        return live_mode.RegistrationEventOutcome(success=True, failure_reason=None, launch_count=count)

    with patch.object(live_mode, "provision_subscriber", side_effect=fake_provision), \
         patch.object(live_mode, "run_baseline_registration", side_effect=fake_baseline), \
         patch.object(live_mode, "run_attack_registration", side_effect=fake_attack), \
         patch.object(live_mode, "run_stability_replay_registration", side_effect=fake_replay), \
         patch.object(live_mode, "parse_amf_log_for_device", side_effect=log.snapshot):
        yield creds, log

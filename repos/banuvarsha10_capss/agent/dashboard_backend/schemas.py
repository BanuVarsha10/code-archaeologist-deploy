"""dashboard_backend/schemas.py

Pydantic request models for the dashboard API. Response bodies are plain
dicts built in pipeline_service.py / main.py — FastAPI's jsonable_encoder
already knows how to serialize the existing project's dataclasses
(ComparisonResult, MeasuredOverhead, AnalyticalRationale, AttackReport,
SchemeScore, ...) and pydantic models (PrivacyPolicy, RegistrationContext,
...) natively, so no separate response schema is re-declared here — doing
so would risk silently drifting from the real shapes those modules return.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from dashboard_backend.live_mode import MAX_LIVE_DEVICES

AttackScenario = Literal[
    "replay", "duplicate_registration", "flooding", "invalid_subscriber", "mixed"
]

# Selectable in Part E's "choose per device" blocking picker — excludes
# invalid_subscriber. See pipeline_service.py's module docstring: that
# scenario structurally cannot participate in the baseline-then-attack
# flow, since by the time the per-device picker fires (after baseline) a
# real subscriber has already been provisioned and registered, which
# contradicts invalid_subscriber's premise of a never-provisioned identity.
PerDeviceAttackScenario = Literal[
    "replay", "duplicate_registration", "flooding", "mixed"
]


class IdentityPair(BaseModel):
    """A previously-generated UE identity — used only by the Tier-2 Manual
    Scenario Builder's reuse_identity (lets the same synthetic UE undergo
    repeated manual scenarios). Attack Testing has no reuse concept: Live
    Mode always provisions a fresh real subscriber per device (Part F
    step 1) — Normal Mode, which is what identity reuse used to serve, was
    removed."""

    ue_id: str
    suci: str


class AttackTestRunRequest(BaseModel):
    """Attack Testing is Live Mode ONLY — every run is real, against the
    real Open5GS/UERANSIM stack (Normal/simulated mode was removed; there
    is no mode field anymore because there is only one mode).

    attack_mode selects how each device's attack scenario is decided
    (Part E):
      "same_for_all" — attack_scenario is picked once, before the batch
        starts, and applies to every device.
      "per_device"   — attack_scenario is left unset here; each device's
        scenario is chosen interactively, after ITS baseline registration
        completes, via POST /api/attack-test/select-scenario. The stream
        blocks on that device until a selection arrives.

    devices_this_run / new_devices_count (device-pool task — replaces the
    old flat num_devices field): most of this run's devices are pulled
    from the persistent device pool ("returning" — see device_pool.py) so
    their real experience history accumulates across sessions, which is
    what gives the Experience Timeline panel genuine longitudinal data.
    new_devices_count of THIS run's devices_this_run are freshly generated
    instead (added to the pool immediately, so they count as "returning"
    starting next session). Defaults to 0 — a plain run reuses the pool;
    generating fresh devices is a deliberate, explicit choice (needed to
    demonstrate cold-start + cross-UE RAG, which requires a device with no
    prior history). attack_scenario == "invalid_subscriber" bypasses the
    pool entirely for every device in the run — see
    pipeline_service.py's module docstring for why that scenario can never
    be a pool device.
    """

    attack_mode: Literal["same_for_all", "per_device"] = "same_for_all"
    attack_scenario: Optional[AttackScenario] = None
    devices_this_run: int = Field(default=1, ge=1, le=MAX_LIVE_DEVICES)
    new_devices_count: int = Field(default=0, ge=0, le=MAX_LIVE_DEVICES)

    @model_validator(mode="after")
    def _validate_scenario_choice(self) -> "AttackTestRunRequest":
        if self.attack_mode == "same_for_all":
            if self.attack_scenario is None:
                raise ValueError("attack_scenario is required when attack_mode is 'same_for_all'")
        elif self.attack_scenario is not None:
            raise ValueError("attack_scenario must be omitted when attack_mode is 'per_device' — it is chosen per device via /api/attack-test/select-scenario")
        if self.new_devices_count > self.devices_this_run:
            raise ValueError("new_devices_count cannot exceed devices_this_run")
        return self


class SelectScenarioRequest(BaseModel):
    """Resolves ONE device's pending attack-scenario selection when
    attack_mode == 'per_device' (Part E). run_id is the value the stream
    emitted in its first ("run_started") event; device_index matches the
    stream's own 0-based device index."""

    run_id: str
    device_index: int = Field(ge=0)
    attack_scenario: PerDeviceAttackScenario


class ManualScenarioRequest(BaseModel):
    """Tier-2 Manual Scenario Builder — describes the synthetic "attack"
    RegistrationContext directly (sliders), skipping Systems/Privacy
    simulation entirely. A clean baseline "pre" context is auto-derived for
    the same fresh identity so this converges on the same
    run_manual_and_assess() -> assess_adaptation() path Attack Testing uses.
    """

    threat_score: float = Field(default=0.5, ge=0.0, le=1.0)
    privacy_score: float = Field(default=0.5, ge=0.0, le=1.0)
    privacy_risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    metadata_leakage: float = Field(default=0.5, ge=0.0, le=1.0)
    correlation_score: float = Field(default=0.5, ge=0.0, le=1.0)
    detection_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    registration_type: Literal["initial", "mobility", "periodic", "emergency"] = "initial"
    slice_type: Literal["eMBB", "URLLC", "mMTC"] = "eMBB"
    dnn: str = "internet"
    attack_type: Optional[str] = None
    attack_severity: Literal["NORMAL", "SUSPICIOUS", "MALICIOUS"] = "SUSPICIOUS"
    request_classification: Literal["ALLOW", "TAG", "BLOCK"] = "TAG"
    # When set, this exact identity is reused instead of generating a fresh
    # one — lets the same UE undergo repeated manual scenarios (varying the
    # sliders each time) so the results are genuinely comparable.
    reuse_identity: Optional[IdentityPair] = None


class ScalingRunRequest(BaseModel):
    """Scaling/throughput panel — runs the FULL real pipeline (provision,
    real baseline + attack registration, Systems + Privacy, real
    assess_adaptation()) for device_count real devices, exactly like Attack
    Testing except: (1) Check 2's stability replay count is 1, not 3 —
    reusing assess_adaptation()'s replay_count parameter, explicitly for
    this panel only (see pipeline_service.run_scale_device()'s docstring)
    — a genuine scale/throughput measurement, not a re-verification of
    stability (already proven elsewhere with the real default of 3); (2)
    each device writes to a dedicated, reset-per-run scratch experience
    store, never the real persistent one Attack Testing/Manual Scenario
    Builder use. 100-500, matching the panel's slider range — a safe,
    user-controlled scale test, distinct from the separate until-failure
    stress test (dashboard_backend/scripts/stress_test.py)."""

    attack_scenario: AttackScenario = "duplicate_registration"
    device_count: int = Field(default=100, ge=100, le=500)

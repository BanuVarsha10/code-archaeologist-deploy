"""dashboard_backend/pipeline_service.py

The Part E convergence point: everything the dashboard needs, built from
existing, unmodified CAPSS code, calling CAPSSAgent.process_registration()
exactly once per real registration event that matters for recorded history.

Live Mode is the dashboard's ONLY mode (Normal/synthetic mode was removed).
Two entry points:
  run_live_device()       — Attack Testing's real per-device 13-step flow
  run_manual_and_assess()  — Tier-2 Manual Scenario Builder (caller-built contexts)

Both converge on assess_adaptation() (capss/scheme_execution/assessment.py)
for the actual before/after 4-check comparison — not reimplemented, not
modified, called exactly as-is. See systems_privacy_view.py's docstring for
why a Systems+Privacy-only prefix is used ahead of it.

invalid_subscriber is the one exception: an identity is either a known
subscriber or it isn't, so there is no meaningful prior baseline for the
SAME identity to compare against — and structurally, a baseline registration
for a subscriber that will later be revealed as never-provisioned makes no
sense (every registration attempt from an unknown subscriber is rejected
identically, real network wise). That scenario skips the baseline/attack/
assess_adaptation() flow entirely and calls the agent directly, exactly
once, to get a real, persisted recommendation (see run_live_device() below).

ARCHITECTURE NOTE — real stability replays vs. assess_adaptation()'s own
Check 2: assess_adaptation() may only be changed for the specific, narrow
reasons explicitly authorized task-by-task (the replay_count parameter;
the baseline-forcing fix's batch_position parameter) — never edited
freely. Its internal Check 2 (ComparisonResult.stability_confirmed) is a
SIMULATED replay — `replay_count` more agent calls on the same
attack_context object (3 by default for every real caller here), not
real new hardware registrations. What run_live_device() adds is a
SEPARATE, additional real-hardware layer on top:
3 more real nr-ue registrations under the same attack scenario, each
independently classified by Systems/Privacy and re-scored via the read-only
helper (never re-invoking the real agent) to check whether the deterministic
scorer still picks scheme_b. Both results are returned — comparison_result.
stability_confirmed (simulated, from the protected function) and
real_stability (real-hardware, computed here) — never conflated.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, List, Optional, Union

StageCallback = Optional[Callable[[str, Dict[str, Any]], None]]

# Part E: either a plain scenario string (resolved for the whole batch
# before any device starts — "same attack for all devices") or a zero-arg
# callable invoked AFTER this device's baseline completes, expected to
# block until the user picks THIS device's scenario ("choose per device").
# invalid_subscriber is never a valid return from the callable form — see
# module docstring; enforced by main.py's picker options, not re-checked
# here.
AttackScenarioResolver = Union[str, Callable[[], str]]


def _emit(on_stage: StageCallback, stage: str, **data: Any) -> None:
    if on_stage is not None:
        on_stage(stage, data)


from capss.scheme_execution.assessment import assess_adaptation, ComparisonResult
from capss.scheme_execution.registry import SchemeRegistry
from capss.scheme_execution.result import ExecutionResult
from capss.agent.capss_agent import CAPSSAgent
from capss.agent.rag.retriever import ExperienceRetriever
from capss.experience_memory.memory import ExperienceMemory
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.context_analyzer.analyzer import ContextAnalyzer
from capss.reasoning.engine import ReasoningEngine
from capss.schemas.context import RegistrationContext

from dashboard_backend.systems_privacy_view import SystemsPrivacyView
from dashboard_backend.identity_gen import mask_identity
from dashboard_backend.llm_explainer import generate_full_explanation

# Scenarios selectable by Part E's per-device (blocking) picker — excludes
# invalid_subscriber, which structurally cannot participate in the
# baseline-then-attack flow (see module docstring): by the time the picker
# fires (after baseline), a real subscriber has already been provisioned
# and a real baseline registration already completed, both of which
# contradict invalid_subscriber's premise of a never-provisioned identity.
PER_DEVICE_SELECTABLE_SCENARIOS = (
    "replay", "duplicate_registration", "flooding", "mixed",
)
# All scenarios selectable for the "same attack for all devices" mode,
# resolved once before any device starts.
ALL_SCENARIOS = PER_DEVICE_SELECTABLE_SCENARIOS + ("invalid_subscriber",)


def _build_read_only_retriever(memory: ExperienceMemory) -> ExperienceRetriever:
    """Mirrors CAPSSAgent.__init__'s own retriever setup exactly (indexing
    every existing experience across every UE into a fresh in-memory
    vector store) — read-only: ExperienceRetriever.index_experience() only
    builds an in-process index, it never touches the experience store
    file. Without this, ReasoningEngine.reason() would never attempt
    cross-UE retrieval at all (retriever=None short-circuits it), so the
    real RAG-style retrieval CAPSSAgent does internally would silently
    never run in this read-only re-scoring path.
    """
    retriever = ExperienceRetriever()
    for existing_ue_id in memory.get_all_ues():
        for exp in memory.retrieve(existing_ue_id):
            retriever.index_experience(exp)
    return retriever


def _read_only_recommendation(
    schemes_path: str,
    context: RegistrationContext,
    experiences: List[Any],
    retriever: ExperienceRetriever,
) -> Any:
    """The full Recommendation — decision_trace (all 7 SchemeScore),
    hybrid_combination/hybrid_benefit_score/hybrid_reason when the winner
    is a hybrid, AND explanation (why_selected, why_alternatives_rejected
    per losing scheme, rules_fired, experience_influence — including real
    cross-UE vector-similarity retrieval results when this UE has fewer
    than 3 of its own experiences, exactly as CAPSSAgent computes
    internally). Read-only: no agent invocation, no writes.

    `experiences` and `retriever` MUST be a snapshot taken BEFORE
    assess_adaptation() runs — NOT re-read afterward. Confirmed by direct
    reproduction: assess_adaptation()'s internal agent calls write new
    experience entries as they run, so re-reading the store after it
    returns shows MORE history than the specific internal call that
    produced comparison_result.scheme_b actually saw when it decided (one
    repro run: the real call saw 0 prior experiences; a naive post-write
    re-read saw 2). That mismatch can show a different ranking/winner on
    the Explainability/AI Agent panels than what Recommendation shows for
    the same device. Composed from the same pure sub-components CAPSSAgent
    uses internally (ContextAnalyzer.analyze / ReasoningEngine.reason —
    neither writes to the experience store); callers capture the snapshot
    via _build_read_only_retriever() + memory.retrieve() before calling
    assess_adaptation, and reuse it here afterward.

    Also used (this-task Part F) for the baseline preview (step 5-6) and
    each real stability replay (step 10) — neither of those is a real
    agent invocation either, for the same reason: they need "what scheme
    would the deterministic scorer pick for this context", not another
    persisted experience.
    """
    kb = SchemeKnowledgeBase(schemes_path)
    profile = ContextAnalyzer().analyze(context, experiences)
    return ReasoningEngine(kb, retriever=retriever).reason(context, profile, experiences)


_ADAPTATION_NOTE_CHANGED_RE = re.compile(r"^Changed from (\S+) to (.+)$")


def _corrected_explanation(explanation: Optional[Dict[str, Any]], comparison: ComparisonResult) -> Optional[Dict[str, Any]]:
    """AI Agent panel data-wiring fix (same class of bug as the Baseline
    card / DualExecutionPanel fix): capss/reasoning/explainer.py's
    adaptation_note (real, correctly generated, never modified here) is
    built from this UE's own real experience-history memory of what it
    previously recommended — e.g. "Changed from GS to Group Signatures
    because ...". That "from" scheme is a real, different concept from
    comparison_result.scheme_a (the dashboard's forced ECIES/ML-KEM
    comparison baseline, per the baseline-forcing fix) — the reasoning
    engine has no knowledge of that dashboard-level concept and was never
    meant to. Rather than teach capss/reasoning/ about it (out of scope,
    and unnecessary), this corrects ONLY the "from X" segment of the
    already-generated sentence to the value shown everywhere else on the
    dashboard (Baseline card, verdict text) — the "to Y because ..." tail
    is passed through verbatim, untouched, exactly as the reasoning
    engine wrote it.

    A no-op or None explanation returns unchanged (e.g. cold-start/first-
    registration/no-change notes never match the "Changed from " pattern
    and pass through as-is)."""
    if not explanation:
        return explanation
    note = explanation.get("adaptation_note")
    if not isinstance(note, str):
        return explanation
    match = _ADAPTATION_NOTE_CHANGED_RE.match(note)
    if not match:
        return explanation
    explanation["adaptation_note"] = f"Changed from {comparison.scheme_a} to {match.group(2)}"
    return explanation


def _build_steps(view: "SystemsPrivacyView", requests: List[Any]) -> List[Dict[str, Any]]:
    steps = []
    for req in requests:
        report, privacy_result, context, validation_context, minimization_result = view.process(req)
        steps.append(
            {
                "request_id": req.request_id,
                "timestamp": req.timestamp,
                "attack_report": report,
                "privacy_result": privacy_result,
                "context": context,
                "validation_breakdown": {
                    "header_result": validation_context.header_result,
                    "parameter_result": validation_context.parameter_result,
                    "subscriber_result": validation_context.subscriber_result,
                    "duplicate_result": validation_context.duplicate_result,
                    "rate_result": validation_context.rate_result,
                },
                "minimization": minimization_result,
            }
        )
    return steps


def _execution_result_to_dict(result: ExecutionResult) -> Dict[str, Any]:
    """ExecutionResult.output_value is raw bytes — not JSON-safe as-is (Part
    F steps 6/11 ask to show the actual output_value, not just timing/size).
    Hex-encoded here for display; every other field passes through as-is."""
    return {
        "success": result.success,
        "output_type": result.output_type,
        "output_value_hex": result.output_value.hex() if result.output_value else None,
        "generation_time_ms": result.generation_time_ms,
        "key_size_bytes": result.key_size_bytes,
        "output_size_bytes": result.output_size_bytes,
        "error": result.error,
        "scheme_name": result.scheme_name,
        "label": result.label,
        "is_placeholder": result.is_placeholder,
        "metadata": result.metadata,
    }


def _live_failure_result(
    ue_id: str, suci: str, masked_identity: str, attack_scenario: Optional[str], reason: str, device_origin: str,
    cancelled: bool = False,
    initial_registration_ms: Optional[float] = None,
    post_attack_computation_ms: Optional[float] = None,
) -> Dict[str, Any]:
    """Shaped like a full device result but marked failed at a specific real
    step — Part F step 13: any step failing marks THIS device failed with a
    specific reason; the batch continues to the next device.

    `cancelled` distinguishes a manual stop-attack request from a genuine
    failure (Part 2, stop-attack task) — nothing about a cancelled device
    actually went wrong, it just wasn't run (or wasn't finished) because
    the user asked the batch to stop. live_success stays False either way
    (this device did not produce a usable result), but callers/UI should
    label cancelled devices distinctly, never as "Failed".

    Performance panel task: `initial_registration_ms`/`post_attack_computation_ms`
    let a caller report whichever of the two timed stages genuinely
    completed before this failure — e.g. a device that fails during the
    real stability-replay layer (Step 10, after assess_adaptation() already
    returned) still has real, honest values for BOTH stages; a device that
    fails before either stage started gets None for both. Never a
    fabricated/partial measurement for a stage that didn't actually finish."""
    return {
        "ue_id": ue_id, "suci": suci, "masked_identity": masked_identity,
        "attack_scenario": attack_scenario, "steps": [], "cold_start": None,
        "baseline_preview": None, "baseline_execution": None,
        "comparison_result": None, "recommendation": None, "no_comparison_reason": None,
        "decision_trace": None, "hybrid_combination": None, "hybrid_benefit_score": None,
        "hybrid_reason": None, "explanation": None,
        "scheme_a_execution": None, "scheme_b_execution": None, "real_stability": None,
        "device_origin": device_origin, "cancelled": cancelled,
        "llm_explanation": None,  # no final ComparisonResult exists for this device to describe
        "live_success": False, "failure_reason": reason,
        "initial_registration_ms": initial_registration_ms,
        "post_attack_computation_ms": post_attack_computation_ms,
    }


def _cancelled_result(
    ue_id: str, suci: str, masked_identity: str, attack_scenario: Optional[str], device_origin: str,
    initial_registration_ms: Optional[float] = None,
    post_attack_computation_ms: Optional[float] = None,
) -> Dict[str, Any]:
    """A device stopped cleanly, between real steps, because of a manual
    stop-attack request — see _live_failure_result's `cancelled` docstring."""
    return _live_failure_result(
        ue_id, suci, masked_identity, attack_scenario, "Cancelled by user", device_origin, cancelled=True,
        initial_registration_ms=initial_registration_ms,
        post_attack_computation_ms=post_attack_computation_ms,
    )


def _run_invalid_subscriber_device(
    view: SystemsPrivacyView, schemes_path: str, experience_path: str, creds: Any, on_stage: StageCallback,
) -> Dict[str, Any]:
    """No baseline is possible for this scenario (see module docstring) —
    single real registration attempt from a never-provisioned subscriber,
    single direct agent call, no assess_adaptation(), no comparison.

    invalid_subscriber devices NEVER enter the device pool (device-pool
    task) — a never-provisioned identity can't meaningfully "return" as a
    known subscriber next session — so `creds` here is always freshly,
    ad hoc generated by the caller and labeled device_origin="new_requested"
    unconditionally; it's never persisted via device_pool.add_new()."""
    from dashboard_backend import live_mode

    provision = live_mode.provision_subscriber("invalid_subscriber", creds, is_returning=False, on_stage=on_stage)
    masked = mask_identity(creds.imsi)
    if not provision.success:
        return _live_failure_result(
            creds.imsi, creds.suci, masked, "invalid_subscriber", provision.failure_reason, "new_requested",
        )

    reg = live_mode.run_attack_registration(provision.config_path, creds, "invalid_subscriber", on_stage=on_stage)
    if not reg.success:
        return _live_failure_result(
            creds.imsi, creds.suci, masked, "invalid_subscriber", reg.failure_reason, "new_requested",
        )

    try:
        requests = live_mode.parse_amf_log_for_device(creds)
    except live_mode.LiveStepError as exc:
        _emit(on_stage, "step_failed", imsi=creds.imsi, reason=str(exc))
        return _live_failure_result(creds.imsi, creds.suci, masked, "invalid_subscriber", str(exc), "new_requested")

    _emit(on_stage, "registering_context", ue_id=creds.imsi)
    steps = _build_steps(view, requests)
    attack_context = steps[-1]["context"]
    _emit(on_stage, "registered", ue_id=creds.imsi, attack_report=steps[-1]["attack_report"])

    _emit(on_stage, "consulting_agent", ue_id=creds.imsi)
    agent = CAPSSAgent(schemes_path=schemes_path, experience_path=experience_path)
    policy = agent.process_registration(attack_context, verbose=False)
    _emit(on_stage, "agent_done", ue_id=creds.imsi, recommendation=policy)

    return {
        "ue_id": creds.imsi, "suci": creds.suci, "masked_identity": masked,
        "attack_scenario": "invalid_subscriber", "steps": steps, "cold_start": None,
        "baseline_preview": None, "baseline_execution": None,
        "comparison_result": None, "recommendation": policy,
        "no_comparison_reason": (
            "An identity is either a known subscriber or not — there is no "
            "meaningful prior baseline to compare against for this scenario."
        ),
        "decision_trace": None, "hybrid_combination": None, "hybrid_benefit_score": None,
        "hybrid_reason": None, "explanation": None,
        "scheme_a_execution": None, "scheme_b_execution": None, "real_stability": None,
        "device_origin": "new_requested", "cancelled": False,
        "llm_explanation": None,  # invalid_subscriber has no comparison_result to describe
        "live_success": True, "failure_reason": None,
        # Performance panel task: neither timed stage applies to this
        # scenario — there's no baseline registration and no
        # assess_adaptation() call (see module docstring on why
        # invalid_subscriber skips the baseline/attack/assess_adaptation
        # flow entirely) — None is the honest value, not a fabricated 0.
        "initial_registration_ms": None,
        "post_attack_computation_ms": None,
    }


def run_live_device(
    view: SystemsPrivacyView,
    schemes_path: str,
    experience_path: str,
    attack_scenario: AttackScenarioResolver,
    creds: Any,
    device_origin: str,
    on_stage: StageCallback = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    batch_position: int = 0,
) -> Dict[str, Any]:
    """The Part F 13-step real per-device Live Mode flow — Live Mode is now
    the dashboard's ONLY mode (Part C). Every registration is real, against
    the real Open5GS/UERANSIM stack; nothing here is simulated.

    `creds` and `device_origin` ("returning" | "new_requested" |
    "new_autofilled") are resolved by the CALLER (main.py, via
    device_pool.py's selection logic) before this runs — this function no
    longer generates its own credentials, so provisioning can correctly
    skip dbctl add / config generation for a returning device (see
    live_mode.provision_subscriber's docstring).

    `batch_position` — baseline-forcing fix: this device's real 0-indexed
    position in the current run (the caller's loop index, e.g. main.py's
    `_stream_devices()` index), passed straight through to
    assess_adaptation()'s `batch_position` so Check 1's forced ECIES/
    ML-KEM baseline alternates across the batch exactly like the "vs.
    static baseline" feature's own alternation — never derived from
    device identity/history. Defaults to 0 (always ECIES) for any caller
    that doesn't track a real batch position.

    Note this is UNRELATED to `baseline_preview` (Steps 5-6 below) — that
    separate, purely-informational read-only recommendation for the
    Pipeline Visualizer/Recommendation panels intentionally still reflects
    this device's real prior history; the baseline-forcing fix is scoped
    exactly to assess_adaptation()'s Check 1 (Assessment section's
    scheme_a), per that task's explicit scope.

    assess_adaptation() (Check 1's mechanism now forced per the baseline-
    forcing fix; every other check unmodified) is called EXACTLY ONCE per
    device below — the sole place CAPSSAgent.process_registration() runs
    "for real" (the call whose experience write is this device's actual
    recorded history — and, for a returning device, the entry that makes
    its Experience Timeline genuinely longitudinal). Everywhere else a
    scheme recommendation is needed (the baseline preview, each real
    stability replay) uses _read_only_recommendation() instead — zero
    extra agent invocations, zero extra experience writes.
    """
    from dashboard_backend import live_mode

    upfront_scenario = attack_scenario if isinstance(attack_scenario, str) else None

    if upfront_scenario == "invalid_subscriber":
        return _run_invalid_subscriber_device(view, schemes_path, experience_path, creds, on_stage)

    is_returning = device_origin == "returning"

    # --- Steps 1-3: provision a real subscriber + real UE config. The
    # scenario value only matters here to decide whether to skip dbctl add
    # for a NEW device (invalid_subscriber) — already ruled out above, so
    # any placeholder non-invalid_subscriber value is equivalent when the
    # real scenario isn't known yet (Part E per-device mode). For a
    # RETURNING device the scenario value doesn't matter at all — dbctl
    # add is always skipped (see provision_subscriber). ---
    provision = live_mode.provision_subscriber(
        upfront_scenario or "duplicate_registration", creds, is_returning, on_stage=on_stage,
    )
    masked = mask_identity(creds.imsi)
    if not provision.success:
        return _live_failure_result(
            creds.imsi, creds.suci, masked, upfront_scenario, provision.failure_reason, device_origin,
        )

    # --- Step 4: BASELINE REGISTRATION (real, single, non-attack timing) ---
    baseline_reg = live_mode.run_baseline_registration(provision.config_path, creds, on_stage=on_stage)
    if not baseline_reg.success:
        return _live_failure_result(
            creds.imsi, creds.suci, masked, upfront_scenario, baseline_reg.failure_reason, device_origin,
        )

    try:
        baseline_requests = live_mode.parse_amf_log_for_device(creds)
    except live_mode.LiveStepError as exc:
        _emit(on_stage, "step_failed", imsi=creds.imsi, reason=str(exc))
        return _live_failure_result(creds.imsi, creds.suci, masked, upfront_scenario, str(exc), device_origin)

    # --- Performance panel: Stage 1 timing ("Initial registration") —
    # wraps exactly the real computation the panel measures: Systems
    # classification + Privacy scoring (_build_steps, which calls
    # SystemsPrivacyView.process()) and the Agent's baseline recommendation
    # (_read_only_recommendation). Deliberately excludes the real hardware
    # nr-ue registration above (network wait time, not computation) and
    # baseline_execution below (real scheme-execution timing, already
    # measured on its own ExecutionResult.generation_time_ms and explicitly
    # out of scope for this aggregate — see the Performance panel task's
    # hard constraint). Same time.perf_counter() measurement style already
    # used by every scheme executor (capss/scheme_execution/base.py).
    _stage1_t0 = time.perf_counter()

    _emit(on_stage, "registering_context", ue_id=creds.imsi)
    baseline_steps = _build_steps(view, baseline_requests)
    pre_context = baseline_steps[-1]["context"]
    _emit(on_stage, "registered", ue_id=creds.imsi, attack_report=baseline_steps[-1]["attack_report"])

    # --- Steps 5-6: read-only baseline preview + its REAL execution ---
    memory = ExperienceMemory(experience_path)
    experiences_before_baseline = memory.retrieve(creds.imsi)
    cold_start = len(experiences_before_baseline) == 0
    retriever_before_baseline = _build_read_only_retriever(memory)
    baseline_preview = _read_only_recommendation(
        schemes_path, pre_context, experiences_before_baseline, retriever_before_baseline,
    )
    baseline_winner = baseline_preview.decision_trace.winner
    initial_registration_ms = (time.perf_counter() - _stage1_t0) * 1000.0
    _emit(on_stage, "baseline_previewed", ue_id=creds.imsi, winner=baseline_winner)

    registry = SchemeRegistry()
    baseline_execution = registry.execute(baseline_winner, {"supi": creds.imsi})
    _emit(on_stage, "baseline_executed", ue_id=creds.imsi, execution=_execution_result_to_dict(baseline_execution))

    # Stop-attack safe point (Part 2): baseline's real registration already
    # finished — nothing to interrupt mid-flight — so this is a clean place
    # to stop before starting the attack registration.
    if should_cancel and should_cancel():
        return _cancelled_result(
            creds.imsi, creds.suci, masked, upfront_scenario, device_origin,
            initial_registration_ms=initial_registration_ms,
        )

    # --- Step 7: ATTACK SELECTION (Part E) ---
    if upfront_scenario is not None:
        resolved_scenario = upfront_scenario
    else:
        _emit(on_stage, "awaiting_attack_selection", ue_id=creds.imsi)
        try:
            resolved_scenario = attack_scenario()  # blocks — see main.py's selection queue
        except Exception as exc:  # noqa: BLE001 — a selection timeout/error is a
            # per-device failure like any other real step (Part F step 13), not a
            # reason to crash the whole batch's worker thread.
            reason = f"No attack scenario was selected for this device: {exc}"
            _emit(on_stage, "step_failed", imsi=creds.imsi, reason=reason)
            return _live_failure_result(
                creds.imsi, creds.suci, masked, None, reason, device_origin,
                initial_registration_ms=initial_registration_ms,
            )
        _emit(on_stage, "attack_selected", ue_id=creds.imsi, attack_scenario=resolved_scenario)

    # --- Step 8: ATTACK REGISTRATION (real, scenario-timed) ---
    attack_reg = live_mode.run_attack_registration(
        provision.config_path, creds, resolved_scenario, is_returning=is_returning, on_stage=on_stage,
    )
    if not attack_reg.success:
        return _live_failure_result(
            creds.imsi, creds.suci, masked, resolved_scenario, attack_reg.failure_reason, device_origin,
            initial_registration_ms=initial_registration_ms,
        )

    try:
        after_attack = live_mode.parse_amf_log_for_device(creds)
    except live_mode.LiveStepError as exc:
        _emit(on_stage, "step_failed", imsi=creds.imsi, reason=str(exc))
        return _live_failure_result(
            creds.imsi, creds.suci, masked, resolved_scenario, str(exc), device_origin,
            initial_registration_ms=initial_registration_ms,
        )

    new_attack_requests = after_attack[len(baseline_requests):]
    if not new_attack_requests:
        reason = "AMF log parsing found no new registration after the attack step"
        _emit(on_stage, "step_failed", imsi=creds.imsi, reason=reason)
        return _live_failure_result(
            creds.imsi, creds.suci, masked, resolved_scenario, reason, device_origin,
            initial_registration_ms=initial_registration_ms,
        )

    # --- Performance panel: Stage 2 timing ("Post-attack computation") —
    # wraps Systems + Privacy classification of the attack event
    # (_build_steps) through assess_adaptation()'s full run (adaptation
    # check, stability, real scheme execution for both A and B, analytical
    # rationale), ending the instant it returns with the final verdict.
    # Deliberately excludes the real hardware attack registration above
    # (network wait time, already finished by this point) and Step 10/11
    # below (the separate real-hardware stability-replay layer and the
    # fresh official re-executions — out of scope for this aggregate).
    _stage2_t0 = time.perf_counter()

    attack_steps = _build_steps(view, new_attack_requests)
    attack_context = attack_steps[-1]["context"]
    _emit(on_stage, "attack_registered", ue_id=creds.imsi, attack_report=attack_steps[-1]["attack_report"])

    # Stop-attack safe point (Part 2): attack's real registration already
    # finished — stop before the (slower) assess_adaptation + stability
    # replay work starts.
    if should_cancel and should_cancel():
        # Stage 2 never reached a final verdict — no partial measurement
        # reported for it (see _live_failure_result's docstring); Stage 1
        # already completed, so that value is still reported honestly.
        return _cancelled_result(
            creds.imsi, creds.suci, masked, resolved_scenario, device_origin,
            initial_registration_ms=initial_registration_ms,
        )

    # --- Step 9: assess_adaptation() — the ONLY real agent invocation for
    # comparison purposes on this device's pre/attack pair. Snapshot BEFORE
    # it runs (same pre-write-snapshot fix as this task's Part B, Issue 1). ---
    experiences_snapshot = memory.retrieve(creds.imsi)
    retriever_snapshot = _build_read_only_retriever(memory)

    _emit(on_stage, "consulting_agent", ue_id=creds.imsi)
    comparison: ComparisonResult = assess_adaptation(
        creds.imsi, pre_context, attack_context, schemes_path, experience_path,
        batch_position=batch_position,
    )
    post_attack_computation_ms = (time.perf_counter() - _stage2_t0) * 1000.0
    # Hybrid execution gap fix: comparison.hybrid_partner_execution is a raw
    # ExecutionResult (real output_value bytes) exactly like scheme_a/scheme_b's
    # own executions — hex-encode it the same way _execution_result_to_dict()
    # already does for those before this ever reaches jsonable_encoder below
    # (raw bytes aren't JSON-serializable; this is the same boundary
    # scheme_a_execution/scheme_b_execution already cross a few lines down).
    if comparison.hybrid_partner_execution is not None:
        comparison.hybrid_partner_execution = _execution_result_to_dict(comparison.hybrid_partner_execution)
    _emit(on_stage, "assessment_done", ue_id=creds.imsi, comparison=comparison)

    # `recommendation` is computed BEFORE the LLM call below (reordered from
    # its previous position after the call) so the explainer can be given
    # the real, complete candidate_scores for all 7 schemes — needed for the
    # "why not the others" section. This does NOT touch the pre-write-
    # snapshot fix: _read_only_recommendation() already only depends on
    # experiences_snapshot/retriever_snapshot, captured above BEFORE
    # assess_adaptation() ran — moving where it's CALLED from doesn't change
    # what data it reads.
    recommendation = _read_only_recommendation(
        schemes_path, attack_context, experiences_snapshot, retriever_snapshot,
    )
    # AI Agent panel data-wiring fix — see _corrected_explanation()'s
    # docstring: rewrites adaptation_note's "from" scheme to the forced
    # baseline (comparison.scheme_a), never capss/reasoning/'s own text
    # generation.
    recommendation.explanation = _corrected_explanation(recommendation.explanation, comparison)
    _emit(
        on_stage, "ranking_done", ue_id=creds.imsi, decision_trace=recommendation.decision_trace,
        hybrid_combination=recommendation.hybrid_combination,
    )

    # --- LLM explainer (purely additive, isolated on purpose) ---
    # assess_adaptation() has ALREADY returned above; `comparison` is final
    # and cannot be affected by anything from here on. `recommendation` is a
    # read-only re-scoring (see _read_only_recommendation's docstring), not
    # a second real agent invocation. This call takes both as read-only
    # input text and asks an LLM to describe them in plain language — it
    # has no way to feed anything back into scheme_a/scheme_b/overall_verdict/
    # confidence/any score, and never blocks the real pipeline:
    # generate_full_explanation() has its own hard timeout and returns None
    # on ANY failure (see llm_explainer.py's module docstring) rather than
    # raising.
    llm_explanation = generate_full_explanation(
        comparison,
        recommendation.decision_trace.candidate_scores,
        hybrid_benefit_score=recommendation.hybrid_benefit_score,
        hybrid_reason=recommendation.hybrid_reason,
    )

    # --- Step 11: fresh, OFFICIAL executions of scheme_a/scheme_b — the
    # earlier baseline_execution (step 6) was a PREVIEW computed before the
    # attack was even known; this pair is guaranteed consistent with what
    # assess_adaptation() actually decided, for the final side-by-side. ---
    scheme_a_execution = registry.execute(comparison.scheme_a, {"supi": creds.imsi})
    scheme_b_execution = registry.execute(comparison.scheme_b, {"supi": creds.imsi})
    _emit(
        on_stage, "schemes_executed", ue_id=creds.imsi,
        scheme_a_execution=_execution_result_to_dict(scheme_a_execution),
        scheme_b_execution=_execution_result_to_dict(scheme_b_execution),
    )

    # --- Step 10: STABILITY CHECK VIA REAL REPLAYS (additional to, not a
    # replacement of, assess_adaptation()'s own simulated Check 2 — see
    # module docstring for why that internal check can't be altered). ---
    # A hardware/parsing failure on ANY of the 3 replays aborts this device
    # (Part F step 13 — "any step failing at any point marks THIS device
    # failed"), same as a baseline/attack failure would. A replay that
    # SUCCEEDS as a real registration but predicts a DIFFERENT scheme than
    # scheme_b is NOT a failure — that is real evidence of instability,
    # exactly what this check exists to discover, and must be recorded
    # rather than treated as an error.
    real_replays: List[Dict[str, Any]] = []
    seen_count = len(after_attack)
    for replay_number in range(1, 4):
        # Stop-attack safe point (Part 2): between replays only — never
        # mid-launch. Whatever replays already completed are simply
        # dropped along with the rest of this device's result; the
        # assess_adaptation() comparison this device would have produced
        # is not partially reported, consistent with every other Part F
        # step 13 failure mode (all-or-nothing per device).
        if should_cancel and should_cancel():
            # Both timed stages already completed successfully by this
            # point (Step 10 runs strictly after assess_adaptation()
            # returns) — report both real values, not None.
            return _cancelled_result(
                creds.imsi, creds.suci, masked, resolved_scenario, device_origin,
                initial_registration_ms=initial_registration_ms,
                post_attack_computation_ms=post_attack_computation_ms,
            )
        replay_reg = live_mode.run_stability_replay_registration(
            provision.config_path, creds, resolved_scenario, replay_number,
            is_returning=is_returning, on_stage=on_stage,
        )
        if not replay_reg.success:
            reason = f"Stability replay {replay_number}/3 failed: {replay_reg.failure_reason}"
            _emit(on_stage, "step_failed", imsi=creds.imsi, reason=reason)
            return _live_failure_result(
                creds.imsi, creds.suci, masked, resolved_scenario, reason, device_origin,
                initial_registration_ms=initial_registration_ms,
                post_attack_computation_ms=post_attack_computation_ms,
            )
        try:
            after_replay = live_mode.parse_amf_log_for_device(creds)
        except live_mode.LiveStepError as exc:
            reason = f"Stability replay {replay_number}/3 log parsing failed: {exc}"
            _emit(on_stage, "step_failed", imsi=creds.imsi, reason=reason)
            return _live_failure_result(
                creds.imsi, creds.suci, masked, resolved_scenario, reason, device_origin,
                initial_registration_ms=initial_registration_ms,
                post_attack_computation_ms=post_attack_computation_ms,
            )
        new_replay_requests = after_replay[seen_count:]
        seen_count = len(after_replay)
        if not new_replay_requests:
            reason = f"Stability replay {replay_number}/3: no new registration observed"
            _emit(on_stage, "step_failed", imsi=creds.imsi, reason=reason)
            return _live_failure_result(
                creds.imsi, creds.suci, masked, resolved_scenario, reason, device_origin,
                initial_registration_ms=initial_registration_ms,
                post_attack_computation_ms=post_attack_computation_ms,
            )

        replay_steps = _build_steps(view, new_replay_requests)
        replay_context = replay_steps[-1]["context"]
        replay_experiences = memory.retrieve(creds.imsi)
        replay_retriever = _build_read_only_retriever(memory)
        replay_recommendation = _read_only_recommendation(
            schemes_path, replay_context, replay_experiences, replay_retriever,
        )
        predicted = replay_recommendation.decision_trace.winner
        matches = predicted == comparison.scheme_b
        real_replays.append({
            "replay_number": replay_number, "success": True, "failure_reason": None,
            "predicted_scheme": predicted, "matches_scheme_b": matches,
        })
        _emit(
            on_stage, "stability_replay_done", ue_id=creds.imsi, replay_number=replay_number,
            predicted_scheme=predicted, matches_scheme_b=matches,
        )

    real_stability = {
        "confirmed": all(r["matches_scheme_b"] for r in real_replays),
        "replays": real_replays,
        "detail": (
            f"{sum(1 for r in real_replays if r['matches_scheme_b'])}/3 real replays "
            f"returned {comparison.scheme_b!r}"
        ),
    }
    _emit(on_stage, "real_stability_done", ue_id=creds.imsi, real_stability=real_stability)

    return {
        "ue_id": creds.imsi,
        "suci": creds.suci,
        "masked_identity": masked,
        "attack_scenario": resolved_scenario,
        "steps": baseline_steps + attack_steps,
        "cold_start": cold_start,
        "baseline_preview": {"winner": baseline_winner, "decision_trace": baseline_preview.decision_trace},
        "baseline_execution": _execution_result_to_dict(baseline_execution),
        "comparison_result": comparison,
        "recommendation": None,
        "no_comparison_reason": None,
        "decision_trace": recommendation.decision_trace,
        "hybrid_combination": recommendation.hybrid_combination,
        "hybrid_benefit_score": recommendation.hybrid_benefit_score,
        "hybrid_reason": recommendation.hybrid_reason,
        "explanation": recommendation.explanation,
        "scheme_a_execution": _execution_result_to_dict(scheme_a_execution),
        "scheme_b_execution": _execution_result_to_dict(scheme_b_execution),
        "real_stability": real_stability,
        "device_origin": device_origin,
        "cancelled": False,
        "llm_explanation": llm_explanation,
        "live_success": True,
        "failure_reason": None,
        "initial_registration_ms": initial_registration_ms,
        "post_attack_computation_ms": post_attack_computation_ms,
    }


def run_scale_device(
    view: SystemsPrivacyView,
    schemes_path: str,
    experience_path: str,
    attack_scenario: str,
    creds: Any,
    batch_position: int,
    replay_count: int = 1,
) -> Dict[str, Any]:
    """Full real pipeline per device — provisioning, real baseline
    registration, Systems + Privacy, real attack registration, Systems +
    Privacy, assess_adaptation() (Check 1's forced ECIES/ML-KEM baseline
    per `batch_position` — see the baseline-forcing fix; Check 2 stability
    at `replay_count`; Check 3 REAL scheme execution for both schemes;
    Check 4 real analytical rationale) — deliberately WITHOUT
    run_live_device()'s Step 10 (3 additional real hardware stability-
    replay registrations — a SEPARATE real-hardware layer on top of Check
    2, not controlled by `replay_count` at all), Step 11 (fresh official
    re-executions, already covered by Check 3's real execution here), or
    the LLM explainer call. Those measure something else (real-hardware
    replay stability already proven elsewhere with the real default of 3;
    UI display data; plain-language prose) and are orthogonal to what
    this function exists for: real per-device THROUGHPUT at scale.

    Shared by dashboard_backend/scripts/stress_test.py (the until-failure
    capacity search) and the Scaling panel (the 100-500 device throughput
    measurement) — both reuse this exact function rather than keeping
    their own copies, so their real per-device cost is identical and
    directly comparable.

    Returns a deliberately MINIMAL dict — no per-scheme candidate
    breakdown, no decision trace, no LLM text — a caller driving hundreds
    of these at once shouldn't have to pay for or transmit data nobody
    asked for at this scale (see the Scaling panel task's explicit
    "per-device display stays MINIMAL" requirement).
    """
    from dashboard_backend import live_mode

    t0 = time.perf_counter()
    masked = mask_identity(creds.imsi)

    def _fail(stage: str, reason: str) -> Dict[str, Any]:
        return {
            "ue_id": creds.imsi, "masked_identity": masked, "success": False,
            "stage": stage, "failure_reason": reason,
            "scheme_a": None, "scheme_b": None, "overall_verdict": None,
            "elapsed_s": time.perf_counter() - t0,
        }

    provision = live_mode.provision_subscriber(attack_scenario, creds, is_returning=False)
    if not provision.success:
        return _fail("provision", provision.failure_reason)

    baseline = live_mode.run_baseline_registration(provision.config_path, creds)
    if not baseline.success:
        return _fail("baseline_registration", baseline.failure_reason)

    try:
        baseline_requests = live_mode.parse_amf_log_for_device(creds)
    except live_mode.LiveStepError as exc:
        return _fail("baseline_log_parse", str(exc))

    baseline_steps = _build_steps(view, baseline_requests)
    pre_context = baseline_steps[-1]["context"]

    attack = live_mode.run_attack_registration(provision.config_path, creds, attack_scenario)
    if not attack.success:
        return _fail("attack_registration", attack.failure_reason)

    try:
        after_attack = live_mode.parse_amf_log_for_device(creds)
    except live_mode.LiveStepError as exc:
        return _fail("attack_log_parse", str(exc))

    new_attack_requests = after_attack[len(baseline_requests):]
    if not new_attack_requests:
        return _fail("attack_log_parse", "AMF log parsing found no new registration after the attack step")

    attack_steps = _build_steps(view, new_attack_requests)
    attack_context = attack_steps[-1]["context"]

    comparison = assess_adaptation(
        creds.imsi, pre_context, attack_context, schemes_path, experience_path,
        replay_count=replay_count, batch_position=batch_position,
    )
    return {
        "ue_id": creds.imsi, "masked_identity": masked, "success": True,
        "stage": "done", "failure_reason": None,
        "scheme_a": comparison.scheme_a, "scheme_b": comparison.scheme_b,
        "overall_verdict": comparison.overall_verdict,
        "elapsed_s": time.perf_counter() - t0,
    }


def run_manual_and_assess(
    pre_context: RegistrationContext,
    attack_context: RegistrationContext,
    schemes_path: str,
    experience_path: str,
    mode: str = "manual",
    on_stage: StageCallback = None,
) -> Dict[str, Any]:
    """Tier-2 Manual Scenario Builder entry point — same single convergence
    point (assess_adaptation), fed caller-built contexts instead of a real
    device's parsed AMF-log requests. Unaffected by this task's Normal-Mode
    removal (Part C) — this was never "Normal Mode", it's a separate
    sliders-driven tool for exploring synthetic contexts directly."""
    ue_id = attack_context.ue_id
    _emit(on_stage, "registered", ue_id=ue_id)
    _emit(on_stage, "attack_simulated", ue_id=ue_id, attack_report={
        "decision": attack_context.request_classification,
        "attack_type": attack_context.attack_type,
        "severity": attack_context.attack_severity,
    })
    # Snapshot BEFORE assess_adaptation() runs — see _read_only_recommendation's
    # docstring (same fix as run_live_device).
    memory = ExperienceMemory(experience_path)
    experiences_snapshot = memory.retrieve(ue_id)
    retriever_snapshot = _build_read_only_retriever(memory)

    # Performance panel task: Manual Scenario Builder has no real baseline
    # registration at all — pre_context/attack_context are both directly
    # caller-built from sliders, never derived from a real registration
    # via SystemsPrivacyView — so "Initial registration" genuinely does
    # not apply here (initial_registration_ms stays None below, honestly,
    # not a fabricated 0). "Post-attack computation" still applies: same
    # assess_adaptation()-only measurement as run_live_device's Stage 2,
    # minus the _build_steps() classification (there's no real attack
    # event to classify — attack_context is already-built input).
    _stage2_t0 = time.perf_counter()
    _emit(on_stage, "consulting_agent", ue_id=ue_id)
    comparison = assess_adaptation(
        ue_id, pre_context, attack_context, schemes_path, experience_path,
    )
    post_attack_computation_ms = (time.perf_counter() - _stage2_t0) * 1000.0
    # Hybrid execution gap fix — same raw-bytes-to-dict conversion as
    # run_live_device's identical call site; see that comment for why.
    if comparison.hybrid_partner_execution is not None:
        comparison.hybrid_partner_execution = _execution_result_to_dict(comparison.hybrid_partner_execution)
    _emit(on_stage, "assessment_done", ue_id=ue_id, comparison=comparison)

    # Reordered before the LLM call for the same reason as run_live_device's
    # identical reordering — see that function's comment.
    recommendation = _read_only_recommendation(
        schemes_path, attack_context, experiences_snapshot, retriever_snapshot,
    )
    # AI Agent panel data-wiring fix — see _corrected_explanation()'s
    # docstring: rewrites adaptation_note's "from" scheme to the forced
    # baseline (comparison.scheme_a), never capss/reasoning/'s own text
    # generation.
    recommendation.explanation = _corrected_explanation(recommendation.explanation, comparison)
    _emit(
        on_stage, "ranking_done", ue_id=ue_id, decision_trace=recommendation.decision_trace,
        hybrid_combination=recommendation.hybrid_combination,
    )

    # LLM explainer — same isolated, strictly-after-the-fact call as
    # run_live_device's (see pipeline_service.py imports / that function's
    # comment for the full guarantee).
    llm_explanation = generate_full_explanation(
        comparison,
        recommendation.decision_trace.candidate_scores,
        hybrid_benefit_score=recommendation.hybrid_benefit_score,
        hybrid_reason=recommendation.hybrid_reason,
    )
    return {
        "ue_id": ue_id,
        "suci": attack_context.suci,
        "masked_identity": mask_identity(ue_id),
        "mode": mode,
        "attack_scenario": "manual",
        "steps": [],
        "comparison_result": comparison,
        "recommendation": None,
        "no_comparison_reason": None,
        "decision_trace": recommendation.decision_trace,
        "hybrid_combination": recommendation.hybrid_combination,
        "hybrid_benefit_score": recommendation.hybrid_benefit_score,
        "hybrid_reason": recommendation.hybrid_reason,
        "llm_explanation": llm_explanation,
        "cold_start": None,
        "initial_registration_ms": None,
        "post_attack_computation_ms": post_attack_computation_ms,
    }

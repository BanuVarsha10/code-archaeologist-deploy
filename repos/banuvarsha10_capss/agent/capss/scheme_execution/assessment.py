"""capss/scheme_execution/assessment.py

Adaptation Assessment — validates CAPSS Agent scheme-switching decisions.

The ``assess_adaptation()`` function runs FOUR independent checks to
determine whether the Agent's scheme change in response to an attack is:
  (1) Real (adaptation actually occurred)
  (2) Stable (same choice under repeated replays)
  (3) Measurably different in overhead (empirical, NOT a security claim)
  (4) Analytically justified for THIS specific attack type

A recommendation is only "VALIDATED" if ALL FOUR pass.

See Part D of the task specification for the definitive description of
each check and the verdict logic.

IMPORTANT: This module is ADDITIVE and READ-ONLY with respect to
existing CAPSS files.  It imports CAPSSAgent and SchemeKnowledgeBase
from existing modules but does NOT modify them.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.scheme_execution.registry import SchemeRegistry
from capss.scheme_execution.result import ExecutionResult

# Number of stability replays (per spec: 3)
_STABILITY_REPLAYS: int = 3


def baseline_for_position(batch_position: int) -> str:
    """Even position -> ECIES (the current real 3GPP standard), odd
    position -> ML-KEM (the leading post-quantum candidate, not yet
    3GPP-standardized). Position in the batch is the ONLY input — device
    origin/history never affects it, deliberately: this is Check 1's
    forced, neutral baseline (see assess_adaptation()'s docstring for why
    scheme_a is no longer derived from the Agent).

    This is the single canonical definition of the alternation rule,
    used by Check 1's forced baseline (below) and by
    dashboard_backend/pipeline_service.run_scale_device() (the Scaling
    panel / stress-test script). Previously also reused by a "vs. static
    baseline" comparison feature — that feature was later removed
    entirely (dashboard_backend/baseline_comparison.py deleted); this
    function itself was NOT removed with it, since Check 1's forced
    baseline and the Scaling panel still depend on it directly.
    """
    return "ECIES" if batch_position % 2 == 0 else "ML-KEM"

# Verdict constants
VERDICT_VALIDATED = "VALIDATED"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_NO_CHANGE = "NO CHANGE"


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class MeasuredOverhead:
    """Check 3 — empirical overhead comparison between two schemes.

    IMPORTANT: % differences here reflect generation time and output size
    ONLY.  They do NOT indicate which scheme provides better security or
    privacy.  That judgment is in AnalyticalRationale (Check 4).
    """
    scheme_a: str
    scheme_b: str
    # Scheme A measurements
    time_a_ms: float
    size_a_bytes: int
    # Scheme B measurements
    time_b_ms: float
    size_b_bytes: int
    # Derived comparisons
    time_diff_pct: float          # positive = B is faster than A
    size_diff_pct: float          # positive = B is smaller than A
    label: str = "Measured Overhead"
    note: str = (
        "% difference reflects generation_time_ms and output_size_bytes only. "
        "This is NOT an indicator of security or privacy improvement. "
        "See AnalyticalRationale for the security/privacy judgment."
    )
    executor_a_error: Optional[str] = None
    executor_b_error: Optional[str] = None


@dataclass
class AnalyticalRationale:
    """Check 4 — literature-backed comparison of scheme properties per attack.

    Data is sourced exclusively from data/privacy_schemes.json (read-only).
    Nothing here is measured in this run.  All claims are Established Properties
    from the knowledge base.
    """
    attack_type: str
    scheme_a: str
    scheme_b: str
    # Attack-type affinity from knowledge base
    affinity_a: Optional[bool]    # attack_type_affinity[attack_type] for A
    affinity_b: Optional[bool]    # attack_type_affinity[attack_type] for B
    # Reasoning profile flags relevant to this attack
    reasoning_flags_a: Dict[str, Any]
    reasoning_flags_b: Dict[str, Any]
    # Agent's own reason/metric_summary from the attack_context run
    agent_reason: str
    agent_metric_summary: Dict[str, float]
    # Verdict of Check 4
    analytically_justified: bool
    justification_note: str
    label: str = "Established Property / Analytical Rationale"
    source_note: str = (
        "All claims sourced from data/privacy_schemes.json (read-only). "
        "Never presented as empirically measured in this run."
    )


@dataclass
class ComparisonResult:
    """Full output of assess_adaptation().

    Contains results of all four checks and an overall verdict.
    """
    ue_id: str
    scheme_a: str                           # pre-attack recommendation
    scheme_b: str                           # post-attack recommendation

    # Check 1
    adaptation_occurred: bool

    # Check 2
    stability_confirmed: bool
    replay_count: int
    stability_detail: str                   # e.g. "3/3 replays returned B"

    # Check 3
    measured_overhead: Optional[MeasuredOverhead]

    # Check 4
    analytical_rationale: Optional[AnalyticalRationale]

    # Verdict
    overall_verdict: str                    # VALIDATED | INCONCLUSIVE | NO CHANGE
    verdict_reason: str                     # human-readable explanation

    metadata: Dict[str, Any] = field(default_factory=dict)

    # Hybrid execution gap fix — purely additive (Option 2, chosen over
    # folding a hybrid partner into Check 3/4): when the Agent's scheme_b
    # recommendation is a hybrid combination (policy.hybrid_schemes has a
    # primary + partner), the partner is executed for real too, via the
    # same SchemeRegistry Check 3 already uses — but reported here as its
    # OWN separate, clearly-labeled result. scheme_a/scheme_b, Check 3's
    # measured_overhead, and Check 4's analytical_rationale all stay scoped
    # to the primary scheme exactly as already validated throughout this
    # project — this never blends into or changes any of those. None for
    # every non-hybrid recommendation (the overwhelming majority of cases)
    # — behavior there is completely unchanged from before this fix.
    hybrid_partner_scheme: Optional[str] = None
    hybrid_partner_execution: Optional[ExecutionResult] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_agent_once(
    context: RegistrationContext,
    schemes_path: str,
    experience_path: str,
    verbose: bool = False,
) -> tuple[str, "PrivacyPolicy"]:  # noqa: F821
    """Run one agent pass and return (selected_scheme, policy)."""
    agent = CAPSSAgent(
        schemes_path=schemes_path,
        experience_path=experience_path,
    )
    policy = agent.process_registration(context, verbose=verbose)
    return policy.selected_scheme, policy


def _load_scheme_profile(schemes_path: str, short_name: str) -> Dict[str, Any]:
    """Load reasoning_profile and attack_type_affinity for a scheme from JSON."""
    with open(schemes_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for scheme in data:
        if scheme.get("short_name") == short_name:
            ds = scheme.get("decision_support", {})
            rp = ds.get("recommendation_profile", {})
            reasoning = rp.get("reasoning_profile", {})
            return {
                "attack_type_affinity": reasoning.get("attack_type_affinity", {}),
                "reasoning_profile": reasoning,
                "capabilities": rp.get("capabilities", []),
                "best_when": rp.get("best_when", []),
            }
    return {}


# Maps real Systems attack_type constants (systems/pre_amf/attack_rules.py,
# lowercased) to the corresponding data/privacy_schemes.json
# attack_type_affinity key, for cases where the words themselves differ
# (not just casing). Audited against every ATTACK_* constant in
# attack_rules.py that the Pre-AMF pipeline actually assigns to an
# attack_type field; only "registration_flood" has no matching KB key.
_ATTACK_TYPE_VOCAB_MAP: Dict[str, str] = {
    "registration_flood": "flooding",
}


def _normalize_attack_type(raw_attack_type: Optional[str]) -> str:
    """Normalize a raw Systems attack_type into a privacy_schemes.json key."""
    normalized = (raw_attack_type or "none").lower()
    return _ATTACK_TYPE_VOCAB_MAP.get(normalized, normalized)


def _pct_diff(a: float, b: float) -> float:
    """Return % by which b is LESS than a (positive = b is smaller/faster)."""
    if a == 0:
        return 0.0
    return round((a - b) / a * 100.0, 2)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def assess_adaptation(
    ue_id: str,
    pre_context: RegistrationContext,
    attack_context: RegistrationContext,
    schemes_path: str = "data/privacy_schemes.json",
    experience_path: Optional[str] = None,
    replay_count: int = _STABILITY_REPLAYS,
    batch_position: int = 0,
) -> ComparisonResult:
    """Assess whether the Agent's scheme adaptation is valid.

    Runs four checks:
      1. Adaptation occurred (A != B)
      2. Stability under `replay_count` replays of attack_context
      3. Measured overhead (B vs A — empirical only)
      4. Analytical justification (B is stronger than A for the specific
         attack type, per knowledge base)

    Args:
        ue_id: Subscriber identifier (for reporting).
        pre_context: RegistrationContext representing the baseline
            (pre-attack) scenario. NOTE (baseline-forcing fix): its
            content is no longer used to DERIVE scheme_a — see
            `batch_position` below. Kept as a required parameter for
            signature/API stability across every existing caller, and
            because Check 2/3/4 still logically pair with "the baseline
            scenario" conceptually, even though this specific field's
            values don't drive Check 1 anymore.
        attack_context: RegistrationContext representing the attack
            scenario. Its attack_type field is used for Check 4.
        schemes_path: Path to data/privacy_schemes.json (read-only).
        experience_path: Optional path to an experience store JSON.
            If None, a temporary file is used and discarded.
        replay_count: Number of Check 2 stability replays. Defaults to
            _STABILITY_REPLAYS (3) — the real, already-verified value used
            by every existing caller (Attack Testing, Manual Scenario
            Builder, the baseline comparison feature, ...). This is an
            explicit opt-in override, not a change to that default; it
            exists solely so dashboard_backend/scripts/stress_test.py can
            request a cheaper (replay_count=1) Check 2 for its own,
            separate scaling-limit measurement. No other caller should
            ever pass a value other than the default.
        batch_position: BASELINE-FORCING FIX. Check 1's scheme_a is no
            longer derived by calling the Agent on pre_context — that let
            a returning device's OWN prior experience history influence
            what should be a neutral, real-network-realistic starting
            point (e.g. a device previously recommended GS could get GS
            again as its "baseline", before any attack even happened,
            muddying the before/after comparison). scheme_a is now always
            FORCED to ECIES or ML-KEM via baseline_for_position() (even
            position -> ECIES, the current real 3GPP standard; odd
            position -> ML-KEM). Defaults to 0 (ECIES) for any caller
            that doesn't track a real batch position. The Agent is still
            called normally for attack_context, producing scheme_b
            exactly as before — this change is scoped to Check 1's
            scheme_a mechanism only.

    Returns:
        ComparisonResult with all four check outcomes and overall_verdict.
    """
    # Use a temp experience file if not specified, so tests don't pollute
    # the production experience_store.json.
    _cleanup_exp = False
    if experience_path is None:
        _fd, experience_path = tempfile.mkstemp(suffix=".json", prefix="capss_assess_")
        os.close(_fd)
        _cleanup_exp = True

    try:
        return _assess_impl(
            ue_id, pre_context, attack_context, schemes_path, experience_path, replay_count, batch_position,
        )
    finally:
        if _cleanup_exp and os.path.exists(experience_path):
            try:
                os.unlink(experience_path)
            except OSError:
                pass


def _assess_impl(
    ue_id: str,
    pre_context: RegistrationContext,
    attack_context: RegistrationContext,
    schemes_path: str,
    experience_path: str,
    replay_count: int = _STABILITY_REPLAYS,
    batch_position: int = 0,
) -> ComparisonResult:
    """Implementation of assess_adaptation (called after temp-file setup)."""

    # -------------------------------------------------------------------
    # CHECK 1 — Adaptation occurred
    # -------------------------------------------------------------------
    # Baseline-forcing fix: scheme_a is FORCED (ECIES/ML-KEM by real batch
    # position), never derived by calling the Agent on pre_context — see
    # assess_adaptation()'s `batch_position` docstring for the full
    # rationale. This also means no experience entry is written for a
    # "baseline" recommendation the Agent never actually made — the only
    # real agent invocation (and the only real experience write) in this
    # function is the attack_context call directly below, exactly as
    # before.
    scheme_a = baseline_for_position(batch_position)
    scheme_b, policy_attack = _run_agent_once(attack_context, schemes_path, experience_path)

    adaptation_occurred = (scheme_a != scheme_b)

    if not adaptation_occurred:
        return ComparisonResult(
            ue_id=ue_id,
            scheme_a=scheme_a,
            scheme_b=scheme_b,
            adaptation_occurred=False,
            stability_confirmed=False,
            replay_count=0,
            stability_detail="No adaptation occurred; stability check skipped.",
            measured_overhead=None,
            analytical_rationale=None,
            overall_verdict=VERDICT_NO_CHANGE,
            verdict_reason=(
                f"Agent recommended the same scheme ({scheme_a!r}) for both "
                f"pre_context and attack_context. No adaptation to assess."
            ),
        )

    # -------------------------------------------------------------------
    # CHECK 2 — Stability (replay_count replays of attack_context; 3 for
    # every real caller except dashboard_backend/scripts/stress_test.py)
    # -------------------------------------------------------------------
    replay_results: list[str] = []
    for _ in range(replay_count):
        # Each replay gets a FRESH agent with a temp experience path so
        # replay runs are truly independent.
        _fd, tmp_exp = tempfile.mkstemp(suffix=".json", prefix="capss_replay_")
        os.close(_fd)
        try:
            s, _ = _run_agent_once(attack_context, schemes_path, tmp_exp)
            replay_results.append(s)
        finally:
            if os.path.exists(tmp_exp):
                try:
                    os.unlink(tmp_exp)
                except OSError:
                    pass

    stability_confirmed = all(s == scheme_b for s in replay_results)
    n_agree = sum(1 for s in replay_results if s == scheme_b)
    stability_detail = (
        f"{n_agree}/{replay_count} replays returned {scheme_b!r}"
    )

    # -------------------------------------------------------------------
    # CHECK 3 — Measured overhead (empirical)
    # -------------------------------------------------------------------
    registry = SchemeRegistry()
    ue_id_dict = {"supi": attack_context.ue_id}

    exec_a: ExecutionResult = registry.execute(scheme_a, ue_id_dict)
    exec_b: ExecutionResult = registry.execute(scheme_b, ue_id_dict)

    overhead = MeasuredOverhead(
        scheme_a=scheme_a,
        scheme_b=scheme_b,
        time_a_ms=exec_a.generation_time_ms,
        size_a_bytes=exec_a.output_size_bytes,
        time_b_ms=exec_b.generation_time_ms,
        size_b_bytes=exec_b.output_size_bytes,
        time_diff_pct=_pct_diff(exec_a.generation_time_ms, exec_b.generation_time_ms),
        size_diff_pct=_pct_diff(exec_a.output_size_bytes, exec_b.output_size_bytes),
        executor_a_error=exec_a.error if not exec_a.success else None,
        executor_b_error=exec_b.error if not exec_b.success else None,
    )

    executors_ok = exec_a.success and exec_b.success

    # -------------------------------------------------------------------
    # Hybrid partner execution (purely additive — see ComparisonResult's
    # hybrid_partner_scheme/hybrid_partner_execution docstring). Does NOT
    # participate in executors_ok / measured_overhead / the verdict below
    # — a hybrid partner failing to execute must never change Check 3's
    # pass/fail state for the PRIMARY comparison that's already validated.
    # policy_attack.hybrid_schemes, when set, is [primary, partner] (single
    # partner — CAPSSAgent only ever evaluates pairwise hybrids); [0] is
    # always scheme_b itself, so the partner is [1].
    # -------------------------------------------------------------------
    hybrid_partner_scheme: Optional[str] = None
    hybrid_partner_execution: Optional[ExecutionResult] = None
    hybrid_schemes = getattr(policy_attack, "hybrid_schemes", None)
    if hybrid_schemes and len(hybrid_schemes) > 1:
        hybrid_partner_scheme = hybrid_schemes[1]
        hybrid_partner_execution = registry.execute(hybrid_partner_scheme, ue_id_dict)

    # -------------------------------------------------------------------
    # CHECK 4 — Analytical justification per attack type
    # -------------------------------------------------------------------
    attack_type = _normalize_attack_type(attack_context.attack_type)

    profile_a = _load_scheme_profile(schemes_path, scheme_a)
    profile_b = _load_scheme_profile(schemes_path, scheme_b)

    affinity_a = profile_a.get("attack_type_affinity", {}).get(attack_type)
    affinity_b = profile_b.get("attack_type_affinity", {}).get(attack_type)

    # Collect relevant reasoning profile flags from both schemes
    rp_a = profile_a.get("reasoning_profile", {})
    rp_b = profile_b.get("reasoning_profile", {})

    # B is analytically justified if:
    #   - B has True affinity for this attack_type AND A does not, OR
    #   - Neither has explicit affinity but B has relevant reasoning flags
    #     that A lacks (e.g. high_threat=True vs false)
    if affinity_b is True and affinity_a is not True:
        analytically_justified = True
        justification_note = (
            f"Knowledge base confirms {scheme_b!r} has attack_type_affinity "
            f"[{attack_type!r}]=True while {scheme_a!r} does not. "
            f"B is analytically stronger for this attack type."
        )
    elif affinity_b is True and affinity_a is True:
        # Both have affinity — check reasoning profile for tie-breaking
        # Check high_threat flag
        ht_a = rp_a.get("high_threat", False)
        ht_b = rp_b.get("high_threat", False)
        if ht_b and not ht_a:
            analytically_justified = True
            justification_note = (
                f"Both {scheme_a!r} and {scheme_b!r} have affinity for "
                f"{attack_type!r}=True, but {scheme_b!r} additionally has "
                f"high_threat=True in its reasoning profile, indicating "
                f"stronger overall threat response capability."
            )
        else:
            analytically_justified = False
            justification_note = (
                f"Both {scheme_a!r} and {scheme_b!r} have equal affinity "
                f"for {attack_type!r}=True. Cannot confirm B is analytically "
                f"STRONGER than A for this attack type — INCONCLUSIVE."
            )
    else:
        # Neither has True affinity OR B does not
        analytically_justified = False
        justification_note = (
            f"Knowledge base does not confirm {scheme_b!r} as analytically "
            f"stronger than {scheme_a!r} for attack_type={attack_type!r}. "
            f"Affinity A={affinity_a!r}, B={affinity_b!r}. "
            f"Adaptation may have occurred for reasons not specific to this "
            f"attack type — verdict: INCONCLUSIVE."
        )

    analytical = AnalyticalRationale(
        attack_type=attack_type,
        scheme_a=scheme_a,
        scheme_b=scheme_b,
        affinity_a=affinity_a,
        affinity_b=affinity_b,
        reasoning_flags_a={k: v for k, v in rp_a.items() if k != "attack_type_affinity"},
        reasoning_flags_b={k: v for k, v in rp_b.items() if k != "attack_type_affinity"},
        agent_reason=policy_attack.reason,
        agent_metric_summary=dict(policy_attack.metric_summary),
        analytically_justified=analytically_justified,
        justification_note=justification_note,
    )

    # -------------------------------------------------------------------
    # Overall verdict
    # -------------------------------------------------------------------
    if not adaptation_occurred:
        verdict = VERDICT_NO_CHANGE
        verdict_reason = f"No adaptation: agent chose {scheme_a!r} in both scenarios."
    elif not stability_confirmed:
        verdict = VERDICT_INCONCLUSIVE
        verdict_reason = (
            f"Adaptation occurred ({scheme_a!r} → {scheme_b!r}) but was NOT "
            f"stable across {replay_count} replays "
            f"({stability_detail}). Cannot reliably assess."
        )
    elif not executors_ok:
        verdict = VERDICT_INCONCLUSIVE
        verdict_reason = (
            f"Adaptation occurred and was stable, but executor(s) failed: "
            f"A={exec_a.error!r}, B={exec_b.error!r}. "
            f"Check 3 results are unreliable."
        )
    elif not analytically_justified:
        verdict = VERDICT_INCONCLUSIVE
        verdict_reason = (
            f"Adaptation occurred ({scheme_a!r} → {scheme_b!r}) and was "
            f"stable, but Check 4 does NOT confirm {scheme_b!r} is "
            f"analytically stronger than {scheme_a!r} for "
            f"attack_type={attack_type!r}. {justification_note}"
        )
    else:
        verdict = VERDICT_VALIDATED
        verdict_reason = (
            f"All 4 checks passed: adaptation occurred ({scheme_a!r} → "
            f"{scheme_b!r}), stable across {replay_count} replays, "
            f"executors ran successfully, and {scheme_b!r} is analytically "
            f"stronger than {scheme_a!r} for attack_type={attack_type!r} "
            f"per the knowledge base."
        )

    return ComparisonResult(
        ue_id=ue_id,
        scheme_a=scheme_a,
        scheme_b=scheme_b,
        adaptation_occurred=adaptation_occurred,
        stability_confirmed=stability_confirmed,
        replay_count=replay_count,
        stability_detail=stability_detail,
        measured_overhead=overhead,
        analytical_rationale=analytical,
        overall_verdict=verdict,
        verdict_reason=verdict_reason,
        metadata={
            "schemes_path": schemes_path,
            "attack_type": attack_type,
            "executor_a_success": exec_a.success if overhead else None,
            "executor_b_success": exec_b.success if overhead else None,
        },
        hybrid_partner_scheme=hybrid_partner_scheme,
        hybrid_partner_execution=hybrid_partner_execution,
    )

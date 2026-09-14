"""dashboard_backend/llm_explainer.py

Purely additive natural-language explanation layer — takes an ALREADY-
FINAL ComparisonResult (from capss.scheme_execution.assessment.
assess_adaptation(), never modified by this module, called by
pipeline_service.py exactly once per real device long before this module
is ever touched) and asks an LLM to write a short, plain-language
paragraph describing that decision.

HARD GUARANTEE — this module can NEVER influence scheme selection,
scoring, or ranking. It runs strictly AFTER assess_adaptation() has
already returned and its result is already final; the ComparisonResult
passed in here is read-only input TEXT for a prose-generation call,
nothing more. It has no path back into scheme_a/scheme_b/overall_verdict/
confidence/any score — it only ever reads them to build a prompt string.
See pipeline_service.py's call site for exactly where in the real flow
this runs (after assess_adaptation() returns, nowhere else).

FAILURE IS ALWAYS SILENT, BY DESIGN — generate_explanation() returns None
on ANY failure: missing API key, network error, timeout, malformed
response, rate limit, anything. It never raises. Callers must treat None
as "no LLM explanation this time" and continue exactly as if this module
didn't exist — the rest of the dashboard's already-real explanation
(rules_fired, analytical_rationale, verdict_reason, decision_trace, ...)
never depends on this succeeding, and never did before this module
existed.

MODEL / CREDENTIAL — Google Gemini, via its plain REST API (no new SDK
dependency; `requests` is already available in this environment). Reads
the key from the GEMINI_API_KEY environment variable — see
dashboard_backend/.env.local (gitignored, never committed) and
run_dashboard_backend.sh for how it's loaded at startup. If that env var
is unset, generate_explanation() returns None immediately, before making
any network call at all. GEMINI_MODEL defaults to a small/cheap model
(gemini-2.0-flash — this is prose generation from already-correct
structured data, not a reasoning task); override via env var if that
model name is ever retired.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

import requests

from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.scheme_execution.assessment import ComparisonResult
from capss.schemas.recommendation import SchemeScore

# Full scheme names — kept identical to dashboard_frontend/src/components/
# SchemeLabel.tsx's SCHEME_FULL_NAMES (same real knowledge-base "name"
# field, duplicated here as plain data purely because this module has no
# import path to a .tsx file). Given to the LLM so its own generated prose
# follows the same "full name (SHORT)" first-mention convention the rest of
# the dashboard UI already uses everywhere a short form is shown.
SCHEME_FULL_NAMES = {
    "ECIES": "Elliptic Curve Integrated Encryption Scheme",
    "ML-KEM": "Module-Lattice Key Encapsulation Mechanism",
    "DP": "Dynamic Pseudonyms",
    "AP": "Adaptive Padding",
    "ZKP": "Zero-Knowledge Proofs",
    "GS": "Group Signatures",
    "IBE": "Identity-Based Encryption",
}

GEMINI_API_KEY_ENV = "GEMINI_API_KEY"
# Confirmed directly against the real API with the real configured key:
# "gemini-2.0-flash" returned 429 RESOURCE_EXHAUSTED with a hard 0 free-tier
# quota for this key/project (not a transient rate limit -- a genuine 0
# limit), while "gemini-2.5-flash" returned a real 200 response. If this
# ever needs to change again (quota/availability shifts, or a different
# key is used), override via the GEMINI_MODEL env var rather than editing
# this default.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_ENDPOINT_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# Hard cap (task requirement) — a slow/hanging LLM API must never stall a
# live device's processing in a batch run, but it must also be large enough
# that the real, expected-length response doesn't get cut off as a false
# "failure". 5s was correct for generate_explanation()'s short paragraph
# and for the ORIGINAL one-sentence-per-scheme "why not the others" list.
# It is no longer enough for generate_full_explanation()'s expanded output
# (minimum 3 grounded sentences x up to 6 rejected schemes, plus KB
# grounding data in the prompt): measured directly against the real Gemini
# API with a real 7-scheme prompt, response time was consistently ~4.9-5.1s
# even on success -- i.e. the old 5s cap was already being hit on the
# common path, not just genuine hangs. Raised to 12s, which leaves real
# headroom above that measured ~5.1s ceiling while still being a bounded,
# short wait for a single device in a live batch run.
REQUEST_TIMEOUT_SECONDS = 12


def _build_prompt(comparison: ComparisonResult) -> str:
    """Grounds the LLM in ONLY the real, already-final fields of this
    ComparisonResult — nothing invented, nothing it has to guess at.
    Fields that are None (e.g. measured_overhead/analytical_rationale on a
    NO_CHANGE verdict, where Check 3/4 never ran) are simply omitted from
    the prompt entirely, rather than mentioned as null — the instruction
    below tells the model not to speculate about anything not given."""
    lines = [
        "You are summarizing a security decision for a non-technical audience "
        "(e.g. a mentor watching a live demo).",
        "Do not invent any facts. Only explain what is given below. If a field is "
        "missing or None, do not speculate about it.",
        "Write a short paragraph (3-5 sentences), plain language, no jargon.",
        "Explain WHY scheme B was chosen over scheme A, referencing the real attack "
        "type and the real knowledge-base property that justified it, if given.",
        "Keep the MEASURED (timing/size) facts and the ANALYTICAL (knowledge-base) "
        "facts clearly distinguished in your explanation -- never blend them into one "
        "unqualified claim (e.g. never say a scheme is 'better' purely because it was "
        "measured as faster; that is a performance fact, not a security judgement).",
        "",
        "REAL DATA (the only source of truth -- do not add anything beyond this):",
        f"- UE: {comparison.ue_id}",
        f"- Scheme before (A): {comparison.scheme_a}",
        f"- Scheme after (B): {comparison.scheme_b}",
        f"- Adaptation occurred: {comparison.adaptation_occurred}",
        f"- Stability confirmed (3 replays): {comparison.stability_confirmed} ({comparison.stability_detail})",
        f"- Overall verdict: {comparison.overall_verdict}",
        f"- Verdict reason: {comparison.verdict_reason}",
    ]

    overhead = comparison.measured_overhead
    if overhead is not None:
        lines += [
            "",
            "MEASURED (empirical timing/size only -- NOT a security or privacy claim):",
            f"- {overhead.scheme_a}: {overhead.time_a_ms:.2f} ms, {overhead.size_a_bytes} bytes",
            f"- {overhead.scheme_b}: {overhead.time_b_ms:.2f} ms, {overhead.size_b_bytes} bytes",
            f"- Time difference: {overhead.time_diff_pct}% (positive = B is faster)",
            f"- Size difference: {overhead.size_diff_pct}% (positive = B is smaller)",
        ]

    rationale = comparison.analytical_rationale
    if rationale is not None:
        lines += [
            "",
            "ANALYTICAL (knowledge-base property, not measured this run):",
            f"- Attack type: {rationale.attack_type}",
            f"- Scheme A ({rationale.scheme_a}) documented affinity for this attack type: {rationale.affinity_a}",
            f"- Scheme B ({rationale.scheme_b}) documented affinity for this attack type: {rationale.affinity_b}",
            f"- Analytically justified: {rationale.analytically_justified}",
            f"- Justification: {rationale.justification_note}",
        ]

    hybrid_partner = comparison.hybrid_partner_scheme
    if hybrid_partner:
        lines += [
            "",
            "HYBRID PARTNER (the Agent's full recommendation combines scheme B with "
            "this partner -- mention this distinctly, e.g. 'the full recommendation "
            "combines B with the partner'; do NOT imply the partner's execution was "
            "part of the MEASURED comparison above, which is scheme A vs scheme B "
            "only):",
            f"- Partner scheme: {hybrid_partner}",
        ]
        partner_exec = comparison.hybrid_partner_execution
        if partner_exec is not None:
            # By the time pipeline_service.py calls generate_explanation(),
            # hybrid_partner_execution has already been hex-encoded to a
            # plain dict (same boundary scheme_a_execution/scheme_b_execution
            # cross via _execution_result_to_dict, since it carries real
            # output_value bytes) -- but accept the raw ExecutionResult
            # dataclass too, for direct/test usage before that conversion.
            if isinstance(partner_exec, dict):
                output_type = partner_exec.get("output_type")
                generation_time_ms = partner_exec.get("generation_time_ms", 0.0)
                output_size_bytes = partner_exec.get("output_size_bytes")
            else:
                output_type = getattr(partner_exec, "output_type", None)
                generation_time_ms = getattr(partner_exec, "generation_time_ms", 0.0)
                output_size_bytes = getattr(partner_exec, "output_size_bytes", None)
            lines.append(
                f"- Partner's own real execution: {output_type}, "
                f"{generation_time_ms:.2f} ms, {output_size_bytes} bytes "
                f"(separate from the scheme A vs B measurement above, not combined with it)"
            )

    return "\n".join(lines)


def generate_explanation(comparison_result: ComparisonResult) -> Optional[str]:
    """Returns a short plain-language explanation string, or None if the
    call fails for ANY reason (see module docstring's failure-is-always-
    silent guarantee). Never raises."""
    api_key = os.environ.get(GEMINI_API_KEY_ENV)
    if not api_key:
        return None

    try:
        response = requests.post(
            GEMINI_ENDPOINT_TEMPLATE.format(model=GEMINI_MODEL),
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": _build_prompt(comparison_result)}]}],
                # Confirmed directly: gemini-2.5-flash defaults to an
                # internal "thinking" pass that pushed real response time
                # past this module's own 5s timeout for the full prompt
                # (a short "say hi" prompt returned fine; this longer,
                # structured one didn't). Not needed here regardless --
                # this is prose generation from already-correct structured
                # data, not a reasoning task (see module docstring) --
                # disabling it cut real response time to ~1.7s.
                "generationConfig": {"thinkingConfig": {"thinkingBudget": 0}},
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return text.strip() or None
    except Exception:  # noqa: BLE001 -- ANY failure (network, timeout, bad key,
        # malformed/unexpected response shape, rate limit, ...) must degrade to
        # "no explanation", never propagate and break the real, already-correct
        # pipeline result this runs after.
        return None


# =============================================================================
# "Why not the others?" extension — purely additive, see module docstring.
#
# Response is structured into two clearly divided sections: Section A ("Why
# the winner was selected" -- LLMExplanation.winner_explanation, unchanged
# from the original prompt) and Section B ("Why the others were not
# selected" -- LLMExplanation.rejected_schemes, each now a minimum of 3
# real, grounded sentences instead of one, drawing on real SchemeScore
# dimensions/rejection_reasons, the real final_score gap to the winner, and
# (best-effort, from the read-only knowledge base) each scheme's real,
# general capabilities/advantages text -- see _format_candidate_line() and
# _general_strengths_text(). An honest-uncertainty exception applies when
# real data can't support all 3 distinct points for a given scheme; see
# _build_full_prompt().
#
# generate_explanation() above is left completely untouched (same signature,
# same prompt, same tests) — it remains a real, valid "winner only" primitive.
# This is a SEPARATE function rather than new optional params on
# generate_explanation(), for one deliberate reason: the task's atomicity
# requirement ("the WHOLE explanation falls back together, not a partial
# result") is easiest to guarantee correctly with a distinct return type
# (LLMExplanation) that can only ever be fully populated or None — bolting
# a second, structurally different payload onto generate_explanation()'s
# Optional[str] contract would either break its existing string-returning
# callers/tests or require silently overloading what a "None vs string"
# result means for two very different shapes of data.
#
# Still exactly ONE network call for the whole thing (winner text + all
# rejections + optional hybrid-partner sentence together) — never two
# separate calls that could succeed/fail independently.
# =============================================================================


@dataclass
class RejectedSchemeExplanation:
    scheme: str  # short_name, e.g. "ZKP"
    # Section B for this scheme: minimum 3 real, grounded sentences (what
    # it's generally good at, why it didn't fit this scenario, how close/
    # far it was) — field name kept as `reason` for API/test stability,
    # but the content is now a short multi-sentence paragraph, not a
    # single line. May be shorter than 3 sentences, honestly framed, when
    # real data doesn't support all 3 distinct points — see
    # _build_full_prompt()'s honest-uncertainty instruction.
    reason: str


@dataclass
class LLMExplanation:
    # Section A: why the winner was selected (unchanged from the original,
    # winner-only prompt style).
    winner_explanation: str
    # Section B: why every other real candidate was NOT selected.
    rejected_schemes: List[RejectedSchemeExplanation] = field(default_factory=list)
    # Populated only when comparison_result.hybrid_partner_scheme is set —
    # None for every non-hybrid recommendation (the overwhelming majority).
    hybrid_partner_explanation: Optional[str] = None


# Real SchemeScore dimensions shown to the LLM as grounding data — the same
# fields the Explainability panel already renders, so a cited reason is
# always independently checkable against what the UI shows elsewhere.
_DIMENSION_FIELDS = (
    "fitness_score", "profile_match", "experience_alignment",
    "privacy_match", "performance_match", "deployment_match",
    "tracking_protection_match", "quantum_match", "identity_protection_match",
)

# Same relative default main.py's SCHEMES_PATH uses (the dashboard backend
# always runs with the `agent/` directory as cwd — see run_dashboard_backend.sh).
# Loaded lazily, once, and ONLY to pull each scheme's real `advantages` /
# `capabilities` text for grounding "what this scheme is generally good at"
# in the "why not the others" section below — read-only, never written to,
# same knowledge base main.py/pipeline_service.py already load this way.
_DEFAULT_SCHEMES_PATH = os.environ.get("CAPSS_SCHEMES_PATH", "data/privacy_schemes.json")
_kb_load_attempted = False
_kb_cache: Optional[SchemeKnowledgeBase] = None


def _get_knowledge_base() -> Optional[SchemeKnowledgeBase]:
    """Best-effort, cached, never raises. If the schemes file can't be
    found from the current working directory (e.g. a test running from a
    different cwd), returns None and callers fall back to the real
    SchemeScore numeric data alone — general-strengths grounding is a
    nice-to-have on top of that, not a hard requirement."""
    global _kb_load_attempted, _kb_cache
    if _kb_load_attempted:
        return _kb_cache
    _kb_load_attempted = True
    try:
        _kb_cache = SchemeKnowledgeBase(_DEFAULT_SCHEMES_PATH)
    except Exception:  # noqa: BLE001 -- grounding-data lookup only, never fatal.
        _kb_cache = None
    return _kb_cache


def _general_strengths_text(short_name: str) -> Optional[str]:
    """Real, KB-sourced text describing what this scheme is generally good
    at (independent of this specific run) -- the same `capabilities` and
    `advantages` fields the Knowledge Base Viewer panel already renders.
    Returns None if the KB isn't available or has nothing for this scheme,
    which the prompt instructions treat as a real absence of data, not
    something to be papered over."""
    kb = _get_knowledge_base()
    if kb is None:
        return None
    scheme = kb.get_by_short_name(short_name)
    if scheme is None:
        return None
    parts = []
    capabilities = scheme.get_capabilities()
    if capabilities:
        parts.append(f"capabilities: {', '.join(capabilities[:4])}")
    if scheme.advantages:
        parts.append(f"documented advantages: {'; '.join(scheme.advantages[:3])}")
    return " | ".join(parts) if parts else None


def _format_candidate_line(
    score: SchemeScore, tag: str = "", winner_score: Optional[float] = None,
) -> str:
    dims = ", ".join(f"{f}={getattr(score, f):.3f}" for f in _DIMENSION_FIELDS)
    line = f"- {tag}{score.short_name} ({SCHEME_FULL_NAMES.get(score.short_name, score.short_name)}): " \
           f"final_score={score.final_score:.3f} ({dims})"
    if winner_score is not None and not tag:
        gap = winner_score - score.final_score
        rel_pct = (gap / winner_score * 100) if winner_score else 0.0
        line += f" | gap_to_winner={gap:.3f} ({rel_pct:.1f}% relatively lower than the winner's final_score)"
    if score.rejection_reasons:
        line += f" | structural rejection reasons: {'; '.join(score.rejection_reasons)}"
    strengths = _general_strengths_text(score.short_name)
    line += f" | general strengths (from knowledge base, independent of this run): {strengths}" if strengths \
        else " | general strengths (from knowledge base): none on record for this scheme"
    return line


def _build_full_prompt(
    comparison: ComparisonResult,
    candidate_scores: List[SchemeScore],
    hybrid_benefit_score: Optional[float],
    hybrid_reason: Optional[str],
) -> str:
    """Reuses _build_prompt()'s exact winner-explanation prompt unchanged
    (this becomes "Section A" of the response), then appends the "Section
    B — why not the others" instructions and the real, complete
    candidate_scores data (all schemes evaluated this run, plus each
    rejected scheme's real KB capabilities/advantages text) — the only
    source of truth the rejection paragraphs may draw from.

    Scaling/performance of this prompt (token count, latency as more
    schemes are added) is explicitly out of scope for this task — see
    generate_full_explanation()'s docstring."""
    winner_name = comparison.scheme_b
    hybrid_partner = comparison.hybrid_partner_scheme
    excluded = {winner_name, hybrid_partner} if hybrid_partner else {winner_name}
    by_name = {s.short_name: s for s in candidate_scores}
    rejected = [s for s in candidate_scores if s.short_name not in excluded]
    winner_score = by_name[winner_name].final_score if winner_name in by_name else None
    full_names_line = ", ".join(f"{short}={full}" for short, full in SCHEME_FULL_NAMES.items())

    lines = [
        _build_prompt(comparison),
        "",
        "Full scheme names (for first-mention only — see formatting rule below): " + full_names_line,
        "",
        "Structure your ENTIRE response into two clearly divided sections, SECTION A and "
        "SECTION B (exact machine-parseable headers given at the very end of this prompt):",
        "",
        "SECTION A — WHY THE WINNER WAS SELECTED: the same 3-5 sentence paragraph described "
        "above, unchanged in style and grounding.",
        "",
        "SECTION B — WHY THE OTHERS WERE NOT SELECTED: for EVERY OTHER real candidate scheme "
        "listed below (never the winner, never the hybrid partner if one is given), write a "
        "minimum of 3 real, grounded sentences covering all three of these distinct points, "
        "in this order:",
        "  1. What this scheme is GENERALLY good at — grounded in its real 'general strengths' "
        "capabilities/advantages text given below. If that text says 'none on record for this "
        "scheme', say so honestly instead of inventing a strength.",
        "  2. Why it did NOT fit THIS specific scenario — grounded in a specific real dimension "
        "score, structural rejection reason, or attack-type affinity given below. Never a "
        "generic 'it scored lower'.",
        "  3. How close or far it was from the winner — grounded in the real gap_to_winner "
        "number given below (e.g. 'only 0.02 behind the winner' vs 'over 0.30 behind').",
        "HONEST-UNCERTAINTY EXCEPTION: if the real data genuinely does not support all 3 "
        "distinct points for a given scheme (e.g. no KB capabilities/advantages text AND no "
        "specific differentiating dimension beyond a generic score gap), write fewer sentences "
        "but say so plainly (e.g. 'the data here does not give a specific reason beyond the "
        "overall score gap') rather than padding with invented or repetitive content. Never "
        "sacrifice accuracy to hit the sentence count.",
        "Every sentence must cite a real number, dimension name, capability, or advantage from "
        "the data below. Do not invent, restate imprecisely, or reference anything not "
        "explicitly listed.",
        "Formatting rule (applies to BOTH sections): the FIRST time a scheme is mentioned by "
        "name anywhere in your response, write it as 'Full Name (SHORT)' using the mapping "
        "given above (e.g. 'Group Signatures (GS)'). Every subsequent mention of that same "
        "scheme may use the short form alone.",
        "Each rejected scheme's entire multi-sentence explanation must be written on a SINGLE "
        "line with no internal line breaks (see the exact response structure at the end of "
        "this prompt) — sentences are separated by spaces/periods only, never newlines.",
    ]
    if hybrid_partner:
        lines.append(
            f"{hybrid_partner!r} is NOT a rejected scheme — it is the real hybrid partner "
            f"combined with {winner_name!r} in the actual recommendation. Do not include it "
            f"in the Section B rejected-schemes list; explain it separately as instructed below."
        )
    lines += [
        "",
        f"REAL CANDIDATE SCORES ({len(candidate_scores)} schemes evaluated this run):",
        _format_candidate_line(by_name[winner_name], tag="WINNER ") if winner_name in by_name else "",
    ]
    lines += [_format_candidate_line(s, winner_score=winner_score) for s in rejected]

    if hybrid_partner:
        lines += [
            "",
            f"HYBRID PARTNER (real, already added to the recommendation — {winner_name!r} + "
            f"{hybrid_partner!r}):",
            f"- hybrid_benefit_score: {hybrid_benefit_score:.3f}" if hybrid_benefit_score is not None else "",
            f"- Reasoning engine's own hybrid_reason: {hybrid_reason}" if hybrid_reason else "",
        ]
        if hybrid_partner in by_name:
            lines.append(_format_candidate_line(by_name[hybrid_partner], tag="PARTNER "))

    lines += [
        "",
        "Respond in EXACTLY this structure, with these exact section headers each on their "
        "own line (omit the HYBRID_PARTNER section, header included, if no hybrid partner "
        "was given above):",
        "",
        "WINNER_EXPLANATION:",
        "<SECTION A: the same 3-5 sentence paragraph style as instructed above>",
        "",
        "REJECTED_SCHEMES:",
        "<SchemeShortName>: <SECTION B for this scheme: 3+ grounded sentences, one line, no "
        "internal line breaks — or fewer sentences with the honest-uncertainty framing above>",
        "<one line per rejected scheme listed above, same short names, no extras, no omissions>",
    ]
    if hybrid_partner:
        lines += [
            "",
            "HYBRID_PARTNER:",
            "<one grounded sentence explaining why this specific partner was added>",
        ]

    return "\n".join(l for l in lines if l is not None)


def _parse_full_response(
    text: str, expected_rejected: List[str], hybrid_partner: Optional[str],
) -> Optional[LLMExplanation]:
    """Strict, all-or-nothing parse. Any structural mismatch (missing
    section, a rejected scheme named that isn't real, a real rejected
    scheme missing from the response, a missing hybrid sentence when one
    was required) returns None for the WHOLE explanation — never a
    partially-populated result. See module docstring's atomicity note."""
    try:
        if "WINNER_EXPLANATION:" not in text or "REJECTED_SCHEMES:" not in text:
            return None
        _, _, after_winner_header = text.partition("WINNER_EXPLANATION:")
        winner_part, _, rest = after_winner_header.partition("REJECTED_SCHEMES:")
        winner_explanation = winner_part.strip()
        if not winner_explanation:
            return None

        if hybrid_partner:
            if "HYBRID_PARTNER:" not in rest:
                return None
            rejected_part, _, hybrid_part = rest.partition("HYBRID_PARTNER:")
        else:
            rejected_part, hybrid_part = rest, ""

        seen: dict[str, str] = {}
        for raw_line in rejected_part.strip().splitlines():
            candidate_line = raw_line.strip().lstrip("-").strip()
            if not candidate_line or ":" not in candidate_line:
                continue
            name, _, reason = candidate_line.partition(":")
            name = name.strip()
            reason = reason.strip()
            if name in expected_rejected and reason:
                seen[name] = reason  # last mention wins if the model repeats a name

        if set(seen) != set(expected_rejected):
            return None  # every real rejected scheme must appear exactly once, no extras

        hybrid_partner_explanation: Optional[str] = None
        if hybrid_partner:
            hybrid_partner_explanation = hybrid_part.strip() or None
            if not hybrid_partner_explanation:
                return None

        return LLMExplanation(
            winner_explanation=winner_explanation,
            rejected_schemes=[
                RejectedSchemeExplanation(scheme=name, reason=seen[name])
                for name in expected_rejected
            ],
            hybrid_partner_explanation=hybrid_partner_explanation,
        )
    except Exception:  # noqa: BLE001 -- parsing failure is a malformed-response
        # failure mode, same as any other; degrade to None, never raise.
        return None


def generate_full_explanation(
    comparison_result: ComparisonResult,
    candidate_scores: List[SchemeScore],
    hybrid_benefit_score: Optional[float] = None,
    hybrid_reason: Optional[str] = None,
) -> Optional[LLMExplanation]:
    """Returns a two-section explanation — Section A (winner_explanation:
    why the winner was selected, unchanged from the original prompt style)
    and Section B (rejected_schemes: a minimum of 3 real, grounded
    sentences per rejected scheme, covering what it's generally good at,
    why it didn't fit this scenario, and how close/far it was from the
    winner, with an honest-uncertainty fallback when real data doesn't
    support all 3 — see _build_full_prompt()) — plus, for a hybrid
    recommendation, one sentence for why the partner was added. Returns
    None if the call/parse fails for ANY reason, exactly the same
    silent-failure guarantee as generate_explanation(). Never raises.
    `candidate_scores` should be every scheme this run actually evaluated
    (decision_trace.candidate_scores) — with fewer than that, the
    rejection list would be incomplete, so an empty/missing list is itself
    treated as "nothing to explain" (None), the same as a missing API key.

    Scaling/performance (token budget, latency as the scheme count grows)
    is explicitly out of scope for this task — REQUEST_TIMEOUT_SECONDS is
    unchanged; see the module docstring's failure-is-always-silent
    guarantee for what happens if a longer response ever runs past it."""
    api_key = os.environ.get(GEMINI_API_KEY_ENV)
    if not api_key or not candidate_scores:
        return None

    winner_name = comparison_result.scheme_b
    hybrid_partner = comparison_result.hybrid_partner_scheme
    excluded = {winner_name, hybrid_partner} if hybrid_partner else {winner_name}
    expected_rejected = [s.short_name for s in candidate_scores if s.short_name not in excluded]

    try:
        response = requests.post(
            GEMINI_ENDPOINT_TEMPLATE.format(model=GEMINI_MODEL),
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": _build_full_prompt(
                    comparison_result, candidate_scores, hybrid_benefit_score, hybrid_reason,
                )}]}],
                "generationConfig": {"thinkingConfig": {"thinkingBudget": 0}},
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return _parse_full_response(text, expected_rejected, hybrid_partner)
    except Exception:  # noqa: BLE001 -- same blanket guarantee as generate_explanation().
        return None

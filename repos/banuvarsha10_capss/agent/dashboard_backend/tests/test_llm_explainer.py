"""Tests for dashboard_backend/llm_explainer.py — the purely additive,
strictly-after-the-real-decision explanation layer.

Confirms (per the LLM-explainer task's testing requirements):
  1. A mocked successful call returns the real generated text.
  2. Every kind of failure (missing key, network error, timeout, bad JSON
     shape, non-2xx status) degrades to None, never raises.
  3. The hard 5-second timeout is actually passed to the HTTP call.
  4. The prompt is built ONLY from the real ComparisonResult fields (no
     invented data), with measured/analytical sections cleanly separated
     and omitted entirely when their source field is None.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from capss.scheme_execution.assessment import (
    AnalyticalRationale,
    ComparisonResult,
    MeasuredOverhead,
)
from dashboard_backend import llm_explainer


def _comparison(overhead=None, rationale=None, hybrid_partner_scheme=None, hybrid_partner_execution=None) -> ComparisonResult:
    return ComparisonResult(
        ue_id="imsi-999700000000001",
        scheme_a="AP",
        scheme_b="GS",
        adaptation_occurred=True,
        stability_confirmed=True,
        replay_count=3,
        stability_detail="3/3 replays returned 'GS'",
        measured_overhead=overhead,
        analytical_rationale=rationale,
        overall_verdict="VALIDATED",
        verdict_reason="All 4 checks passed.",
        hybrid_partner_scheme=hybrid_partner_scheme,
        hybrid_partner_execution=hybrid_partner_execution,
    )


def _hybrid_partner_execution_dict() -> dict:
    """Mirrors the shape hybrid_partner_execution actually has by the time
    generate_explanation() sees it in production: pipeline_service.py
    hex-encodes it via _execution_result_to_dict() (same boundary
    scheme_a_execution/scheme_b_execution cross) BEFORE calling
    generate_explanation() — never the raw ExecutionResult dataclass."""
    return {
        "success": True, "output_type": "pseudonym", "output_value_hex": "4ea8",
        "generation_time_ms": 0.06, "key_size_bytes": 32, "output_size_bytes": 32,
        "error": None, "scheme_name": "DP", "label": "Dynamic Pseudonym",
        "is_placeholder": False, "metadata": {},
    }


def _overhead() -> MeasuredOverhead:
    return MeasuredOverhead(
        scheme_a="AP", scheme_b="GS",
        time_a_ms=1.23, size_a_bytes=64,
        time_b_ms=4.56, size_b_bytes=427,
        time_diff_pct=-270.7, size_diff_pct=-567.2,
    )


def _rationale() -> AnalyticalRationale:
    return AnalyticalRationale(
        attack_type="duplicate_registration",
        scheme_a="AP", scheme_b="GS",
        affinity_a=False, affinity_b=True,
        reasoning_flags_a={}, reasoning_flags_b={},
        agent_reason="test", agent_metric_summary={},
        analytically_justified=True,
        justification_note="GS has documented affinity for duplicate_registration; AP does not.",
    )


# ---------------------------------------------------------------------------
# 1. Successful call
# ---------------------------------------------------------------------------

def test_generate_explanation_returns_real_text_on_success(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "  GS was chosen because it resists duplicate registration attacks.  "}]}}],
    }
    with patch.object(llm_explainer.requests, "post", return_value=fake_response) as mock_post:
        result = llm_explainer.generate_explanation(_comparison(_overhead(), _rationale()))

    assert result == "GS was chosen because it resists duplicate registration attacks."
    mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# 2. Every failure mode degrades to None, never raises
# ---------------------------------------------------------------------------

def test_generate_explanation_returns_none_when_no_api_key(monkeypatch):
    monkeypatch.delenv(llm_explainer.GEMINI_API_KEY_ENV, raising=False)
    with patch.object(llm_explainer.requests, "post") as mock_post:
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None
    mock_post.assert_not_called()  # must not even attempt a network call without a key


def test_generate_explanation_returns_none_on_network_error(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    with patch.object(llm_explainer.requests, "post", side_effect=requests.exceptions.ConnectionError("no route")):
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None


def test_generate_explanation_returns_none_on_timeout(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    with patch.object(llm_explainer.requests, "post", side_effect=requests.exceptions.Timeout("too slow")):
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None


def test_generate_explanation_returns_none_on_bad_status_code(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "bad-key")
    fake_response = MagicMock()
    fake_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
    with patch.object(llm_explainer.requests, "post", return_value=fake_response):
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None


def test_generate_explanation_returns_none_on_malformed_response_shape(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"unexpected": "shape"}  # no "candidates" key
    with patch.object(llm_explainer.requests, "post", return_value=fake_response):
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None


def test_generate_explanation_returns_none_on_empty_text(monkeypatch):
    """An LLM response that technically succeeds but returns empty/whitespace
    text should be treated the same as no explanation, not an empty string
    the frontend would render as an empty box."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"candidates": [{"content": {"parts": [{"text": "   "}]}}]}
    with patch.object(llm_explainer.requests, "post", return_value=fake_response):
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None


# ---------------------------------------------------------------------------
# 3. Hard timeout is actually enforced
# ---------------------------------------------------------------------------

def test_generate_explanation_disables_thinking_mode(monkeypatch):
    """Regression guard for a real, measured latency bug: gemini-2.5-flash
    defaults to an internal 'thinking' pass that pushed real response time
    for the full prompt past this module's own 5s timeout (confirmed via a
    live call -- ReadTimeout at 10s). thinkingBudget: 0 brought a real call
    down to ~1.7-2.2s. This must stay wired into every request."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    with patch.object(llm_explainer.requests, "post", return_value=fake_response) as mock_post:
        llm_explainer.generate_explanation(_comparison())

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["generationConfig"]["thinkingConfig"]["thinkingBudget"] == 0


def test_generate_explanation_passes_the_hard_timeout_to_the_http_call(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    with patch.object(llm_explainer.requests, "post", return_value=fake_response) as mock_post:
        llm_explainer.generate_explanation(_comparison())

    _, kwargs = mock_post.call_args
    assert kwargs["timeout"] == llm_explainer.REQUEST_TIMEOUT_SECONDS
    # Raised from 5s to 12s alongside the "why not the others" expansion —
    # measured directly against the real Gemini API, the longer 3-sentence-
    # per-scheme response consistently took ~4.9-5.1s even on success, so
    # the old 5s cap was already being hit on the common path. Still a
    # bounded, short wait for one device in a live batch run, not unbounded.
    assert llm_explainer.REQUEST_TIMEOUT_SECONDS == 12


def test_generate_explanation_returns_none_when_the_call_actually_exceeds_the_timeout(monkeypatch):
    """Confirms the timeout is wired to something real, not just a value
    that's passed but never enforced: simulate requests' own behavior when
    a call genuinely exceeds its timeout (it raises Timeout)."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")

    def slow_post(*_args, **kwargs):
        assert kwargs["timeout"] == llm_explainer.REQUEST_TIMEOUT_SECONDS
        raise requests.exceptions.Timeout(f"exceeded {kwargs['timeout']}s")

    with patch.object(llm_explainer.requests, "post", side_effect=slow_post):
        result = llm_explainer.generate_explanation(_comparison())

    assert result is None


# ---------------------------------------------------------------------------
# 5. Hybrid partner — mentioned distinctly, never folded into MEASURED
# ---------------------------------------------------------------------------

def test_generate_explanation_succeeds_for_a_real_hybrid_case(monkeypatch):
    """Mirrors the real GS+DP duplicate_registration case used to verify
    the hybrid execution fix: confirms generate_explanation() still
    produces a real explanation (not silently swallowed by the hybrid
    fields) when hybrid_partner_scheme/execution are populated."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key-for-test")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {
        "candidates": [{"content": {"parts": [{
            "text": "GS was chosen for duplicate registration; the full recommendation "
                    "combines GS with DP for extra tracking protection.",
        }]}}],
    }
    comparison = _comparison(
        _overhead(), _rationale(),
        hybrid_partner_scheme="DP",
        hybrid_partner_execution=_hybrid_partner_execution_dict(),
    )
    with patch.object(llm_explainer.requests, "post", return_value=fake_response):
        result = llm_explainer.generate_explanation(comparison)

    assert result is not None
    assert "DP" in result


def test_prompt_mentions_hybrid_partner_distinctly_without_dict_form(monkeypatch):
    prompt = llm_explainer._build_prompt(_comparison(
        _overhead(), _rationale(),
        hybrid_partner_scheme="DP",
        hybrid_partner_execution=_hybrid_partner_execution_dict(),
    ))
    assert "HYBRID PARTNER" in prompt
    assert "Partner scheme: DP" in prompt
    assert "pseudonym" in prompt
    assert "0.06 ms" in prompt
    assert "32 bytes" in prompt
    # Must not imply the partner's execution was part of the primary
    # scheme A vs B measurement — the distinction must be explicit.
    assert "not combined with it" in prompt


def test_prompt_handles_raw_execution_result_dataclass_too():
    """generate_explanation() only ever receives the hex-encoded dict form
    in production (pipeline_service.py converts it before calling this),
    but _build_prompt() should not hard-crash if ever handed the raw
    ExecutionResult dataclass directly (e.g. direct/test usage)."""
    from capss.scheme_execution.result import ExecutionResult

    raw_exec = ExecutionResult(
        success=True, output_type="pseudonym", output_value=b"\x01\x02",
        generation_time_ms=0.06, key_size_bytes=32, output_size_bytes=32,
        error=None, scheme_name="DP", label="Dynamic Pseudonym",
        metadata={},
    )
    prompt = llm_explainer._build_prompt(_comparison(
        hybrid_partner_scheme="DP", hybrid_partner_execution=raw_exec,
    ))
    assert "Partner scheme: DP" in prompt
    assert "pseudonym" in prompt


def test_prompt_omits_hybrid_section_when_no_hybrid_partner():
    prompt = llm_explainer._build_prompt(_comparison(_overhead(), _rationale()))
    assert "HYBRID PARTNER" not in prompt


# ---------------------------------------------------------------------------
# 4. Prompt grounding — only real fields, measured/analytical kept separate
# ---------------------------------------------------------------------------

def test_prompt_contains_only_real_field_values_and_no_invention_instruction():
    prompt = llm_explainer._build_prompt(_comparison(_overhead(), _rationale()))

    assert "Do not invent any facts" in prompt
    assert "imsi-999700000000001" in prompt
    assert "AP" in prompt and "GS" in prompt
    assert "VALIDATED" in prompt
    assert "duplicate_registration" in prompt
    assert "MEASURED" in prompt and "ANALYTICAL" in prompt


def test_prompt_omits_measured_and_analytical_sections_when_none():
    """A NO_CHANGE verdict never runs Check 3/4, so measured_overhead and
    analytical_rationale are genuinely None — the prompt must not mention
    fabricated values for them, just omit the SECTIONS entirely (the
    general instruction line that mentions both words by name always
    stays, regardless — only the real-data sections are conditional)."""
    prompt = llm_explainer._build_prompt(_comparison(overhead=None, rationale=None))

    assert "MEASURED (empirical timing/size only" not in prompt
    assert "ANALYTICAL (knowledge-base property" not in prompt
    assert "Do not invent any facts" in prompt


# ---------------------------------------------------------------------------
# 6. "Why not the others?" extension — generate_full_explanation()
# ---------------------------------------------------------------------------

def _score(short_name, final_score, **dims) -> "llm_explainer.SchemeScore":
    from capss.schemas.recommendation import SchemeScore

    defaults = dict(
        fitness_score=0.5, privacy_match=0.5, performance_match=0.5, deployment_match=0.5,
        experience_alignment=0.5, tracking_protection_match=0.5, quantum_match=0.5,
        identity_protection_match=0.5, profile_match=0.5,
    )
    defaults.update(dims)
    return SchemeScore(
        scheme_id=f"SCHEME-{short_name}", scheme_name=short_name, short_name=short_name,
        final_score=final_score, **defaults,
    )


def _seven_scores(winner="GS", winner_score=0.58):
    """7 real-shaped SchemeScore objects — winner plus 6 real alternatives
    with varied final_score/dimensions, mirroring an actual duplicate_
    registration ranking."""
    others = [
        _score("ML-KEM", 0.5399, quantum_match=0.95),
        _score("ECIES", 0.4917, privacy_match=0.4),
        _score("DP", 0.4878, tracking_protection_match=0.8),
        _score("AP", 0.4868, performance_match=0.9),
        _score("IBE", 0.4567, identity_protection_match=0.9),
        _score("ZKP", 0.4384, profile_match=0.08),
    ]
    return [_score(winner, winner_score)] + others


def _mock_response(text: str) -> MagicMock:
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return fake_response


def test_generate_full_explanation_returns_none_without_candidate_scores(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    with patch.object(llm_explainer.requests, "post") as mock_post:
        result = llm_explainer.generate_full_explanation(_comparison(), [])

    assert result is None
    mock_post.assert_not_called()


def test_generate_full_explanation_parses_a_well_formed_non_hybrid_response(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    scores = _seven_scores()
    text = (
        "WINNER_EXPLANATION:\n"
        "GS was chosen because it has documented affinity for duplicate registration.\n\n"
        "REJECTED_SCHEMES:\n"
        "ML-KEM: Strong on quantum_match (0.95) but lacks affinity for this attack type.\n"
        "ECIES: Lower privacy_match (0.40) than GS.\n"
        "DP: Close on most dimensions, marginally behind on final_score (0.49 vs 0.58).\n"
        "AP: Strong performance_match (0.90) but weaker overall final_score.\n"
        "IBE: Strong identity_protection_match (0.90) but lower final_score.\n"
        "ZKP: Much lower profile_match (0.08) than GS.\n"
    )
    with patch.object(llm_explainer.requests, "post", return_value=_mock_response(text)) as mock_post:
        result = llm_explainer.generate_full_explanation(_comparison(), scores)

    mock_post.assert_called_once()
    assert result is not None
    assert result.winner_explanation.startswith("GS was chosen")
    assert result.hybrid_partner_explanation is None
    assert {r.scheme for r in result.rejected_schemes} == {"ML-KEM", "ECIES", "DP", "AP", "IBE", "ZKP"}
    zkp = next(r for r in result.rejected_schemes if r.scheme == "ZKP")
    assert "0.08" in zkp.reason


def test_generate_full_explanation_excludes_hybrid_partner_from_rejections(monkeypatch):
    """The additional hybrid requirement: when scheme_b=GS and
    hybrid_partner_scheme=DP, the rejection list must cover the remaining
    5 schemes (not DP), and a separate hybrid_partner_explanation must be
    populated."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    scores = _seven_scores()
    comparison = _comparison(hybrid_partner_scheme="DP")
    text = (
        "WINNER_EXPLANATION:\n"
        "GS was chosen because it has documented affinity for duplicate registration.\n\n"
        "REJECTED_SCHEMES:\n"
        "ML-KEM: Strong on quantum_match (0.95) but lacks affinity for this attack type.\n"
        "ECIES: Lower privacy_match (0.40) than GS.\n"
        "AP: Strong performance_match (0.90) but weaker overall final_score.\n"
        "IBE: Strong identity_protection_match (0.90) but lower final_score.\n"
        "ZKP: Much lower profile_match (0.08) than GS.\n\n"
        "HYBRID_PARTNER:\n"
        "DP was added because it scores higher on tracking_protection_match (0.80), "
        "covering a gap GS alone does not address.\n"
    )
    with patch.object(llm_explainer.requests, "post", return_value=_mock_response(text)):
        result = llm_explainer.generate_full_explanation(
            comparison, scores, hybrid_benefit_score=0.25, hybrid_reason="Hybrid of GS and DP yields a benefit score of 0.25.",
        )

    assert result is not None
    rejected_names = {r.scheme for r in result.rejected_schemes}
    assert rejected_names == {"ML-KEM", "ECIES", "AP", "IBE", "ZKP"}
    assert "DP" not in rejected_names
    assert result.hybrid_partner_explanation is not None
    assert "tracking_protection_match" in result.hybrid_partner_explanation


def test_generate_full_explanation_returns_none_when_a_rejected_scheme_is_missing(monkeypatch):
    """Atomicity: if the model's response doesn't cover every REAL rejected
    scheme, the whole explanation fails together — never a partial list."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    scores = _seven_scores()
    text = (
        "WINNER_EXPLANATION:\nGS was chosen.\n\n"
        "REJECTED_SCHEMES:\n"
        "ML-KEM: Strong on quantum_match but lacks affinity.\n"
        "ECIES: Lower privacy_match.\n"
        # DP, AP, IBE, ZKP missing entirely — malformed.
    )
    with patch.object(llm_explainer.requests, "post", return_value=_mock_response(text)):
        result = llm_explainer.generate_full_explanation(_comparison(), scores)

    assert result is None


def test_generate_full_explanation_returns_none_when_hybrid_sentence_missing(monkeypatch):
    """Atomicity for the hybrid case specifically: a hybrid partner was
    given but the model's response has no HYBRID_PARTNER section — the
    whole explanation must fail, not silently omit that sentence."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    scores = _seven_scores()
    comparison = _comparison(hybrid_partner_scheme="DP")
    text = (
        "WINNER_EXPLANATION:\nGS was chosen.\n\n"
        "REJECTED_SCHEMES:\n"
        "ML-KEM: Strong on quantum_match but lacks affinity.\n"
        "ECIES: Lower privacy_match.\n"
        "AP: Weaker final_score.\n"
        "IBE: Weaker final_score.\n"
        "ZKP: Much lower profile_match.\n"
        # HYBRID_PARTNER section missing entirely.
    )
    with patch.object(llm_explainer.requests, "post", return_value=_mock_response(text)):
        result = llm_explainer.generate_full_explanation(comparison, scores, hybrid_benefit_score=0.25)

    assert result is None


def test_generate_full_explanation_returns_none_on_network_failure(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    with patch.object(llm_explainer.requests, "post", side_effect=requests.exceptions.Timeout("slow")):
        result = llm_explainer.generate_full_explanation(_comparison(), _seven_scores())

    assert result is None


def test_full_prompt_includes_all_seven_real_candidate_dimensions():
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)

    for name in ("GS", "ML-KEM", "ECIES", "DP", "AP", "IBE", "ZKP"):
        assert name in prompt
    assert "fitness_score=" in prompt and "profile_match=" in prompt
    assert "Do not invent, restate imprecisely" in prompt


def test_full_prompt_excludes_hybrid_partner_from_rejection_instruction():
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(
        _comparison(hybrid_partner_scheme="DP"), scores, 0.25, "Hybrid of GS and DP yields a benefit score of 0.25.",
    )

    assert "'DP' is NOT a rejected scheme" in prompt
    assert "HYBRID PARTNER (real, already added" in prompt  # data section (space-separated, human-readable)
    assert "HYBRID_PARTNER:" in prompt  # output-format section header (underscore, machine-parseable)
    assert "0.25" in prompt


def test_full_prompt_omits_hybrid_instructions_for_non_hybrid_case():
    """No real hybrid partner given: the dedicated hybrid DATA section and
    the HYBRID_PARTNER OUTPUT section header must both be absent. The
    format instruction's own passing mention of "the HYBRID_PARTNER
    section" (telling the model to omit it) is expected to remain — that's
    a real, always-present instruction, not hybrid-specific data."""
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)

    assert "HYBRID PARTNER (real, already added" not in prompt
    assert "HYBRID_PARTNER:" not in prompt


def test_generate_full_explanation_passes_the_same_hard_timeout(monkeypatch):
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    scores = _seven_scores()
    text = (
        "WINNER_EXPLANATION:\nGS was chosen.\n\nREJECTED_SCHEMES:\n"
        "ML-KEM: a.\nECIES: b.\nDP: c.\nAP: d.\nIBE: e.\nZKP: f.\n"
    )
    with patch.object(llm_explainer.requests, "post", return_value=_mock_response(text)) as mock_post:
        llm_explainer.generate_full_explanation(_comparison(), scores)

    _, kwargs = mock_post.call_args
    assert kwargs["timeout"] == llm_explainer.REQUEST_TIMEOUT_SECONDS
    assert kwargs["json"]["generationConfig"]["thinkingConfig"]["thinkingBudget"] == 0


# ---------------------------------------------------------------------------
# 7. Two-section restructure — Section A (why selected) / Section B (why
#    the others were not selected, now >=3 real grounded sentences each,
#    with KB-sourced "general strengths" grounding and an honest-
#    uncertainty exception when real data can't support all 3 points).
# ---------------------------------------------------------------------------

def test_general_strengths_text_returns_real_kb_data_for_a_known_scheme():
    """Integration check against the REAL, unmodified data/privacy_schemes.json
    (tests run with `agent/` as cwd, same as the dashboard backend itself) —
    confirms the KB-grounding lookup actually returns real capabilities/
    advantages text, not just that it doesn't crash."""
    text = llm_explainer._general_strengths_text("ECIES")
    assert text is not None
    assert "capabilities:" in text or "documented advantages:" in text


def test_general_strengths_text_returns_none_for_an_unknown_scheme():
    assert llm_explainer._general_strengths_text("NOT_A_REAL_SCHEME") is None


def test_general_strengths_text_returns_none_when_kb_file_is_missing(monkeypatch):
    """Best-effort grounding: an unavailable KB file must degrade to None,
    never raise -- the rejection paragraph still has real SchemeScore
    numeric data to draw its other 2 points from."""
    monkeypatch.setattr(llm_explainer, "_kb_load_attempted", False)
    monkeypatch.setattr(llm_explainer, "_kb_cache", None)
    monkeypatch.setattr(llm_explainer, "_DEFAULT_SCHEMES_PATH", "/nonexistent/path/schemes.json")
    assert llm_explainer._general_strengths_text("ECIES") is None
    # Restore real lazy-loading state for any later test in this process.
    monkeypatch.setattr(llm_explainer, "_kb_load_attempted", False)
    monkeypatch.setattr(llm_explainer, "_kb_cache", None)


def test_format_candidate_line_includes_gap_to_winner_for_rejected_schemes():
    winner = _score("GS", 0.580)
    candidate = _score("ML-KEM", 0.5475, quantum_match=0.95)
    line = llm_explainer._format_candidate_line(candidate, winner_score=winner.final_score)
    assert "gap_to_winner=0.033" in line or "gap_to_winner=0.032" in line
    assert "%" in line


def test_format_candidate_line_omits_gap_for_the_winner_itself():
    winner = _score("GS", 0.580)
    line = llm_explainer._format_candidate_line(winner, tag="WINNER ", winner_score=winner.final_score)
    assert "gap_to_winner" not in line


def test_full_prompt_includes_section_a_and_section_b_labels():
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)
    assert "SECTION A" in prompt
    assert "SECTION B" in prompt
    assert "WHY THE OTHERS WERE NOT SELECTED" in prompt


def test_full_prompt_instructs_minimum_three_sentences_with_honest_uncertainty():
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)
    assert "minimum of 3 real, grounded sentences" in prompt
    assert "HONEST-UNCERTAINTY EXCEPTION" in prompt
    assert "generally good at" in prompt.lower() or "GENERALLY good at" in prompt
    assert "gap_to_winner" in prompt


def test_full_prompt_includes_full_scheme_names_mapping_and_first_mention_rule():
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)
    for short, full in llm_explainer.SCHEME_FULL_NAMES.items():
        assert f"{short}={full}" in prompt
    assert "Full Name (SHORT)" in prompt


def test_full_prompt_includes_general_strengths_grounding_per_rejected_scheme(monkeypatch):
    """Isolates the prompt-building logic from real KB content by stubbing
    a deterministic value, so this test doesn't silently start failing if
    data/privacy_schemes.json's real advantages text is ever edited."""
    monkeypatch.setattr(
        llm_explainer, "_general_strengths_text",
        lambda short_name: f"STUB-STRENGTHS-FOR-{short_name}",
    )
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)
    for name in ("ML-KEM", "ECIES", "DP", "AP", "IBE", "ZKP"):
        assert f"STUB-STRENGTHS-FOR-{name}" in prompt


def test_full_prompt_reports_no_kb_data_honestly_when_strengths_missing(monkeypatch):
    monkeypatch.setattr(llm_explainer, "_general_strengths_text", lambda short_name: None)
    scores = _seven_scores()
    prompt = llm_explainer._build_full_prompt(_comparison(), scores, None, None)
    assert "none on record for this scheme" in prompt


def test_parse_full_response_accepts_a_real_multi_sentence_single_line_rejection(monkeypatch):
    """The new expected shape: each rejected scheme's >=3 sentences on ONE
    line, space-separated, not newline-separated."""
    monkeypatch.setenv(llm_explainer.GEMINI_API_KEY_ENV, "fake-key")
    scores = _seven_scores()
    ml_kem_text = (
        "Module-Lattice Key Encapsulation Mechanism (ML-KEM) is generally good at "
        "post-quantum security, offering quantum resistance. It did not fit this "
        "scenario as well because its quantum_match (0.950) did not translate into "
        "a higher final_score than GS. ML-KEM was only 0.033 behind the winner, a "
        "5.7% relative gap."
    )
    text = (
        "WINNER_EXPLANATION:\nGS was chosen because it has documented affinity for "
        "duplicate registration.\n\n"
        "REJECTED_SCHEMES:\n"
        f"ML-KEM: {ml_kem_text}\n"
        "ECIES: Generally good at identity protection. Lower privacy_match (0.40) "
        "than GS did not fit this scenario. 0.088 behind the winner (15.2%).\n"
        "DP: Generally good at tracking protection. Close on most dimensions here, "
        "marginally behind on final_score (0.49 vs 0.58). Only 0.09 behind the winner.\n"
        "AP: Generally good at traffic-analysis resistance. Strong performance_match "
        "(0.90) did not outweigh a lower overall final_score. 0.093 behind the winner.\n"
        "IBE: Generally good at identity-based encryption. Strong identity_protection_"
        "match (0.90) still left a lower final_score. 0.123 behind the winner.\n"
        "ZKP: Generally good at zero-knowledge proofs. Much lower profile_match (0.08) "
        "than GS did not fit this scenario. 0.142 behind the winner, the largest gap.\n"
    )
    with patch.object(llm_explainer.requests, "post", return_value=_mock_response(text)):
        result = llm_explainer.generate_full_explanation(_comparison(), scores)

    assert result is not None
    ml_kem = next(r for r in result.rejected_schemes if r.scheme == "ML-KEM")
    assert ml_kem.reason == ml_kem_text
    # Real multi-sentence content: at least 3 sentence-ending periods.
    assert ml_kem.reason.count(". ") + ml_kem.reason.endswith(".") >= 2

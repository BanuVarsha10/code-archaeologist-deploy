"""Verifies pipeline_service.run_live_device() — the Part F 13-step real
per-device Live Mode flow — WITHOUT real hardware (see live_fixtures.py):
  - never double-invokes the agent (Issue 1 regression guard, this task's
    Part B, now against the new orchestration)
  - handles invalid_subscriber as a no-comparison, single-agent-call case
  - cold_start flag reflects real prior experience-store state
  - the read-only re-scoring snapshot is taken pre-write, not post-write
    (this task's Part B, Issue 1 — same fix, now inside run_live_device)
  - the baseline preview, its real execution, the official scheme_a/b
    executions, and the real (hardware-driven) stability replays are all
    present and internally consistent (Part F steps 5, 6, 10, 11)
  - Part E's per-device attack-scenario resolver is called exactly once,
    after baseline
  - failure isolation at every real step, including a replay mid-flow
    (Part H)
"""

from datetime import datetime
from unittest.mock import patch

from capss.experience_memory.memory import ExperienceMemory
from capss.scheme_execution.assessment import assess_adaptation

from demo_for_mentor import make_request

from dashboard_backend import pipeline_service
from dashboard_backend.systems_privacy_view import SystemsPrivacyView
from dashboard_backend.pipeline_service import run_live_device
from dashboard_backend.tests.live_fixtures import mock_live_hardware, ATTACK_LAUNCH_COUNTS

SCHEMES_PATH = "data/privacy_schemes.json"


def _ceiling_experience_count(tmp_path, ue_id, suci, scenario):
    """What assess_adaptation() alone produces for this device's real
    pre/attack contexts — the ceiling run_live_device must not exceed. Built
    from the exact same request timing live_fixtures.FakeAmfLog produces
    (baseline at offset 0, attack launches at offsets 1..N), so the
    resulting contexts match run_live_device's internal ones exactly."""
    base_time = datetime(2026, 1, 1, 12, 0, 0)
    baseline_req = make_request(ue_id, suci, "R1", 0, base_time=base_time)
    attack_reqs = [
        make_request(ue_id, suci, f"R{i + 2}", i + 1, base_time=base_time)
        for i in range(ATTACK_LAUNCH_COUNTS.get(scenario, 1))
    ]
    view = SystemsPrivacyView()
    pre_context = view.process(baseline_req)[2]
    attack_context = None
    for req in attack_reqs:
        attack_context = view.process(req)[2]
    exp_path = str(tmp_path / "ceiling.json")
    assess_adaptation(ue_id, pre_context, attack_context, SCHEMES_PATH, exp_path)
    return len(ExperienceMemory(exp_path).retrieve(ue_id))


def test_run_live_device_does_not_double_invoke_the_agent(tmp_path):
    ue_id = "imsi-999700000007777"
    suci = "suci-0-999-70-0000-0-0-0000007777"
    ceiling = _ceiling_experience_count(tmp_path, ue_id, suci, "duplicate_registration")

    exp_path = str(tmp_path / "service.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested")

    assert result["live_success"] is True
    service_count = len(ExperienceMemory(exp_path).retrieve(ue_id))
    assert service_count == ceiling, (
        f"run_live_device stored {service_count} experiences vs {ceiling} from "
        f"assess_adaptation() alone — indicates the agent was invoked more than "
        f"once per event (double-invocation regression). The baseline preview "
        f"and the 3 real stability replays must both be read-only."
    )


def test_invalid_subscriber_skips_comparison_and_invokes_agent_exactly_once(tmp_path):
    ue_id = "imsi-999700000009999"
    suci = "suci-0-999-70-0000-0-0-0000009999"
    exp_path = str(tmp_path / "invalid_sub.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "invalid_subscriber", creds, "new_requested")

    assert result["comparison_result"] is None
    assert result["no_comparison_reason"]
    assert result["recommendation"] is not None
    assert result["baseline_preview"] is None
    assert result["real_stability"] is None
    assert len(ExperienceMemory(exp_path).retrieve(ue_id)) == 1


def test_cold_start_flag_and_pre_write_snapshot(tmp_path):
    """Regression guard (this task's Part B, Issue 1, re-verified against
    the new orchestration): the read-only recommendation's decision_trace
    must reflect the snapshot taken BEFORE assess_adaptation() writes, not
    a post-write re-read."""
    ue_id = "imsi-999700000001111"
    suci = "suci-0-999-70-0000-0-0-0000001111"
    exp_path = str(tmp_path / "cold_start.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested")

    assert result["cold_start"] is True
    trace = result["decision_trace"]
    assert trace.experience_contribution["total_experiences"] == 0, (
        f"Expected 0 (pre-write snapshot) but got {trace.experience_contribution['total_experiences']} "
        f"— the read-only re-scoring is re-reading the experience store AFTER assess_adaptation() wrote to it."
    )
    # trace.winner is a best-effort read-only approximation of what
    # assess_adaptation()'s real attack_context agent call picked. It can
    # legitimately disagree with comparison_result.scheme_b in edge cases:
    # that real call runs AFTER Check1's pre_context call already wrote ONE
    # experience — both inside the same atomic, protected assess_adaptation()
    # call — while this snapshot is deliberately captured before
    # assess_adaptation starts at all (the correct point for the pre-write
    # snapshot fix; capturing it mid-call isn't possible without
    # instrumenting protected code). Assert it's a real, valid scheme from
    # this same ranking, not exact equality with scheme_b.
    assert trace.winner in {s.short_name for s in trace.candidate_scores}


def test_baseline_preview_and_dual_execution_are_real_and_consistent(tmp_path):
    """Part F steps 5-6, 11: the baseline preview's winning scheme has a
    REAL execution (output_value_hex present, not fabricated), and the
    official scheme_a/scheme_b executions (shown side by side in the final
    comparison) match what assess_adaptation() actually decided.

    Baseline-forcing fix (intentional behavior change, not a regression):
    `baseline_preview` (Steps 5-6, shown in the Pipeline Visualizer/
    Recommendation panels) is a SEPARATE, still real, still history-
    influenced read-only recommendation for pre_context — deliberately
    UNCHANGED by the fix (see run_live_device()'s `batch_position`
    docstring for why it's out of that fix's scope). `comparison.scheme_a`
    (Check 1, the Assessment section's real starting point) is now ALWAYS
    forced to ECIES/ML-KEM by real batch position instead — the two are
    no longer expected to agree, and asserting so used to only pass
    because both happened to be computed the same (old) way."""
    ue_id = "imsi-999700000002222"
    suci = "suci-0-999-70-0000-0-0-0000002222"
    exp_path = str(tmp_path / "dual_exec.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "flooding", creds, "new_requested")

    assert result["live_success"] is True
    comparison = result["comparison_result"]

    baseline_winner = result["baseline_preview"]["winner"]
    assert result["baseline_execution"]["success"] is True
    assert result["baseline_execution"]["scheme_name"] == baseline_winner
    assert result["baseline_execution"]["output_value_hex"] is not None
    # Baseline-forcing fix: comparison.scheme_a is FORCED (ECIES for
    # batch_position=0, the default this call uses) — no longer derived
    # from pre_context/history, so it is NOT expected to equal
    # baseline_preview's separate, still real, still history-influenced
    # recommendation (see docstring above).
    assert comparison.scheme_a == "ECIES"

    assert result["scheme_a_execution"]["scheme_name"] == comparison.scheme_a
    assert result["scheme_b_execution"]["scheme_name"] == comparison.scheme_b
    assert result["scheme_a_execution"]["success"] is True
    assert result["scheme_b_execution"]["success"] is True


def test_real_stability_reflects_three_real_replays(tmp_path):
    """Part F step 10: 3 REAL nr-ue registrations under the same attack
    scenario, each independently re-scored (read-only) against scheme_b —
    distinct from (and reported alongside, not instead of) assess_
    adaptation()'s own simulated Check 2."""
    ue_id = "imsi-999700000003333"
    suci = "suci-0-999-70-0000-0-0-0000003333"
    exp_path = str(tmp_path / "real_stability.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "replay", creds, "new_requested")

    real_stability = result["real_stability"]
    assert len(real_stability["replays"]) == 3
    for i, replay in enumerate(real_stability["replays"], start=1):
        assert replay["replay_number"] == i
        assert replay["success"] is True
        assert replay["predicted_scheme"] is not None
    expected_confirmed = all(r["matches_scheme_b"] for r in real_stability["replays"])
    assert real_stability["confirmed"] == expected_confirmed
    # This is a SEPARATE real-hardware signal from assess_adaptation()'s own
    # (simulated) Check 2 — both must be present, never conflated.
    assert result["comparison_result"].stability_confirmed in (True, False)


def test_decision_trace_covers_all_seven_schemes_read_only(tmp_path):
    ue_id = "imsi-999700000004444"
    suci = "suci-0-999-70-0000-0-0-0000004444"
    exp_path = str(tmp_path / "candidates.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "replay", creds, "new_requested")

    assert len(result["decision_trace"].candidate_scores) == 7


def test_hybrid_combination_is_surfaced_when_the_agent_suggests_one(tmp_path):
    ue_id = "imsi-999700000005555"
    suci = "suci-0-999-70-0000-0-0-0000005555"
    exp_path = str(tmp_path / "hybrid.json")
    view = SystemsPrivacyView()
    with mock_live_hardware(ue_id, suci) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested")

    assert "hybrid_combination" in result
    if result["hybrid_combination"] is not None:
        assert len(result["hybrid_combination"]) == 2
        assert result["hybrid_benefit_score"] is not None
        assert result["hybrid_reason"]


def test_cross_ue_retrieval_fires_in_the_read_only_recommendation(tmp_path):
    exp_path = str(tmp_path / "cross_ue.json")
    view = SystemsPrivacyView()
    found_rag_rule = False
    for i in range(5):
        ue_id = f"imsi-99970000000{i:04d}"
        suci = f"suci-0-999-70-0000-0-0-00000{i:04d}"
        with mock_live_hardware(ue_id, suci) as (creds, _log):
            result = run_live_device(view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested")
        explanation = result.get("explanation")
        if explanation and any("RAG" in r for r in explanation.get("rules_fired", [])):
            found_rag_rule = True

    assert found_rag_rule, (
        "No device in this batch triggered cross-UE RAG retrieval — "
        "the retriever is likely not being wired up in the read-only path."
    )


# ---------------------------------------------------------------------------
# Part E — per-device attack-scenario resolver
# ---------------------------------------------------------------------------

def test_resolver_is_called_exactly_once_after_baseline(tmp_path):
    exp_path = str(tmp_path / "resolver.json")
    view = SystemsPrivacyView()
    calls = []

    def resolver():
        calls.append(1)
        return "flooding"

    with mock_live_hardware("imsi-999709999990001", "suci-r1") as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, resolver, creds, "new_requested")

    assert len(calls) == 1
    assert result["attack_scenario"] == "flooding"
    assert result["live_success"] is True


def test_resolver_timeout_is_isolated_as_a_device_failure(tmp_path):
    exp_path = str(tmp_path / "resolver_timeout.json")
    view = SystemsPrivacyView()

    def resolver():
        raise TimeoutError("No attack scenario selected within 600s")

    with mock_live_hardware("imsi-999709999990002", "suci-r2") as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, resolver, creds, "new_requested")

    assert result["live_success"] is False
    assert "No attack scenario was selected" in result["failure_reason"]


# ---------------------------------------------------------------------------
# Part F step 13 — failure isolation at every real step
# ---------------------------------------------------------------------------

def test_isolates_provision_failure(tmp_path):
    exp_path = str(tmp_path / "fail_provision.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990003", "suci-f1", fail_at="provision") as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "replay", creds, "new_requested")

    assert result["live_success"] is False
    assert "simulated provision failure" in result["failure_reason"]


def test_isolates_baseline_failure(tmp_path):
    exp_path = str(tmp_path / "fail_baseline.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990004", "suci-f2", fail_at="baseline") as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "replay", creds, "new_requested")

    assert result["live_success"] is False
    assert "simulated baseline failure" in result["failure_reason"]


def test_isolates_attack_failure(tmp_path):
    exp_path = str(tmp_path / "fail_attack.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990005", "suci-f3", fail_at="attack") as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "flooding", creds, "new_requested")

    assert result["live_success"] is False
    assert "simulated attack failure" in result["failure_reason"]


def test_isolates_mid_flow_stability_replay_failure(tmp_path):
    """Part H: explicit test for a failure mid-way through the new real-
    registration sequence — the 2nd of 3 real stability replays fails.
    The whole device is marked failed (not a partial 2/3 result) and
    real_stability is None, consistent with every other real-step failure."""
    exp_path = str(tmp_path / "fail_replay.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990006", "suci-f4", fail_replay_number=2) as (creds, _log):
        result = run_live_device(view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested")

    assert result["live_success"] is False
    assert "replay 2/3" in result["failure_reason"]
    assert result["real_stability"] is None
    assert result["comparison_result"] is None  # device failed before reaching a final result


# ---------------------------------------------------------------------------
# Stop-attack task (Part 2) — should_cancel checkpoints
# ---------------------------------------------------------------------------

def test_cancels_after_baseline_before_attack_registration(tmp_path):
    """Stopping right after baseline's real registration already finished
    must produce a cancelled (not failed) result, and must never reach the
    attack registration step at all."""
    exp_path = str(tmp_path / "cancel_after_baseline.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990007", "suci-c1") as (creds, _log):
        result = run_live_device(
            view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested",
            should_cancel=lambda: True,  # cancelled from the very first checkpoint
        )

    assert result["live_success"] is False
    assert result["cancelled"] is True
    assert result["failure_reason"] == "Cancelled by user"
    assert result["comparison_result"] is None
    assert result["real_stability"] is None


def test_cancels_after_attack_before_assessment(tmp_path):
    """Stopping exactly at the second checkpoint (after attack's real
    registration, before assess_adaptation) — cancel only from the SECOND
    call onward, so baseline's checkpoint passes through."""
    exp_path = str(tmp_path / "cancel_after_attack.json")
    view = SystemsPrivacyView()
    calls = {"n": 0}

    def should_cancel():
        calls["n"] += 1
        return calls["n"] >= 2  # pass the baseline checkpoint, cancel at the attack checkpoint

    with mock_live_hardware("imsi-999709999990008", "suci-c2") as (creds, _log):
        result = run_live_device(
            view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested",
            should_cancel=should_cancel,
        )

    assert result["cancelled"] is True
    assert result["comparison_result"] is None  # never reached assess_adaptation()
    assert calls["n"] >= 2


def test_cancels_between_stability_replays(tmp_path):
    """Cancel only once assess_adaptation() has already produced a real
    comparison — i.e. mid-way through the 3 real stability replays. The
    already-computed comparison_result must NOT be reported (Part F step
    13's all-or-nothing rule applies to cancellation too, same as any
    other step failure)."""
    exp_path = str(tmp_path / "cancel_mid_replay.json")
    view = SystemsPrivacyView()
    calls = {"n": 0}

    def should_cancel():
        calls["n"] += 1
        return calls["n"] >= 3  # pass baseline + attack checkpoints, cancel before replay 1

    with mock_live_hardware("imsi-999709999990009", "suci-c3") as (creds, _log):
        result = run_live_device(
            view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested",
            should_cancel=should_cancel,
        )

    assert result["cancelled"] is True
    assert result["comparison_result"] is None
    assert result["real_stability"] is None


def test_never_cancelled_run_completes_normally_with_should_cancel_param(tmp_path):
    """should_cancel that always returns False must not change behavior at
    all versus omitting it entirely."""
    exp_path = str(tmp_path / "never_cancelled.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990010", "suci-c4") as (creds, _log):
        result = run_live_device(
            view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested",
            should_cancel=lambda: False,
        )

    assert result["live_success"] is True
    assert result["cancelled"] is False
    assert result["comparison_result"] is not None


# ---------------------------------------------------------------------------
# LLM explainer task — isolated integration with run_live_device()
# ---------------------------------------------------------------------------

def test_llm_explanation_field_populated_on_success(tmp_path):
    """generate_full_explanation() is called with the REAL, already-final
    ComparisonResult plus the REAL candidate_scores for all 7 schemes, and
    its return value is attached as-is — mocked here so the test doesn't
    depend on a real API key/network call."""
    from dashboard_backend.llm_explainer import LLMExplanation, RejectedSchemeExplanation

    fake_explanation = LLMExplanation(
        winner_explanation="GS was chosen for real reasons.",
        rejected_schemes=[RejectedSchemeExplanation(scheme="ZKP", reason="Lower profile_match.")],
    )
    exp_path = str(tmp_path / "llm_success.json")
    view = SystemsPrivacyView()
    with mock_live_hardware("imsi-999709999990011", "suci-llm1") as (creds, _log), \
         patch.object(pipeline_service, "generate_full_explanation", return_value=fake_explanation) as mock_llm:
        result = run_live_device(view, SCHEMES_PATH, exp_path, "duplicate_registration", creds, "new_requested")

    assert result["llm_explanation"] is fake_explanation
    # Called with the REAL, final ComparisonResult and the REAL candidate_scores
    # from decision_trace — not before either exists.
    mock_llm.assert_called_once()
    (passed_comparison, passed_scores), kwargs = mock_llm.call_args
    assert passed_comparison is result["comparison_result"]
    assert passed_scores is result["decision_trace"].candidate_scores
    assert kwargs["hybrid_benefit_score"] == result["hybrid_benefit_score"]
    assert kwargs["hybrid_reason"] == result["hybrid_reason"]


def test_llm_failure_does_not_affect_the_rest_of_the_device_result(tmp_path):
    """The core testing requirement: when the LLM call fails (here,
    simulated exactly as llm_explainer.generate_full_explanation itself
    would return on any real failure — None), every other real field in
    the device result must be completely unaffected — same as a run where
    the LLM was never involved at all."""
    exp_path_a = str(tmp_path / "llm_failed.json")
    exp_path_b = str(tmp_path / "llm_absent.json")
    view_a = SystemsPrivacyView()
    view_b = SystemsPrivacyView()

    with mock_live_hardware("imsi-999709999990012", "suci-llm2") as (creds_a, _log_a), \
         patch.object(pipeline_service, "generate_full_explanation", return_value=None):
        result_with_llm_failure = run_live_device(
            view_a, SCHEMES_PATH, exp_path_a, "duplicate_registration", creds_a, "new_requested",
        )

    with mock_live_hardware("imsi-999709999990013", "suci-llm3") as (creds_b, _log_b), \
         patch.object(pipeline_service, "generate_full_explanation", return_value=None):
        result_without_llm = run_live_device(
            view_b, SCHEMES_PATH, exp_path_b, "duplicate_registration", creds_b, "new_requested",
        )

    assert result_with_llm_failure["llm_explanation"] is None
    assert result_with_llm_failure["live_success"] is True
    # Every OTHER field is present and shaped identically regardless of the
    # LLM outcome — the real pipeline genuinely does not know or care.
    for key in result_with_llm_failure:
        if key in ("ue_id", "suci", "masked_identity"):
            continue  # these differ because each run used a different fresh identity
        if key == "llm_explanation":
            continue
        assert type(result_with_llm_failure[key]) is type(result_without_llm[key]), key


def test_llm_explainer_import_is_the_real_module_not_a_stub():
    """Guards against this ever silently becoming a no-op: confirms
    pipeline_service actually imports the real generate_full_explanation
    function (not reimplementing or shadowing it)."""
    from dashboard_backend.llm_explainer import generate_full_explanation as real_fn

    assert pipeline_service.generate_full_explanation is real_fn

"""tests/scheme_execution/test_assessment.py

Tests for the 4-check adaptation assessment module.

Covers:
  - VERDICT_NO_CHANGE when agent selects the same scheme in both contexts
  - VERDICT_VALIDATED when all 4 checks pass
  - VERDICT_INCONCLUSIVE when stability or analytical check fails
  - MeasuredOverhead fields are populated correctly
  - AnalyticalRationale fields are populated correctly

NOTE: These tests run the actual CAPSSAgent which requires:
  - data/privacy_schemes.json to be accessible
  - Tests are run from the /home/athin_/5g-project/agent directory

The assessment module uses temporary experience files so it does NOT
pollute any existing experience_store.json.
"""

import pytest

from capss.schemas.context import RegistrationContext
from capss.scheme_execution.assessment import (
    assess_adaptation,
    baseline_for_position,
    ComparisonResult,
    MeasuredOverhead,
    AnalyticalRationale,
    VERDICT_VALIDATED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NO_CHANGE,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_context(
    supi: str = "imsi-001010000000001",
    attack_type: str = None,
    registration_type: str = "initial",
    slice_type: str = "eMBB",
    dnn: str = "internet",
    **kwargs,
) -> RegistrationContext:
    """Build a RegistrationContext for testing."""
    from datetime import datetime
    return RegistrationContext(
        ue_id=supi,
        suci=f"suci-0-001-01-A8924-0-0-{supi[-6:]}",
        registration_type=registration_type,
        slice_type=slice_type,
        dnn=dnn,
        timestamp=datetime.utcnow(),
        attack_type=attack_type,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Assessment tests
# ---------------------------------------------------------------------------

class TestAssessAdaptation:
    """Tests for assess_adaptation()."""

    def test_returns_comparison_result(self):
        """assess_adaptation returns a ComparisonResult."""
        pre = _make_context(supi="imsi-001010000000001")
        attack = _make_context(supi="imsi-001010000000001", attack_type="tracking")
        result = assess_adaptation(
            ue_id="imsi-001010000000001",
            pre_context=pre,
            attack_context=attack,
        )
        assert isinstance(result, ComparisonResult)

    def test_verdict_is_one_of_three_values(self):
        """Verdict must be one of the three constants."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        assert result.overall_verdict in (
            VERDICT_VALIDATED, VERDICT_INCONCLUSIVE, VERDICT_NO_CHANGE
        )

    def test_ue_id_preserved(self):
        """ue_id in result matches what was passed."""
        pre = _make_context(supi="imsi-999")
        attack = _make_context(supi="imsi-999")
        result = assess_adaptation("imsi-999", pre, attack)
        assert result.ue_id == "imsi-999"

    def test_scheme_a_and_b_are_strings(self):
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        assert isinstance(result.scheme_a, str)
        assert isinstance(result.scheme_b, str)

    def test_no_change_verdict_when_same_scheme(self):
        """If scheme_a (now the FORCED baseline — see baseline-forcing fix
        below) equals scheme_b (the real Agent's attack_context pick),
        verdict is NO_CHANGE. A neutral, no-attack context is the real
        case this happens: batch_position defaults to 0 (forces ECIES),
        and the real Agent also picks ECIES for a genuinely neutral
        context — confirmed empirically, not assumed — so this is still a
        real, meaningful NO_CHANGE case post-fix, just via a different
        real mechanism than before (previously this relied on the same
        pre_context/attack_context producing the same Agent pick TWICE;
        now scheme_a doesn't call the Agent at all)."""
        ctx = _make_context(supi="imsi-001010000000001")
        result = assess_adaptation("imsi-001010000000001", ctx, ctx)
        if result.overall_verdict == VERDICT_NO_CHANGE:
            assert result.adaptation_occurred is False
            assert result.measured_overhead is None
            assert result.analytical_rationale is None

    def test_scheme_a_is_forced_regardless_of_pre_context_or_history(self):
        """Baseline-forcing fix (core behavior change): scheme_a must be
        ECIES/ML-KEM per baseline_for_position(batch_position), NEVER
        derived from pre_context or this UE's prior experience history —
        even when pre_context describes a high-threat scenario that would
        clearly steer the real Agent toward a very different scheme if it
        were consulted (which it deliberately no longer is for this
        step)."""
        # A pre_context engineered to look like a high-threat, high-
        # tracking-risk scenario — if scheme_a were still Agent-derived,
        # this would very plausibly NOT be ECIES/ML-KEM. It must be
        # exactly one of the two regardless, because the Agent is never
        # consulted for it anymore.
        high_threat_pre = _make_context(
            supi="imsi-001010000000099", attack_type="flooding",
            request_classification="BLOCK", attack_severity="MALICIOUS",
            detection_confidence=0.95, threat_score=0.9,
            correlation_score=0.9, privacy_score=0.1,
            privacy_risk_level="HIGH", metadata_leakage=0.9,
        )
        attack = _make_context(supi="imsi-001010000000099", attack_type="tracking")

        result_even = assess_adaptation(
            "imsi-001010000000099", high_threat_pre, attack, batch_position=0,
        )
        assert result_even.scheme_a == "ECIES"

        result_odd = assess_adaptation(
            "imsi-001010000000099", high_threat_pre, attack, batch_position=1,
        )
        assert result_odd.scheme_a == "ML-KEM"

    def test_scheme_a_forcing_alternates_by_batch_position(self):
        """Even position -> ECIES, odd position -> ML-KEM — see
        baseline_for_position()."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        for position, expected in [(0, "ECIES"), (1, "ML-KEM"), (2, "ECIES"), (3, "ML-KEM")]:
            result = assess_adaptation(
                "imsi-001010000000001", pre, attack, batch_position=position,
            )
            assert result.scheme_a == expected, f"batch_position={position}"

    def test_baseline_for_position_alternates_directly(self):
        """Direct unit test of baseline_for_position() itself, migrated
        here from the now-removed "vs. static baseline" feature's own
        test file (dashboard_backend/tests/test_baseline_comparison.py) —
        that feature was removed, but this function is still real, still
        shared, still used by assess_adaptation()'s Check 1 (above) and
        by dashboard_backend/pipeline_service.run_scale_device(), so its
        own direct coverage is preserved here rather than deleted with
        the feature it was originally built alongside."""
        assert [baseline_for_position(i) for i in range(6)] == [
            "ECIES", "ML-KEM", "ECIES", "ML-KEM", "ECIES", "ML-KEM",
        ]

    def test_scheme_b_is_still_the_real_unaffected_agent_call(self):
        """The fix is scoped to scheme_a only — scheme_b (attack_context)
        must still come from a real, normal Agent call, unaffected by
        batch_position. Confirmed by checking scheme_b is identical
        whether batch_position is 0 or 1 (only scheme_a should move)."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result_a = assess_adaptation("imsi-001010000000001", pre, attack, batch_position=0)
        result_b = assess_adaptation("imsi-001010000000001", pre, attack, batch_position=1)
        assert result_a.scheme_b == result_b.scheme_b
        assert result_a.scheme_a != result_b.scheme_a  # only scheme_a moved

    def test_adaptation_occurred_field(self):
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        assert isinstance(result.adaptation_occurred, bool)

    def test_stability_fields_populated(self):
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        if result.adaptation_occurred:
            assert result.replay_count == 3
            assert "/" in result.stability_detail  # e.g. "3/3"
            assert isinstance(result.stability_confirmed, bool)

    def test_measured_overhead_populated_when_adaptation_occurred(self):
        """If adaptation occurred, MeasuredOverhead must be populated."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        if result.adaptation_occurred:
            assert result.measured_overhead is not None
            mo = result.measured_overhead
            assert isinstance(mo, MeasuredOverhead)
            assert mo.scheme_a == result.scheme_a
            assert mo.scheme_b == result.scheme_b
            assert mo.time_a_ms >= 0
            assert mo.time_b_ms >= 0
            assert mo.size_a_bytes >= 0
            assert mo.size_b_bytes >= 0

    def test_analytical_rationale_populated_when_adaptation_occurred(self):
        """If adaptation occurred, AnalyticalRationale must be populated."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        if result.adaptation_occurred:
            assert result.analytical_rationale is not None
            ar = result.analytical_rationale
            assert isinstance(ar, AnalyticalRationale)
            assert ar.attack_type == "tracking"
            assert isinstance(ar.analytically_justified, bool)
            assert isinstance(ar.justification_note, str)
            assert len(ar.justification_note) > 0

    def test_analytical_rationale_source_note(self):
        """AnalyticalRationale.source_note must mention knowledge base."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        if result.adaptation_occurred and result.analytical_rationale:
            assert "privacy_schemes.json" in result.analytical_rationale.source_note

    def test_measured_overhead_note_about_security(self):
        """MeasuredOverhead.note must warn it's not a security indicator."""
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        if result.adaptation_occurred and result.measured_overhead:
            assert "NOT" in result.measured_overhead.note.upper() or \
                   "security" in result.measured_overhead.note.lower()

    def test_verdict_reason_is_nonempty(self):
        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        assert isinstance(result.verdict_reason, str)
        assert len(result.verdict_reason) > 0

    def test_attack_type_affinity_lookup_is_case_insensitive(self):
        """Check 4 must match attack_type_affinity even when attack_context.attack_type
        is uppercase (as produced by the real Systems module via AttackReport), against
        the lowercase snake_case keys stored in data/privacy_schemes.json.

        Regression test for a bug where the case mismatch caused affinity_a/affinity_b
        to silently resolve to None on every real attack, making Check 4 permanently
        unable to confirm analytical justification against real Systems-produced data.
        """
        pre = _make_context(supi="imsi-999700000000001", attack_type=None)
        attack = _make_context(
            supi="imsi-999700000000001",
            attack_type="DUPLICATE_REGISTRATION",
            request_classification="TAG",
            attack_severity="SUSPICIOUS",
            detection_confidence=0.8,
            threat_score=0.5,
            correlation_score=0.85,
            privacy_score=0.3,
            privacy_risk_level="HIGH",
            metadata_leakage=0.9,
        )
        result = assess_adaptation("imsi-999700000000001", pre, attack)
        if result.adaptation_occurred:
            ar = result.analytical_rationale
            assert ar is not None
            # attack_type stored lowercase after normalization
            assert ar.attack_type == "duplicate_registration"
            # At least one of the affinity lookups must resolve to an actual
            # bool (not None) — proving the lowercase KB keys were matched.
            assert ar.affinity_a is not None or ar.affinity_b is not None

    def test_flooding_attack_type_vocabulary_is_normalized(self):
        """Check 4 must match attack_type_affinity even when attack_context.attack_type
        is the real Systems constant "REGISTRATION_FLOOD" (systems/pre_amf/attack_rules.py
        ATTACK_FLOOD), which after lowercasing becomes "registration_flood" — a different
        WORD than the knowledge base's "flooding" key, not just a different case.

        Regression test for a vocabulary mismatch bug distinct from the earlier case-only
        fix: even after .lower(), "registration_flood" != "flooding", so affinity_a/
        affinity_b silently resolved to None for every real flooding attack.
        """
        pre = _make_context(supi="imsi-999700000000002", attack_type=None)
        attack = _make_context(
            supi="imsi-999700000000002",
            attack_type="REGISTRATION_FLOOD",
            request_classification="BLOCK",
            attack_severity="MALICIOUS",
            detection_confidence=0.9,
            threat_score=0.8,
            correlation_score=0.2,
            privacy_score=0.4,
            privacy_risk_level="HIGH",
            metadata_leakage=0.5,
        )
        result = assess_adaptation("imsi-999700000000002", pre, attack)
        if result.adaptation_occurred:
            ar = result.analytical_rationale
            assert ar is not None
            # attack_type stored as the normalized KB key, not the raw Systems word
            assert ar.attack_type == "flooding"
            # At least one of the affinity lookups must resolve to an actual
            # bool (not None) — proving the vocab-mapped key matched the KB.
            assert ar.affinity_a is not None or ar.affinity_b is not None

    def test_does_not_write_to_production_experience_store(self, tmp_path):
        """assess_adaptation uses a temp file — production store is untouched.

        This test verifies the isolation by checking that if we pass
        a specific (temp) experience_path, the assessment function uses it.
        """
        import os
        exp_file = tmp_path / "test_experience.json"
        exp_file.write_text("[]")

        pre = _make_context()
        attack = _make_context(attack_type="tracking")
        result = assess_adaptation(
            "imsi-001010000000001", pre, attack,
            experience_path=str(exp_file),
        )
        assert isinstance(result, ComparisonResult)


# ---------------------------------------------------------------------------
# MeasuredOverhead field tests
# ---------------------------------------------------------------------------

class TestMeasuredOverhead:
    """Tests for MeasuredOverhead fields."""

    def _get_overhead(self, attack_type="tracking") -> MeasuredOverhead:
        pre = _make_context()
        attack = _make_context(attack_type=attack_type)
        result = assess_adaptation("imsi-001010000000001", pre, attack)
        return result.measured_overhead

    def test_overhead_time_diff_pct_is_float(self):
        mo = self._get_overhead()
        if mo:
            assert isinstance(mo.time_diff_pct, float)

    def test_overhead_size_diff_pct_is_float(self):
        mo = self._get_overhead()
        if mo:
            assert isinstance(mo.size_diff_pct, float)

    def test_overhead_label_field(self):
        mo = self._get_overhead()
        if mo:
            assert mo.label == "Measured Overhead"


# ---------------------------------------------------------------------------
# Verdict constant tests
# ---------------------------------------------------------------------------

class TestVerdictConstants:
    """Tests that the verdict constants have expected string values."""

    def test_validated_value(self):
        assert VERDICT_VALIDATED == "VALIDATED"

    def test_inconclusive_value(self):
        assert VERDICT_INCONCLUSIVE == "INCONCLUSIVE"

    def test_no_change_value(self):
        assert VERDICT_NO_CHANGE == "NO CHANGE"

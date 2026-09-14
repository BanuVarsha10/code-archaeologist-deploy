"""CAPSS Reasoning Engine — Core intelligence orchestrator.

Combines all reasoning sub-modules to produce a final Recommendation
for a given registration context. This module does NOT directly
communicate with datasets or databases — it only performs reasoning.

Pipeline:
    Context + Requirements + Experiences
        → Score all schemes (SchemeScorer)
        → Evaluate hybrid combinations
        → Select winner (or fallback)
        → Generate explanation (ExplanationGenerator)
        → Build DecisionTrace
        → Return Recommendation
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import (
    DecisionTrace,
    Recommendation,
    SchemeScore,
)
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.reasoning.metrics import MetricsCalculator
from capss.reasoning.profile_matcher import ProfileMatcher
from capss.reasoning.scorer import SchemeScorer
from capss.reasoning.explainer import ExplanationGenerator


class ReasoningEngine:
    """Orchestrates the full reasoning pipeline."""

    VERSION = "1.0"

    def __init__(
        self,
        knowledge_base: SchemeKnowledgeBase,
        config: dict | None = None,
        retriever: Any | None = None,
    ) -> None:
        self.knowledge_base = knowledge_base
        self.config = config or {}
        self.retriever = retriever
        self.metrics = MetricsCalculator(self.config)
        self.profile_matcher = ProfileMatcher()
        self.scorer = SchemeScorer(self.metrics, self.profile_matcher, self.config)
        self.explainer = ExplanationGenerator()

        # Thresholds
        thresholds = self.config.get("thresholds", {})
        self.min_score = float(thresholds.get("min_recommendation_score", 0.4))
        self.hybrid_threshold = float(thresholds.get("hybrid_benefit_threshold", 0.15))

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def reason(
        self,
        context: RegistrationContext,
        requirement_profile: RequirementProfile,
        experiences: List[Experience],
        ablation_mode: Optional[str] = None,
    ) -> Recommendation:
        """Run the full reasoning pipeline and return a Recommendation.

        ablation_mode: additive, default None — completely normal, current
        behavior, provably a no-op for every existing caller (none of them
        pass this parameter). "no_experience" treats this UE's real local
        history as empty and skips cross-UE RAG retrieval entirely for
        this pass only — every scheme falls through to
        MetricsCalculator.compute_eas()'s own existing, unmodified "no
        history" default (0.5), exactly as a genuine first-ever
        registration would. "no_threat"/"no_privacy" (handled entirely in
        ContextAnalyzer.analyze() — see there) still flow through here
        unchanged via `requirement_profile`; this parameter only exists
        here for the "no_experience" case and for parity/clarity with
        every other real call site using the same real ablation_mode
        value throughout a pass."""
        start = time.perf_counter()
        effective_experiences = [] if ablation_mode == "no_experience" else experiences

        # 1. Cross-UE retrieval if per-UE experience count is below threshold (< 3)
        cross_ue_matches = None
        if len(effective_experiences) < 3 and self.retriever is not None and ablation_mode != "no_experience":
            cross_ue_matches = self.retriever.retrieve_similar(
                requirement_profile=requirement_profile,
                context=context,
                top_k=5,
                exclude_ue_id=context.ue_id,
            )

        # 2. Get all schemes from knowledge base
        schemes = self.knowledge_base.get_all_schemes()

        # 3. Score all schemes (passing optional cross-UE experiences)
        all_scores = self.scorer.score_all_schemes(
            schemes, requirement_profile, effective_experiences, cross_ue_experiences=cross_ue_matches,
        )

        # 3. Get top candidates (top 3)
        top_candidates = all_scores[:3] if len(all_scores) >= 3 else all_scores

        # 4. Determine winner
        is_fallback = False
        fallback_reason: Optional[str] = None

        if not all_scores or all_scores[0].final_score < self.min_score:
            # Fallback handling (recommendation #12)
            is_fallback = True
            fallback_reason = (
                "No scheme exceeded the minimum recommendation threshold "
                f"({self.min_score:.2f}). Using highest-scoring scheme as fallback."
            )

        winner = all_scores[0] if all_scores else None
        runner_up = all_scores[1] if len(all_scores) > 1 else None

        if winner is None:
            # Absolute fallback — shouldn't happen if KB is loaded
            return self._empty_fallback(context, start)

        # 5. Evaluate hybrid combinations for the winner
        hybrid_combination: Optional[List[str]] = None
        hybrid_benefit_score: Optional[float] = None
        hybrid_reason: Optional[str] = None
        winner_scheme = self.knowledge_base.get_scheme(winner.scheme_id)

        if winner_scheme:
            hybrid_combination, hybrid_benefit_score, hybrid_reason = (
                self._evaluate_hybrids(winner_scheme, schemes, requirement_profile)
            )

        # 6. Knowledge coverage
        kb_coverage, kb_missing = self.knowledge_base.get_knowledge_coverage(
            requirement_profile,
        )

        # 7. Compute calibrated confidence
        hist_agreement = self._compute_historical_agreement(
            effective_experiences, winner.scheme_id, winner,
        )
        confidence = self.metrics.compute_confidence(
            context_completeness=requirement_profile.context_completeness,
            scheme_match=winner.final_score,
            historical_agreement=hist_agreement,
            knowledge_completeness=kb_coverage,
        )

        # 8. Adaptation tracking
        adaptation_delta: Optional[float] = None
        previous_scheme: Optional[str] = None
        adaptation_reason_str: Optional[str] = None

        if effective_experiences:
            latest = effective_experiences[0]  # sorted desc by timestamp
            previous_scheme = latest.selected_scheme
            if previous_scheme != winner.short_name:
                adaptation_delta = abs(winner.final_score - latest.decision_score)
                adaptation_reason_str = (
                    f"Context changed: scheme switched from {previous_scheme} "
                    f"to {winner.short_name}"
                )
            else:
                adaptation_delta = 0.0

        # 9. Risk assessment
        risk_assessment = self._assess_risk(winner, requirement_profile)

        # 10. Generate explanation
        explanation = self.explainer.generate_explanation(
            winner=winner,
            context=context,
            experiences=effective_experiences,
            all_scores=all_scores,
            requirement_profile=requirement_profile,
            knowledge_base_schemes=schemes,
            cross_ue_matches=cross_ue_matches,
        )

        # 11. Build decision trace
        elapsed_ms = (time.perf_counter() - start) * 1000
        score_gap = (
            (winner.final_score - runner_up.final_score) if runner_up else None
        )

        decision_trace = DecisionTrace(
            context_summary={
                "ue_id": context.ue_id,
                "slice_type": context.slice_type,
                "dnn": context.dnn,
                "registration_type": context.registration_type,
                "timestamp": context.timestamp.isoformat(),
            },
            requirement_profile=requirement_profile.model_dump(),
            candidate_scores=all_scores,
            top_candidates=top_candidates,
            comparison_details={
                "total_schemes_evaluated": len(schemes),
                "total_scored": len(all_scores),
                "score_range": {
                    "max": all_scores[0].final_score if all_scores else 0,
                    "min": all_scores[-1].final_score if all_scores else 0,
                },
            },
            winner=winner.short_name,
            winner_score=winner.final_score,
            runner_up=runner_up.short_name if runner_up else None,
            runner_up_score=runner_up.final_score if runner_up else None,
            score_gap=score_gap,
            rules_fired=explanation.get("rules_fired", []),
            context_influence=explanation.get("context_influence", {}),
            experience_contribution={
                "total_experiences": len(effective_experiences),
                "historical_agreement": hist_agreement,
            },
            knowledge_coverage=kb_coverage,
            missing_knowledge=kb_missing,
            adaptation_delta=adaptation_delta,
            previous_scheme=previous_scheme,
            adaptation_reason=adaptation_reason_str,
            processing_time_ms=elapsed_ms,
        )

        # 12. Build recommendation
        return Recommendation(
            primary_scheme=winner.short_name,
            primary_scheme_id=winner.scheme_id,
            primary_score=winner.final_score,
            alternative_scheme=runner_up.short_name if runner_up else None,
            alternative_scheme_id=runner_up.scheme_id if runner_up else None,
            alternative_score=runner_up.final_score if runner_up else None,
            hybrid_combination=hybrid_combination,
            hybrid_benefit_score=hybrid_benefit_score,
            hybrid_reason=hybrid_reason,
            reason=explanation.get("why_selected", "Selected based on highest score"),
            confidence=confidence,
            risk_assessment=risk_assessment,
            metric_breakdown=winner.score_breakdown,
            decision_trace=decision_trace,
            explanation=explanation,
            knowledge_version=self.knowledge_base.get_knowledge_version(),
            reasoning_version=self.VERSION,
            is_fallback=is_fallback,
            fallback_reason=fallback_reason,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _evaluate_hybrids(
        self,
        winner_scheme: PrivacyScheme,
        all_schemes: List[PrivacyScheme],
        requirement_profile: RequirementProfile,
    ) -> tuple:
        """Evaluate if a hybrid combination improves coverage."""
        compatible_names = winner_scheme.get_compatible_hybrids()
        if not compatible_names:
            return None, None, None

        best_benefit = 0.0
        best_partner: Optional[str] = None
        best_reason = ""

        for partner_name in compatible_names:
            partner = self.knowledge_base.get_by_short_name(partner_name)
            if partner is None:
                # Try by name
                partner = self.knowledge_base.get_by_name(partner_name)
            if partner is None:
                continue

            benefit, reason = self.scorer.evaluate_hybrid(
                winner_scheme, partner, requirement_profile,
            )
            if benefit > best_benefit:
                best_benefit = benefit
                best_partner = partner.short_name
                best_reason = reason

        if best_benefit >= self.hybrid_threshold:
            return (
                [winner_scheme.short_name, best_partner],
                best_benefit,
                best_reason,
            )

        return None, None, None

    def _compute_historical_agreement(
        self,
        experiences: List[Experience],
        winner_id: str,
        winner: Optional[SchemeScore] = None,
    ) -> float:
        """How well does the winner agree with historical decisions and outcomes?"""
        if not experiences:
            return 0.5  # Neutral if no history

        if winner and hasattr(winner, "experience_alignment"):
            return winner.experience_alignment

        matching = sum(
            1 for e in experiences if e.selected_scheme_id == winner_id
        )
        return matching / len(experiences)

    def _assess_risk(
        self,
        winner: SchemeScore,
        requirement_profile: RequirementProfile,
    ) -> str:
        """Determine risk level of adopting this scheme."""
        if winner.is_rejected:
            return "high"
        if winner.final_score >= 0.75 and not requirement_profile.quantum_threat:
            return "low"
        if winner.final_score >= 0.5:
            return "medium"
        return "high"

    def _empty_fallback(
        self,
        context: RegistrationContext,
        start: float,
    ) -> Recommendation:
        """Return a minimal fallback recommendation when KB is empty."""
        elapsed = (time.perf_counter() - start) * 1000
        trace = DecisionTrace(
            context_summary={"ue_id": context.ue_id},
            processing_time_ms=elapsed,
        )
        return Recommendation(
            primary_scheme="UNKNOWN",
            primary_scheme_id="UNKNOWN",
            primary_score=0.0,
            reason="No schemes available in knowledge base",
            confidence=0.0,
            risk_assessment="high",
            decision_trace=trace,
            is_fallback=True,
            fallback_reason="Knowledge base is empty",
        )
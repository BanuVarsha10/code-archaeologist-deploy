"""CAPSS Policy Generator — Recommendation → PrivacyPolicy.

Transforms a Recommendation into a structured, machine-readable
PrivacyPolicy document with enforcement metadata, expiry, and
versioning.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from capss.schemas.context import RegistrationContext
from capss.schemas.recommendation import Recommendation
from capss.schemas.policy import PrivacyPolicy


class PolicyGenerator:
    """Generates a PrivacyPolicy from a Recommendation and Context."""

    def generate(
        self,
        recommendation: Recommendation,
        context: RegistrationContext,
    ) -> PrivacyPolicy:
        """Generate a structured privacy policy from a recommendation.

        Args:
            recommendation: The reasoning engine's output.
            context: The registration context.

        Returns:
            A fully populated PrivacyPolicy.
        """
        now = datetime.utcnow()

        # Build enforcement parameters
        enforcement = self._build_enforcement(recommendation, context)

        # Adaptation info
        trace = recommendation.decision_trace
        adaptation_info: Dict[str, Any] = {}
        if trace.previous_scheme:
            adaptation_info = {
                "previous_scheme": trace.previous_scheme,
                "adaptation_delta": trace.adaptation_delta,
                "adaptation_reason": trace.adaptation_reason,
            }

        # Metric summary
        metric_summary = dict(recommendation.metric_breakdown)
        metric_summary["primary_score"] = recommendation.primary_score
        metric_summary["confidence"] = recommendation.confidence

        policy = PrivacyPolicy(
            selected_scheme=recommendation.primary_scheme,
            selected_scheme_id=recommendation.primary_scheme_id,
            hybrid_schemes=(
                recommendation.hybrid_combination
                if recommendation.hybrid_combination
                else None
            ),
            reason=recommendation.reason,
            confidence=recommendation.confidence,
            risk_assessment=recommendation.risk_assessment,
            timestamp=now,
            expiry=now + timedelta(hours=24),
            enforcement=enforcement,
            version="1.0",
            knowledge_version=recommendation.knowledge_version,
            reasoning_version=recommendation.reasoning_version,
            metric_summary=metric_summary,
            adaptation_info=adaptation_info,
            is_fallback=recommendation.is_fallback,
        )

        return policy

    def _build_enforcement(
        self,
        recommendation: Recommendation,
        context: RegistrationContext,
    ) -> Dict[str, Any]:
        """Build enforcement parameters for the policy."""
        enforcement: Dict[str, Any] = {
            "apply_to_ue": context.ue_id,
            "primary_scheme": recommendation.primary_scheme,
            "registration_type": context.registration_type,
            "slice_type": context.slice_type,
            "dnn": context.dnn,
        }

        if recommendation.hybrid_combination:
            enforcement["hybrid_schemes"] = recommendation.hybrid_combination
            enforcement["hybrid_benefit_score"] = recommendation.hybrid_benefit_score

        return enforcement
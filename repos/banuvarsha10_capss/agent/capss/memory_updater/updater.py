"""CAPSS Memory Updater — Policy → Experience.

Converts a generated policy and its context into a long-term Experience
record. Handles adaptation tracking (scheme changes, confidence trends).
This closes the learning loop of the Agent.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from capss.schemas.context import RegistrationContext
from capss.schemas.experience import Experience
from capss.schemas.policy import PrivacyPolicy
from capss.schemas.recommendation import Recommendation
from capss.experience_memory.memory import ExperienceMemory


class MemoryUpdater:
    """Converts policies into experiences and stores them."""

    def __init__(self, experience_memory: ExperienceMemory) -> None:
        self.memory = experience_memory

    def update(
        self,
        policy: PrivacyPolicy,
        context: RegistrationContext,
        recommendation: Recommendation,
    ) -> Experience:
        """Create an Experience from a policy and store it.

        Args:
            policy: The generated privacy policy.
            context: The registration context.
            recommendation: The reasoning engine's output.

        Returns:
            The created Experience.
        """
        ue_id = context.ue_id

        # Context snapshot (serialise to dict, converting datetime)
        ctx_dump = context.model_dump()
        ctx_dump["timestamp"] = context.timestamp.isoformat()

        # Requirement profile from decision trace
        req_profile = dict(recommendation.decision_trace.requirement_profile)

        # Adaptation info
        adapt = self._compute_adaptation_info(ue_id, policy.selected_scheme)

        # Confidence trend
        trend = self._update_confidence_trend(ue_id, recommendation.confidence)

        # Average decision score
        avg_score = self._compute_average_decision_score(
            ue_id, recommendation.primary_score,
        )

        experience = Experience(
            experience_id=str(uuid.uuid4()),
            ue_id=ue_id,
            context_snapshot=ctx_dump,
            requirement_profile=req_profile,
            selected_scheme=recommendation.primary_scheme,
            selected_scheme_id=recommendation.primary_scheme_id,
            alternative_scheme=recommendation.alternative_scheme,
            hybrid_combination=recommendation.hybrid_combination,
            reason=recommendation.reason,
            confidence=recommendation.confidence,
            decision_score=recommendation.primary_score,
            timestamp=datetime.utcnow(),
            outcome=None,  # Future: track success/failure
            adaptation_count=adapt["count"],
            previous_scheme=adapt["previous_scheme"],
            adaptation_reason=adapt["reason"],
            success_count=0,
            failure_count=0,
            confidence_trend=trend,
            average_decision_score=avg_score,
            experience_decay_factor=1.0,
            knowledge_version=recommendation.knowledge_version,
            reasoning_version=recommendation.reasoning_version,
        )

        return experience

    def _compute_adaptation_info(
        self, ue_id: str, new_scheme: str,
    ) -> Dict[str, Any]:
        """Compare with previous experience to detect scheme changes."""
        latest = self.memory.get_latest(ue_id)

        if not latest:
            return {"count": 0, "previous_scheme": None, "reason": None}

        count = latest.adaptation_count
        prev = latest.selected_scheme
        reason: Optional[str] = None

        if prev != new_scheme:
            count += 1
            reason = (
                f"Scheme changed from {prev} to {new_scheme} "
                f"due to updated context analysis"
            )

        return {"count": count, "previous_scheme": prev, "reason": reason}

    def _update_confidence_trend(
        self, ue_id: str, new_confidence: float,
    ) -> List[float]:
        """Append to confidence trend, keeping last 10 values."""
        latest = self.memory.get_latest(ue_id)
        trend = list(latest.confidence_trend) if latest else []
        trend.append(new_confidence)
        return trend[-10:]  # Keep last 10

    def _compute_average_decision_score(
        self, ue_id: str, new_score: float,
    ) -> float:
        """Running average of decision scores."""
        exps = self.memory.retrieve(ue_id)
        if not exps:
            return new_score
        scores = [e.decision_score for e in exps] + [new_score]
        return sum(scores) / len(scores)

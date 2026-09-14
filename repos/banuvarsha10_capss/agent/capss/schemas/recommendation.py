"""CAPSS Recommendation Schema — Reasoning engine output.

Contains the full recommendation with decision trace for
explainability (XAI). Every recommendation exposes:
  - Why the scheme was selected
  - Why alternatives were rejected
  - Which rules fired
  - Which context factors influenced the decision most
  - Which historical experiences contributed
  - Full weighted score breakdown

This supports Decision Trace Objects (recommendation #6) and
Explainability Metrics (recommendation #5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SchemeScore(BaseModel):
    """Quantitative score for a single candidate scheme."""

    scheme_id: str
    scheme_name: str
    short_name: str

    # --- Dimensional scores (0.0 – 1.0) ---
    fitness_score: float = Field(0.0, ge=0.0, le=1.0)
    privacy_match: float = Field(0.0, ge=0.0, le=1.0)
    performance_match: float = Field(0.0, ge=0.0, le=1.0)
    deployment_match: float = Field(0.0, ge=0.0, le=1.0)
    experience_alignment: float = Field(0.0, ge=0.0, le=1.0)
    tracking_protection_match: float = Field(0.0, ge=0.0, le=1.0)
    quantum_match: float = Field(0.0, ge=0.0, le=1.0)
    identity_protection_match: float = Field(0.0, ge=0.0, le=1.0)
    profile_match: float = Field(0.0, ge=0.0, le=1.0)

    # --- Composite ---
    final_score: float = Field(0.0, ge=0.0, le=1.0)
    score_breakdown: Dict[str, float] = Field(default_factory=dict)

    # --- Rejection info ---
    rejection_reasons: List[str] = Field(default_factory=list)
    is_rejected: bool = False


class DecisionTrace(BaseModel):
    """Full trace of the decision-making process.

    This object captures every stage:
        Context → Requirements → Candidates → Scores → Comparison → Winner
    """

    # --- Input summary ---
    context_summary: Dict[str, Any] = Field(default_factory=dict)
    requirement_profile: Dict[str, Any] = Field(default_factory=dict)

    # --- Scoring ---
    candidate_scores: List[SchemeScore] = Field(default_factory=list)
    top_candidates: List[SchemeScore] = Field(default_factory=list)
    comparison_details: Dict[str, Any] = Field(default_factory=dict)

    # --- Winner ---
    winner: str = ""
    winner_score: float = 0.0
    runner_up: Optional[str] = None
    runner_up_score: Optional[float] = None
    score_gap: Optional[float] = None

    # --- Explainability ---
    rules_fired: List[str] = Field(default_factory=list)
    context_influence: Dict[str, float] = Field(default_factory=dict)
    experience_contribution: Dict[str, Any] = Field(default_factory=dict)

    # --- Knowledge & Coverage ---
    knowledge_coverage: float = Field(
        1.0,
        description="Fraction of reasoning dimensions covered by knowledge base",
    )
    missing_knowledge: List[str] = Field(
        default_factory=list,
        description="Reasoning dimensions not covered",
    )

    # --- Adaptation ---
    adaptation_delta: Optional[float] = Field(
        None, description="Score change from previous recommendation",
    )
    previous_scheme: Optional[str] = Field(
        None, description="Previously selected scheme for this UE",
    )
    adaptation_reason: Optional[str] = Field(
        None, description="Why the scheme changed",
    )

    # --- Performance ---
    processing_time_ms: float = 0.0


class Recommendation(BaseModel):
    """Final recommendation from the Reasoning Engine.

    Includes the primary scheme, alternative, optional hybrid,
    confidence, risk assessment, full metric breakdown, decision
    trace, and human-readable explanation.
    """

    # --- Primary recommendation ---
    primary_scheme: str = Field(..., description="Short name of the recommended scheme")
    primary_scheme_id: str = Field(..., description="ID of the recommended scheme")
    primary_score: float = Field(..., ge=0.0, le=1.0)

    # --- Alternative ---
    alternative_scheme: Optional[str] = None
    alternative_scheme_id: Optional[str] = None
    alternative_score: Optional[float] = None

    # --- Hybrid ---
    hybrid_combination: Optional[List[str]] = None
    hybrid_benefit_score: Optional[float] = None
    hybrid_reason: Optional[str] = None

    # --- Reasoning output ---
    reason: str = Field(..., description="Primary reason for this recommendation")
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Calibrated confidence (see confidence formula)",
    )
    risk_assessment: str = Field(
        ...,
        description="Risk level if this scheme is adopted: low | medium | high",
    )

    # --- Detailed breakdown ---
    metric_breakdown: Dict[str, float] = Field(default_factory=dict)
    decision_trace: DecisionTrace = Field(default_factory=DecisionTrace)
    explanation: Dict[str, Any] = Field(default_factory=dict)

    # --- Metadata ---
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    knowledge_version: str = "1.0"
    reasoning_version: str = "1.0"

    # --- Fallback handling (recommendation #12) ---
    is_fallback: bool = Field(
        False,
        description="True if no scheme exceeded the minimum threshold",
    )
    fallback_reason: Optional[str] = None

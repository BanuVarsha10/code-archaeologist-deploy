"""CAPSS Experience Schema — Agent memory records.

Each Experience represents a stored decision for a specific UE.
The Experience Memory maintains a bounded set of these per UE,
enabling the agent to adapt recommendations over time.

Enhanced Fields (per recommendation #7):
    - adaptation_count: How many times the recommendation changed for this UE
    - success_count / failure_count: Outcome tracking (future)
    - confidence_trend: Historical confidence values for trend analysis
    - decision_score: The overall recommendation score at decision time
    - experience_decay_factor: Time-based relevance decay
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Experience(BaseModel):
    """A stored decision record for a UE registration."""

    # --- Identification ---
    experience_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique experience identifier",
    )
    ue_id: str = Field(..., description="UE this experience belongs to")

    # --- Context snapshot ---
    context_snapshot: Dict[str, Any] = Field(
        ...,
        description="Serialised RegistrationContext at decision time",
    )
    requirement_profile: Dict[str, Any] = Field(
        ...,
        description="Serialised RequirementProfile at decision time",
    )

    # --- Decision ---
    selected_scheme: str = Field(..., description="Short name of the selected scheme")
    selected_scheme_id: str = Field(..., description="ID of the selected scheme")
    alternative_scheme: Optional[str] = Field(
        None, description="Runner-up scheme short name",
    )
    hybrid_combination: Optional[List[str]] = Field(
        None, description="Hybrid scheme combination if recommended",
    )
    reason: str = Field(..., description="Human-readable reason for the decision")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Calibrated confidence score",
    )
    decision_score: float = Field(
        0.0, description="Overall recommendation score at decision time",
    )

    # --- Timing ---
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this experience was recorded",
    )

    # --- Outcome tracking (future) ---
    outcome: Optional[str] = Field(
        None,
        description="Outcome of following this recommendation: success | failure | unknown",
    )

    # --- Adaptation tracking ---
    adaptation_count: int = Field(
        0, description="Number of scheme changes for this UE so far",
    )
    previous_scheme: Optional[str] = Field(
        None, description="What the previous recommendation was (for adaptation tracking)",
    )
    adaptation_reason: Optional[str] = Field(
        None, description="Why the scheme changed from the previous recommendation",
    )

    # --- Learning metrics ---
    success_count: int = Field(0, description="Cumulative successful outcomes")
    failure_count: int = Field(0, description="Cumulative failed outcomes")
    confidence_trend: List[float] = Field(
        default_factory=list,
        description="History of confidence scores for trend analysis",
    )
    average_decision_score: float = Field(
        0.0, description="Running average of decision scores",
    )
    experience_decay_factor: float = Field(
        1.0,
        ge=0.0, le=1.0,
        description="Time-based relevance decay (1.0 = fully relevant)",
    )

    # --- Versioning ---
    knowledge_version: str = Field("1.0", description="Knowledge base version at decision time")
    reasoning_version: str = Field("1.0", description="Reasoning engine version at decision time")

    model_config = {"str_strip_whitespace": True}

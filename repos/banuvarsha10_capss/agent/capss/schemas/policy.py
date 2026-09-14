"""CAPSS Policy Schema — Machine-readable privacy policy.

Transforms the reasoning output into a structured, protocol-independent
privacy policy document. Includes:
    - Validation results (recommendation #11)
    - Knowledge/Reasoning versioning (recommendation #8)
    - Enforcement metadata
    - Adaptation tracking
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ValidationResult(BaseModel):
    """Result of policy validation (recommendation #11).

    Checks consistency, hybrid compatibility, required fields,
    and detects conflicting schemes before issuing the policy.
    """

    is_valid: bool = True
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    hybrid_compatible: bool = True
    completeness_score: float = Field(
        1.0, ge=0.0, le=1.0,
        description="Fraction of policy fields that are complete",
    )


class PrivacyPolicy(BaseModel):
    """Structured privacy policy document.

    This is the final, machine-readable output of the CAPSS Agent
    for a single registration event.
    """

    # --- Identification ---
    policy_id: str = Field(
        default_factory=lambda: f"POL-{uuid.uuid4().hex[:8].upper()}",
        description="Unique policy identifier",
    )

    # --- Scheme selection ---
    selected_scheme: str = Field(..., description="Short name of the selected scheme")
    selected_scheme_id: str = Field(..., description="ID of the selected scheme")
    hybrid_schemes: Optional[List[str]] = Field(
        None, description="Additional hybrid schemes if recommended",
    )

    # --- Reasoning ---
    reason: str = Field(..., description="Human-readable reason for selection")
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_assessment: str = Field(
        "low", description="Risk level: low | medium | high",
    )

    # --- Timing ---
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    expiry: Optional[datetime] = Field(
        None,
        description="When this policy expires and should be re-evaluated",
    )

    # --- Enforcement ---
    enforcement: Dict[str, Any] = Field(
        default_factory=dict,
        description="Enforcement parameters for the selected scheme",
    )

    # --- Versioning (recommendation #8) ---
    version: str = Field("1.0", description="Policy format version")
    knowledge_version: str = Field("1.0", description="Knowledge base version used")
    reasoning_version: str = Field("1.0", description="Reasoning engine version used")

    # --- Validation (recommendation #11) ---
    validation_result: ValidationResult = Field(default_factory=ValidationResult)

    # --- Metrics summary ---
    metric_summary: Dict[str, float] = Field(
        default_factory=dict,
        description="Key metric scores for this policy",
    )

    # --- Adaptation info (recommendation #10) ---
    adaptation_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="Adaptation details: previous_scheme, change_reason, delta",
    )

    # --- Fallback ---
    is_fallback: bool = Field(
        False,
        description="True if this is a fallback policy (no scheme met threshold)",
    )

    def set_default_expiry(self, hours: int = 24) -> None:
        """Set a default expiry time relative to the timestamp."""
        self.expiry = self.timestamp + timedelta(hours=hours)

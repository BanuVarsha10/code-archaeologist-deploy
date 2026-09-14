"""CAPSS Privacy Scheme Schema — Structured knowledge base model.

Matches the JSON knowledge base format exactly. Uses Dict[str, Any]
for nested structures to remain flexible — the knowledge base can
contain ANY number of schemes with varying internal details, and the
system will dynamically load and score them all.

The quantitative_metrics dict is the primary scoring interface:
    privacy_score, security_score, latency_score, energy_score,
    tracking_score, identity_score, scalability_score,
    deployment_score, quantum_score  (all int 1–5)
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class PrivacyScheme(BaseModel):
    """Full privacy scheme model matching the knowledge base JSON.

    This model accepts whatever schemes are present in the JSON file.
    No scheme names or IDs are hard-coded — the system is fully
    dynamic with respect to the number and type of mechanisms.
    """

    # --- Identity ---
    id: str = Field(..., description="Scheme identifier (e.g. 'SCHEME-001')")
    name: str = Field(..., description="Full scheme name")
    short_name: str = Field(..., description="Abbreviated name (e.g. 'ECIES')")
    version: str = Field("1.0", description="Scheme definition version")

    # --- Description ---
    description: str = Field(..., description="Detailed description of the scheme")
    category: str = Field(..., description="Scheme category (e.g. 'Identity Protection')")
    primary_privacy_goal: str = Field(..., description="Primary privacy objective")
    secondary_goals: List[str] = Field(default_factory=list)

    # --- Cryptographic details ---
    cryptographic_characteristics: Dict[str, Any] = Field(default_factory=dict)

    # --- Security assessment ---
    security_metrics: Dict[str, Any] = Field(default_factory=dict)

    # --- Performance characteristics ---
    performance: Dict[str, Any] = Field(default_factory=dict)

    # --- Deployment readiness ---
    deployment: Dict[str, Any] = Field(default_factory=dict)

    # --- Infrastructure requirements ---
    requirements: Dict[str, Any] = Field(default_factory=dict)

    # --- Threat model ---
    threat_model: Dict[str, Any] = Field(default_factory=dict)

    # --- Decision support metadata ---
    decision_support: Dict[str, Any] = Field(default_factory=dict)

    # --- Suitability profiles ---
    suitability: Dict[str, Any] = Field(default_factory=dict)

    # --- Resource suitability ---
    resource_suitability: Dict[str, Any] = Field(default_factory=dict)

    # --- Hardware constraints ---
    constraints: Dict[str, Any] = Field(default_factory=dict)

    # --- Hybrid combination support ---
    hybrid_support: Dict[str, Any] = Field(default_factory=dict)

    # --- Practical information ---
    use_cases: List[str] = Field(default_factory=list)
    real_world_examples: List[str] = Field(default_factory=list)
    advantages: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    # --- Reasoning support ---
    reasoning_support: Dict[str, Any] = Field(default_factory=dict)

    # --- Quantitative scoring (primary interface for the Reasoning Engine) ---
    quantitative_metrics: Dict[str, Any] = Field(default_factory=dict)

    # --- Evidence & references ---
    evidence: Dict[str, Any] = Field(default_factory=dict)
    references: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    # --- Helper methods ---

    def get_metric(self, key: str, default: int = 3) -> int:
        """Get a quantitative metric score (1-5), with fallback."""
        return int(self.quantitative_metrics.get(key, default))

    def is_quantum_resistant(self) -> bool:
        """Check if scheme provides quantum resistance."""
        crypto = self.cryptographic_characteristics
        return bool(crypto.get("quantum_resistant", False))

    def supports_anonymous_auth(self) -> bool:
        """Check if scheme supports anonymous authentication."""
        sec = self.security_metrics
        return bool(sec.get("anonymous_authentication", False))

    def get_compatible_hybrids(self) -> List[str]:
        """Get list of compatible hybrid partner scheme names."""
        return list(self.hybrid_support.get("compatible_with", []))

    def get_reasoning_profile(self) -> Dict[str, Any]:
        """Get the reasoning profile from decision_support."""
        ds = self.decision_support
        rp = ds.get("recommendation_profile", {})
        return dict(rp.get("reasoning_profile", {}))

    def get_capabilities(self) -> List[str]:
        """Get the list of capabilities from decision_support."""
        ds = self.decision_support
        rp = ds.get("recommendation_profile", {})
        return list(rp.get("capabilities", []))

    def get_context_preferences(self) -> Dict[str, bool]:
        """Get context preference flags from decision_support."""
        ds = self.decision_support
        return dict(ds.get("context_preferences", {}))

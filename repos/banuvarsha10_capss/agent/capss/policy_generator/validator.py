"""CAPSS Policy Validator — Validates policies before issuance.

Checks consistency, hybrid compatibility, required fields, and
detects conflicting schemes. Prevents invalid policy generation
(recommendation #11).
"""

from __future__ import annotations

from typing import List

from capss.schemas.policy import PrivacyPolicy, ValidationResult
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase


class PolicyValidator:
    """Validates a PrivacyPolicy against the knowledge base."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.min_confidence = float(
            self.config.get("thresholds", {}).get("min_recommendation_score", 0.3)
        )

    def validate(
        self,
        policy: PrivacyPolicy,
        knowledge_base: SchemeKnowledgeBase,
    ) -> ValidationResult:
        """Validate a policy for consistency and completeness.

        Args:
            policy: The policy to validate.
            knowledge_base: The scheme knowledge base for lookups.

        Returns:
            ValidationResult with is_valid, warnings, errors.
        """
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Check scheme exists in knowledge base
        scheme = knowledge_base.get_by_short_name(policy.selected_scheme)
        if scheme is None:
            scheme = knowledge_base.get_scheme(policy.selected_scheme_id)
        if scheme is None:
            errors.append(
                f"Scheme '{policy.selected_scheme}' (ID: {policy.selected_scheme_id}) "
                f"not found in knowledge base."
            )

        # 2. Check confidence threshold
        if policy.confidence < self.min_confidence:
            warnings.append(
                f"Confidence ({policy.confidence:.2f}) is below minimum threshold "
                f"({self.min_confidence:.2f})."
            )

        # 3. Check hybrid compatibility
        hybrid_compatible = True
        if policy.hybrid_schemes and len(policy.hybrid_schemes) > 1:
            primary_name = policy.hybrid_schemes[0]
            primary = knowledge_base.get_by_short_name(primary_name)
            if primary:
                compatible_partners = primary.get_compatible_hybrids()
                for partner_name in policy.hybrid_schemes[1:]:
                    partner = (
                        knowledge_base.get_by_short_name(partner_name)
                        or knowledge_base.get_by_name(partner_name)
                    )
                    partner_identifiers = {
                        partner_name,
                        getattr(partner, "short_name", None),
                        getattr(partner, "name", None),
                        getattr(partner, "id", None),
                    }
                    if not partner_identifiers.intersection(compatible_partners):
                        errors.append(
                            f"Hybrid scheme '{partner_name}' is not compatible "
                            f"with '{primary_name}'."
                        )
                        hybrid_compatible = False

        # 4. Check required fields
        completeness = 1.0
        missing_fields = []
        if not policy.reason:
            missing_fields.append("reason")
        if not policy.selected_scheme:
            missing_fields.append("selected_scheme")
        if not policy.selected_scheme_id:
            missing_fields.append("selected_scheme_id")

        if missing_fields:
            errors.append(f"Missing required fields: {', '.join(missing_fields)}")
            completeness -= len(missing_fields) * 0.2

        # 5. Check expiry
        if policy.expiry is None:
            warnings.append("Policy has no expiry time set.")

        # 6. Fallback warning
        if policy.is_fallback:
            warnings.append(
                "This is a fallback policy — no scheme met the minimum threshold."
            )

        is_valid = len(errors) == 0

        return ValidationResult(
            is_valid=is_valid,
            warnings=warnings,
            errors=errors,
            hybrid_compatible=hybrid_compatible,
            completeness_score=max(0.0, completeness),
        )
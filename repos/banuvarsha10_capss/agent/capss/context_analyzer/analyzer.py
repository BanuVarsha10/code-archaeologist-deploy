"""CAPSS Context Analyzer — Derives RequirementProfile from RegistrationContext.

Converts raw registration context (including data from the Systems Module
and Privacy Module) into a structured RequirementProfile that the Reasoning
Engine uses to evaluate candidate privacy schemes.

Input Sources Used:
    Systems Module: request_classification, attack_type, attack_severity,
                    detection_confidence, validation_results
    Privacy Module: privacy_score, privacy_risk_level, metadata_leakage,
                    correlation_score
    Registration:   ue_id, suci, registration_type, slice_type, dnn, timestamp
    Historical:     Previous experiences for this UE
"""

from typing import List, Optional, Dict, Any
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience

DEFAULT_CONFIG = {
    "slice_weights": {"eMBB": 0.5, "URLLC": 0.8, "mMTC": 0.6},
    "dnn_weights": {"internet": 0.4, "ims": 0.7, "iot": 0.5, "enterprise": 0.9},
    "registration_type_weights": {"initial": 0.6, "mobility": 0.5, "periodic": 0.3, "emergency": 0.95},
}

# Ablation study feature — additive only, default (ablation_mode=None)
# leaves every existing code path provably unchanged (see analyze()'s
# docstring). Neutralizes the RAW INPUT FIELDS a signal carries, not any
# derivation logic — every _compute_*/_derive_* method below is called
# exactly as before, unmodified, just on a sanitized context copy when a
# mode is active. This means real cross-cutting effects (e.g. Systems'
# validation_results already feeding into metadata-leakage risk,
# Privacy's privacy_risk_level already feeding into threat_level) are
# automatically and correctly neutralized too, without hand-enumerating
# every derived effect — the existing, already-verified None-handling in
# each method does the rest.
_NO_THREAT_NEUTRAL_FIELDS = {
    # "As if no attack was detected" — every Systems Module + combined-
    # threat field RegistrationContext carries (see that schema's own
    # field groupings). request_classification="ALLOW" (not just None)
    # because _derive_threat_level's BLOCK/TAG branches are matched by
    # value, not by None-ness — ALLOW is that field's own real neutral
    # value, same as a genuinely clean registration would have.
    "request_classification": "ALLOW",
    "attack_type": None,
    "attack_severity": None,
    "detection_confidence": None,
    "validation_results": None,
    "attack_result": None,
    "threat_score": None,
}
_NO_PRIVACY_NEUTRAL_FIELDS = {
    # "As if Privacy Module produced no signal" — every Privacy Module
    # field RegistrationContext carries.
    "privacy_score": None,
    "privacy_risk_level": None,
    "metadata_leakage": None,
    "correlation_score": None,
}


class ContextAnalyzer:
    """Derives a RequirementProfile from a RegistrationContext.

    Uses information from the Systems Module (attack detection, request
    classification), Privacy Module (privacy scores, risk levels), and
    the registration event itself to produce a profile that drives the
    Reasoning Engine's scheme selection.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or DEFAULT_CONFIG

    def analyze(
        self,
        context: RegistrationContext,
        experiences: Optional[List[Experience]] = None,
        ablation_mode: Optional[str] = None,
    ) -> RequirementProfile:
        """Main analysis entry point.

        ablation_mode: additive, default None — completely normal, current
        behavior, provably a no-op for every existing caller (none of them
        pass this parameter). "no_threat"/"no_privacy" build a sanitized
        COPY of `context` (via Pydantic's model_copy — the real, original
        `context` object passed in by the caller is never mutated) with
        that signal's real raw input fields forced to neutral defaults,
        then run the exact same, unmodified analysis below on that copy.
        "no_experience" and any other value are a no-op here (that mode is
        handled entirely in ReasoningEngine.reason() instead — see there).
        """
        experiences = experiences or []

        if ablation_mode == "no_threat":
            effective_context = context.model_copy(update=_NO_THREAT_NEUTRAL_FIELDS)
        elif ablation_mode == "no_privacy":
            effective_context = context.model_copy(update=_NO_PRIVACY_NEUTRAL_FIELDS)
        else:
            effective_context = context

        # 1. Threat Level — combines Systems Module + Privacy Module + registration type
        threat_level = self._derive_threat_level(effective_context)

        # 2. Privacy Requirement — context sensitivity score
        privacy_req = self._compute_context_sensitivity(effective_context)

        # 3. Tracking Risk
        tracking_risk = self._compute_tracking_risk(effective_context, experiences)

        # 4. Metadata Leakage Risk — from Privacy Module or inferred
        metadata_risk = self._compute_metadata_leakage_risk(effective_context)

        # 5. Correlation Risk — from Privacy Module or inferred from history
        correlation_risk = self._compute_correlation_risk(effective_context, experiences)

        # 6. Latency Requirement — from slice type
        latency_map = {"eMBB": "medium", "URLLC": "ultra_low", "mMTC": "high"}
        latency_req = latency_map.get(effective_context.slice_type, "medium")

        # 7. Resource Profile — from slice type
        resource_map = {"eMBB": "powerful", "URLLC": "powerful", "mMTC": "constrained"}
        resource_prof = resource_map.get(effective_context.slice_type, "moderate")

        # 8. Network Confidence — from Systems Module validation results
        net_conf = self._compute_network_confidence(effective_context)

        # 9. Context Completeness — fraction of available fields
        completeness = self._compute_context_completeness(effective_context)

        # 10. Quantum Threat — currently always False (future extension)
        quantum = False

        # 11. Anonymous Auth — required for enterprise/emergency contexts
        anon_auth = effective_context.dnn == "enterprise" or effective_context.registration_type == "emergency"

        # 12. Identity Protection — always required in 5G context
        identity_required = True

        return RequirementProfile(
            threat_level=threat_level,
            privacy_requirement=privacy_req,
            tracking_risk=tracking_risk,
            metadata_leakage_risk=metadata_risk,
            correlation_risk=correlation_risk,
            latency_requirement=latency_req,
            resource_profile=resource_prof,
            network_confidence=net_conf,
            context_completeness=completeness,
            quantum_threat=quantum,
            anonymous_auth_required=anon_auth,
            identity_protection_required=identity_required,
            attack_type=effective_context.attack_type,
        )

    # ------------------------------------------------------------------
    # Threat Level Derivation
    # ------------------------------------------------------------------

    def _derive_threat_level(self, context: RegistrationContext) -> str:
        """Derive threat level from Systems Module + Privacy Module + registration type.

        Priority:
            1. Systems Module: request_classification == BLOCK → critical
            2. Systems Module: attack_severity if provided
            3. Privacy Module: privacy_risk_level if provided
            4. Systems Module: threat_score if provided
            5. Fallback: registration_type mapping
        """
        # If Systems Module blocked the request, threat is critical
        if context.request_classification == "BLOCK":
            return "critical"

        # If Systems Module tagged the request, start at high
        if context.request_classification == "TAG":
            base = "high"
        else:
            # Default from registration type
            base = {
                "emergency": "critical",
                "initial": "medium",
                "mobility": "medium",
                "periodic": "low",
            }.get(context.registration_type, "low")

        # Override with Systems Module attack_severity if more severe
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        current_level = severity_order.get(base, 0)

        if context.attack_severity is not None:
            severity_level = severity_order.get(context.attack_severity, 0)
            if severity_level > current_level:
                base = context.attack_severity
                current_level = severity_level

        # Override with Privacy Module privacy_risk_level if more severe
        if context.privacy_risk_level is not None:
            risk_level = severity_order.get(context.privacy_risk_level, 0)
            if risk_level > current_level:
                base = context.privacy_risk_level
                current_level = risk_level

        # Override with numeric threat_score if more severe
        if context.threat_score is not None:
            if context.threat_score > 0.8 and current_level < 3:
                base = "critical"
            elif context.threat_score > 0.6 and current_level < 2:
                base = "high"
            elif context.threat_score > 0.3 and current_level < 1:
                base = "medium"

        return base

    # ------------------------------------------------------------------
    # Privacy Metrics
    # ------------------------------------------------------------------

    def _compute_context_sensitivity(self, context: RegistrationContext) -> float:
        """Context Sensitivity Score (CSS) — weighted combination of slice, DNN, reg type."""
        sw = self.config["slice_weights"].get(context.slice_type, 0.5)
        dw = self.config["dnn_weights"].get(context.dnn, 0.5)
        rw = self.config["registration_type_weights"].get(context.registration_type, 0.5)
        return min(1.0, (sw + dw + rw) / 3.0)

    def _compute_tracking_risk(
        self,
        context: RegistrationContext,
        experiences: Optional[List[Experience]] = None,
    ) -> float:
        """Compute tracking risk from context and history."""
        risk = 0.3
        if context.registration_type == "mobility":
            risk += 0.3
        if context.slice_type == "mMTC":
            risk += 0.2
        # Systems Module: attack type indicates tracking attempt
        att_lower = (context.attack_type or "").lower()
        if "duplicate" in att_lower or "tracking" in att_lower or att_lower in ["replay", "duplicate"]:
            risk += 0.35
        # More history → higher tracking risk
        if experiences and len(experiences) >= 3:
            risk += 0.2
        return min(1.0, risk)

    def _compute_metadata_leakage_risk(self, context: RegistrationContext) -> float:
        """Compute metadata leakage risk from Privacy Module or inferred."""
        # If Privacy Module provided a value, use it as the base
        if context.metadata_leakage is not None:
            base = context.metadata_leakage
        else:
            base = 0.5

        # Adjust based on DNN type
        if context.dnn in ["ims", "enterprise"]:
            base = max(base, 0.8)

        # Systems Module: failed validations increase leakage risk
        if context.validation_results:
            failed = sum(1 for v in context.validation_results.values() if not v)
            if failed > 0:
                base = min(1.0, base + 0.1 * failed)

        return min(1.0, base)

    def _compute_correlation_risk(
        self,
        context: RegistrationContext,
        experiences: Optional[List[Experience]] = None,
    ) -> float:
        """Compute correlation risk from Privacy Module or inferred from history."""
        # If Privacy Module provided a value, use it directly
        if context.correlation_score is not None:
            return context.correlation_score

        risk = 0.2
        if experiences and len(experiences) >= 2:
            risk += 0.4
        return min(1.0, risk)

    # ------------------------------------------------------------------
    # Network Confidence
    # ------------------------------------------------------------------

    def _compute_network_confidence(self, context: RegistrationContext) -> float:
        """Derive network confidence from Systems Module outputs."""
        confidence = 0.8  # Default: reasonably confident

        # Systems Module: request classification
        if context.request_classification == "BLOCK":
            confidence = 0.1
        elif context.request_classification == "TAG":
            confidence = 0.4

        # Systems Module: detection confidence inversely affects network confidence
        if context.detection_confidence is not None:
            # High detection confidence of an attack → low network confidence
            if context.attack_result in ["detected", "suspected"]:
                confidence = min(confidence, 1.0 - context.detection_confidence)

        # Legacy field
        if context.attack_result in ["detected", "suspected"] and context.detection_confidence is None:
            confidence = 0.2

        # Systems Module: validation results
        if context.validation_results:
            total = len(context.validation_results)
            passed = sum(1 for v in context.validation_results.values() if v)
            validation_ratio = passed / total if total > 0 else 1.0
            confidence = min(confidence, validation_ratio)

        return max(0.0, min(1.0, confidence))

    # ------------------------------------------------------------------
    # Context Completeness
    # ------------------------------------------------------------------

    def _compute_context_completeness(self, context: RegistrationContext) -> float:
        """Fraction of all context fields that are populated."""
        all_fields = [
            # Required fields (always populated)
            context.ue_id,
            context.suci,
            context.registration_type,
            context.slice_type,
            context.dnn,
            context.timestamp,
            # Systems Module fields
            context.request_classification,
            context.attack_type,
            context.attack_severity,
            context.detection_confidence,
            context.validation_results,
            # Privacy Module fields
            context.privacy_score,
            context.privacy_risk_level,
            context.metadata_leakage,
            context.correlation_score,
            # Combined threat fields
            context.attack_result,
            context.threat_score,
        ]
        populated = sum(1 for f in all_fields if f is not None)
        return populated / len(all_fields)

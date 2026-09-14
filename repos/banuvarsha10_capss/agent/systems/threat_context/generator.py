"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

Threat Context Generator

Converts Pre-AMF validation results into a ThreatContext object.
"""

from systems.pre_amf.models import ValidationContext
from systems.threat_context.models import ThreatContext
from systems.threat_context.calculator import ThreatCalculator


class ThreatContextGenerator:
    """
    Generates a ThreatContext from a ValidationContext.
    """

    def __init__(self):
        self.calculator = ThreatCalculator()

    def generate(self, context: ValidationContext) -> ThreatContext:
        """
        Build the ThreatContext for a registration request.
        """

        threat_score, confidence, factors = self.calculator.calculate(context)

        classification = context.classification_result

        return ThreatContext(
            registration_id=context.request.request_id,

            timestamp=context.request.timestamp,

            ue_id=context.request.ue_id,

            experiment_name=context.request.experiment_name,

            attack_detected=classification.decision != "ALLOW",

            attack_type=classification.attack_type,

            decision=classification.decision,

            severity=classification.severity,

            threat_score=threat_score,

            confidence=confidence,

            authentication_result=context.request.authentication_result,

            contributing_factors=factors,

            reasons=classification.reasons.copy()
        )
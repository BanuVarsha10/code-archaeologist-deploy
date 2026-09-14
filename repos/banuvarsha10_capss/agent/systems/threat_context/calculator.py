"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    calculator.py

Purpose
-------
Calculates a context-aware threat score from the
Pre-AMF Security Layer outputs.

Threat Score Range:
    0 - 100

This module contains NO reporting or CSV generation.
"""

from systems.pre_amf.models import ValidationContext
from systems.threat_context.models import ThreatFactors
from systems.pre_amf.attack_rules import (
    THREAT_DUPLICATE_WEIGHT,
    THREAT_RATE_WEIGHT,
    THREAT_SUBSCRIBER_WEIGHT,
    THREAT_HEADER_WEIGHT,
    THREAT_PARAMETER_WEIGHT,
    THREAT_HISTORY_WEIGHT,
)

class ThreatCalculator:
    """
    Computes an explainable threat score using weighted
    contributions from each detector and validator.
    """


    def calculate(self, context: ValidationContext):

        factors = ThreatFactors()

        # ==================================================
        # Duplicate Behaviour
        # ==================================================

        if (
            context.duplicate_result is not None
            and context.duplicate_result.detected
        ):

            severity = max(
                0.0,
                min(context.duplicate_result.score / 100.0, 1.0)
            )

            factors.duplicate_score = round(
                severity *
                context.duplicate_result.confidence *
                THREAT_DUPLICATE_WEIGHT,
                2
            )

        # ==================================================
        # Registration Rate Behaviour
        # ==================================================

        if (
            context.rate_result is not None
            and context.rate_result.detected
        ):

            severity = max(
                0.0,
                min(context.rate_result.score / 100.0, 1.0)
            )

            factors.rate_score = round(
                severity *
                context.rate_result.confidence *
                THREAT_RATE_WEIGHT,
                2
            )

        # ==================================================
        # Subscriber Validation
        # ==================================================

        if (
            context.subscriber_result is not None
            and not context.subscriber_result.passed
        ):

            factors.subscriber_score = THREAT_SUBSCRIBER_WEIGHT

        # ==================================================
        # Header Validation
        # ==================================================

        if (
            context.header_result is not None
            and not context.header_result.passed
        ):

            factors.header_score = THREAT_HEADER_WEIGHT

        # ==================================================
        # Parameter Validation
        # ==================================================

        if (
            context.parameter_result is not None
            and not context.parameter_result.passed
        ):

            factors.parameter_score = THREAT_PARAMETER_WEIGHT

        # ==================================================
        # Historical Behaviour
        # ==================================================

        history = context.history

        duplicate_index = min(history.duplicate_count, 5) / 5

        failed_index = min(history.failed_attempts, 5) / 5

        replay_index = min(history.replay_count, 3) / 3

        flood_index = min(history.flood_count, 3) / 3

        history_index = (
            duplicate_index +
            failed_index +
            replay_index +
            flood_index
        ) / 4

        factors.history_score = round(
            history_index *
            THREAT_HISTORY_WEIGHT,
            2
        )

        # ==================================================
        # Final Threat Score
        # ==================================================

        threat_score = round(

            factors.duplicate_score +

            factors.rate_score +

            factors.subscriber_score +

            factors.header_score +

            factors.parameter_score +

            factors.history_score,

            2

        )

        threat_score = min(threat_score, 100)

        # ==================================================
        # Confidence
        # ==================================================

        confidence_values = []

        if context.duplicate_result is not None:

            confidence_values.append(
                context.duplicate_result.confidence
            )

        if context.rate_result is not None:

            confidence_values.append(
                context.rate_result.confidence
            )

        if (
            context.subscriber_result is not None
            and not context.subscriber_result.passed
        ):

            confidence_values.append(1.0)

        if (
            context.header_result is not None
            and not context.header_result.passed
        ):

            confidence_values.append(1.0)

        if (
            context.parameter_result is not None
            and not context.parameter_result.passed
        ):

            confidence_values.append(1.0)

        if confidence_values:

            confidence = round(

                sum(confidence_values) /
                len(confidence_values),

                2

            )

        else:

            confidence = 0.0

        return threat_score, confidence, factors
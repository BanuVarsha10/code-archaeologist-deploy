"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    validator.py

Purpose
-------
Main orchestration module for the CAPSS
Pre-AMF Security Layer.

Responsibilities
----------------
1. Maintain UE registration history.
2. Maintain experiment statistics.
3. Create ValidationContext.
4. Execute all validators.
5. Execute all detectors.
6. Execute the Request Classifier.
7. Return the final classification.

Pipeline
--------

Registration Request
        │
        ▼
Validation Context
        │
        ▼
Header Validator
        │
        ▼
Parameter Validator
        │
        ▼
Subscriber Validator
        │
        ▼
Duplicate Detector
        │
        ▼
Rate Monitor
        │
        ▼
Request Classifier
        │
        ▼
ALLOW / TAG / BLOCK
"""

from systems.pre_amf.models import (
    RegistrationRequest,
    RegistrationHistory,
    ValidationContext,
    ClassificationResult,
    AttackStatistics,
)

from systems.pre_amf.validators.header_validator import (
    HeaderValidator,
)

from systems.pre_amf.validators.parameter_validator import (
    ParameterValidator,
)

from systems.pre_amf.validators.subscriber_validator import (
    SubscriberValidator,
)

from systems.pre_amf.detectors.duplicate_detector import (
    DuplicateDetector,
)

from systems.pre_amf.detectors.rate_monitor import (
    RateMonitor,
)

from systems.pre_amf.request_classifier import (
    RequestClassifier,
)


# ==========================================================
# Pre-AMF Validator
# ==========================================================

class PreAMFValidator:
    """
    Executes the complete Pre-AMF
    validation pipeline.
    """

    def __init__(self):

        # ----------------------------------------------
        # Validators
        # ----------------------------------------------

        self.header_validator = HeaderValidator()

        self.parameter_validator = ParameterValidator()

        self.subscriber_validator = SubscriberValidator()

        # ----------------------------------------------
        # Behaviour Detectors
        # ----------------------------------------------

        self.duplicate_detector = DuplicateDetector()

        self.rate_monitor = RateMonitor()

        # ----------------------------------------------
        # Final Decision Engine
        # ----------------------------------------------

        self.classifier = RequestClassifier()

        # ----------------------------------------------
        # Per-UE Registration History
        # ----------------------------------------------

        self.histories = {}

        # ----------------------------------------------
        # Experiment Statistics
        # ----------------------------------------------

        self.statistics = AttackStatistics()

    # ======================================================
    # Registration History
    # ======================================================

    def get_history(
        self,
        ue_id: str,
    ) -> RegistrationHistory:
        """
        Retrieve the history associated
        with a subscriber.

        A new history object is created
        automatically for new subscribers.
        """

        if ue_id not in self.histories:

            self.histories[ue_id] = RegistrationHistory(

                ue_id=ue_id

            )

        return self.histories[ue_id]

    # ======================================================
    # Validation
    # ======================================================

    def validate_with_context(
        self,
        request: RegistrationRequest,
    ) -> ValidationContext:

        # ----------------------------------------------
        # Retrieve Registration History
        # ----------------------------------------------

        history = self.get_history(

            request.ue_id

        )

        # ----------------------------------------------
        # Build Validation Context
        # ----------------------------------------------

        context = ValidationContext(

            request=request,

            history=history,

            statistics=self.statistics,
            
            experiment_name=request.experiment_name,

        )

        # ----------------------------------------------
        # Header Validation
        # ----------------------------------------------

        context.header_result = (

            self.header_validator.validate(

                request

            )

        )

        # ----------------------------------------------
        # Parameter Validation
        # ----------------------------------------------

        context.parameter_result = (

            self.parameter_validator.validate(

                request

            )

        )

        # ----------------------------------------------
        # Subscriber Validation
        # ----------------------------------------------

        context.subscriber_result = (

            self.subscriber_validator.validate(

                request

            )

        )
        # ----------------------------------------------
        # Duplicate Registration Detection
        # ----------------------------------------------

        context.duplicate_result = (

            self.duplicate_detector.detect(

                context

            )

        )

        # ----------------------------------------------
        # Registration Rate Monitoring
        # ----------------------------------------------

        context.rate_result = (

            self.rate_monitor.detect(

                context

            )

        )

        # ----------------------------------------------
        # Final Classification
        # ----------------------------------------------

        context.classification_result = (

            self.classifier.classify(

                context

            )

        )


        # ----------------------------------------------
        # Update Registration History
        # ----------------------------------------------

        history.last_result = (

            context.classification_result.decision

        )

        history.last_attack = (

            context.classification_result.attack_type

        )
        
        if history.first_seen is None:
            history.first_seen = request.timestamp

        history.last_seen = request.timestamp

        history.last_gnb = request.gnb_ip

        history.last_suci = request.suci

        history.timestamps.append(request.timestamp)

        history.registration_count += 1
        # ----------------------------------------------
        # Save History
        # ----------------------------------------------

        self.histories[request.ue_id] = history

        # ----------------------------------------------
        # Return Full Context
        # ----------------------------------------------

        return context

    # ======================================================
    # Classification Only
    # ======================================================

    def validate(

        self,

        request: RegistrationRequest,

    ) -> ClassificationResult:

        """
        Backward-compatible wrapper.

        Returns only the final classification.
        """

        context = self.validate_with_context(

            request

        )

        return context.classification_result

    # ======================================================
    # Statistics
    # ======================================================

    def get_statistics(
        self,
    ) -> AttackStatistics:
        """
        Return the current experiment statistics.
        """

        return self.statistics

    # ======================================================
    # Reset
    # ======================================================

    def reset_statistics(
        self,
    ) -> None:
        """
        Reset experiment statistics and
        registration histories.
        """

        self.statistics = AttackStatistics()

        self.histories.clear()


# ==========================================================
# Convenience Wrapper
# ==========================================================

def validate_request(
    request: RegistrationRequest,
    validator: PreAMFValidator | None = None,
) -> ClassificationResult:
    """
    Validate a registration request.

    If no validator instance is supplied,
    a temporary validator is created.

    NOTE
    ----
    For experiments involving multiple
    registrations or attack scenarios,
    reuse the SAME PreAMFValidator
    instance so that UE history is
    preserved across requests.
    """

    if validator is None:

        validator = PreAMFValidator()

    return validator.validate_with_context(

        request

    ).classification_result
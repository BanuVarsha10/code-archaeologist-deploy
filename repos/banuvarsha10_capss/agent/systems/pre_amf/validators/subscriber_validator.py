"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    subscriber_validator.py

Purpose
-------
Validates whether a subscriber exists before the
registration request proceeds through the remaining
Pre-AMF Security Layer.

Current Implementation
----------------------
Uses a local subscriber database.

Future Implementation
---------------------
Replace only subscriber_exists() with a MongoDB query.
The remaining code will remain unchanged.
"""

from pathlib import Path
from pymongo import MongoClient

from systems.pre_amf.attack_rules import (
    BLOCK_UNKNOWN_SUBSCRIBERS,
    MESSAGE_INVALID_SUBSCRIBER,
)

from systems.pre_amf.models import (
    RegistrationRequest,
    ValidationResult,
)


class SubscriberValidator:
    """
    Validates subscriber identity.
    """

    def __init__(self):

        self.client = MongoClient("mongodb://localhost:27017/")

        self.db = self.client["open5gs"]

        self.collection = self.db["subscribers"]

    # ======================================================
    # Load Subscriber Database
    # ======================================================

    def load_subscribers(self) -> set[str]:
        """
        Load valid subscribers.

        Current implementation:
            Local text file.

        Future implementation:
            MongoDB.
        """

        subscriber_file = (

            Path(__file__).resolve().parent.parent

            / "subscriber_database.txt"

        )

        subscribers = set()

        if not subscriber_file.exists():

            return subscribers

        with open(subscriber_file, "r") as file:

            for line in file:

                subscriber = line.strip()

                if subscriber:

                    subscribers.add(subscriber)

        return subscribers

    # ======================================================
    # Subscriber Lookup
    # ======================================================

    def subscriber_exists(
        self,
        ue_id: str,
    ) -> bool:
        """
        Check whether the subscriber exists
        in the Open5GS MongoDB database.
        """

        imsi = ue_id.replace("imsi-", "")


        subscriber = self.collection.find_one(
            {"imsi": imsi}
        )


        return subscriber is not None

    # ======================================================
    # Validation
    # ======================================================

    def validate(
        self,
        request: RegistrationRequest,
    ) -> ValidationResult:

        errors = []

        warnings = []

        score = 100

        # --------------------------------------------------
        # UE ID Present
        # --------------------------------------------------

        if not request.ue_id:

            return ValidationResult(

                passed=False,

                errors=[

                    "Missing UE ID."

                ],

                warnings=[],

                score=0

            )

        # --------------------------------------------------
        # Subscriber Exists
        # --------------------------------------------------

        if self.subscriber_exists(request.ue_id):

            return ValidationResult(

                passed=True,

                errors=[],

                warnings=[],

                score=score

            )

        # --------------------------------------------------
        # Unknown Subscriber
        # --------------------------------------------------

        score -= 100

        if BLOCK_UNKNOWN_SUBSCRIBERS:

            errors.append(

                f"{MESSAGE_INVALID_SUBSCRIBER} "

                f"({request.ue_id})"

            )

            return ValidationResult(

                passed=False,

                errors=errors,

                warnings=[],

                score=max(score, 0)

            )

        warnings.append(

            f"{MESSAGE_INVALID_SUBSCRIBER} "

            f"({request.ue_id})"

        )

        return ValidationResult(

            passed=True,

            errors=[],

            warnings=warnings,

            score=max(score, 0)

        )


# ==========================================================
# Convenience Function
# ==========================================================

def validate_subscriber(
    request: RegistrationRequest,
) -> ValidationResult:
    """
    Convenience wrapper.
    """

    validator = SubscriberValidator()

    return validator.validate(request)
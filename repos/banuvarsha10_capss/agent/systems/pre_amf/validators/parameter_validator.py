"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    parameter_validator.py

Purpose
-------
Performs lightweight validation of registration
parameters extracted from AMF logs.

Responsibilities
----------------
1. Validate authentication result.
2. Validate registration status.
3. Validate registration type.
4. Validate SUCI format.
5. Validate UE ID.
6. Validate DNN.
7. Validate S-NSSAI.
8. Compute validation score.

This validator DOES NOT
-----------------------
- Detect flooding
- Detect duplicate registrations
- Query subscriber database
- Perform AI reasoning
"""

import re

from systems.pre_amf.attack_rules import (
    VALID_AUTH_RESULTS,
    VALID_REGISTRATION_STATUS,
    VALID_REGISTRATION_TYPES,
)

from systems.pre_amf.models import (
    RegistrationRequest,
    ValidationResult,
)


class ParameterValidator:
    """
    Performs parameter validation on a parsed
    registration request.
    """

    def validate(
        self,
        request: RegistrationRequest,
    ) -> ValidationResult:

        errors = []
        warnings = []

        score = 100

        
        # ==================================================
        # Registration Status
        # ==================================================

        if request.registration_status not in VALID_REGISTRATION_STATUS:

            errors.append(
                f"Invalid Registration Status: "
                f"{request.registration_status}"
            )

            score -= 20

        # ==================================================
        # Registration Type
        # ==================================================

        if request.registration_type not in VALID_REGISTRATION_TYPES:

            errors.append(
                f"Invalid Registration Type: "
                f"{request.registration_type}"
            )

            score -= 15

        # ==================================================
        # SUCI Validation
        # ==================================================

        if not request.suci:

            errors.append("Missing SUCI")

            score -= 25

        else:

            suci_pattern = r"^suci-[A-Za-z0-9\-.]+$"

            if not re.match(suci_pattern, request.suci):

                errors.append(
                    "Invalid SUCI format"
                )

                score -= 15

        # ==================================================
        # UE ID
        # ==================================================

        if not request.ue_id:

            errors.append("Missing UE ID")

            score -= 15

        elif not request.ue_id.lower().startswith("imsi-"):

            warnings.append(
                "UE ID does not follow IMSI format."
            )

            score -= 5

        # ==================================================
        # DNN
        # ==================================================

        if not request.dnn:

            warnings.append(
                "DNN not available."
            )

            score -= 5

        # ==================================================
        # S-NSSAI
        # ==================================================

        if not request.snssai:

            warnings.append(
                "S-NSSAI not available."
            )

            score -= 5

        # ==================================================
        # gNB
        # ==================================================

        if not request.gnb_ip:

            warnings.append(
                "gNB IP not available."
            )

            score -= 5

        # ==================================================
        # Event
        # ==================================================

        if request.event != "Registration":

            warnings.append(
                f"Unexpected Event: {request.event}"
            )

            score -= 5

        # ==================================================
        # Score Normalization
        # ==================================================

        score = max(score, 0)

        # ==================================================
        # Result
        # ==================================================

        if errors:

            return ValidationResult(

                passed=False,

                errors=errors,

                warnings=warnings,

                score=score

            )

        return ValidationResult(

            passed=True,

            errors=[],

            warnings=warnings,

            score=score

        )


# ==========================================================
# Convenience Function
# ==========================================================

def validate_parameters(
    request: RegistrationRequest,
) -> ValidationResult:
    """
    Validate registration parameters.

    Example
    -------

    result = validate_parameters(request)
    """

    validator = ParameterValidator()

    return validator.validate(request)
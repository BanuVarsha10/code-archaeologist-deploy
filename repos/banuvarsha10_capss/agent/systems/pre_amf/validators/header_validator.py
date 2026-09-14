"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    header_validator.py

Purpose
-------
Performs structural validation of a parsed
registration request before further processing.

Responsibilities
----------------
1. Validate required fields.
2. Ensure required fields are not empty.
3. Compute a validation score.
4. Return ValidationResult.

This validator DOES NOT
-----------------------
- Detect attacks
- Detect flooding
- Query subscriber database
- Perform behavioural analysis
"""

from dataclasses import fields

from systems.pre_amf.attack_rules import (
    REQUIRED_FIELDS,
)

from systems.pre_amf.models import (
    RegistrationRequest,
    ValidationResult,
)


class HeaderValidator:
    """
    Performs structural validation of a
    RegistrationRequest.
    """

    def validate(
        self,
        request: RegistrationRequest,
    ) -> ValidationResult:

        errors = []
        warnings = []

        score = 100

        # ==================================================
        # Request Exists
        # ==================================================

        if request is None:

            return ValidationResult(

                passed=False,

                errors=[
                    "RegistrationRequest object is None."
                ],

                warnings=[],

                score=0

            )

        # ==================================================
        # Dataclass Fields
        # ==================================================

        available_fields = {

            field.name

            for field in fields(request)

        }

        # ==================================================
        # Required Fields
        # ==================================================

        for field_name in REQUIRED_FIELDS:

            if field_name not in available_fields:

                errors.append(

                    f"Missing required field: {field_name}"

                )

                score -= 20

                continue

            value = getattr(request, field_name)

            # ----------------------------------------------
            # None Value
            # ----------------------------------------------

            if value is None:

                errors.append(

                    f"{field_name} is None."

                )

                score -= 10

                continue

            # ----------------------------------------------
            # Empty String
            # ----------------------------------------------

            if isinstance(value, str):

                if value.strip() == "":

                    errors.append(

                        f"{field_name} is empty."

                    )

                    score -= 10

        # ==================================================
        # Score Normalization
        # ==================================================

        score = max(score, 0)

        # ==================================================
        # Validation Result
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

            warnings=[],

            score=score

        )


# ==========================================================
# Convenience Function
# ==========================================================

def validate_header(
    request: RegistrationRequest,
) -> ValidationResult:
    """
    Validate a registration request.

    Example
    -------

    result = validate_header(request)
    """

    validator = HeaderValidator()

    return validator.validate(request)
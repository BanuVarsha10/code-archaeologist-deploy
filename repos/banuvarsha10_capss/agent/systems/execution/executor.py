import time
from datetime import datetime

from .models import *


SUPPORTED_SCHEMES = {
    "ECIES",
    "ML-KEM",
    "IBE",
    "GS",
    "AP",
    "DP",
    "ZKP"
}


class ExecutionEngine:

    def execute(self, policy):

        start = time.perf_counter()

        notes = []

        validation = policy["validation_result"]["is_valid"]

        if not validation:

            return PolicyExecution(

                policy_id=policy["policy_id"],

                ue_id=policy["enforcement"]["apply_to_ue"],

                timestamp=datetime.now(),

                primary_scheme=policy["selected_scheme"],

                hybrid_schemes=policy["hybrid_schemes"],

                confidence=policy["confidence"],

                risk_assessment=policy["risk_assessment"],

                execution_status=ExecutionStatus.FAILED,

                authentication_result="NOT_EXECUTED",

                processing_time_ms=0,

                evidence=ExecutionEvidence(
                    validation_passed=False,
                    policy_applied=False,
                    authentication_continued=False,
                    execution_notes=["Policy validation failed"]
                )
            )

        primary = policy["selected_scheme"]

        hybrids = policy["hybrid_schemes"]

        applied = True

        for scheme in [primary] + hybrids:

            if scheme not in SUPPORTED_SCHEMES:

                applied = False

                notes.append(f"{scheme} unsupported")

        if applied:
            notes.append("Policy successfully applied.")

        elapsed = (time.perf_counter() - start) * 1000

        return PolicyExecution(

            policy_id=policy["policy_id"],

            ue_id=policy["enforcement"]["apply_to_ue"],

            timestamp=datetime.now(),

            primary_scheme=primary,

            hybrid_schemes=hybrids,

            confidence=policy["confidence"],

            risk_assessment=policy["risk_assessment"],

            execution_status=ExecutionStatus.SUCCESS if applied else ExecutionStatus.PARTIAL,

            authentication_result="SUCCESS" if applied else "UNKNOWN",

            processing_time_ms=elapsed,

            evidence=ExecutionEvidence(

                validation_passed=True,

                policy_applied=applied,

                authentication_continued=True,

                execution_notes=notes
            )
        )
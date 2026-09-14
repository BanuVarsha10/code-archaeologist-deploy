import csv
from pathlib import Path


class ExecutionLogger:

    HEADER = [

        "Policy_ID",

        "UE_ID",

        "Primary_Scheme",

        "Hybrid_Schemes",

        "Risk",

        "Confidence",

        "Execution_Status",

        "Authentication_Result",

        "Processing_Time_ms",

        "Validation",

        "Policy_Applied"
    ]

    def write(self, executions, filename):

        Path(filename).parent.mkdir(parents=True, exist_ok=True)

        with open(filename, "w", newline="") as f:

            writer = csv.writer(f)

            writer.writerow(self.HEADER)

            for e in executions:

                writer.writerow([

                    e.policy_id,

                    e.ue_id,

                    e.primary_scheme,

                    "|".join(e.hybrid_schemes),

                    e.risk_assessment,

                    round(e.confidence,3),

                    e.execution_status.value,

                    e.authentication_result,

                    round(e.processing_time_ms,3),

                    e.evidence.validation_passed,

                    e.evidence.policy_applied

                ])
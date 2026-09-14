"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    report.py

Purpose
-------
Serializes ThreatContext objects into reports and CSV files.

This module performs NO threat calculation or attack detection.
Those responsibilities belong to:

• Pre-AMF Security Layer
• Threat Context Generator

Responsibilities:
• Build report objects
• Export systems_output.csv
• Print summaries
"""

from pathlib import Path
import csv

from systems.pre_amf.models import AttackReport
from systems.threat_context.models import ThreatContext


class ReportGenerator:
    """
    Generates reports from ThreatContext objects.
    """

    def __init__(self):
        self.reports = []

    # ======================================================
    # Build Report
    # ======================================================

    def build_report(
        self,
        threat_context: ThreatContext,
    ) -> AttackReport:

        report = AttackReport(

            request_id=threat_context.registration_id,

            experiment_name=threat_context.experiment_name,

            timestamp=threat_context.timestamp,

            ue_id=threat_context.ue_id,

            attack_detected=threat_context.attack_detected,

            attack_type=threat_context.attack_type,

            decision=threat_context.decision,

            severity=threat_context.severity,

            confidence=threat_context.confidence,

            risk_score=threat_context.threat_score,

            reasons=threat_context.reasons,

        )

        self.reports.append(report)

        return report

    # ======================================================
    # Export CSV
    # ======================================================

    def export_csv(
        self,
        output_file,
    ):

        output_file = Path(output_file)

        output_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8",
        ) as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow([

                "Registration_ID",

                "Experiment",

                "Timestamp",

                "UE_ID",

                "Attack_Detected",

                "Attack_Type",

                "Decision",

                "Severity",

                "Threat_Score",

                "Threat_Confidence",

                "Reasons",

            ])

            for report in self.reports:

                writer.writerow([

                    report.request_id,

                    report.experiment_name,

                    report.timestamp,

                    report.ue_id,

                    report.attack_detected,

                    report.attack_type,

                    report.decision,

                    report.severity,

                    report.risk_score,

                    report.confidence,

                    " | ".join(report.reasons),

                ])

    # ======================================================
    # Summary
    # ======================================================

    def print_summary(self):

        print()
        print("=" * 60)
        print("CAPSS Systems Report")
        print("=" * 60)

        print(f"Total Requests : {len(self.reports)}")

        attacks = sum(

            report.attack_detected

            for report in self.reports

        )

        print(f"Attacks Found  : {attacks}")

        print(f"Normal Traffic : {len(self.reports) - attacks}")

        if self.reports:

            avg_score = sum(

                report.risk_score

                for report in self.reports

            ) / len(self.reports)

            print(f"Average Threat Score : {avg_score:.2f}")

        print("=" * 60)


# ==========================================================
# Convenience Functions
# ==========================================================

def generate_report(
    threat_context: ThreatContext,
) -> AttackReport:

    generator = ReportGenerator()

    return generator.build_report(threat_context)


def export_reports(
    reports,
    output_file,
):

    generator = ReportGenerator()

    generator.reports = reports

    generator.export_csv(output_file)
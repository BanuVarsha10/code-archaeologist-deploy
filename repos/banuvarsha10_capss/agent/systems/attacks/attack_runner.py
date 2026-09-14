"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    attack_runner.py

Purpose
-------
Runs the complete Pre-AMF validation pipeline.

Pipeline
--------

registration_dataset.csv
        │
        ▼
RegistrationLoader
        │
        ▼
PreAMFValidator
        │
        ▼
ReportGenerator
        │
        ▼
attack_dataset.csv
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from systems.pre_amf.registration_loader import (
    load_registration_dataset,
)

from systems.pre_amf.validator import (
    PreAMFValidator,
)

from systems.pre_amf.report import (
    ReportGenerator,
)

from systems.threat_context.generator import ThreatContextGenerator


# ==========================================================
# Paths
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DATASET = (
    BASE_DIR
    / "datasets"
    / "registration_dataset.csv"
)

OUTPUT = (
    BASE_DIR
    / "datasets"
    / "attack_dataset.csv"
)


# ==========================================================
# Runner
# ==========================================================

class AttackRunner:

    def __init__(self):

        self.validator = PreAMFValidator()

        self.threat_generator = ThreatContextGenerator()

        self.report_generator = ReportGenerator()

    # ------------------------------------------------------

    def run(self):

        print()

        print("=" * 60)
        print("CAPSS Pre-AMF Attack Runner")
        print("=" * 60)

        # ------------------------------------------
        # Load registrations
        # ------------------------------------------

        requests = load_registration_dataset(

            DATASET

        )

        print(f"Loaded {len(requests)} registration requests.")

        # ------------------------------------------
        # Validate every request
        # ------------------------------------------

        for request in requests:

            validation_context = self.validator.validate_with_context(
                request
            )

            threat_context = self.threat_generator.generate(
                validation_context
            )

            self.report_generator.build_report(
                threat_context
            )

        # ------------------------------------------
        # Export attack dataset
        # ------------------------------------------

        self.report_generator.export_csv(

            OUTPUT

        )

        # ------------------------------------------
        # Print statistics
        # ------------------------------------------

        self.report_generator.print_summary()

        stats = self.validator.get_statistics()

        print()

        print("=" * 60)

        print("Statistics")

        print("=" * 60)

        print(f"Total Requests      : {stats.total_requests}")
        print(f"Allowed             : {stats.allowed}")
        print(f"Tagged              : {stats.tagged}")
        print(f"Blocked             : {stats.blocked}")
        print(f"Duplicate Attacks   : {stats.duplicate_attacks}")
        print(f"Replay Attacks      : {stats.replay_attacks}")
        print(f"Flood Attacks       : {stats.flood_attacks}")
        print(f"Invalid Subscribers : {stats.invalid_subscribers}")
        print(f"Invalid Headers     : {stats.invalid_headers}")
        print(f"Invalid Parameters  : {stats.invalid_parameters}")

        print()

        print(f"Attack dataset saved to:")

        print(OUTPUT)

        print("=" * 60)


# ==========================================================
# Main
# ==========================================================

def main():

    runner = AttackRunner()

    runner.run()


if __name__ == "__main__":

    main()
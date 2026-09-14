import os
import subprocess
import sys
import time

# --------------------------------------------------
# Base Directories
# --------------------------------------------------

PRIVACY_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(PRIVACY_DIR)

LOGGING_DIR = os.path.join(PROJECT_DIR, "logging")

# --------------------------------------------------
# Scripts to Execute
# --------------------------------------------------
# Order is dependency-driven:
#   1. Logging must run first - everything downstream reads the
#      registration data it produces.
#   2. security_context.py runs next because correlation_analyzer.py,
#      privacy_score.py, and privacy_threat_analyze.py all depend on
#      the attack context (Attack_Detected, Attack_Type, Decision,
#      Severity, Confidence) it merges in - none of them recalculate
#      that themselves.
#   3. correlation_analyzer.py / metadata_minimizer.py / privacy_score.py
#      can run in any order relative to each other - none of them
#      reads another's output, they just each need step 2 done first.
#   4. privacy_threat_analyze.py also just needs step 2's merged
#      attack context, so it can run anytime after security_context.py.
#   5. generate_privacy_context.py is intentionally NOT run by this
#      pipeline - privacy_context.csv / privacy_context_summary.csv
#      are produced separately (outside this run) and consumed as-is
#      by evaluation.py.
#   6. privacy_summary.py must run last among the analysis scripts,
#      since it aggregates the report files written by correlation_analyzer.py,
#      metadata_minimizer.py, privacy_score.py, and privacy_threat_analyze.py.
#   7. generate_privacy_graphs.py runs last overall - it reads both
#      the raw dataset and privacy_summary.txt, so privacy_summary.py
#      must have already written that file.
# Evaluation is based on the privacy_context from the privacy team, agent_output from the agent team, system_output from the system team

PIPELINE = [

    # -----------------------------
    # Logging
    # -----------------------------

    ("Logging", os.path.join(LOGGING_DIR, "metrics_collector.py")),

    ("Logging", os.path.join(LOGGING_DIR, "registration_logger.py")),

    # -----------------------------
    # Security Context Generation
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "security_context.py")),

    # -----------------------------
    # Privacy Analysis
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "correlation_analyzer.py")),

    ("Privacy", os.path.join(PRIVACY_DIR, "metadata_minimizer.py")),

    ("Privacy", os.path.join(PRIVACY_DIR, "privacy_score.py")),

    # -----------------------------
    # Threat Analysis
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "privacy_threat_analyze.py")),

    # -----------------------------
    # Final Summary
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "privacy_summary.py")),

    # -----------------------------
    # Graphs
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "generate_privacy_graphs.py"))

]

# --------------------------------------------------
# Banner
# --------------------------------------------------

print("\n======================================================")
print("              CAPSS PRIVACY PIPELINE")
print("======================================================\n")

start_time = time.time()

# --------------------------------------------------
# Execute Pipeline
# --------------------------------------------------

for index, (module, script) in enumerate(PIPELINE, start=1):

    print(f"[{index}/{len(PIPELINE)}] {module}")
    print(f"Running : {os.path.basename(script)}")

    result = subprocess.run(
        [sys.executable, script]
    )

    if result.returncode != 0:

        print("\nERROR")
        print(f"{os.path.basename(script)} failed.")

        sys.exit(result.returncode)

    print("Completed Successfully.\n")

# --------------------------------------------------
# Finish
# --------------------------------------------------

end_time = time.time()

print("======================================================")
print("     CAPSS Privacy Pipeline Completed Successfully")
print("======================================================")

print(f"\nExecution Time : {end_time - start_time:.2f} seconds\n")

# --------------------------------------------------
# Generated Outputs
# --------------------------------------------------
# NOTE: the five graphs below (risk_score_distribution.png through
# attack_confidence_distribution.png) are only produced by
# generate_privacy_graphs.py when the dataset actually has attack
# columns (Risk_Score, Attack_Type, Decision, Severity, Confidence).
# They're listed here as expected outputs of a normal run since the
# pipeline's dataset does include those columns (via security_context.py),
# but if that ever changes, some of these files may not appear.

print("Generated Outputs")
print("--------------------------------------------------")

outputs = [

    # Logging

    "results/metrics_report.txt",

    "results/registration_summary.txt",

    # Security Context

    "results/privacy_dataset.csv",

    # Privacy

    "results/privacy_report.txt",

    "results/anonymized_registration_dataset.csv",

    "results/correlation_report.txt",

    # Threat Analysis

    "results/privacy_threat_report.txt",

    # Final Report

    "results/privacy_summary.txt",

    # Graphs

    "results/graphs/privacy_score_distribution.png",

    "results/graphs/exposure_distribution.png",

    "results/graphs/identifier_statistics.png",

    "results/graphs/registration_statistics.png",

    "results/graphs/risk_score_distribution.png",

    "results/graphs/attack_type_distribution.png",

    "results/graphs/decision_distribution.png",

    "results/graphs/severity_distribution.png",

    "results/graphs/attack_confidence_distribution.png"

]

for file in outputs:

    print(f"✓ {file}")

print("--------------------------------------------------")

print("\nPipeline Finished Successfully.\n")
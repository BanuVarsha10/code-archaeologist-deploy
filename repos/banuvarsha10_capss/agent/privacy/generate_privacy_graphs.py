import os
import re
import csv
import matplotlib.pyplot as plt
from collections import Counter

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASETS_DIR = os.path.join(BASE_DIR, "..", "datasets")

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)

GRAPH_DIR = os.path.join(
    RESULTS_DIR,
    "graphs"
)

os.makedirs(GRAPH_DIR, exist_ok=True)

# --------------------------------------------------
# CSV Source
# --------------------------------------------------
# Only privacy4.csv is read (per-record data used to build the
# graphs). A graph only gets populated for a column group if
# privacy4.csv's header actually contains the columns that group
# needs:
#   - privacy/identifier/registration graphs need UE_ID, SUCI,
#     gNB_IP, Timestamp, DNN, S_NSSAI, Authentication_Result,
#     Registration_Status
#   - attack/risk graphs need Risk_Score, Attack_Type, Decision,
#     Severity, Confidence

TARGET_CSV_FILENAME = "privacy_test.csv"

TARGET_CSV_PATH = os.path.join(DATASETS_DIR, TARGET_CSV_FILENAME)

ALL_CSV_FILES = [TARGET_CSV_PATH] if os.path.isfile(TARGET_CSV_PATH) else []

PRIVACY_COLUMNS = {
    "UE_ID", "SUCI", "gNB_IP", "Timestamp",
    "DNN", "S_NSSAI", "Authentication_Result", "Registration_Status"
}

ATTACK_COLUMNS = {
    "Risk_Score", "Attack_Type", "Decision", "Severity", "Confidence"
}

privacy_files_used = []
attack_files_used = []

# --------------------------------------------------
# Summary Text Source
# --------------------------------------------------
# privacy_summary.txt holds the authoritative aggregate numbers
# (Average Privacy Score, Highest Exposure Score, Average/
# Highest/Lowest Risk Score, Correlation Score, Correlation
# Confidence, Attack Detection Rate, Average Confidence, etc.)
# already computed by privacy_score.py / correlation_analyzer.py
# / privacy_threat_analyzer.py. Rather than re-deriving these
# from privacy4.csv (which can drift out of sync with the
# report), they're read directly from the summary text and
# overlaid as reference lines on the matching graphs, plus
# printed in a cross-check against what privacy4.csv itself
# computes.

SUMMARY_TXT_FILENAME = "privacy_summary.txt"

SUMMARY_TXT_CANDIDATES = [
    os.path.join(BASE_DIR, "..", SUMMARY_TXT_FILENAME),
    os.path.join(RESULTS_DIR, SUMMARY_TXT_FILENAME),
    os.path.join(RESULTS_DIR, "tables", SUMMARY_TXT_FILENAME),
    os.path.join(BASE_DIR, SUMMARY_TXT_FILENAME),
]

SUMMARY_TXT_PATH = next(
    (p for p in SUMMARY_TXT_CANDIDATES if os.path.isfile(p)),
    None
)


def extract_number(text, label):
    """Grab the first number that follows `label` (colon and/or
    blank lines in between are both fine, since \\s matches
    newlines too)."""
    pattern = re.escape(label) + r"\s*:?\s*([\-0-9]+\.?[0-9]*)"
    match = re.search(pattern, text)
    return float(match.group(1)) if match else None


def extract_text(text, label):
    """Grab the first non-empty line of free text that follows
    `label` (e.g. 'Overall Risk Level: Not available')."""
    pattern = re.escape(label) + r"\s*:?\s*\n*\s*([^\n]+)"
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None


def parse_privacy_summary(path):
    """Pull the aggregate metrics CAPSS's own report already
    computed, so the graphs can reference the same numbers
    instead of recalculating (and potentially disagreeing)."""

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    section_e_start = text.find("SECTION E")
    section_e_text = text[section_e_start:] if section_e_start != -1 else text

    return {
        "avg_privacy_score": extract_number(text, "Average Privacy Score"),
        "highest_exposure_score": extract_number(text, "Highest Exposure Score"),
        "avg_risk_score": extract_number(text, "Average Risk Score"),
        "highest_risk_score": extract_number(text, "Highest Risk Score"),
        "lowest_risk_score": extract_number(text, "Lowest Risk Score"),
        "overall_risk_level": extract_text(text, "Overall Risk Level"),
        "correlation_score": extract_number(text, "Correlation Score"),
        "correlation_risk_level": extract_text(text, "Correlation Risk Level"),
        "correlation_confidence": extract_number(text, "Correlation Confidence"),
        "attack_detection_rate": extract_number(text, "Attack Detection Rate"),
        "avg_confidence_pct": extract_number(section_e_text, "Average Confidence"),
        "total_attacks_detected": extract_number(section_e_text, "Total Attacks Detected"),
        "overall_privacy_risk": extract_text(text, "Overall Privacy Risk"),
    }


summary_metrics = {}

if SUMMARY_TXT_PATH:
    summary_metrics = parse_privacy_summary(SUMMARY_TXT_PATH)
else:
    print(f"WARNING: {SUMMARY_TXT_FILENAME} not found in any of: {SUMMARY_TXT_CANDIDATES}")

# --------------------------------------------------
# Registration/Auth Outcome Keywords
# --------------------------------------------------
# NOTE: kept in the same uppercase style as
# correlation_analyzer.py's FAILURE_KEYWORDS/SUCCESS_KEYWORDS,
# so this pipeline agrees on what "success" means everywhere.
# If correlation_analyzer.py's sets are ever shared as an
# importable module, swap this local definition for an import
# from there instead of keeping a second copy in sync by hand.

SUCCESS_KEYWORDS = {"SUCCESS"}

# --------------------------------------------------
# Preferred display order for categorical fields
# --------------------------------------------------
# Used only to keep bars in a sensible order when the category
# is present in the data; any value seen in the CSV that isn't
# in this list (e.g. a new attack type added later) is still
# included, just appended at the end instead of being dropped.

SEVERITY_ORDER = ["NORMAL", "SUSPICIOUS", "MALICIOUS", "CRITICAL"]
DECISION_ORDER = ["ALLOW", "TAG", "BLOCK"]


def ordered_labels(counter, preferred_order):
    ordered = [label for label in preferred_order if label in counter]
    remaining = sorted(label for label in counter if label not in preferred_order)
    return ordered + remaining

# --------------------------------------------------
# Exposure Calculation Functions
# --------------------------------------------------

def ue_id_exposure(value):
    if value == "":
        return 0
    elif value.startswith("imsi"):
        return 30          # Original IMSI
    elif value.startswith("UE_"):
        return 5           # Pseudonymized
    else:
        return 10


def suci_exposure(value):
    if value == "":
        return 0
    elif value.startswith("SUCI_"):
        return 5           # Pseudonymized
    elif value.startswith("suci"):
        return 20          # Original SUCI
    else:
        return 10


def gnb_exposure(value):
    if value == "":
        return 0
    elif "xxx" in value:
        return 3           # Masked IP
    else:
        return 15          # Original IP


def timestamp_exposure(value):
    if value == "":
        return 0
    elif value.startswith("T+"):
        return 2           # Relative Timestamp
    else:
        return 5           # Exact Timestamp


def generic_exposure(value, weight):
    if value == "":
        return 0
    return weight

# --------------------------------------------------
# Variables
# --------------------------------------------------

privacy_scores = []

exposure_scores = []

registration_status = []

authentication = []

ue_ids = []

suci_ids = []

# New: attack/risk fields
risk_scores = []
attack_types = []
decisions = []
severities = []
confidences = []

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------
# Only privacy4.csv is opened. Its header is checked against
# PRIVACY_COLUMNS and ATTACK_COLUMNS independently, so the file
# can feed either group, both, or neither, depending on which
# columns it actually has.

if not ALL_CSV_FILES:
    print(f"WARNING: {TARGET_CSV_FILENAME} not found in {DATASETS_DIR}")

for csv_path in ALL_CSV_FILES:

    with open(csv_path, "r", encoding="utf-8") as file:

        reader = csv.DictReader(file)

        fieldnames = set(reader.fieldnames or [])

        has_privacy_columns = PRIVACY_COLUMNS.issubset(fieldnames)
        has_attack_columns = ATTACK_COLUMNS.issubset(fieldnames)

        if not has_privacy_columns and not has_attack_columns:
            continue

        if has_privacy_columns:
            privacy_files_used.append(csv_path)

        if has_attack_columns:
            attack_files_used.append(csv_path)

        for row in reader:

            if has_privacy_columns:

                exposure = 0

                exposure += ue_id_exposure(row["UE_ID"].strip())
                exposure += suci_exposure(row["SUCI"].strip())
                exposure += gnb_exposure(row["gNB_IP"].strip())
                exposure += timestamp_exposure(row["Timestamp"].strip())

                exposure += generic_exposure(row["DNN"].strip(), 10)
                exposure += generic_exposure(row["S_NSSAI"].strip(), 10)
                exposure += generic_exposure(row["Authentication_Result"].strip(), 5)
                exposure += generic_exposure(row["Registration_Status"].strip(), 5)

                privacy = max(0, 100 - exposure)

                exposure_scores.append(exposure)
                privacy_scores.append(privacy)

                registration_status.append(row["Registration_Status"])
                authentication.append(row["Authentication_Result"])

                if row["UE_ID"]:
                    ue_ids.append(row["UE_ID"])

                if row["SUCI"]:
                    suci_ids.append(row["SUCI"])

            # ------------------------------------------
            # Attack / risk fields
            # ------------------------------------------
            # Attack_Type covers NONE (no attack), REPLAY,
            # REGISTRATION_FLOOD, INVALID_SUBSCRIBER, and any
            # future type CAPSS starts tagging - all handled
            # generically via Counter below, so INVALID_SUBSCRIBER
            # is already counted correctly without special-casing
            # it.

            if has_attack_columns:

                risk_score_raw = row.get("Risk_Score", "").strip()
                if risk_score_raw != "":
                    try:
                        risk_scores.append(float(risk_score_raw))
                    except ValueError:
                        pass

                attack_type = row.get("Attack_Type", "").strip()
                if attack_type != "":
                    attack_types.append(attack_type)

                decision = row.get("Decision", "").strip()
                if decision != "":
                    decisions.append(decision)

                severity = row.get("Severity", "").strip()
                if severity != "":
                    severities.append(severity)

                confidence_raw = row.get("Confidence", "").strip()
                if confidence_raw != "":
                    try:
                        confidences.append(float(confidence_raw))
                    except ValueError:
                        pass

# --------------------------------------------------
# Graph 1
# Privacy Score Distribution
# --------------------------------------------------

plt.figure(figsize=(8,5))

plt.bar(
    range(1, len(privacy_scores)+1),
    privacy_scores
)

if summary_metrics.get("avg_privacy_score") is not None:
    plt.axhline(
        y=summary_metrics["avg_privacy_score"],
        color="black",
        linestyle="--",
        label=f"Summary Avg: {summary_metrics['avg_privacy_score']:.2f}"
    )
    plt.legend()

plt.title("Privacy Score Distribution")

plt.xlabel("Registration Record")

plt.ylabel("Privacy Score")

plt.ylim(0,100)

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "privacy_score_distribution.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 2
# Exposure Distribution
# --------------------------------------------------

plt.figure(figsize=(8,5))

plt.bar(
    range(1, len(exposure_scores)+1),
    exposure_scores
)

if summary_metrics.get("highest_exposure_score") is not None:
    plt.axhline(
        y=summary_metrics["highest_exposure_score"],
        color="black",
        linestyle="--",
        label=f"Summary Highest: {summary_metrics['highest_exposure_score']:.2f}"
    )
    plt.legend()

plt.title("Metadata Exposure Distribution")

plt.xlabel("Registration Record")

plt.ylabel("Exposure Score")

plt.ylim(0,100)

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "exposure_distribution.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 3
# Identifier Statistics
# --------------------------------------------------

unique_ue = len(set(ue_ids))

unique_suci = len(set(suci_ids))

repeated_ue = sum(
    1
    for count in Counter(ue_ids).values()
    if count > 1
)

repeated_suci = sum(
    1
    for count in Counter(suci_ids).values()
    if count > 1
)

labels = [
    "Unique UE",
    "Repeated UE",
    "Unique SUCI",
    "Repeated SUCI"
]

values = [
    unique_ue,
    repeated_ue,
    unique_suci,
    repeated_suci
]

plt.figure(figsize=(8,5))

plt.bar(labels, values)

plt.title("Identifier Statistics")

plt.ylabel("Count")

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "identifier_statistics.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 4
# Registration Statistics
# --------------------------------------------------

# NOTE: was previously registration_status.count("Success"),
# which is a case-sensitive exact match. If the CSV stores
# uppercase values ("SUCCESS"/"FAILED", as the rest of this
# pipeline assumes), that comparison never matched anything and
# this chart always showed 0% success regardless of the real
# data. Comparing case-insensitively against the shared keyword
# set fixes that.

success = sum(
    1
    for status in registration_status
    if status.strip().upper() in SUCCESS_KEYWORDS
)

failure = len(registration_status) - success

plt.figure(figsize=(6,6))

plt.pie(
    [success, failure],
    labels=["Success", "Failure"],
    autopct="%1.1f%%",
    startangle=90
)

plt.title("Registration Success Rate")

plt.tight_layout()

plt.savefig(
    os.path.join(
        GRAPH_DIR,
        "registration_statistics.png"
    )
)

plt.close()

# --------------------------------------------------
# Graph 5 (NEW)
# Overall Risk Score Distribution
# --------------------------------------------------

if risk_scores:

    plt.figure(figsize=(8,5))

    plt.bar(
        range(1, len(risk_scores)+1),
        risk_scores,
        color="firebrick"
    )

    if summary_metrics.get("avg_risk_score") is not None:
        plt.axhline(
            y=summary_metrics["avg_risk_score"],
            color="blue",
            linestyle="--",
            label=f"Summary Avg: {summary_metrics['avg_risk_score']:.2f}"
        )

    if summary_metrics.get("highest_risk_score") is not None:
        plt.axhline(
            y=summary_metrics["highest_risk_score"],
            color="black",
            linestyle=":",
            label=f"Summary Highest: {summary_metrics['highest_risk_score']:.2f}"
        )

    if summary_metrics.get("lowest_risk_score") is not None:
        plt.axhline(
            y=summary_metrics["lowest_risk_score"],
            color="green",
            linestyle=":",
            label=f"Summary Lowest: {summary_metrics['lowest_risk_score']:.2f}"
        )

    if any(k in summary_metrics for k in ("avg_risk_score", "highest_risk_score", "lowest_risk_score")):
        plt.legend()

    plt.title("Overall Risk Score Distribution")

    plt.xlabel("Registration Record")

    plt.ylabel("Risk Score")

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "risk_score_distribution.png"
        )
    )

    plt.close()

# --------------------------------------------------
# Graph 6 (NEW)
# Attack Type Distribution
# --------------------------------------------------
# NONE means "no attack detected" and is included here so the
# chart shows the full picture (how much traffic was clean vs.
# flagged), rather than only the attack categories.

if attack_types:

    attack_counts = Counter(attack_types)

    attack_labels = ordered_labels(
        attack_counts,
        ["NONE", "REPLAY", "REGISTRATION_FLOOD", "INVALID_SUBSCRIBER"]
    )

    attack_values = [attack_counts[label] for label in attack_labels]

    plt.figure(figsize=(8,5))

    plt.barh(attack_labels, attack_values, color="darkorange")

    plt.title("Attack Type Distribution")

    plt.xlabel("Count")

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "attack_type_distribution.png"
        )
    )

    plt.close()

# --------------------------------------------------
# Graph 7 (NEW)
# Decision Distribution
# --------------------------------------------------

if decisions:

    decision_counts = Counter(decisions)

    decision_labels = ordered_labels(decision_counts, DECISION_ORDER)

    decision_values = [decision_counts[label] for label in decision_labels]

    plt.figure(figsize=(6,6))

    plt.pie(
        decision_values,
        labels=decision_labels,
        autopct="%1.1f%%",
        startangle=90
    )

    plt.title("Decision Distribution")

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "decision_distribution.png"
        )
    )

    plt.close()

# --------------------------------------------------
# Graph 8 (NEW)
# Severity Distribution
# --------------------------------------------------
# Includes MALICIOUS (used by REGISTRATION_FLOOD and
# INVALID_SUBSCRIBER records in this dataset) alongside
# NORMAL/SUSPICIOUS, plus CRITICAL if it ever appears.

if severities:

    severity_counts = Counter(severities)

    severity_labels = ordered_labels(severity_counts, SEVERITY_ORDER)

    severity_values = [severity_counts[label] for label in severity_labels]

    plt.figure(figsize=(8,5))

    plt.bar(severity_labels, severity_values, color="crimson")

    plt.title("Severity Distribution")

    plt.ylabel("Count")

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "severity_distribution.png"
        )
    )

    plt.close()

# --------------------------------------------------
# Graph 9 (NEW)
# Attack Confidence Distribution
# --------------------------------------------------

if confidences:

    plt.figure(figsize=(8,5))

    plt.hist(confidences, bins=10, range=(0,1), color="teal", edgecolor="black")

    avg_confidence_pct = summary_metrics.get("avg_confidence_pct")
    if avg_confidence_pct is not None:
        # Summary reports this as a percentage (e.g. 84.4); the
        # histogram's x-axis is a 0-1 fraction, so convert before
        # drawing the reference line.
        avg_confidence_fraction = (
            avg_confidence_pct / 100
            if avg_confidence_pct > 1
            else avg_confidence_pct
        )
        plt.axvline(
            x=avg_confidence_fraction,
            color="red",
            linestyle="--",
            label=f"Summary Avg: {avg_confidence_pct:.1f}%"
        )
        plt.legend()

    plt.title("Attack Confidence Distribution")

    plt.xlabel("Confidence")

    plt.ylabel("Count")

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "attack_confidence_distribution.png"
        )
    )

    plt.close()

# --------------------------------------------------
# Done
# --------------------------------------------------

print("\n===========================================")
print("Privacy Graphs Generated Successfully")
print("===========================================")

print(f"Dataset Used : {TARGET_CSV_FILENAME}")
print(f"Used for Privacy Graphs : {[os.path.basename(f) for f in privacy_files_used]}")
print(f"Used for Attack/Risk Graphs : {[os.path.basename(f) for f in attack_files_used]}")
print(f"Summary Text Used : {os.path.basename(SUMMARY_TXT_PATH) if SUMMARY_TXT_PATH else 'NOT FOUND'}")
print(f"Output Directory : {GRAPH_DIR}")

print("\nGenerated Files")

print("------------------------------")

print("privacy_score_distribution.png")
print("exposure_distribution.png")
print("identifier_statistics.png")
print("registration_statistics.png")

if risk_scores:
    print("risk_score_distribution.png")
if attack_types:
    print("attack_type_distribution.png")
if decisions:
    print("decision_distribution.png")
if severities:
    print("severity_distribution.png")
if confidences:
    print("attack_confidence_distribution.png")

print("------------------------------")

# --------------------------------------------------
# Summary Report Metrics + Cross-Check
# --------------------------------------------------
# These numbers come straight from privacy_summary.txt (the
# authoritative output of privacy_score.py /
# correlation_analyzer.py / privacy_threat_analyzer.py). Where
# privacy4.csv also lets us compute an equivalent figure, the two
# are compared so a drift between the report and the raw CSV
# doesn't go unnoticed.

if summary_metrics:

    print("\nSummary Report Metrics (privacy_summary.txt)")
    print("------------------------------")
    for key, value in summary_metrics.items():
        if value is not None:
            print(f"{key} : {value}")
    print("------------------------------")

    TOLERANCE = 0.5

    if privacy_scores and summary_metrics.get("avg_privacy_score") is not None:
        computed_avg_privacy = sum(privacy_scores) / len(privacy_scores)
        diff = abs(computed_avg_privacy - summary_metrics["avg_privacy_score"])
        flag = "WARNING: MISMATCH" if diff > TOLERANCE else "OK"
        print(
            f"[{flag}] Avg Privacy Score - CSV: {computed_avg_privacy:.2f} "
            f"vs Summary: {summary_metrics['avg_privacy_score']:.2f}"
        )

    if exposure_scores and summary_metrics.get("highest_exposure_score") is not None:
        computed_max_exposure = max(exposure_scores)
        diff = abs(computed_max_exposure - summary_metrics["highest_exposure_score"])
        flag = "WARNING: MISMATCH" if diff > TOLERANCE else "OK"
        print(
            f"[{flag}] Highest Exposure Score - CSV: {computed_max_exposure:.2f} "
            f"vs Summary: {summary_metrics['highest_exposure_score']:.2f}"
        )

    if risk_scores and summary_metrics.get("avg_risk_score") is not None:
        computed_avg_risk = sum(risk_scores) / len(risk_scores)
        diff = abs(computed_avg_risk - summary_metrics["avg_risk_score"])
        flag = "WARNING: MISMATCH" if diff > TOLERANCE else "OK"
        print(
            f"[{flag}] Avg Risk Score - CSV: {computed_avg_risk:.2f} "
            f"vs Summary: {summary_metrics['avg_risk_score']:.2f}"
        )

    print("------------------------------")
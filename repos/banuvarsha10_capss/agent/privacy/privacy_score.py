import os
import re
import csv
from collections import Counter

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CHANGED: now reads the merged dataset produced by security_context.py
# (Phase 2 of the integration), which carries Attack_Detected /
# Attack_Type / Decision / Severity / Confidence alongside the original
# registration fields. Previously this pointed at
# datasets/registration_dataset20.csv, which has none of those columns.
CSV_FILE = os.path.join(
    BASE_DIR,
    "..",
    "datasets",
    "privacy_test.csv" 
)
 
RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

REPORT_FILE = os.path.join(RESULTS_DIR, "privacy_report.txt")

# Report produced by correlation_analyzer.py. Read-only here - this
# file never generates or recalculates a correlation score, it only
# parses the one correlation_analyzer.py already wrote out.
CORRELATION_REPORT_FILE = os.path.join(RESULTS_DIR, "correlation_report.txt")

# --------------------------------------------------
# Maximum Possible Exposure
# --------------------------------------------------

MAX_WEIGHTS = {
    "UE_ID": 30,
    "SUCI": 20,
    "gNB_IP": 15,
    "DNN": 10,
    "S_NSSAI": 10,
    "Timestamp": 5,
    "Authentication_Result": 5,
    "Registration_Status": 5
}

# --------------------------------------------------
# Overall Risk Score Weights
# --------------------------------------------------
# Overall_Risk_Score (0-100) = Repeated Registrations
#                             + Failed Registrations
#                             + Metadata Exposure
#                             + Attack Indicators
#
# NOTE: This is the full combined risk picture (kept exactly as
# before, only renamed from "Risk_Score" to "Overall_Risk_Score").
# Repeated/Failed/Attack Indicators conceptually belong to Threat
# Detection, but per your call they stay here rather than being
# removed - Privacy_Risk_Score (below) is the separate, pure
# exposure-only score requested on top of this.
#
# These weights are a documented design choice (they sum to 100)
# so the final Overall_Risk_Score stays on a 0-100 scale like the
# existing Privacy/Exposure/Privacy_Risk_Score.
#
# UPDATED (round 2): "Attack_Indicators" is spent by
# attack_behaviour_component() using the Systems team's real
# Attack_Detected / Severity / Confidence / Decision fields, instead
# of the old repeat-count-plus-failure proxy.
#
# "Repeated_Registrations" is renamed to "Behaviour_Risk" - it was
# never attack detection, it's a behavioural privacy signal (the
# same UE showing up repeatedly), so the name now says what it is.
#
# "Failed_Registrations" is KEPT (not removed, despite feedback
# suggesting it's duplicate logic). Registration/auth failure and
# Systems' Attack_Detected are different signals: a registration can
# fail for ordinary reasons (wrong DNN, expired credential, network
# issue) with no attack flag at all, and an attack can be detected on
# a record where registration succeeded (e.g. reconnaissance, a
# replay that still completes). Its weight is reduced rather than
# zeroed, since there is now some overlap now that real attack data
# exists.
#
# UPDATED (round 3): "Behaviour_Correlation" is no longer waiting on
# a per-record Correlation_Score column. correlation_analyzer.py only
# ever produces one Correlation Score for the whole dataset (see its
# report), not one per registration, so this component now applies
# that single dataset-wide value identically to every record - a
# global "this registration environment has high/low linkability
# risk" context factor, not a per-record differentiator. See
# get_overall_correlation_score() / correlation_component() below.
#
# Weights were rebalanced (not copied from any single suggestion)
# to make room for Behaviour_Correlation while still summing to 100.

RISK_WEIGHTS = {
    "Metadata_Exposure": 25,
    "Behaviour_Risk": 20,          # renamed from Repeated_Registrations
    "Failed_Registrations": 15,    # kept, weight reduced
    "Behaviour_Correlation": 15,   # dataset-wide correlation score, applied globally
    "Attack_Indicators": 25
}

# Registration/auth outcome values used consistently with the
# rest of the pipeline (correlation_analyzer.py compares these
# as uppercase, e.g. "SUCCESS" / "FAILED").
SUCCESS_KEYWORDS = {"SUCCESS"}

# Placeholder values used by the anonymizer for DNN / S_NSSAI.
# Anything that doesn't match one of these is treated as a real,
# specific value (and therefore more identifying).
DNN_PLACEHOLDER_VALUES = {"DEFAULT_DNN"}
NSSAI_PLACEHOLDER_VALUES = {"DEFAULT_SLICE"}

# --------------------------------------------------
# Attack Context Lookup Tables (NEW)
# --------------------------------------------------
# Used only by attack_behaviour_component() below. These convert
# the Systems team's Severity / Decision strings into numbers.
# Risk_Score from attack.csv is intentionally NOT used anywhere in
# this file - it is always 0 in the current dataset and would
# contribute nothing but dead weight to the score.

SEVERITY_RANK = {
    "NONE": 0,
    "NORMAL": 0,
    "LOW": 1,
    "SUSPICIOUS": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DECISION_MULTIPLIER = {
    "BLOCK": 1.0,
    "TAG": 0.6,
    "ALLOW": 0.3,
    "UNKNOWN": 0.5,
}

# --------------------------------------------------
# Safe field access (boundary condition: short/malformed rows)
# --------------------------------------------------
# csv.DictReader fills missing trailing columns with None rather
# than "". Every call site below does field(row, col).strip()-
# equivalent work, so this keeps an "always a stripped string"
# contract without changing any scoring logic.

def field(row, key):
    value = row.get(key)
    return value.strip() if value else ""

# --------------------------------------------------
# Overall Correlation Score (dataset-wide, from correlation_analyzer.py)
# --------------------------------------------------
# correlation_analyzer.py computes exactly one Correlation Score for
# the entire dataset (see its "CORRELATION METRICS" section) and only
# writes it into correlation_report.txt - it does not emit a
# per-record column. So instead of waiting on that column, this reads
# the single dataset-wide value straight out of the report line:
#   "Correlation Score              : 62.00 %"
# and every record in this run is given that same value (see
# correlation_component() below). Returns None - not 0 - when the
# report is missing or the line can't be found, so callers can tell
# "no data yet" apart from "a genuine 0% correlation score".

CORRELATION_SCORE_PATTERN = re.compile(r"Correlation Score\s*:\s*([\d.]+)\s*%")

def get_overall_correlation_score(report_path):
    if not os.path.exists(report_path):
        return None

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return None

    match = CORRELATION_SCORE_PATTERN.search(content)
    if not match:
        return None

    try:
        return float(match.group(1))
    except ValueError:
        return None

# --------------------------------------------------
# Exposure Calculation Functions
# --------------------------------------------------

def ue_id_exposure(value):
    # Case-insensitive so real IDs / pseudonyms are recognized
    # regardless of how the source system cased them
    # (e.g. "imsi-...", "IMSI-...", "UE_001", "ue_001").
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("imsi"):
        return 30          # Original IMSI
    elif lowered.startswith("ue_"):
        return 5           # Pseudonym
    else:
        return 10

def suci_exposure(value):
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("suci_"):
        return 5           # Anonymized label, e.g. SUCI_001 / suci_001
    elif lowered.startswith("suci"):
        return 20          # Real SUCI, e.g. suci-0-999-... / SUCI-0-999-...
    else:
        return 10

def gnb_exposure(value):
    if value == "":
        return 0
    elif "xxx" in value.lower():
        return 3           # Masked IP
    else:
        return 15          # Real IP

def timestamp_exposure(value):
    if value == "":
        return 0
    elif value.lower().startswith("t+"):
        return 2           # Relative timestamp
    else:
        return 5           # Exact timestamp

def generic_exposure(value, weight):
    if value == "":
        return 0
    return weight

def dnn_exposure(value):
    # generic_exposure() only checks empty-vs-non-empty, so a
    # placeholder like "DEFAULT_DNN" would score identically to a
    # real APN name like "internet". Placeholders now score low
    # (same weight as any other anonymized pseudonym-style field)
    # and any other value is treated as real/identifying.
    if value == "":
        return 0
    elif value.upper() in DNN_PLACEHOLDER_VALUES:
        return 3
    else:
        return 10

def nssai_exposure(value):
    # Same fix as dnn_exposure(), for S_NSSAI.
    if value == "":
        return 0
    elif value.upper() in NSSAI_PLACEHOLDER_VALUES:
        return 3
    else:
        return 10

# --------------------------------------------------
# Overall Risk Score - Component Functions
# --------------------------------------------------

def behaviour_risk_component(ue_id, ue_id_counts):
    # RENAMED from repeated_registrations_component(). Same UE
    # reappearing across the dataset is a behavioural privacy
    # signal, not attack detection - each repeat beyond the first
    # adds points, capped at the weight ceiling.
    count = ue_id_counts.get(ue_id, 0)
    if count <= 1:
        return 0
    return min(RISK_WEIGHTS["Behaviour_Risk"], (count - 1) * 6)

def correlation_component(overall_correlation_score):
    # Applies correlation_analyzer.py's dataset-wide Correlation
    # Score (parsed from its report by get_overall_correlation_score()
    # below) as a GLOBAL context factor - the same value is added to
    # every record's Overall_Risk_Score in this run. It intentionally
    # does not differentiate between records: correlation_analyzer.py
    # only ever produces one score for the whole dataset, so this
    # component tells the Privacy module "this registration
    # environment has high/low linkability risk" rather than "this
    # specific record is more/less linkable than others".
    # Contributes 0 if the report is missing or unparseable.
    if overall_correlation_score is None:
        return 0

    score = max(0.0, min(overall_correlation_score, 100.0))

    return round((score / 100) * RISK_WEIGHTS["Behaviour_Correlation"], 2)

def failed_registrations_component(registration_status, authentication_result):

    reg = registration_status.strip().upper()
    auth = authentication_result.strip().upper()

    # Empty registration = failure
    reg_failed = (reg == "") or (reg not in SUCCESS_KEYWORDS)

    # Empty authentication = NOT a failure
    auth_failed = (auth != "") and (auth not in SUCCESS_KEYWORDS)

    if reg_failed or auth_failed:
        return RISK_WEIGHTS["Failed_Registrations"]

    return 0

def metadata_exposure_component(exposure_value):
    # Reuses the existing 0-100 Exposure score, scaled down to
    # its share of the overall Risk Score.
    return round(exposure_value * (RISK_WEIGHTS["Metadata_Exposure"] / 100), 2)

def attack_behaviour_component(attack_detected, severity, confidence_val, decision):
    # REPLACES the old attack_indicators_component() proxy (which
    # guessed at attacks from UE repeat-count + failure). Now that
    # privacy_dataset.csv carries the Systems team's own attack
    # verdict, this reads it directly instead of re-deriving it:
    #
    #   - No attack detected on this record -> contributes 0.
    #   - Otherwise, blend how severe the attack is (Severity,
    #     mapped 0-1 via SEVERITY_RANK) with how confident the
    #     detector was (Confidence, clamped 0-1), then scale by
    #     how strongly Systems acted on it (Decision: BLOCK hits
    #     hardest, TAG partially, ALLOW lightly).
    #   - Result is scaled into the same 15-point budget the old
    #     "Attack_Indicators" weight already used, so the overall
    #     0-100 scale of Overall_Risk_Score is unchanged.
    #
    # Risk_Score from attack.csv is deliberately not used here -
    # it is always 0 in the current dataset.

    if not attack_detected:
        return 0

    severity_ratio = SEVERITY_RANK.get(severity, 0) / 4

    confidence_clamped = max(0.0, min(confidence_val, 1.0))

    decision_multiplier = DECISION_MULTIPLIER.get(decision, 0.5)

    blended = (severity_ratio * 0.5 + confidence_clamped * 0.5) * decision_multiplier

    return round(blended * RISK_WEIGHTS["Attack_Indicators"], 2)

def risk_level_from_score(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    else:
        return "LOW"

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

scores = []

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)
    rows = list(reader)

# UE_ID repeat counts across the whole dataset - needed for the
# "Behaviour_Risk" component of Overall_Risk_Score.
ue_id_counts = Counter(field(row, "UE_ID") for row in rows)

# Dataset-wide Correlation Score from correlation_analyzer.py's
# report - computed once here (not per-row) since it is the same
# global value for every record in this run. None if the report
# hasn't been generated yet; correlation_component() treats that
# as "contribute 0" rather than erroring.
overall_correlation_score = get_overall_correlation_score(CORRELATION_REPORT_FILE)

for row in rows:

    exposure = 0

    exposure += ue_id_exposure(field(row, "UE_ID"))
    exposure += suci_exposure(field(row, "SUCI"))
    exposure += gnb_exposure(field(row, "gNB_IP"))
    exposure += timestamp_exposure(field(row, "Timestamp"))

    exposure += dnn_exposure(field(row, "DNN"))
    exposure += nssai_exposure(field(row, "S_NSSAI"))
    exposure += generic_exposure(field(row, "Authentication_Result"), 5)
    exposure += generic_exposure(field(row, "Registration_Status"), 5)

    privacy_score = max(0, 100 - exposure)

    # ----------------------------------------------
    # Privacy_Risk_Score - exposure only
    # ----------------------------------------------
    # Per the requested split: this is the pure "how identifying
    # is this record's metadata" score, with no behavioural
    # signals (repeats/failures/attack indicators) mixed in.
    # Those live in Overall_Risk_Score instead.

    privacy_risk_score = min(100, exposure)
    privacy_risk_level = risk_level_from_score(privacy_risk_score)

    # ----------------------------------------------
    # Attack Context Fields (NEW)
    # ----------------------------------------------
    # Read straight from privacy_dataset.csv - not recalculated.
    # Risk_Score is intentionally not read/used (always 0).

    attack_detected_raw = field(row, "Attack_Detected").upper()
    attack_detected = attack_detected_raw in {"TRUE", "1", "YES"}

    attack_type = field(row, "Attack_Type").upper() or "NONE"

    decision = field(row, "Decision").upper() or "UNKNOWN"

    severity = field(row, "Severity").upper() or "NONE"

    confidence_raw = field(row, "Confidence")
    try:
        confidence_val = float(confidence_raw) if confidence_raw else 0.0
    except ValueError:
        confidence_val = 0.0

    # ----------------------------------------------
    # Overall_Risk_Score (renamed from Risk_Score - now:
    # metadata exposure + behaviour risk + failed registrations
    # + behaviour correlation + attack behaviour)
    # ----------------------------------------------

    ue_id_stripped = field(row, "UE_ID")

    overall_risk_score = 0
    overall_risk_score += metadata_exposure_component(exposure)
    overall_risk_score += behaviour_risk_component(ue_id_stripped, ue_id_counts)
    overall_risk_score += failed_registrations_component(
        field(row, "Registration_Status"),
        field(row, "Authentication_Result")
    )
    overall_risk_score += correlation_component(overall_correlation_score)
    overall_risk_score += attack_behaviour_component(
        attack_detected,
        severity,
        confidence_val,
        decision
    )

    overall_risk_score = min(100, round(overall_risk_score, 2))
    overall_risk_level = risk_level_from_score(overall_risk_score)

    scores.append({
        "Timestamp": row.get("Timestamp", ""),
        "UE_ID": row.get("UE_ID", ""),
        "Exposure": exposure,
        "Privacy": privacy_score,
        "Privacy_Risk_Score": privacy_risk_score,
        "Privacy_Risk_Level": privacy_risk_level,
        "Overall_Risk_Score": overall_risk_score,
        "Overall_Risk_Level": overall_risk_level,
        "Attack_Detected": attack_detected,
        "Attack_Type": attack_type,
        "Decision": decision,
        "Severity": severity,
        "Confidence": confidence_val
    })

# --------------------------------------------------
# Statistics
# --------------------------------------------------

total_records = len(scores)

average_privacy = (
    sum(r["Privacy"] for r in scores)/total_records
    if total_records else 0
)

highest_exposure = max((r["Exposure"] for r in scores), default=0)
lowest_exposure = min((r["Exposure"] for r in scores), default=0)

average_privacy_risk_score = (
    sum(r["Privacy_Risk_Score"] for r in scores)/total_records
    if total_records else 0
)

highest_privacy_risk_score = max((r["Privacy_Risk_Score"] for r in scores), default=0)
lowest_privacy_risk_score = min((r["Privacy_Risk_Score"] for r in scores), default=0)

average_overall_risk_score = (
    sum(r["Overall_Risk_Score"] for r in scores)/total_records
    if total_records else 0
)

highest_overall_risk_score = max(r["Overall_Risk_Score"] for r in scores) if scores else 0
lowest_overall_risk_score = min(r["Overall_Risk_Score"] for r in scores) if scores else 0

# --------------------------------------------------
# Console Report
# --------------------------------------------------

print("\n========== Privacy Report ==========\n")

print(f"Total Records          : {total_records}")
print(f"Average Privacy Score  : {average_privacy:.2f}")
print(f"Highest Exposure Score : {highest_exposure}")
print(f"Lowest Exposure Score  : {lowest_exposure}")

print("\n========== Privacy Risk Score (Exposure Only) ==========\n")

print(f"Average Privacy Risk Score : {average_privacy_risk_score:.2f}")
print(f"Highest Privacy Risk Score : {highest_privacy_risk_score}")
print(f"Lowest Privacy Risk Score  : {lowest_privacy_risk_score}")

print("\n========== Overall Risk Score ==========\n")

print(f"Average Overall Risk Score : {average_overall_risk_score:.2f}")
print(f"Highest Overall Risk Score : {highest_overall_risk_score}")
print(f"Lowest Overall Risk Score  : {lowest_overall_risk_score}")

print("\nIndividual Records\n")

for i,record in enumerate(scores,1):

    print(
        f"Record {i}: "
        f"Exposure={record['Exposure']} "
        f"Privacy={record['Privacy']} "
        f"Privacy_Risk_Score={record['Privacy_Risk_Score']} "
        f"Privacy_Risk_Level={record['Privacy_Risk_Level']} "
        f"Overall_Risk_Score={record['Overall_Risk_Score']} "
        f"Overall_Risk_Level={record['Overall_Risk_Level']} "
        f"Attack_Detected={record['Attack_Detected']} "
        f"Attack_Type={record['Attack_Type']} "
        f"Decision={record['Decision']} "
        f"Severity={record['Severity']} "
        f"Confidence={record['Confidence']}"
    )

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(REPORT_FILE,"w",encoding="utf-8") as report:

    report.write("========== Privacy Report ==========\n\n")

    report.write(f"Total Records          : {total_records}\n")
    report.write(f"Average Privacy Score  : {average_privacy:.2f}\n")
    report.write(f"Highest Exposure Score : {highest_exposure}\n")
    report.write(f"Lowest Exposure Score  : {lowest_exposure}\n\n")

    report.write("========== Privacy Risk Score (Exposure Only) ==========\n\n")

    report.write(f"Average Privacy Risk Score : {average_privacy_risk_score:.2f}\n")
    report.write(f"Highest Privacy Risk Score : {highest_privacy_risk_score}\n")
    report.write(f"Lowest Privacy Risk Score  : {lowest_privacy_risk_score}\n\n")

    report.write("========== Overall Risk Score ==========\n\n")

    report.write(f"Average Overall Risk Score : {average_overall_risk_score:.2f}\n")
    report.write(f"Highest Overall Risk Score : {highest_overall_risk_score}\n")
    report.write(f"Lowest Overall Risk Score  : {lowest_overall_risk_score}\n\n")

    report.write("Individual Records\n\n")

    for i,record in enumerate(scores,1):

        report.write(
            f"Record {i}\n"
            f"Timestamp          : {record['Timestamp']}\n"
            f"UE_ID              : {record['UE_ID']}\n"
            f"Exposure           : {record['Exposure']}\n"
            f"Privacy            : {record['Privacy']}\n"
            f"Privacy_Risk_Score : {record['Privacy_Risk_Score']}\n"
            f"Privacy_Risk_Level : {record['Privacy_Risk_Level']}\n"
            f"Overall_Risk_Score : {record['Overall_Risk_Score']}\n"
            f"Overall_Risk_Level : {record['Overall_Risk_Level']}\n"
            f"Attack_Detected    : {record['Attack_Detected']}\n"
            f"Attack_Type        : {record['Attack_Type']}\n"
            f"Decision           : {record['Decision']}\n"
            f"Severity           : {record['Severity']}\n"
            f"Confidence         : {record['Confidence']}\n\n"
        )

print("\nReport saved successfully!")
print(REPORT_FILE)
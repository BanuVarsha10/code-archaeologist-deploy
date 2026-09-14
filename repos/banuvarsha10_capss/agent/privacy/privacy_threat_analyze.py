import os
import re
import csv

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)

os.makedirs(RESULTS_DIR, exist_ok=True)

PRIVACY_REPORT = os.path.join(
    RESULTS_DIR,
    "privacy_report.txt"
)

CORRELATION_REPORT = os.path.join(
    RESULTS_DIR,
    "correlation_report.txt"
)

# Combined registration + attack-detection dataset produced by
# the Systems team's pipeline. This file is OPTIONAL - if it
# isn't present, the script still runs; Section A/B/E note
# that the Systems team's data wasn't available rather than
# guessing.
#
# NOTE: If your dataset is saved under a different name/path,
# update this one line only - nothing else in the script
# depends on the filename.

ATTACK_REPORT = os.path.join(
    BASE_DIR,
    "..",
    "datasets",
    "privacy_test.csv"
)

OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "privacy_threat_report.txt"
)

# --------------------------------------------------
# ARCHITECTURE NOTE (Systems Team vs. Privacy Team)
# --------------------------------------------------
# This script previously duplicated attack detection: it
# re-derived "Registration Flood", "Brute Force
# Authentication", "Authentication Abuse", "Registration Retry
# Attack" and "Mobility Tracking Risk" locally from raw
# frequency/burst/failure signals in the correlation report,
# competing with the Systems team's own attack pipeline
# (attack_dataset CSV) instead of just consuming it.
#
# That local attack-behaviour detection has been removed. The
# Privacy Team's job here is now strictly:
#   1) Summarize what the Systems team's pipeline already
#      decided (Section A/B) - never re-classify it.
#   2) Assess genuine PRIVACY risk (identifiability,
#      linkability, tracking, inference) from privacy/exposure/
#      correlation signals (Section C) - never label these as
#      "attacks", since repeated identifiers are a privacy
#      exposure, not proof of malicious behaviour.
#   3) Recommend privacy protections, not security controls
#      like rate limiting (Section D).
#
# --------------------------------------------------
# CHANGE LOG (this revision)
# --------------------------------------------------
# Confidence for every privacy risk in Section C is now built
# the same two-step way code 1 (the pre-Systems-team-CSV
# script) builds all of its threat confidences:
#
#   1) A continuous 0-99 "severity" score from the actual
#      signals relevant to that risk (privacy/exposure/
#      correlation/location) - never a flat constant, never a
#      floor that clamps two different datasets to the same
#      number.
#   2) A single damp() step that discounts that severity based
#      on how confident we are this is more than coincidental
#      repetition - exactly like code 1's damp(), just driven
#      by system_behaviour (from the Systems team's CSV) instead
#      of code 1's locally-computed behaviour_classification,
#      since that local frequency/burst/failure analysis was
#      intentionally removed from this script (see architecture
#      note above) and system_behaviour is this script's
#      equivalent signal for "is this traffic actually
#      behaving like an attack".
#
# Previously, Identity Disclosure Risk, Membership Inference
# Risk and Location Correlation Risk each had their own
# hand-rolled floor (min 90 / min 60 / min location_score),
# which is exactly why two datasets with a meaningfully
# different Correlation Score (e.g. 10 unique UEs vs 20 unique
# UEs) could still land in the same confidence band - the
# floor was overriding the real difference in signal strength.
# Those floors are removed; every risk below now just computes
# its own continuous severity and passes it through damp(),
# same as code 1. Nothing else in the file (CSV parsing,
# Sections A/B/D/E, system_behaviour derivation itself) has
# changed.
#
# --------------------------------------------------
# Small Parsing Helpers
# --------------------------------------------------

def extract_float(label, text, default=0.0):

    match = re.search(
        re.escape(label) + r"\s*:\s*([0-9.]+)",
        text
    )

    if match:
        return float(match.group(1))

    return default


def extract_int(label, text, default=0):

    match = re.search(
        re.escape(label) + r"\s*:\s*([0-9]+)",
        text
    )

    if match:
        return int(match.group(1))

    return default


def extract_str(label, text, default="N/A"):

    match = re.search(
        re.escape(label) + r"\s*:\s*(.+)",
        text
    )

    if match:
        return match.group(1).strip()

    return default


def risk_word_to_score(word):

    mapping = {
        "LOW": 20,
        "MEDIUM": 50,
        "HIGH": 80,
        "VERY HIGH": 100
    }

    return mapping.get((word or "").strip().upper(), 0)


def risk_level_from_confidence(confidence):
    # Renamed from severity_from_confidence: these are PRIVACY
    # RISK LEVELS, not attack severities - the wording matters
    # so this report never implies "an attack was detected"
    # for something that is only a structural privacy risk.

    if confidence >= 90:
        return "CRITICAL"

    if confidence >= 70:
        return "HIGH"

    if confidence >= 40:
        return "MEDIUM"

    return "LOW"


# --------------------------------------------------
# Variables
# --------------------------------------------------

privacy_score = 0
exposure_score = 0

privacy_overall_risk_score = 0.0

correlation_score = 0

max_registrations = 0

repeated_ue = False
repeated_suci = False
repeated_gnb = False
repeated_dnn = False
repeated_slice = False

privacy_risks = []

# Recommendations are privacy-focused only. Rate limiting,
# throttling, lockouts etc. belong to the Systems team, not
# here.

RECOMMENDATIONS = {
    "Linkability Risk": "Increase pseudonym rotation frequency",
    "Subscriber Tracking Risk": "Reduce metadata retention window",
    "Behaviour Profiling Risk": "Reduce service metadata retention (DNN/S-NSSAI)",
    "Metadata Correlation Risk": "Minimize stored identifiers across sessions",
    "Metadata Inference Risk": "Minimize exposed/stored identifiers",
    "Identity Disclosure Risk": "Strengthen identifier concealment (SUCI use, encryption)",
    "Membership Inference Risk": "Limit repeated participation visibility, aggregate records",
    "Location Correlation Risk": "Shorten location history retention, generalize gNB records"
}

# --------------------------------------------------
# Read Privacy Report
# --------------------------------------------------

with open(PRIVACY_REPORT, "r", encoding="utf-8") as file:

    privacy_text = file.read()

match = re.search(
    r"Average Privacy Score\s*:\s*([0-9.]+)",
    privacy_text
)

if match:
    privacy_score = float(match.group(1))

match = re.search(
    r"Highest Exposure Score\s*:\s*([0-9.]+)",
    privacy_text
)

if match:
    exposure_score = float(match.group(1))

# --------------------------------------------------
# Read Privacy Report's Own Overall Risk Score
# --------------------------------------------------
# The privacy report computes its own "Average Overall Risk
# Score" (from exposure/privacy alone). It is read in here so
# it can be cross-checked against this script's own assessment
# further down.

match = re.search(
    r"Average Overall Risk Score\s*:\s*([0-9.]+)",
    privacy_text
)

if match:
    privacy_overall_risk_score = float(match.group(1))

# --------------------------------------------------
# Read Correlation Report
# --------------------------------------------------

with open(CORRELATION_REPORT, "r", encoding="utf-8") as file:

    correlation_text = file.read()

match = re.search(
    r"Correlation Score\s*:\s*([0-9.]+)",
    correlation_text
)

if match:
    correlation_score = float(match.group(1))

match = re.search(
    r"Maximum Registrations / UE\s*:\s*([0-9.]+)",
    correlation_text
)

if match:
    max_registrations = int(float(match.group(1)))

repeated_ue = (
    "Repeated UE IDs                : YES"
    in correlation_text
)

repeated_suci = (
    "Repeated SUCIs                 : YES"
    in correlation_text
)

repeated_gnb = (
    "Repeated gNB                   : YES"
    in correlation_text
)

repeated_dnn = (
    "Repeated DNN                   : YES"
    in correlation_text
)

repeated_slice = (
    "Repeated S-NSSAI               : YES"
    in correlation_text
)

# --------------------------------------------------
# Read Correlation Report (descriptive UE attribution only)
# --------------------------------------------------
# These fields are read purely to say WHICH UE a privacy risk
# is about ("Affected UE"). They are display attribution, not
# attack-detection inputs - frequency/burst/failure-based
# attack classification has been removed from this script
# entirely (see architecture note above).

most_bursty_ue = extract_str(
    "Most Bursty UE", correlation_text
)

lowest_success_rate_ue = extract_str(
    "Lowest Success Rate UE", correlation_text
)

# "Lowest Success Rate UE" is stored as e.g.
# "imsi-999700000000001 (100.0% success)" - keep just the UE.

match = re.search(
    r"Lowest Success Rate UE\s*:\s*(.+?)\s*\(",
    correlation_text
)

if match:
    lowest_success_rate_ue = match.group(1).strip()

most_mobile_ue = extract_str(
    "Most Mobile UE", correlation_text
)

max_unique_gnbs = extract_int(
    "Max Unique gNBs (single UE)", correlation_text
)

ues_with_repeated_location = extract_int(
    "UEs With Repeated Location", correlation_text
)

location_correlation_risk = extract_str(
    "Location Correlation Risk", correlation_text
)

# --------------------------------------------------
# Read Attack Detection Report (Systems Team Pipeline)
# --------------------------------------------------
# This is the SINGLE source of truth for attack behaviour in
# this report. The Privacy Team never re-derives or overrides
# it - Section A/B below only summarize/display it.
#
# Rows with a blank UE_ID (e.g. Attack_Type = INVALID_SUBSCRIBER,
# where the request never carried a valid UE identifier at all)
# get an explicit, visible placeholder (falling back to the
# SUCI when available) so a missing-UE_ID attack is never
# silently dropped from the report.

attack_records = []

if os.path.exists(ATTACK_REPORT):

    with open(ATTACK_REPORT, "r", encoding="utf-8", newline="") as file:

        reader = csv.DictReader(file)

        for row in reader:

            attack_detected_raw = str(row.get("Attack_Detected", "")).strip().upper()

            confidence_raw = row.get("Confidence", "")

            confidence_display = "N/A"
            confidence_value = None

            try:
                confidence_value = float(confidence_raw)

                # Accept confidence expressed either as a 0-1
                # fraction or as an already-scaled percentage.
                if confidence_value <= 1.0:
                    confidence_value *= 100.0

                confidence_display = f"{confidence_value:.0f}%"

            except (TypeError, ValueError):
                confidence_value = None

            raw_ue_id = str(row.get("UE_ID", "")).strip()

            if raw_ue_id:
                ue_id_display = raw_ue_id
            else:
                raw_suci = str(row.get("SUCI", "")).strip()

                if raw_suci:
                    ue_id_display = f"UNKNOWN UE (SUCI: {raw_suci})"
                else:
                    ue_id_display = "UNKNOWN UE (no UE_ID/SUCI in record)"

            attack_records.append({
                "ue_id": ue_id_display,
                "attack_detected": attack_detected_raw in ("TRUE", "YES", "1"),
                "attack_type": row.get("Attack_Type", "N/A"),
                "decision": str(row.get("Decision", "N/A")).strip(),
                "severity": row.get("Severity", "N/A"),
                "confidence_display": confidence_display,
                "confidence_value": confidence_value
            })

confirmed_attacks = [record for record in attack_records if record["attack_detected"]]

# --------------------------------------------------
# Attack Detection Statistics (Systems Team Pipeline)
# --------------------------------------------------

attack_type_counts = {}
decision_counts = {}

SEVERITY_RANK = {
    "LOW": 1,
    "SUSPICIOUS": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "MALICIOUS": 4,
    "VERY HIGH": 4
}

highest_severity = "N/A"
highest_severity_rank = 0
attack_confidence_values = []

for record in confirmed_attacks:

    attack_type_counts[record["attack_type"]] = (
        attack_type_counts.get(record["attack_type"], 0) + 1
    )

    decision_counts[record["decision"]] = (
        decision_counts.get(record["decision"], 0) + 1
    )

    if record["confidence_value"] is not None:
        attack_confidence_values.append(record["confidence_value"])

    rank = SEVERITY_RANK.get(str(record["severity"]).strip().upper(), 0)

    if rank > highest_severity_rank:
        highest_severity_rank = rank
        highest_severity = record["severity"]

average_attack_confidence = (
    sum(attack_confidence_values) / len(attack_confidence_values)
    if attack_confidence_values else 0.0
)

# --------------------------------------------------
# System Behaviour Summary (Derived FROM the Attack Pipeline)
# --------------------------------------------------
# Replaces the old locally-computed frequency/burst-based
# "Registration Behaviour Classification". Behaviour is now
# purely a summary of what the Systems team's pipeline already
# decided per record (Decision/Severity), never a second,
# competing classification computed here from raw signals.

system_behaviour_reasons = []
_seen_reason_keys = set()

for record in confirmed_attacks:

    key = (record["attack_type"], record["decision"], record["severity"])

    if key not in _seen_reason_keys:
        _seen_reason_keys.add(key)
        system_behaviour_reasons.append(
            f"{record['attack_type']} detected "
            f"(Decision: {record['decision']}, Severity: {record['severity']})"
        )

if not os.path.exists(ATTACK_REPORT):

    system_behaviour = "UNKNOWN"
    system_behaviour_reasons.append(
        "Attack dataset not found; behaviour cannot be determined "
        "from Systems Team output."
    )

elif len(confirmed_attacks) == 0:

    system_behaviour = "NORMAL"
    system_behaviour_reasons.append(
        "No attacks detected in the attack pipeline output."
    )

elif any(record["decision"].strip().upper() == "BLOCK" for record in confirmed_attacks):

    system_behaviour = "MALICIOUS"

else:

    system_behaviour = "SUSPICIOUS"

# --------------------------------------------------
# Privacy-Risk Damping (mirrors code 1's damp()) — NEW
# --------------------------------------------------
# Code 1 never let a structural privacy risk (repeated
# identifiers, high correlation, etc.) claim full "attack-
# level" confidence unless there was actual behavioural
# evidence backing it up - it multiplied every threat's
# continuous severity score by a tier-based factor
# (0.40 / 0.70 / 1.00) keyed off its own locally-computed
# behaviour_classification, then re-floored/re-ceiled the
# result.
#
# This script no longer computes behaviour locally (see
# architecture note above) - system_behaviour, sourced from
# the Systems team's CSV, is this script's equivalent signal
# for "does the traffic actually look like an attack". So the
# same damping mechanism is applied here, keyed off
# system_behaviour instead. UNKNOWN (no CSV available) is
# treated the same as SUSPICIOUS - i.e. neither confirmed
# nor ruled out - rather than silently defaulting to full or
# zero confidence.
#
# NOTE: the specific multiplier values are carried over
# unchanged from code 1's BEHAVIOUR_MULTIPLIER - a documented
# design choice, not a value derived from the reports.

BEHAVIOUR_MULTIPLIER = {
    "NORMAL": 0.40,
    "SUSPICIOUS": 0.70,
    "MALICIOUS": 1.00,
    "UNKNOWN": 0.70
}

privacy_risk_multiplier = BEHAVIOUR_MULTIPLIER[system_behaviour]


def damp(confidence):
    # Same shape as code 1's damp(): applies the behaviour-
    # tier multiplier and re-floors/re-ceils the result so a
    # privacy risk built purely from repeated identifiers
    # cannot claim attack-level confidence without the
    # Systems team's pipeline actually backing it up.
    return max(1, min(99, int(confidence * privacy_risk_multiplier)))

# --------------------------------------------------
# Privacy Evidence Confidence Engine
# --------------------------------------------------
# Confidence for genuine PRIVACY risks depends only on privacy
# signals - Privacy Score, Exposure Score, Correlation Score,
# and location-repetition risk. It intentionally no longer
# folds in registration frequency, burst pattern, or auth
# failure rate: those are attack-behaviour signals and are the
# Systems team's job to weigh, not this script's. This
# continuous score is the pre-damp "severity" - damp() above
# is applied at each usage site below, same two-step pattern
# as code 1.
#
# NOTE: weights (40/30/20/10) are a documented design choice,
# not a value taken from the reports.

def compute_privacy_confidence():

    location_score = risk_word_to_score(location_correlation_risk)

    confidence = (
        (correlation_score * 0.40) +
        ((100.0 - privacy_score) * 0.30) +
        (exposure_score * 0.20) +
        (location_score * 0.10)
    )

    return min(99, int(confidence))


privacy_confidence = compute_privacy_confidence()


def compute_identity_disclosure_confidence():
    # Continuous pre-damp severity (no floor - see change log
    # above). Exposure/privacy severity dominates (that's what
    # actually defines "identity disclosure"), with
    # correlation_score as a secondary amplifier: the easier
    # records are to link together, the more confidently a
    # disclosed identifier can be tied back to a specific
    # subscriber. damp() is applied at the usage site below.

    base = (
        (exposure_score * 0.40) +
        ((100.0 - privacy_score) * 0.35) +
        (correlation_score * 0.25)
    )

    return min(99, int(base))


def compute_membership_inference_confidence():
    # Continuous pre-damp severity (no floor - see change log
    # above), so a dataset sitting just over the
    # correlation_score>=60 / privacy_score<50 trigger reads
    # differently from one deep into HIGH correlation
    # territory. damp() is applied at the usage site below.

    base = (
        (correlation_score * 0.55) +
        ((100.0 - privacy_score) * 0.45)
    )

    return min(99, int(base))


def compute_location_correlation_confidence():
    # Continuous pre-damp severity (no floor - see change log
    # above): the location word still dominates (that's what
    # actually triggers this risk), with correlation_score and
    # privacy_score as secondary factors, same pattern as every
    # other risk in this file. damp() is applied at the usage
    # site below.

    location_score = risk_word_to_score(location_correlation_risk)

    base = (
        (location_score * 0.50) +
        (correlation_score * 0.30) +
        ((100.0 - privacy_score) * 0.20)
    )

    return min(99, int(base))


# --------------------------------------------------
# Privacy Risk Detection
# --------------------------------------------------
# Genuine, structural PRIVACY risks only - identifiability,
# linkability, tracking, and inference concerns that follow
# from repeated identifiers and exposed metadata. These are
# risks regardless of whether traffic behaviour looks like an
# attack, so they carry a Risk Level (LOW/MEDIUM/HIGH/CRITICAL),
# never an attack verdict. Every risk below now computes its
# own continuous severity, then applies damp() - same two-step
# pattern as code 1 - instead of using an un-damped score or a
# hand-rolled floor.

# ==================================================
# Linkability Risk
# ==================================================

if correlation_score >= 70 and (
    repeated_ue or repeated_suci
):

    confidence = damp(privacy_confidence)

    privacy_risks.append({

        "name": "Linkability Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": most_bursty_ue if most_bursty_ue != "N/A" else lowest_success_rate_ue,

        "reason": [

            f"Correlation Score = {correlation_score:.2f}%",

            f"Same UE observed {max_registrations} times",

            "Persistent UE/SUCI pseudonyms enable record linkage"

        ],

        "evidence": [

            f"Repeated UE IDs = {repeated_ue}, Repeated SUCIs = {repeated_suci}"

        ]
    })

# ==================================================
# Subscriber Tracking Risk
# ==================================================

if correlation_score >= 70 and (
    repeated_ue and repeated_gnb
):

    confidence = damp(privacy_confidence)

    privacy_risks.append({

        "name": "Subscriber Tracking Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": most_mobile_ue,

        "reason": [

            "Repeated UE registrations detected",

            "Same gNB reused repeatedly",

            "Historical movement/session tracking is possible"

        ],

        "evidence": [

            f"Max Unique gNBs (single UE) = {max_unique_gnbs}",

            f"UEs With Repeated Location = {ues_with_repeated_location}",

            f"Location Correlation Risk = {location_correlation_risk}"

        ]
    })

# ==================================================
# Behaviour Profiling Risk
# ==================================================

if correlation_score >= 70 and (
    repeated_dnn or repeated_slice
):

    confidence = damp(privacy_confidence)

    privacy_risks.append({

        "name": "Behaviour Profiling Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": most_bursty_ue if most_bursty_ue != "N/A" else "N/A",

        "reason": [

            "Repeated service usage detected",

            "Repeated S-NSSAI / DNN usage",

            "Long-term behavioural patterns can be inferred"

        ],

        "evidence": [

            f"Repeated DNN = {repeated_dnn}, Repeated S-NSSAI = {repeated_slice}"

        ]
    })

# ==================================================
# Metadata Correlation Risk
# ==================================================

if correlation_score >= 80:

    confidence = damp(privacy_confidence)

    privacy_risks.append({

        "name": "Metadata Correlation Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": "Dataset-wide",

        "reason": [

            f"Correlation Score = {correlation_score:.2f}%",

            "Multiple metadata fields remain correlated",

            "Cross-session linkage is possible"

        ],

        "evidence": [

            f"Repeated UE/SUCI/gNB/DNN/S-NSSAI = "
            f"{repeated_ue}/{repeated_suci}/{repeated_gnb}/{repeated_dnn}/{repeated_slice}"

        ]
    })

# ==================================================
# Metadata Inference Risk
# ==================================================

if exposure_score >= 70:

    confidence = damp(privacy_confidence)

    privacy_risks.append({

        "name": "Metadata Inference Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": "Dataset-wide",

        "reason": [

            f"Exposure Score = {exposure_score:.2f}",

            f"Privacy Score = {privacy_score:.2f}",

            "Sensitive metadata remains visible"

        ],

        "evidence": [

            f"Privacy evidence confidence (pre-damp) = {privacy_confidence}%"

        ]
    })

# ==================================================
# Identity Disclosure Risk
# ==================================================

if exposure_score >= 85 and privacy_score <= 20:

    confidence = damp(compute_identity_disclosure_confidence())

    privacy_risks.append({

        "name": "Identity Disclosure Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": "Dataset-wide",

        "reason": [

            "Privacy score is critically low",

            "Identifiers are highly exposed",

            "Subscriber identity disclosure is possible"

        ],

        "evidence": [

            f"Privacy Score = {privacy_score:.2f}, Exposure Score = {exposure_score:.2f}",

            f"Correlation Score = {correlation_score:.2f}%"

        ]
    })

# ==================================================
# Membership Inference Risk
# ==================================================

if correlation_score >= 60 and privacy_score < 50:

    confidence = damp(compute_membership_inference_confidence())

    privacy_risks.append({

        "name": "Membership Inference Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": "Dataset-wide",

        "reason": [

            "Repeated participation detected",

            "Correlation remains high",

            "Presence of a subscriber may be inferred"

        ],

        "evidence": [

            f"Correlation Score = {correlation_score:.2f}%, Privacy Score = {privacy_score:.2f}"

        ]
    })

# ==================================================
# Location Correlation Risk
# ==================================================

if location_correlation_risk in ("MEDIUM", "HIGH", "VERY HIGH") and ues_with_repeated_location > 0:

    confidence = damp(compute_location_correlation_confidence())

    privacy_risks.append({

        "name": "Location Correlation Risk",

        "confidence": confidence,

        "risk_level": risk_level_from_confidence(confidence),

        "affected_ue": most_mobile_ue,

        "reason": [

            f"Location Correlation Risk = {location_correlation_risk}",

            f"UEs With Repeated Location = {ues_with_repeated_location}",

            "Repeated registrations from the same gNB reveal a fixed approximate location"

        ],

        "evidence": [

            f"Max Unique gNBs (single UE) = {max_unique_gnbs}"

        ]
    })

# --------------------------------------------------
# Overall Risk Assessment
# --------------------------------------------------

if privacy_score >= 60:

    if correlation_score >= 80:
        overall_risk = "MEDIUM"

    elif correlation_score >= 50:
        overall_risk = "LOW"

    else:
        overall_risk = "LOW"

elif privacy_score >= 40:

    if correlation_score >= 80:
        overall_risk = "HIGH"

    elif correlation_score >= 50:
        overall_risk = "MEDIUM"

    else:
        overall_risk = "MEDIUM"

else:

    if correlation_score >= 80:
        overall_risk = "VERY HIGH"

    elif correlation_score >= 50:
        overall_risk = "HIGH"

    else:
        overall_risk = "HIGH"

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "VERY HIGH"]

# Overall risk can be escalated (never de-escalated) by what
# the Systems team's pipeline found - this is the "optionally
# include Attack Severity" step: using their verdict, not
# re-deriving one.

if system_behaviour == "MALICIOUS":

    current_index = RISK_ORDER.index(overall_risk)
    overall_risk = RISK_ORDER[min(current_index + 1, len(RISK_ORDER) - 1)]

# --------------------------------------------------
# Cross-Check Against Privacy Report's Own Overall Risk
# --------------------------------------------------
# The privacy report computes its own "Average Overall Risk
# Score" independently (from exposure/privacy alone). It is
# converted to the same LOW/MEDIUM/HIGH/VERY HIGH scale using
# the same 40/60/80 cutoffs already used elsewhere in this
# pipeline, and is only ever allowed to escalate - never
# de-escalate - this script's overall_risk.

def score_to_risk_level(score):

    if score >= 80:
        return "VERY HIGH"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


privacy_report_risk_level = score_to_risk_level(privacy_overall_risk_score)

current_index = RISK_ORDER.index(overall_risk)
privacy_report_index = RISK_ORDER.index(privacy_report_risk_level)

overall_risk = RISK_ORDER[max(current_index, privacy_report_index)]

# --------------------------------------------------
# Sort Privacy Risks by Confidence
# --------------------------------------------------

privacy_risks.sort(
    key=lambda risk: risk["confidence"],
    reverse=True
)

# --------------------------------------------------
# Build Report
# --------------------------------------------------

report = []

report.append("=========================================================")
report.append("        CAPSS PRIVACY THREAT ASSESSMENT")
report.append("=========================================================\n")

report.append(f"Overall Privacy Risk : {overall_risk}\n")


def render_privacy_risk_block(report, index, risk):

    report.append("---------------------------------------------------------")

    report.append(f"Privacy Risk {index}\n")

    report.append(
        f"Risk Name : {risk['name']}\n"
    )

    report.append(
        f"Confidence : {risk['confidence']}%"
    )

    report.append(
        f"Risk Level : {risk['risk_level']}"
    )

    report.append(
        f"Affected UE : {risk['affected_ue']}\n"
    )

    report.append("Reason")

    for reason in risk["reason"]:

        report.append(f" • {reason}")

    report.append("\nEvidence")

    for evidence_line in risk["evidence"]:

        report.append(f" • {evidence_line}")

    report.append(
        f"\nRecommendation : {RECOMMENDATIONS.get(risk['name'], 'Review and monitor')}"
    )

    report.append("")


# --------------------------------------------------
# SECTION A — System Behaviour Summary (Systems Team Pipeline)
# --------------------------------------------------
# A direct summary of what the Systems team's pipeline
# already decided. Never a second, competing classification.

report.append("---------------------------------------------------------")
report.append("SECTION A — SYSTEM BEHAVIOUR SUMMARY")
report.append("(Derived directly from the Systems team's attack pipeline)")
report.append("---------------------------------------------------------\n")

report.append(f"Behaviour : {system_behaviour}\n")

report.append("Reason")

for reason in system_behaviour_reasons:
    report.append(f" • {reason}")

report.append("")

if decision_counts:

    report.append("Decision Breakdown")

    for decision, count in sorted(
        decision_counts.items(), key=lambda kv: kv[1], reverse=True
    ):
        report.append(f" • {decision} : {count}")

    report.append("")

# --------------------------------------------------
# SECTION B — Confirmed Attacks (from Systems Team)
# --------------------------------------------------

report.append("---------------------------------------------------------")
report.append("SECTION B — CONFIRMED ATTACKS (from Systems Team)")
report.append("---------------------------------------------------------\n")

if not os.path.exists(ATTACK_REPORT):

    report.append(
        f"Attack dataset not found at {ATTACK_REPORT}; "
        "skipping confirmed-attacks section.\n"
    )

elif len(confirmed_attacks) == 0:

    report.append("No attacks detected in the attack pipeline output.\n")

else:

    for record in confirmed_attacks:

        report.append(f"UE ID           : {record['ue_id']}")
        report.append(f"Confirmed Attack : {record['attack_type']}")
        report.append(f"Decision        : {record['decision']}")
        report.append(f"Severity        : {record['severity']}")
        report.append(f"Confidence      : {record['confidence_display']}")
        report.append("")

# --------------------------------------------------
# SECTION C — Privacy Risks
# --------------------------------------------------

report.append("---------------------------------------------------------")
report.append("SECTION C — PRIVACY RISKS")
report.append("(Structural exposure from repeated/exposed identifiers;")
report.append(" these are privacy risks, not attack verdicts)")
report.append("---------------------------------------------------------\n")

if len(privacy_risks) == 0:

    report.append("No significant privacy risks detected.\n")

else:

    for index, risk in enumerate(privacy_risks, start=1):
        render_privacy_risk_block(report, index, risk)

# --------------------------------------------------
# SECTION D — Privacy Recommendations
# --------------------------------------------------

report.append("---------------------------------------------------------")
report.append("SECTION D — PRIVACY RECOMMENDATIONS")
report.append("---------------------------------------------------------\n")

if len(privacy_risks) == 0:

    report.append("No privacy-specific recommendations at this time.\n")

else:

    seen_recommendations = []

    for risk in privacy_risks:

        recommendation = RECOMMENDATIONS.get(risk["name"], "Review and monitor")

        if recommendation not in seen_recommendations:
            seen_recommendations.append(recommendation)

    for recommendation in seen_recommendations:
        report.append(f" • {recommendation}")

    report.append("")

# --------------------------------------------------
# SECTION E — Attack Statistics (Systems Team Pipeline)
# --------------------------------------------------

report.append("---------------------------------------------------------")
report.append("SECTION E — ATTACK STATISTICS")
report.append("---------------------------------------------------------\n")

if not os.path.exists(ATTACK_REPORT):

    report.append("Attack dataset not found; no statistics available.\n")

elif len(confirmed_attacks) == 0:

    report.append("No attack statistics available.\n")

else:

    report.append(f"Total Attacks Detected : {len(confirmed_attacks)}\n")

    report.append("By Attack Type")

    for attack_type, count in sorted(
        attack_type_counts.items(), key=lambda kv: kv[1], reverse=True
    ):
        report.append(f" • {attack_type} : {count}")

    report.append("")

    report.append("By Decision")

    for decision, count in sorted(
        decision_counts.items(), key=lambda kv: kv[1], reverse=True
    ):
        report.append(f" • {decision} : {count}")

    report.append("")

    report.append(f"Average Confidence : {average_attack_confidence:.1f}%")
    report.append(f"Highest Severity   : {highest_severity}\n")

# --------------------------------------------------
# Console Output
# --------------------------------------------------

print()

for line in report:

    print(line)

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    for line in report:

        file.write(line + "\n")

# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\n=========================================================")
print("Privacy Threat Report Generated Successfully")
print("=========================================================")

print(f"\nOutput File : {OUTPUT_FILE}")

print(f"\nOverall Risk       : {overall_risk}")
print(f"System Behaviour    : {system_behaviour}")

print(f"\nConfirmed Attacks (Systems Team) : {len(confirmed_attacks)}")

if len(confirmed_attacks) > 0:

    print("------------------------------")

    for record in confirmed_attacks:

        print(
            f"• {record['ue_id']} — {record['attack_type']} "
            f"({record['decision']}, {record['severity']}, "
            f"{record['confidence_display']})"
        )

    print("------------------------------")

print(f"\nPrivacy Risks Identified : {len(privacy_risks)}")

if len(privacy_risks) > 0:

    print("------------------------------")

    for risk in privacy_risks:

        print(f"• {risk['name']} ({risk['confidence']}%, {risk['risk_level']})")

    print("------------------------------")

print("\nAssessment Complete.\n")
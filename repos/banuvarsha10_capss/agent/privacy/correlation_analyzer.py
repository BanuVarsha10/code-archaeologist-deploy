import os
import csv
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FILE = os.path.join(
    BASE_DIR,
    "..",
    "datasets",
    "privacy_test.csv"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)

os.makedirs(RESULTS_DIR, exist_ok=True)

REPORT_FILE = os.path.join(
    RESULTS_DIR,
    "correlation_report.txt"
)

# --------------------------------------------------
# Optional Column Names (adjust here if your CSV uses
# different header names for these fields)
# --------------------------------------------------

REGISTRATION_RESULT_COLUMN = "Registration_Status"
AUTH_RESULT_COLUMN = "Authentication_Result"

FAILURE_KEYWORDS = {"FAIL", "FAILURE", "FAILED", "REJECT", "REJECTED", "DENIED"}
SUCCESS_KEYWORDS = {"SUCCESS", "SUCCESSFUL", "ACCEPT", "ACCEPTED", "OK"}

# --------------------------------------------------
# Variables
# --------------------------------------------------

ue_ids = []
suci_ids = []

gnb_ips = []
dnns = []
snssais = []

timestamps = []

contains_real_identifier = False

# --------------------------------------------------
# True Row Count (NEW)
# --------------------------------------------------
# total_records (further below) is len(ue_ids), which only
# counts rows where UE_ID was non-blank - a row like an
# orphaned INVALID_SUBSCRIBER event (blank UE_ID) is
# silently excluded from it. total_dataset_rows counts
# EVERY row read from the CSV, regardless of whether UE_ID
# was populated, so the report can show the true sample
# size alongside the UE-specific one instead of the two
# being conflated under one number.

total_dataset_rows = 0

# --------------------------------------------------
# Per-UE tracking structures (NEW)
# --------------------------------------------------

ue_timestamps = defaultdict(list)      # UE_ID -> list of datetime objects
ue_reg_failures = Counter()            # UE_ID -> count of failed registrations
ue_auth_failures = Counter()           # UE_ID -> count of failed authentications
ue_auth_successes = Counter()          # UE_ID -> count of successful authentications

ue_gnb_history = defaultdict(list)     # UE_ID -> chronological list of gNB IPs (NEW)
ue_auth_sequence = defaultdict(list)   # UE_ID -> chronological list of "FAIL"/"SUCCESS"/"UNKNOWN" (NEW)
ue_timeline = defaultdict(list)        # UE_ID -> chronological list of event dicts (NEW)

# --------------------------------------------------
# Security Context tracking structures (NEW)
# Populated from the Attack_Detected / Attack_Type / Decision /
# Severity / Confidence columns that privacy1.csv carries in
# from the Systems team's attack dataset.
# --------------------------------------------------

attack_detected_flags = []             # list of bool, one per record
attack_type_counter = Counter()        # Attack_Type -> count (excludes NONE)
ue_security_events = defaultdict(list) # UE_ID -> list of security event dicts
orphaned_security_events = []          # NEW - security events where UE_ID was blank

SEVERITY_RANK = {
    "NONE": 0,
    "NORMAL": 0,
    "LOW": 1,
    "SUSPICIOUS": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        total_dataset_rows += 1

        # ------------------------------------------
        # UE ID
        # ------------------------------------------

        ue = row["UE_ID"].strip()

        if ue:

            ue_ids.append(ue)

            if ue.startswith("imsi-"):
                contains_real_identifier = True

        # ------------------------------------------
        # SUCI
        # ------------------------------------------

        suci = row["SUCI"].strip()

        if suci:

            suci_ids.append(suci)

            if suci.startswith("suci-"):
                contains_real_identifier = True

        # ------------------------------------------
        # gNB
        # ------------------------------------------

        gnb = row["gNB_IP"].strip()

        if gnb:
            gnb_ips.append(gnb)

        # ------------------------------------------
        # DNN
        # ------------------------------------------

        dnn = row["DNN"].strip()

        if dnn:
            dnns.append(dnn)

        # ------------------------------------------
        # S-NSSAI
        # ------------------------------------------

        snssai = row["S_NSSAI"].strip()

        if snssai:
            snssais.append(snssai)

        # ------------------------------------------
        # Timestamp
        # ------------------------------------------

        timestamp = row["Timestamp"].strip()

        parsed_timestamp = None

        if timestamp:

            try:

                parsed_timestamp = datetime.strptime(
                    timestamp,
                    "%m/%d %H:%M:%S.%f"
                )

                timestamps.append(parsed_timestamp)

            except:
                pass

        # ------------------------------------------
        # Per-UE Timestamp Tracking (NEW)
        # ------------------------------------------

        if ue and parsed_timestamp:
            ue_timestamps[ue].append(parsed_timestamp)

        # ------------------------------------------
        # Previous Failures / Auth History (NEW)
        # ------------------------------------------
        # If the Auth_Result field is missing or blank for
        # a record, it is treated as a success (no failure
        # was reported for it).

        reg_result = row.get(REGISTRATION_RESULT_COLUMN, "")
        reg_result = reg_result.strip().upper() if reg_result else ""

        auth_result = row.get(AUTH_RESULT_COLUMN, "")
        auth_result = auth_result.strip().upper() if auth_result else ""

        if not auth_result:
            auth_result = "SUCCESS"

        if ue:

            if reg_result in FAILURE_KEYWORDS:
                ue_reg_failures[ue] += 1

            if auth_result in FAILURE_KEYWORDS:
                ue_auth_failures[ue] += 1
            elif auth_result in SUCCESS_KEYWORDS:
                ue_auth_successes[ue] += 1

        # ------------------------------------------
        # Location History (NEW)
        # ------------------------------------------

        if ue and gnb:
            ue_gnb_history[ue].append(gnb)

        # ------------------------------------------
        # Failure Sequence Tracking (NEW)
        # ------------------------------------------
        # Preserves the chronological order of
        # authentication outcomes per UE, e.g.
        # FAIL -> SUCCESS -> FAIL

        if ue:

            if auth_result in FAILURE_KEYWORDS:
                ue_auth_sequence[ue].append("FAIL")
            elif auth_result in SUCCESS_KEYWORDS:
                ue_auth_sequence[ue].append("SUCCESS")
            else:
                ue_auth_sequence[ue].append("UNKNOWN")

        # ------------------------------------------
        # Behaviour Timeline (NEW)
        # ------------------------------------------
        # Stores every event per UE in chronological
        # order (as encountered in the dataset) so the
        # full sequence of behaviour can be reviewed.

        # ------------------------------------------
        # Security Context Fields (NEW)
        # ------------------------------------------
        # Pulled straight from privacy1.csv's merged attack
        # columns. Not recalculated - just read and reported.

        request_id = row.get("Request_ID", "").strip() if row.get("Request_ID") else "N/A"

        attack_detected_raw = row.get("Attack_Detected", "")
        attack_detected_raw = attack_detected_raw.strip().upper() if attack_detected_raw else ""
        attack_detected = attack_detected_raw in {"TRUE", "1", "YES"}

        attack_type = row.get("Attack_Type", "")
        attack_type = attack_type.strip().upper() if attack_type else "NONE"
        if not attack_type:
            attack_type = "NONE"

        decision = row.get("Decision", "")
        decision = decision.strip().upper() if decision else "UNKNOWN"

        severity = row.get("Severity", "")
        severity = severity.strip().upper() if severity else "NONE"

        confidence_raw = row.get("Confidence", "")
        try:
            confidence_val = float(confidence_raw) if confidence_raw else 0.0
        except ValueError:
            confidence_val = 0.0

        attack_detected_flags.append(attack_detected)

        if attack_type != "NONE":
            attack_type_counter[attack_type] += 1

        if ue:

            ue_security_events[ue].append({
                "attack_detected": attack_detected,
                "attack_type": attack_type,
                "decision": decision,
                "severity": severity,
                "confidence": confidence_val,
            })

        else:

            orphaned_security_events.append({
                "request_id": request_id,
                "attack_detected": attack_detected,
                "attack_type": attack_type,
                "decision": decision,
                "severity": severity,
                "confidence": confidence_val,
                "suci": suci,
            })

        if ue:

            ue_timeline[ue].append({
                "timestamp": parsed_timestamp if parsed_timestamp else timestamp,
                "gnb": gnb,
                "dnn": dnn,
                "snssai": snssai,
                "reg_result": reg_result if reg_result else "N/A",
                "auth_result": auth_result if auth_result else "N/A",
                "request_id": request_id,          # NEW
                "attack_type": attack_type,         # NEW
                "decision": decision,                # NEW
                "severity": severity,                # NEW
                "confidence": confidence_val,        # NEW
            })

# --------------------------------------------------
# Counters
# --------------------------------------------------

ue_counter = Counter(ue_ids)

suci_counter = Counter(suci_ids)

gnb_counter = Counter(gnb_ips)

dnn_counter = Counter(dnns)

snssai_counter = Counter(snssais)

# --------------------------------------------------
# Dataset Statistics
# --------------------------------------------------

total_records = len(ue_ids)

unique_ue = len(ue_counter)

unique_suci = len(suci_counter)

unique_gnb = len(gnb_counter)

unique_dnn = len(dnn_counter)

unique_snssai = len(snssai_counter)

repeated_ue = sum(
    1
    for count in ue_counter.values()
    if count > 1
)

repeated_suci = sum(
    1
    for count in suci_counter.values()
    if count > 1
)

repeated_gnb = sum(
    1
    for count in gnb_counter.values()
    if count > 1
)

repeated_dnn = sum(
    1
    for count in dnn_counter.values()
    if count > 1
)

repeated_snssai = sum(
    1
    for count in snssai_counter.values()
    if count > 1
)

# --------------------------------------------------
# Registration Statistics
# --------------------------------------------------

if unique_ue > 0:

    average_registrations = (
        total_records / unique_ue
    )

    max_registrations = max(
        ue_counter.values()
    )

    most_active_ue = (
        ue_counter.most_common(1)[0][0]
    )

else:

    average_registrations = 0

    max_registrations = 0

    most_active_ue = "N/A"

if unique_suci > 0:

    most_active_suci = (
        suci_counter.most_common(1)[0][0]
    )

else:

    most_active_suci = "N/A"

# --------------------------------------------------
# Registration Duration
# --------------------------------------------------

if len(timestamps) >= 2:

    registration_duration = (
        max(timestamps) - min(timestamps)
    ).total_seconds()

else:

    registration_duration = 0

# --------------------------------------------------
# Average / Min / Max Registration Interval (NEW)
# --------------------------------------------------
# Per-UE average interval = time span of that UE's
# registrations divided by number of gaps between them.
# Min/Max capture the tightest and widest gaps observed,
# which highlights bursts and long dormant periods.
# This is data-driven (based on actual timestamps), not
# a fixed constant.

ue_avg_intervals = {}
ue_min_intervals = {}
ue_max_intervals = {}

all_gaps = []

for ue, ts_list in ue_timestamps.items():

    if len(ts_list) >= 2:

        ts_sorted = sorted(ts_list)

        gaps = [
            (ts_sorted[i] - ts_sorted[i - 1]).total_seconds()
            for i in range(1, len(ts_sorted))
        ]

        if gaps:

            ue_avg_intervals[ue] = sum(gaps) / len(gaps)

            ue_min_intervals[ue] = min(gaps)

            ue_max_intervals[ue] = max(gaps)

            all_gaps.extend(gaps)

# Global baseline interval: the average gap we'd expect
# if registrations were spread evenly across the full
# observation window.

if total_records >= 2 and registration_duration > 0:
    global_avg_interval = registration_duration / (total_records - 1)
else:
    global_avg_interval = 0

# Dataset-wide average of per-UE average intervals
# (only over UEs that registered more than once).

if ue_avg_intervals:
    average_registration_interval = statistics.mean(ue_avg_intervals.values())
else:
    average_registration_interval = 0

# Dataset-wide min/max interval, taken across every
# consecutive gap observed for every UE (NEW).

if all_gaps:
    dataset_min_interval = min(all_gaps)
    dataset_max_interval = max(all_gaps)
else:
    dataset_min_interval = 0
    dataset_max_interval = 0

# --------------------------------------------------
# Burst Registration Detection (NEW - data-driven)
# --------------------------------------------------
# Instead of a fixed time threshold (e.g. "3 minutes"),
# a UE is flagged as "bursty" if its own average
# registration interval is unusually small compared to
# the overall pattern seen across UEs in this dataset.
#
# Method:
#   - If we have enough UEs with repeat registrations,
#     compute the mean and standard deviation of their
#     average intervals, and flag any UE whose interval
#     falls more than 1 standard deviation below the mean.
#   - If there isn't enough data to compute a meaningful
#     standard deviation, fall back to comparing each UE's
#     interval against the global baseline interval
#     (flagging it if it is at least 5x denser).

burst_ues = []

interval_values = list(ue_avg_intervals.values())

if len(interval_values) >= 2:

    mean_interval = statistics.mean(interval_values)

    stdev_interval = statistics.pstdev(interval_values)

    burst_threshold = max(mean_interval - stdev_interval, 0)

    for ue, avg_interval in ue_avg_intervals.items():

        if stdev_interval > 0 and avg_interval < burst_threshold:
            burst_ues.append(ue)

elif len(interval_values) == 1 and global_avg_interval > 0:

    for ue, avg_interval in ue_avg_intervals.items():

        if avg_interval < (global_avg_interval / 5):
            burst_ues.append(ue)

burst_detected = len(burst_ues) > 0

burst_ue_count = len(burst_ues)

most_bursty_ue = "N/A"

if burst_ues:

    most_bursty_ue = min(
        burst_ues,
        key=lambda u: ue_avg_intervals[u]
    )

# --------------------------------------------------
# Previous Failures / Authentication History Summary (NEW)
# --------------------------------------------------

total_reg_failures = sum(ue_reg_failures.values())

ues_with_reg_failures = len(ue_reg_failures)

most_failed_ue = "N/A"

if ue_reg_failures:
    most_failed_ue = ue_reg_failures.most_common(1)[0][0]

total_auth_failures = sum(ue_auth_failures.values())

total_auth_successes = sum(ue_auth_successes.values())

ues_with_auth_failures = len(ue_auth_failures)

most_auth_failed_ue = "N/A"

if ue_auth_failures:
    most_auth_failed_ue = ue_auth_failures.most_common(1)[0][0]

# --------------------------------------------------
# Success Rate per UE (NEW)
# --------------------------------------------------

ue_success_rate = {}

for ue in set(list(ue_auth_successes.keys()) + list(ue_auth_failures.keys())):

    successes = ue_auth_successes.get(ue, 0)

    failures = ue_auth_failures.get(ue, 0)

    attempts = successes + failures

    if attempts > 0:
        ue_success_rate[ue] = (successes / attempts) * 100

lowest_success_rate_ue = "N/A"

lowest_success_rate_value = None

if ue_success_rate:

    lowest_success_rate_ue = min(ue_success_rate, key=ue_success_rate.get)

    lowest_success_rate_value = ue_success_rate[lowest_success_rate_ue]

# --------------------------------------------------
# Failure Sequence per UE (NEW)
# --------------------------------------------------
# Only recorded for UEs that experienced at least one
# authentication failure, showing the order in which
# failures and successes occurred.

ue_failure_sequences = {}

for ue, sequence in ue_auth_sequence.items():

    if "FAIL" in sequence:
        ue_failure_sequences[ue] = " -> ".join(sequence)

# --------------------------------------------------
# Location History (gNB history per UE) (NEW)
# --------------------------------------------------

ue_unique_gnb_count = {}

ue_repeated_location = {}

for ue, gnb_list in ue_gnb_history.items():

    per_ue_gnb_counter = Counter(gnb_list)

    ue_unique_gnb_count[ue] = len(per_ue_gnb_counter)

    ue_repeated_location[ue] = any(
        count > 1 for count in per_ue_gnb_counter.values()
    )

most_mobile_ue = "N/A"

if ue_unique_gnb_count:
    most_mobile_ue = max(ue_unique_gnb_count, key=ue_unique_gnb_count.get)

max_unique_gnb_per_ue = (
    max(ue_unique_gnb_count.values()) if ue_unique_gnb_count else 0
)

ues_with_repeated_location = sum(
    1 for reused in ue_repeated_location.values() if reused
)

# --------------------------------------------------
# Dataset-Aware Identifier Metrics (NEW)
# --------------------------------------------------
# The original scoring used flat Boolean flags ("was ANY
# value repeated at all?"), which cannot distinguish:
#   - a dataset with 10 UEs where 2 are repeated (20%)
#     from one where 8 are repeated (80%) - both score
#     identically as "Repeated UE = YES"
#   - a dataset with 10 UEs from one with 500 UEs, if both
#     happen to have at least one repeat
#
# Every identifier field (UE, SUCI, gNB, DNN, S-NSSAI) is
# now scored with several complementary, continuous,
# dataset-driven metrics instead of a single YES/NO flag:
#
#   diversity_ratio            = unique / total
#                                 (how much of the field is
#                                 distinct values at all)
#
#   record_repetition_ratio    = 1 - diversity_ratio
#                                 (fraction of RECORDS that
#                                 are "extra" reuses of a
#                                 value already seen)
#
#   distinct_repetition_ratio  = repeated_distinct_count /
#                                 unique
#                                 (fraction of DISTINCT
#                                 values that show reuse at
#                                 all - directly answers
#                                 "2 repeated out of 10 UEs
#                                 = 20%")
#
#   entropy / normalized_entropy / concentration
#                                 = Shannon-entropy-based
#                                 measurement of how evenly
#                                 reuse is spread across
#                                 values (low entropy = reuse
#                                 concentrated on very few
#                                 values = more dangerous)
#
#   linkability_index          = blended 0-1 score
#                                 (average of
#                                 record_repetition_ratio and
#                                 concentration) used to
#                                 weight this field in the
#                                 Correlation Score below,
#                                 replacing the previous
#                                 "boolean * fixed points"
#                                 approach with
#                                 "ratio * fixed points".
#
# The original repeated_ue / repeated_suci / ... counts and
# the YES/NO display flags derived from them are still
# computed exactly as before, further down, purely for
# backward-compatible reporting.


def shannon_entropy(counter, total):
    """Shannon entropy (in bits) of the value distribution."""

    if total <= 0:
        return 0.0

    entropy = 0.0

    for count in counter.values():

        p = count / total

        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def identifier_metrics(counter, total):
    """
    Returns a dict of dataset-aware linkability metrics for
    one identifier field (UE, SUCI, gNB, DNN, S-NSSAI, ...).
    """

    unique_count = len(counter)

    repeated_distinct_count = sum(
        1 for count in counter.values() if count > 1
    )

    if total <= 0 or unique_count == 0:

        return {
            "total": total,
            "unique": unique_count,
            "repeated_distinct_count": repeated_distinct_count,
            "diversity_ratio": 0.0,
            "record_repetition_ratio": 0.0,
            "distinct_repetition_ratio": 0.0,
            "entropy": 0.0,
            "normalized_entropy": 0.0,
            "concentration": 0.0,
            "linkability_index": 0.0,
        }

    diversity_ratio = unique_count / total

    record_repetition_ratio = 1 - diversity_ratio

    distinct_repetition_ratio = (
        repeated_distinct_count / unique_count if unique_count > 0 else 0.0
    )

    entropy = shannon_entropy(counter, total)

    if unique_count > 1:
        max_entropy = math.log2(unique_count)
        normalized_entropy = (entropy / max_entropy) if max_entropy > 0 else 0.0
    else:
        # A single distinct value across every record is the
        # maximum possible concentration (normalized entropy 0).
        normalized_entropy = 0.0

    concentration = 1 - normalized_entropy

    # Linkability index blends "how much reuse exists at the
    # record level" with "how concentrated that reuse is" -
    # both matter, since heavy-but-spread-out reuse is less
    # dangerous than reuse concentrated on a few identities.
    linkability_index = (record_repetition_ratio + concentration) / 2

    return {
        "total": total,
        "unique": unique_count,
        "repeated_distinct_count": repeated_distinct_count,
        "diversity_ratio": diversity_ratio,
        "record_repetition_ratio": record_repetition_ratio,
        "distinct_repetition_ratio": distinct_repetition_ratio,
        "entropy": entropy,
        "normalized_entropy": normalized_entropy,
        "concentration": concentration,
        "linkability_index": linkability_index,
    }


ue_metrics = identifier_metrics(ue_counter, total_records)
suci_metrics = identifier_metrics(suci_counter, len(suci_ids))
gnb_metrics = identifier_metrics(gnb_counter, len(gnb_ips))
dnn_metrics = identifier_metrics(dnn_counter, len(dnns))
snssai_metrics = identifier_metrics(snssai_counter, len(snssais))

# --------------------------------------------------
# UE Registration Distribution Inequality (NEW)
# --------------------------------------------------
# Average registrations/UE alone cannot tell these two
# datasets apart:
#   Dataset A: UE1=90, UE2=1, UE3=1        (avg ~30.7)
#   Dataset B: UE1=30, UE2=30, UE3=31      (avg ~30.3)
# Both have a similar average, but A concentrates almost
# all activity on a single UE (much higher tracking risk)
# while B spreads it evenly. The Gini coefficient of the
# per-UE registration-count distribution captures this:
# 0 = perfectly equal activity across UEs, 1 = maximally
# unequal (all activity on one UE).


def gini_coefficient(values):
    """
    Gini coefficient of a list of non-negative values.
    0 = perfect equality, 1 = maximal inequality.
    """

    values = sorted(v for v in values if v is not None)

    n = len(values)

    total = sum(values)

    if n == 0 or total == 0:
        return 0.0

    weighted_sum = sum((i + 1) * v for i, v in enumerate(values))

    return (2 * weighted_sum) / (n * total) - (n + 1) / n


ue_registration_gini = gini_coefficient(list(ue_counter.values()))

# --------------------------------------------------
# Correlation Factors
# --------------------------------------------------

factor_score = 0.0
factor_count = 0.0

# -----------------------------
# UE Reuse (weight 25) - NOW RATIO-BASED
# -----------------------------
# Was: "if repeated_ue > 0: +25 else +0" (boolean).
# Now: linkability_index (0.0-1.0) * 25, so a dataset with
# a 20% distinct-repetition ratio no longer scores the same
# as one with an 80% distinct-repetition ratio.

factor_score += ue_metrics["linkability_index"] * 25
factor_count += 25

# -----------------------------
# SUCI Reuse (weight 20) - NOW RATIO-BASED
# -----------------------------

factor_score += suci_metrics["linkability_index"] * 20
factor_count += 20

# -----------------------------
# gNB Reuse (weight 15) - NOW RATIO-BASED
# -----------------------------

factor_score += gnb_metrics["linkability_index"] * 15
factor_count += 15

# -----------------------------
# DNN Reuse (weight 10) - NOW RATIO-BASED
# -----------------------------

factor_score += dnn_metrics["linkability_index"] * 10
factor_count += 10

# -----------------------------
# S-NSSAI Reuse (weight 10) - NOW RATIO-BASED
# -----------------------------

factor_score += snssai_metrics["linkability_index"] * 10
factor_count += 10

# -----------------------------
# Dataset Scale / Subscriber Volume (weight 15)
# -----------------------------
# Fixes: "correlation score is identical for 10 UEs and 20
# UEs". Every ratio-based factor above is still normalized
# by dataset size (a ratio), so two datasets that differ
# ONLY in how many UEs were observed (same ratios) could
# still tie. This factor scores the raw number of unique
# UEs seen in THIS dataset on a smooth, ever-increasing
# curve, so the score always shifts as UE count changes.
#
# Formula: unique_ue / (unique_ue + K)
#   - Strictly increasing in unique_ue: 10 UEs and 20 UEs
#     will never land on the same value.
#   - Bounded between 0 and 1.
#   - K is a smoothing constant (not a pass/fail threshold):
#     it sets how quickly the curve climbs. K = 10 means a
#     10-UE dataset sits at the curve's midpoint (0.50);
#     20 UEs -> 0.67; 50 UEs -> 0.83; 100 UEs -> 0.91.

DATASET_SCALE_SMOOTHING_CONSTANT = 10

if unique_ue > 0:
    dataset_scale_ratio = unique_ue / (unique_ue + DATASET_SCALE_SMOOTHING_CONSTANT)
else:
    dataset_scale_ratio = 0.0

factor_score += dataset_scale_ratio * 15
factor_count += 15

# -----------------------------
# UE Registration Distribution Inequality (weight 10)
# -----------------------------
# Fixes: average-registrations-per-UE cannot distinguish
# "one UE dominates the traffic" from "activity is spread
# evenly" when the averages happen to match. The Gini
# coefficient computed above captures exactly this.

factor_score += ue_registration_gini * 10
factor_count += 10

# -----------------------------
# Registration Frequency
# -----------------------------

if average_registrations >= 20:
    factor_score += 10
elif average_registrations >= 10:
    factor_score += 7
elif average_registrations >= 5:
    factor_score += 5

factor_count += 10

# -----------------------------
# Long Observation Window
# -----------------------------

if registration_duration >= 3600:
    factor_score += 10
elif registration_duration >= 600:
    factor_score += 5

factor_count += 10

# -----------------------------
# NOTE ON SCORING METHODOLOGY
# -----------------------------
# Correlation Score measures how easily registration
# records can be linked via persistent metadata (UE ID,
# SUCI, gNB, DNN, S-NSSAI, registration frequency, and
# observation window), now weighted by:
#   - per-field linkability_index (repetition ratio blended
#     with entropy-based concentration) instead of a flat
#     Boolean "was there any repeat?" flag,
#   - a dataset-scale factor so datasets that differ only in
#     UE count never tie,
#   - a Gini-coefficient factor so datasets that differ only
#     in how evenly registrations are spread across UEs
#     never tie.
# Nothing below this point is added to
# factor_score / factor_count.
#
# Burst registration, previous failures, authentication
# history, and location history are behavioural / anomaly
# indicators, not metadata-linkability indicators, so they
# are intentionally excluded from the correlation score.
# They are still fully computed and reported below (see
# the BURST REGISTRATION ANALYSIS, FAILURE / AUTHENTICATION
# HISTORY, and LOCATION HISTORY sections of the report) —
# just not folded into this score.

max_ue_reg_failures = max(ue_reg_failures.values()) if ue_reg_failures else 0

max_ue_auth_failures = max(ue_auth_failures.values()) if ue_auth_failures else 0

# --------------------------------------------------
# Final Correlation Score
# --------------------------------------------------

correlation_score = (
    factor_score / factor_count
) * 100 if factor_count else 0.0

# --------------------------------------------------
# Correlation Risk Level
# --------------------------------------------------

if correlation_score >= 80:

    correlation_level = "VERY HIGH"

elif correlation_score >= 60:

    correlation_level = "HIGH"

elif correlation_score >= 40:

    correlation_level = "MEDIUM"

else:

    correlation_level = "LOW"

# --------------------------------------------------
# Individual Risk Levels
# --------------------------------------------------
# These remain threshold-based indicators for quick triage,
# but the thresholds are now applied to the continuous
# linkability_index / ratio values instead of plain repeat
# counts, so they still reflect dataset size and
# concentration rather than a bare "any repeat" flag.

linkability_risk = "LOW"

tracking_risk = "LOW"

profiling_risk = "LOW"

metadata_correlation_risk = "LOW"

# Linkability (UE + SUCI combined linkability index)

combined_id_linkability = (
    ue_metrics["linkability_index"] + suci_metrics["linkability_index"]
) / 2

if combined_id_linkability >= 0.6:

    linkability_risk = "HIGH"

elif combined_id_linkability >= 0.3:

    linkability_risk = "MEDIUM"

# Tracking (average registrations + distribution inequality)

if average_registrations >= 20 or ue_registration_gini >= 0.6:

    tracking_risk = "HIGH"

elif average_registrations >= 5 or ue_registration_gini >= 0.3:

    tracking_risk = "MEDIUM"

# Profiling (DNN + S-NSSAI combined linkability index)

combined_profiling_linkability = (
    dnn_metrics["linkability_index"] + snssai_metrics["linkability_index"]
) / 2

if combined_profiling_linkability >= 0.6:

    profiling_risk = "HIGH"

elif combined_profiling_linkability >= 0.3:

    profiling_risk = "MEDIUM"

# Profiling - enhanced with location diversity (NEW)

if max_unique_gnb_per_ue >= 5 and profiling_risk != "HIGH":

    profiling_risk = "HIGH"

elif max_unique_gnb_per_ue >= 2 and profiling_risk == "LOW":

    profiling_risk = "MEDIUM"

# Metadata Correlation (gNB linkability index)

if gnb_metrics["linkability_index"] >= 0.6:

    metadata_correlation_risk = "HIGH"

elif gnb_metrics["linkability_index"] >= 0.3:

    metadata_correlation_risk = "MEDIUM"

# Location Correlation Risk (NEW)

location_correlation_risk = "LOW"

if ues_with_repeated_location > 0 and max_unique_gnb_per_ue >= 5:

    location_correlation_risk = "HIGH"

elif ues_with_repeated_location > 0 or max_unique_gnb_per_ue >= 2:

    location_correlation_risk = "MEDIUM"

# --------------------------------------------------
# Correlation Factors (display flags - kept exactly as in
# the original for backward-compatible reporting; these no
# longer drive the score directly - see linkability_index,
# dataset_scale_ratio and ue_registration_gini above)
# --------------------------------------------------

ue_factor = "YES" if repeated_ue > 0 else "NO"

suci_factor = "YES" if repeated_suci > 0 else "NO"

gnb_factor = "YES" if repeated_gnb > 0 else "NO"

dnn_factor = "YES" if repeated_dnn > 0 else "NO"

snssai_factor = "YES" if repeated_snssai > 0 else "NO"

history_factor = (
    "YES"
    if average_registrations > 1
    else "NO"
)

burst_factor = "YES" if burst_detected else "NO"

previous_failures_factor = "YES" if max_ue_reg_failures > 0 else "NO"

auth_history_factor = "YES" if max_ue_auth_failures > 0 else "NO"

location_history_factor = (
    "YES"
    if (max_unique_gnb_per_ue >= 2 or ues_with_repeated_location > 0)
    else "NO"
)

if correlation_score >= 90:

    confidence = 99

elif correlation_score >= 80:

    confidence = 95

elif correlation_score >= 60:

    confidence = 90

else:

    confidence = 75

# --------------------------------------------------
# Sample-Size-Adjusted Confidence (NEW - additional metric)
# --------------------------------------------------
# The Correlation Confidence above is a fixed lookup table
# keyed only off the score itself, with no statistical
# grounding. This does NOT replace it (kept exactly as-is
# above for backward compatibility) - it adds a second,
# complementary confidence measurement based on how many
# registration records the score was actually computed
# from: more observations -> more statistical confidence
# that the measured ratios reflect the true underlying
# pattern, independent of what the score itself came out to.
#
# Formula: 1 - 1/sqrt(n+1), scaled to a percentage and
# capped at 99%. Grows quickly for small n and flattens out
# for large n, without ever needing a fixed sample-size
# threshold.

if total_dataset_rows > 0:
    sample_size_confidence = min(99.0, (1 - 1 / math.sqrt(total_dataset_rows + 1)) * 100)
else:
    sample_size_confidence = 0.0

# --------------------------------------------------
# Security Context Analysis (NEW - item 2)
# --------------------------------------------------

total_security_events = len(attack_detected_flags)

attack_count = sum(1 for flag in attack_detected_flags if flag)

attack_rate = (
    (attack_count / total_security_events) * 100
    if total_security_events > 0 else 0.0
)

unique_attack_types = len(attack_type_counter)

most_common_attack = "N/A"

if attack_type_counter:
    most_common_attack = attack_type_counter.most_common(1)[0][0]

# --------------------------------------------------
# Active Attack Type Breakdown (NEW)
# --------------------------------------------------
# attack_type_counter is built from EVERY row in the dataset,
# including rows where UE_ID was blank (e.g. an orphaned
# INVALID_SUBSCRIBER event). That means an attack type like
# INVALID_SUBSCRIBER was already folded into
# unique_attack_types / most_common_attack above - it just
# had no visible line of its own in the report, so it looked
# "missing" even though it wasn't. This gives every attack
# type - including ones tied to a missing UE_ID - its own
# explicit line, count, and share of total requests.

attack_type_breakdown_lines = []

for atype, count in attack_type_counter.most_common():

    pct = (
        (count / total_security_events) * 100
        if total_security_events > 0 else 0.0
    )

    attack_type_breakdown_lines.append(
        f"  {atype:<20} : {count} event(s)  ({pct:.2f} % of all requests)"
    )

attack_type_breakdown_text = (
    "\n".join(attack_type_breakdown_lines)
    if attack_type_breakdown_lines
    else "  No attacks detected."
)

# --------------------------------------------------
# Per-UE Security Breakdown (NEW - item 3)
# --------------------------------------------------

ue_security_summary = {}

for ue, events in ue_security_events.items():

    total_requests = len(events)

    attack_events = sum(1 for e in events if e["attack_detected"])

    ue_attack_types = sorted(
        {e["attack_type"] for e in events if e["attack_type"] != "NONE"}
    )

    highest_severity = "NONE"

    if events:
        highest_severity = max(
            (e["severity"] for e in events),
            key=lambda s: SEVERITY_RANK.get(s, 0)
        )

    confidences = [e["confidence"] for e in events]

    average_confidence = (
        sum(confidences) / len(confidences) if confidences else 0.0
    )

    ue_security_summary[ue] = {
        "total_requests": total_requests,
        "attack_events": attack_events,
        "attack_types": ue_attack_types,
        "highest_severity": highest_severity,
        "average_confidence": average_confidence,
    }

# --------------------------------------------------
# Interpretation
# --------------------------------------------------

if contains_real_identifier:

    interpretation = (
        "Direct subscriber identifiers are present in the dataset.\n"
        "Repeated IMSI and SUCI values enable strong correlation\n"
        "between multiple registration sessions. The dataset exhibits\n"
        "a high probability of long-term subscriber linkability,\n"
        "tracking and behavioural profiling. Metadata minimization\n"
        "is strongly recommended before analytics sharing."
    )

else:

    interpretation = (
        "Direct identifiers have been pseudonymized through metadata\n"
        "minimization. Historical registrations remain linkable only\n"
        "through persistent pseudonyms, allowing CAPSS to retrieve\n"
        "previous privacy experiences while reducing subscriber\n"
        "identity disclosure."
    )
# --------------------------------------------------
# Build Report
# --------------------------------------------------

report = f"""
=========================================================
        CAPSS CORRELATION ANALYSIS REPORT
=========================================================

DATASET INFORMATION
---------------------------------------------------------
Total Rows In Dataset          : {total_dataset_rows}

Total Registration Records     : {total_records} (rows with a non-blank UE_ID)

Unique UE IDs                  : {unique_ue}

Unique SUCIs                   : {unique_suci}

Unique gNB IPs                 : {unique_gnb}

Unique DNNs                    : {unique_dnn}

Unique S-NSSAIs                : {unique_snssai}

---------------------------------------------------------

SECURITY CONTEXT ANALYSIS (NEW)
---------------------------------------------------------
Sourced directly from the Systems team's attack context
merged into privacy1.csv (Attack_Detected, Attack_Type,
Decision, Severity, Confidence). Not recalculated here.

Total Security Events          : {total_security_events}

Attack Detected Requests       : {attack_count}

Attack Detection Rate          : {attack_rate:.2f} %

Unique Attack Types            : {unique_attack_types}

Most Common Attack             : {most_common_attack}

Active Attack Type Breakdown (NEW):
{attack_type_breakdown_text}

Note: this breakdown counts EVERY request tagged with an
attack type, whether or not it had a UE_ID - so an attack
like INVALID_SUBSCRIBER (typically raised on requests with
a missing/blank UE_ID) is always listed here even though it
is excluded from the per-UE breakdown further below.

---------------------------------------------------------

REGISTRATION STATISTICS
---------------------------------------------------------
Average Registrations / UE     : {average_registrations:.2f}

Maximum Registrations / UE     : {max_registrations}

Most Active UE                 : {most_active_ue}

Most Active SUCI               : {most_active_suci}

Registration Duration (sec)    : {registration_duration:.2f}

Average Registration Interval  : {average_registration_interval:.2f} sec (per UE, avg)

Minimum Registration Interval  : {dataset_min_interval:.2f} sec (dataset-wide)

Maximum Registration Interval  : {dataset_max_interval:.2f} sec (dataset-wide)

Global Baseline Interval       : {global_avg_interval:.2f} sec (dataset-wide expected)

---------------------------------------------------------

UE REGISTRATION DISTRIBUTION (GINI COEFFICIENT) (NEW)
---------------------------------------------------------
This catches cases the average alone misses: e.g. one UE
with 90 registrations vs. two UEs with 1 each can have the
same average as three UEs with ~30 each, but very different
concentration of tracking risk.

UE Registration Gini Coeff.    : {ue_registration_gini:.3f} (0 = evenly spread, 1 = concentrated on one UE)

Contribution to Score          : {ue_registration_gini * 10:.2f} / 10 points

---------------------------------------------------------

IDENTIFIER DIVERSITY, REPETITION & ENTROPY METRICS (NEW)
---------------------------------------------------------
Replaces plain YES/NO repeat flags with continuous,
dataset-size-aware metrics used to weight the Correlation
Score, so results are comparable across datasets of
different sizes and reuse intensity.

Diversity Ratio            = unique / total (how much of
                              the field is distinct values)
Record Repetition Ratio     = 1 - Diversity Ratio (fraction
                              of RECORDS reusing a prior
                              value)
Distinct Repetition Ratio   = (# distinct values that
                              repeat) / unique (fraction of
                              DISTINCT VALUES that show
                              reuse at all, e.g. "2 out of
                              10 UEs repeated = 20%")
Entropy / Norm. Entropy     = Shannon entropy of the value
                              distribution, normalized 0-1
                              against the theoretical
                              maximum for this many unique
                              values (1 = perfectly even,
                              0 = fully concentrated)
Concentration               = 1 - Norm. Entropy
Linkability Index           = (Record Repetition Ratio +
                              Concentration) / 2 -> the 0-1
                              score actually used to weight
                              this field in the Correlation
                              Score

UE_ID:
  Total={ue_metrics['total']}  Unique={ue_metrics['unique']}  Repeated Distinct Values={ue_metrics['repeated_distinct_count']}
  Diversity Ratio={ue_metrics['diversity_ratio']:.3f}  Record Repetition Ratio={ue_metrics['record_repetition_ratio']:.3f}
  Distinct Repetition Ratio={ue_metrics['distinct_repetition_ratio']:.3f}  Entropy={ue_metrics['entropy']:.3f} bits
  Norm. Entropy={ue_metrics['normalized_entropy']:.3f}  Concentration={ue_metrics['concentration']:.3f}
  Linkability Index={ue_metrics['linkability_index']:.3f}

SUCI:
  Total={suci_metrics['total']}  Unique={suci_metrics['unique']}  Repeated Distinct Values={suci_metrics['repeated_distinct_count']}
  Diversity Ratio={suci_metrics['diversity_ratio']:.3f}  Record Repetition Ratio={suci_metrics['record_repetition_ratio']:.3f}
  Distinct Repetition Ratio={suci_metrics['distinct_repetition_ratio']:.3f}  Entropy={suci_metrics['entropy']:.3f} bits
  Norm. Entropy={suci_metrics['normalized_entropy']:.3f}  Concentration={suci_metrics['concentration']:.3f}
  Linkability Index={suci_metrics['linkability_index']:.3f}

gNB_IP:
  Total={gnb_metrics['total']}  Unique={gnb_metrics['unique']}  Repeated Distinct Values={gnb_metrics['repeated_distinct_count']}
  Diversity Ratio={gnb_metrics['diversity_ratio']:.3f}  Record Repetition Ratio={gnb_metrics['record_repetition_ratio']:.3f}
  Distinct Repetition Ratio={gnb_metrics['distinct_repetition_ratio']:.3f}  Entropy={gnb_metrics['entropy']:.3f} bits
  Norm. Entropy={gnb_metrics['normalized_entropy']:.3f}  Concentration={gnb_metrics['concentration']:.3f}
  Linkability Index={gnb_metrics['linkability_index']:.3f}

DNN:
  Total={dnn_metrics['total']}  Unique={dnn_metrics['unique']}  Repeated Distinct Values={dnn_metrics['repeated_distinct_count']}
  Diversity Ratio={dnn_metrics['diversity_ratio']:.3f}  Record Repetition Ratio={dnn_metrics['record_repetition_ratio']:.3f}
  Distinct Repetition Ratio={dnn_metrics['distinct_repetition_ratio']:.3f}  Entropy={dnn_metrics['entropy']:.3f} bits
  Norm. Entropy={dnn_metrics['normalized_entropy']:.3f}  Concentration={dnn_metrics['concentration']:.3f}
  Linkability Index={dnn_metrics['linkability_index']:.3f}

S_NSSAI:
  Total={snssai_metrics['total']}  Unique={snssai_metrics['unique']}  Repeated Distinct Values={snssai_metrics['repeated_distinct_count']}
  Diversity Ratio={snssai_metrics['diversity_ratio']:.3f}  Record Repetition Ratio={snssai_metrics['record_repetition_ratio']:.3f}
  Distinct Repetition Ratio={snssai_metrics['distinct_repetition_ratio']:.3f}  Entropy={snssai_metrics['entropy']:.3f} bits
  Norm. Entropy={snssai_metrics['normalized_entropy']:.3f}  Concentration={snssai_metrics['concentration']:.3f}
  Linkability Index={snssai_metrics['linkability_index']:.3f}

---------------------------------------------------------

DATASET SCALE FACTOR (NEW)
---------------------------------------------------------
Unique UEs Observed            : {unique_ue}

Dataset Scale Ratio            : {dataset_scale_ratio:.3f} (0-1, rises with unique_ue count)

Scale Contribution to Score    : {dataset_scale_ratio * 15:.2f} / 15 points

Note: this ratio is strictly increasing in the number of
unique UEs observed, so two datasets that differ only in
UE count (e.g. 10 vs 20 UEs) will always produce different
Correlation Scores, even if every ratio-based factor above
is identical between them.

---------------------------------------------------------

BURST REGISTRATION ANALYSIS
---------------------------------------------------------
Burst Registration Detected    : {burst_factor}

Number of Bursty UEs           : {burst_ue_count}

Most Bursty UE                 : {most_bursty_ue}

---------------------------------------------------------

FAILURE / AUTHENTICATION HISTORY
---------------------------------------------------------
Total Registration Failures    : {total_reg_failures}

UEs With Registration Failures : {ues_with_reg_failures}

Most Failed UE                 : {most_failed_ue}

Total Auth Failures            : {total_auth_failures}

Total Auth Successes           : {total_auth_successes}

UEs With Auth Failures         : {ues_with_auth_failures}

Most Auth-Failed UE            : {most_auth_failed_ue}

Lowest Success Rate UE         : {lowest_success_rate_ue}"""

if lowest_success_rate_value is not None:
    report += f" ({lowest_success_rate_value:.1f}% success)"

report += """

---------------------------------------------------------

PER-UE FAILURE / AUTH BREAKDOWN
---------------------------------------------------------
"""

if ue_reg_failures or ue_auth_failures:

    all_flagged_ues = set(
        list(ue_reg_failures.keys()) + list(ue_auth_failures.keys())
    )

    for ue in sorted(all_flagged_ues):

        reg_fail_count = ue_reg_failures.get(ue, 0)

        auth_fail_count = ue_auth_failures.get(ue, 0)

        success_rate = ue_success_rate.get(ue)

        rate_text = (
            f"{success_rate:.1f}%" if success_rate is not None else "N/A"
        )

        report += (
            f"{ue}: Reg Failures={reg_fail_count}, "
            f"Auth Failures={auth_fail_count}, "
            f"Success Rate={rate_text}\n"
        )

else:

    report += "No registration or authentication failures recorded.\n"

report += """
---------------------------------------------------------

PER-UE SECURITY BREAKDOWN (NEW)
---------------------------------------------------------
"""

if ue_security_summary:

    for ue in sorted(ue_security_summary.keys()):

        summary = ue_security_summary[ue]

        attack_types_text = (
            ", ".join(summary["attack_types"])
            if summary["attack_types"] else "None"
        )

        report += (
            f"{ue}:\n"
            f"  Total Requests       : {summary['total_requests']}\n"
            f"  Attack Events        : {summary['attack_events']}\n"
            f"  Attack Types         : {attack_types_text}\n"
            f"  Highest Severity     : {summary['highest_severity']}\n"
            f"  Average Confidence   : {summary['average_confidence']:.2f}\n\n"
        )

else:

    report += "No security context available for any UE.\n"

report += """
---------------------------------------------------------

SECURITY EVENTS WITH NO UE_ID (NEW)
---------------------------------------------------------
Requests where UE_ID was blank are excluded from the
per-UE breakdown above (there is no UE to key them by),
but a missing UE_ID combined with a detected attack is
itself a meaningful signal (e.g. Attack_Type=INVALID_SUBSCRIBER)
and should not be silently dropped from the report.
"""

if orphaned_security_events:

    for event in orphaned_security_events:

        report += (
            f"[{event['request_id']}] "
            f"Attack Detected={event['attack_detected']}  "
            f"Attack Type={event['attack_type']}  "
            f"Decision={event['decision']}  "
            f"Severity={event['severity']}  "
            f"Confidence={event['confidence']:.2f}  "
            f"SUCI={event['suci'] or 'N/A'}\n"
        )

else:

    report += "No security events with a missing UE_ID were found.\n"

report += """
---------------------------------------------------------

FAILURE SEQUENCES (Chronological)
---------------------------------------------------------
"""

if ue_failure_sequences:

    for ue, sequence in ue_failure_sequences.items():

        report += f"{ue}: {sequence}\n"

else:

    report += "No UE experienced an authentication failure.\n"

report += f"""
---------------------------------------------------------

LOCATION HISTORY (gNB PER UE)
---------------------------------------------------------
Most Mobile UE                 : {most_mobile_ue}

Max Unique gNBs (single UE)    : {max_unique_gnb_per_ue}

UEs With Repeated Location     : {ues_with_repeated_location}

Location Correlation Risk      : {location_correlation_risk}

---------------------------------------------------------

CORRELATION METRICS
---------------------------------------------------------
Correlation Score              : {correlation_score:.2f} %

Correlation Risk Level         : {correlation_level}

Correlation Confidence         : {confidence} %

Sample-Size-Adjusted Confidence: {sample_size_confidence:.2f} % (based on {total_dataset_rows} rows in the dataset, NEW - additional metric, does not replace the above)

---------------------------------------------------------

CORRELATION FACTORS
---------------------------------------------------------
Repeated UE IDs                : {ue_factor}  (linkability index {ue_metrics['linkability_index']:.3f})

Repeated SUCIs                  : {suci_factor}  (linkability index {suci_metrics['linkability_index']:.3f})

Repeated gNB                    : {gnb_factor}  (linkability index {gnb_metrics['linkability_index']:.3f})

Repeated DNN                    : {dnn_factor}  (linkability index {dnn_metrics['linkability_index']:.3f})

Repeated S-NSSAI                : {snssai_factor}  (linkability index {snssai_metrics['linkability_index']:.3f})

Dataset Scale (Unique UEs)     : {unique_ue} UEs -> {dataset_scale_ratio:.3f} ratio

UE Distribution Gini            : {ue_registration_gini:.3f}

Historical Registrations       : {history_factor}

Burst Registration Pattern     : {burst_factor}

Previous Failures Present      : {previous_failures_factor}

Auth History Failures Present  : {auth_history_factor}

Location History Correlation   : {location_history_factor}

---------------------------------------------------------

POTENTIAL PRIVACY RISKS
---------------------------------------------------------
Linkability Risk               : {linkability_risk}

Subscriber Tracking Risk       : {tracking_risk}

Behavioural Profiling Risk     : {profiling_risk}

Metadata Correlation Risk      : {metadata_correlation_risk}

Location Correlation Risk      : {location_correlation_risk}

---------------------------------------------------------

CORRELATION OBSERVATIONS
---------------------------------------------------------
"""

# --------------------------------------------------
# Dynamic Observations
# --------------------------------------------------

if repeated_ue > 0:
    report += (
        f"• Same UE identifier appears across multiple registrations "
        f"(distinct repetition ratio {ue_metrics['distinct_repetition_ratio']:.2f}, "
        f"linkability index {ue_metrics['linkability_index']:.2f}).\n"
    )

if repeated_suci > 0:
    report += (
        f"• Same SUCI is reused across registration sessions "
        f"(distinct repetition ratio {suci_metrics['distinct_repetition_ratio']:.2f}, "
        f"linkability index {suci_metrics['linkability_index']:.2f}).\n"
    )

if repeated_gnb > 0:
    report += (
        f"• Registrations repeatedly originate from the same gNB "
        f"(distinct repetition ratio {gnb_metrics['distinct_repetition_ratio']:.2f}, "
        f"linkability index {gnb_metrics['linkability_index']:.2f}).\n"
    )

if repeated_dnn > 0:
    report += (
        f"• DNN reuse enables service usage correlation "
        f"(linkability index {dnn_metrics['linkability_index']:.2f}).\n"
    )

if repeated_snssai > 0:
    report += (
        f"• S-NSSAI reuse reveals slice association patterns "
        f"(linkability index {snssai_metrics['linkability_index']:.2f}).\n"
    )

report += (
    f"• {unique_ue} unique UE(s) observed in this dataset, contributing "
    f"{dataset_scale_ratio * 15:.2f} of 15 points to the Correlation Score "
    "purely from population scale.\n"
)

if ue_registration_gini >= 0.5:
    report += (
        f"• Registration activity is concentrated rather than evenly spread "
        f"across UEs (Gini coefficient {ue_registration_gini:.2f}), raising "
        "tracking risk beyond what the average alone would suggest.\n"
    )

if average_registrations > 5:
    report += "• Frequent registrations increase long-term correlation potential.\n"

if registration_duration > 3600:
    report += "• Long observation period strengthens behavioural correlation.\n"

if burst_detected:
    report += (
        f"• Burst registration pattern detected for {burst_ue_count} UE(s) "
        "(registrations far denser than the dataset's typical pattern).\n"
    )

if total_reg_failures > 0:
    report += (
        f"• {total_reg_failures} registration failure(s) recorded "
        f"across {ues_with_reg_failures} UE(s), indicating retry behaviour.\n"
    )

if total_auth_failures > 0:
    report += (
        f"• {total_auth_failures} authentication failure(s) recorded "
        f"across {ues_with_auth_failures} UE(s).\n"
    )

if lowest_success_rate_value is not None and lowest_success_rate_value < 100:
    report += (
        f"• {lowest_success_rate_ue} has the lowest authentication success "
        f"rate at {lowest_success_rate_value:.1f}%.\n"
    )

if ue_failure_sequences:
    report += (
        f"• {len(ue_failure_sequences)} UE(s) show a mixed "
        "fail/success authentication sequence over time.\n"
    )

if ues_with_repeated_location > 0:
    report += (
        f"• {ues_with_repeated_location} UE(s) repeatedly register from "
        "the same gNB, strengthening location correlation.\n"
    )

if max_unique_gnb_per_ue >= 5:
    report += (
        f"• {most_mobile_ue} registered from {max_unique_gnb_per_ue} "
        "distinct gNBs, indicating high mobility that aids tracking.\n"
    )

if (
    repeated_ue == 0 and
    repeated_suci == 0 and
    repeated_gnb == 0
):
    report += "• No significant identifier reuse was detected.\n"

if attack_type_counter.get("INVALID_SUBSCRIBER", 0) > 0:
    report += (
        f"• {attack_type_counter['INVALID_SUBSCRIBER']} INVALID_SUBSCRIBER "
        "attack(s) detected on request(s) with a missing UE_ID - see the "
        "Active Attack Type Breakdown and Security Events With No UE_ID "
        "sections above.\n"
    )

# --------------------------------------------------
# Behaviour Timeline (NEW)
# --------------------------------------------------
# Only printed for UEs with more than one registration,
# to keep the report focused on UEs that matter for
# correlation analysis.

report += """
---------------------------------------------------------

BEHAVIOUR TIMELINE (Repeat UEs Only)
---------------------------------------------------------
"""

repeat_ues = [ue for ue, count in ue_counter.items() if count > 1]

if repeat_ues:

    for ue in sorted(repeat_ues):

        events = ue_timeline.get(ue, [])

        def _sort_key(event):
            ts = event["timestamp"]
            return ts if isinstance(ts, datetime) else datetime.min

        sorted_events = sorted(events, key=_sort_key)

        report += f"\n{ue}:\n"

        for event in sorted_events:

            ts_display = event["timestamp"]

            report += (
                f"  - [{event.get('request_id', 'N/A')}] {ts_display} | "
                f"gNB: {event['gnb'] or 'N/A'} | "
                f"DNN: {event['dnn'] or 'N/A'} | "
                f"S-NSSAI: {event['snssai'] or 'N/A'} | "
                f"Reg: {event['reg_result']} | "
                f"Auth: {event['auth_result']} | "
                f"Attack: {event.get('attack_type', 'N/A')} | "
                f"Decision: {event.get('decision', 'N/A')} | "
                f"Severity: {event.get('severity', 'N/A')} | "
                f"Confidence: {event.get('confidence', 0.0):.2f}\n"
            )

else:

    report += "No UE registered more than once.\n"

# --------------------------------------------------
# Interpretation
# --------------------------------------------------

report += f"""

---------------------------------------------------------

INTERPRETATION
---------------------------------------------------------
{interpretation}

=========================================================
"""

# --------------------------------------------------
# Display
# --------------------------------------------------

print(report)

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(REPORT_FILE, "w", encoding="utf-8") as file:

    file.write(report)

print("\nReport saved successfully!")

print(REPORT_FILE)
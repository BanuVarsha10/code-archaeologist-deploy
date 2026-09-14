import os
import csv
from datetime import datetime
# --------------------------------------------------
# File Paths
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# CHANGED: now reads privacy1.csv, which carries the Systems team's
# security-context columns (Request_ID, Cause_Code, Attack_Detected,
# Attack_Type, Decision, Severity, Confidence, Risk_Score, Reasons)
# in addition to the original registration fields. Previously this
# pointed at datasets/registration_dataset20.csv, which has none of
# those columns.
INPUT_FILE = os.path.join(
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
OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "anonymized_registration_dataset5.csv"
)
DUPLICATE_FILE = os.path.join(
    RESULTS_DIR,
    "duplicate_registration_dataset.csv"
)
# --------------------------------------------------
# Dictionaries for pseudonyms
# --------------------------------------------------
ue_map = {}
suci_map = {}
ue_counter = 1
suci_counter = 1
rows = []
duplicate_rows = []
seen_rows = set()
first_timestamp = None
# --------------------------------------------------
# Output Fieldnames
# --------------------------------------------------
# CHANGED: extended to match privacy1.csv's full column set, in the
# same order as the source file. Request_ID, Cause_Code,
# Attack_Detected, Attack_Type, Decision, Severity, Confidence,
# Risk_Score and Reasons are NEW - they are passed straight through
# unchanged (not anonymized, not recalculated). Only Timestamp,
# UE_ID, SUCI, gNB_IP, DNN and S_NSSAI go through the transforms
# below, exactly as before.
fieldnames = [
    "Request_ID",
    "Timestamp",
    "Event",
    "UE_ID",
    "SUCI",
    "Authentication_Result",
    "Registration_Status",
    "Cause_Code",
    "gNB_IP",
    "DNN",
    "S_NSSAI",
    "Attack_Detected",
    "Attack_Type",
    "Decision",
    "Severity",
    "Confidence",
    "Risk_Score",
    "Reasons"
]
# --------------------------------------------------
# Duplicate-Detection Fieldnames
# --------------------------------------------------
# NOT the same as `fieldnames` above. Duplicate detection stays
# scoped to the original anonymization-relevant fields only. If it
# used the full `fieldnames` list instead, Request_ID (unique per
# record, e.g. REQ000001) and Reasons (free-text, varies per record)
# would make every row_key unique - duplicate_rows would always come
# back empty, silently breaking duplicate detection. So "is this row
# a duplicate registration" is still judged the same way it always
# was, while every pass-through field still rides along unchanged in
# the row itself.
DUPLICATE_CHECK_FIELDS = [
    "Timestamp",
    "Event",
    "UE_ID",
    "SUCI",
    "Authentication_Result",
    "Registration_Status",
    "gNB_IP",
    "DNN",
    "S_NSSAI"
]
# --------------------------------------------------
# Read Dataset
# --------------------------------------------------
with open(INPUT_FILE, "r", encoding="utf-8") as file:
    reader = csv.DictReader(file)
    for row in reader:
        # ------------------------------------------
        # Convert Timestamp to Relative Time
        # ------------------------------------------
        if row["Timestamp"]:
            current_time = datetime.strptime(
                row["Timestamp"],
                "%m/%d %H:%M:%S.%f"
            )
            if first_timestamp is None:
                first_timestamp = current_time
            delta = current_time - first_timestamp
            row["Timestamp"] = f"T+{delta.total_seconds():.3f}s"
        # ------------------------------------------
        # Replace UE_ID
        # ------------------------------------------
        if row["UE_ID"]:
            if row["UE_ID"] not in ue_map:
                ue_map[row["UE_ID"]] = f"UE_{ue_counter:03}"
                ue_counter += 1
            row["UE_ID"] = ue_map[row["UE_ID"]]
        # ------------------------------------------
        # Replace SUCI
        # ------------------------------------------
        if row["SUCI"]:
            if row["SUCI"] not in suci_map:
                suci_map[row["SUCI"]] = f"SUCI_{suci_counter:03}"
                suci_counter += 1
            row["SUCI"] = suci_map[row["SUCI"]]
        # ------------------------------------------
        # Mask gNB IP
        # ------------------------------------------
        if row["gNB_IP"]:
            parts = row["gNB_IP"].split(".")
            if len(parts) == 4:
                row["gNB_IP"] = f"{parts[0]}.{parts[1]}.xxx.xxx"
        # ------------------------------------------
        # Generalize DNN
        # ------------------------------------------
        if row["DNN"]:
            row["DNN"] = "DEFAULT_DNN"
        # ------------------------------------------
        # Generalize S-NSSAI
        # ------------------------------------------
        if row["S_NSSAI"]:
            row["S_NSSAI"] = "DEFAULT_SLICE"
        # ------------------------------------------
        # Duplicate Row Detection
        # ------------------------------------------
        # A row is a duplicate if every DUPLICATE_CHECK_FIELDS value
        # matches a row already kept (see note above on why this is
        # a narrower field set than the full output row). Duplicates
        # are removed from the anonymized output and set aside
        # separately instead of being silently dropped.
        row_key = tuple(row.get(field, "") for field in DUPLICATE_CHECK_FIELDS)
        if row_key in seen_rows:
            duplicate_rows.append(row)
        else:
            seen_rows.add(row_key)
            rows.append(row)
# --------------------------------------------------
# Write Anonymized Dataset
# --------------------------------------------------
with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as file:
    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )
    writer.writeheader()
    writer.writerows(rows)
# --------------------------------------------------
# Write Duplicate Rows (only if any were found)
# --------------------------------------------------
if duplicate_rows:
    with open(
        DUPLICATE_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )
        writer.writeheader()
        writer.writerows(duplicate_rows)
print("\n======================================")
print("Metadata Minimization Completed")
print(f"Records Processed : {len(rows) + len(duplicate_rows)}")
print(f"Unique Records     : {len(rows)}")
print(f"Duplicate Records  : {len(duplicate_rows)}")
print(f"Output File        : {OUTPUT_FILE}")
if duplicate_rows:
    print(f"Duplicate File     : {DUPLICATE_FILE}")
print("======================================")
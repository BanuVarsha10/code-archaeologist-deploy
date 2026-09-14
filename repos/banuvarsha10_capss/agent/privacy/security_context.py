import os
import pandas as pd

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_DIR = os.path.join(BASE_DIR, "..", "datasets")

REGISTRATION_FILE = os.path.join(DATASET_DIR, "registration_dataset_test.csv")
ATTACK_FILE = os.path.join(DATASET_DIR, "attack_dataset_test.csv")
OUTPUT_FILE = os.path.join(DATASET_DIR, "privacy4.csv")

# --------------------------------------------------
# Default values used ONLY when a registration has
# no matching attack record (LEFT JOIN leaves these blank)
# --------------------------------------------------

ATTACK_DEFAULTS = {
    "Experiment": "UNKNOWN",
    "Attack_Detected": False, 
    "Attack_Type": "NONE",
    "Decision": "UNKNOWN",
    "Severity": "NONE",
    "Confidence": 0.0,
    "Risk_Score": 0.0,
    "Reasons": "No security analysis available."
}

# --------------------------------------------------
# Read Both Datasets
# --------------------------------------------------

reg = pd.read_csv(REGISTRATION_FILE)
attack = pd.read_csv(ATTACK_FILE)

if "Request_ID" not in reg.columns:
    raise ValueError(f"'Request_ID' not found in {REGISTRATION_FILE}")

if "Request_ID" not in attack.columns:
    raise ValueError(f"'Request_ID' not found in {ATTACK_FILE}")

# --------------------------------------------------
# Merge (LEFT JOIN on Request_ID)
#
# Both files contain 'Timestamp' and 'UE_ID'. Nothing is
# dropped — pandas' suffixes keep BOTH versions instead of
# silently overwriting one:
#
#   Timestamp         -> from registration_dataset(1).csv
#   Timestamp_attack  -> from attack_dataset1.csv
#   UE_ID             -> from registration_dataset(1).csv
#   UE_ID_attack       -> from attack_dataset1.csv
# --------------------------------------------------

merged = reg.merge(
    attack,
    on="Request_ID",
    how="left",
    suffixes=("", "_attack")
)

# --------------------------------------------------
# Fill defaults for registrations with no matching attack row
# --------------------------------------------------

for col, default in ATTACK_DEFAULTS.items():
    if col in merged.columns:
        merged[col] = merged[col].fillna(default)

unmatched_count = merged["Decision"].eq("UNKNOWN").sum() if "Decision" in merged.columns else 0
if unmatched_count > 0:
    print(f"[INFO] {unmatched_count} registrations had no matching "
          f"attack record and were defaulted to UNKNOWN/NONE.")

# --------------------------------------------------
# Drop duplicate / unneeded columns
#
# Timestamp_attack and UE_ID_attack are identical to the
# registration file's Timestamp/UE_ID (same event), so keeping
# both is redundant. Experiment is only useful for internal
# testing labels, not the actual privacy pipeline.
#
# Risk_Score is kept EXACTLY as received from the attack
# dataset — it is NOT recalculated here. The Systems team's
# Risk_Score stays as raw input; CAPSS's own overall risk
# score gets computed separately later in metadata_minimizer.py
# / privacy_score.py, using this Risk_Score as one of the inputs.
# --------------------------------------------------

drop_cols = ["Timestamp_attack", "UE_ID_attack", "Experiment"]
merged = merged.drop(columns=[c for c in drop_cols if c in merged.columns])

# --------------------------------------------------
# Final column order
# --------------------------------------------------

final_columns = [
    "Request_ID", "Timestamp", "Event", "UE_ID", "SUCI",
    "Authentication_Result", "Registration_Status", "Cause_Code",
    "gNB_IP", "DNN", "S_NSSAI",
    "Attack_Detected", "Attack_Type", "Decision", "Severity",
    "Confidence", "Risk_Score", "Reasons"
]

# Only keep columns that actually exist (in case a source file
# is missing one), preserving the intended order.
merged = merged[[c for c in final_columns if c in merged.columns]]

# --------------------------------------------------
# Save
# --------------------------------------------------

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
merged.to_csv(OUTPUT_FILE, index=False)

print("----------------------------------------")
print("Security Context Merge Completed")
print(f"Registrations   : {len(reg)}")
print(f"Attack Records  : {len(attack)}")
print(f"Merged Rows     : {len(merged)}")
print(f"Columns         : {list(merged.columns)}")
print(f"Saved To        : {OUTPUT_FILE}")
print("----------------------------------------")
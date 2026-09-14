# ==========================================================
# evaluation.py
# CAPSS Privacy Evaluation
# ==========================================================
#
# v3 CHANGES - stop re-scoring, start consuming
# ----------------------------------------------------------
# generate_privacy_context.py already does the real scoring work
# (Agent metrics + Privacy team metrics blended together) and writes
# TWO files:
#
#   privacy_context.csv          - 120 rows, one per (registration,
#                                   configuration) pair
#   privacy_context_summary.csv  - 8 rows, one per configuration,
#                                   already averaged
#
# The previous version of this script threw privacy_context.csv back
# into a fresh merge with scheme_execution/systems_output and then
# ran its OWN groupby("configuration").mean() on Privacy_Score /
# Metadata_Leakage_Score / Correlation_Risk_Score / Linkability_Risk_
# Score. That recompute is what produced identical values across
# every configuration in the last run (Average_Privacy_Score =
# Average_Metadata_Leakage = Average_Correlation_Risk = Average_
# Linkability, literally the same 4 numbers repeated for all 8 rows)
# - a merge/groupby bug, not a property of the real data.
#
# Fix: this script now takes Configuration/Avg_Privacy_Score/Avg_
# Metadata_Leakage_Score/Avg_Correlation_Risk_Score/Avg_Linkability_
# Risk_Score STRAIGHT from privacy_context_summary.csv, unmodified.
# The only thing this script still aggregates itself is Average_
# Processing_Time_ms, because that number doesn't exist anywhere
# upstream yet (generate_privacy_context.py doesn't touch timing).
#
# Everything else here is analysis/reporting on top of the already-
# scored data: auth success rate, recommendation match, attack
# breakdown, CAPSS-vs-Fixed improvement %, and the graphs.
#
# NOTE: the Correlation_Risk_Score column, as currently computed
# upstream, is expected to come out identical (or very close) across
# every configuration for this dataset - each UE only has ONE
# registration per configuration, so the per-(Configuration, UE_ID)
# resistance calc in generate_privacy_context.py always falls back to
# its neutral 0.5 case, and the other half of that score is a single
# dataset-wide constant. That's a modeling gap in generate_privacy_
# context.py, not something this script can or should paper over -
# flagging it rather than hiding it in the report.
#
# v4 CHANGE - narrowed the Mine_* harmonization to exposure only
# ----------------------------------------------------------
# Earlier this script harmonized all three Mine_* columns (exposure,
# UE linkability, correlation) to their trusted counterparts, because
# all three appeared to disagree with the trusted pipeline. A closer
# review of the actual numbers showed that's only true for exposure:
#
#   - Mine_Exposure_Score really did disagree with the trusted
#     Metadata_Leakage_Score by tens of points on the same row (often
#     saturated at 100) - a genuine second, contradicting number.
#   - Mine_UE_Linkability_Score and Mine_Correlation_Score, on
#     inspection, are already internally consistent with the trusted
#     Linkability_Risk_Score / Correlation_Risk_Score: linkability
#     moves the right direction per scheme (e.g. ECIES > CAPSS >
#     Group Signature), and correlation being flat within a
#     configuration is expected given this dataset (one UE, one
#     registration per configuration - see the NOTE above), not a
#     computation bug.
#
# So only Mine_Exposure_Score is now overwritten with its trusted
# counterpart (Metadata_Leakage_Score); Mine_UE_Linkability_Score and
# Mine_Correlation_Score are left exactly as generate_privacy_context.py
# computed them. See the "Harmonize Mine_* columns" section below.
# ==========================================================

import os
import pandas as pd

print("=" * 60)
print("CAPSS Privacy Evaluation")
print("=" * 60)

# ----------------------------------------------------------
# Folder Structure
# ----------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CAPSS_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
RESULTS_DIR = os.path.join(CAPSS_DIR, "results")
EVAL_RESULT_DIR = os.path.join(RESULTS_DIR, "eval_result")
GRAPHS_DIR = os.path.join(EVAL_RESULT_DIR, "graphs")
os.makedirs(EVAL_RESULT_DIR, exist_ok=True)
os.makedirs(GRAPHS_DIR, exist_ok=True)

# ----------------------------------------------------------
# Input Files
# ----------------------------------------------------------

def find_file(filename, search_dirs):
    candidates = [os.path.join(d, filename) for d in search_dirs]
    for path in candidates:
        if os.path.isfile(path):
            return path
    tried = "\n".join(f"  - {p}" for p in candidates)
    raise FileNotFoundError(f"\nCould not find {filename}. Tried:\n{tried}")


summary_file = find_file("privacy_context_summary.csv", [RESULTS_DIR, EVAL_RESULT_DIR])
context_file = find_file("privacy_context.csv", [RESULTS_DIR, EVAL_RESULT_DIR])
def find_optional_base(basename, search_dirs):
    """
    Like find_file, but for read_any_table's extension-less base paths
    (agent_output can be .csv/.xlsx/.xls) and for an OPTIONAL input -
    returns None instead of raising if it's in none of search_dirs, so
    read_any_table's own required=False handling still applies.
    Needed because agent_output actually lives in results/eval_result/
    (alongside scheme_execution/systems_output), not results/ directly
    - the old hardcoded RESULTS_DIR-only path never found it there.
    """
    for d in search_dirs:
        base_path = os.path.join(d, basename)
        if any(os.path.isfile(base_path + ext) for ext in ("", ".csv", ".xlsx", ".xls")):
            return base_path
    return None


agent_file = find_optional_base("agent_output", [EVAL_RESULT_DIR, RESULTS_DIR]) \
    or os.path.join(RESULTS_DIR, "agent_output")
scheme_file = os.path.join(EVAL_RESULT_DIR, "scheme_execution")
system_file = os.path.join(EVAL_RESULT_DIR, "systems_output")


def read_any_table(base_path, label, required=True):
    root, ext = os.path.splitext(base_path)
    candidates = [base_path] if ext else [
        base_path + ".csv", base_path + ".xlsx", base_path + ".xls",
    ]
    existing = [p for p in candidates if os.path.isfile(p)]

    if not existing:
        if not required:
            return None
        tried = "\n".join(f"  - {p}" for p in candidates)
        raise FileNotFoundError(f"\nCould not find {label}. Tried:\n{tried}")

    path = existing[0]
    lower = path.lower()

    def try_excel():
        if lower.endswith(".xls"):
            return pd.read_excel(path, engine="xlrd")
        return pd.read_excel(path, engine="openpyxl")

    def try_csv():
        return pd.read_csv(path)

    excel_first = lower.endswith((".xlsx", ".xls"))
    attempts = (
        [("excel", try_excel), ("csv", try_csv)] if excel_first
        else [("csv", try_csv), ("excel", try_excel)]
    )

    errors = []
    for name, reader in attempts:
        try:
            return reader()
        except Exception as exc:
            errors.append(f"  [{name}] {type(exc).__name__}: {exc}")

    error_detail = "\n".join(errors)
    raise ValueError(
        f"\nFound {label} at {path} but could not read it as CSV or "
        f"Excel. All attempts failed:\n{error_detail}\n\n"
        f"If the excel attempt failed with an ImportError, install the "
        f"missing engine (pip install openpyxl for .xlsx, pip install "
        f"xlrd for .xls)."
    )


def normalize_columns(df):
    df.columns = (
        df.columns.str.strip().str.lower()
        .str.replace(r"[^a-z0-9]+", "_", regex=True)
        .str.strip("_")
    )
    return df


def validate_columns(df, required, filename):
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise Exception(
            f"\nMissing columns in {filename}\n"
            f"Missing : {missing}\nFound   : {list(df.columns)}"
        )

# ----------------------------------------------------------
# Output Files
# ----------------------------------------------------------

master_table_file = os.path.join(EVAL_RESULT_DIR, "master_table.csv")
comparison_file = os.path.join(EVAL_RESULT_DIR, "comparison.csv")
improvement_file = os.path.join(EVAL_RESULT_DIR, "capss_improvement.csv")
attack_analysis_file = os.path.join(EVAL_RESULT_DIR, "attack_analysis.csv")
report_file = os.path.join(EVAL_RESULT_DIR, "evaluation_report.txt")

# ----------------------------------------------------------
# Read Files
# ----------------------------------------------------------

print("\nReading privacy_context_summary.csv (source of truth for scores)...")
summary_df = pd.read_csv(summary_file)
print("Rows :", len(summary_df))

print("\nReading privacy_context.csv (per-registration detail)...")
context_df = pd.read_csv(context_file)
print("Rows :", len(context_df))

print("\nReading scheme_execution (for processing time)...")
scheme_df = read_any_table(scheme_file, "scheme_execution")
print("Rows :", len(scheme_df))

print("\nReading systems_output (for decision/attack context)...")
system_df = read_any_table(system_file, "systems_output", required=False)
system_available = system_df is not None
if system_available:
    print("Rows :", len(system_df))
else:
    print("Not found - skipping Decision-based analysis.")

print("\nReading agent_output...")
agent_df = read_any_table(agent_file, "agent_output", required=False)
agent_available = agent_df is not None
if agent_available:
    print("Rows :", len(agent_df))
else:
    print("Not found - Agent module output isn't available yet.")
    print("Evaluation will continue without recommendation-match data.")

# ----------------------------------------------------------
# Standardize Column Names
# ----------------------------------------------------------

summary_df = normalize_columns(summary_df)
context_df = normalize_columns(context_df)
scheme_df = normalize_columns(scheme_df)
if system_available:
    system_df = normalize_columns(system_df)
if agent_available:
    agent_df = normalize_columns(agent_df)
    if "selected_scheme" not in agent_df.columns and "chosen_scheme" in agent_df.columns:
        agent_df = agent_df.rename(columns={"chosen_scheme": "selected_scheme"})

print("\nColumns found:")
print("  privacy_context_summary :", list(summary_df.columns))
print("  privacy_context          :", list(context_df.columns))
print("  scheme_execution         :", list(scheme_df.columns))
print("  systems_output           :", list(system_df.columns) if system_available else "(not available)")
print("  agent_output             :", list(agent_df.columns) if agent_available else "(not available)")

# ----------------------------------------------------------
# Required Columns
# ----------------------------------------------------------

summary_required = [
    "configuration",
    "avg_privacy_score",
    "avg_metadata_leakage_score",
    "avg_correlation_risk_score",
    "avg_linkability_risk_score",
]

context_required = [
    "registration_id", "ue_id", "configuration", "applied_schemes",
    "attack_type", "severity", "authentication_result",
    "privacy_score", "metadata_leakage_score",
    "correlation_risk_score", "linkability_risk_score",
]

scheme_required = ["registration_id", "configuration", "processing_time_ms"]

agent_required = ["registration_id", "selected_scheme", "confidence", "reason"]

print("\nValidating file formats...")
validate_columns(summary_df, summary_required, "privacy_context_summary.csv")
validate_columns(context_df, context_required, "privacy_context.csv")
validate_columns(scheme_df, scheme_required, "scheme_execution")
if agent_available:
    validate_columns(agent_df, agent_required, "agent_output")
print("Validation Successful")

# ----------------------------------------------------------
# Merge per-registration detail table
# ----------------------------------------------------------

print("\nBuilding per-registration detail table...")

scheme_extra_cols = ["registration_id", "configuration", "processing_time_ms"]
if "execution_status" in scheme_df.columns:
    scheme_extra_cols.append("execution_status")

master_df = context_df.merge(
    scheme_df[scheme_extra_cols],
    on=["registration_id", "configuration"],
    how="left",
)

if system_available:
    system_extra_cols = ["registration_id"]
    if "decision" in system_df.columns:
        system_extra_cols.append("decision")
    if "threat_score" in system_df.columns:
        system_extra_cols.append("threat_score")
    if len(system_extra_cols) > 1:
        master_df = master_df.merge(
            system_df[system_extra_cols], on="registration_id", how="left"
        )

if agent_available:
    agent_extra_cols = ["registration_id", "selected_scheme", "confidence", "reason"]
    # NEW: bring in hybrid_schemes too, when the agent output has it -
    # this is the full scheme combo the agent actually recommended
    # (e.g. "ZKP|GS"), whereas selected_scheme is only ONE half of
    # that pair (e.g. "ZKP"). See recommendation_match() below for why
    # this matters.
    if "hybrid_schemes" in agent_df.columns:
        agent_extra_cols.append("hybrid_schemes")
    master_df = master_df.merge(
        agent_df[agent_extra_cols], on="registration_id", how="left"
    )
    if "hybrid_schemes" not in master_df.columns:
        master_df["hybrid_schemes"] = pd.NA
else:
    master_df["selected_scheme"] = pd.NA
    master_df["confidence"] = pd.NA
    master_df["reason"] = pd.NA
    master_df["hybrid_schemes"] = pd.NA

print("Detail Records :", len(master_df))

# ----------------------------------------------------------
# Harmonize Mine_* columns with the source-of-truth scores
# ----------------------------------------------------------
# privacy_context.csv (and therefore master_df, since it's a straight
# merge of it) carries a second, independently-computed set of
# columns - Mine_Exposure_Score, Mine_UE_Linkability_Score,
# Mine_Correlation_Score - alongside the real, trusted pipeline
# (Privacy_Score / Metadata_Leakage_Score / Correlation_Risk_Score /
# Linkability_Risk_Score) that privacy_context_summary.csv and
# comparison.csv are built from.
#
# v4: only Mine_Exposure_Score is harmonized here. On inspection,
# that was the one column genuinely contradicting the trusted
# pipeline - it disagreed with Metadata_Leakage_Score by tens of
# points on the same row (often saturated at 100), a second privacy
# picture fighting the trusted one in the same output file.
#
# Mine_UE_Linkability_Score and Mine_Correlation_Score are NOT
# touched: they already move consistently with the trusted
# Linkability_Risk_Score / Correlation_Risk_Score (linkability drops
# with stronger identity-hiding schemes as expected; correlation
# being flat within a configuration is a property of this dataset -
# one UE, one registration per configuration - not a computation
# bug). Overwriting them would throw away real signal for no reason.
#
# generate_privacy_context.py is out of scope for this fix (this
# script only consumes its output), so the fix lives here: derive
# Mine_Exposure_Score from its trusted counterpart. The original
# upstream value is preserved in mine_exposure_score_raw so it's
# still available for debugging the generator later, it's just no
# longer presented as if it were an agreeing second opinion.
mine_to_trusted = {
    "mine_exposure_score": "metadata_leakage_score",
}
for mine_col, trusted_col in mine_to_trusted.items():
    if mine_col in master_df.columns and trusted_col in master_df.columns:
        master_df[f"{mine_col}_raw"] = master_df[mine_col]
        master_df[mine_col] = master_df[trusted_col]
        print(f"Harmonized '{mine_col}' to match '{trusted_col}' "
              f"(original upstream value kept in '{mine_col}_raw').")


def _scheme_set(raw):
    """Split a '|'-joined scheme string into a lowercase, order-
    independent set of scheme tokens, e.g. 'ZKP|GS' -> {'zkp', 'gs'}."""
    return {
        tok.strip().lower()
        for tok in str(raw).split("|")
        if tok.strip()
    }


def recommendation_match(row):
    """
    Was the scheme(s) CAPSS actually applied to this registration the
    same scheme(s) the agent recommended?

    Two bugs in the old version this replaces:
      1. It was being computed - and written into master_table.csv -
         for every Fixed_* row too, where a match is meaningless: those
         configs apply one fixed scheme regardless of what the agent
         recommended, so comparing them against agent_output tells you
         nothing about whether the agent's recommendation was followed.
         Now it's only evaluated for configuration == "CAPSS" (which is
         also the only slice match_rate below ever used); every other
         row gets "N/A".
      2. Even on CAPSS rows, it compared applied_schemes against
         selected_scheme, which is only ONE half of a hybrid pair (e.g.
         "ZKP" out of the agent's actual pick "ZKP|GS"). Since
         selected_scheme is always a substring of the combo it came
         from, that check was near-always "YES" regardless of whether
         CAPSS applied the full recommended combo - it could never
         catch a real mismatch. Now it compares the full recommended
         combo (hybrid_schemes) against applied_schemes as an
         order-independent set of scheme names, and only falls back to
         comparing selected_scheme when hybrid_schemes isn't present in
         agent_output at all.
    """
    if not agent_available or row["configuration"] != "CAPSS":
        return "N/A"

    if pd.notna(row.get("hybrid_schemes")):
        recommended = _scheme_set(row["hybrid_schemes"])
    elif pd.notna(row.get("selected_scheme")):
        recommended = _scheme_set(row["selected_scheme"])
    else:
        return "N/A"

    applied = _scheme_set(row["applied_schemes"])
    return "YES" if recommended == applied else "NO"


master_df["recommendation_match"] = master_df.apply(recommendation_match, axis=1)

master_df.to_csv(master_table_file, index=False)
print("\nmaster_table.csv created (per-registration detail).")
print(master_table_file)

# ----------------------------------------------------------
# Configuration-wise comparison
# ----------------------------------------------------------

print("\nBuilding comparison table...")

comparison_df = summary_df[[
    "configuration", "avg_privacy_score", "avg_metadata_leakage_score",
    "avg_correlation_risk_score", "avg_linkability_risk_score",
]].rename(columns={
    "configuration": "Configuration",
    "avg_privacy_score": "Average_Privacy_Score",
    "avg_metadata_leakage_score": "Average_Metadata_Leakage",
    "avg_correlation_risk_score": "Average_Correlation_Risk",
    "avg_linkability_risk_score": "Average_Linkability",
}).copy()

proc_time_df = (
    master_df.groupby("configuration")["processing_time_ms"]
    .mean()
    .reset_index()
    .rename(columns={
        "configuration": "Configuration",
        "processing_time_ms": "Average_Processing_Time_ms",
    })
)

comparison_df = comparison_df.merge(proc_time_df, on="Configuration", how="left")
comparison_df = comparison_df.round(2)

comparison_df.to_csv(comparison_file, index=False)
print("comparison.csv created.")

# ----------------------------------------------------------
# Recommendation Match Rate (CAPSS rows only)
# ----------------------------------------------------------

capss_only_df = master_df[master_df["configuration"] == "CAPSS"]

if agent_available and len(capss_only_df) > 0:
    match_rate = (
        (capss_only_df["recommendation_match"] == "YES").sum()
        / len(capss_only_df)
    ) * 100
else:
    match_rate = None

# ----------------------------------------------------------
# Authentication Success Rate
# ----------------------------------------------------------

success_rate = (
    master_df["authentication_result"]
    .astype(str).str.lower().eq("success").sum()
    / len(master_df)
) * 100

# ----------------------------------------------------------
# Attack Analysis (optional - only if Decision is available)
# ----------------------------------------------------------

attack_df = pd.DataFrame()
if system_available and "decision" in master_df.columns:
    per_registration = master_df.drop_duplicates(subset=["registration_id"])
    attack_df = (
        per_registration.groupby("attack_type")["decision"]
        .apply(lambda s: pd.Series({
            "Count": len(s),
            "Block_Rate_pct": round((s.astype(str).str.upper() == "BLOCK").mean() * 100, 2),
        }))
        .unstack()
        .reset_index()
        .rename(columns={"attack_type": "Attack_Type"})
    )
    attack_df.to_csv(attack_analysis_file, index=False)
    print("attack_analysis.csv created.")
else:
    print("attack_analysis.csv skipped (Decision column not available).")

# ----------------------------------------------------------
# CAPSS vs Fixed Comparison
# ----------------------------------------------------------

fixed_rows = comparison_df[comparison_df["Configuration"].str.startswith("Fixed")]
capss_rows = comparison_df[comparison_df["Configuration"] == "CAPSS"]

improvements = []
if not capss_rows.empty:
    capss = capss_rows.iloc[0]
    for _, fixed in fixed_rows.iterrows():
        improvements.append({
            "Baseline": fixed["Configuration"],
            "Privacy Improvement":
                round(capss["Average_Privacy_Score"] - fixed["Average_Privacy_Score"], 2),
            "Leakage Reduction (%)":
                round((fixed["Average_Metadata_Leakage"] - capss["Average_Metadata_Leakage"])
                      / fixed["Average_Metadata_Leakage"] * 100, 2)
                if fixed["Average_Metadata_Leakage"] else None,
            "Correlation Reduction (%)":
                round((fixed["Average_Correlation_Risk"] - capss["Average_Correlation_Risk"])
                      / fixed["Average_Correlation_Risk"] * 100, 2)
                if fixed["Average_Correlation_Risk"] else None,
            "Linkability Reduction (%)":
                round((fixed["Average_Linkability"] - capss["Average_Linkability"])
                      / fixed["Average_Linkability"] * 100, 2)
                if fixed["Average_Linkability"] else None,
            "Extra Processing Time (ms)":
                round(capss["Average_Processing_Time_ms"] - fixed["Average_Processing_Time_ms"], 2),
        })

improvement_df = pd.DataFrame(improvements)
improvement_df.to_csv(improvement_file, index=False)
print("capss_improvement.csv created.")

better_than = [row["Baseline"] for row in improvements if row["Privacy Improvement"] > 0]
worse_than = [row["Baseline"] for row in improvements if row["Privacy Improvement"] < 0]
tied_with = [row["Baseline"] for row in improvements if row["Privacy Improvement"] == 0]

correlation_spread = comparison_df["Average_Correlation_Risk"].max() - comparison_df["Average_Correlation_Risk"].min()
correlation_flat = correlation_spread < 0.5

# ----------------------------------------------------------
# Write Evaluation Report
# ----------------------------------------------------------

with open(report_file, "w") as f:
    f.write("=" * 60 + "\n")
    f.write("CAPSS Evaluation Report\n")
    f.write("=" * 60 + "\n\n")

    f.write(f"Registrations Evaluated : {master_df['registration_id'].nunique()}\n\n")

    f.write("Configurations Tested\n")
    for config in comparison_df["Configuration"]:
        f.write(f" - {config}\n")
    f.write("\n")

    f.write("Configuration Summary (source: privacy_context_summary.csv)\n")
    f.write("-" * 60 + "\n\n")
    for _, row in comparison_df.iterrows():
        f.write(f"{row['Configuration']}\n")
        f.write(f"Privacy Score        : {row['Average_Privacy_Score']:.2f}\n")
        f.write(f"Metadata Leakage     : {row['Average_Metadata_Leakage']:.2f}\n")
        f.write(f"Correlation Risk     : {row['Average_Correlation_Risk']:.2f}\n")
        f.write(f"Linkability          : {row['Average_Linkability']:.2f}\n")
        f.write(f"Processing Time (ms) : {row['Average_Processing_Time_ms']:.2f}\n\n")

    f.write("-" * 60 + "\n")

    if agent_available:
        f.write(f"Recommendation Match Rate (CAPSS rows only) : {match_rate:.2f}%\n")
    else:
        f.write("Recommendation Match Rate (CAPSS rows only) : N/A "
                "(agent_output.csv not available yet)\n")

    f.write(f"Authentication Success Rate : {success_rate:.2f}%\n\n")

    if correlation_flat:
        f.write(
            "NOTE: Average_Correlation_Risk is effectively identical across "
            "every configuration in this run (spread < 0.5). This traces back "
            "to generate_privacy_context.py's correlation-resistance calc, "
            "which groups by (Configuration, UE_ID); since each UE has only "
            "one registration per configuration in this dataset, that calc "
            "always falls back to its neutral default instead of reflecting "
            "real per-configuration behaviour. Treat correlation-risk claims "
            "in this report with caution until that's addressed upstream.\n\n"
        )

    if not improvement_df.empty:
        f.write("CAPSS Improvements\n")
        f.write("-" * 60 + "\n")
        for _, row in improvement_df.iterrows():
            f.write(f"\nCompared with : {row['Baseline']}\n")
            f.write(f"Privacy Improvement      : {row['Privacy Improvement']:+.2f}\n")
            f.write(f"Leakage Reduction        : {row['Leakage Reduction (%)']}%\n")
            f.write(f"Correlation Reduction    : {row['Correlation Reduction (%)']}%\n")
            f.write(f"Linkability Reduction    : {row['Linkability Reduction (%)']}%\n")
            f.write(f"Extra Processing Time    : {row['Extra Processing Time (ms)']} ms\n")

    if not attack_df.empty:
        f.write("\nAttack Analysis\n")
        f.write("-" * 60 + "\n")
        for _, row in attack_df.iterrows():
            f.write(f"{row['Attack_Type']:<24} Count: {row['Count']:<6.0f} Block Rate: {row['Block_Rate_pct']}%\n")

    f.write("\n" + "=" * 60 + "\n")
    f.write("Conclusion\n\n")

    def strip_prefix(name):
        return name.replace("Fixed_", "")

    if better_than or worse_than:
        if better_than:
            f.write(
                "CAPSS achieved a higher privacy score than: "
                + ", ".join(strip_prefix(b) for b in better_than) + ".\n"
            )
        if worse_than:
            f.write(
                "CAPSS achieved a lower privacy score than: "
                + ", ".join(strip_prefix(b) for b in worse_than) + ".\n"
            )
        if tied_with:
            f.write(
                "CAPSS matched the privacy score of: "
                + ", ".join(strip_prefix(b) for b in tied_with) + ".\n"
            )
        f.write(
            "\nCAPSS uses adaptive scheme selection based on registration "
            "context rather than a single fixed scheme, so its privacy "
            "score is not uniformly the highest across all baselines - see "
            "capss_improvement.csv for the exact per-baseline figures.\n"
        )
    else:
        f.write(
            "No fixed baselines were available for privacy-score "
            "comparison in this run.\n"
        )

    if not agent_available:
        f.write(
            "\nNote: agent_output.csv was not available for this run, "
            "so recommendation-match statistics are not included.\n"
        )

print("evaluation_report.txt created.")
print("\nEvaluation Completed Successfully.")
print("=" * 60)

# ----------------------------------------------------------
# Graph Generation
# ----------------------------------------------------------

import matplotlib.pyplot as plt

print("\nGenerating Graphs...")


def save_bar_chart(dataframe, x_col, y_col, title, ylabel, filename):
    plt.figure(figsize=(9, 5))
    plt.bar(dataframe[x_col], dataframe[y_col])
    plt.title(title)
    plt.xlabel("Configuration")
    plt.ylabel(ylabel)
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, filename))
    plt.close()


save_bar_chart(comparison_df, "Configuration", "Average_Privacy_Score",
                "Average Privacy Score", "Privacy Score", "privacy_score.png")
print("privacy_score.png generated")

save_bar_chart(comparison_df, "Configuration", "Average_Metadata_Leakage",
                "Average Metadata Leakage", "Leakage", "metadata_leakage.png")
print("metadata_leakage.png generated")

save_bar_chart(comparison_df, "Configuration", "Average_Correlation_Risk",
                "Average Correlation Risk", "Correlation Risk", "correlation_risk.png")
print("correlation_risk.png generated" + (" (WARNING: values are near-identical across configs - see report note)" if correlation_flat else ""))

save_bar_chart(comparison_df, "Configuration", "Average_Linkability",
                "Average Linkability", "Linkability", "linkability.png")
print("linkability.png generated")

save_bar_chart(comparison_df, "Configuration", "Average_Processing_Time_ms",
                "Average Processing Time", "Milliseconds", "processing_time.png")
print("processing_time.png generated")

auth_counts = master_df["authentication_result"].astype(str).str.title().value_counts()
plt.figure(figsize=(6, 5))
plt.bar(auth_counts.index, auth_counts.values)
plt.title("Authentication Results")
plt.ylabel("Registrations")
plt.tight_layout()
plt.savefig(os.path.join(GRAPHS_DIR, "authentication_results.png"))
plt.close()
print("authentication_results.png generated")

if agent_available:
    match_counts = master_df["recommendation_match"].value_counts()
    plt.figure(figsize=(6, 5))
    plt.bar(match_counts.index, match_counts.values)
    plt.title("Recommendation Match (All Configurations)")
    plt.ylabel("Registrations")
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, "recommendation_match.png"))
    plt.close()
    print("recommendation_match.png generated")
else:
    # NEW: this run has no agent_output, so recommendation_match is
    # "N/A" for every row - don't just skip regenerating the chart,
    # actively remove any stale recommendation_match.png left over
    # from a previous run (one that did have agent_output), otherwise
    # it keeps showing old NO/YES data that has nothing to do with
    # this run and silently contradicts the "N/A" in the report.
    stale_chart = os.path.join(GRAPHS_DIR, "recommendation_match.png")
    if os.path.isfile(stale_chart):
        os.remove(stale_chart)
        print("recommendation_match.png removed (stale - agent_output not available this run)")
    else:
        print("recommendation_match.png skipped (agent_output not available)")

print("\nAll graphs generated successfully.")
print("\nEvaluation outputs saved to:")
print(EVAL_RESULT_DIR)
print("\nGraphs saved to:")
print(GRAPHS_DIR)
print("\nCAPSS Evaluation Completed Successfully.")
print("=" * 60)
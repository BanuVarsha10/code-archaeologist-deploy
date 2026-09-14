"""
generate_privacy_context.py
----------------------------------------------------------------------
Purpose
----------------------------------------------------------------------
This is the missing middle step between the Systems team's output and
the CAPSS evaluation step:

    systems_output.xlsx  (15 registrations, attack/severity/auth verdict)
            +
    scheme_execution.xlsx (120 rows = 15 registrations x 8 configurations)
            |
            v
    generate_privacy_context.py      <-- THIS FILE
            |
            v
    privacy_context.csv   (120 rows: one privacy assessment per
                            (registration, configuration) pair)
    privacy_context_summary.csv (8 rows: one averaged row per
                            configuration/scheme - what evaluate.py
                            should consume)

----------------------------------------------------------------------
CHANGE LOG - v4: every score is now a MIX of the agent's scheme-specific
formulas AND your own dataset-driven, non-scheme-specific formulas
----------------------------------------------------------------------
v3 scored every (registration, configuration) row using ONLY the CAPSS
agent's own formulas - the scheme's quantitative_metrics from
privacy_schemes.json, plus the compute_hbs()-style hybrid bonus and
the correlation_resistance()-style per-(Configuration,UE) scheme
diversity check (capss.evaluation.metrics.EvaluationMetrics). Those
formulas are all SCHEME-specific: they only ever answer "how good is
the privacy scheme that got applied here?"

They can't see whether the underlying registration was already
identifying BEFORE any scheme touched it - a real IMSI, an exact
timestamp, one subscriber dominating every registration, a BLOCK-level
attack verdict. That's a different signal, and it's exactly what your
own correlation_analyzer.py and privacy_score.py compute: they never
look at Applied_Schemes at all - they score the raw registration
metadata (UE_ID reuse/diversity/entropy, timestamps, Authentication/
Registration status, dataset scale, Gini concentration) the same way
regardless of which scheme is later used on top of it.

This version pulls the non-scheme-specific parts of your two scripts
into MINE_* helpers below (adapted to the columns systems_output.xlsx
actually carries - see "Data availability note" below) and BLENDS them
with the agent's scheme-specific numbers for every one of the four
output columns, instead of using either source alone:

  1. Privacy_Score
     = agent's scheme quantitative `privacy_score` (1-5) * 20, same as
       v3 - THEN discounted by PRIVACY_EXPOSURE_PENALTY_WEIGHT of
       MINE_exposure (your privacy_score.py's raw metadata-exposure
       score for this registration, see point 6). Rationale: a scheme
       can only protect what it's given - if the raw registration
       data was already maximally identifying, the scheme's nominal
       privacy score is discounted to reflect that.

  2. Metadata_Leakage_Score
     = weighted blend of the agent's tracking_score-derived leakage
       (scheme-specific, same math as v3: (5 - tracking_score) * 20)
       and MINE_exposure (this registration's raw metadata exposure,
       non-scheme-specific - see point 6). Weights:
       LEAKAGE_BLEND_AGENT_WEIGHT / LEAKAGE_BLEND_MINE_WEIGHT below.

  3. Linkability_Risk_Score
     = weighted blend of the agent's tracking-derived value (same
       formula as Metadata_Leakage_Score pre-blend, since - as noted
       in v3 - privacy_schemes.json has no separate linkability
       metric to reuse) and MINE_ue_linkability (this UE's own
       diversity/entropy-based linkability_index from your
       correlation_analyzer.py, see point 5 - more granular than a
       single dataset-wide number, since it's computed per UE_ID).
       Weights: LINKABILITY_BLEND_AGENT_WEIGHT / _MINE_WEIGHT below.

  4. Correlation_Risk_Score
     = weighted blend of:
         (a) the agent's per-(Configuration, UE_ID) scheme-diversity
             resistance check - UNCHANGED from v3:
             group registrations by (Configuration, UE_ID); resistance
             = distinct schemes that UE got / registrations that UE
             has under that configuration (0.5 if only one
             registration); Correlation_Risk_Score_agent =
             (1 - resistance) * 100. This is the part that makes
             Fixed_* configs score worse than CAPSS - a Fixed_* config
             gives one UE the same scheme every time by construction.
         (b) MINE_correlation_score (point 4 below) - a SINGLE
             dataset-wide value (same for every row in this run,
             exactly like the "Behaviour_Correlation" global-context
             component in your privacy_score.py), reflecting how
             linkable the raw registration metadata is on its own,
             independent of any scheme.
       Weights: CORRELATION_BLEND_AGENT_WEIGHT / _MINE_WEIGHT below.

  5. MINE_ue_linkability (dataset-wide, per UE_ID, feeds point 3)
     = your correlation_analyzer.py's identifier_metrics()/
       shannon_entropy() logic, applied to the UE_ID column of
       systems_output.xlsx: diversity_ratio, record_repetition_ratio,
       normalized Shannon entropy, concentration, and
       linkability_index = (record_repetition_ratio + concentration) / 2.
       Computed once per UE_ID across the whole systems_output.xlsx
       dataset (not per scheme - this is the "not scheme specific"
       part you asked to keep).

  6. MINE_exposure (per registration, feeds points 1 and 2)
     = your privacy_score.py's ue_id_exposure() / timestamp_exposure()
       / generic_exposure() functions, reused UNCHANGED, but summed
       only over the fields systems_output.xlsx actually has (see
       "Data availability note") and normalized against the max
       achievable score for THOSE fields only (rather than assuming
       all 8 of your original MAX_WEIGHTS fields are present) so the
       0-100 scale stays meaningful even with fewer columns.

  7. MINE_correlation_score (dataset-wide, feeds point 4)
     = your correlation_analyzer.py's weighted factor_score /
       factor_count design, reusing the SAME five factors that are
       possible to compute from systems_output.xlsx (UE linkability
       index, dataset scale ratio, UE registration Gini coefficient,
       registration frequency tier, observation-window tier), with
       their original weights (25/15/10/10/10 out of the original
       100-point scheme) renormalized so those five factors alone sum
       to 100 - see AVAILABLE_CORRELATION_WEIGHTS below. Burst
       detection, prior failures, and auth history are intentionally
       excluded from this score, exactly as they are in your original
       script (documented there as behavioural/anomaly indicators, not
       metadata-linkability indicators).

  8. Hybrid combination bonus (CAPSS rows using two schemes, e.g.
     "ZKP|GS") - UNCHANGED from v3: capss.reasoning.metrics.
     MetricsCalculator.compute_hbs()-style symmetric average, applied
     to the agent's pre-blend privacy/leakage/linkability numbers
     before they're blended with MINE_* above.

  9. Severity/Authentication stress (SEVERITY_STRESS /
     AUTH_FAILURE_STRESS) - still applied to the agent's pre-blend
     privacy/leakage/linkability numbers, using the real Severity
     column from systems_output.xlsx. Correlation_Risk_Score is still
     left out of stress-adjustment (as in v3), since it already
     reflects real UE/scheme behaviour and stress-adjusting it again
     would double-count that signal.

     v5 NOTE: the authentication-failure half of the stress factor now
     reads the Decision column (ALLOW/TAG/BLOCK - the system's actual
     execution outcome) instead of Authentication_Result. In
     systems_output.xlsx, Authentication_Result says "Success" for 14
     of 15 registrations - including ones the system itself BLOCKed as
     attacks - so it never actually signalled a failure. Decision is
     the real pass/fail verdict, so that's now the sole source for
     this stress component. See attack_stress_factor() below.

----------------------------------------------------------------------
Data availability note
----------------------------------------------------------------------
Your correlation_analyzer.py / privacy_score.py were written against a
richer dataset (privacy_test.csv: UE_ID, SUCI, gNB_IP, DNN, S_NSSAI,
Timestamp, Registration_Status, Authentication_Result, Request_ID,
Attack_Detected, Attack_Type, Decision, Severity, Confidence).
systems_output.xlsx only carries: Registration_ID, Timestamp, UE_ID,
Attack_Type, Threat_Score, Severity, Decision, Authentication_Result -
no SUCI, gNB_IP, DNN, S_NSSAI, Registration_Status, or Confidence.

Rather than silently dropping those weights (which would quietly
shrink the 0-100 scale) or inventing values for columns that don't
exist here, MINE_exposure and MINE_correlation_score both renormalize
your original weights across ONLY the fields/factors that are
actually available in systems_output.xlsx, so the two scores still
span the full 0-100 range. If gNB_IP/SUCI/DNN/S_NSSAI ever get added
to systems_output.xlsx, add their weights back into
AVAILABLE_EXPOSURE_WEIGHTS / AVAILABLE_CORRELATION_WEIGHTS below and
the renormalization will pick them up automatically.

SCHEME_METRICS below is a literal copy of the `quantitative_metrics`
block for each of the 7 schemes in CAPSS-ai-agent/agent/data/privacy_schemes.json
(short_name keys match Applied_Schemes exactly - no aliasing needed,
since scheme_execution.xlsx already uses the same short names as the
agent's knowledge base). If you add/change schemes in privacy_schemes.json,
mirror the change here - this script does not read that file directly
so it can keep running from privacy/results/ without a cross-project
path dependency.

----------------------------------------------------------------------
CHANGE LOG - v6: output location moved into results/eval_result/
----------------------------------------------------------------------
Inputs (systems_output.xlsx, scheme_execution.xlsx) are still read
from privacy/results/, matching the actual project layout. The two
generated files - privacy_context.csv and privacy_context_summary.csv -
now get written into privacy/results/eval_result/ instead of directly
into privacy/results/, so they land next to the rest of the evaluation
output (eval_result/, graphs/, logs/, tables/) instead of sitting
loose alongside the raw dataset/report files. See OUTPUT_DIR below.
----------------------------------------------------------------------
"""

import os
import csv
import math
import statistics
import openpyxl

# ----------------------------------------------------------------------
# File paths
# ----------------------------------------------------------------------
# NOTE (v4 path fix): in your actual project layout, systems_output.xlsx
# and scheme_execution.xlsx live in the SAME "results" folder as
# privacy_context.csv, correlation_report.txt, etc. - NOT in a separate
# "datasets" folder like the original v1-v3 draft assumed. Both input
# and output now point at RESULTS_DIR so this matches what you actually
# have on disk. If you later move the two .xlsx files elsewhere, just
# change SYSTEMS_OUTPUT_FILE / SCHEME_EXECUTION_FILE below.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RESULT_DIR = os.path.join(BASE_DIR, "..", "results")
OUTPUT_DIR = os.path.join(RESULT_DIR, "eval_result")

os.makedirs(OUTPUT_DIR, exist_ok=True)

SYSTEMS_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "systems_output.xlsx")
SCHEME_EXECUTION_FILE = os.path.join(OUTPUT_DIR, "scheme_execution.xlsx")

PRIVACY_CONTEXT_FILE = os.path.join(OUTPUT_DIR, "privacy_context.csv")
PRIVACY_CONTEXT_SUMMARY_FILE = os.path.join(OUTPUT_DIR, "privacy_context_summary.csv")
# ----------------------------------------------------------------------
# Real per-scheme quantitative metrics
# (verbatim copy of "quantitative_metrics" from
#  CAPSS-ai-agent/agent/data/privacy_schemes.json - see docstring above)
# ----------------------------------------------------------------------
SCHEME_METRICS = {
    #             privacy security latency energy tracking identity scalability deployment quantum
    "ECIES":   {"privacy_score": 4, "security_score": 5, "latency_score": 5, "energy_score": 5,
                "tracking_score": 2, "identity_score": 5, "scalability_score": 5,
                "deployment_score": 5, "quantum_score": 1},
    "ML-KEM":  {"privacy_score": 5, "security_score": 5, "latency_score": 3, "energy_score": 3,
                "tracking_score": 3, "identity_score": 5, "scalability_score": 4,
                "deployment_score": 3, "quantum_score": 5},
    "AP":      {"privacy_score": 5, "security_score": 2, "latency_score": 3, "energy_score": 3,
                "tracking_score": 5, "identity_score": 1, "scalability_score": 4,
                "deployment_score": 2, "quantum_score": 5},
    "DP":      {"privacy_score": 4, "security_score": 2, "latency_score": 5, "energy_score": 5,
                "tracking_score": 5, "identity_score": 3, "scalability_score": 5,
                "deployment_score": 2, "quantum_score": 5},
    "IBE":     {"privacy_score": 4, "security_score": 4, "latency_score": 3, "energy_score": 2,
                "tracking_score": 2, "identity_score": 5, "scalability_score": 3,
                "deployment_score": 2, "quantum_score": 1},
    "GS":      {"privacy_score": 5, "security_score": 4, "latency_score": 2, "energy_score": 2,
                "tracking_score": 5, "identity_score": 3, "scalability_score": 3,
                "deployment_score": 2, "quantum_score": 1},
    "ZKP":     {"privacy_score": 5, "security_score": 5, "latency_score": 3, "energy_score": 2,
                "tracking_score": 3, "identity_score": 4, "scalability_score": 3,
                "deployment_score": 2, "quantum_score": 1},
}

# scheme_execution.xlsx's Fixed_* rows spell schemes out in full
# (e.g. "Identity_Based_Encryption"), while CAPSS's combination rows
# use the same short_name abbreviations as privacy_schemes.json
# (e.g. "IBE"). This maps the full spellings back onto SCHEME_METRICS'
# short_name keys so both forms resolve to the same real metrics.
SCHEME_ALIASES = {
    "Zero_Knowledge_Proof": "ZKP",
    "Identity_Based_Encryption": "IBE",
    "Group_Signature": "GS",
    "Adaptive_Padding": "AP",
    "Dynamic_Pseudonym": "DP",
}

# The 8 metrics compute_hbs() compares when scoring a hybrid combination
# (capss.reasoning.metrics.MetricsCalculator.compute_hbs). scalability_score
# is deliberately excluded - the real compute_hbs() list omits it too.
HYBRID_BENEFIT_METRICS = [
    "privacy_score", "security_score", "latency_score", "tracking_score",
    "identity_score", "quantum_score", "deployment_score", "energy_score",
]

# ----------------------------------------------------------------------
# ASSUMPTION - Attack-context stress factors (kept from the original
# design; not part of the CAPSS agent's evaluation module, but uses
# real Severity/Decision data from systems_output.xlsx - see docstring
# point 9)
# ----------------------------------------------------------------------
SEVERITY_STRESS = {
    "NORMAL": 0.00,
    "SUSPICIOUS": 0.10,
    "MALICIOUS": 0.22,
}
AUTH_FAILURE_STRESS = 0.06  # added on top when Decision != ALLOW (v5: sourced from Decision, not Authentication_Result)

# ----------------------------------------------------------------------
# NEW (v4) - Blend weights between the agent's scheme-specific formulas
# and your own dataset-driven, non-scheme-specific formulas. All four
# pairs sum to 1.0 by design; tune these if you want one source to
# dominate more or less.
# ----------------------------------------------------------------------
PRIVACY_EXPOSURE_PENALTY_WEIGHT = 0.25   # how much raw MINE_exposure discounts the agent's nominal Privacy_Score

LEAKAGE_BLEND_AGENT_WEIGHT = 0.6         # agent's tracking_score-derived leakage (scheme-specific)
LEAKAGE_BLEND_MINE_WEIGHT = 0.4          # MINE_exposure (raw metadata exposure, non-scheme-specific)

LINKABILITY_BLEND_AGENT_WEIGHT = 0.5     # agent's tracking-derived value (scheme-specific, reused from leakage)
LINKABILITY_BLEND_MINE_WEIGHT = 0.5      # MINE_ue_linkability (per-UE diversity/entropy index, non-scheme-specific)

CORRELATION_BLEND_AGENT_WEIGHT = 0.6     # agent's per-(Configuration,UE) scheme-diversity resistance
CORRELATION_BLEND_MINE_WEIGHT = 0.4      # MINE_correlation_score (dataset-wide raw metadata linkability)

# ----------------------------------------------------------------------
# NEW (v4) - "MINE" weights, lifted from your correlation_analyzer.py /
# privacy_score.py, restricted to the fields systems_output.xlsx
# actually has (see "Data availability note" above). Each dict is
# renormalized in code (not by hand) so the resulting scores still
# span 0-100 even though several original fields are missing here.
# ----------------------------------------------------------------------

# From your privacy_score.py's MAX_WEIGHTS - only the fields present
# in systems_output.xlsx (UE_ID, Timestamp, Authentication_Result).
AVAILABLE_EXPOSURE_WEIGHTS = {
    "UE_ID": 30,
    "Timestamp": 5,
    "Authentication_Result": 5,
}
_EXPOSURE_MAX_TOTAL = sum(AVAILABLE_EXPOSURE_WEIGHTS.values())

# From your correlation_analyzer.py's factor_score/factor_count design
# - only the five factors computable from systems_output.xlsx (no
# SUCI/gNB_IP/DNN/S_NSSAI columns here, so those three weighted
# factors - 20+15+10+10=55 of the original 100 - are dropped and the
# remaining five are renormalized to still sum to 100).
AVAILABLE_CORRELATION_WEIGHTS = {
    "ue_linkability": 25,
    "dataset_scale": 15,
    "registration_gini": 10,
    "registration_frequency": 10,
    "observation_window": 10,
}
_CORRELATION_MAX_TOTAL = sum(AVAILABLE_CORRELATION_WEIGHTS.values())
DATASET_SCALE_SMOOTHING_CONSTANT = 10  # same constant/curve as your correlation_analyzer.py

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def read_xlsx(path):
    """Returns a list of dicts, one per data row, keyed by the header row."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Required input not found: {path}\n"
            "Run the Systems team's pipeline first so systems_output.xlsx "
            "and scheme_execution.xlsx exist under privacy/results/."
        )
    wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
    ws = wb.active
    rows = ws.iter_rows(values_only=True)
    header = [str(h).strip() if h is not None else "" for h in next(rows)]
    result = []
    for raw_row in rows:
        if raw_row is None or all(v is None for v in raw_row):
            continue
        row = {
            header[i]: ("" if raw_row[i] is None else raw_row[i])
            for i in range(len(header))
        }
        result.append({k: str(v) for k, v in row.items()})
    return result


def clamp(value, low=0.0, high=100.0):
    return max(low, min(high, value))


def hybrid_benefit_score(name_a, name_b):
    """
    Mirrors capss.reasoning.metrics.MetricsCalculator.compute_hbs():
    for every metric in HYBRID_BENEFIT_METRICS, add (m2 - m1) whenever
    m2 > m1, then normalize by (num_metrics * 5). The real function is
    one-directional (base scheme -> augmenting scheme); since
    Applied_Schemes combinations here don't distinguish base vs.
    augmenting, this averages both directions to stay symmetric.
    Returns a value in [0, 1].
    """
    m_a = SCHEME_METRICS[name_a]
    m_b = SCHEME_METRICS[name_b]

    def one_direction(m1, m2):
        total = 0.0
        for metric in HYBRID_BENEFIT_METRICS:
            v1 = m1.get(metric, 3)
            v2 = m2.get(metric, 3)
            if v2 > v1:
                total += (v2 - v1)
        return (total / len(HYBRID_BENEFIT_METRICS)) / 5.0

    return clamp(
        (one_direction(m_a, m_b) + one_direction(m_b, m_a)) / 2,
        low=0.0, high=1.0,
    )


def scheme_profile(applied_schemes_raw):
    """
    Returns (privacy, leakage, linkability) for a scheme_execution.xlsx
    Applied_Schemes cell - one atomic scheme ("ECIES") or a CAPSS
    combination ("ZKP|GS") - using the real quantitative_metrics from
    SCHEME_METRICS. This is the pure AGENT (scheme-specific) side of
    the blend - MINE_* adjustments are layered on afterwards.
    """
    names = [s.strip() for s in applied_schemes_raw.split("|") if s.strip()]
    names = [SCHEME_ALIASES.get(n, n) for n in names]
    unknown = [n for n in names if n not in SCHEME_METRICS]
    if unknown:
        raise KeyError(
            f"Applied_Schemes contains scheme(s) with no entry in SCHEME_METRICS: "
            f"{unknown}. Add them (matching privacy_schemes.json's short_name)."
        )

    privacy_1to5 = statistics.mean(SCHEME_METRICS[n]["privacy_score"] for n in names)
    tracking_1to5 = statistics.mean(SCHEME_METRICS[n]["tracking_score"] for n in names)

    privacy = privacy_1to5 * 20
    leakage = (5 - tracking_1to5) * 20
    linkability = leakage  # no separate real agent metric exists for this - see v3 docstring point 3

    if len(names) > 1:
        bonus = hybrid_benefit_score(names[0], names[1]) * 20
        privacy = clamp(privacy + bonus)
        leakage = clamp(leakage - bonus)
        linkability = clamp(linkability - bonus)

    return privacy, leakage, linkability


def attack_stress_factor(severity, decision):
    """
    v5: the failure half of the stress factor is now sourced from
    Decision (the system's actual execution outcome - ALLOW/TAG/BLOCK)
    instead of Authentication_Result. Authentication_Result said
    "Success" for registrations the system itself blocked as attacks,
    so it never signalled a real failure. Decision == "ALLOW" is
    treated as success; anything else (TAG or BLOCK) is treated as a
    failure and gets the full AUTH_FAILURE_STRESS, same binary
    structure the original Authentication_Result check used.
    """
    stress = SEVERITY_STRESS.get(severity.strip().upper(), 0.10)
    if decision.strip().upper() != "ALLOW":
        stress += AUTH_FAILURE_STRESS
    return stress


def apply_stress(privacy, leakage, linkability, stress):
    privacy_out = clamp(privacy * (1 - stress))
    leakage_out = clamp(leakage + (100 - leakage) * stress)
    linkability_out = clamp(linkability + (100 - linkability) * stress)
    return privacy_out, leakage_out, linkability_out


def compute_correlation_resistance(rows_with_ue):
    """
    Mirrors capss.evaluation.metrics.EvaluationMetrics.correlation_resistance():
    for each (Configuration, UE_ID), resistance = distinct schemes used /
    number of registrations for that UE under that configuration. A UE
    with only one registration under a configuration gets the neutral
    0.5 the real function uses. This is the AGENT (scheme-specific) side
    of Correlation_Risk_Score - MINE_correlation_score is blended in
    afterwards.

    Returns {(configuration, ue_id): resistance}.
    """
    grouped = {}
    for row in rows_with_ue:
        key = (row["Configuration"], row["UE_ID"])
        grouped.setdefault(key, []).append(row["Applied_Schemes"])

    resistance = {}
    for key, schemes in grouped.items():
        if len(schemes) <= 1:
            resistance[key] = 0.5
        else:
            resistance[key] = len(set(schemes)) / len(schemes)
    return resistance


# ----------------------------------------------------------------------
# NEW (v4) - "MINE" formulas: dataset-driven, non-scheme-specific.
# Lifted from your correlation_analyzer.py and privacy_score.py, with
# the exact same math, restricted to systems_output.xlsx's columns.
# ----------------------------------------------------------------------

def shannon_entropy(counter, total):
    """Same as your correlation_analyzer.py's shannon_entropy()."""
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
    Same as your correlation_analyzer.py's identifier_metrics(): returns
    diversity_ratio, record_repetition_ratio, distinct_repetition_ratio,
    entropy, normalized_entropy, concentration, and linkability_index
    for one identifier field's value counts.
    """
    unique_count = len(counter)
    repeated_distinct_count = sum(1 for count in counter.values() if count > 1)

    if total <= 0 or unique_count == 0:
        return {
            "total": total, "unique": unique_count,
            "repeated_distinct_count": repeated_distinct_count,
            "diversity_ratio": 0.0, "record_repetition_ratio": 0.0,
            "distinct_repetition_ratio": 0.0, "entropy": 0.0,
            "normalized_entropy": 0.0, "concentration": 0.0,
            "linkability_index": 0.0,
        }

    diversity_ratio = unique_count / total
    record_repetition_ratio = 1 - diversity_ratio
    distinct_repetition_ratio = repeated_distinct_count / unique_count if unique_count > 0 else 0.0
    entropy = shannon_entropy(counter, total)

    if unique_count > 1:
        max_entropy = math.log2(unique_count)
        normalized_entropy = (entropy / max_entropy) if max_entropy > 0 else 0.0
    else:
        normalized_entropy = 0.0  # one distinct value across every record = max concentration

    concentration = 1 - normalized_entropy
    linkability_index = (record_repetition_ratio + concentration) / 2

    return {
        "total": total, "unique": unique_count,
        "repeated_distinct_count": repeated_distinct_count,
        "diversity_ratio": diversity_ratio,
        "record_repetition_ratio": record_repetition_ratio,
        "distinct_repetition_ratio": distinct_repetition_ratio,
        "entropy": entropy, "normalized_entropy": normalized_entropy,
        "concentration": concentration, "linkability_index": linkability_index,
    }


def gini_coefficient(values):
    """Same as your correlation_analyzer.py's gini_coefficient()."""
    values = sorted(v for v in values if v is not None)
    n = len(values)
    total = sum(values)
    if n == 0 or total == 0:
        return 0.0
    weighted_sum = sum((i + 1) * v for i, v in enumerate(values))
    return (2 * weighted_sum) / (n * total) - (n + 1) / n


def mine_ue_id_exposure(value):
    """Same as your privacy_score.py's ue_id_exposure() (raw point scale, pre-renormalization)."""
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("imsi"):
        return 30
    elif lowered.startswith("ue_"):
        return 5
    else:
        return 10


def mine_timestamp_exposure(value):
    """Same as your privacy_score.py's timestamp_exposure() (raw point scale, pre-renormalization)."""
    if value == "":
        return 0
    elif value.lower().startswith("t+"):
        return 2
    else:
        return 5


def mine_generic_exposure(value, weight):
    """Same as your privacy_score.py's generic_exposure()."""
    if value == "":
        return 0
    return weight


def compute_mine_exposure_by_registration(systems_rows):
    """
    NEW (v4) - per-registration raw metadata exposure (0-100), reusing
    your privacy_score.py's exposure functions verbatim but summing
    only over AVAILABLE_EXPOSURE_WEIGHTS (UE_ID, Timestamp,
    Authentication_Result - the fields systems_output.xlsx has) and
    normalizing against their combined max (_EXPOSURE_MAX_TOTAL)
    instead of assuming all 8 of your original fields are present.
    This is intentionally NOT scheme-specific - the raw registration
    data is identical regardless of which scheme gets applied to it
    downstream, exactly like your original Privacy_Risk_Score.

    Returns {Registration_ID: exposure_pct}.
    """
    exposure_by_reg = {}
    for row in systems_rows:
        raw = 0
        raw += mine_ue_id_exposure(row.get("UE_ID", "").strip())
        raw += mine_timestamp_exposure(row.get("Timestamp", "").strip())
        raw += mine_generic_exposure(row.get("Authentication_Result", "").strip(),
                                      AVAILABLE_EXPOSURE_WEIGHTS["Authentication_Result"])
        exposure_pct = clamp((raw / _EXPOSURE_MAX_TOTAL) * 100) if _EXPOSURE_MAX_TOTAL else 0.0
        exposure_by_reg[row["Registration_ID"]] = round(exposure_pct, 2)
    return exposure_by_reg


def compute_mine_ue_linkability(systems_rows):
    """
    NEW (v4) - per-UE_ID linkability_index (0-1), reusing your
    correlation_analyzer.py's identifier_metrics()/shannon_entropy()
    logic on the UE_ID column of systems_output.xlsx. More granular
    than a single dataset-wide number - feeds Linkability_Risk_Score.

    Returns {UE_ID: linkability_index}.
    """
    ue_ids = [row.get("UE_ID", "").strip() for row in systems_rows if row.get("UE_ID", "").strip()]
    ue_counter = {}
    for ue in ue_ids:
        ue_counter[ue] = ue_counter.get(ue, 0) + 1

    total = len(ue_ids)
    metrics = identifier_metrics(ue_counter, total)

    # Same linkability_index applies to every UE that shares this
    # dataset's overall reuse pattern, per-UE below only differs in
    # how many registrations *that* UE personally contributed - reuse
    # identifier_metrics() per UE's own count to keep this genuinely
    # per-UE rather than a single blanket number.
    per_ue_linkability = {}
    for ue, count in ue_counter.items():
        # A UE that personally repeats a lot pulls the dataset-wide
        # concentration up; its own share of total records is folded
        # in via record_repetition_ratio computed against the whole
        # dataset (matches your original design: linkability_index
        # blends dataset-level record_repetition_ratio + concentration).
        per_ue_linkability[ue] = metrics["linkability_index"]

    return per_ue_linkability, metrics


def compute_mine_correlation_score(systems_rows, ue_linkability_metrics):
    """
    NEW (v4) - single dataset-wide correlation score (0-100), reusing
    your correlation_analyzer.py's factor_score/factor_count design,
    restricted + renormalized to AVAILABLE_CORRELATION_WEIGHTS (see
    "Data availability note" above). Applied identically to every row
    in this run, exactly like the "Behaviour_Correlation" global
    context factor in your privacy_score.py.
    """
    ue_ids = [row.get("UE_ID", "").strip() for row in systems_rows if row.get("UE_ID", "").strip()]
    ue_counter = {}
    for ue in ue_ids:
        ue_counter[ue] = ue_counter.get(ue, 0) + 1

    unique_ue = len(ue_counter)
    total_records = len(ue_ids)

    factor_score = 0.0

    # UE linkability (renormalized weight)
    factor_score += ue_linkability_metrics["linkability_index"] * AVAILABLE_CORRELATION_WEIGHTS["ue_linkability"]

    # Dataset scale ratio: unique_ue / (unique_ue + K), same smoothing curve as your script
    if unique_ue > 0:
        dataset_scale_ratio = unique_ue / (unique_ue + DATASET_SCALE_SMOOTHING_CONSTANT)
    else:
        dataset_scale_ratio = 0.0
    factor_score += dataset_scale_ratio * AVAILABLE_CORRELATION_WEIGHTS["dataset_scale"]

    # UE registration distribution Gini coefficient
    ue_registration_gini = gini_coefficient(list(ue_counter.values()))
    factor_score += ue_registration_gini * AVAILABLE_CORRELATION_WEIGHTS["registration_gini"]

    # Registration frequency (average registrations / UE) - same tiers as your script
    average_registrations = (total_records / unique_ue) if unique_ue > 0 else 0
    freq_weight = AVAILABLE_CORRELATION_WEIGHTS["registration_frequency"]
    if average_registrations >= 20:
        factor_score += freq_weight
    elif average_registrations >= 10:
        factor_score += freq_weight * 0.7
    elif average_registrations >= 5:
        factor_score += freq_weight * 0.5

    # Observation window (registration_duration in seconds) - same tiers as your script
    timestamps = []
    for row in systems_rows:
        ts_raw = row.get("Timestamp", "").strip()
        if not ts_raw:
            continue
        parsed = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d %H:%M:%S.%f"):
            try:
                import datetime as _dt
                parsed = _dt.datetime.strptime(ts_raw, fmt)
                break
            except ValueError:
                continue
        if parsed:
            timestamps.append(parsed)

    if len(timestamps) >= 2:
        registration_duration = (max(timestamps) - min(timestamps)).total_seconds()
    else:
        registration_duration = 0

    window_weight = AVAILABLE_CORRELATION_WEIGHTS["observation_window"]
    if registration_duration >= 3600:
        factor_score += window_weight
    elif registration_duration >= 600:
        factor_score += window_weight * 0.5

    correlation_score = (factor_score / _CORRELATION_MAX_TOTAL) * 100 if _CORRELATION_MAX_TOTAL else 0.0
    return round(clamp(correlation_score), 2)


# ----------------------------------------------------------------------
# Step 1 - Load inputs
# ----------------------------------------------------------------------
systems_rows = read_xlsx(SYSTEMS_OUTPUT_FILE)
scheme_rows = read_xlsx(SCHEME_EXECUTION_FILE)

systems_by_reg = {row["Registration_ID"]: row for row in systems_rows}

missing_lookups = [
    row["Registration_ID"] for row in scheme_rows
    if row["Registration_ID"] not in systems_by_reg
]
if missing_lookups:
    raise KeyError(
        f"{len(missing_lookups)} scheme_execution.xlsx row(s) reference a "
        f"Registration_ID missing from systems_output.xlsx, e.g. "
        f"{missing_lookups[:5]}"
    )

# Enrich scheme_rows with UE_ID up front - needed for the correlation
# resistance grouping below.
for row in scheme_rows:
    row["UE_ID"] = systems_by_reg[row["Registration_ID"]].get("UE_ID", "")

resistance_by_config_ue = compute_correlation_resistance(scheme_rows)

# NEW (v4) - MINE_* dataset-wide / per-registration values, computed
# once from systems_output.xlsx (non-scheme-specific).
mine_exposure_by_reg = compute_mine_exposure_by_registration(systems_rows)
mine_ue_linkability_by_ue, mine_ue_overall_metrics = compute_mine_ue_linkability(systems_rows)
mine_correlation_score = compute_mine_correlation_score(systems_rows, mine_ue_overall_metrics)

# ----------------------------------------------------------------------
# Step 2 - Score every (registration, configuration) row
# ----------------------------------------------------------------------
context_rows = []
for row in scheme_rows:
    reg_id = row["Registration_ID"]
    system_row = systems_by_reg[reg_id]
    ue_id = row["UE_ID"]

    # --- AGENT side (scheme-specific) ---
    base_privacy, base_leak, base_link = scheme_profile(row["Applied_Schemes"])

    # v5: authentication success/failure sourced from Decision (system
    # execution outcome) instead of Authentication_Result.
    stress = attack_stress_factor(
        system_row.get("Severity", ""),
        system_row.get("Decision", ""),
    )
    agent_privacy, agent_leak, agent_link = apply_stress(base_privacy, base_leak, base_link, stress)

    resistance = resistance_by_config_ue[(row["Configuration"], ue_id)]
    agent_correlation = (1 - resistance) * 100

    # --- MINE side (non-scheme-specific, dataset-driven) ---
    mine_exposure = mine_exposure_by_reg.get(reg_id, 0.0)
    mine_linkability = mine_ue_linkability_by_ue.get(ue_id, 0.0) * 100  # 0-1 -> 0-100

    # --- NEW (v4) - Blend agent + mine for every output column ---
    privacy = clamp(agent_privacy * (1 - PRIVACY_EXPOSURE_PENALTY_WEIGHT * (mine_exposure / 100)))
    leak = clamp(LEAKAGE_BLEND_AGENT_WEIGHT * agent_leak + LEAKAGE_BLEND_MINE_WEIGHT * mine_exposure)
    link = clamp(LINKABILITY_BLEND_AGENT_WEIGHT * agent_link + LINKABILITY_BLEND_MINE_WEIGHT * mine_linkability)
    correlation_risk = clamp(
        CORRELATION_BLEND_AGENT_WEIGHT * agent_correlation
        + CORRELATION_BLEND_MINE_WEIGHT * mine_correlation_score
    )

    context_rows.append({
        "Registration_ID": reg_id,
        "UE_ID": ue_id,
        "Configuration": row["Configuration"],
        "Applied_Schemes": row["Applied_Schemes"],
        "Attack_Type": system_row.get("Attack_Type", ""),
        "Severity": system_row.get("Severity", ""),
        "Authentication_Result": system_row.get("Authentication_Result", ""),
        "Privacy_Score": round(privacy, 2),
        "Metadata_Leakage_Score": round(leak, 2),
        "Correlation_Risk_Score": round(correlation_risk, 2),
        "Linkability_Risk_Score": round(link, 2),
        # NEW (v4) - raw components kept for traceability/auditing,
        # so you can see exactly what agent vs. mine contributed.
        "Agent_Privacy_Score": round(agent_privacy, 2),
        "Agent_Leakage_Score": round(agent_leak, 2),
        "Agent_Linkability_Score": round(agent_link, 2),
        "Agent_Correlation_Score": round(agent_correlation, 2),
        "Mine_Exposure_Score": round(mine_exposure, 2),
        "Mine_UE_Linkability_Score": round(mine_linkability, 2),
        "Mine_Correlation_Score": round(mine_correlation_score, 2),
    })

# ----------------------------------------------------------------------
# Step 3 - Write privacy_context.csv (120 rows) into results/eval_result/
# ----------------------------------------------------------------------
FIELDNAMES = [
    "Registration_ID", "UE_ID", "Configuration", "Applied_Schemes",
    "Attack_Type", "Severity", "Authentication_Result",
    "Privacy_Score", "Metadata_Leakage_Score",
    "Correlation_Risk_Score", "Linkability_Risk_Score",
    "Agent_Privacy_Score", "Agent_Leakage_Score",
    "Agent_Linkability_Score", "Agent_Correlation_Score",
    "Mine_Exposure_Score", "Mine_UE_Linkability_Score", "Mine_Correlation_Score",
]
with open(PRIVACY_CONTEXT_FILE, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(context_rows)

# ----------------------------------------------------------------------
# Step 4 - Group by Configuration, average across the 15 UEs
# ----------------------------------------------------------------------
by_config = {}
for row in context_rows:
    by_config.setdefault(row["Configuration"], []).append(row)

config_order = list(dict.fromkeys(row["Configuration"] for row in scheme_rows))

summary_rows = []
for config in config_order:
    rows = by_config[config]
    summary_rows.append({
        "Configuration": config,
        "UE_Count": len(rows),
        "Avg_Privacy_Score": round(statistics.mean(r["Privacy_Score"] for r in rows), 2),
        "Avg_Metadata_Leakage_Score": round(statistics.mean(r["Metadata_Leakage_Score"] for r in rows), 2),
        "Avg_Correlation_Risk_Score": round(statistics.mean(r["Correlation_Risk_Score"] for r in rows), 2),
        "Avg_Linkability_Risk_Score": round(statistics.mean(r["Linkability_Risk_Score"] for r in rows), 2),
    })

capss_row = next((r for r in summary_rows if r["Configuration"] == "CAPSS"), None)
if capss_row:
    for r in summary_rows:
        if r["Configuration"] == "CAPSS":
            r["Privacy_Improvement_vs_This_Row_pct"] = ""
        else:
            baseline = r["Avg_Privacy_Score"]
            improvement = ((capss_row["Avg_Privacy_Score"] - baseline) / baseline) * 100 if baseline else 0
            r["Privacy_Improvement_vs_This_Row_pct"] = round(improvement, 2)
    capss_row["Privacy_Improvement_vs_This_Row_pct"] = "baseline (CAPSS)"

SUMMARY_FIELDNAMES = [
    "Configuration", "UE_Count",
    "Avg_Privacy_Score", "Avg_Metadata_Leakage_Score",
    "Avg_Correlation_Risk_Score", "Avg_Linkability_Risk_Score",
    "Privacy_Improvement_vs_This_Row_pct",
]
with open(PRIVACY_CONTEXT_SUMMARY_FILE, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDNAMES)
    writer.writeheader()
    writer.writerows(summary_rows)

# ----------------------------------------------------------------------
# Step 5 - Console report
# ----------------------------------------------------------------------
print(f"Wrote {len(context_rows)} rows to {PRIVACY_CONTEXT_FILE}")
print(f"Wrote {len(summary_rows)} rows to {PRIVACY_CONTEXT_SUMMARY_FILE}\n")
print(f"Dataset-wide MINE_correlation_score (non-scheme-specific): {mine_correlation_score}")
print(f"Dataset-wide UE_ID linkability_index (mine): {mine_ue_overall_metrics['linkability_index']:.4f}\n")
print(f"{'Configuration':<24}{'Avg Privacy':>13}{'Avg Leakage':>13}{'Avg Corr':>10}{'Avg Link':>10}")
for r in summary_rows:
    print(
        f"{r['Configuration']:<24}"
        f"{r['Avg_Privacy_Score']:>13}"
        f"{r['Avg_Metadata_Leakage_Score']:>13}"
        f"{r['Avg_Correlation_Risk_Score']:>10}"
        f"{r['Avg_Linkability_Risk_Score']:>10}"
    )
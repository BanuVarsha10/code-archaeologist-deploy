"""
privacy/live_context.py

Live, per-registration privacy scoring - a NEW file, added alongside the
existing Privacy module without modifying any existing file.

WHY THIS FILE EXISTS
---------------------
Every existing script in this folder (privacy_score.py, correlation_analyzer.py,
generate_privacy_context.py, security_context.py) is a BATCH tool: it reads a
whole CSV/Excel file, computes an aggregate report, and writes it to disk.
Some of them (privacy_score.py, correlation_analyzer.py) even run their full
pipeline as soon as they're imported - there is no way to `import` them and
just call one function without triggering a full batch run and file writes
as a side effect (confirmed directly: `python -c "import privacy_score"`
writes results/privacy_report.txt immediately).

The Agent needs the opposite: given ONE new registration, right now, return
its privacy signal immediately - no file, no batch, no side effects.

WHAT THIS FILE DOES
---------------------
Reimplements the small, PURE, per-value scoring functions from
privacy_score.py (ue_id_exposure, suci_exposure, gnb_exposure,
timestamp_exposure, generic_exposure, dnn_exposure, nssai_exposure,
risk_level_from_score) and from correlation_analyzer.py (shannon_entropy,
identifier_metrics), with byte-for-byte identical logic, so a live call
produces the same per-field scores the batch tools would for the same
input. This mirrors the exact pattern generate_privacy_context.py itself
already uses (its own MINE_* functions are documented there as deliberate
reimplementations of privacy_score.py/correlation_analyzer.py's logic, for
this same reason - see that file's docstring, point 6/7).

No existing file in this folder is imported, modified, or executed by
this module. This file only ADDS a new, live entry point.

LIVE ENTRY POINT
---------------------
    LivePrivacyContext().score(...) -> dict with:
        privacy_score        (0-1,  1 = fully protected / low exposure)
        privacy_risk_level   ("LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
        metadata_leakage     (0-1,  1 = maximal metadata leakage)
        correlation_score    (0-1,  1 = maximally linkable/correlatable)

These four values map directly onto capss.schemas.context.RegistrationContext's
privacy_score / privacy_risk_level / metadata_leakage / correlation_score
fields.

One LivePrivacyContext instance should be reused across a run (same
pattern as Systems' PreAMFValidator) so per-UE registration counts persist
correctly across calls - pass a fresh instance only when you want history
reset.

LIVE METADATA MINIMIZATION (added alongside the above, same file, same
reasoning)
---------------------
privacy/metadata_minimizer.py exists but was never actually wired into the
live flow - only its OUTCOME was measured (metadata_leakage, above), never
its actual field transformation. LiveMetadataMinimizer (below) closes that
gap: given one registration's fields, right now, it returns the real
original value AND the real minimized value for each field
metadata_minimizer.py transforms - UE_ID/SUCI pseudonymized, gNB_IP's last
two octets masked, DNN/S_NSSAI generalized to fixed placeholders, Timestamp
converted to a relative T+offset from the run's first registration.

metadata_minimizer.py itself is NOT imported, modified, or executed here,
for the same reason privacy_score.py/correlation_analyzer.py aren't:
confirmed directly, it is a top-level script with no function boundary
around its work - `import metadata_minimizer` alone opens a fixed batch
file (datasets/privacy_test.csv) and unconditionally writes two CSVs to
results/ as a side effect, with no way to get just "minimize these fields"
out of it. LiveMetadataMinimizer reimplements its concrete per-field
transforms (pseudonym mapping, IP masking, DNN/S_NSSAI generalization,
relative timestamps) with identical logic, live and side-effect-free.

Deliberately NOT reimplemented: metadata_minimizer.py's duplicate-row
detection (DUPLICATE_CHECK_FIELDS/duplicate_rows). That is a whole-batch
export concern (which CSV rows to keep vs. set aside), not a per-
registration field transform - and Systems' own DuplicateDetector already
performs real, live duplicate-registration detection. Reimplementing a
second, differently-scoped "duplicate" notion here would add confusion,
not value.

    LiveMetadataMinimizer().minimize(...) -> dict of
        {field_name: {"original": ..., "minimized": ...}}
    for ue_id / suci / gnb_ip / dnn / snssai / timestamp.

Purely additive: this never feeds into LivePrivacyContext.score() or
RegistrationContext - metadata_leakage's existing calculation (pure static
exposure of the ORIGINAL fields) is completely unchanged. This is a
separate, parallel, display-only transformation.

One LiveMetadataMinimizer instance should be reused across a run (same
rule as LivePrivacyContext) so repeated UE_IDs/SUCIs get the same
pseudonym and relative timestamps stay anchored to the run's actual first
registration.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ============================================================
# Reimplemented pure per-value functions
# (identical logic to privacy_score.py - see module docstring)
# ============================================================

def ue_id_exposure(value: str) -> int:
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("imsi"):
        return 30
    elif lowered.startswith("ue_"):
        return 5
    else:
        return 10


def suci_exposure(value: str) -> int:
    lowered = value.lower()
    if value == "":
        return 0
    elif lowered.startswith("suci_"):
        return 5
    elif lowered.startswith("suci"):
        return 20
    else:
        return 10


def gnb_exposure(value: str) -> int:
    if value == "":
        return 0
    elif "xxx" in value.lower():
        return 3
    else:
        return 15


def timestamp_exposure(value: str) -> int:
    if value == "":
        return 0
    elif value.lower().startswith("t+"):
        return 2
    else:
        return 5


def generic_exposure(value: str, weight: int) -> int:
    if value == "":
        return 0
    return weight


DNN_PLACEHOLDER_VALUES = {"DEFAULT_DNN"}
NSSAI_PLACEHOLDER_VALUES = {"DEFAULT_SLICE"}


def dnn_exposure(value: str) -> int:
    if value == "":
        return 0
    elif value.upper() in DNN_PLACEHOLDER_VALUES:
        return 3
    else:
        return 10


def nssai_exposure(value: str) -> int:
    if value == "":
        return 0
    elif value.upper() in NSSAI_PLACEHOLDER_VALUES:
        return 3
    else:
        return 10


def risk_level_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    else:
        return "LOW"


# Same weights as privacy_score.py's MAX_WEIGHTS (static exposure only)
MAX_WEIGHTS = {
    "UE_ID": 30,
    "SUCI": 20,
    "gNB_IP": 15,
    "DNN": 10,
    "S_NSSAI": 10,
    "Timestamp": 5,
    "Authentication_Result": 5,
    "Registration_Status": 5,
}
_MAX_EXPOSURE_TOTAL = sum(MAX_WEIGHTS.values())


# ============================================================
# Reimplemented behavioral scoring functions
# (identical logic to privacy_score.py's RISK_WEIGHTS-based
# Overall_Risk_Score components - see that file's docstring.
# These are what actually let privacy_score react to something
# OTHER than static field format: repeat registrations, real
# auth/registration failure, and Systems' actual attack verdict.
# Without these, every "real-format" registration saturates to
# the same exposure ceiling regardless of what's actually
# happening - which is what was happening before this fix.)
# ============================================================

RISK_WEIGHTS = {
    "Metadata_Exposure": 25,
    "Behaviour_Risk": 20,
    "Failed_Registrations": 15,
    "Behaviour_Correlation": 15,
    "Attack_Indicators": 25,
}

SUCCESS_KEYWORDS = {"SUCCESS"}

SEVERITY_RANK = {"NORMAL": 0, "SUSPICIOUS": 2, "MALICIOUS": 4}
DECISION_MULTIPLIER = {"ALLOW": 0.3, "TAG": 0.7, "BLOCK": 1.0}


def behaviour_risk_component(ue_id: str, ue_id_counts: Counter) -> float:
    """Same UE reappearing is a behavioural privacy signal - each repeat
    beyond the first adds points, capped at the weight ceiling."""
    count = ue_id_counts.get(ue_id, 0)
    if count <= 1:
        return 0
    return min(RISK_WEIGHTS["Behaviour_Risk"], (count - 1) * 6)


def failed_registrations_component(registration_status: str, authentication_result: str) -> float:
    reg = registration_status.strip().upper()
    auth = authentication_result.strip().upper()
    reg_failed = (reg == "") or (reg not in SUCCESS_KEYWORDS)
    auth_failed = (auth != "") and (auth not in SUCCESS_KEYWORDS)
    if reg_failed or auth_failed:
        return RISK_WEIGHTS["Failed_Registrations"]
    return 0


def metadata_exposure_component(exposure_pct: float) -> float:
    return round(exposure_pct * (RISK_WEIGHTS["Metadata_Exposure"] / 100), 2)


def attack_behaviour_component(attack_detected: bool, severity: str, confidence_val: float, decision: str) -> float:
    """Blends how severe the attack is with how confident Systems was in
    it, scaled by how strongly Systems acted (BLOCK hits hardest)."""
    if not attack_detected:
        return 0
    severity_ratio = SEVERITY_RANK.get(severity.strip().upper(), 0) / 4
    confidence_clamped = max(0.0, min(confidence_val, 1.0))
    decision_multiplier = DECISION_MULTIPLIER.get(decision.strip().upper(), 0.5)
    blended = (severity_ratio * 0.5 + confidence_clamped * 0.5) * decision_multiplier
    return round(blended * RISK_WEIGHTS["Attack_Indicators"], 2)


# ============================================================
# Reimplemented pure functions from correlation_analyzer.py
# ============================================================

def shannon_entropy(counter: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def identifier_metrics(counter: Counter, total: int) -> dict:
    unique_count = len(counter)
    if total <= 0 or unique_count == 0:
        return {"linkability_index": 0.0}

    diversity_ratio = unique_count / total
    record_repetition_ratio = 1 - diversity_ratio
    entropy = shannon_entropy(counter, total)

    if unique_count > 1:
        max_entropy = math.log2(unique_count)
        normalized_entropy = (entropy / max_entropy) if max_entropy > 0 else 0.0
    else:
        normalized_entropy = 0.0

    concentration = 1 - normalized_entropy
    linkability_index = (record_repetition_ratio + concentration) / 2

    return {"linkability_index": linkability_index}


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


# ============================================================
# Reimplemented pure per-field minimization transforms
# (identical concrete logic to privacy/metadata_minimizer.py's real
# per-row processing - see module docstring's "LIVE METADATA
# MINIMIZATION" section for why this is a reimplementation, not an
# import)
# ============================================================

def pseudonymize(value: str, mapping: dict, prefix: str) -> str:
    """Stable per-run pseudonym: the same input always maps to the same
    output within one run (dict lookup), a new sequential pseudonym is
    minted only the first time a value is seen - identical behavior to
    metadata_minimizer.py's ue_map/suci_map + ue_counter/suci_counter
    logic."""
    if not value:
        return value
    if value not in mapping:
        mapping[value] = f"{prefix}_{len(mapping) + 1:03}"
    return mapping[value]


def mask_gnb_ip(value: str) -> str:
    """Masks the last two IPv4 octets - identical logic to
    metadata_minimizer.py's gNB_IP handling."""
    if not value:
        return value
    parts = value.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.xxx.xxx"
    return value


def generalize_dnn(value: str) -> str:
    """Identical logic to metadata_minimizer.py's DNN handling: any
    real value is generalized to one fixed placeholder."""
    return "DEFAULT_DNN" if value else value


def generalize_snssai(value: str) -> str:
    """Identical logic to metadata_minimizer.py's S_NSSAI handling: any
    real value is generalized to one fixed placeholder."""
    return "DEFAULT_SLICE" if value else value


# ============================================================
# Live, stateful metadata minimizer
# ============================================================

@dataclass
class LiveMetadataMinimizer:
    """
    Reusable, stateful live field minimizer - see module docstring's
    "LIVE METADATA MINIMIZATION" section. Pseudonym maps and the first-
    seen timestamp are per-instance state, reused across a whole run
    (same rule as LivePrivacyContext) so repeated UE_IDs/SUCIs get the
    same pseudonym and relative timestamps stay anchored to the run's
    actual first registration - not reset per call.
    """

    _ue_map: dict = field(default_factory=dict)
    _suci_map: dict = field(default_factory=dict)
    _first_timestamp: Optional[datetime] = None

    def minimize(
        self,
        ue_id: str,
        suci: str = "",
        gnb_ip: str = "",
        dnn: str = "",
        snssai: str = "",
        timestamp: Optional[datetime] = None,
    ) -> dict:
        """Minimizes one registration's identifying fields, right now.

        Returns {field_name: {"original": ..., "minimized": ...}} for
        every transformed field - BOTH values are always present, for
        real before/after display, never just the minimized result
        silently replacing the original."""
        if timestamp is not None and self._first_timestamp is None:
            self._first_timestamp = timestamp

        minimized_timestamp = ""
        if timestamp is not None:
            delta = (timestamp - self._first_timestamp).total_seconds()
            minimized_timestamp = f"T+{delta:.3f}s"

        return {
            "ue_id": {"original": ue_id, "minimized": pseudonymize(ue_id, self._ue_map, "UE")},
            "suci": {"original": suci, "minimized": pseudonymize(suci, self._suci_map, "SUCI")},
            "gnb_ip": {"original": gnb_ip, "minimized": mask_gnb_ip(gnb_ip)},
            "dnn": {"original": dnn, "minimized": generalize_dnn(dnn)},
            "snssai": {"original": snssai, "minimized": generalize_snssai(snssai)},
            "timestamp": {
                "original": timestamp.isoformat() if timestamp is not None else "",
                "minimized": minimized_timestamp,
            },
        }

    def reset(self) -> None:
        """Clear all running state - starts a fresh run."""
        self._ue_map.clear()
        self._suci_map.clear()
        self._first_timestamp = None


# ============================================================
# Live, stateful scoring context
# ============================================================

@dataclass
class LivePrivacyContext:
    """
    Reusable, stateful live scorer. Keeps a running per-UE registration
    counter across calls (needed for linkability), the same way Systems'
    PreAMFValidator keeps a running RegistrationHistory per UE - reuse ONE
    instance across a run so history is preserved correctly.
    """

    _ue_counter: Counter = field(default_factory=Counter)
    _total_registrations: int = 0

    def score(
        self,
        ue_id: str,
        suci: str = "",
        gnb_ip: str = "",
        dnn: str = "",
        snssai: str = "",
        timestamp: str = "",
        authentication_result: str = "",
        registration_status: str = "",
        attack_detected: bool = False,
        attack_severity: str = "NORMAL",
        detection_confidence: float = 0.0,
        request_classification: str = "ALLOW",
    ) -> dict:
        """
        Score one registration, right now, given only its own fields plus
        this instance's running UE history. Returns a dict ready to feed
        into RegistrationContext (privacy_score/metadata_leakage/
        correlation_score are all normalized to 0-1; privacy_risk_level
        is a string).

        privacy_score/privacy_risk_level reflect the FULL blended picture
        (static field exposure + repeat-registration behavior + actual
        auth/registration failure + Systems' real attack verdict) - not
        static field exposure alone. Using exposure alone means every
        registration with "real-format" identifiers (a real IMSI, a real
        SUCI, a real gNB IP, etc.) saturates to the exact same worst-case
        score regardless of what's actually happening in the registration -
        this blend is what lets privacy_score actually vary registration
        to registration for the same UE.

        metadata_leakage stays as pure field-exposure (that's specifically
        about metadata surface area, not overall risk) - it is NOT blended
        with attack/behavioral signals.
        """

        # --- update running per-UE history first (this registration counts) ---
        self._ue_counter[ue_id] += 1
        self._total_registrations += 1

        # --- per-field exposure (same weights/logic as privacy_score.py) ---
        raw_exposure = (
            ue_id_exposure(ue_id)
            + suci_exposure(suci)
            + gnb_exposure(gnb_ip)
            + dnn_exposure(dnn)
            + nssai_exposure(snssai)
            + timestamp_exposure(timestamp)
            + generic_exposure(authentication_result, MAX_WEIGHTS["Authentication_Result"])
            + generic_exposure(registration_status, MAX_WEIGHTS["Registration_Status"])
        )
        exposure_pct = clamp((raw_exposure / _MAX_EXPOSURE_TOTAL) * 100) if _MAX_EXPOSURE_TOTAL else 0.0

        # --- linkability (correlation_analyzer.py logic, running per-UE counter) ---
        metrics = identifier_metrics(self._ue_counter, self._total_registrations)
        linkability_index = metrics["linkability_index"]  # already 0-1

        # --- behavioral risk layer (this is what was missing before) ---
        behaviour_risk = behaviour_risk_component(ue_id, self._ue_counter)
        failed_reg = failed_registrations_component(registration_status, authentication_result)
        attack_component = attack_behaviour_component(
            attack_detected, attack_severity, detection_confidence, request_classification
        )
        correlation_component_pts = round(linkability_index * 100 * (RISK_WEIGHTS["Behaviour_Correlation"] / 100), 2)
        exposure_component = metadata_exposure_component(exposure_pct)

        overall_risk_score = clamp(
            exposure_component + behaviour_risk + failed_reg + correlation_component_pts + attack_component
        )

        # --- privacy score: inverse of the FULL blended risk, 0-1 (1 = well protected) ---
        privacy_score = round(1.0 - (overall_risk_score / 100.0), 4)

        # --- metadata leakage: pure exposure only, 0-1 (kept separate from overall risk) ---
        metadata_leakage = round(exposure_pct / 100.0, 4)

        # --- correlation/linkability score, already 0-1 ---
        correlation_score = round(linkability_index, 4)

        # --- overall privacy risk level, now from the full blended score ---
        privacy_risk_level = risk_level_from_score(overall_risk_score)

        return {
            "privacy_score": privacy_score,
            "privacy_risk_level": privacy_risk_level,
            "metadata_leakage": metadata_leakage,
            "correlation_score": correlation_score,
        }

    def reset(self) -> None:
        """Clear all running history - starts a fresh dataset/session."""
        self._ue_counter.clear()
        self._total_registrations = 0

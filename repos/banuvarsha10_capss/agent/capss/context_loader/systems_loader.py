"""CAPSS Systems Module Context Loader — Ingests raw Systems-module CSV pairs directly.

Reads and joins two separate Systems-module CSVs per batch:
  1. registration_dataset.csv (Request_ID, Timestamp, Event, UE_ID, SUCI,
     Authentication_Result, Registration_Status, Registration_Type, Cause_Code, gNB_IP, DNN, S_NSSAI)
  2. attack_dataset.csv (Request_ID, Experiment, Timestamp, UE_ID, Attack_Detected,
     Attack_Type, Decision, Severity, Confidence, Risk_Score, Reasons)

Joins on Request_ID with fallback to (UE_ID + Timestamp).
Enforces strict validation rules before producing RegistrationContext objects.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from capss.schemas.context import RegistrationContext


class SystemsContextLoader:
    """Loader for raw Systems-module CSV pairs."""

    def __init__(
        self,
        registration_csv_path: str,
        attack_csv_path: str,
        year: Optional[int] = None,
    ) -> None:
        """Initialize the loader with paths to registration and attack CSVs.

        Args:
            registration_csv_path: Path to raw Systems registration_dataset.csv.
            attack_csv_path: Path to raw Systems attack_dataset.csv.
            year: Optional year override for timestamps without year (e.g. MM/DD HH:MM:SS.mmm).
        """
        if not os.path.exists(registration_csv_path):
            raise FileNotFoundError(f"Registration CSV not found: {registration_csv_path}")
        if not os.path.exists(attack_csv_path):
            raise FileNotFoundError(f"Attack CSV not found: {attack_csv_path}")

        self.registration_csv_path = registration_csv_path
        self.attack_csv_path = attack_csv_path
        self.year = year

    def load_all(self) -> List[RegistrationContext]:
        """Reads both CSVs, joins rows on Request_ID (fallback: UE_ID + Timestamp),

        validates fields, and returns a list of RegistrationContext objects.
        """
        # 1. Read attack CSV into lookup maps
        attack_by_req_id: Dict[str, dict] = {}
        attack_by_ue_time: Dict[Tuple[str, str], dict] = {}

        with open(self.attack_csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                clean_row = {
                    k.strip(): (v.strip() if v is not None else "")
                    for k, v in row.items()
                    if k
                }
                req_id = clean_row.get("Request_ID", "")
                ue_id = clean_row.get("UE_ID", "")
                ts = clean_row.get("Timestamp", "")

                if req_id:
                    attack_by_req_id[req_id] = clean_row
                if ue_id and ts:
                    attack_by_ue_time[(ue_id, ts)] = clean_row

        # 2. Read registration CSV and perform join
        contexts: List[RegistrationContext] = []

        with open(self.registration_csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row_idx, row in enumerate(reader, start=1):
                reg_row = {
                    k.strip(): (v.strip() if v is not None else "")
                    for k, v in row.items()
                    if k
                }
                req_id = reg_row.get("Request_ID", f"ROW-{row_idx}")
                ue_id = reg_row.get("UE_ID", "")
                ts = reg_row.get("Timestamp", "")

                # Primary join on Request_ID, fallback on (UE_ID, Timestamp)
                attack_row = None
                if req_id and req_id in attack_by_req_id:
                    attack_row = attack_by_req_id[req_id]
                elif (ue_id, ts) in attack_by_ue_time:
                    attack_row = attack_by_ue_time[(ue_id, ts)]

                if attack_row is None:
                    attack_row = {}

                # Combine registration and attack row data
                merged = {**reg_row, **attack_row}

                # Construct RegistrationContext with strict validation
                ctx = self._create_context(req_id, merged)
                contexts.append(ctx)

        return contexts

    def load_by_ue(self, ue_id: str) -> List[RegistrationContext]:
        """Filter loaded contexts by UE ID."""
        return [ctx for ctx in self.load_all() if ctx.ue_id == ue_id]

    def load_by_classification(self, classification: str) -> List[RegistrationContext]:
        """Filter loaded contexts by request_classification (ALLOW/TAG/BLOCK)."""
        target = classification.strip().upper()
        return [ctx for ctx in self.load_all() if ctx.request_classification == target]

    def get_summary(self) -> Dict[str, Any]:
        """Return summary statistics for loaded contexts."""
        contexts = self.load_all()
        if not contexts:
            return {"total_records": 0, "unique_ues": 0, "classifications": {}}

        classifications: Dict[str, int] = {}
        attack_types: Dict[str, int] = {}
        unique_ues = set()

        for ctx in contexts:
            unique_ues.add(ctx.ue_id)
            if ctx.request_classification:
                classifications[ctx.request_classification] = (
                    classifications.get(ctx.request_classification, 0) + 1
                )
            if ctx.attack_type:
                attack_types[ctx.attack_type] = (
                    attack_types.get(ctx.attack_type, 0) + 1
                )

        return {
            "total_records": len(contexts),
            "unique_ues": len(unique_ues),
            "classifications": classifications,
            "attack_types": attack_types,
        }

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _create_context(self, req_id: str, merged: dict) -> RegistrationContext:
        """Validates raw fields and creates a RegistrationContext object.

        Raises ValueError with clear Request_ID context if validation fails.
        """
        display_req_id = req_id or merged.get("Request_ID") or "UNKNOWN_REQ_ID"

        # Mandatory Field 1: UE_ID -> ue_id
        ue_id = merged.get("UE_ID", "").strip()
        if not ue_id:
            raise ValueError(
                f"Mandatory field 'UE_ID' is missing for Request_ID '{display_req_id}'"
            )

        # Mandatory Field 2: SUCI -> suci
        suci = merged.get("SUCI", "").strip()
        if not suci:
            raise ValueError(
                f"Mandatory field 'SUCI' is missing for Request_ID '{display_req_id}'"
            )

        # Mandatory Field 3: Timestamp -> timestamp
        raw_ts = merged.get("Timestamp", "").strip()
        if not raw_ts:
            raise ValueError(
                f"Mandatory field 'Timestamp' is missing for Request_ID '{display_req_id}'"
            )

        try:
            timestamp = self._parse_timestamp(raw_ts)
        except Exception as e:
            raise ValueError(
                f"Invalid Timestamp '{raw_ts}' for Request_ID '{display_req_id}': {e}"
            ) from e

        # Standardize Registration_Type (lowercase)
        raw_reg_type = merged.get("Registration_Type", "initial").strip().lower()
        registration_type = raw_reg_type if raw_reg_type in ("initial", "mobility", "periodic", "emergency") else "initial"

        # Standardize S_NSSAI -> slice_type (eMBB, URLLC, mMTC)
        raw_snssai = merged.get("S_NSSAI", "eMBB").strip().upper()
        if "SST:1" in raw_snssai or "SST-1" in raw_snssai or raw_snssai == "EMBB":
            slice_type = "eMBB"
        elif "SST:2" in raw_snssai or "SST-2" in raw_snssai or raw_snssai == "URLLC":
            slice_type = "URLLC"
        elif "SST:3" in raw_snssai or "SST-3" in raw_snssai or raw_snssai in ("MMTC", "MIOT"):
            slice_type = "mMTC"
        elif raw_snssai in ("EMBB", "URLLC", "MMTC"):
            slice_type = raw_snssai if raw_snssai != "MMTC" else "mMTC"
        else:
            slice_type = "eMBB"

        # DNN
        dnn = merged.get("DNN", "internet").strip().lower() or "internet"

        # Validation Rule 1: Decision -> request_classification (must be ALLOW / TAG / BLOCK)
        raw_decision = merged.get("Decision", "").strip().upper()
        if not raw_decision:
            raise ValueError(
                f"Mandatory field 'Decision' is missing for Request_ID '{display_req_id}'"
            )
        if raw_decision not in ("ALLOW", "TAG", "BLOCK"):
            raise ValueError(
                f"Invalid request_classification (Decision) '{raw_decision}' for Request_ID '{display_req_id}': "
                "must be one of ALLOW, TAG, BLOCK"
            )
        request_classification = raw_decision

        # Attack_Detected & Attack_Type logic
        raw_attack_detected = merged.get("Attack_Detected", "").strip().lower()
        raw_attack_type = merged.get("Attack_Type", "").strip().lower()

        is_attack = raw_attack_detected in ("true", "1", "yes")
        if not is_attack or raw_attack_type in ("none", "null", ""):
            attack_type = "NONE"
        else:
            attack_type = raw_attack_type

        # Severity -> attack_severity
        raw_severity = merged.get("Severity", "").strip().lower()
        attack_severity = raw_severity if raw_severity else None

        # Validation Rule 3: Confidence -> detection_confidence (float)
        raw_confidence = merged.get("Confidence", "").strip()
        detection_confidence: Optional[float] = None
        if raw_confidence:
            try:
                detection_confidence = float(raw_confidence)
            except ValueError as e:
                raise ValueError(
                    f"Invalid Confidence '{raw_confidence}' for Request_ID '{display_req_id}': must be a float"
                ) from e

        # Validation Rule 3: Risk_Score -> threat_score (float)
        raw_risk_score = merged.get("Risk_Score", "").strip()
        threat_score: Optional[float] = None
        if raw_risk_score:
            try:
                threat_score = float(raw_risk_score)
            except ValueError as e:
                raise ValueError(
                    f"Invalid Risk_Score '{raw_risk_score}' for Request_ID '{display_req_id}': must be a float"
                ) from e

        # Reasons -> validation_results & reasons
        reasons_str = merged.get("Reasons", "").strip()
        validation_results: Optional[Dict[str, bool]] = None
        reasons: Optional[str] = None

        if reasons_str:
            reasons = reasons_str
            validation_results = {}
            parts = [p.strip() for p in reasons_str.split(";") if p.strip()]
            for part in parts:
                validation_results[part] = raw_decision == "ALLOW"

        # Fields NOT present in raw CSVs are left strictly as None (not guessed/defaulted)
        privacy_score = None
        privacy_risk_level = None
        metadata_leakage = None
        correlation_score = None

        raw_auth_res = merged.get("Authentication_Result", "").strip().upper()
        authentication_result = raw_auth_res if raw_auth_res else None

        return RegistrationContext(
            ue_id=ue_id,
            suci=suci,
            registration_type=registration_type,
            slice_type=slice_type,
            dnn=dnn,
            timestamp=timestamp,
            request_classification=request_classification,
            attack_type=attack_type,
            attack_severity=attack_severity,
            detection_confidence=detection_confidence,
            validation_results=validation_results,
            privacy_score=privacy_score,
            privacy_risk_level=privacy_risk_level,
            metadata_leakage=metadata_leakage,
            correlation_score=correlation_score,
            threat_score=threat_score,
            reasons=reasons,
            authentication_result=authentication_result,
        )

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse ISO timestamp or common datetime formats."""
        ts_str = ts_str.strip()
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"

        dt = None
        try:
            dt = datetime.fromisoformat(ts_str)
        except ValueError:
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(ts_str, fmt)
                    break
                except ValueError:
                    pass

            if dt is None:
                # Fallback for timestamps missing year (e.g. "07/16 13:16:20.312") or "%M:%S.%f"
                for fmt in ("%m/%d %H:%M:%S.%f", "%m/%d %H:%M:%S", "%M:%S.%f"):
                    try:
                        parsed = datetime.strptime(ts_str, fmt)
                        target_year = self.year if self.year is not None else datetime.now().year
                        dt = parsed.replace(year=target_year)
                        break
                    except ValueError:
                        pass

        if dt is None:
            raise ValueError(f"Could not parse timestamp format: '{ts_str}'")

        # If year is 1900 (log default), replace with target year
        if dt.year == 1900:
            target_year = self.year if self.year is not None else datetime.now().year
            dt = dt.replace(year=target_year)

        return dt


def load_systems_contexts(
    registration_csv_path: str,
    attack_csv_path: str,
    year: Optional[int] = None,
) -> List[RegistrationContext]:
    """Helper function to load RegistrationContext list from raw Systems CSVs."""
    loader = SystemsContextLoader(registration_csv_path, attack_csv_path, year=year)
    return loader.load_all()

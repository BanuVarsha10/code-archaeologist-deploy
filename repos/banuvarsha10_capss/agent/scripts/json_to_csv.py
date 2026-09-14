"""
json_to_csv.py

Converts the JSON output of run_agent.py (--output results.json) into a
flat CSV suitable for sharing with teammates or importing into Excel/Sheets.

Usage:
    python json_to_csv.py results.json results.csv
"""

import csv
import json
import sys


def flatten_policy(policy: dict) -> dict:
    enforcement = policy.get("enforcement", {}) or {}
    validation = policy.get("validation_result", {}) or {}
    metrics = policy.get("metric_summary", {}) or {}
    adaptation = policy.get("adaptation_info", {}) or {}

    return {
        "policy_id": policy.get("policy_id"),
        "ue_id": enforcement.get("apply_to_ue"),
        "registration_type": enforcement.get("registration_type"),
        "slice_type": enforcement.get("slice_type"),
        "dnn": enforcement.get("dnn"),
        "selected_scheme": policy.get("selected_scheme"),
        "selected_scheme_id": policy.get("selected_scheme_id"),
        "hybrid_schemes": "+".join(policy.get("hybrid_schemes") or []),
        "hybrid_benefit_score": enforcement.get("hybrid_benefit_score"),
        "confidence": policy.get("confidence"),
        "risk_assessment": policy.get("risk_assessment"),
        "reason": policy.get("reason"),
        "timestamp": policy.get("timestamp"),
        "expiry": policy.get("expiry"),
        "is_valid": validation.get("is_valid"),
        "validation_errors": "; ".join(validation.get("errors") or []),
        "hybrid_compatible": validation.get("hybrid_compatible"),
        "sfs": metrics.get("sfs"),
        "eas": metrics.get("eas"),
        "ors": metrics.get("ors"),
        "pm": metrics.get("pm"),
        "primary_score": metrics.get("primary_score"),
        "previous_scheme": adaptation.get("previous_scheme"),
        "adaptation_delta": adaptation.get("adaptation_delta"),
        "is_fallback": policy.get("is_fallback"),
    }


def main():
    if len(sys.argv) != 3:
        print("Usage: python json_to_csv.py <input.json> <output.csv>")
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]

    with open(in_path, "r", encoding="utf-8") as f:
        policies = json.load(f)

    rows = [flatten_policy(p) for p in policies]

    if not rows:
        print("No policies found in input file.")
        sys.exit(1)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()

"""capss/scheme_execution/__init__.py

CAPSS Scheme Execution Module — top-level package.

Provides real (or clearly-labeled) cryptographic execution for all 7
CAPSS privacy schemes, plus an adaptation assessment framework.

Quick usage:
    from capss.scheme_execution import SchemeRegistry, assess_adaptation

    registry = SchemeRegistry()
    result = registry.execute("ECIES", {"supi": "imsi-001010000000001"})
    print(result.output_type, result.generation_time_ms)

See each sub-module for details:
    base.py       — SchemeExecutor ABC
    result.py     — ExecutionResult dataclass
    registry.py   — SchemeRegistry (short_name → executor)
    assessment.py — 4-check adaptation assessment
    executors/    — 7 concrete executors

Terminology reminder (enforced by output_type values):
    "suci"              ECIES only — real standardised 3GPP SUCI
    "suci_proposed_pqc" ML-KEM only — proposed PQC SUCI (NOT standardised)
    "pseudonym"         DP — rotating pseudonym, NOT a SUCI
    "padded_payload"    AP — padded payload, NO identity, NOT a SUCI
    "zk_proof"          ZKP — Schnorr proof of knowledge, NOT a SUCI
    "group_signature"   GS — simplified ring signature, NOT a SUCI
    "ibe_ciphertext"    IBE — identity-encrypted ciphertext, NOT a SUCI
"""

from capss.scheme_execution.result import ExecutionResult, VALID_OUTPUT_TYPES
from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.registry import SchemeRegistry, default_registry
from capss.scheme_execution.assessment import (
    assess_adaptation,
    ComparisonResult,
    MeasuredOverhead,
    AnalyticalRationale,
    VERDICT_VALIDATED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NO_CHANGE,
)

__all__ = [
    # Core types
    "ExecutionResult",
    "VALID_OUTPUT_TYPES",
    "SchemeExecutor",
    # Registry
    "SchemeRegistry",
    "default_registry",
    # Assessment
    "assess_adaptation",
    "ComparisonResult",
    "MeasuredOverhead",
    "AnalyticalRationale",
    "VERDICT_VALIDATED",
    "VERDICT_INCONCLUSIVE",
    "VERDICT_NO_CHANGE",
]

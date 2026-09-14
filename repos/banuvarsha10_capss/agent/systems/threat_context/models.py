"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    models.py

Purpose
-------
Defines the Threat Context generated after the
Pre-AMF Security Layer.

The Threat Context is the interface between:

Pre-AMF
    ↓
Threat Context
    ↓
Privacy Module
    ↓
Agent

This file contains ONLY data structures.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


# ==========================================================
# Threat Factors
# ==========================================================

@dataclass
class ThreatFactors:
    """
    Individual factors contributing to the final threat score.
    """

    duplicate_score: float = 0.0

    rate_score: float = 0.0

    subscriber_score: float = 0.0

    header_score: float = 0.0

    parameter_score: float = 0.0

    history_score: float = 0.0


# ==========================================================
# Threat Context
# ==========================================================

@dataclass
class ThreatContext:
    """
    Final threat context produced after the
    Pre-AMF Security Layer.

    This object is consumed by:

    • Privacy Module
    • AI Recommendation Agent
    • Systems Reporting
    """

    registration_id: str

    timestamp: datetime

    ue_id: str

    experiment_name: str

    attack_detected: bool

    attack_type: str

    decision: str

    severity: str

    threat_score: float

    confidence: float

    authentication_result: str

    contributing_factors: ThreatFactors

    reasons: List[str] = field(default_factory=list)
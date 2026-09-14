"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    models.py

Purpose
-------
Defines all shared data models used throughout the
Pre-AMF Security Layer.

This file contains ONLY data structures.

No validation or processing logic should appear here.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


# ==========================================================
# Registration Request
# ==========================================================

@dataclass
class RegistrationRequest:
    """
    Parsed registration request produced by
    parse_amf_logs.py.
    """

    request_id: str

    timestamp: datetime

    ue_id: str

    suci: str

    event: str

    authentication_result: str

    registration_status: str

    gnb_ip: str

    dnn: str

    snssai: str

    registration_type: str = "INITIAL"

    cause_code: str = "SUCCESS"

    experiment_name: str = "NORMAL"

    attack_label: str = "NONE"

    attack_type: str = "NONE"


# ==========================================================
# Registration History
# ==========================================================

@dataclass
class RegistrationHistory:
    """
    Stores historical information for a single UE.
    """

    ue_id: str

    timestamps: List[datetime] = field(default_factory=list)

    registration_count: int = 0

    successful_attempts: int = 0

    failed_attempts: int = 0

    duplicate_count: int = 0

    replay_count: int = 0

    flood_count: int = 0

    first_seen: Optional[datetime] = None

    last_seen: Optional[datetime] = None

    last_gnb: str = ""

    last_suci: str = ""

    last_attack: str = "NONE"

    last_result: str = ""


# ==========================================================
# Attack Statistics
# ==========================================================

@dataclass
class AttackStatistics:
    """
    Overall statistics for one experiment.
    """

    total_requests: int = 0

    allowed: int = 0

    tagged: int = 0

    blocked: int = 0

    duplicate_attacks: int = 0

    replay_attacks: int = 0

    flood_attacks: int = 0

    invalid_subscribers: int = 0

    invalid_headers: int = 0

    invalid_parameters: int = 0


# ==========================================================
# Validation Result
# ==========================================================

@dataclass
class ValidationResult:
    """
    Output of every validator.
    """

    passed: bool

    errors: List[str] = field(default_factory=list)

    warnings: List[str] = field(default_factory=list)

    score: float = 100.0


# ==========================================================
# Detection Result
# ==========================================================

@dataclass
class DetectionResult:
    """
    Output of every behavioural detector.
    """

    detected: bool

    attack_type: str

    confidence: float

    severity: str

    score: float

    message: str

    detector_name: str = ""

    current_rate: float = 0.0

    peak_rate: float = 0.0

    current_count: int = 0

    window_seconds: int = 0


# ==========================================================
# Classification Result
# ==========================================================

@dataclass
class ClassificationResult:
    """
    Final decision produced by the
    Pre-AMF Security Layer.
    """

    decision: str

    attack_flag: bool

    attack_type: str

    severity: str

    reasons: List[str] = field(default_factory=list)


# ==========================================================
# Attack Report
# ==========================================================

@dataclass
class AttackReport:
    """
    Standardized report generated after every
    registration request.

    This report forms the interface between the
    Systems module and the Privacy module.
    """

    request_id: str

    experiment_name: str

    timestamp: datetime

    ue_id: str

    attack_detected: bool

    attack_type: str

    decision: str

    severity: str

    confidence: float

    risk_score: float = 0.0

    reasons: List[str] = field(default_factory=list)


# ==========================================================
# Validation Context
# ==========================================================

@dataclass
class ValidationContext:
    """
    Shared object passed through the entire
    Pre-AMF validation pipeline.
    """

    request: RegistrationRequest

    history: RegistrationHistory

    statistics: AttackStatistics

    experiment_name: str = "NORMAL"

    header_result: Optional[ValidationResult] = None

    parameter_result: Optional[ValidationResult] = None

    subscriber_result: Optional[ValidationResult] = None

    duplicate_result: Optional[DetectionResult] = None

    rate_result: Optional[DetectionResult] = None

    classification_result: Optional[ClassificationResult] = None
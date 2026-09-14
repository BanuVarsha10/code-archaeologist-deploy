"""CAPSS Context Schema — Registration context and requirement profiles.

Defines the data structures for representing a 5G registration event
and the derived privacy/security requirement profile produced by the
Context Analyzer.

Future Extension:
    When the Privacy Module and Pre-AMF Module become available,
    simply populate the optional fields (privacy_score, attack_result,
    correlation_score, metadata_leakage, threat_score). No schema
    changes are required.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class RegistrationContext(BaseModel):
    """Represents a single 5G registration event.

    Current fields come from Open5GS + UERANSIM registration logs.
    Optional fields are reserved for future Privacy/Pre-AMF module output.
    """

    # --- Current fields (available now) ---
    ue_id: str = Field(..., description="Unique UE identifier (e.g. 'UE-001')")
    suci: str = Field(..., description="Subscription Concealed Identifier")
    registration_type: str = Field(
        ...,
        description="Registration type: initial | mobility | periodic | emergency",
    )
    slice_type: str = Field(
        ...,
        description="Network slice type: eMBB | URLLC | mMTC",
    )
    dnn: str = Field(
        ...,
        description="Data Network Name: internet | ims | iot | enterprise",
    )
    timestamp: datetime = Field(..., description="Registration timestamp (ISO 8601)")

    # --- Systems Module fields ---
    request_classification: Optional[str] = Field(
        None,
        description="Systems Module classification: ALLOW | TAG | BLOCK",
    )
    attack_type: Optional[str] = Field(
        None,
        description="Detected attack type: replay | flooding | invalid_subscriber | duplicate | none",
    )
    attack_severity: Optional[str] = Field(
        None,
        description="Attack severity level: low | medium | high | critical",
    )
    detection_confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Systems Module detection confidence",
    )
    validation_results: Optional[Dict[str, bool]] = Field(
        None,
        description="Systems Module validation results: {header: True, subscriber: True, ...}",
    )
    reasons: Optional[str] = Field(
        None,
        description="Raw security decision reasons from Systems Module",
    )
    authentication_result: Optional[str] = Field(
        None,
        description="Authentication result from Systems module: SUCCESS | FAILED",
    )

    # --- Privacy Module fields ---
    privacy_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Privacy assessment score from Privacy Module",
    )
    privacy_risk_level: Optional[str] = Field(
        None,
        description="Privacy risk level from Privacy Module: low | medium | high | critical",
    )
    metadata_leakage: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Metadata leakage assessment from Privacy Module",
    )
    correlation_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Cross-registration correlation risk from Privacy Module",
    )

    # --- Combined threat fields ---
    attack_result: Optional[str] = Field(
        None,
        description="Attack detection result: none | detected | suspected",
    )
    threat_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Overall threat assessment score",
    )

    model_config = {"str_strip_whitespace": True}


class RequirementProfile(BaseModel):
    """Derived privacy and security requirements from context analysis.

    Produced by the Context Analyzer module. Represents the high-level
    reasoning attributes that the Reasoning Engine uses to evaluate
    candidate privacy schemes.
    """

    threat_level: str = Field(
        ...,
        description="Assessed threat level: low | medium | high | critical",
    )
    privacy_requirement: float = Field(
        ..., ge=0.0, le=1.0,
        description="How much privacy protection is needed (0=none, 1=maximum)",
    )
    tracking_risk: float = Field(
        ..., ge=0.0, le=1.0,
        description="Risk of subscriber tracking across registrations",
    )
    metadata_leakage_risk: float = Field(
        ..., ge=0.0, le=1.0,
        description="Risk of metadata information leakage",
    )
    correlation_risk: float = Field(
        ..., ge=0.0, le=1.0,
        description="Risk of cross-registration identity correlation",
    )
    latency_requirement: str = Field(
        ...,
        description="Latency tolerance: ultra_low | low | medium | high",
    )
    resource_profile: str = Field(
        ...,
        description="UE resource capability: constrained | moderate | powerful",
    )
    network_confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence in network security posture",
    )
    context_completeness: float = Field(
        ..., ge=0.0, le=1.0,
        description="Fraction of context fields that are populated",
    )
    quantum_threat: bool = Field(
        False,
        description="Whether quantum-resistant protection is needed",
    )
    anonymous_auth_required: bool = Field(
        False,
        description="Whether anonymous authentication is required",
    )
    identity_protection_required: bool = Field(
        True,
        description="Whether identity protection is a priority",
    )
    attack_type: Optional[str] = Field(
        None,
        description="Detected attack type: replay | flooding | invalid_subscriber | duplicate_registration | none",
    )

"""
capss/integration/systems_adapter.py

Translation layer between the Systems module (systems/pre_amf,
systems/threat_context) and the Agent module's RegistrationContext.

DESIGN RULE: this file contains ONLY field mapping and unit conversion.
No reinterpretation of Systems' decisions, no new detection logic. If
Systems says ALLOW, this layer never overrides that to TAG or BLOCK.

Systems' own source files (systems/pre_amf/*, systems/threat_context/*)
are never imported-and-modified here - only imported and called.
"""

from typing import Optional

from systems.pre_amf.models import RegistrationRequest, AttackReport
from systems.pre_amf.validator import PreAMFValidator
from systems.pre_amf.report import ReportGenerator
from systems.threat_context.generator import ThreatContextGenerator

from capss.schemas.context import RegistrationContext


# ============================================================
# Field mapping: AttackReport -> RegistrationContext
# ============================================================

def attack_report_to_registration_context(
    report: AttackReport,
    request: RegistrationRequest,
    slice_type: str = "eMBB",
) -> RegistrationContext:
    """
    Converts Systems' AttackReport (produced via ThreatContext) into
    the Agent's RegistrationContext.

    Field renames:
        decision            -> request_classification
        severity             -> attack_severity
        confidence            -> detection_confidence
        risk_score (0-100)    -> threat_score (0-1, normalized here)

    slice_type defaults to "eMBB" because Systems does not currently
    emit a network-slice-derived field; override this if/when Systems
    exposes S-NSSAI-to-slice-type mapping directly.
    """

    return RegistrationContext(
        ue_id=report.ue_id,
        suci=request.suci,
        registration_type=request.registration_type.lower(),
        slice_type=slice_type,
        dnn=request.dnn,
        timestamp=report.timestamp,
        request_classification=report.decision,
        attack_type=report.attack_type,
        attack_severity=report.severity,
        detection_confidence=report.confidence,
        authentication_result=request.authentication_result,
        reasons="; ".join(report.reasons) if report.reasons else None,
        threat_score=_normalize_threat_score(report.risk_score),
    )


def _normalize_threat_score(raw_score: float) -> float:
    """
    Systems' threat_score (systems/threat_context/calculator.py) is
    explicitly documented and clamped to a 0-100 range. RegistrationContext
    expects 0-1. Clip defensively in case Systems' clamp is ever relaxed.
    """
    normalized = raw_score / 100.0
    return max(0.0, min(1.0, normalized))


# ============================================================
# Full pipeline runner: RegistrationRequest -> AttackReport
# ============================================================

class SystemsPipeline:
    """
    Thin wrapper running a RegistrationRequest through Systems'
    real, unmodified validation -> threat context -> report pipeline.

    ONE instance should be reused across all requests for a given
    run, so that per-UE RegistrationHistory (duplicate/replay/rate
    detection) is preserved correctly across requests, matching
    Systems' own documented usage pattern (see validate_request()'s
    docstring in systems/pre_amf/validator.py).
    """

    def __init__(self):
        self.validator = PreAMFValidator()
        self.tc_generator = ThreatContextGenerator()
        self.reporter = ReportGenerator()

    def process(self, request: RegistrationRequest) -> AttackReport:
        validation_context = self.validator.validate_with_context(request)
        threat_context = self.tc_generator.generate(validation_context)
        return self.reporter.build_report(threat_context)

    def process_to_agent_context(
        self,
        request: RegistrationRequest,
        slice_type: str = "eMBB",
    ) -> RegistrationContext:
        report = self.process(request)
        return attack_report_to_registration_context(report, request, slice_type)

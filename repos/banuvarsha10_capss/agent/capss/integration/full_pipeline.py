"""
capss/integration/full_pipeline.py

The complete, live CAPSS pipeline: Systems -> Privacy -> Agent.

    UE registration request
            |
            v
    Systems (real, unmodified): PreAMFValidator -> ThreatContextGenerator
            |
            v
    ThreatContext / AttackReport
            |
            v
    Privacy (real, unmodified - live_context.py is new, adds no changes
    to any existing Privacy file): LivePrivacyContext.score()
            |
            v
    Combined RegistrationContext (Systems fields + Privacy fields)
            |
            v
    Agent (real, unmodified): CAPSSAgent.process_registration()
            |
            v
    PrivacyPolicy (selected scheme / hybrid / confidence / explanation)

DESIGN RULE (same as systems_adapter.py): this file only maps fields and
orchestrates calls. No detection, scoring, or reasoning logic lives here -
that all stays in Systems/Privacy/Agent's own real code.
"""

from dataclasses import dataclass, field
from typing import Optional

from systems.pre_amf.models import RegistrationRequest, AttackReport
from systems.pre_amf.validator import PreAMFValidator
from systems.pre_amf.report import ReportGenerator
from systems.threat_context.generator import ThreatContextGenerator

from privacy.live_context import LivePrivacyContext

from capss.schemas.context import RegistrationContext
from capss.agent.capss_agent import CAPSSAgent
from capss.schemas.policy import PrivacyPolicy


def _normalize_threat_score(raw_score: float) -> float:
    """Systems' risk_score is documented/clamped 0-100; RegistrationContext wants 0-1."""
    return max(0.0, min(1.0, raw_score / 100.0))


def build_registration_context(
    report: AttackReport,
    request: RegistrationRequest,
    privacy_result: dict,
    slice_type: str = "eMBB",
) -> RegistrationContext:
    """
    Combines Systems' AttackReport with Privacy's live scoring result into
    one complete RegistrationContext for the Agent. Field renames only:
        decision            -> request_classification
        severity            -> attack_severity
        confidence          -> detection_confidence
        risk_score (0-100)  -> threat_score (0-1)
        privacy_result[...] -> privacy_score / privacy_risk_level /
                                metadata_leakage / correlation_score (as-is,
                                already normalized by LivePrivacyContext)
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
        privacy_score=privacy_result["privacy_score"],
        privacy_risk_level=privacy_result["privacy_risk_level"],
        metadata_leakage=privacy_result["metadata_leakage"],
        correlation_score=privacy_result["correlation_score"],
    )


@dataclass
class CAPSSFullPipeline:
    """
    Reusable, stateful orchestrator for the complete live CAPSS flow.

    ONE instance should be reused across every registration in a run/session,
    so that:
      - Systems' per-UE RegistrationHistory (duplicate/replay/rate detection)
      - Privacy's per-UE registration counter (linkability/correlation)
      - the Agent's per-UE experience memory
    all persist correctly across calls - exactly matching how each of the
    three modules is documented to be used on its own.
    """

    schemes_path: str
    experience_path: str = "experience_store.json"
    slice_type: str = "eMBB"

    validator: PreAMFValidator = field(init=False)
    tc_generator: ThreatContextGenerator = field(init=False)
    reporter: ReportGenerator = field(init=False)
    privacy_context: LivePrivacyContext = field(init=False)
    agent: CAPSSAgent = field(init=False)

    def __post_init__(self):
        self.validator = PreAMFValidator()
        self.tc_generator = ThreatContextGenerator()
        self.reporter = ReportGenerator()
        self.privacy_context = LivePrivacyContext()
        self.agent = CAPSSAgent(schemes_path=self.schemes_path, experience_path=self.experience_path)

    def process(self, request: RegistrationRequest, gnb_ip: Optional[str] = None) -> tuple[AttackReport, dict, RegistrationContext, PrivacyPolicy]:
        """
        Runs one registration through the complete live pipeline.
        Returns (attack_report, privacy_result, registration_context, policy)
        so callers/tests can inspect every stage, not just the final policy.
        """

        # --- SYSTEMS ---
        validation_context = self.validator.validate_with_context(request)
        threat_context = self.tc_generator.generate(validation_context)
        report = self.reporter.build_report(threat_context)

        # --- PRIVACY ---
        privacy_result = self.privacy_context.score(
            ue_id=request.ue_id,
            suci=request.suci,
            gnb_ip=gnb_ip if gnb_ip is not None else request.gnb_ip,
            dnn=request.dnn,
            snssai=request.snssai,
            timestamp=request.timestamp.isoformat(),
            authentication_result=request.authentication_result,
            registration_status=request.registration_status,
            attack_detected=report.attack_detected,
            attack_severity=report.severity,
            detection_confidence=report.confidence,
            request_classification=report.decision,
        )

        # --- COMBINE ---
        context = build_registration_context(report, request, privacy_result, self.slice_type)

        # --- AGENT ---
        policy = self.agent.process_registration(context, verbose=False)

        return report, privacy_result, context, policy

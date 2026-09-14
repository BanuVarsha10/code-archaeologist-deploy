"""dashboard_backend/systems_privacy_view.py

Systems + Privacy ONLY — mirrors CAPSSFullPipeline.process()
(capss/integration/full_pipeline.py:121-151) but stops before its
"--- AGENT ---" section. Never touches CAPSSAgent, never writes to the
experience store.

Why this exists: assess_adaptation() (capss/scheme_execution/assessment.py)
already calls CAPSSAgent.process_registration() internally to derive scheme
A/B and to persist the resulting experience(s). If every scenario step were
first run through the full CAPSSFullPipeline (which also ends in
agent.process_registration()) and THEN handed to assess_adaptation(), every
event would be agent-processed twice into the same experience file. This
class provides the Systems+Privacy-only half of that pipeline so the agent
is invoked exactly once per real event, only inside assess_adaptation()
(or, for invalid_subscriber, exactly once via a direct call — see
pipeline_service.py).

Uses the same real, unmodified classes CAPSSFullPipeline uses, in the same
order, via the same already-exported build_registration_context() helper —
no detection/scoring/reasoning logic is reimplemented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from systems.pre_amf.models import RegistrationRequest, AttackReport, ValidationContext
from systems.pre_amf.validator import PreAMFValidator
from systems.pre_amf.report import ReportGenerator
from systems.threat_context.generator import ThreatContextGenerator

from privacy.live_context import LivePrivacyContext, LiveMetadataMinimizer

from capss.schemas.context import RegistrationContext
from capss.integration.full_pipeline import build_registration_context


@dataclass
class SystemsPrivacyView:
    """Reusable, stateful Systems+Privacy-only view of the pipeline.

    ONE instance should be reused across every registration in a batch run
    (same rule as CAPSSFullPipeline), so per-UE RegistrationHistory and
    Privacy's per-UE linkability counters persist correctly across calls.
    """

    slice_type: str = "eMBB"

    validator: PreAMFValidator = field(init=False)
    tc_generator: ThreatContextGenerator = field(init=False)
    reporter: ReportGenerator = field(init=False)
    privacy_context: LivePrivacyContext = field(init=False)
    metadata_minimizer: LiveMetadataMinimizer = field(init=False)

    def __post_init__(self):
        self.validator = PreAMFValidator()
        self.tc_generator = ThreatContextGenerator()
        self.reporter = ReportGenerator()
        self.privacy_context = LivePrivacyContext()
        self.metadata_minimizer = LiveMetadataMinimizer()

    def process(
        self,
        request: RegistrationRequest,
        gnb_ip: Optional[str] = None,
    ) -> tuple[AttackReport, dict, RegistrationContext, ValidationContext, dict]:
        """Runs one registration through Systems + Privacy only.

        Returns (attack_report, privacy_result, registration_context,
        validation_context, minimization_result) — validation_context
        carries the granular per-validator breakdown (header_result,
        parameter_result, subscriber_result, duplicate_result, rate_result)
        the Systems Module panel needs, on top of the summarized
        AttackReport the rest of the dashboard uses; minimization_result
        carries real original/minimized field pairs from
        LiveMetadataMinimizer (see privacy/live_context.py) — purely
        additive display data, never fed back into privacy_result or
        registration_context. Does NOT call CAPSSAgent and does NOT write
        to any experience store or any file.
        """
        # --- SYSTEMS --- (identical to CAPSSFullPipeline.process())
        validation_context = self.validator.validate_with_context(request)
        threat_context = self.tc_generator.generate(validation_context)
        report = self.reporter.build_report(threat_context)

        # --- PRIVACY ---
        # attack_detected/attack_severity/detection_confidence/
        # request_classification feed LivePrivacyContext.score()'s
        # behavioral risk layer (privacy/live_context.py) — without these,
        # score() silently falls back to its NORMAL/ALLOW/not-detected
        # defaults, meaning the dashboard would never actually benefit
        # from the behavioral blend even though it's now real code path.
        # Sourced from the same `report` object already built above, no
        # new data — matches capss/integration/full_pipeline.py's identical
        # call exactly.
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

        # --- COMBINE (no agent call) ---
        context = build_registration_context(report, request, privacy_result, self.slice_type)

        # --- METADATA MINIMIZATION (real, additive — never feeds back into
        # privacy_result/context above; see LiveMetadataMinimizer's
        # docstring) ---
        minimization_result = self.metadata_minimizer.minimize(
            ue_id=request.ue_id,
            suci=request.suci,
            gnb_ip=gnb_ip if gnb_ip is not None else request.gnb_ip,
            dnn=request.dnn,
            snssai=request.snssai,
            timestamp=request.timestamp,
        )

        return report, privacy_result, context, validation_context, minimization_result

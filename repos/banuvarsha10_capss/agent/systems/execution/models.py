from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import List


class ExecutionStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


@dataclass
class ExecutionEvidence:
    validation_passed: bool
    policy_applied: bool
    authentication_continued: bool
    execution_notes: List[str] = field(default_factory=list)


@dataclass
class PolicyExecution:

    policy_id: str

    ue_id: str

    timestamp: datetime

    primary_scheme: str

    hybrid_schemes: List[str]

    confidence: float

    risk_assessment: str

    execution_status: ExecutionStatus

    authentication_result: str

    processing_time_ms: float

    evidence: ExecutionEvidence
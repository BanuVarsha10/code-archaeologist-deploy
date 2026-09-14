"""Experience Schema and Feature Extractor for Cross-UE RAG Vector Retrieval.

Converts RequirementProfile, RegistrationContext, or Experience objects into
normalized numeric feature vectors (13 dimensions) for cosine similarity retrieval.
"""

from typing import List, Dict, Any, Optional
import numpy as np
from capss.schemas.context import RequirementProfile, RegistrationContext
from capss.schemas.experience import Experience


# Slice type one-hot map
SLICE_MAP = {"eMBB": [1.0, 0.0, 0.0], "URLLC": [0.0, 1.0, 0.0], "mMTC": [0.0, 0.0, 1.0]}
DEFAULT_SLICE = [0.33, 0.33, 0.33]

# Registration type one-hot map
REG_TYPE_MAP = {
    "initial": [1.0, 0.0, 0.0, 0.0],
    "mobility": [0.0, 1.0, 0.0, 0.0],
    "periodic": [0.0, 0.0, 1.0, 0.0],
    "emergency": [0.0, 0.0, 0.0, 1.0],
}
DEFAULT_REG_TYPE = [0.25, 0.25, 0.25, 0.25]

# Threat level numeric map
THREAT_MAP = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.00}

# Attack type numeric map
ATTACK_MAP = {
    "none": 0.0,
    "duplicate_registration": 0.25,
    "replay": 0.50,
    "invalid_subscriber": 0.75,
    "flooding": 1.00,
}


def profile_to_feature_vector(
    profile: RequirementProfile,
    context: Optional[RegistrationContext] = None,
) -> List[float]:
    """
    Extracts a 13-dimensional normalized feature vector [0.0 - 1.0] from a RequirementProfile.
    """
    threat = THREAT_MAP.get(str(getattr(profile, "threat_level", "low")).lower(), 0.25)
    priv_req = float(getattr(profile, "privacy_requirement", 0.5))
    track_risk = float(getattr(profile, "tracking_risk", 0.3))
    meta_risk = float(getattr(profile, "metadata_leakage_risk", 0.3))
    corr_risk = float(getattr(profile, "correlation_risk", 0.3))

    slice_type = getattr(context, "slice_type", "eMBB") if context else "eMBB"
    slice_vec = SLICE_MAP.get(slice_type, DEFAULT_SLICE)

    reg_type = getattr(context, "registration_type", "initial") if context else "initial"
    reg_vec = REG_TYPE_MAP.get(reg_type, DEFAULT_REG_TYPE)

    att_type = (getattr(context, "attack_type", None) or "none").lower()
    att_score = ATTACK_MAP.get(att_type, 0.5 if att_type != "none" else 0.0)

    vec = [
        threat,
        priv_req,
        track_risk,
        meta_risk,
        corr_risk,
        *slice_vec,
        *reg_vec,
        att_score,
    ]
    return vec


def experience_to_feature_vector(exp: Experience) -> List[float]:
    """
    Extracts a 13-dimensional normalized feature vector from a stored Experience object.
    Prefers requirement_profile and context_snapshot embedded in the experience.
    """
    req_dict = getattr(exp, "requirement_profile", {}) or {}
    ctx_dict = getattr(exp, "context_snapshot", {}) or {}

    threat = THREAT_MAP.get(str(req_dict.get("threat_level", "low")).lower(), 0.25)
    priv_req = float(req_dict.get("privacy_requirement", 0.5))
    track_risk = float(req_dict.get("tracking_risk", 0.3))
    meta_risk = float(req_dict.get("metadata_leakage_risk", 0.3))
    corr_risk = float(req_dict.get("correlation_risk", 0.3))

    slice_type = ctx_dict.get("slice_type", "eMBB")
    slice_vec = SLICE_MAP.get(slice_type, DEFAULT_SLICE)

    reg_type = ctx_dict.get("registration_type", "initial")
    reg_vec = REG_TYPE_MAP.get(reg_type, DEFAULT_REG_TYPE)

    att_type = str(ctx_dict.get("attack_type", "none")).lower()
    att_score = ATTACK_MAP.get(att_type, 0.5 if att_type != "none" else 0.0)

    vec = [
        threat,
        priv_req,
        track_risk,
        meta_risk,
        corr_risk,
        *slice_vec,
        *reg_vec,
        att_score,
    ]
    return vec

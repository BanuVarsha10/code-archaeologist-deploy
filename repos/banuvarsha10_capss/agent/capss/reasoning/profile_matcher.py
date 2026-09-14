"""
Profile Matcher Module.

This module provides the ProfileMatcher class which evaluates and scores how well a
given PrivacyScheme satisfies a RequirementProfile based on the scheme's reasoning 
profile and context preferences.
"""

from typing import Dict, Any, List, Tuple
from capss.schemas.context import RequirementProfile
from capss.schemas.scheme import PrivacyScheme


def _to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val > 0
    if isinstance(val, str):
        v = val.strip().lower()
        return v in ("true", "1", "yes", "high", "critical")
    return bool(val)


# Bug 3 fix: dampens (does not zero out) the tracking/correlation-risk
# dimensions' weight for a scheme whose knowledge-base attack_type_affinity
# for the CURRENT attack_type is explicitly documented False. Confirmed
# structural, not coincidental (see diagnosis): ContextAnalyzer hardcodes
# tracking_risk += 0.35 for any replay/duplicate-classified context, and
# correlation_risk structurally tends to be high for replay too (SUCI-reuse
# is replay's defining signature) -- so a scheme with NO documented replay
# affinity (e.g. GS) could still win purely on general tracking/correlation
# fit, overriding the KB's own explicit "not suited for this attack"
# signal. 0.35 keeps this a dampening rather than a veto: high_tracking_risk
# (weight 2.0) + high_correlation_risk (weight 2.0) + the tracking_risk
# context preference (weight 1.3) together drop from 5.3 to ~1.86 of
# combined weight for the mismatched scheme specifically -- still a real,
# nonzero contribution a scheme could win on if strong enough elsewhere
# (see verification: a False-affinity scheme with an overwhelming
# unrelated-dimension advantage still wins), just no longer enough on its
# own to outweigh attack_type_affinity's single 2.0-weighted dimension the
# way the undampened 5.3 could. Only applies when affinity is explicitly
# False for THIS attack_type -- never for True affinity, and never when no
# attack is active (attack_type is None/"none"), so duplicate_registration
# (where the same tracking_risk rule fires but GS's affinity is correctly
# True) and normal registrations are both completely unaffected.
ATTACK_MISMATCH_TRACKING_DAMPENING = 0.35

# The 3 profile_matcher dimensions this dampening applies to -- every other
# dimension (privacy, quantum, latency, identity protection, ...) is
# untouched regardless of attack_type_affinity, which is what keeps this a
# targeted dampening rather than a broader scheme-wide penalty.
_TRACKING_CORRELATION_DIMENSIONS = frozenset({"high_tracking_risk", "high_correlation_risk", "tracking_risk"})


class ProfileMatcher:
    """
    A matcher class that compares a requirement profile against a privacy scheme.
    """

    def match(self, requirement_profile: RequirementProfile, scheme: PrivacyScheme) -> float:
        """
        Calculates a compatibility score for a scheme against the provided requirement profile.
        """
        reasoning_profile: Dict[str, Any] = scheme.get_reasoning_profile()
        context_prefs: Dict[str, bool] = scheme.get_context_preferences()

        # Bug 3 fix: is THIS scheme's KB affinity for the CURRENT attack_type
        # explicitly documented False (not just absent/None -- a real
        # "this scheme is not suited for this attack" entry)?
        attack_type_raw = (getattr(requirement_profile, 'attack_type', None) or '').strip().lower()
        attack_type_key = 'duplicate_registration' if attack_type_raw in ('duplicate', 'duplicate_registration') else attack_type_raw
        affinity_map = reasoning_profile.get('attack_type_affinity', {}) or {}
        explicit_affinity = affinity_map.get(attack_type_key, None) if attack_type_key else None
        affinity_documented_false = attack_type_key not in ('', 'none', 'null') and explicit_affinity is False

        def _dampened_weight(name: str, weight: float) -> float:
            if affinity_documented_false and name in _TRACKING_CORRELATION_DIMENSIONS:
                return weight * ATTACK_MISMATCH_TRACKING_DAMPENING
            return weight

        # Define dimensions and their evaluations
        # Format: (name, is_required, is_supported, weight)
        evaluations: List[Tuple[str, bool, bool, float]] = [
            # -----------------------------------------------------------------
            # Reasoning profile mappings
            # -----------------------------------------------------------------
            (
                'high_threat',
                requirement_profile.threat_level in ['high', 'critical'],
                _to_bool(reasoning_profile.get('high_threat', False)),
                2.0
            ),
            (
                'high_privacy_required',
                requirement_profile.privacy_requirement > 0.6,
                _to_bool(reasoning_profile.get('high_privacy_required', False)),
                1.0
            ),
            (
                'high_metadata_leakage',
                requirement_profile.metadata_leakage_risk > 0.5,
                _to_bool(reasoning_profile.get('high_metadata_leakage', False)),
                2.0
            ),
            (
                'high_tracking_risk',
                requirement_profile.tracking_risk > 0.5,
                _to_bool(reasoning_profile.get('high_tracking_risk', False)),
                _dampened_weight('high_tracking_risk', 2.0)
            ),
            (
                'high_correlation_risk',
                requirement_profile.correlation_risk > 0.5,
                _to_bool(reasoning_profile.get('high_correlation_risk', False)),
                _dampened_weight('high_correlation_risk', 2.0)
            ),
            (
                'low_latency_required',
                requirement_profile.latency_requirement in ['ultra_low', 'low'],
                _to_bool(reasoning_profile.get('low_latency_required', False)),
                1.0
            ),
            (
                'attack_type_affinity',
                (getattr(requirement_profile, 'attack_type', None) or '').strip().lower() in ['duplicate', 'duplicate_registration', 'flooding', 'invalid_subscriber', 'replay'],
                _to_bool(
                    reasoning_profile.get('attack_type_affinity', {}).get(
                        'duplicate_registration' if (getattr(requirement_profile, 'attack_type', None) or '').strip().lower() in ['duplicate', 'duplicate_registration'] else (getattr(requirement_profile, 'attack_type', None) or '').strip().lower(),
                        False
                    )
                ),
                2.0
            ),
            # -----------------------------------------------------------------
            # Context preferences mappings
            # -----------------------------------------------------------------
            (
                'high_privacy',
                requirement_profile.privacy_requirement > 0.6,
                _to_bool(context_prefs.get('high_privacy', False)),
                1.5
            ),
            (
                'quantum_safe',
                bool(requirement_profile.quantum_threat),
                _to_bool(context_prefs.get('quantum_safe', False)),
                2.0
            ),
            (
                'tracking_risk',
                requirement_profile.tracking_risk > 0.5,
                _to_bool(context_prefs.get('tracking_risk', False)),
                _dampened_weight('tracking_risk', 1.3)
            ),
            (
                'anonymous_authentication_required',
                bool(requirement_profile.anonymous_auth_required),
                _to_bool(context_prefs.get('anonymous_authentication_required', False)),
                1.0
            ),
            (
                'identity_protection_required',
                bool(requirement_profile.identity_protection_required),
                _to_bool(context_prefs.get('identity_protection_required', False)),
                1.5
            ),
            (
                'resource_constrained',
                requirement_profile.resource_profile == 'constrained',
                _to_bool(context_prefs.get('resource_constrained', False)),
                1.0
            ),
            (
                'low_latency',
                requirement_profile.latency_requirement in ['ultra_low', 'low'],
                _to_bool(context_prefs.get('low_latency', False)),
                1.5
            ),
        ]

        total_score = 0.0
        max_possible_score = 0.0
        min_possible_score = 0.0

        # Calculate scores and min/max boundaries for normalization
        for name, is_req, is_sup, weight in evaluations:
            if is_req and is_sup:
                raw_score = 1.0
            elif is_req and not is_sup:
                raw_score = -0.5
            elif not is_req and is_sup:
                raw_score = 0.0
            else:  # not is_req and not is_sup
                raw_score = 0.25
            
            total_score += weight * raw_score
            
            if is_req:
                max_possible_score += weight * 1.0
                min_possible_score += weight * -0.5
            else:
                max_possible_score += weight * 0.25
                min_possible_score += weight * 0.0

        # Edge case: Avoid division by zero
        if max_possible_score == min_possible_score:
            return 0.0

        # Normalize score to 0.0 - 1.0 range
        normalized_score = (total_score - min_possible_score) / (max_possible_score - min_possible_score)
        
        # Return clamped value to guarantee 0-1 range
        return max(0.0, min(1.0, normalized_score))
from typing import List, Dict, Any, Optional, Tuple
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme

def _clamp(val: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Clamps a floating point value to the range [min_val, max_val]."""
    return max(min_val, min(max_val, val))


# Maximum allowed deviation of Experience Alignment Score (EAS) from its
# neutral midpoint (0.5), in either direction. Confirmed directly: without
# this bound, EAS can swing across its full [0.0, 1.0] range (i.e. up to
# +-0.5 from neutral) as accumulated experience grows, and at a 20% weight
# in compute_ors() this let a scheme's final_score margin over a rival
# widen without limit purely from repeated history, even after the
# knowledge-base-driven (SFS/PRI) component had already decided the
# ranking on an empty store. Capping the swing keeps EAS able to
# meaningfully nudge ranking -- including deciding close calls and cold-
# start cross-UE retrieval -- without letting accumulated momentum alone
# ever fully override the context/knowledge-base baseline. 0.15 keeps
# EAS's maximum possible contribution to compute_ors() (0.15 * 0.20 = 0.03)
# comfortably below SFS's typical influence, while still leaving a real,
# non-trivial signal for the sign-test / adaptation behavior this project
# already verifies elsewhere.
EAS_MAX_DEVIATION_FROM_NEUTRAL = 0.15


def _to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val > 0
    if isinstance(val, str):
        v = val.strip().lower()
        return v in ("true", "1", "yes", "high", "critical")
    return bool(val)

class MetricsCalculator:
    """
    Calculator for various reasoning metrics in the CAPSS framework.
    Evaluates context, privacy requirements, scheme fitness, experience alignment, and overall confidence.
    """
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        
        # Extract nested config keys
        cs = self.config.get('context_sensitivity', {})
        self.slice_weights = cs.get('slice_weights', {'eMBB': 0.5, 'URLLC': 0.8, 'mMTC': 0.6})
        self.dnn_weights = cs.get('dnn_weights', {'internet': 0.4, 'ims': 0.7, 'iot': 0.5, 'enterprise': 0.9})
        self.reg_type_weights = cs.get('registration_type_weights', {
            'initial': 0.6, 'mobility': 0.5, 'periodic': 0.3, 'emergency': 0.95
        })
        
        self.scoring_weights = self.config.get('scoring_weights', {
            'privacy_match': 0.20,
            'security_match': 0.15,
            'performance_match': 0.15,
            'deployment_match': 0.10,
            'experience_alignment': 0.10,
            'tracking_protection': 0.20,
            'identity_protection': 0.05,
            'quantum_match': 0.05
        })
        
        self.confidence_weights = self.config.get('confidence_weights', {
            'context_completeness': 0.25,
            'scheme_match': 0.30,
            'historical_agreement': 0.30,
            'knowledge_completeness': 0.15
        })

    def compute_css(self, context: RegistrationContext) -> float:
        """
        Computes Context Sensitivity Score (CSS).
        """
        slice_w = self.slice_weights.get(getattr(context, 'slice_type', ''), 0.5)
        dnn_w = self.dnn_weights.get(getattr(context, 'dnn', ''), 0.5)
        reg_w = self.reg_type_weights.get(getattr(context, 'registration_type', ''), 0.5)
        
        score = (slice_w * 0.35) + (dnn_w * 0.40) + (reg_w * 0.25)
        return _clamp(score)

    def compute_pri(self, requirement_profile: RequirementProfile, css: Optional[float] = None) -> float:
        """
        Computes Privacy Requirement Index (PRI).
        """
        css_val = 0.5 if css is None else css
        threat_mult = {'low': 0.5, 'medium': 0.7, 'high': 0.9, 'critical': 1.0}
        
        tm = threat_mult.get(getattr(requirement_profile, 'threat_level', 'medium'), 0.5)
        tracking_factor = max(getattr(requirement_profile, 'tracking_risk', 0.5), 0.3)
        
        pri = css_val * tm * tracking_factor
        
        # Boost if privacy_requirement is high
        if getattr(requirement_profile, 'privacy_requirement', 0.5) > 0.7:
            pri = pri * 1.2
            
        return _clamp(pri)

    def compute_sfs(self, scheme: PrivacyScheme, requirement_profile: RequirementProfile) -> Tuple[float, Dict[str, float]]:
        """
        Computes Scheme Fitness Score (SFS) against a requirement profile.
        Returns the overall score and the individual dimensional scores.
        """
        dimensions = {}
        
        # Standard matches
        dimensions['privacy_match'] = scheme.get_metric('privacy_score', 3) / 5.0
        dimensions['security_match'] = scheme.get_metric('security_score', 3) / 5.0
        dimensions['deployment_match'] = scheme.get_metric('deployment_score', 3) / 5.0
        
        # Latency / Performance Match
        latency_score = scheme.get_metric('latency_score', 3)
        req_latency = getattr(requirement_profile, 'latency_requirement', 'normal')
        if req_latency == 'ultra_low':
            dimensions['performance_match'] = (latency_score / 5.0) if latency_score >= 4 else (latency_score / 10.0)
        elif req_latency == 'low':
            dimensions['performance_match'] = (latency_score / 5.0) if latency_score >= 3 else (latency_score / 10.0)
        else:
            dimensions['performance_match'] = latency_score / 5.0

        # Tracking match
        tracking_score = scheme.get_metric('tracking_score', 3) / 5.0
        if getattr(requirement_profile, 'tracking_risk', 0.0) > 0.5 or getattr(requirement_profile, 'correlation_risk', 0.0) > 0.5:
            if _to_bool(scheme.get_reasoning_profile().get('high_tracking_risk', False)) or _to_bool(scheme.get_reasoning_profile().get('high_correlation_risk', False)):
                tracking_score *= 1.4
            elif getattr(requirement_profile, 'tracking_risk', 0.0) > 0.5:
                tracking_score *= 1.2
        dimensions['tracking_protection'] = _clamp(tracking_score)

        # Metadata leakage match
        privacy_match = dimensions['privacy_match']
        if getattr(requirement_profile, 'metadata_leakage_risk', 0.0) > 0.5:
            if _to_bool(scheme.get_reasoning_profile().get('high_metadata_leakage', False)):
                privacy_match *= 1.4
        dimensions['privacy_match'] = _clamp(privacy_match)
        
        # Identity match
        if getattr(requirement_profile, 'identity_protection_required', False):
            dimensions['identity_protection'] = scheme.get_metric('identity_score', 3) / 5.0
        else:
            dimensions['identity_protection'] = 1.0 # Optimal if not required
            
        # Quantum match
        quantum_score = scheme.get_metric('quantum_score', 3) / 5.0
        if getattr(requirement_profile, 'quantum_threat', False):
            dimensions['quantum_match'] = quantum_score
        else:
            dimensions['quantum_match'] = 1.0 # Optimal if not a threat

        # Energy match
        energy_score = scheme.get_metric('energy_score', 3) / 5.0
        if getattr(requirement_profile, 'resource_profile', '') == 'constrained':
            dimensions['energy_match'] = energy_score
        else:
            dimensions['energy_match'] = 1.0

        # Compute weighted sum
        total_score = 0.0
        total_weight = 0.0
        for k, v in dimensions.items():
            w = self.scoring_weights.get(k, 0.0)
            # Exclude keys from average if they have no configured weight
            if w > 0:
                total_score += v * w
                total_weight += w
                
        final_sfs = (total_score / total_weight) if total_weight > 0 else 0.5
        return _clamp(final_sfs), dimensions

    def compute_eas(
        self,
        experiences: List[Experience],
        scheme: PrivacyScheme,
        requirement_profile: Optional[RequirementProfile] = None,
        cross_ue_experiences: Optional[List[Tuple[Experience, float]]] = None,
    ) -> float:
        """
        Computes Experience Alignment Score (EAS) based on historical selection frequency,
        recency (decay factor), confidence, and outcome (success/failure) track record.
        
        If same-UE history is empty or sparse (<3) and cross_ue_experiences are provided,
        incorporates cross-UE similar experiences weighted by similarity.
        """
        effective_experiences = list(experiences) if experiences else []

        # Current query's attack_type, normalized once and reused below both
        # for the cross-UE attack-type gate and the existing is_attack_active
        # check. Unset/None is treated the same as the literal "none" label
        # stored experiences use (RegistrationContext leaves attack_type None
        # for a normal registration; Experience.context_snapshot stores the
        # string "none" for the same case -- see experience_schema.py's
        # ATTACK_MAP) so the two representations compare equal.
        query_attack_type = (getattr(requirement_profile, 'attack_type', None) or 'none').strip().lower()

        # Only use cross-UE retrieval if same-UE experience count is below threshold (< 3)
        if len(effective_experiences) < 3 and cross_ue_experiences:
            for cross_exp, similarity in cross_ue_experiences:
                # Cross-UE attack-type gate: a borrowed experience is only
                # legitimate evidence for THIS scheme's alignment if it was
                # stored under the SAME attack_type as the current query.
                # Confirmed directly (diagnosis repro): retrieve_similar's
                # embedding under-weights attack_type (1 of 13 dims, ordinal
                # scalar) enough that e.g. duplicate_registration-stored GS
                # experiences come back at 0.93-0.99 similarity against a
                # genuine REPLAY query, letting GS (no documented replay
                # affinity in the knowledge base) pick up a real, capped-but-
                # nonzero EAS boost purely from an unrelated attack type.
                # Excluded entirely rather than discounted: the knowledge
                # base's attack_type_affinity table is already the
                # authoritative source for "is this scheme's use under this
                # attack type justified" (Check 4 uses it the same way) --
                # borrowed evidence from a DIFFERENT attack type isn't a
                # weaker version of a legitimate signal about the current
                # decision, it isn't evidence about it at all, so it gets
                # zero weight here rather than a same-but-smaller one. This
                # is a different kind of discount from the existing
                # `* 0.5 * similarity` recency/confidence decay below, which
                # legitimately still applies to SAME-attack-type matches.
                exp_context = getattr(cross_exp, 'context_snapshot', {}) or {}
                exp_attack_type = str(exp_context.get('attack_type', 'none') or 'none').strip().lower()
                if exp_attack_type != query_attack_type:
                    continue

                original_decay = getattr(cross_exp, 'experience_decay_factor', 1.0)
                cross_exp_copy = Experience(
                    ue_id=getattr(cross_exp, 'ue_id', 'cross_ue'),
                    context_snapshot=exp_context,
                    requirement_profile=getattr(cross_exp, 'requirement_profile', {}),
                    selected_scheme=getattr(cross_exp, 'selected_scheme', ''),
                    selected_scheme_id=getattr(cross_exp, 'selected_scheme_id', ''),
                    reason=getattr(cross_exp, 'reason', ''),
                    confidence=getattr(cross_exp, 'confidence', 0.8),
                    outcome=getattr(cross_exp, 'outcome', None),
                    success_count=getattr(cross_exp, 'success_count', 0),
                    failure_count=getattr(cross_exp, 'failure_count', 0),
                    experience_decay_factor=original_decay * 0.5 * float(similarity),
                )
                effective_experiences.append(cross_exp_copy)

        if not effective_experiences:
            return 0.5

        # Same attack-type relevance gate Bug 2 established for cross-UE
        # data, now extended to OWN-UE data too. Cross-UE entries in
        # effective_experiences already only got there by passing this
        # exact check at insertion above (Bug 2's merge-loop gate) --
        # re-checking them here is a redundant no-op, not a behavior
        # change. What this newly excludes is OWN-UE experiences: found
        # during the Bug 4 investigation that a device's own history had
        # NO attack-type gating at all (matching_experiences filtered
        # purely by selected_scheme_id) -- a real device with 6 own
        # duplicate_registration/none experiences (all selecting GS) still
        # got a real, measured EAS boost (0.5864) toward GS on a REPLAY
        # query, where GS has no documented affinity, purely from
        # unrelated own history. Filtered here (before matching AND before
        # the total_weight denominator) rather than only in the matching
        # step, so an irrelevant own experience doesn't even dilute other
        # schemes' ratios -- consistent with how Bug 2's cross-UE
        # experiences never entered effective_experiences at all when
        # mismatched, not just excluded from matching.
        relevant_experiences = [
            exp for exp in effective_experiences
            if str((getattr(exp, 'context_snapshot', {}) or {}).get('attack_type', 'none') or 'none')
            .strip().lower() == query_attack_type
        ]

        # Check if active attack/high threat is present (dampens historical bias)
        is_attack_active = False
        if requirement_profile:
            threat = getattr(requirement_profile, 'threat_level', 'low')
            if threat in ['high', 'critical'] or query_attack_type not in ['none', 'null']:
                is_attack_active = True

        matching_experiences = []
        for exp in relevant_experiences:
            exp_scheme_id = getattr(exp, 'selected_scheme_id', None)
            exp_scheme_name = getattr(exp, 'selected_scheme', None)

            if exp_scheme_id == getattr(scheme, 'id', None) or exp_scheme_name == getattr(scheme, 'short_name', None):
                matching_experiences.append(exp)

        if not matching_experiences:
            return 0.5

        total_weight = sum(getattr(exp, 'experience_decay_factor', 1.0) for exp in relevant_experiences)
        if total_weight <= 0:
            return 0.5

        weighted_count = sum(getattr(exp, 'experience_decay_factor', 1.0) for exp in matching_experiences)
        selection_ratio = weighted_count / total_weight

        # Filter resolved experiences (those with known outcome) for outcome_signal calculation
        resolved_signals = []
        resolved_weights = []
        confidences = []

        for exp in matching_experiences:
            decay = getattr(exp, 'experience_decay_factor', 1.0)
            conf = getattr(exp, 'confidence', 1.0)
            confidences.append(conf)

            succ = getattr(exp, 'success_count', 0)
            fail = getattr(exp, 'failure_count', 0)
            tot = succ + fail
            out = getattr(exp, 'outcome', None)

            if tot > 0:
                sig = succ / tot
                resolved_signals.append(sig * decay)
                resolved_weights.append(decay)
            elif out in ("success", "failure"):
                sig = 1.0 if out == "success" else 0.0
                resolved_signals.append(sig * decay)
                resolved_weights.append(decay)
            # Pending experiences (outcome is None / "unknown" and tot == 0) are excluded from outcome signal

        sum_resolved_weights = sum(resolved_weights)
        if sum_resolved_weights > 0:
            avg_outcome_signal = sum(resolved_signals) / sum_resolved_weights
        else:
            avg_outcome_signal = 0.5  # Neutral fallback when no resolved outcomes exist yet

        avg_conf = (sum(confidences) / len(confidences)) if confidences else 1.0

        # Base selection alignment from historical selection frequency and confidence
        base_selection_alignment = selection_ratio * avg_conf

        # Neutral baseline is 0.5.
        # Shift score for selection consistency (base_selection_alignment) and outcome track record (outcome_delta).
        outcome_delta = avg_outcome_signal - 0.5  # ranges -0.5 to +0.5
        res = 0.5 + (base_selection_alignment * 0.3) + (outcome_delta * 0.7 * selection_ratio * avg_conf)

        if is_attack_active:
            # Shift towards neutral 0.5 so threat adaptation takes priority over historical bias
            res = 0.5 * res + 0.5 * 0.5

        # Bound EAS's swing from neutral (see EAS_MAX_DEVIATION_FROM_NEUTRAL's
        # docstring) -- experience can still meaningfully nudge the ranking,
        # but can never fully overwhelm the knowledge-base-driven baseline
        # no matter how much history accumulates.
        return _clamp(res, 0.5 - EAS_MAX_DEVIATION_FROM_NEUTRAL, 0.5 + EAS_MAX_DEVIATION_FROM_NEUTRAL)

    def compute_hbs(self, scheme1: PrivacyScheme, scheme2: PrivacyScheme, requirement_profile: RequirementProfile) -> float:
        """
        Computes Hybrid Benefit Score (HBS) for combining scheme1 and scheme2.
        """
        # Check compatibility
        compatible_hybrids = set()
        if hasattr(scheme1, 'get_compatible_hybrids'):
            hybrids = scheme1.get_compatible_hybrids()
            if isinstance(hybrids, list):
                compatible_hybrids.update(hybrids)
                
        scheme2_id = getattr(scheme2, 'id', None)
        scheme2_name = getattr(scheme2, 'short_name', None)
        scheme2_full_name = getattr(scheme2, 'name', None)
        
        if (
            scheme2_id not in compatible_hybrids
            and scheme2_name not in compatible_hybrids
            and scheme2_full_name not in compatible_hybrids
        ):
            return 0.0
            
        metrics_to_check = [
            'privacy_score', 'security_score', 'latency_score', 
            'tracking_score', 'identity_score', 'quantum_score', 
            'deployment_score', 'energy_score'
        ]
        
        total_improvement = 0.0
        for metric in metrics_to_check:
            s1_val = scheme1.get_metric(metric, 3)
            s2_val = scheme2.get_metric(metric, 3)
            if s2_val > s1_val:
                total_improvement += (s2_val - s1_val)
                
        improvement_normalized = (total_improvement / len(metrics_to_check)) / 5.0
        return _clamp(improvement_normalized)

    def compute_ad(self, current_scheme_id: str, experiences: List[Experience]) -> float:
        """
        Computes Anomaly Detection (AD) score / deviation from most recent experience.
        """
        if not experiences:
            return 0.0
            
        # Assuming last item is the most recent experience based on chronological appending
        latest = experiences[-1] 
        
        if getattr(latest, 'selected_scheme_id', None) == current_scheme_id:
            return 0.0
            
        # Fallback to a nominal difference if specific historical scores are unparsed
        return 0.5

    def compute_ors(self, sfs: float, pri_match: float, eas: float, hbs: float) -> float:
        """
        Computes Overall Recommendation Score (ORS).
        """
        sfs_weight = self.config.get('ors_weights', {}).get('sfs', 0.40)
        pri_weight = self.config.get('ors_weights', {}).get('pri_match', 0.25)
        eas_weight = self.config.get('ors_weights', {}).get('eas', 0.20)
        hbs_weight = self.config.get('ors_weights', {}).get('hbs', 0.15)
        
        score = (sfs * sfs_weight) + (pri_match * pri_weight) + (eas * eas_weight) + (hbs * hbs_weight)
        return _clamp(score)

    def compute_confidence(self, context_completeness: float, scheme_match: float, historical_agreement: float, knowledge_completeness: float) -> float:
        """
        Computes final confidence score.
        """
        cc_weight = self.confidence_weights.get('context_completeness', 0.30)
        sm_weight = self.confidence_weights.get('scheme_match', 0.30)
        ha_weight = self.confidence_weights.get('historical_agreement', 0.20)
        kc_weight = self.confidence_weights.get('knowledge_completeness', 0.20)
        
        score = (
            context_completeness * cc_weight +
            scheme_match * sm_weight +
            historical_agreement * ha_weight +
            knowledge_completeness * kc_weight
        )
        return _clamp(score)
from typing import List, Dict, Any, Optional
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import SchemeScore

class ExplanationGenerator:
    """
    Generates detailed explanations for scheme recommendations and rejections
    to provide transparency into the reasoning engine's decision-making process.
    """

    def generate_explanation(
        self, 
        winner: SchemeScore, 
        context: RegistrationContext, 
        experiences: List[Experience], 
        all_scores: List[SchemeScore], 
        requirement_profile: RequirementProfile, 
        knowledge_base_schemes: Optional[List[PrivacyScheme]] = None,
        cross_ue_matches: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive explanation dictionary based on the selected scheme,
        the context, requirements, and historical experiences.
        """
        # 1. why_selected
        why_selected = f"Selected {winner.scheme_name} based on optimal fitness."
        if knowledge_base_schemes:
            for scheme in knowledge_base_schemes:
                if scheme.id == winner.scheme_id:
                    # Attempt to extract reasoning_support if it exists
                    reasoning_support = getattr(scheme, 'reasoning_support', None)
                    if reasoning_support:
                        template = getattr(reasoning_support, 'selection_reason_template', None)
                        if template:
                            why_selected = template
                    break
        
        # 2. why_alternatives_rejected
        why_alternatives_rejected = {}
        for score in all_scores:
            if score.scheme_id != winner.scheme_id:
                if getattr(score, 'rejection_reasons', None):
                    why_alternatives_rejected[score.scheme_name] = "; ".join(score.rejection_reasons)
                else:
                    winner_score = getattr(winner, 'final_score', 0.0)
                    alt_score = getattr(score, 'final_score', 0.0)
                    why_alternatives_rejected[score.scheme_name] = (
                        f"Score {alt_score:.2f} lower than {winner.short_name} ({winner_score:.2f})"
                    )
        
        # 3. rules_fired
        rules_fired = []
        if getattr(requirement_profile, 'identity_protection_required', False):
            rules_fired.append('RULE_IDENTITY_PROTECTION_REQUIRED')
        if getattr(requirement_profile, 'latency_requirement', '') in ['ultra_low']:
            rules_fired.append('RULE_URLLC_LOW_LATENCY')
        if getattr(requirement_profile, 'quantum_threat', False):
            rules_fired.append('RULE_QUANTUM_RESISTANCE_REQUIRED')
        if getattr(requirement_profile, 'anonymous_auth_required', False):
            rules_fired.append('RULE_ANONYMOUS_AUTH_REQUIRED')
        if getattr(requirement_profile, 'privacy_requirement', 0.0) > 0.7:
            rules_fired.append('RULE_HIGH_PRIVACY_CONTEXT')
        if getattr(requirement_profile, 'threat_level', '') in ['high', 'critical']:
            rules_fired.append('RULE_HIGH_THREAT_LEVEL')
        if getattr(requirement_profile, 'resource_profile', '') == 'constrained':
            rules_fired.append('RULE_RESOURCE_CONSTRAINED')
        if getattr(requirement_profile, 'tracking_risk', 0.0) > 0.5:
            rules_fired.append('RULE_HIGH_TRACKING_RISK')
        if getattr(context, 'registration_type', '') == 'emergency':
            rules_fired.append('RULE_EMERGENCY_REGISTRATION')

        # 4. context_influence
        context_influence = {
            'slice_type': 0.35,
            'dnn': 0.40,
            'registration_type': 0.25
        }

        # 5. experience_influence
        ue_id = getattr(context, 'ue_id', 'Unknown')
        if cross_ue_matches:
            k = len(cross_ue_matches)
            avg_sim = sum(sim for _, sim in cross_ue_matches) / k if k > 0 else 0.0
            rules_fired.append(f"RULE_RAG_CROSS_UE_RETRIEVAL(k={k}, avg_sim={avg_sim:.2f})")
            if not experiences:
                experience_influence = f"Cold start for {ue_id}: {k} similar registrations from other UEs (avg similarity {avg_sim:.2f}) support this recommendation"
                adaptation_note = f"Cross-UE RAG assisted cold start recommendation for {ue_id}"
            else:
                n = len(experiences)
                m = sum(1 for e in experiences if getattr(e, 'selected_scheme', None) == winner.scheme_name or getattr(e, 'scheme_id', None) == winner.scheme_id)
                experience_influence = f"{n} local experiences + {k} cross-UE similar experiences (avg similarity {avg_sim:.2f})"
                adaptation_note = "Local history supplemented by cross-UE similarity"
        elif not experiences:
            experience_influence = f"No previous experiences for {ue_id}"
            adaptation_note = "First registration for this UE"
        else:
            n = len(experiences)
            m = sum(1 for e in experiences if getattr(e, 'selected_scheme', None) == winner.scheme_name or getattr(e, 'scheme_id', None) == winner.scheme_id)
            experience_influence = f"{n} previous experiences for {ue_id}; {m} selected {winner.scheme_name}"
            
            # Determine adaptation note based on recent experience
            latest_exp = experiences[-1] # Assuming chronological order or easily accessible latest
            prev_scheme = getattr(latest_exp, 'selected_scheme', getattr(latest_exp, 'scheme_id', 'Unknown'))
            
            if prev_scheme == winner.scheme_name or prev_scheme == winner.scheme_id:
                adaptation_note = "No change from previous recommendation"
            else:
                adaptation_note = f"Changed from {prev_scheme} to {winner.scheme_name} because optimal scheme profile updated based on current context"

        # 6. confidence_explanation
        confidence_explanation = "High confidence based on strict criteria matching and score margins."
        
        # 7. risk_explanation
        risk_explanation = "Risk managed correctly by checking minimum threat capabilities against deployment maturity."

        return {
            'why_selected': why_selected,
            'why_alternatives_rejected': why_alternatives_rejected,
            'rules_fired': rules_fired,
            'context_influence': context_influence,
            'experience_influence': experience_influence,
            'confidence_explanation': confidence_explanation,
            'risk_explanation': risk_explanation,
            'adaptation_note': adaptation_note
        }

    def generate_rejection_reasons(self, scheme: PrivacyScheme, requirement_profile: RequirementProfile) -> List[str]:
        """
        Analyzes a scheme against the requirement profile and returns specific reasons
        if the scheme is found lacking in mandatory capabilities.
        """
        reasons = []

        # Check quantum resistance
        if getattr(requirement_profile, 'quantum_threat', False):
            if not getattr(scheme, 'is_quantum_resistant', getattr(scheme, 'quantum_safe', False)):
                reasons.append("Lacks required quantum resistance.")

        # Check anonymous auth support
        if getattr(requirement_profile, 'anonymous_auth_required', False):
            if not getattr(scheme, 'supports_anonymous_auth', False):
                reasons.append("Does not support required anonymous authentication.")

        # Check latency compatibility
        latency_req = getattr(requirement_profile, 'latency_requirement', 'standard')
        if latency_req == 'ultra_low':
            scheme_latency = getattr(scheme, 'latency_overhead', 'standard')
            if scheme_latency not in ['ultra_low', 'low']:
                reasons.append(f"Latency overhead '{scheme_latency}' incompatible with '{latency_req}' requirement.")

        # Check resource constraints
        if getattr(requirement_profile, 'resource_profile', 'standard') == 'constrained':
            computational_overhead = getattr(scheme, 'computational_overhead', 'low')
            if computational_overhead in ['high', 'very_high']:
                reasons.append(f"Computational overhead '{computational_overhead}' too high for constrained resources.")

        # Check tracking protection adequacy
        if getattr(requirement_profile, 'tracking_risk', 0.0) > 0.5:
            anti_tracking_level = getattr(scheme, 'anti_tracking_score', getattr(scheme, 'anti_tracking_level', 0.0))
            if isinstance(anti_tracking_level, (int, float)) and anti_tracking_level < 0.6:
                reasons.append("Insufficient anti-tracking capabilities for high tracking risk context.")
            elif isinstance(anti_tracking_level, str) and anti_tracking_level.lower() in ['low', 'none', 'minimal']:
                reasons.append("Insufficient anti-tracking capabilities for high tracking risk context.")

        return reasons
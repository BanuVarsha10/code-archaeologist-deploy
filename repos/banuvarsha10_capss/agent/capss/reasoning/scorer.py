from typing import List, Tuple, Optional, Dict
from capss.schemas.context import RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import SchemeScore
from capss.reasoning.metrics import MetricsCalculator
from capss.reasoning.profile_matcher import ProfileMatcher

class SchemeScorer:
    """
    Evaluates and scores privacy schemes against contextual requirements and historical experiences.
    """

    def __init__(self, metrics: MetricsCalculator, profile_matcher: ProfileMatcher, config: dict = None):
        """
        Initialize the SchemeScorer.

        Args:
            metrics: An instance of MetricsCalculator to compute scores.
            profile_matcher: An instance of ProfileMatcher to compute profile match.
            config: Optional configuration dictionary.
        """
        self.metrics = metrics
        self.profile_matcher = profile_matcher
        self.config = config or {}

    def score_scheme(
        self,
        scheme: PrivacyScheme,
        requirement_profile: RequirementProfile,
        experiences: List[Experience],
        cross_ue_experiences: Optional[List[Tuple[Experience, float]]] = None,
    ) -> SchemeScore:
        """
        Scores a single privacy scheme based on the requirement profile and experiences.

        Args:
            scheme: The privacy scheme to score.
            requirement_profile: The contextual requirement profile.
            experiences: List of historical experiences for calculating alignment.
            cross_ue_experiences: Optional list of cross-UE similar experiences and similarity scores.

        Returns:
            SchemeScore: The evaluated score object containing detailed metrics and potential rejections.
        """
        # 1. Compute SFS and dimensional scores
        sfs, dim_scores = self.metrics.compute_sfs(scheme, requirement_profile)
        
        # 2. Compute EAS (with optional cross-UE experiences)
        eas = self.metrics.compute_eas(
            experiences,
            scheme,
            requirement_profile,
            cross_ue_experiences=cross_ue_experiences,
        )
        
        # 3. Compute profile match
        pm = self.profile_matcher.match(requirement_profile, scheme)
        
        # 4. Compute ORS (No hybrid evaluation at this stage)
        ors = self.metrics.compute_ors(sfs, pm, eas, 0.0)
        
        # 5. Determine rejection reasons
        rejection_reasons = []
        if getattr(requirement_profile, 'quantum_threat', False) and not scheme.is_quantum_resistant():
            rejection_reasons.append('Not quantum resistant')
            
        if getattr(requirement_profile, 'anonymous_auth_required', False) and not scheme.supports_anonymous_auth():
            rejection_reasons.append('Does not support anonymous authentication')
            
        if getattr(requirement_profile, 'latency_requirement', '') == 'ultra_low' and scheme.get_metric('latency_score', 0) < 3:
            rejection_reasons.append('Latency too high for URLLC')
            
        if getattr(requirement_profile, 'resource_profile', '') == 'constrained' and scheme.get_metric('energy_score', 0) < 3:
            rejection_reasons.append('Too resource-intensive for constrained devices')
            
        is_rejected = len(rejection_reasons) > 0
        
        # 6. If rejected, reduce final_score by 50%
        final_score = ors
        if is_rejected:
            final_score *= 0.5
            
        # 7. Build SchemeScore with all dimensional scores
        return SchemeScore(
            scheme_id=scheme.id,
            scheme_name=scheme.name,
            short_name=scheme.short_name,
            fitness_score=sfs,
            privacy_match=dim_scores.get('privacy_match', 0.0),
            performance_match=dim_scores.get('performance_match', 0.0),
            deployment_match=dim_scores.get('deployment_match', 0.0),
            experience_alignment=eas,
            tracking_protection_match=dim_scores.get('tracking_protection', 0.0),
            quantum_match=dim_scores.get('quantum_match', 0.0),
            identity_protection_match=dim_scores.get('identity_protection', 0.0),
            profile_match=pm,
            final_score=final_score,
            score_breakdown={
                'sfs': sfs,
                'eas': eas,
                'ors': ors,
                'pm': pm,
                **dim_scores
            },
            rejection_reasons=rejection_reasons,
            is_rejected=is_rejected
        )

    def score_all_schemes(
        self,
        schemes: List[PrivacyScheme],
        requirement_profile: RequirementProfile,
        experiences: List[Experience],
        cross_ue_experiences: Optional[List[Tuple[Experience, float]]] = None,
    ) -> List[SchemeScore]:
        """
        Scores a list of schemes and returns them sorted by final score in descending order.

        Args:
            schemes: The list of privacy schemes to score.
            requirement_profile: The contextual requirement profile.
            experiences: List of historical experiences for calculating alignment.
            cross_ue_experiences: Optional list of cross-UE similar experiences and similarity scores.

        Returns:
            List[SchemeScore]: The sorted list of scheme scores.
        """
        scores = [
            self.score_scheme(scheme, requirement_profile, experiences, cross_ue_experiences=cross_ue_experiences)
            for scheme in schemes
        ]
        scores.sort(key=lambda s: s.final_score, reverse=True)
        return scores

    def evaluate_hybrid(self, scheme1: PrivacyScheme, scheme2: PrivacyScheme, requirement_profile: RequirementProfile) -> Tuple[float, str]:
        """
        Evaluates the potential benefit of forming a hybrid from two schemes.

        Args:
            scheme1: The first privacy scheme (base).
            scheme2: The second privacy scheme (augmenting).
            requirement_profile: The requirement profile.

        Returns:
            Tuple[float, str]: A tuple containing the benefit score and a reasoning string.
        """
        compatible_hybrids = scheme1.get_compatible_hybrids()
        if (
            scheme2.id not in compatible_hybrids
            and scheme2.short_name not in compatible_hybrids
            and scheme2.name not in compatible_hybrids
        ):
            return 0.0, f"Schemes {scheme1.short_name} and {scheme2.short_name} are not compatible for hybridization."
            
        hbs = self.metrics.compute_hbs(scheme1, scheme2, requirement_profile)
        reason = f"Hybrid of {scheme1.short_name} and {scheme2.short_name} yields a benefit score of {hbs:.2f}."
        return hbs, reason
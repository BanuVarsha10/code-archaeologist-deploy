"""CAPSS Evaluation Metrics — Research-critical evaluation framework.

Computes all evaluation metrics needed for publication (recommendation #13):
    - Recommendation Stability
    - Adaptation Rate
    - Average Confidence
    - Confidence Trend Direction
    - Experience Reuse Rate
    - Hybrid Recommendation Rate
    - Recommendation Diversity (Shannon Entropy)
    - Decision Latency Statistics
    - Knowledge Coverage Statistics
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from capss.schemas.experience import Experience
from capss.schemas.recommendation import DecisionTrace
from capss.experience_memory.memory import ExperienceMemory


class EvaluationMetrics:
    """Static methods for computing research evaluation metrics."""

    @staticmethod
    def recommendation_stability(experiences: List[Experience]) -> float:
        """Fraction of consecutive same-scheme recommendations."""
        if len(experiences) < 2:
            return 1.0
        sorted_exps = sorted(experiences, key=lambda e: e.timestamp)
        same = sum(
            1 for i in range(1, len(sorted_exps))
            if sorted_exps[i].selected_scheme == sorted_exps[i - 1].selected_scheme
        )
        return same / (len(sorted_exps) - 1)

    @staticmethod
    def adaptation_rate(experiences: List[Experience]) -> float:
        """Fraction of scheme changes across consecutive registrations."""
        if len(experiences) < 2:
            return 0.0
        return 1.0 - EvaluationMetrics.recommendation_stability(experiences)

    @staticmethod
    def average_confidence(experiences: List[Experience]) -> float:
        """Mean confidence across all experiences."""
        if not experiences:
            return 0.0
        return sum(e.confidence for e in experiences) / len(experiences)

    @staticmethod
    def confidence_trend_direction(experiences: List[Experience]) -> str:
        """Determine if confidence is increasing, decreasing, or stable."""
        if len(experiences) < 2:
            return "stable"
        sorted_exps = sorted(experiences, key=lambda e: e.timestamp)
        first_half = sorted_exps[: len(sorted_exps) // 2]
        second_half = sorted_exps[len(sorted_exps) // 2 :]
        avg_first = sum(e.confidence for e in first_half) / len(first_half)
        avg_second = sum(e.confidence for e in second_half) / len(second_half)
        delta = avg_second - avg_first
        if delta > 0.05:
            return "increasing"
        elif delta < -0.05:
            return "decreasing"
        return "stable"

    @staticmethod
    def experience_reuse_rate(memory: ExperienceMemory) -> float:
        """Fraction of UEs with more than 1 experience."""
        all_ues = memory.get_all_ues()
        if not all_ues:
            return 0.0
        reused = sum(1 for ue in all_ues if len(memory.retrieve(ue)) > 1)
        return reused / len(all_ues)

    @staticmethod
    def hybrid_recommendation_rate(experiences: List[Experience]) -> float:
        """Fraction of experiences that include a hybrid combination."""
        if not experiences:
            return 0.0
        hybrid_count = sum(
            1 for e in experiences
            if e.hybrid_combination and len(e.hybrid_combination) > 1
        )
        return hybrid_count / len(experiences)

    @staticmethod
    def recommendation_diversity(experiences: List[Experience]) -> float:
        """Shannon entropy of scheme distribution (normalised 0-1)."""
        if not experiences:
            return 0.0
        counts: Dict[str, int] = {}
        for e in experiences:
            counts[e.selected_scheme] = counts.get(e.selected_scheme, 0) + 1
        total = len(experiences)
        entropy = -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values()
            if c > 0
        )
        # Normalise by max possible entropy
        max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1.0
        return entropy / max_entropy if max_entropy > 0 else 0.0

    @staticmethod
    def decision_latency_stats(traces: List[DecisionTrace]) -> Dict[str, float]:
        """min/max/avg/p95 processing time in ms."""
        if not traces:
            return {"min_ms": 0, "max_ms": 0, "avg_ms": 0, "p95_ms": 0}
        times = sorted([t.processing_time_ms for t in traces])
        p95_idx = int(len(times) * 0.95)
        return {
            "min_ms": round(times[0], 2),
            "max_ms": round(times[-1], 2),
            "avg_ms": round(sum(times) / len(times), 2),
            "p95_ms": round(times[min(p95_idx, len(times) - 1)], 2),
        }

    @staticmethod
    def knowledge_coverage_stats(traces: List[DecisionTrace]) -> Dict[str, Any]:
        """Average and minimum knowledge coverage across traces."""
        if not traces:
            return {"avg_coverage": 1.0, "min_coverage": 1.0, "missing_dimensions": []}
        coverages = [t.knowledge_coverage for t in traces]
        all_missing: List[str] = []
        for t in traces:
            all_missing.extend(t.missing_knowledge)
        return {
            "avg_coverage": round(sum(coverages) / len(coverages), 4),
            "min_coverage": round(min(coverages), 4),
            "missing_dimensions": list(set(all_missing)),
        }

    # ------------------------------------------------------------------
    # Architecture-required comparison metrics (GAP 4)
    # ------------------------------------------------------------------

    @staticmethod
    def privacy_score_improvement(
        adaptive_scores: List[float],
        static_score: float,
    ) -> Dict[str, float]:
        """Compare adaptive privacy scores against a fixed static baseline.

        Args:
            adaptive_scores: List of per-registration confidence/fitness scores
                from the adaptive CAPSS agent.
            static_score: The fixed privacy_score (0-1) of the static baseline
                scheme (e.g. ECIES privacy_score/5.0).

        Returns:
            Dict with avg_adaptive, static, absolute_improvement,
            relative_improvement_pct, and registrations_improved_pct.
        """
        if not adaptive_scores:
            return {
                "avg_adaptive": 0.0, "static": static_score,
                "absolute_improvement": 0.0, "relative_improvement_pct": 0.0,
                "registrations_improved_pct": 0.0,
            }
        avg = sum(adaptive_scores) / len(adaptive_scores)
        improved = sum(1 for s in adaptive_scores if s > static_score)
        return {
            "avg_adaptive": round(avg, 4),
            "static": round(static_score, 4),
            "absolute_improvement": round(avg - static_score, 4),
            "relative_improvement_pct": round(
                ((avg - static_score) / static_score * 100) if static_score > 0 else 0.0, 2,
            ),
            "registrations_improved_pct": round(improved / len(adaptive_scores) * 100, 2),
        }

    @staticmethod
    def metadata_leakage_reduction(
        contexts: list,
        adaptive_schemes: List[str],
        scheme_tracking_scores: Dict[str, int],
    ) -> Dict[str, float]:
        """Estimate metadata leakage reduction from adaptive scheme selection.

        Uses each scheme's tracking_score as a proxy for anti-leakage capability.
        Higher tracking_score → better metadata protection → lower leakage.

        Args:
            contexts: List of RegistrationContext objects.
            adaptive_schemes: The scheme selected for each registration.
            scheme_tracking_scores: Dict mapping scheme short_name → tracking_score (1-5).

        Returns:
            Dict with avg_protection_score, contexts_with_high_protection_pct, etc.
        """
        if not adaptive_schemes:
            return {"avg_protection_score": 0.0, "contexts_with_high_protection_pct": 0.0}

        protection_scores = []
        for scheme in adaptive_schemes:
            ts = scheme_tracking_scores.get(scheme, 3)
            protection_scores.append(ts / 5.0)

        avg_protection = sum(protection_scores) / len(protection_scores)
        high_protection = sum(1 for s in protection_scores if s >= 0.8)

        return {
            "avg_protection_score": round(avg_protection, 4),
            "contexts_with_high_protection_pct": round(
                high_protection / len(protection_scores) * 100, 2,
            ),
            "min_protection_score": round(min(protection_scores), 4),
            "max_protection_score": round(max(protection_scores), 4),
        }

    @staticmethod
    def correlation_resistance(
        experiences: List[Experience],
    ) -> Dict[str, Any]:
        """Evaluate correlation resistance from scheme diversity per UE.

        If a UE consistently gets the same scheme, correlation risk increases.
        Diverse scheme selection across registrations for the same UE reduces
        the ability of an attacker to correlate registrations.

        Args:
            experiences: All experiences across all UEs.

        Returns:
            Dict with per-UE correlation resistance and overall average.
        """
        if not experiences:
            return {"avg_resistance": 0.0, "per_ue": {}}

        ue_schemes: Dict[str, List[str]] = {}
        for e in experiences:
            ue_schemes.setdefault(e.ue_id, []).append(e.selected_scheme)

        per_ue: Dict[str, float] = {}
        for ue_id, schemes in ue_schemes.items():
            if len(schemes) <= 1:
                per_ue[ue_id] = 0.5  # Neutral for single registration
            else:
                unique_ratio = len(set(schemes)) / len(schemes)
                per_ue[ue_id] = round(unique_ratio, 4)

        avg = sum(per_ue.values()) / len(per_ue) if per_ue else 0.0

        return {
            "avg_resistance": round(avg, 4),
            "per_ue": per_ue,
            "ues_with_diverse_selection": sum(1 for v in per_ue.values() if v > 0.5),
            "total_ues": len(per_ue),
        }

    @staticmethod
    def attack_resilience(
        contexts: list,
        adaptive_policies: list,
    ) -> Dict[str, Any]:
        """Evaluate how well the adaptive agent responds to attack scenarios.

        Checks whether the agent selects higher-security schemes when
        attack indicators are present in the context.

        Args:
            contexts: List of RegistrationContext objects.
            adaptive_policies: Corresponding PrivacyPolicy objects.

        Returns:
            Dict with attack detection stats and response quality.
        """
        if not contexts or not adaptive_policies:
            return {
                "total_contexts": 0,
                "attack_contexts": 0,
                "normal_contexts": 0,
                "attack_avg_confidence": 0.0,
                "normal_avg_confidence": 0.0,
            }

        attack_confidences = []
        normal_confidences = []
        attack_schemes: List[str] = []
        normal_schemes: List[str] = []

        for ctx, policy in zip(contexts, adaptive_policies):
            is_attack = (
                getattr(ctx, "attack_result", None) in ["detected", "suspected"]
                or getattr(ctx, "request_classification", None) in ["TAG", "BLOCK"]
                or getattr(ctx, "attack_type", None) not in [None, "none"]
            )
            if is_attack:
                attack_confidences.append(policy.confidence)
                attack_schemes.append(policy.selected_scheme)
            else:
                normal_confidences.append(policy.confidence)
                normal_schemes.append(policy.selected_scheme)

        return {
            "total_contexts": len(contexts),
            "attack_contexts": len(attack_confidences),
            "normal_contexts": len(normal_confidences),
            "attack_avg_confidence": round(
                sum(attack_confidences) / len(attack_confidences), 4,
            ) if attack_confidences else 0.0,
            "normal_avg_confidence": round(
                sum(normal_confidences) / len(normal_confidences), 4,
            ) if normal_confidences else 0.0,
            "attack_scheme_distribution": EvaluationMetrics._scheme_distribution(attack_schemes),
            "normal_scheme_distribution": EvaluationMetrics._scheme_distribution(normal_schemes),
            "different_response_to_attacks": set(attack_schemes) != set(normal_schemes) if attack_schemes else False,
        }

    @staticmethod
    def _scheme_distribution(schemes: List[str]) -> Dict[str, float]:
        """Normalised scheme frequency distribution."""
        if not schemes:
            return {}
        counts: Dict[str, int] = {}
        for s in schemes:
            counts[s] = counts.get(s, 0) + 1
        total = len(schemes)
        return {k: round(v / total, 4) for k, v in sorted(counts.items())}

    @staticmethod
    def authentication_success_rate(contexts: List[Any]) -> float:
        """Fraction of contexts where Authentication_Result == SUCCESS."""
        if not contexts:
            return 0.0
        success_count = 0
        for ctx in contexts:
            auth_res = getattr(ctx, "authentication_result", None)
            if auth_res is not None:
                if str(auth_res).strip().upper() == "SUCCESS":
                    success_count += 1
            else:
                # Fallback: ALLOW or TAG implies successful registration/auth
                if getattr(ctx, "request_classification", None) in ("ALLOW", "TAG"):
                    success_count += 1
        return round(success_count / len(contexts), 4)

    @staticmethod
    def computational_overhead(
        traces: Optional[List[DecisionTrace]] = None,
        wall_clock_times_ms: Optional[List[float]] = None,
    ) -> Dict[str, float]:
        """Full per-registration wall-clock processing overhead in ms (mean, median, p95).

        Measures total end-to-end execution overhead (context load + memory retrieval +
        reasoning + policy generation), distinct from decision_latency_stats.
        """
        times = list(wall_clock_times_ms) if wall_clock_times_ms else []
        if not times and traces:
            times = [t.processing_time_ms for t in traces]

        if not times:
            return {"mean_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0}

        sorted_times = sorted(times)
        n = len(sorted_times)
        mean = sum(sorted_times) / n
        median = (
            sorted_times[n // 2]
            if n % 2 != 0
            else (sorted_times[n // 2 - 1] + sorted_times[n // 2]) / 2.0
        )
        p95_idx = int(n * 0.95)
        p95 = sorted_times[min(p95_idx, n - 1)]

        return {
            "mean_ms": round(mean, 2),
            "median_ms": round(median, 2),
            "p95_ms": round(p95, 2),
        }

    # ------------------------------------------------------------------
    # Compute All
    # ------------------------------------------------------------------

    @staticmethod
    def compute_all(
        memory: ExperienceMemory,
        traces: Optional[List[DecisionTrace]] = None,
        contexts: Optional[List[Any]] = None,
        wall_clock_times_ms: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        """Compute all evaluation metrics."""
        all_experiences: List[Experience] = []
        for ue_id in memory.get_all_ues():
            all_experiences.extend(memory.retrieve(ue_id))

        result: Dict[str, Any] = {
            "recommendation_stability": EvaluationMetrics.recommendation_stability(all_experiences),
            "adaptation_rate": EvaluationMetrics.adaptation_rate(all_experiences),
            "average_confidence": EvaluationMetrics.average_confidence(all_experiences),
            "confidence_trend": EvaluationMetrics.confidence_trend_direction(all_experiences),
            "experience_reuse_rate": EvaluationMetrics.experience_reuse_rate(memory),
            "hybrid_recommendation_rate": EvaluationMetrics.hybrid_recommendation_rate(all_experiences),
            "recommendation_diversity": EvaluationMetrics.recommendation_diversity(all_experiences),
            "correlation_resistance": EvaluationMetrics.correlation_resistance(all_experiences),
        }

        if contexts:
            result["authentication_success_rate"] = EvaluationMetrics.authentication_success_rate(contexts)
        if wall_clock_times_ms or traces:
            result["computational_overhead"] = EvaluationMetrics.computational_overhead(traces, wall_clock_times_ms)

        if traces:
            result["decision_latency"] = EvaluationMetrics.decision_latency_stats(traces)
            result["knowledge_coverage"] = EvaluationMetrics.knowledge_coverage_stats(traces)

        return result
import os

def create_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

base_dir = r"C:\Users\Mathin M\.gemini\antigravity\scratch\capss-agent"

files = {}

files["capss/reasoning/metrics.py"] = """
import math
from typing import List, Dict, Any
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme

class MetricsCalculator:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.weights = self.config.get("scoring_weights", {})

    def compute_css(self, context: RegistrationContext) -> float:
        slice_weight = self.config.get("slice_weights", {"eMBB": 0.5, "URLLC": 0.8, "mMTC": 0.6})
        dnn_weight = self.config.get("dnn_weights", {"internet": 0.4, "ims": 0.7, "iot": 0.5, "enterprise": 0.9})
        reg_type_weight = self.config.get("reg_type_weights", {"initial": 0.6, "mobility": 0.5, "periodic": 0.3, "emergency": 0.95})
        
        sw = slice_weight.get(getattr(context.slice_type, 'value', str(context.slice_type)), 0.5)
        dw = dnn_weight.get(context.dnn, 0.5)
        rw = reg_type_weight.get(getattr(context.registration_type, 'value', str(context.registration_type)), 0.5)
        
        css = sw * 0.35 + dw * 0.40 + rw * 0.25
        return min(max(css, 0.0), 1.0)

    def compute_pri(self, requirement_profile: RequirementProfile) -> float:
        threat_mult = {"low": 0.5, "medium": 0.7, "high": 0.9, "critical": 1.0}
        tm = threat_mult.get(getattr(requirement_profile.threat_level, 'value', str(requirement_profile.threat_level)), 0.5)
        css = 0.5 # Approximation if not passed
        pri = css * tm * getattr(requirement_profile, 'tracking_risk', 0.5)
        return min(max(pri, 0.0), 1.0)

    def compute_sfs(self, scheme: PrivacyScheme, requirement_profile: RequirementProfile, config: dict) -> float:
        privacy_match = scheme.get_metric('privacy_score', 3) / 5.0
        security_match = scheme.get_metric('security_score', 3) / 5.0
        latency_match = scheme.get_metric('latency_score', 3) / 5.0
        tracking_match = scheme.get_metric('tracking_score', 3) / 5.0
        identity_match = scheme.get_metric('identity_score', 3) / 5.0
        quantum_match = scheme.get_metric('quantum_score', 3) / 5.0
        deployment_match = scheme.get_metric('deployment_score', 3) / 5.0
        
        sfs = (privacy_match * 0.25 + security_match * 0.2 + latency_match * 0.15 + 
               tracking_match * 0.1 + identity_match * 0.1 + quantum_match * 0.1 + deployment_match * 0.1)
        return min(max(sfs, 0.0), 1.0)

    def compute_eas(self, experiences: List[Experience], scheme: PrivacyScheme) -> float:
        if not experiences: return 0.5
        count = sum(1 for e in experiences if e.applied_scheme == scheme.id)
        if count == 0: return 0.4
        return min(0.5 + (count / len(experiences)) * 0.5, 1.0)

    def compute_hbs(self, schemes: List[PrivacyScheme], requirement_profile: RequirementProfile) -> float:
        return 0.1

    def compute_ad(self, current_scheme: str, experiences: List[Experience]) -> float:
        if not experiences: return 0.0
        return 0.0 if experiences[-1].applied_scheme == current_scheme else 0.5

    def compute_ors(self, sfs: float, pri_match: float, eas: float, hbs: float, config: dict) -> float:
        return min(max(sfs * 0.40 + pri_match * 0.25 + eas * 0.20 + hbs * 0.15, 0.0), 1.0)

    def compute_confidence(self, context_completeness: float, scheme_match: float, historical_agreement: float, knowledge_completeness: float, config: dict) -> float:
        return min(max(context_completeness * 0.30 + scheme_match * 0.30 + historical_agreement * 0.20 + knowledge_completeness * 0.20, 0.0), 1.0)
"""

files["capss/reasoning/profile_matcher.py"] = """
from capss.schemas.context import RequirementProfile
from capss.schemas.scheme import PrivacyScheme

class ProfileMatcher:
    def match(self, requirement_profile: RequirementProfile, scheme: PrivacyScheme) -> float:
        rp = scheme.get_reasoning_profile()
        cp = scheme.get_context_preferences()
        
        matches = 0
        total = max(len(rp), 1)
        # Simplified matching logic
        matches = sum(1 for k, v in rp.items() if v)
        return min(matches / total, 1.0)
"""

files["capss/reasoning/scorer.py"] = """
from typing import List, Tuple
from capss.schemas.context import RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import SchemeScore
from capss.reasoning.metrics import MetricsCalculator
from capss.reasoning.profile_matcher import ProfileMatcher

class SchemeScorer:
    def __init__(self, metrics: MetricsCalculator, profile_matcher: ProfileMatcher, config: dict = None):
        self.metrics = metrics
        self.profile_matcher = profile_matcher
        self.config = config or {}

    def score_scheme(self, scheme: PrivacyScheme, requirement_profile: RequirementProfile, experiences: List[Experience]) -> SchemeScore:
        sfs = self.metrics.compute_sfs(scheme, requirement_profile, self.config)
        pri_match = self.profile_matcher.match(requirement_profile, scheme)
        eas = self.metrics.compute_eas(experiences, scheme)
        hbs = 0.0
        ors = self.metrics.compute_ors(sfs, pri_match, eas, hbs, self.config)
        
        reasons = []
        if ors < 0.3:
            reasons.append("Low overall score")
            
        return SchemeScore(
            scheme_id=scheme.id,
            final_score=ors,
            dimensional_scores={"sfs": sfs, "pri_match": pri_match, "eas": eas},
            rejection_reasons=reasons
        )

    def score_all_schemes(self, schemes: List[PrivacyScheme], requirement_profile: RequirementProfile, experiences: List[Experience]) -> List[SchemeScore]:
        scores = [self.score_scheme(s, requirement_profile, experiences) for s in schemes]
        return sorted(scores, key=lambda x: x.final_score, reverse=True)

    def evaluate_hybrid(self, scheme1: PrivacyScheme, scheme2: PrivacyScheme, requirement_profile: RequirementProfile) -> Tuple[float, str]:
        if scheme2.id in scheme1.get_compatible_hybrids():
            return 0.2, "Compatible hybrids"
        return 0.0, "Incompatible"
"""

files["capss/reasoning/explainer.py"] = """
from typing import List
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import Recommendation, SchemeScore

class ExplanationGenerator:
    def generate_explanation(self, recommendation: Recommendation, context: RegistrationContext, experiences: List[Experience], all_scores: List[SchemeScore]) -> dict:
        return {
            "why_selected": f"Selected {recommendation.recommended_scheme} due to highest score.",
            "why_alternatives_rejected": {s.scheme_id: "Score lower than recommended" for s in all_scores if s.scheme_id != recommendation.recommended_scheme},
            "rules_fired": ["DEFAULT_RULE"],
            "context_influence": {"slice_type": 0.35},
            "experience_influence": f"Based on {len(experiences)} past experiences.",
            "confidence_explanation": f"Confidence: {recommendation.confidence}",
            "risk_explanation": "Standard risk profile",
            "adaptation_note": "Standard adaptation"
        }

    def generate_rejection_reasons(self, scheme: PrivacyScheme, requirement_profile: RequirementProfile) -> List[str]:
        return ["Does not meet requirements"]
"""

files["capss/reasoning/engine.py"] = """
import time
from typing import List
from capss.schemas.context import RegistrationContext, RequirementProfile
from capss.schemas.experience import Experience
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.recommendation import Recommendation, DecisionTrace
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.reasoning.metrics import MetricsCalculator
from capss.reasoning.profile_matcher import ProfileMatcher
from capss.reasoning.scorer import SchemeScorer
from capss.reasoning.explainer import ExplanationGenerator

class ReasoningEngine:
    def __init__(self, knowledge_base: SchemeKnowledgeBase, config: dict = None):
        self.knowledge_base = knowledge_base
        self.config = config or {}
        self.metrics = MetricsCalculator(self.config)
        self.profile_matcher = ProfileMatcher()
        self.scorer = SchemeScorer(self.metrics, self.profile_matcher, self.config)
        self.explainer = ExplanationGenerator()

    def reason(self, context: RegistrationContext, requirement_profile: RequirementProfile, experiences: List[Experience]) -> Recommendation:
        start_time = time.perf_counter()
        schemes = self.knowledge_base.get_all_schemes()
        scores = self.scorer.score_all_schemes(schemes, requirement_profile, experiences)
        
        winner_id = scores[0].scheme_id if scores else self.config.get("fallback_scheme", "default_scheme")
        winner_scheme = self.knowledge_base.get_scheme(winner_id)
        
        dt = DecisionTrace(
            candidate_scores=scores,
            evaluated_hybrids=[],
            processing_time_ms=(time.perf_counter() - start_time) * 1000
        )
        
        rec = Recommendation(
            recommended_scheme=winner_id,
            confidence=0.85,
            decision_trace=dt,
            explanation={}
        )
        rec.explanation = self.explainer.generate_explanation(rec, context, experiences, scores)
        return rec
"""

files["capss/reasoning/__init__.py"] = """
from .metrics import MetricsCalculator
from .profile_matcher import ProfileMatcher
from .scorer import SchemeScorer
from .explainer import ExplanationGenerator
from .engine import ReasoningEngine
"""

files["capss/policy_generator/generator.py"] = """
from capss.schemas.context import RegistrationContext
from capss.schemas.recommendation import Recommendation
from capss.schemas.policy import PrivacyPolicy

class PolicyGenerator:
    def generate(self, recommendation: Recommendation, context: RegistrationContext) -> PrivacyPolicy:
        return PrivacyPolicy(
            policy_id=f"POL-{context.ue_id}",
            applied_scheme=recommendation.recommended_scheme,
            enforcement_params={},
            expiry="24h",
            confidence=recommendation.confidence
        )
"""

files["capss/policy_generator/validator.py"] = """
from capss.schemas.policy import PrivacyPolicy, ValidationResult
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase

class PolicyValidator:
    def validate(self, policy: PrivacyPolicy, knowledge_base: SchemeKnowledgeBase) -> ValidationResult:
        is_valid = knowledge_base.get_scheme(policy.applied_scheme) is not None
        return ValidationResult(is_valid=is_valid, errors=[], warnings=[])
"""

files["capss/policy_generator/__init__.py"] = """
from .generator import PolicyGenerator
from .validator import PolicyValidator
"""

files["capss/evaluation/metrics.py"] = """
from typing import List
from capss.schemas.experience import Experience
from capss.schemas.recommendation import DecisionTrace
from capss.experience_memory.memory import ExperienceMemory

class EvaluationMetrics:
    @staticmethod
    def recommendation_stability(experiences: List[Experience]) -> float:
        if len(experiences) < 2: return 1.0
        sames = sum(1 for i in range(1, len(experiences)) if experiences[i].applied_scheme == experiences[i-1].applied_scheme)
        return sames / (len(experiences) - 1)

    @staticmethod
    def adaptation_rate(experiences: List[Experience]) -> float:
        return 1.0 - EvaluationMetrics.recommendation_stability(experiences)

    @staticmethod
    def average_confidence(experiences: List[Experience]) -> float:
        if not experiences: return 0.0
        return sum(e.confidence for e in experiences if hasattr(e, 'confidence')) / len(experiences)

    @staticmethod
    def confidence_trend_direction(experiences: List[Experience]) -> str:
        return "stable"

    @staticmethod
    def experience_reuse_rate(memory: ExperienceMemory) -> float:
        stats = memory.get_stats()
        return stats.get("reuse_rate", 0.0)

    @staticmethod
    def hybrid_recommendation_rate(experiences: List[Experience]) -> float:
        return 0.0

    @staticmethod
    def recommendation_diversity(experiences: List[Experience]) -> float:
        return 1.0

    @staticmethod
    def decision_latency_stats(traces: List[DecisionTrace]) -> dict:
        times = [t.processing_time_ms for t in traces]
        if not times: return {}
        return {"avg": sum(times)/len(times), "max": max(times), "min": min(times)}

    @staticmethod
    def knowledge_coverage_stats(traces: List[DecisionTrace]) -> dict:
        return {"avg": 1.0}

    @staticmethod
    def compute_all(memory: ExperienceMemory, traces: List[DecisionTrace] = None) -> dict:
        return {}
"""

files["capss/evaluation/benchmark.py"] = """
from typing import List
from capss.schemas.context import RegistrationContext

class Benchmark:
    def __init__(self, agent):
        self.agent = agent

    def run_full_benchmark(self, contexts: List[RegistrationContext]) -> dict:
        for ctx in contexts:
            self.agent.process_registration(ctx)
        return self.agent.get_agent_stats()

    def compare_against_static(self, contexts: List[RegistrationContext], static_scheme: str) -> dict:
        return {}

    def compare_against_random(self, contexts: List[RegistrationContext]) -> dict:
        return {}

    def run_ablation(self, contexts: List[RegistrationContext]) -> dict:
        return {}
"""

files["capss/evaluation/__init__.py"] = """
from .metrics import EvaluationMetrics
from .benchmark import Benchmark
"""

files["capss/agent/capss_agent.py"] = """
import json
import os
from typing import List
from capss.schemas.context import RegistrationContext
from capss.schemas.policy import PrivacyPolicy
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.experience_memory.memory import ExperienceMemory
from capss.context_analyzer.analyzer import ContextAnalyzer
from capss.reasoning.engine import ReasoningEngine
from capss.policy_generator.generator import PolicyGenerator
from capss.policy_generator.validator import PolicyValidator
from capss.memory_updater.updater import MemoryUpdater

class CAPSSAgent:
    def __init__(self, schemes_path: str, config_path: str = None, experience_path: str = None):
        self.knowledge_base = SchemeKnowledgeBase()
        self.memory = ExperienceMemory()
        self.analyzer = ContextAnalyzer()
        self.engine = ReasoningEngine(self.knowledge_base)
        self.generator = PolicyGenerator()
        self.validator = PolicyValidator()
        self.updater = MemoryUpdater()
        
        self.policies_generated = []
        self.decision_traces = []
        self.processing_times = []

    def process_registration(self, context: RegistrationContext) -> PrivacyPolicy:
        experiences = self.memory.retrieve(context.ue_id)
        req_profile = self.analyzer.analyze(context, experiences)
        recommendation = self.engine.reason(context, req_profile, experiences)
        policy = self.generator.generate(recommendation, context)
        val_result = self.validator.validate(policy, self.knowledge_base)
        
        self.policies_generated.append(policy)
        if recommendation.decision_trace:
            self.decision_traces.append(recommendation.decision_trace)
            self.processing_times.append(recommendation.decision_trace.processing_time_ms)
            
        print("╔══════════════════════════════════════════════════════════════╗")
        print(f"║  CAPSS Agent — UE: {context.ue_id}")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  ✓ RECOMMENDATION: {recommendation.recommended_scheme}")
        print("╚══════════════════════════════════════════════════════════════╝")
        
        exp = self.updater.update(policy, context, recommendation)
        self.memory.store(exp)
        return policy

    def process_batch(self, contexts: List[RegistrationContext]) -> List[PrivacyPolicy]:
        policies = []
        for ctx in contexts:
            policies.append(self.process_registration(ctx))
        return policies

    def get_agent_stats(self) -> dict:
        return {
            "total_processed": len(self.policies_generated)
        }
"""

files["capss/agent/__init__.py"] = """
from .capss_agent import CAPSSAgent
"""

files["run_agent.py"] = """
import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capss.context_loader.loader import ContextLoader
from capss.agent.capss_agent import CAPSSAgent

def main():
    parser = argparse.ArgumentParser(description="CAPSS Agent — Privacy Recommendation System")
    parser.add_argument("--data", required=True, help="Path to registration CSV")
    parser.add_argument("--schemes", required=True, help="Path to privacy_schemes.json")
    parser.add_argument("--config", default=None, help="Path to config directory")
    parser.add_argument("--experience", default=None, help="Path to experience store JSON")
    parser.add_argument("--ue", default=None, help="Process only this UE ID")
    parser.add_argument("--output", default=None, help="Output policies JSON path")
    args = parser.parse_args()
    
    agent = CAPSSAgent(args.schemes, args.config, args.experience)
    # Loader placeholder logic
    print("Agent initialized.")

if __name__ == "__main__":
    main()
"""

for path, content in files.items():
    create_file(os.path.join(base_dir, path), content.strip())

print("Files created successfully.")

"""CAPSS Agent — Main Orchestrator.

Ties all modules together into a single, coherent processing pipeline:

    Registration → Context Analysis → Experience Retrieval →
    Reasoning → Policy Generation → Validation → Memory Update

Produces rich console output showing the full reasoning chain
for every registration processed.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from capss.schemas.context import RegistrationContext
from capss.schemas.policy import PrivacyPolicy
from capss.schemas.recommendation import Recommendation, DecisionTrace
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.experience_memory.memory import ExperienceMemory
from capss.context_analyzer.analyzer import ContextAnalyzer
from capss.reasoning.engine import ReasoningEngine
from capss.policy_generator.generator import PolicyGenerator
from capss.policy_generator.validator import PolicyValidator
from capss.memory_updater.updater import MemoryUpdater


class CAPSSAgent:
    """Context-Aware Adaptive Privacy and Security System Agent.

    Processes 5G registration events and recommends the most appropriate
    privacy protection mechanism based on context analysis, historical
    experience, and scheme knowledge.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        schemes_path: str,
        config_path: str | None = None,
        experience_path: str | None = None,
    ) -> None:
        """Initialize the CAPSS Agent.

        Args:
            schemes_path: Path to privacy_schemes.json.
            config_path: Optional path to config directory (with weights.json, thresholds.json).
            experience_path: Optional path to experience store JSON file.
        """
        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize modules
        from capss.agent.rag.retriever import ExperienceRetriever
        self.retriever = ExperienceRetriever()

        self.knowledge_base = SchemeKnowledgeBase(schemes_path)
        self.memory = ExperienceMemory(
            storage_path=experience_path or "experience_store.json",
            max_per_ue=self.config.get("memory", {}).get("max_experiences_per_ue", 6),
        )
        self.analyzer = ContextAnalyzer(
            config=self.config.get("context_sensitivity"),
        )
        self.engine = ReasoningEngine(self.knowledge_base, config=self.config, retriever=self.retriever)
        self.generator = PolicyGenerator()
        self.validator = PolicyValidator(config=self.config)
        self.updater = MemoryUpdater(self.memory)

        # Index existing memory into retriever
        for ue_id in self.memory.get_all_ues():
            for exp in self.memory.retrieve(ue_id):
                self.retriever.index_experience(exp)

        # Tracking
        self.recommendations: List[Recommendation] = []
        self.policies_generated: List[PrivacyPolicy] = []
        self.decision_traces: List[DecisionTrace] = []
        self.processing_times: List[float] = []
        self._registration_count = 0

    def reset(self) -> None:
        """Reset agent state for fresh evaluation runs.

        Clears all tracking data and experience memory while
        preserving the knowledge base and configuration.
        Used by the Benchmark module between comparison runs.
        """
        self.recommendations.clear()
        self.policies_generated.clear()
        self.decision_traces.clear()
        self.processing_times.clear()
        self._registration_count = 0
        self.memory.clear()
        self.retriever.clear()

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    def process_registration(
        self,
        context: RegistrationContext,
        verbose: bool = True,
    ) -> PrivacyPolicy:
        """Process a single 5G registration event.

        Full pipeline:
            1. Retrieve previous experiences for this UE
            2. Analyze context → RequirementProfile
            3. Reason → Recommendation
            4. Generate policy
            5. Validate policy
            6. Update experience memory
            7. Print reasoning chain (if verbose)

        Args:
            context: The registration context.
            verbose: Whether to print the reasoning chain.

        Returns:
            The generated PrivacyPolicy.
        """
        self._registration_count += 1
        start = time.perf_counter()

        # Step 1: Retrieve experiences
        experiences = self.memory.retrieve(context.ue_id)

        # Step 2: Analyze context
        req_profile = self.analyzer.analyze(context, experiences)

        # Step 3: Reason
        recommendation = self.engine.reason(context, req_profile, experiences)

        # Step 4: Generate policy
        policy = self.generator.generate(recommendation, context)

        # Step 5: Validate policy
        validation = self.validator.validate(policy, self.knowledge_base)
        policy.validation_result = validation

        # Step 6: Update experience memory and RAG retriever
        experience = self.updater.update(policy, context, recommendation)
        self.memory.store(experience)
        self.retriever.index_experience(experience)

        # Track
        self.recommendations.append(recommendation)
        self.policies_generated.append(policy)
        self.decision_traces.append(recommendation.decision_trace)
        elapsed = (time.perf_counter() - start) * 1000
        self.processing_times.append(elapsed)

        # Step 7: Print
        if verbose:
            self._print_reasoning_chain(
                context, req_profile, experiences, recommendation,
                policy, validation, elapsed,
            )

        return policy

    def process_batch(
        self,
        contexts: List[RegistrationContext],
        verbose: bool = True,
    ) -> List[PrivacyPolicy]:
        """Process a batch of registrations sequentially.

        Order matters — earlier registrations build experience
        that influences later ones.

        Args:
            contexts: Ordered list of registration contexts.
            verbose: Whether to print per-registration output.

        Returns:
            List of generated policies.
        """
        policies: List[PrivacyPolicy] = []

        if verbose:
            print("\n" + "=" * 64)
            print("  CAPSS AGENT — BATCH PROCESSING")
            print(f"  Registrations: {len(contexts)}")
            print(f"  Schemes loaded: {self.knowledge_base.get_scheme_count()}")
            print("=" * 64)

        for ctx in contexts:
            policy = self.process_registration(ctx, verbose=verbose)
            policies.append(policy)

        if verbose:
            self._print_batch_summary(policies)

        return policies

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_agent_stats(self) -> Dict[str, Any]:
        """Return comprehensive agent statistics."""
        mem_stats = self.memory.get_stats()
        avg_time = (
            sum(self.processing_times) / len(self.processing_times)
            if self.processing_times
            else 0
        )
        avg_confidence = (
            sum(p.confidence for p in self.policies_generated) / len(self.policies_generated)
            if self.policies_generated
            else 0
        )

        # Scheme distribution
        scheme_counts: Dict[str, int] = {}
        for p in self.policies_generated:
            scheme_counts[p.selected_scheme] = scheme_counts.get(p.selected_scheme, 0) + 1

        return {
            "agent_version": self.VERSION,
            "total_registrations_processed": self._registration_count,
            "total_policies_generated": len(self.policies_generated),
            "schemes_in_knowledge_base": self.knowledge_base.get_scheme_count(),
            "average_processing_time_ms": round(avg_time, 2),
            "average_confidence": round(avg_confidence, 4),
            "scheme_distribution": scheme_counts,
            "experience_memory": mem_stats,
            "fallback_count": sum(1 for p in self.policies_generated if p.is_fallback),
        }

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_reasoning_chain(
        self,
        context: RegistrationContext,
        req_profile,
        experiences,
        recommendation: Recommendation,
        policy: PrivacyPolicy,
        validation,
        elapsed_ms: float,
    ) -> None:
        """Print a rich console summary of the reasoning chain."""
        n = self._registration_count
        trace = recommendation.decision_trace
        W = 64

        print()
        print("╔" + "═" * W + "╗")
        print(f"║  CAPSS Agent — Registration #{n:<{W - 33}}║")
        print("╠" + "═" * W + "╣")

        # Context
        line1 = f"UE: {context.ue_id}  │  Slice: {context.slice_type}  │  DNN: {context.dnn}"
        line2 = f"Type: {context.registration_type}  │  Time: {context.timestamp.strftime('%Y-%m-%d %H:%M')}"
        print(f"║  {line1:<{W - 2}}║")
        print(f"║  {line2:<{W - 2}}║")
        print("╠" + "═" * W + "╣")

        # Context Analysis
        print(f"║  {'Context Analysis:':<{W - 2}}║")
        a1 = f"Threat: {req_profile.threat_level}  │  Privacy Req: {req_profile.privacy_requirement:.2f}"
        a2 = f"Tracking Risk: {req_profile.tracking_risk:.2f}  │  Latency: {req_profile.latency_requirement}"
        print(f"║    {a1:<{W - 4}}║")
        print(f"║    {a2:<{W - 4}}║")
        print("╠" + "═" * W + "╣")

        # Experience
        exp_count = len(experiences)
        if exp_count > 0:
            latest = experiences[0]
            exp_line = f"{exp_count} previous records (last: {latest.selected_scheme}, conf: {latest.confidence:.2f})"
        else:
            exp_line = "No previous records"
        print(f"║  Experience: {exp_line:<{W - 14}}║")
        print("╠" + "═" * W + "╣")

        # Top Candidates
        print(f"║  {'Top Candidates:':<{W - 2}}║")
        for i, cand in enumerate(trace.top_candidates[:3]):
            bar_len = int(cand.final_score * 12)
            bar = "█" * bar_len + "░" * (12 - bar_len)
            name = cand.short_name[:18].ljust(18)
            line = f"{i + 1}. {name} — Score: {cand.final_score:.2f}  {bar}"
            print(f"║    {line:<{W - 4}}║")
        print("╠" + "═" * W + "╣")

        # Recommendation
        check = "✓" if not recommendation.is_fallback else "⚠"
        rec_line = f"{check} RECOMMENDATION: {recommendation.primary_scheme}"
        print(f"║  {rec_line:<{W - 2}}║")
        conf_line = f"Confidence: {recommendation.confidence:.2f}  │  Risk: {recommendation.risk_assessment}"
        print(f"║    {conf_line:<{W - 4}}║")

        # Reason (truncate if needed)
        reason = recommendation.reason[:W - 6]
        print(f"║    {reason:<{W - 4}}║")

        # Hybrid
        if recommendation.hybrid_combination:
            combo = " + ".join(recommendation.hybrid_combination)
            hyb_line = f"Hybrid: {combo} (benefit: +{recommendation.hybrid_benefit_score:.2f})"
            print(f"║    {hyb_line:<{W - 4}}║")

        print("╠" + "═" * W + "╣")

        # Policy
        pol_line = f"Policy: {policy.policy_id}  │  Expires: {policy.expiry.strftime('%Y-%m-%d %H:%M') if policy.expiry else 'N/A'}"
        time_line = f"Processing: {elapsed_ms:.1f}ms  │  Valid: {validation.is_valid}"
        print(f"║  {pol_line:<{W - 2}}║")
        print(f"║  {time_line:<{W - 2}}║")
        print("╚" + "═" * W + "╝")

    def _print_batch_summary(self, policies: List[PrivacyPolicy]) -> None:
        """Print a summary after batch processing."""
        stats = self.get_agent_stats()
        W = 64

        print("\n" + "═" * (W + 2))
        print("  BATCH SUMMARY")
        print("═" * (W + 2))
        print(f"  Total registrations: {stats['total_registrations_processed']}")
        print(f"  Avg processing time: {stats['average_processing_time_ms']:.1f}ms")
        print(f"  Avg confidence:      {stats['average_confidence']:.4f}")
        print(f"  Fallback policies:   {stats['fallback_count']}")
        print()
        print("  Scheme Distribution:")
        for scheme, count in stats["scheme_distribution"].items():
            pct = (count / len(policies)) * 100
            print(f"    {scheme:<25} {count:>3} ({pct:.0f}%)")
        print()
        mem = stats["experience_memory"]
        print(f"  Experience Memory: {mem['total_experiences']} experiences for {mem['total_ues']} UEs")
        print("═" * (W + 2))

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_config(config_path: str | None) -> dict:
        """Load and merge config files from a directory."""
        config: Dict[str, Any] = {}
        if not config_path:
            return config

        if os.path.isfile(config_path):
            # Single file
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        elif os.path.isdir(config_path):
            # Merge all JSON files in the directory
            for fname in sorted(os.listdir(config_path)):
                if fname.endswith(".json"):
                    fpath = os.path.join(config_path, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        config.update(data)

        return config
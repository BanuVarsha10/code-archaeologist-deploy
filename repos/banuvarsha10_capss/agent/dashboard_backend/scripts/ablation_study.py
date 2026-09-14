"""dashboard_backend/scripts/ablation_study.py

Ablation study for CAPSS's three-signal reasoning pipeline (Systems'
threat classification, Privacy's scoring, and Experience/RAG history).
Runs a batch of real scenarios through the FULL real pipeline
(SystemsPrivacyView -> ContextAnalyzer -> ReasoningEngine, the same real,
unmodified classes every other dashboard entry point uses) four times per
scenario -- once per ablation_mode -- using the exact SAME registration
context and the exact SAME experience/retriever snapshot for all four
passes, so any difference in the resulting recommended scheme is
attributable ONLY to which signal was ablated, never to context drift or
history drift between passes.

WHY DISAGREEMENT RATE VS. FULL CAPSS, NOT "ACCURACY":
there is no ground truth for which scheme SHOULD be recommended for a
given context -- CAPSS's own scorer is the only real judge that exists,
and the ablated passes are not being checked against an external oracle.
So the only honest, defensible metric here is: how often does removing a
signal change the FINAL recommended scheme compared to running the full,
unablated pipeline (ablation_mode=None) on the identical input? A high
disagreement rate for a mode means that signal is influential for this
scenario mix; a near-zero rate means the other signals alone already
converge on the same scheme most of the time. This is an influence/
sensitivity metric, not an accuracy or error metric, and must never be
reported as one.

WHY A SEEDING PHASE EXISTS: MetricsCalculator.compute_eas() already
returns a neutral 0.5 when a scheme has no experience history at all (its
own, pre-existing, unmodified behavior -- see capss/reasoning/metrics.py).
If every scenario in the batch used a brand-new, never-before-seen
identity, "no_experience" would be trivially identical to the full-CAPSS
pass for every single case (both would already be looking at zero
history), which would produce a meaningless, uninformative 0% disagreement
rate for that mode. So this script first seeds real, persisted experience
history for a handful of UEs via the ONE real place experiences get
written -- CAPSSAgent.process_registration() (called here exactly as every
other real caller in the project calls it, never reimplemented) -- into a
dedicated, disposable experience store used only by this script. Roughly
half of the batch's scenarios then reuse a seeded identity (real per-UE
history) and the other half use fresh identities (relying on cross-UE RAG
retrieval instead, the other real path "no_experience" also disables), so
both of "no_experience"'s real code paths are genuinely exercised.

Ablation modes (see capss/context_analyzer/analyzer.py and
capss/reasoning/engine.py for the underlying mechanism):
  None            Full CAPSS -- completely normal, unmodified behavior.
  "no_threat"     Systems' threat_level/attack_type-derived inputs forced
                  neutral for this pass only; Systems' real classification
                  is untouched, only whether it's USED here is affected.
  "no_privacy"    Privacy's privacy_requirement/metadata_leakage/
                  correlation-derived inputs forced neutral for this pass
                  only; Privacy's real scoring is untouched.
  "no_experience" This UE's real history and cross-UE RAG both skipped for
                  this pass only; every scheme gets the neutral 0.5
                  experience-alignment default, as if a genuine first-ever
                  registration.

Output: a JSON results file under ablation_study_results/ containing full
per-scenario detail (every mode's recommended scheme + score) plus
aggregate disagreement rates overall and broken down by scenario type.
Also prints a live per-scenario log and a summary table to the console.

Usage (from agent/, i.e. `cd ~/5g-project/agent`):
    python3 -m dashboard_backend.scripts.ablation_study
    python3 -m dashboard_backend.scripts.ablation_study --num-scenarios 20 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tests.integration.subscriber_fixtures import mock_subscriber_database

from capss.agent.capss_agent import CAPSSAgent
from capss.agent.rag.retriever import ExperienceRetriever
from capss.context_analyzer.analyzer import ContextAnalyzer
from capss.experience_memory.memory import ExperienceMemory
from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.reasoning.engine import ReasoningEngine

from demo_for_mentor import make_request

from dashboard_backend.identity_gen import generate_fresh_identities, mask_identity
from dashboard_backend.scenario_builder import SCENARIOS as ATTACK_SCENARIO_TYPES, build_scenario_requests
from dashboard_backend.systems_privacy_view import SystemsPrivacyView

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR / "ablation_study_results"

SCHEMES_PATH = "data/privacy_schemes.json"  # same relative default every other dashboard entry point uses
# Dedicated, disposable experience store -- never the real
# dashboard_experience_store.json or the project's own experience_store.json.
ABLATION_EXPERIENCE_PATH = str(SCRIPT_DIR / "ablation_experience_store.json")

ABLATION_MODES: Tuple[Optional[str], ...] = (None, "no_threat", "no_privacy", "no_experience")
MODE_LABELS: Dict[Optional[str], str] = {
    None: "full_capss",
    "no_threat": "no_threat",
    "no_privacy": "no_privacy",
    "no_experience": "no_experience",
}
NON_FULL_MODE_LABELS = tuple(v for k, v in MODE_LABELS.items() if k is not None)

# "normal" (a single clean, non-attack registration -- real request_classification
# comes back ALLOW/NONE from Systems on its own, nothing is forced) is added
# on top of scenario_builder.py's 5 real attack scenarios. Without it, every
# scenario in the batch is Systems-module-attack-driven, which pushes
# tracking_risk/threat_level to their high end for every single case and
# saturates "no_threat" near 100% disagreement while starving "no_privacy" of
# any case where correlation/metadata-leakage risk can independently cross
# their >0.5 scoring thresholds (capss/reasoning/metrics.py's compute_sfs
# only applies privacy's tracking/metadata multipliers when the OUTER
# tracking_risk>0.5 check isn't already satisfied by the attack alone) --
# confirmed directly by inspecting per-mode RequirementProfile values on a
# sample case before adding this. SCENARIO_TYPES below is this script's own
# full set (attack + normal); ATTACK_SCENARIO_TYPES is only used for the
# seeding phase and the by-scenario aggregate breakdown of the 5 real
# attack types.
SCENARIO_TYPES: Tuple[str, ...] = ATTACK_SCENARIO_TYPES + ("normal",)

# invalid_subscriber and normal are structurally excluded from the seeding
# phase -- invalid_subscriber because seeding requires a real, provisioned,
# successful registration (see scenario_builder.py and
# dashboard_backend/pipeline_service.py's module docstring); normal is
# excluded only because seeding wants attack-history variety across seed
# UEs (a normal registration is already well covered as its own case type).
NON_INVALID_SCENARIOS = tuple(s for s in ATTACK_SCENARIO_TYPES if s != "invalid_subscriber")

# Cycled across cases (not left fixed at scenario_builder.py's "internet"/
# "eMBB" defaults) so Privacy's real, dnn/slice-sensitive signals
# (metadata_leakage's dnn-based floor, context sensitivity's slice/dnn
# weights) actually vary across the batch -- a fixed dnn/slice_type would
# mean every scenario's privacy-relevant inputs look the same, which is
# exactly the kind of homogeneity that produced the degenerate all-0%
# "no_privacy" result this diversification exists to fix.
DNN_CYCLE: Tuple[str, ...] = ("internet", "ims", "enterprise", "iot")
SLICE_CYCLE: Tuple[str, ...] = ("eMBB", "URLLC", "mMTC")


def _build_requests(ue_id: str, suci: str, attack_scenario: str, dnn: str, base_time=None) -> List[Any]:
    """Same relative-timing recipe as scenario_builder.build_scenario_requests
    (systems/pre_amf/attack_rules.py thresholds: REPLAY_INTERVAL=2s,
    DUPLICATE_INTERVAL=10s, MAX_REGISTRATIONS_PER_WINDOW=5/30s), reproduced
    here (rather than calling build_scenario_requests directly) only because
    that function's signature has no dnn parameter -- adding one there would
    change a shared, already-tested dashboard test-fixture helper's
    signature for a need specific to this script. "normal" is new: a single
    clean registration, no follow-up, real Systems/Privacy classification
    with nothing forced -- the counterpart to invalid_subscriber's single-
    request shape, but for a legitimate, provisioned subscriber."""
    if attack_scenario == "normal":
        return [make_request(ue_id, suci, "N1", 0, dnn=dnn, base_time=base_time)]
    if attack_scenario == "replay":
        return [
            make_request(ue_id, suci, "R1", 0, dnn=dnn, base_time=base_time),
            make_request(ue_id, suci, "R2", 1, dnn=dnn, base_time=base_time),
        ]
    if attack_scenario == "duplicate_registration":
        return [
            make_request(ue_id, suci, "D1", 0, dnn=dnn, base_time=base_time),
            make_request(ue_id, suci, "D2", 5, dnn=dnn, base_time=base_time),
        ]
    if attack_scenario == "flooding":
        return [
            make_request(ue_id, suci, f"F{i + 1}", i * 5, dnn=dnn, base_time=base_time)
            for i in range(6)
        ]
    if attack_scenario == "invalid_subscriber":
        return [make_request(ue_id, suci, "I1", 0, dnn=dnn, base_time=base_time)]
    if attack_scenario == "mixed":
        return [
            make_request(ue_id, suci, "M1", 0, dnn=dnn, base_time=base_time),
            make_request(ue_id, suci, "M2", 5, dnn=dnn, base_time=base_time),
            make_request(ue_id, suci, "M3", 6, dnn=dnn, base_time=base_time),
        ]
    raise ValueError(f"Unknown attack_scenario: {attack_scenario!r}")


@dataclass
class ScenarioCase:
    case_id: str
    ue_id: str
    suci: str
    attack_scenario: str
    identity_source: str  # "fresh_cold_start" | "seeded_returning" | "fresh_never_provisioned"
    dnn: str
    slice_type: str


def _build_read_only_retriever(memory: ExperienceMemory) -> ExperienceRetriever:
    """Mirrors CAPSSAgent.__init__'s own retriever setup exactly (indexes
    every existing experience across every UE into a fresh in-memory
    vector store) -- read-only: ExperienceRetriever.index_experience() only
    builds an in-process index, it never touches the experience store
    file. Same pattern dashboard_backend/pipeline_service.py's own
    _build_read_only_retriever uses, reproduced here rather than imported
    since that one is a private helper scoped to pipeline_service.py."""
    retriever = ExperienceRetriever()
    for existing_ue_id in memory.get_all_ues():
        for exp in memory.retrieve(existing_ue_id):
            retriever.index_experience(exp)
    return retriever


SEED_ROUNDS_PER_UE = 3  # >1 so real per-UE experience history has genuine depth --
# with only 1 experience, compute_eas's real historical-agreement ratio is
# still close to its 0.5 neutral default (see capss/reasoning/metrics.py's
# EAS_MAX_DEVIATION_FROM_NEUTRAL comment), which would make "no_experience"
# barely distinguishable from Full CAPSS even for "seeded_returning" cases.


def _seed_experience_history(
    view: SystemsPrivacyView, seed_identities: List[Tuple[str, str]], on_log,
) -> None:
    """Writes real, persisted experience history for each seed UE via the
    ONE real place experiences get written: CAPSSAgent.process_registration()
    (never reimplemented here). Each seed UE gets SEED_ROUNDS_PER_UE separate
    real registrations (varied scenario + dnn each round) run through the
    real Systems+Privacy pipeline, each followed by exactly one real agent
    call -- identical in shape to how every other real caller in the project
    persists an experience, just repeated so real history has depth."""
    agent = CAPSSAgent(schemes_path=SCHEMES_PATH, experience_path=ABLATION_EXPERIENCE_PATH)
    for ue_id, suci in seed_identities:
        for round_num in range(SEED_ROUNDS_PER_UE):
            scenario = random.choice(NON_INVALID_SCENARIOS)
            dnn = DNN_CYCLE[round_num % len(DNN_CYCLE)]
            requests = _build_requests(ue_id, suci, scenario, dnn)
            context = None
            for req in requests:
                _report, _privacy_result, context, _validation_context, _minimization_result = view.process(req)
            policy = agent.process_registration(context, verbose=False)
            on_log(
                f"  seeded {mask_identity(ue_id)} round {round_num + 1}/{SEED_ROUNDS_PER_UE} "
                f"via {scenario:22s} (dnn={dnn:10s}) -> {policy.selected_scheme}"
            )


def _build_case_matrix(num_scenarios: int, seed_identities: List[Tuple[str, str]]) -> List[ScenarioCase]:
    """Deterministic, reproducible mix: cycles through every real scenario
    type (5 real Systems attacks + "normal"), alternating between a
    never-before-seen ("cold start") identity and one of the seeded,
    already-registered identities ("returning" -- real own-UE experience
    history exists), so both of "no_experience"'s real code paths (its own
    history, and cross-UE RAG when it has none) get genuinely exercised
    across the batch. dnn/slice_type are cycled independently of scenario
    type so Privacy-sensitive signals vary across cases regardless of which
    attack (if any) is present. invalid_subscriber always uses a fresh,
    never-provisioned identity -- the only structurally valid choice for
    that scenario (see module docstring)."""
    cases: List[ScenarioCase] = []
    fresh_pool = iter(generate_fresh_identities(num_scenarios))
    i = 0
    while len(cases) < num_scenarios:
        scenario = SCENARIO_TYPES[i % len(SCENARIO_TYPES)]
        case_id = f"case_{len(cases) + 1:02d}"
        dnn = DNN_CYCLE[i % len(DNN_CYCLE)]
        slice_type = SLICE_CYCLE[i % len(SLICE_CYCLE)]
        if scenario == "invalid_subscriber":
            ident = next(fresh_pool)
            cases.append(ScenarioCase(case_id, ident.ue_id, ident.suci, scenario, "fresh_never_provisioned", dnn, slice_type))
        elif i % 2 == 0 or not seed_identities:
            ident = next(fresh_pool)
            cases.append(ScenarioCase(case_id, ident.ue_id, ident.suci, scenario, "fresh_cold_start", dnn, slice_type))
        else:
            seed_ue_id, seed_suci = seed_identities[(i // 2) % len(seed_identities)]
            cases.append(ScenarioCase(case_id, seed_ue_id, seed_suci, scenario, "seeded_returning", dnn, slice_type))
        i += 1
    return cases


def run_case(case: ScenarioCase, view: SystemsPrivacyView, kb: SchemeKnowledgeBase) -> Dict[str, Any]:
    """Runs one scenario's real Systems+Privacy classification exactly
    once, then scores the resulting context through the full real
    ContextAnalyzer -> ReasoningEngine pipeline four times, once per
    ablation_mode, on an IDENTICAL context + experience/retriever
    snapshot each time -- read-only throughout, no experience writes, no
    agent invocation (matches _read_only_recommendation()'s documented
    snapshot-before-read pattern in pipeline_service.py).

    view.slice_type is set for the duration of this case only, then
    restored -- SystemsPrivacyView.slice_type is a plain per-instance
    dataclass field read at call time by build_registration_context(), not
    detection state, so varying it between calls on the same, reused view
    instance is safe and doesn't disturb that instance's real accumulated
    per-UE RegistrationHistory (which is what "seeded_returning" cases rely
    on)."""
    original_slice_type = view.slice_type
    view.slice_type = case.slice_type
    try:
        requests = _build_requests(case.ue_id, case.suci, case.attack_scenario, case.dnn)
        context = None
        for req in requests:
            _report, _privacy_result, context, _validation_context, _minimization_result = view.process(req)
    finally:
        view.slice_type = original_slice_type
    assert context is not None

    memory = ExperienceMemory(ABLATION_EXPERIENCE_PATH)
    experiences_snapshot = memory.retrieve(case.ue_id)
    retriever_snapshot = _build_read_only_retriever(memory)

    per_mode: Dict[str, Dict[str, Any]] = {}
    for mode in ABLATION_MODES:
        profile = ContextAnalyzer().analyze(context, experiences_snapshot, ablation_mode=mode)
        rec = ReasoningEngine(kb, retriever=retriever_snapshot).reason(
            context, profile, experiences_snapshot, ablation_mode=mode,
        )
        per_mode[MODE_LABELS[mode]] = {
            "primary_scheme": rec.primary_scheme,
            "primary_score": round(rec.primary_score, 4),
            "confidence": round(rec.confidence, 4),
            "is_fallback": rec.is_fallback,
        }

    full_scheme = per_mode["full_capss"]["primary_scheme"]
    return {
        "case_id": case.case_id,
        "masked_identity": mask_identity(case.ue_id),
        "attack_scenario": case.attack_scenario,
        "identity_source": case.identity_source,
        "dnn": case.dnn,
        "slice_type": case.slice_type,
        "prior_experience_count": len(experiences_snapshot),
        "results_by_mode": per_mode,
        "disagreed_with_full": {
            label: (per_mode[label]["primary_scheme"] != full_scheme) for label in NON_FULL_MODE_LABELS
        },
    }


def aggregate(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    overall: Dict[str, Any] = {}
    for label in NON_FULL_MODE_LABELS:
        disagree_count = sum(1 for r in results if r["disagreed_with_full"][label])
        overall[label] = {
            "disagreement_count": disagree_count,
            "disagreement_rate": round(disagree_count / total, 4) if total else None,
        }

    by_scenario: Dict[str, Dict[str, float]] = {}
    for scenario in SCENARIO_TYPES:
        scen_results = [r for r in results if r["attack_scenario"] == scenario]
        if not scen_results:
            continue
        by_scenario[scenario] = {
            label: round(sum(1 for r in scen_results if r["disagreed_with_full"][label]) / len(scen_results), 4)
            for label in NON_FULL_MODE_LABELS
        }

    return {
        "total_scenarios": total,
        "overall_disagreement_rate": overall,
        "disagreement_rate_by_scenario_type": by_scenario,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--num-scenarios", type=int, default=20, help="total scenarios to run (default 20)")
    parser.add_argument("--num-seed-ues", type=int, default=6, help="UEs seeded with real prior history (default 6)")
    parser.add_argument("--seed", type=int, default=None, help="random.seed() for reproducible scenario/identity assignment")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    # Fresh, disposable experience store for every run of this script, so
    # results are reproducible and never polluted by a prior run's history.
    ExperienceMemory(ABLATION_EXPERIENCE_PATH).clear()

    seed_pool = generate_fresh_identities(args.num_seed_ues)
    seed_identities = [(ident.ue_id, ident.suci) for ident in seed_pool]
    seed_suffixes = {ue_id.replace("imsi-", "") for ue_id, _ in seed_identities}

    case_matrix = _build_case_matrix(args.num_scenarios, seed_identities)
    fresh_suffixes = {
        case.ue_id.replace("imsi-", "")
        for case in case_matrix
        if case.attack_scenario != "invalid_subscriber"
    }
    allow_list = fresh_suffixes | seed_suffixes

    view = SystemsPrivacyView()
    kb = SchemeKnowledgeBase(SCHEMES_PATH)

    print(f"Seeding real experience history for {len(seed_identities)} UEs...")
    with mock_subscriber_database(seed_suffixes):
        _seed_experience_history(view, seed_identities, on_log=print)

    print(f"\nRunning {len(case_matrix)} scenarios through the full real pipeline (4 ablation modes each)...")
    results: List[Dict[str, Any]] = []
    with mock_subscriber_database(allow_list):
        for case in case_matrix:
            result = run_case(case, view, kb)
            results.append(result)
            diff_flags = " ".join(
                f"{label}={'DIFF' if result['disagreed_with_full'][label] else 'same'}"
                for label in NON_FULL_MODE_LABELS
            )
            print(
                f"  {case.case_id}  {case.attack_scenario:22s} ({case.identity_source:24s})  "
                f"full={result['results_by_mode']['full_capss']['primary_scheme']:6s}  {diff_flags}"
            )

    summary = aggregate(results)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = RESULTS_DIR / f"ablation_study_{timestamp}.json"
    out_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "num_scenarios": len(results),
                "num_seed_ues": len(seed_identities),
                "ablation_modes": list(MODE_LABELS.values()),
                "metric_definition": (
                    "disagreement_rate = fraction of scenarios where this mode's "
                    "primary_scheme differs from ablation_mode=None (Full CAPSS) on "
                    "the identical context/experience snapshot. No ground truth exists "
                    "for 'correct' scheme, so this is an influence/sensitivity metric, "
                    "not an accuracy metric."
                ),
                "per_scenario_detail": results,
                "aggregate": summary,
            },
            indent=2,
        )
    )

    print(f"\nResults written to {out_path}\n")
    print("Aggregate disagreement rate vs. Full CAPSS (ablation_mode=None):")
    for label, stats in summary["overall_disagreement_rate"].items():
        rate_pct = stats["disagreement_rate"] * 100 if stats["disagreement_rate"] is not None else 0.0
        print(f"  {label:16s} {stats['disagreement_count']:2d}/{summary['total_scenarios']} = {rate_pct:.1f}%")


if __name__ == "__main__":
    main()

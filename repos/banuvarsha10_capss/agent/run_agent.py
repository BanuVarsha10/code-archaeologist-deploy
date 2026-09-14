"""CAPSS Agent CLI — Entry point for running the CAPSS Agent.

Usage:
    python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json
    python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json --config configs/
    python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json --ue UE-001
    python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json --output results.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capss.context_loader.loader import ContextLoader
from capss.agent.capss_agent import CAPSSAgent


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = argparse.ArgumentParser(
        description="CAPSS Agent — Context-Aware Adaptive Privacy and Security System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json
  python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json --config configs/
  python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json --ue UE-001
  python run_agent.py --data data/registration_dataset.csv --schemes data/privacy_schemes.json --output results.json --quiet
""",
    )
    parser.add_argument("--data", required=True, help="Path to registration CSV file")
    parser.add_argument("--attack-data", default=None, help="Path to attack CSV file (Systems module paired batch)")
    parser.add_argument("--schemes", required=True, help="Path to privacy_schemes.json")
    parser.add_argument("--config", default=None, help="Path to config directory or file")
    parser.add_argument("--experience", default=None, help="Path to experience store JSON")
    parser.add_argument("--ue", default=None, help="Process only this UE ID")
    parser.add_argument("--year", type=int, default=None, help="Assumed year for timestamps missing year (e.g. 2024)")
    parser.add_argument("--output", default=None, help="Save policies to JSON file")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-registration output")
    parser.add_argument("--stats", action="store_true", help="Print agent stats after processing")

    args = parser.parse_args()

    # Validate paths
    if not os.path.exists(args.data):
        print(f"Error: Data file not found: {args.data}", file=sys.stderr)
        sys.exit(1)
    if args.attack_data and not os.path.exists(args.attack_data):
        print(f"Error: Attack data file not found: {args.attack_data}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.schemes):
        print(f"Error: Schemes file not found: {args.schemes}", file=sys.stderr)
        sys.exit(1)

    # Initialize agent
    print("\n╔════════════════════════════════════════════════╗")
    print("║     CAPSS — Privacy Recommendation Agent      ║")
    print("╚════════════════════════════════════════════════╝\n")

    agent = CAPSSAgent(
        schemes_path=args.schemes,
        config_path=args.config,
        experience_path=args.experience,
    )

    print(f"  Schemes loaded: {agent.knowledge_base.get_scheme_count()}")

    # Load registrations
    attack_data_path = args.attack_data
    if not attack_data_path and os.path.exists(args.data):
        # Auto-detect attack_dataset.csv in the same directory as --data CSV
        data_dir = os.path.dirname(args.data)
        candidate_attack = os.path.join(data_dir, "attack_dataset.csv")
        if os.path.exists(candidate_attack):
            attack_data_path = candidate_attack

    if attack_data_path:
        from capss.context_loader.systems_loader import SystemsContextLoader
        loader = SystemsContextLoader(args.data, attack_data_path, year=args.year)
    else:
        loader = ContextLoader(args.data)

    if args.ue:
        contexts = loader.load_by_ue(args.ue)
        print(f"  Registrations for {args.ue}: {len(contexts)}")
    else:
        contexts = loader.load_all()
        print(f"  Total registrations: {len(contexts)}")
        summary = loader.get_summary()
        print(f"  Unique UEs: {summary.get('unique_ues', 'N/A')}")

    if not contexts:
        print("\n  No registrations found. Exiting.")
        sys.exit(0)

    # Process
    verbose = not args.quiet
    policies = agent.process_batch(contexts, verbose=verbose)

    # Stats
    if args.stats or verbose:
        stats = agent.get_agent_stats()
        print("\n  Agent Statistics:")
        print(f"    Version:           {stats['agent_version']}")
        print(f"    Processed:         {stats['total_registrations_processed']}")
        print(f"    Avg time:          {stats['average_processing_time_ms']:.1f}ms")
        print(f"    Avg confidence:    {stats['average_confidence']:.4f}")

    # Output
    if args.output:
        output_data = []
        for policy in policies:
            output_data.append(policy.model_dump(mode="json"))
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"\n  Policies saved to: {args.output}")

    print("\n  Done.\n")


if __name__ == "__main__":
    main()
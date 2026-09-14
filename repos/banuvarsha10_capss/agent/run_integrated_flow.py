"""
run_integrated_flow.py

Full CAPSS flow: Systems module (real, unmodified) -> adapter -> Agent
module (real, unmodified).

Usage:
    python run_integrated_flow.py --data <registration_dataset.csv> \\
        --schemes data/privacy_schemes.json \\
        [--experience experience_store.json] [--output results.json]

NOTE ON SUBSCRIBER VALIDATION:
Systems' SubscriberValidator requires a live MongoDB/Open5GS instance.
If no such instance is reachable, pass --mock-subscribers to use an
in-memory allow-list instead (TEST/DEMO USE ONLY - see
tests/integration/subscriber_fixtures.py for details). Without this flag,
this script uses Systems' real subscriber validation unmodified, and will
fail if no database is reachable - this is intentional, so production runs
never silently fall back to a mock.
"""

import argparse
import json
import sys

from systems.pre_amf.registration_loader import RegistrationLoader
from capss.integration.systems_adapter import SystemsPipeline
from capss.agent.capss_agent import CAPSSAgent


def main():
    parser = argparse.ArgumentParser(description="CAPSS integrated Systems -> Agent flow")
    parser.add_argument("--data", required=True, help="Path to registration CSV")
    parser.add_argument("--schemes", required=True, help="Path to privacy_schemes.json")
    parser.add_argument("--experience", default="experience_store.json", help="Experience store path")
    parser.add_argument("--output", default=None, help="Save policies to JSON file")
    parser.add_argument("--mock-subscribers", action="store_true",
                         help="Use in-memory subscriber allow-list instead of MongoDB (TEST/DEMO ONLY)")
    parser.add_argument("--known-subscribers", default="",
                         help="Comma-separated IMSIs for --mock-subscribers (default: none known)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    print("=" * 80)
    print("CAPSS INTEGRATED FLOW: Systems -> Agent")
    print("=" * 80)

    requests = RegistrationLoader(args.data).load()
    print(f"\nLoaded {len(requests)} registration requests from {args.data}\n")

    pipeline = SystemsPipeline()
    agent = CAPSSAgent(schemes_path=args.schemes, experience_path=args.experience)

    def run_all():
        results = []
        for i, request in enumerate(requests, 1):
            report = pipeline.process(request)
            from capss.integration.systems_adapter import attack_report_to_registration_context
            context = attack_report_to_registration_context(report, request)
            policy = agent.process_registration(context, verbose=False)
            results.append(policy)
            if not args.quiet:
                hybrid = "+".join(policy.hybrid_schemes[1:]) if policy.hybrid_schemes and len(policy.hybrid_schemes) > 1 else ""
                print(f"[{i}] UE={request.ue_id} | Systems: {report.decision} ({report.attack_type}) "
                      f"-> Agent: {policy.selected_scheme}{'+' + hybrid if hybrid else ''} "
                      f"(conf={policy.confidence:.3f}, valid={policy.validation_result.is_valid})")
        return results

    if args.mock_subscribers:
        from tests.integration.subscriber_fixtures import mock_subscriber_database
        known = {s.strip() for s in args.known_subscribers.split(",") if s.strip()}
        print(f"[DEMO MODE] Using in-memory subscriber allow-list ({len(known)} known IMSIs) "
              f"instead of MongoDB. Systems' real subscriber_validator.py is unmodified on disk.\n")
        with mock_subscriber_database(known):
            results = run_all()
    else:
        results = run_all()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([p.model_dump(mode="json") for p in results], f, indent=2, default=str)
        print(f"\nPolicies saved to: {args.output}")

    print("\n" + "=" * 80)
    print("Done. Systems' own source files were not modified.")
    print("=" * 80)


if __name__ == "__main__":
    sys.exit(main())

# CAPSS: Context-Aware Adaptive Privacy and Security System

## Overview
CAPSS is an autonomous AI agent framework designed to provide adaptive privacy and security recommendations for 5G/6G User Equipments (UEs). By observing registration data, analyzing security threats, retrieving historical experiences, and consulting a rich knowledge base of cryptographic privacy schemes, CAPSS ensures optimal privacy scheme selection in real-time.

## Architecture
```text
[Context Loader / Systems Loader] -> (RegistrationContext)
       |
       v
[Context Analyzer] <--> [Experience Memory] <--> [RAG Vector Store]
       |                       |                      |
       v                       | (per-UE exact)       | (cross-UE similarity)
(RequirementProfile)           v                      v
       |---------------> [Reasoning Engine] <--> [Scheme Knowledge Base]
                               |
                               v
                        (Recommendation)
                               |
                               v
                       [Policy Generator] -> (PrivacyPolicy) -> [Policy Validator] -> Output
                               |
                               v
                       [Memory Updater] ---> [Experience Memory] & [RAG Vector Store]
```

## Cross-UE RAG Retrieval Subsystem
CAPSS includes an additive Retrieval-Augmented Generation (RAG) vector search module (`capss.agent.rag`). When a new or cold-start UE (with `< 3` local experiences) registers, CAPSS performs in-memory cosine similarity retrieval across normalized 13-dimensional context vectors from past registrations of other UEs. This enables immediate, evidence-backed privacy recommendations for cold-start UEs before they build their own local interaction history, while preserving 100% exact local history precedence once sufficient per-UE experience exists (`>= 3`).

## Quick Start
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the agent against sample paired Systems & Attack datasets:
   ```bash
   python run_agent.py --data data/samples/duplicate_registration_batch.csv --attack-data data/samples/duplicate_registration_attack.csv --schemes data/privacy_schemes.json
   ```

## CLI Usage

```bash
python run_agent.py --data <path> --schemes <path> [options]
```

### Command-Line Arguments:
- `--data <path>` **(Required)**: Path to registration CSV file.
- `--attack-data <path>` **(Optional)**: Path to attack dataset CSV file. *Note: `--attack-data` is required when ingesting raw Systems-module data split across two separate CSVs (registration events and attack detection events) joined on `Request_ID`.*
- `--schemes <path>` **(Required)**: Path to `privacy_schemes.json` knowledge base.
- `--config <path>` **(Optional)**: Path to custom configuration JSON file or directory containing `weights.json` and `thresholds.json`.
- `--experience <path>` **(Optional)**: Path to custom persistent experience store JSON file.
- `--ue <ue_id>` **(Optional)**: Process only registrations matching a specific UE ID.
- `--year <YYYY>` **(Optional)**: Assumed calendar year for timestamps lacking an explicit year (e.g. `--year 2024`).
- `--output <path>` **(Optional)**: Path to write generated policy results to a JSON file.
- `--quiet` **(Optional)**: Suppress verbose per-registration console formatting.
- `--stats` **(Optional)**: Print agent summary and performance statistics after processing.

### Example Commands:
```bash
# Process paired Systems-module batch with output file and stats
python run_agent.py --data data/samples/duplicate_registration_batch.csv --attack-data data/samples/duplicate_registration_attack.csv --schemes data/privacy_schemes.json --output result.json --stats

# Process single standalone registration CSV for a specific UE
python run_agent.py --data data/samples/standard_registrations.csv --schemes data/privacy_schemes.json --ue UE-001
```

## Interactive Demonstration
Run the 3-step user registration adaptation scenario (Normal → Privacy Issue → Linkability & Hybrid Scheme):
```bash
python scripts/test_user_flow.py
```

## Testing
The repository includes a comprehensive automated test suite consisting of **92 passing tests** covering context loading, threat analysis, experience memory FIFO eviction, reasoning engine scoring, policy validation, and 5 full traffic scenarios.

Run the full test suite:
```bash
python -m pytest tests/ -v
```

Run only scenario tests:
```bash
python -m pytest tests/scenarios/ -v
```

## Extension Guide
To extend CAPSS with new privacy schemes or reasoning logic, update `data/privacy_schemes.json` or customize module classes in `capss/agent/capss_agent.py`.

#!/bin/bash

PROJECT="CAPSS"

mkdir -p $PROJECT/{docs,open5gs,ueransim,logging,privacy,agent,datasets,experiments,results,paper,presentation}

mkdir -p $PROJECT/open5gs/{configs,scripts,patches}
mkdir -p $PROJECT/ueransim/{configs,scripts}

mkdir -p $PROJECT/logging/schemas
mkdir -p $PROJECT/privacy/schemes

mkdir -p $PROJECT/agent/{rag,llm,examples}

mkdir -p $PROJECT/datasets/{raw,processed}

mkdir -p $PROJECT/results/{figures,tables,logs}

mkdir -p $PROJECT/presentation/diagrams

# Root files
touch $PROJECT/README.md
touch $PROJECT/.gitignore
touch $PROJECT/requirements.txt
touch $PROJECT/setup.sh

# Docs
touch $PROJECT/docs/proposal.md
touch $PROJECT/docs/architecture.md
touch $PROJECT/docs/literature_review.md
touch $PROJECT/docs/meeting_notes.md
touch $PROJECT/docs/tasks.md

# Open5GS
touch $PROJECT/open5gs/scripts/restart.sh
touch $PROJECT/open5gs/scripts/stop.sh
touch $PROJECT/open5gs/scripts/collect_logs.sh
touch $PROJECT/open5gs/patches/README.md

# UERANSIM
touch $PROJECT/ueransim/scripts/start_gnb.sh
touch $PROJECT/ueransim/scripts/start_ue.sh

# Logging
touch $PROJECT/logging/registration_logger.py
touch $PROJECT/logging/metrics_collector.py
touch $PROJECT/logging/parse_amf_logs.py

touch $PROJECT/logging/schemas/registration_schema.json
touch $PROJECT/logging/schemas/metrics_schema.json

# Privacy
touch $PROJECT/privacy/metadata_inventory.md
touch $PROJECT/privacy/metadata_minimizer.py
touch $PROJECT/privacy/privacy_score.py
touch $PROJECT/privacy/correlation_analyzer.py

touch $PROJECT/privacy/schemes/ecies.md
touch $PROJECT/privacy/schemes/pqc.md
touch $PROJECT/privacy/schemes/padding.md
touch $PROJECT/privacy/schemes/supi_rear.md

# Agent
touch $PROJECT/agent/rag/vector_store.py
touch $PROJECT/agent/rag/embedding_generator.py
touch $PROJECT/agent/rag/retriever.py
touch $PROJECT/agent/rag/experience_schema.py

touch $PROJECT/agent/llm/prompts.py
touch $PROJECT/agent/llm/reasoning_engine.py
touch $PROJECT/agent/llm/policy_generator.py

touch $PROJECT/agent/examples/sample_experiences.json

# Datasets
touch $PROJECT/datasets/raw/.gitkeep
touch $PROJECT/datasets/processed/.gitkeep

# Experiments
touch $PROJECT/experiments/experiment_10_ues.py
touch $PROJECT/experiments/experiment_20_ues.py
touch $PROJECT/experiments/experiment_50_ues.py
touch $PROJECT/experiments/benchmark.py

# Results
touch $PROJECT/results/figures/.gitkeep
touch $PROJECT/results/tables/.gitkeep
touch $PROJECT/results/logs/.gitkeep

# Paper
touch $PROJECT/paper/outline.md
touch $PROJECT/paper/related_work.md
touch $PROJECT/paper/methodology.md
touch $PROJECT/paper/experiments.md
touch $PROJECT/paper/references.bib

echo "CAPSS project structure created successfully!"



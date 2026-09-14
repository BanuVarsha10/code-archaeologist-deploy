# Agent Module

## Purpose
The core orchestrator of the CAPSS system, integrating all sub-modules into a cohesive pipeline.

## Classes
- `CAPSSAgent`: Handles processing of individual registrations and batches, coordinating between memory, knowledge base, reasoning engine, and policy generation.

## Usage
```python
from capss.agent import CAPSSAgent
agent = CAPSSAgent(schemes_path="schemes.json")
policy = agent.process_registration(context)
```
